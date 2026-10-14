-- Explicit stopped installation; private per-state limits require owner enrollment.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_multi_event') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_window_history;
REVOKE ALL ON SCHEMA signal_window_history FROM PUBLIC;
CREATE TABLE signal_window_history.profile (
 partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),state_key text NOT NULL CHECK(octet_length(state_key) BETWEEN 1 AND 256),
 scope_generation uuid NOT NULL REFERENCES signal_finding_scope.activation(scope_generation),
 max_rows bigint NOT NULL CHECK(max_rows BETWEEN 1 AND 16384),max_bytes bigint NOT NULL CHECK(max_bytes BETWEEN 4096 AND 33554432),
 retention_ms bigint NOT NULL CHECK(retention_ms BETWEEN 1 AND 31536000000),
 used_rows bigint NOT NULL DEFAULT 0 CHECK(used_rows BETWEEN 0 AND max_rows),used_bytes bigint NOT NULL DEFAULT 0 CHECK(used_bytes BETWEEN 0 AND max_bytes),
 watermark_seconds bigint,watermark_nanos integer,
 CHECK((watermark_seconds IS NULL AND watermark_nanos IS NULL) OR
  (watermark_seconds IS NOT NULL AND watermark_nanos IS NOT NULL AND watermark_nanos BETWEEN 0 AND 1999999999)),
 PRIMARY KEY(partition_id,state_key)
);
CREATE TABLE signal_window_history.assessments (
 partition_id uuid NOT NULL,state_key text NOT NULL,id bytea NOT NULL CHECK(octet_length(id)=32),
 checkpoint bigint NOT NULL CHECK(checkpoint>0),recorded_at_ms bigint NOT NULL,expires_at_ms bigint NOT NULL CHECK(expires_at_ms>recorded_at_ms),
 payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 65536),payload_sha256 bytea NOT NULL CHECK(payload_sha256=sha256(payload)),
 PRIMARY KEY(partition_id,state_key,id),FOREIGN KEY(partition_id,state_key) REFERENCES signal_window_history.profile(partition_id,state_key)
);
CREATE INDEX assessment_expiry ON signal_window_history.assessments(partition_id,state_key,expires_at_ms);
REVOKE ALL ON ALL TABLES IN SCHEMA signal_window_history FROM PUBLIC;
-- Canonical UTC clocks use Chrono's POSIX-second plus nanosecond pair.
-- Leap seconds retain second59 with nanoseconds in [1e9,2e9); normalizing
-- them into the next POSIX second would destroy the detector's exact ordering.
CREATE FUNCTION signal_window_history.timestamp_pair(value text) RETURNS bigint[]
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog,signal_control,pg_temp AS $time$
DECLARE fields text[];year bigint;month bigint;day bigint;hour bigint;minute bigint;second bigint;
 nanos bigint;days_in_month integer;adjusted bigint;era bigint;year_of_era bigint;day_of_year bigint;days bigint;
BEGIN
 IF octet_length(value)>40 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 fields:=regexp_match(value,'^(-[0-9]{4,6}|[0-9]{4}|[+][0-9]{5,6})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$');
 IF fields IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 year:=fields[1]::bigint;month:=fields[2]::bigint;day:=fields[3]::bigint;
 hour:=fields[4]::bigint;minute:=fields[5]::bigint;second:=fields[6]::bigint;
 IF year NOT BETWEEN -262143 AND 262142 OR month NOT BETWEEN 1 AND 12
  OR hour NOT BETWEEN 0 AND 23 OR minute NOT BETWEEN 0 AND 59 OR second NOT BETWEEN 0 AND 60 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 days_in_month:=CASE WHEN month IN (4,6,9,11) THEN 30 WHEN month=2 THEN
  CASE WHEN year%4=0 AND (year%100<>0 OR year%400=0) THEN 29 ELSE 28 END ELSE 31 END;
 IF day NOT BETWEEN 1 AND days_in_month THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 nanos:=rpad(coalesce(fields[7],''),9,'0')::bigint;
 IF second=60 THEN nanos:=nanos+1000000000; END IF;
 -- Proleptic Gregorian days from civil fields, using floor division for BCE.
 -- March starts a 400-year era; 719468 is the civil-day offset of 1970-01-01.
 adjusted:=year-CASE WHEN month<=2 THEN 1 ELSE 0 END;
 era:=floor(adjusted::numeric/400)::bigint;year_of_era:=adjusted-era*400;
 day_of_year:=(153*(month+CASE WHEN month>2 THEN -3 ELSE 9 END)+2)/5+day-1;
 days:=era*146097+year_of_era*365+year_of_era/4-year_of_era/100+day_of_year-719468;
 RETURN ARRAY[days*86400+hour*3600+minute*60+least(second,59),nanos];
END $time$;
REVOKE ALL ON FUNCTION signal_window_history.timestamp_pair(text) FROM PUBLIC;
CREATE FUNCTION signal_window_history.archive_publication() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE cfg signal_window_history.profile;state_value jsonb;detector jsonb;policy jsonb;assessment jsonb;
 refs jsonb;sequences jsonb;payload bytea;identity bytea;now_ms bigint;count_rows bigint;count_bytes bigint;key text;
 pending_ids bytea[]:=ARRAY[]::bytea[];
 watermark_text text;next_watermark_seconds bigint;next_watermark_nanos integer;
 anchor_text text;anchor_seconds bigint;anchor_nanos integer;clock_pair bigint[];
BEGIN
 key:=convert_from(NEW.claims,'UTF8')::jsonb->>'state_key';
 SELECT * INTO cfg FROM signal_window_history.profile WHERE partition_id=NEW.partition_id AND state_key=key FOR UPDATE;
 IF NOT FOUND THEN RETURN NEW; END IF;
 SELECT convert_from(value,'UTF8')::jsonb INTO state_value FROM signal_control.state WHERE partition_id=NEW.partition_id AND signal_control.state.key=cfg.state_key;
 detector:=state_value->'metadata'->'window'->'state';policy:=detector->'policy';
 IF state_value->>'scope_generation' IS DISTINCT FROM cfg.scope_generation::text
  OR jsonb_typeof(detector->'outputs') IS DISTINCT FROM 'array'
  OR jsonb_array_length(detector->'outputs')>16384
  OR (policy->>'max_history_assessments')::bigint IS DISTINCT FROM cfg.max_rows
  OR (policy->>'max_history_bytes')::bigint IS DISTINCT FROM cfg.max_bytes
  OR (policy->>'history_retention_ms')::bigint IS DISTINCT FROM cfg.retention_ms THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 watermark_text:=detector->>'watermark';
 IF watermark_text IS NULL THEN
  IF cfg.watermark_seconds IS NOT NULL OR jsonb_array_length(detector->'outputs')<>0 THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 ELSE
  clock_pair:=signal_window_history.timestamp_pair(watermark_text);
  next_watermark_seconds:=clock_pair[1];next_watermark_nanos:=clock_pair[2]::integer;
  IF cfg.watermark_seconds IS NOT NULL AND (next_watermark_seconds,next_watermark_nanos)<(cfg.watermark_seconds,cfg.watermark_nanos) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 END IF;
 SELECT count(*),coalesce(sum(256+octet_length(a.payload)),0) INTO count_rows,count_bytes FROM signal_window_history.assessments a WHERE a.partition_id=cfg.partition_id AND a.state_key=cfg.state_key;
 IF count_rows<>cfg.used_rows OR count_bytes<>cfg.used_bytes
  OR EXISTS(SELECT 1 FROM signal_window_history.assessments a WHERE a.partition_id=cfg.partition_id AND a.state_key=cfg.state_key AND (a.id<>sha256(a.payload) OR a.payload_sha256<>sha256(a.payload))) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 FOR assessment IN SELECT x FROM jsonb_array_elements(detector->'outputs') x LOOP
  IF assessment->'schema_version' IS DISTINCT FROM '1'::jsonb OR assessment ? 'evidence'
   OR assessment->>'outcome' NOT IN ('match','no_match','indeterminate') OR assessment->>'outcome' IS NULL
   OR jsonb_typeof(assessment->'event_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(assessment->'event_ids')>1000
   OR (assessment->>'outcome'='match' AND jsonb_array_length(assessment->'event_ids')=0) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  anchor_text:=assessment->>'anchor';
  IF anchor_text IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  clock_pair:=signal_window_history.timestamp_pair(anchor_text);
  anchor_seconds:=clock_pair[1];anchor_nanos:=clock_pair[2]::integer;
  IF (anchor_seconds,anchor_nanos)>(next_watermark_seconds,next_watermark_nanos) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  SELECT coalesce(jsonb_object_agg(k,v),'{}'::jsonb) INTO refs FROM jsonb_each(state_value->'metadata'->'canonical_sha256') m(k,v) WHERE assessment->'event_ids' ? k;
  SELECT coalesce(jsonb_object_agg(k,v),'{}'::jsonb) INTO sequences FROM jsonb_each(state_value->'canonical_sequences') m(k,v) WHERE assessment->'event_ids' ? k;
  IF (SELECT count(*) FROM jsonb_object_keys(coalesce(refs,'{}'::jsonb)))<>jsonb_array_length(assessment->'event_ids')
   OR (SELECT count(*) FROM jsonb_object_keys(coalesce(sequences,'{}'::jsonb)))<>jsonb_array_length(assessment->'event_ids') THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  payload:=convert_to(jsonb_build_object('schema_version',1,'scope_generation',cfg.scope_generation,'source',(state_value->'metadata')-'window'-'canonical_sha256','policy',policy,'assessment',assessment,'canonical_sha256',refs,'canonical_sequences',sequences)::text,'UTF8');
  IF octet_length(payload)>65536 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
  identity:=sha256(payload);
  -- Every new detector output is sealed strictly after the prior watermark.
  -- An old pending record may replay, but a reclaimed record cannot resurrect.
  IF cfg.watermark_seconds IS NOT NULL AND (anchor_seconds,anchor_nanos)<=(cfg.watermark_seconds,cfg.watermark_nanos)
   AND NOT EXISTS(SELECT 1 FROM signal_window_history.assessments a WHERE a.partition_id=cfg.partition_id AND a.state_key=cfg.state_key AND a.id=identity) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  pending_ids:=array_append(pending_ids,identity);
  INSERT INTO signal_window_history.assessments VALUES(cfg.partition_id,cfg.state_key,identity,(state_value->>'checkpoint')::bigint,now_ms,now_ms+cfg.retention_ms,payload,identity) ON CONFLICT(partition_id,state_key,id) DO NOTHING;
 END LOOP;
 -- A retained output pins its original custody record even after expiry. Reads
 -- must withhold expired evidence; replay never grants it another retention term.
 DELETE FROM signal_window_history.assessments a WHERE a.partition_id=cfg.partition_id AND a.state_key=cfg.state_key AND a.expires_at_ms<=now_ms AND NOT (a.id=ANY(pending_ids));
 SELECT count(*),coalesce(sum(256+octet_length(a.payload)),0) INTO count_rows,count_bytes FROM signal_window_history.assessments a WHERE a.partition_id=cfg.partition_id AND a.state_key=cfg.state_key;
 IF count_rows>cfg.max_rows OR count_bytes>cfg.max_bytes THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 UPDATE signal_window_history.profile SET used_rows=count_rows,used_bytes=count_bytes,
  watermark_seconds=next_watermark_seconds,watermark_nanos=next_watermark_nanos WHERE partition_id=cfg.partition_id AND state_key=cfg.state_key;
 RETURN NEW;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_parameter_value OR invalid_datetime_format OR datetime_field_overflow THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_window_history.archive_publication() FROM PUBLIC;
CREATE TRIGGER archive_window_publication AFTER INSERT ON signal_multi_event.requests FOR EACH ROW EXECUTE FUNCTION signal_window_history.archive_publication();
COMMIT;

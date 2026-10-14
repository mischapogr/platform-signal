-- Explicit stopped owner installation; no automatic runtime grants.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_window_history') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_window_history_read;
REVOKE ALL ON SCHEMA signal_window_history_read FROM PUBLIC;
CREATE FUNCTION signal_window_history_read.read_page(t jsonb,r jsonb,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;cfg signal_window_history.profile;s signal_control.state;
 state_value jsonb;source_binding jsonb;policy jsonb;record signal_window_history.assessments;
 state_sha text;profile_sha text;c jsonb;result jsonb;entry jsonb;items jsonb:='[]'::jsonb;next_cursor jsonb;
 row_limit integer;byte_limit integer;used_bytes integer:=2048;row_count bigint;byte_count bigint;
 now_ms bigint;truncated boolean:=false;expired boolean;before_checkpoint bigint;before_id bytea;
BEGIN
 IF r IS NULL OR octet_length(r::text)>8192 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','key','head','limit','max_bytes','cursor']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'key') IS DISTINCT FROM 'string'
  OR octet_length(r->>'key') NOT BETWEEN 1 AND 256 OR r->>'key' ~ '[[:cntrl:]]'
  OR jsonb_typeof(r->'head') IS DISTINCT FROM 'string' OR (r->>'head')::uuid='00000000-0000-0000-0000-000000000000'::uuid
  OR jsonb_typeof(r->'limit') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'max_bytes') IS DISTINCT FROM 'number'
  OR jsonb_typeof(r->'cursor') NOT IN ('object','null') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 row_limit:=(r->>'limit')::integer;byte_limit:=(r->>'max_bytes')::integer;
 IF row_limit NOT BETWEEN 1 AND 128 OR byte_limit NOT BETWEEN 4096 AND 1048576 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF p.head IS DISTINCT FROM (r->>'head')::uuid THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 SELECT * INTO cfg FROM signal_window_history.profile WHERE partition_id=p.id AND state_key=r->>'key';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=cfg.state_key;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 state_value:=convert_from(s.value,'UTF8')::jsonb;
 source_binding:=(state_value->'metadata')-'window'-'canonical_sha256';
 policy:=state_value->'metadata'->'window'->'state'->'policy';
 IF state_value->>'scope_generation' IS DISTINCT FROM cfg.scope_generation::text
  OR source_binding->>'source_store' IS DISTINCT FROM t->'scope'->>'store_id'
  OR source_binding->>'source_partition' IS DISTINCT FROM p.id::text
  OR source_binding->>'source_tenant' IS DISTINCT FROM p.tenant
  OR source_binding->>'source_stream' IS DISTINCT FROM p.stream::text
  OR (state_value->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR (policy->>'max_history_assessments')::bigint IS DISTINCT FROM cfg.max_rows
  OR (policy->>'max_history_bytes')::bigint IS DISTINCT FROM cfg.max_bytes
  OR (policy->>'history_retention_ms')::bigint IS DISTINCT FROM cfg.retention_ms THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 SELECT count(*),coalesce(sum(256+octet_length(a.payload)),0) INTO row_count,byte_count
  FROM signal_window_history.assessments a WHERE a.partition_id=p.id AND a.state_key=cfg.state_key;
 IF row_count<>cfg.used_rows OR byte_count<>cfg.used_bytes OR row_count>cfg.max_rows OR byte_count>cfg.max_bytes
  OR EXISTS(SELECT 1 FROM signal_window_history.assessments a WHERE a.partition_id=p.id AND a.state_key=cfg.state_key
   AND (a.id<>sha256(a.payload) OR a.payload_sha256<>sha256(a.payload) OR a.checkpoint>p.checkpoint OR a.recorded_at_ms>now_ms
    OR a.expires_at_ms::numeric<>a.recorded_at_ms::numeric+cfg.retention_ms
    OR convert_from(a.payload,'UTF8')::jsonb->'schema_version' IS DISTINCT FROM '1'::jsonb
    OR convert_from(a.payload,'UTF8')::jsonb->>'scope_generation' IS DISTINCT FROM cfg.scope_generation::text
    OR convert_from(a.payload,'UTF8')::jsonb->'source' IS DISTINCT FROM source_binding
    OR convert_from(a.payload,'UTF8')::jsonb->'policy' IS DISTINCT FROM policy)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 state_sha:=encode(sha256(s.value),'hex');
 -- Include the complete bounded inventory, so owner rewrites cannot silently
 -- change an already issued page position even with recomputed row checksums.
 SELECT encode(sha256(convert_to(jsonb_build_object('profile',to_jsonb(cfg),'rows',coalesce(jsonb_agg(encode(sha256(convert_to(to_jsonb(a)::text,'UTF8')),'hex') ORDER BY a.id),'[]'::jsonb))::text,'UTF8')),'hex')
  INTO profile_sha FROM signal_window_history.assessments a WHERE a.partition_id=p.id AND a.state_key=cfg.state_key;
 c:=r->'cursor';
 IF c<>'null'::jsonb THEN
  PERFORM signal_control.require_keys(c,ARRAY['schema_version','scope','key','head','state_sha','profile_sha','checkpoint','id']);
  IF c->'schema_version' IS DISTINCT FROM '1'::jsonb OR c->'scope' IS DISTINCT FROM t->'scope'
   OR c->'key' IS DISTINCT FROM r->'key' OR c->'head' IS DISTINCT FROM r->'head'
   OR c->>'state_sha' IS DISTINCT FROM state_sha OR c->>'profile_sha' IS DISTINCT FROM profile_sha
   OR jsonb_typeof(c->'checkpoint') IS DISTINCT FROM 'number' OR c->>'id'!~'^[0-9a-f]{64}$' THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  before_checkpoint:=(c->>'checkpoint')::bigint;before_id:=decode(c->>'id','hex');
  IF NOT EXISTS(SELECT 1 FROM signal_window_history.assessments a WHERE a.partition_id=p.id AND a.state_key=cfg.state_key AND a.checkpoint=before_checkpoint AND a.id=before_id) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 FOR record IN SELECT a.* FROM signal_window_history.assessments a WHERE a.partition_id=p.id AND a.state_key=cfg.state_key
  AND (before_checkpoint IS NULL OR (a.checkpoint,a.id)<(before_checkpoint,before_id)) ORDER BY a.checkpoint DESC,a.id DESC LIMIT row_limit+1 LOOP
  IF jsonb_array_length(items)>=row_limit THEN truncated:=true;EXIT; END IF;
  expired:=record.expires_at_ms<=now_ms;
  entry:=jsonb_build_object('id',encode(record.id,'hex'),'checkpoint',record.checkpoint,'recorded_at_ms',record.recorded_at_ms,'expires_at_ms',record.expires_at_ms,'expired',expired,'payload',CASE WHEN expired THEN NULL ELSE encode(record.payload,'hex') END);
  IF used_bytes+octet_length(entry::text)>byte_limit THEN
   IF jsonb_array_length(items)=0 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
   truncated:=true;EXIT;
  END IF;
  used_bytes:=used_bytes+octet_length(entry::text);items:=items||jsonb_build_array(entry);
  next_cursor:=jsonb_build_object('schema_version',1,'scope',t->'scope','key',cfg.state_key,'head',p.head,'state_sha',state_sha,'profile_sha',profile_sha,'checkpoint',record.checkpoint,'id',encode(record.id,'hex'));
 END LOOP;
 result:=jsonb_build_object('schema_version',1,'scope',t->'scope','key',cfg.state_key,'head',p.head,'checkpoint',p.checkpoint,'state_sha',state_sha,'profile_sha',profile_sha,'retained_rows',cfg.used_rows,'retained_bytes',cfg.used_bytes,'read_at_ms',now_ms,'lease_remaining_ms',floor(extract(epoch FROM p.lease_until-clock_timestamp())*1000)::bigint,'records',items,'truncated',truncated,'cursor',CASE WHEN truncated THEN next_cursor ELSE NULL END);
 IF octet_length(result::text)>byte_limit THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_window_history_read.read_page(jsonb,jsonb,bytea,bytea) FROM PUBLIC;
COMMIT;

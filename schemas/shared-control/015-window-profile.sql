-- Explicit stopped owner installation, without enrollment or runtime grants.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_replay_release') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_window_profile;
REVOKE ALL ON SCHEMA signal_window_profile FROM PUBLIC;
CREATE FUNCTION signal_window_profile.inspect(t jsonb,r jsonb,expected_schema bytea,expected_routines bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;cfg signal_window_history.profile;present boolean;
BEGIN
 IF r IS NULL OR octet_length(r::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','key','head','scope_generation','history_rows','history_bytes','retention_ms','bootstrap_checkpoint']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'key') IS DISTINCT FROM 'string'
  OR octet_length(r->>'key') NOT BETWEEN 1 AND 256 OR r->>'key' ~ '[[:cntrl:]]'
  OR jsonb_typeof(r->'head') NOT IN ('string','null')
  OR jsonb_typeof(r->'scope_generation') IS DISTINCT FROM 'string'
  OR jsonb_typeof(r->'history_rows') IS DISTINCT FROM 'number' OR (r->>'history_rows')::bigint NOT BETWEEN 1 AND 16384
  OR jsonb_typeof(r->'history_bytes') IS DISTINCT FROM 'number' OR (r->>'history_bytes')::bigint NOT BETWEEN 4096 AND 33554432
  OR jsonb_typeof(r->'retention_ms') IS DISTINCT FROM 'number' OR (r->>'retention_ms')::bigint NOT BETWEEN 1 AND 31536000000
  OR jsonb_typeof(r->'bootstrap_checkpoint') NOT IN ('number','null') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF p.head IS DISTINCT FROM (r->>'head')::uuid THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['signal_state_read','signal_multi_event','signal_replay_transfer','signal_window_history_read','signal_replay_release','signal_window_profile','signal_finding_lookup','signal_window_pin']) n WHERE NOT has_schema_privilege(session_user,n,'USAGE'))
  OR EXISTS(SELECT 1 FROM unnest(ARRAY[
   'signal_state_read.read_state(jsonb,text,uuid,bytea,bytea)',
   'signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea)',
   'signal_replay_transfer.release_replaced(jsonb,bytea,bytea,bytea)',
   'signal_window_history_read.read_page(jsonb,jsonb,bytea,bytea)',
   'signal_replay_release.release_obsolete(jsonb,bytea,bytea,bytea)',
   'signal_finding_lookup.known(jsonb,jsonb,bytea,bytea)',
   'signal_window_pin.retain(jsonb,bytea,bytea,bytea)']) n WHERE NOT has_function_privilege(session_user,n,'EXECUTE')) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO cfg FROM signal_window_history.profile WHERE partition_id=p.id AND state_key=r->>'key' FOR UPDATE;
 IF NOT FOUND OR cfg.scope_generation IS DISTINCT FROM (r->>'scope_generation')::uuid
  OR cfg.max_rows IS DISTINCT FROM (r->>'history_rows')::bigint
  OR cfg.max_bytes IS DISTINCT FROM (r->>'history_bytes')::bigint
  OR cfg.retention_ms IS DISTINCT FROM (r->>'retention_ms')::bigint
  OR NOT EXISTS(SELECT 1 FROM signal_finding_scope.producers q WHERE q.partition_id=p.id AND q.scope_generation=cfg.scope_generation) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT EXISTS(SELECT 1 FROM signal_control.state s WHERE s.partition_id=p.id AND s.key=cfg.state_key) INTO present;
 IF present THEN
  PERFORM signal_window_history_read.read_page(t,jsonb_build_object('schema_version',1,'key',cfg.state_key,'head',p.head,'limit',1,'max_bytes',1048576,'cursor',NULL),expected_schema,expected_routines);
 ELSE
  IF r->'bootstrap_checkpoint'='null'::jsonb OR (r->>'bootstrap_checkpoint')::bigint IS DISTINCT FROM p.checkpoint
   OR cfg.used_rows<>0 OR cfg.used_bytes<>0 OR cfg.watermark_seconds IS NOT NULL OR cfg.watermark_nanos IS NOT NULL
   OR EXISTS(SELECT 1 FROM signal_window_history.assessments a WHERE a.partition_id=p.id AND a.state_key=cfg.state_key) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 END IF;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_window_profile.inspect(jsonb,jsonb,bytea,bytea) FROM PUBLIC;
COMMIT;

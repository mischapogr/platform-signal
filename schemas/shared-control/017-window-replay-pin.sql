-- Explicit stopped installation. No lifecycle or owner authority is granted.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_window_pin;
REVOKE ALL ON SCHEMA signal_window_pin FROM PUBLIC;
CREATE FUNCTION signal_window_pin.retain(t jsonb,raw bytea,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;r jsonb;proof jsonb;s signal_control.state;envelope jsonb;
 revision_json jsonb;value_json jsonb;result jsonb;
BEGIN
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 16384 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 r:=convert_from(raw,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','id','object','kind','reference']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR r->>'operation' IS DISTINCT FROM 'pin'
  OR r->>'kind' IS DISTINCT FROM 'replay' THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 proof:=convert_from(signal_control.hex_bytes(r->'reference',4096),'UTF8')::jsonb;
 PERFORM signal_control.require_keys(proof,ARRAY['schema_version','scope','state_key','rule_revision','metadata_sha256','object','object_bytes','object_sha256']);
 IF proof->'schema_version' IS DISTINCT FROM '1'::jsonb OR proof->'scope' IS DISTINCT FROM t->'scope'
  OR proof->'object' IS DISTINCT FROM r->'object'
  OR jsonb_typeof(proof->'state_key') IS DISTINCT FROM 'string' OR octet_length(proof->>'state_key') NOT BETWEEN 1 AND 256 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=proof->>'state_key' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT jsonb_agg(get_byte(s.revision,i) ORDER BY i),jsonb_agg(get_byte(sha256(s.value),i) ORDER BY i)
  INTO revision_json,value_json FROM generate_series(0,31) i;
 envelope:=convert_from(s.value,'UTF8')::jsonb;
 IF proof->'rule_revision' IS DISTINCT FROM revision_json OR proof->'metadata_sha256' IS DISTINCT FROM value_json
  OR envelope->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR envelope#>'{metadata,schema_version}' IS DISTINCT FROM '1'::jsonb
  OR envelope#>'{metadata,window,schema_version}' IS DISTINCT FROM '1'::jsonb
  OR (envelope->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR NOT EXISTS(SELECT 1 FROM signal_window_history.profile h WHERE h.partition_id=p.id AND h.state_key=s.key
    AND h.scope_generation=(envelope->>'scope_generation')::uuid) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 -- The exact object/version, length and digest must belong to a committed
 -- manifest in this partition; arbitrary object pins cannot be manufactured.
 IF (SELECT count(*) FROM signal_control.commits WHERE partition_id=p.id)>128 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 IF EXISTS(SELECT 1 FROM signal_control.commits c WHERE c.partition_id=p.id
   AND c.manifest_sha256<>sha256(c.manifest)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 IF NOT EXISTS(SELECT 1 FROM signal_control.commits c,
    LATERAL jsonb_array_elements(convert_from(c.manifest,'UTF8')::jsonb->'files') f
    WHERE c.partition_id=p.id AND c.backend_id=(r->'object'->>'backend_id')::uuid
      AND f->'object'->'key'=r->'object'->'key' AND f->'object'->'version'=r->'object'->'version'
      AND f->'object'->'bytes'=proof->'object_bytes' AND f->'object'->'sha256'=proof->'object_sha256') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 result:=signal_control.object_control(t,raw,expected_schema,expected_routines);
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_window_pin.retain(jsonb,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;

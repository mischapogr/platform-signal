-- Explicit stopped installation; no grants or activation are synthesized.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_replay_transfer;
REVOKE ALL ON SCHEMA signal_replay_transfer FROM PUBLIC;
CREATE FUNCTION signal_replay_transfer.release_replaced(t jsonb,raw bytea,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions; old signal_control.object_pins; replacement signal_control.object_pins;
 s signal_control.state; r jsonb;old_ref jsonb;new_ref jsonb;revision_json jsonb;value_json jsonb;core_raw bytea;result jsonb;
BEGIN
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 r:=convert_from(raw,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','id','replacement','state_key','expected_head','revision','value_sha256']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(r->'replacement') IS DISTINCT FROM 'string' OR (r->>'id')::uuid=(r->>'replacement')::uuid
  OR (r->>'id')::uuid='00000000-0000-0000-0000-000000000000'::uuid OR (r->>'replacement')::uuid='00000000-0000-0000-0000-000000000000'::uuid
  OR jsonb_typeof(r->'state_key') IS DISTINCT FROM 'string' OR octet_length(r->>'state_key') NOT BETWEEN 1 AND 256 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 IF p.head IS DISTINCT FROM (r->>'expected_head')::uuid THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=r->>'state_key' FOR UPDATE;
 IF NOT FOUND OR s.revision IS DISTINCT FROM signal_control.hex_bytes(r->'revision',32)
  OR sha256(s.value) IS DISTINCT FROM signal_control.hex_bytes(r->'value_sha256',32)
  OR (convert_from(s.value,'UTF8')::jsonb->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO old FROM signal_control.object_pins WHERE partition_id=p.id AND id=(r->>'id')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO replacement FROM signal_control.object_pins WHERE partition_id=p.id AND id=(r->>'replacement')::uuid FOR UPDATE;
 IF NOT FOUND OR replacement.state<>'retained' OR replacement.kind<>'replay' OR old.kind<>'replay'
  OR old.object_reference IS DISTINCT FROM replacement.object_reference OR old.reference_sha256 IS DISTINCT FROM replacement.reference_sha256
  OR old.request_sha256<>sha256(old.request) OR replacement.request_sha256<>sha256(replacement.request) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 old_ref:=convert_from(signal_control.hex_bytes(convert_from(old.request,'UTF8')::jsonb->'reference',4096),'UTF8')::jsonb;
 new_ref:=convert_from(signal_control.hex_bytes(convert_from(replacement.request,'UTF8')::jsonb->'reference',4096),'UTF8')::jsonb;
 SELECT jsonb_agg(get_byte(s.revision,i) ORDER BY i),jsonb_agg(get_byte(sha256(s.value),i) ORDER BY i) INTO revision_json,value_json FROM generate_series(0,31) i;
 IF old_ref->'schema_version' IS DISTINCT FROM '1'::jsonb OR new_ref->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR old_ref->>'state_key' IS DISTINCT FROM r->>'state_key' OR new_ref->>'state_key' IS DISTINCT FROM r->>'state_key'
  OR old_ref->'rule_revision' IS DISTINCT FROM revision_json OR new_ref->'rule_revision' IS DISTINCT FROM revision_json
  OR new_ref->'metadata_sha256' IS DISTINCT FROM value_json OR new_ref->'scope' IS DISTINCT FROM t->'scope'
  OR old_ref->'object' IS DISTINCT FROM new_ref->'object' OR old_ref->'object_bytes' IS DISTINCT FROM new_ref->'object_bytes'
  OR old_ref->'object_sha256' IS DISTINCT FROM new_ref->'object_sha256'
  OR old_ref->'scope'->>'store_id' IS DISTINCT FROM t->'scope'->>'store_id'
  OR old_ref->'scope'->>'tenant' IS DISTINCT FROM t->'scope'->>'tenant'
  OR old_ref->'scope'->>'stream' IS DISTINCT FROM t->'scope'->>'stream'
  OR old_ref->'scope'->>'partition_id' IS DISTINCT FROM p.id::text THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 core_raw:=convert_to(jsonb_build_object('schema_version',1,'operation','release','id',r->>'id','reason',encode(raw,'hex'))::text,'UTF8');
 result:=signal_control.object_control(t,core_raw,expected_schema,expected_routines);
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result||jsonb_build_object('request_sha256',encode(sha256(raw),'hex'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_replay_transfer.release_replaced(jsonb,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;

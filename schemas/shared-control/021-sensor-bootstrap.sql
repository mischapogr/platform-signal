-- Explicit stopped installation. Runtime initialization requires an empty key
-- and an owner-selected current checkpoint; never advances event publication.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_sensor_bootstrap;
REVOKE ALL ON SCHEMA signal_sensor_bootstrap FROM PUBLIC;
CREATE FUNCTION signal_sensor_bootstrap.initialize(t jsonb,raw bytea,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;s signal_control.state;r jsonb;value jsonb;frame jsonb;v jsonb;
 payload bytea;revision bytea;revision_json jsonb;charge bigint;result jsonb;
BEGIN
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 262144 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 r:=convert_from(raw,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','head','checkpoint','state']);
 v:=r->'state';PERFORM signal_control.require_keys(v,ARRAY['key','revision','bytes']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR jsonb_typeof(r->'head') NOT IN ('string','null') OR (r->>'head')::uuid IS DISTINCT FROM p.head
  OR jsonb_typeof(r->'checkpoint') IS DISTINCT FROM 'number' OR (r->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR jsonb_typeof(v->'key') IS DISTINCT FROM 'string' OR octet_length(v->>'key') NOT BETWEEN 1 AND 256
  OR v->>'key' ~ '[[:cntrl:]]' THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 revision:=signal_control.hex_bytes(v->'revision',32);payload:=signal_control.hex_bytes(v->'bytes',65536);
 IF octet_length(revision)<>32 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 SELECT jsonb_agg(get_byte(revision,i) ORDER BY i) INTO revision_json FROM generate_series(0,31) i;
 value:=convert_from(payload,'UTF8')::jsonb;frame:=value#>'{metadata,sensor,snapshot,record}';
 IF value->'schema_version' IS DISTINCT FROM '1'::jsonb OR (value->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR value->'canonical_sequences' IS DISTINCT FROM '{}'::jsonb
  OR value#>'{metadata,canonical_sha256}' IS DISTINCT FROM '{}'::jsonb
  OR value#>'{metadata,sensor,canonical_sha256}' IS DISTINCT FROM '{}'::jsonb
  OR value#>'{metadata,schema_version}' IS DISTINCT FROM '1'::jsonb
  OR value#>'{metadata,sensor,schema_version}' IS DISTINCT FROM '1'::jsonb
  OR value#>'{metadata,scope}' IS DISTINCT FROM t->'scope'
  OR value#>'{metadata,rule_revision}' IS DISTINCT FROM revision_json
  OR value#>>'{metadata,key}' IS DISTINCT FROM v->>'key'
  OR value#>>'{metadata,sensor,snapshot,stream}' IS DISTINCT FROM t#>>'{scope,stream}'
  OR frame->'schema_version' IS DISTINCT FROM '1'::jsonb OR frame->'revision' IS DISTINCT FROM '1'::jsonb
  OR (frame->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR frame->'outbox' IS DISTINCT FROM '[]'::jsonb
  OR frame#>'{state,proofs}' IS DISTINCT FROM '[]'::jsonb
  OR frame#>'{state,known}' IS DISTINCT FROM '[]'::jsonb
  OR jsonb_typeof(frame#>'{state,monitor,slots}') IS DISTINCT FROM 'array'
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(frame#>'{state,monitor,slots}') slot
    WHERE slot->'latest' IS DISTINCT FROM 'null'::jsonb OR slot->'heartbeat_at_ms' IS DISTINCT FROM 'null'::jsonb OR slot->'checkpoint' IS DISTINCT FROM 'null'::jsonb)
  OR NOT EXISTS(SELECT 1 FROM signal_multi_event.profile h JOIN signal_finding_scope.activation a USING(scope_generation)
    JOIN signal_finding_scope.producers producer ON producer.scope_generation=h.scope_generation AND producer.partition_id=p.id
    WHERE h.singleton AND a.singleton AND h.scope_generation=(value->>'scope_generation')::uuid
      AND a.store_id=(t->'scope'->>'store_id')::uuid AND a.store_generation=(t->'scope'->>'generation')::uuid) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=v->>'key' FOR UPDATE;
 IF FOUND THEN
  IF s.revision<>revision OR s.value<>payload THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 ELSE
  charge:=192+octet_length(v->>'key')+octet_length(payload);
  UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+charge
   WHERE singleton AND used_rows<max_rows AND charge<=max_bytes-used_bytes;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
  INSERT INTO signal_control.state(partition_id,key,revision,value) VALUES(p.id,v->>'key',revision,payload);
 END IF;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 result:=jsonb_build_object('schema_version',1,'partition_id',p.id,'head',p.head,'checkpoint',p.checkpoint,
   'state',jsonb_build_object('key',v->>'key','revision',encode(revision,'hex'),'bytes',encode(payload,'hex')));
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_sensor_bootstrap.initialize(jsonb,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;

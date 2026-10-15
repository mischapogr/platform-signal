-- Explicit stopped owner installation. No event/head/checkpoint publication.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_sensor_maintenance;
REVOKE ALL ON SCHEMA signal_sensor_maintenance FROM PUBLIC;
CREATE FUNCTION signal_sensor_maintenance.apply(t jsonb,raw bytea,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;s signal_control.state;r jsonb;prior jsonb;next_state jsonb;old_value jsonb;
 new_value jsonb;old_record jsonb;new_record jsonb;item jsonb;stored signal_control.findings;
 old_outbox jsonb;new_outbox jsonb;tail jsonb;identity uuid;payload jsonb;new_bytes bytea;
 revision_json jsonb;delta bigint;removed bigint;ordinal bigint;result jsonb;
BEGIN
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 1048576 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 r:=convert_from(raw,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','head','prior','state','retired']);
 prior:=r->'prior';next_state:=r->'state';
 PERFORM signal_control.require_keys(prior,ARRAY['schema_version','key','checkpoint','revision','value_sha256','scope_generation']);
 PERFORM signal_control.require_keys(next_state,ARRAY['key','revision','bytes']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR prior->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR jsonb_typeof(r->'head') NOT IN ('string','null') OR (r->>'head')::uuid IS DISTINCT FROM p.head
  OR jsonb_typeof(prior->'key') IS DISTINCT FROM 'string' OR octet_length(prior->>'key') NOT BETWEEN 1 AND 256
  OR prior->'key' IS DISTINCT FROM next_state->'key'
  OR prior->'revision' IS DISTINCT FROM next_state->'revision'
  OR jsonb_typeof(prior->'checkpoint') IS DISTINCT FROM 'number' OR (prior->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR jsonb_typeof(r->'retired') IS DISTINCT FROM 'array' OR jsonb_array_length(r->'retired')>128 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=prior->>'key' FOR UPDATE;
 IF NOT FOUND OR s.revision IS DISTINCT FROM signal_control.hex_bytes(prior->'revision',32) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 new_bytes:=signal_control.hex_bytes(next_state->'bytes',65536);
 old_value:=convert_from(s.value,'UTF8')::jsonb;new_value:=convert_from(new_bytes,'UTF8')::jsonb;
 SELECT jsonb_agg(get_byte(s.revision,i) ORDER BY i) INTO revision_json FROM generate_series(0,31) i;
 IF new_value->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR old_value->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR (new_value->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
  OR new_value->'scope_generation' IS DISTINCT FROM old_value->'scope_generation'
  OR new_value->'scope_generation' IS DISTINCT FROM prior->'scope_generation'
  OR new_value#>'{metadata,schema_version}' IS DISTINCT FROM '1'::jsonb
  OR new_value#>'{metadata,scope}' IS DISTINCT FROM t->'scope'
  OR new_value#>>'{metadata,key}' IS DISTINCT FROM s.key
  OR new_value#>'{metadata,rule_revision}' IS DISTINCT FROM revision_json
  OR ((new_value->'metadata')-'sensor'-'canonical_sha256') IS DISTINCT FROM ((old_value->'metadata')-'sensor'-'canonical_sha256')
  OR new_value#>'{metadata,sensor,schema_version}' IS DISTINCT FROM '1'::jsonb
  OR NOT EXISTS(SELECT 1 FROM signal_multi_event.profile h JOIN signal_finding_scope.activation a USING(scope_generation)
    JOIN signal_finding_scope.producers producer ON producer.scope_generation=h.scope_generation AND producer.partition_id=p.id
    WHERE h.singleton AND a.singleton AND h.scope_generation=(prior->>'scope_generation')::uuid
      AND a.store_id=(t->'scope'->>'store_id')::uuid AND a.store_generation=(t->'scope'->>'generation')::uuid) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 old_record:=old_value#>'{metadata,sensor,snapshot,record}';new_record:=new_value#>'{metadata,sensor,snapshot,record}';
 old_outbox:=old_record->'outbox';new_outbox:=new_record->'outbox';
 IF jsonb_typeof(old_record) IS DISTINCT FROM 'object' OR jsonb_typeof(new_record) IS DISTINCT FROM 'object'
  OR jsonb_typeof(old_outbox) IS DISTINCT FROM 'array' OR jsonb_typeof(new_outbox) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 removed:=jsonb_array_length(r->'retired');
 FOR item,ordinal IN SELECT x,n FROM jsonb_array_elements(r->'retired') WITH ORDINALITY a(x,n) LOOP
  PERFORM signal_control.require_keys(item,ARRAY['id','payload']);identity:=(item->>'id')::uuid;payload:=item->'payload';
  SELECT * INTO stored FROM signal_control.findings WHERE id=identity;
  IF NOT FOUND OR stored.partition_id<>p.id THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  IF stored.content_sha256<>sha256(stored.content) THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  IF payload IS DISTINCT FROM convert_from(stored.content,'UTF8')::jsonb THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  -- On exact target-state replay the original prefix is already gone. Confirm
  -- original stored bodies anyway; never turn an echo into a new publication.
  IF s.value<>new_bytes AND (old_outbox->(ordinal::integer-1)->>'id' IS DISTINCT FROM identity::text
    OR (payload#-'{attributes,signal.scope.v1}') IS DISTINCT FROM old_outbox->(ordinal::integer-1)#>'{bytes,finding}') THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 END LOOP;
 IF s.value<>new_bytes THEN
  IF sha256(s.value) IS DISTINCT FROM signal_control.hex_bytes(prior->'value_sha256',32)
   OR removed>jsonb_array_length(old_outbox)
   OR (new_record->>'revision')::bigint IS DISTINCT FROM (old_record->>'revision')::bigint+1
   OR new_record->'checkpoint' IS DISTINCT FROM old_record->'checkpoint'
   OR (new_record->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
   OR ((new_value#>'{metadata,sensor,snapshot}')-'record') IS DISTINCT FROM ((old_value#>'{metadata,sensor,snapshot}')-'record')
   OR (new_record-'revision'-'outbox'-'state') IS DISTINCT FROM (old_record-'revision'-'outbox'-'state')
   OR ((new_record->'state')-'history'-'monitor') IS DISTINCT FROM ((old_record->'state')-'history'-'monitor')
   OR ((new_record#>'{state,monitor}')-'clock_ms') IS DISTINCT FROM ((old_record#>'{state,monitor}')-'clock_ms')
   OR jsonb_typeof(new_record#>'{state,monitor,clock_ms}') IS DISTINCT FROM 'number'
   OR (new_record#>>'{state,monitor,clock_ms}')::bigint<(old_record#>>'{state,monitor,clock_ms}')::bigint THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  SELECT coalesce(jsonb_agg(x ORDER BY n),'[]'::jsonb) INTO tail FROM jsonb_array_elements(old_outbox) WITH ORDINALITY a(x,n) WHERE n>removed;
  IF new_outbox IS DISTINCT FROM tail THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  IF jsonb_typeof(new_value->'canonical_sequences') IS DISTINCT FROM 'object'
   OR jsonb_typeof(new_value#>'{metadata,canonical_sha256}') IS DISTINCT FROM 'object'
   OR new_value#>'{metadata,canonical_sha256}' IS DISTINCT FROM new_value#>'{metadata,sensor,canonical_sha256}'
   OR EXISTS(SELECT 1 FROM jsonb_each(new_value->'canonical_sequences') e WHERE e.value IS DISTINCT FROM old_value->'canonical_sequences'->e.key
       OR new_value#>'{metadata,canonical_sha256}'->e.key IS DISTINCT FROM old_value#>'{metadata,canonical_sha256}'->e.key)
   OR (SELECT count(*) FROM jsonb_object_keys(new_value->'canonical_sequences'))<>(SELECT count(*) FROM jsonb_object_keys(new_value#>'{metadata,canonical_sha256}')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  delta:=octet_length(new_bytes)-octet_length(s.value);
  UPDATE signal_control.store SET used_bytes=used_bytes+delta WHERE singleton AND (delta<=0 OR delta<=max_bytes-used_bytes);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
  UPDATE signal_control.state SET value=new_bytes WHERE partition_id=p.id AND key=s.key;
 END IF;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 result:=jsonb_build_object('schema_version',1,'partition_id',p.id,'head',p.head,'checkpoint',p.checkpoint,
  'state',jsonb_build_object('key',s.key,'revision',encode(s.revision,'hex'),'bytes',encode(new_bytes,'hex')));
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;

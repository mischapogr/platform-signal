-- Stopped explicit owner installation. This releases a replay pin, never objects.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_window_history_read') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_replay_release;
REVOKE ALL ON SCHEMA signal_replay_release FROM PUBLIC;
CREATE FUNCTION signal_replay_release.release_obsolete(t jsonb,raw bytea,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;pin signal_control.object_pins;s signal_control.state;
 r jsonb;original jsonb;ref jsonb;state_value jsonb;frame jsonb;entry record;c signal_control.commits;
 sequences bigint[];object_hash bytea;known boolean:=false;core_raw bytea;result jsonb;revision_json jsonb;
BEGIN
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 r:=convert_from(raw,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','id','catalog_id','state_key','expected_head','revision','value_sha256']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'state_key') IS DISTINCT FROM 'string'
  OR octet_length(r->>'state_key') NOT BETWEEN 1 AND 256 OR r->>'state_key' ~ '[[:cntrl:]]'
  OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string' OR (r->>'id')::uuid='00000000-0000-0000-0000-000000000000'::uuid
  OR jsonb_typeof(r->'catalog_id') IS DISTINCT FROM 'string' OR (r->>'catalog_id')::uuid='00000000-0000-0000-0000-000000000000'::uuid
  OR jsonb_typeof(r->'expected_head') IS DISTINCT FROM 'string' OR (r->>'expected_head')::uuid='00000000-0000-0000-0000-000000000000'::uuid THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 PERFORM signal_control.hex_bytes(r->'revision',32);PERFORM signal_control.hex_bytes(r->'value_sha256',32);
 SELECT * INTO pin FROM signal_control.object_pins WHERE partition_id=p.id AND id=(r->>'id')::uuid FOR UPDATE;
 IF NOT FOUND OR pin.kind<>'replay' OR pin.request_sha256<>sha256(pin.request) OR pin.reference_sha256<>sha256(pin.object_reference) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 original:=convert_from(pin.request,'UTF8')::jsonb;
 ref:=convert_from(signal_control.hex_bytes(original->'reference',4096),'UTF8')::jsonb;
 SELECT jsonb_agg(get_byte(signal_control.hex_bytes(r->'revision',32),i) ORDER BY i) INTO revision_json FROM generate_series(0,31) i;
 IF ref->'schema_version' IS DISTINCT FROM '1'::jsonb OR ref->>'state_key' IS DISTINCT FROM r->>'state_key'
  OR ref->'rule_revision' IS DISTINCT FROM revision_json
  OR ref->'scope'->>'store_id' IS DISTINCT FROM t->'scope'->>'store_id'
  OR ref->'scope'->>'tenant' IS DISTINCT FROM p.tenant OR ref->'scope'->>'stream' IS DISTINCT FROM p.stream::text
  OR ref->'scope'->>'partition_id' IS DISTINCT FROM p.id::text OR ref->'object' IS DISTINCT FROM original->'object'
  OR signal_control.object_reference(ref->'object') IS DISTINCT FROM pin.object_reference THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 core_raw:=convert_to(jsonb_build_object('schema_version',1,'operation','release','id',r->>'id','reason',encode(raw,'hex'))::text,'UTF8');
 -- Existing-only replay resolves an original uncertain release after the catalog
 -- pin expires or the head advances. It cannot authorize another mutation.
 IF pin.state='released' THEN
  result:=signal_control.object_control(t,core_raw,expected_schema,expected_routines);
  RETURN result||jsonb_build_object('request_sha256',encode(sha256(raw),'hex'));
 END IF;
 IF p.head IS DISTINCT FROM (r->>'expected_head')::uuid THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=r->>'state_key' FOR UPDATE;
 IF NOT FOUND OR s.revision IS DISTINCT FROM signal_control.hex_bytes(r->'revision',32)
  OR sha256(s.value) IS DISTINCT FROM signal_control.hex_bytes(r->'value_sha256',32) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF (SELECT count(*) FROM (SELECT 1 FROM signal_control.state WHERE partition_id=p.id LIMIT 129) x)>128
  OR (SELECT count(*) FROM (SELECT 1 FROM signal_window_history.profile WHERE partition_id=p.id LIMIT 129) x)>128
  OR (SELECT count(*) FROM (SELECT 1 FROM signal_window_history.assessments WHERE partition_id=p.id LIMIT 65537) x)>65536
  OR (SELECT coalesce(sum(octet_length(payload)),0) FROM signal_window_history.assessments WHERE partition_id=p.id)>67108864 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 IF EXISTS(SELECT 1 FROM signal_window_history.profile h WHERE h.partition_id=p.id AND NOT EXISTS(SELECT 1 FROM signal_control.state st WHERE st.partition_id=p.id AND st.key=h.state_key)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 -- The existing dynamic catalog validates the complete bounded commit chain,
 -- original requests/manifests, exact backend object sets and integrity seals.
 PERFORM signal_control.read_catalog_snapshot(t->'scope',(r->>'catalog_id')::uuid,5000,expected_schema,expected_routines);
 FOR s IN SELECT * FROM signal_control.state WHERE partition_id=p.id LOOP
  state_value:=convert_from(s.value,'UTF8')::jsonb;
  IF state_value->'schema_version' IS DISTINCT FROM '1'::jsonb OR (state_value->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint
   OR jsonb_typeof(state_value->'canonical_sequences') IS DISTINCT FROM 'object'
   OR jsonb_typeof(state_value->'metadata'->'canonical_sha256') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  -- Validate the entire per-key archive, even though only one row is returned.
  -- No expired retained row is ignored by the accounting below.
  PERFORM signal_window_history_read.read_page(t,jsonb_build_object('schema_version',1,'key',s.key,'head',p.head,'limit',1,'max_bytes',1048576,'cursor',NULL),expected_schema,expected_routines);
 END LOOP;
 FOR frame IN
  SELECT jsonb_build_object('map',v->'canonical_sequences','hashes',v->'metadata'->'canonical_sha256','history',false)
   FROM (SELECT convert_from(value,'UTF8')::jsonb v FROM signal_control.state WHERE partition_id=p.id) x
  UNION ALL
  SELECT jsonb_build_object('map',v->'canonical_sequences','hashes',v->'canonical_sha256','history',true,'ids',v->'assessment'->'event_ids','outcome',v->'assessment'->>'outcome')
   FROM (SELECT convert_from(payload,'UTF8')::jsonb v FROM signal_window_history.assessments WHERE partition_id=p.id) x
 LOOP
  IF jsonb_typeof(frame->'map') IS DISTINCT FROM 'object' OR jsonb_typeof(frame->'hashes') IS DISTINCT FROM 'object'
   OR (SELECT count(*) FROM jsonb_object_keys(frame->'map'))>4096
   OR (SELECT count(*) FROM jsonb_object_keys(frame->'map'))<>(SELECT count(*) FROM jsonb_object_keys(frame->'hashes')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  IF frame->'history'='true'::jsonb THEN
   IF jsonb_typeof(frame->'ids') IS DISTINCT FROM 'array' OR jsonb_array_length(frame->'ids')>1000
    OR frame->>'outcome' IS NULL OR frame->>'outcome' NOT IN ('match','no_match','indeterminate')
    OR (frame->>'outcome'='match' AND jsonb_array_length(frame->'ids')=0)
    OR jsonb_array_length(frame->'ids')<>(SELECT count(*) FROM jsonb_object_keys(frame->'map'))
    OR jsonb_array_length(frame->'ids')<>(SELECT count(DISTINCT x) FROM jsonb_array_elements(frame->'ids') x)
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(frame->'ids') x WHERE jsonb_typeof(x)<>'string' OR NOT (frame->'map' ? (x#>>'{}'))) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  END IF;
  FOR entry IN SELECT key,value FROM jsonb_each(frame->'map') LOOP
   IF entry.key IS DISTINCT FROM (entry.key::uuid)::text OR entry.key::uuid='00000000-0000-0000-0000-000000000000'::uuid
    OR jsonb_typeof(entry.value) IS DISTINCT FROM 'number' OR entry.value::text!~'^[0-9]+$'
    OR entry.value::text::bigint NOT BETWEEN 1 AND p.checkpoint
    OR jsonb_typeof(frame->'hashes'->entry.key) IS DISTINCT FROM 'array' OR jsonb_array_length(frame->'hashes'->entry.key)<>32
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(frame->'hashes'->entry.key) b WHERE jsonb_typeof(b)<>'number' OR b::text!~'^[0-9]+$' OR b::text::bigint NOT BETWEEN 0 AND 255) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  END LOOP;
 END LOOP;
 SELECT ARRAY(SELECT DISTINCT sequence FROM (
  SELECT m.value::text::bigint AS sequence FROM signal_control.state st CROSS JOIN LATERAL jsonb_each(convert_from(st.value,'UTF8')::jsonb->'canonical_sequences') m WHERE st.partition_id=p.id
  UNION ALL
  SELECT m.value::text::bigint FROM signal_window_history.assessments a CROSS JOIN LATERAL jsonb_each(convert_from(a.payload,'UTF8')::jsonb->'canonical_sequences') m WHERE a.partition_id=p.id
 ) x LIMIT 65537) INTO sequences;
 IF cardinality(sequences)>65536 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 object_hash:=pin.reference_sha256;
 FOR c IN SELECT * FROM signal_control.commits WHERE partition_id=p.id LOOP
  IF object_hash=ANY(c.object_hashes) THEN
   known:=true;
   IF EXISTS(SELECT 1 FROM unnest(sequences) n WHERE n BETWEEN c.first_sequence AND c.last_sequence) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  END IF;
 END LOOP;
 IF NOT known THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 result:=signal_control.object_control(t,core_raw,expected_schema,expected_routines);
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result||jsonb_build_object('request_sha256',encode(sha256(raw),'hex'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_replay_release.release_obsolete(jsonb,bytea,bytea,bytea) FROM PUBLIC;
COMMIT;

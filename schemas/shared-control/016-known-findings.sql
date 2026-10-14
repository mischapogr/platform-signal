-- Explicit stopped owner installation. Comparison only, no finding mutation.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_window_profile') IS DISTINCT FROM current_user
  OR NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_finding_lookup;
REVOKE ALL ON SCHEMA signal_finding_lookup FROM PUBLIC;
CREATE FUNCTION signal_finding_lookup.known(t jsonb,r jsonb,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions;item jsonb;stored signal_control.findings;candidate jsonb;original jsonb;
 known jsonb:='[]'::jsonb;
BEGIN
 IF r IS NULL OR octet_length(r::text)>2097152 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','head','items']);
 IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'head') NOT IN ('string','null')
  OR jsonb_typeof(r->'items') IS DISTINCT FROM 'array' OR jsonb_array_length(r->'items')>128
  OR (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(r->'items') x)<>jsonb_array_length(r->'items') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF p.head IS DISTINCT FROM (r->>'head')::uuid THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 FOR item IN SELECT x FROM jsonb_array_elements(r->'items') x LOOP
  PERFORM signal_control.require_keys(item,ARRAY['id','payload']);candidate:=item->'payload';
  IF jsonb_typeof(item->'id') IS DISTINCT FROM 'string' OR (item->>'id')::uuid='00000000-0000-0000-0000-000000000000'::uuid
   OR jsonb_typeof(candidate) IS DISTINCT FROM 'object' OR octet_length(candidate::text)>131072
   OR candidate->'schema_version' IS DISTINCT FROM '1'::jsonb OR candidate->'id' IS DISTINCT FROM item->'id'
   OR jsonb_typeof(candidate->'attributes') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  SELECT * INTO stored FROM signal_control.findings WHERE id=(item->>'id')::uuid;
  IF NOT FOUND THEN CONTINUE; END IF;
  IF stored.partition_id<>p.id THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  IF stored.content_sha256<>sha256(stored.content) THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  original:=convert_from(stored.content,'UTF8')::jsonb;
  IF (original#>'{attributes,signal.scope.v1}') IS NOT NULL AND (candidate#>'{attributes,signal.scope.v1}') IS NOT NULL
   AND original#>'{attributes,signal.scope.v1}' IS DISTINCT FROM candidate#>'{attributes,signal.scope.v1}' THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  IF (original#-'{attributes,signal.scope.v1}') IS DISTINCT FROM (candidate#-'{attributes,signal.scope.v1}') THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  -- Exact/semantically equivalent echoes preserve the original opaque bytes.
  -- An unknown legacy record is never upgraded by a newly scoped candidate.
  known:=known||jsonb_build_array(item->'id');
 END LOOP;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN jsonb_build_object('schema_version',1,'partition_id',p.id,'head',p.head,'ids',known);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_finding_lookup.known(jsonb,jsonb,bytea,bytea) FROM PUBLIC;
COMMIT;

-- Explicit stopped additive installation by the core schema owner.
-- Activation, private limits and runtime grants are separate owner actions.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR EXISTS(SELECT 1 FROM signal_control.store WHERE ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
END $$;
CREATE SCHEMA signal_multi_event;
REVOKE ALL ON SCHEMA signal_multi_event FROM PUBLIC;
CREATE TABLE signal_multi_event.profile (
 singleton boolean PRIMARY KEY CHECK(singleton),scope_generation uuid NOT NULL REFERENCES signal_finding_scope.activation(scope_generation),
 max_rows bigint NOT NULL CHECK(max_rows BETWEEN 1 AND 65536),max_bytes bigint NOT NULL CHECK(max_bytes BETWEEN 4096 AND 67108864),
 used_rows bigint NOT NULL DEFAULT 0 CHECK(used_rows BETWEEN 0 AND max_rows),used_bytes bigint NOT NULL DEFAULT 0 CHECK(used_bytes BETWEEN 0 AND max_bytes)
);
CREATE TABLE signal_multi_event.requests (
 partition_id uuid NOT NULL,commit_id uuid NOT NULL,claims bytea NOT NULL CHECK(octet_length(claims) BETWEEN 1 AND 131072),
 claims_sha256 bytea NOT NULL CHECK(octet_length(claims_sha256)=32),PRIMARY KEY(partition_id,commit_id),
 FOREIGN KEY(partition_id,commit_id) REFERENCES signal_control.commits(partition_id,id)
);
CREATE TABLE signal_multi_event.facts (
 finding_id uuid PRIMARY KEY,partition_id uuid NOT NULL,scope_generation uuid NOT NULL,
 fact bytea NOT NULL CHECK(octet_length(fact) BETWEEN 1 AND 131072),fact_sha256 bytea NOT NULL CHECK(octet_length(fact_sha256)=32),
 finding_sha256 bytea NOT NULL CHECK(octet_length(finding_sha256)=32),
 FOREIGN KEY(partition_id,finding_id) REFERENCES signal_control.findings(partition_id,id),
 FOREIGN KEY(partition_id,scope_generation) REFERENCES signal_finding_scope.producers(partition_id,scope_generation)
);
REVOKE ALL ON ALL TABLES IN SCHEMA signal_multi_event FROM PUBLIC;
CREATE FUNCTION signal_multi_event.publish(t jsonb,raw bytea,raw_claims bytea,resolve_only boolean,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions; a signal_finding_scope.activation; producer signal_finding_scope.producers;
 cfg signal_multi_event.profile; saved signal_multi_event.requests; old signal_control.state;
 r jsonb;c jsonb;v jsonb;f jsonb;ref jsonb;metadata jsonb;old_value jsonb;new_value jsonb;selected_state jsonb;payload bytea;fact_bytes bytea;
 result jsonb;first_seq bigint;last_seq bigint;sequence bigint;identity uuid;count_refs bigint:=0;
 charge bigint;new_rows bigint:=1;count_rows bigint;count_bytes bigint;retained boolean;
BEGIN
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 1048576
  OR raw_claims IS NULL OR octet_length(raw_claims) NOT BETWEEN 1 AND 131072 OR resolve_only IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 SELECT * INTO cfg FROM signal_multi_event.profile WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 SELECT * INTO a FROM signal_finding_scope.activation WHERE singleton;
 IF NOT FOUND OR a.scope_generation IS DISTINCT FROM cfg.scope_generation
  OR a.store_id IS DISTINCT FROM (t->'scope'->>'store_id')::uuid
  OR a.store_generation IS DISTINCT FROM (t->'scope'->>'generation')::uuid THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 r:=convert_from(raw,'UTF8')::jsonb;c:=convert_from(raw_claims,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(r,ARRAY['schema_version','id','previous','first_sequence','last_sequence','manifest','rule_revision','normalizer_revision','states','findings','work','receipts']);
 PERFORM signal_control.require_keys(c,ARRAY['schema_version','scope_generation','startup','wal_floor','prior','facts','state_key']);
 IF c->'schema_version' NOT IN ('2'::jsonb,'3'::jsonb)
  OR jsonb_typeof(c->'scope_generation') IS DISTINCT FROM 'string' OR (c->>'scope_generation')::uuid IS DISTINCT FROM cfg.scope_generation
  OR jsonb_typeof(c->'startup') IS DISTINCT FROM 'string' OR (c->>'startup')::uuid='00000000-0000-0000-0000-000000000000'::uuid
  OR jsonb_typeof(c->'prior') NOT IN ('object','null')
  OR jsonb_typeof(c->'facts') IS DISTINCT FROM 'array' OR jsonb_array_length(c->'facts')>128
  OR jsonb_typeof(r->'states') IS DISTINCT FROM 'array' OR jsonb_typeof(r->'findings') IS DISTINCT FROM 'array'
  OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(r->'first_sequence') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'last_sequence') IS DISTINCT FROM 'number'
  OR jsonb_typeof(c->'state_key') IS DISTINCT FROM 'string' OR octet_length(c->>'state_key') NOT BETWEEN 1 AND 256
  OR jsonb_typeof(c->'wal_floor') IS DISTINCT FROM 'number' OR (c->>'wal_floor')::bigint<0 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 first_seq:=(r->>'first_sequence')::bigint;last_seq:=(r->>'last_sequence')::bigint;
 IF first_seq IS NULL OR first_seq<1 OR last_seq IS NULL OR last_seq<first_seq THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r->'states') x WHERE x->>'key'=c->>'state_key') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 SELECT x INTO selected_state FROM jsonb_array_elements(r->'states') x WHERE x->>'key'=c->>'state_key';
 IF signal_control.hex_bytes(selected_state->'revision',32) IS DISTINCT FROM signal_control.hex_bytes(r->'rule_revision',32) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 new_value:=convert_from(signal_control.hex_bytes(selected_state->'bytes',65536),'UTF8')::jsonb;
 PERFORM signal_control.require_keys(new_value,ARRAY['schema_version','scope_generation','checkpoint','metadata','canonical_sequences']);
 IF new_value->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR new_value->>'scope_generation' IS DISTINCT FROM cfg.scope_generation::text
  OR jsonb_typeof(new_value->'checkpoint') IS DISTINCT FROM 'number'
  OR (new_value->>'checkpoint')::bigint IS DISTINCT FROM last_seq
  OR jsonb_typeof(new_value->'metadata') IS DISTINCT FROM 'object'
  OR jsonb_typeof(new_value->'metadata'->'canonical_sha256') IS DISTINCT FROM 'object'
  OR jsonb_typeof(new_value->'canonical_sequences') IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(new_value->'canonical_sequences'))>4096 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 FOR ref IN SELECT jsonb_build_object('event_id',key,'sequence',value) FROM jsonb_each(new_value->'canonical_sequences') LOOP
  IF (ref->>'event_id')::uuid IS NULL OR (ref->>'event_id')::uuid='00000000-0000-0000-0000-000000000000'::uuid
   OR jsonb_typeof(ref->'sequence') IS DISTINCT FROM 'number'
   OR (ref->>'sequence')::bigint NOT BETWEEN 1 AND last_seq
   OR (new_value->'metadata'->'canonical_sha256' ? (ref->>'event_id')) IS DISTINCT FROM true
   OR jsonb_typeof(new_value->'metadata'->'canonical_sha256'->(ref->>'event_id')) IS DISTINCT FROM 'array'
   OR jsonb_array_length(new_value->'metadata'->'canonical_sha256'->(ref->>'event_id'))<>32
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(new_value->'metadata'->'canonical_sha256'->(ref->>'event_id')) x WHERE jsonb_typeof(x) IS DISTINCT FROM 'number' OR x::text!~'^[0-9]+$' OR x::text::bigint NOT BETWEEN 0 AND 255) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(new_value->'canonical_sequences'))<>(SELECT count(*) FROM jsonb_object_keys(new_value->'metadata'->'canonical_sha256')) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 SELECT * INTO saved FROM signal_multi_event.requests WHERE partition_id=p.id AND commit_id=(r->>'id')::uuid;
 retained:=FOUND;
 IF retained THEN
  IF saved.claims<>raw_claims OR saved.claims_sha256<>sha256(raw_claims) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 ELSE
  IF resolve_only THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_UNCERTAIN'; END IF;
  IF EXISTS(SELECT 1 FROM signal_control.commits WHERE partition_id=p.id AND id=(r->>'id')::uuid) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  SELECT * INTO producer FROM signal_finding_scope.producers WHERE partition_id=p.id;
  IF NOT FOUND OR producer.scope_generation<>cfg.scope_generation OR producer.stream<>p.stream
   OR producer.startup_id IS DISTINCT FROM (c->>'startup')::uuid OR producer.wal_floor IS DISTINCT FROM (c->>'wal_floor')::bigint THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  IF c->'prior' IS DISTINCT FROM 'null'::jsonb THEN
   PERFORM signal_control.require_keys(c->'prior',ARRAY['schema_version','key','checkpoint','revision','value_sha256','scope_generation']);
   SELECT * INTO old FROM signal_control.state WHERE partition_id=p.id AND key=c->>'state_key' FOR UPDATE;
   IF NOT FOUND OR c->'prior'->>'key' IS DISTINCT FROM c->>'state_key'
    OR c->'prior'->'schema_version' IS DISTINCT FROM '1'::jsonb
    OR (c->'prior'->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint OR p.checkpoint<>first_seq-1
    OR signal_control.hex_bytes(c->'prior'->'revision',32) IS DISTINCT FROM old.revision
    OR old.revision IS DISTINCT FROM signal_control.hex_bytes(r->'rule_revision',32)
    OR signal_control.hex_bytes(c->'prior'->'value_sha256',32) IS DISTINCT FROM sha256(old.value)
    OR (c->'prior'->>'scope_generation')::uuid IS DISTINCT FROM cfg.scope_generation THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
   old_value:=convert_from(old.value,'UTF8')::jsonb;
   IF old_value->'schema_version' IS DISTINCT FROM '1'::jsonb
    OR old_value->>'scope_generation' IS DISTINCT FROM cfg.scope_generation::text
    OR (old_value->>'checkpoint')::bigint IS DISTINCT FROM p.checkpoint THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
  END IF;
 END IF;
 SELECT (SELECT count(*) FROM signal_multi_event.requests)+(SELECT count(*) FROM signal_multi_event.facts),
  (SELECT coalesce(sum(256+octet_length(claims)),0) FROM signal_multi_event.requests)+(SELECT coalesce(sum(512+octet_length(fact)),0) FROM signal_multi_event.facts)
  INTO count_rows,count_bytes;
 IF count_rows<>cfg.used_rows OR count_bytes<>cfg.used_bytes
  OR EXISTS(SELECT 1 FROM signal_multi_event.requests WHERE claims_sha256<>sha256(claims))
  OR EXISTS(SELECT 1 FROM signal_multi_event.facts m JOIN signal_control.findings f ON f.partition_id=m.partition_id AND f.id=m.finding_id WHERE m.fact_sha256<>sha256(m.fact) OR m.finding_sha256<>f.content_sha256 OR f.content_sha256<>sha256(f.content)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 IF (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(c->'facts') x)<>jsonb_array_length(c->'facts') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 charge:=256+octet_length(raw_claims);
 FOR v IN SELECT x FROM jsonb_array_elements(c->'facts') x LOOP
  PERFORM signal_control.require_keys(v,ARRAY['id','anchor_sequence','references','source','account','resource','binding_digest']);
  identity:=(v->>'id')::uuid;sequence:=(v->>'anchor_sequence')::bigint;
  IF jsonb_typeof(v->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'anchor_sequence') IS DISTINCT FROM 'number'
   OR identity IS NULL OR identity='00000000-0000-0000-0000-000000000000'::uuid OR sequence IS NULL OR sequence>last_seq
   OR (sequence<first_seq AND (c->'schema_version'<>'3'::jsonb OR c->'prior'='null'::jsonb OR sequence>(c->'prior'->>'checkpoint')::bigint))
   OR jsonb_typeof(v->'binding_digest') IS DISTINCT FROM 'string'
   OR jsonb_typeof(v->'source') NOT IN ('string','null') OR jsonb_typeof(v->'account') NOT IN ('string','null') OR jsonb_typeof(v->'resource') NOT IN ('string','null')
   OR sequence<=(c->>'wal_floor')::bigint OR jsonb_typeof(v->'references') IS DISTINCT FROM 'array'
   OR jsonb_array_length(v->'references') NOT BETWEEN 1 AND 1000
   OR (SELECT count(DISTINCT x->>'event_id') FROM jsonb_array_elements(v->'references') x)<>jsonb_array_length(v->'references')
   OR (SELECT count(DISTINCT x->>'sequence') FROM jsonb_array_elements(v->'references') x)<>jsonb_array_length(v->'references') THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  count_refs:=count_refs+jsonb_array_length(v->'references');
  IF count_refs>4096 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v->'references') x WHERE (x->>'sequence')::bigint=sequence) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  FOR ref IN SELECT x FROM jsonb_array_elements(v->'references') x LOOP
   PERFORM signal_control.require_keys(ref,ARRAY['event_id','sequence']);
   IF jsonb_typeof(ref->'event_id') IS DISTINCT FROM 'string' OR jsonb_typeof(ref->'sequence') IS DISTINCT FROM 'number'
    OR (ref->>'event_id')::uuid IS NULL OR (ref->>'event_id')::uuid='00000000-0000-0000-0000-000000000000'::uuid
    OR (ref->>'sequence')::bigint IS NULL OR (ref->>'sequence')::bigint<1 THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
   IF (ref->>'sequence')::bigint NOT BETWEEN first_seq AND last_seq OR (ref->>'sequence')::bigint<=(c->>'wal_floor')::bigint THEN
    IF c->'prior'='null'::jsonb OR (ref->>'sequence')::bigint>(c->'prior'->>'checkpoint')::bigint THEN
     RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
    IF NOT retained AND (old_value->'metadata'->'canonical_sha256' ? (ref->>'event_id')) IS DISTINCT FROM true THEN
     RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
    IF NOT retained AND (old_value->'canonical_sequences'->>(ref->>'event_id'))::bigint IS DISTINCT FROM (ref->>'sequence')::bigint THEN
     RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
   END IF;
  END LOOP;
  SELECT x INTO f FROM jsonb_array_elements(r->'findings') x WHERE x->>'id'=v->>'id';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  payload:=signal_control.hex_bytes(f->'bytes',65536);
  metadata:=jsonb_build_object('schema_version',1,'generation',cfg.scope_generation::text,'binding_digest',v->>'binding_digest','source',v->'source','account',v->'account','resource',v->'resource');
  IF convert_from(payload,'UTF8')::jsonb->'attributes'->'signal.scope.v1' IS DISTINCT FROM metadata
   OR convert_from(payload,'UTF8')::jsonb->'event_ids' IS DISTINCT FROM (SELECT jsonb_agg(x->'event_id') FROM jsonb_array_elements(v->'references') x)
   OR octet_length(signal_control.hex_bytes(v->'binding_digest',32))<>32 THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  IF EXISTS(SELECT 1 FROM (VALUES(v->>'source'),(v->>'account'),(v->>'resource')) x(value) WHERE value IS NOT NULL AND (octet_length(value)>256 OR btrim(value)='')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  fact_bytes:=convert_to(v::text,'UTF8');
  IF EXISTS(SELECT 1 FROM signal_multi_event.facts WHERE finding_id=identity AND (partition_id<>p.id OR scope_generation<>cfg.scope_generation OR fact<>fact_bytes OR finding_sha256<>sha256(payload))) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  IF NOT EXISTS(SELECT 1 FROM signal_multi_event.facts WHERE finding_id=identity) THEN
   IF EXISTS(SELECT 1 FROM signal_control.findings WHERE id=identity) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
   new_rows:=new_rows+1;charge:=charge+512+octet_length(fact_bytes);
  END IF;
 END LOOP;
 FOR f IN SELECT x FROM jsonb_array_elements(r->'findings') x LOOP
  payload:=signal_control.hex_bytes(f->'bytes',65536);
  IF convert_from(payload,'UTF8')::jsonb->'attributes' ? 'signal.scope.v1'
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(c->'facts') x WHERE x->>'id'=f->>'id')
   AND NOT EXISTS(SELECT 1 FROM signal_control.findings WHERE id=(f->>'id')::uuid AND content=payload AND content_sha256=sha256(payload)) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 END LOOP;
 IF NOT retained AND (cfg.used_rows+new_rows>cfg.max_rows OR cfg.used_bytes+charge>cfg.max_bytes) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 result:=signal_control.publish(t,raw,resolve_only,expected_schema,expected_routines);
 IF NOT retained THEN
  FOR v IN SELECT x FROM jsonb_array_elements(c->'facts') x LOOP
   SELECT x INTO f FROM jsonb_array_elements(r->'findings') x WHERE x->>'id'=v->>'id';
   payload:=signal_control.hex_bytes(f->'bytes',65536);fact_bytes:=convert_to(v::text,'UTF8');
   INSERT INTO signal_multi_event.facts VALUES((v->>'id')::uuid,p.id,cfg.scope_generation,fact_bytes,sha256(fact_bytes),sha256(payload)) ON CONFLICT(finding_id) DO NOTHING;
  END LOOP;
  INSERT INTO signal_multi_event.requests VALUES(p.id,(r->>'id')::uuid,raw_claims,sha256(raw_claims));
  UPDATE signal_multi_event.profile SET used_rows=used_rows+new_rows,used_bytes=used_bytes+charge WHERE singleton;
 END IF;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire OR invalid_parameter_value THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) FROM PUBLIC;
COMMIT;

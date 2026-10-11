-- Explicit stopped additive scoped publication; frozen core and007 are untouched.
BEGIN;
SET LOCAL search_path=pg_catalog,signal_control,pg_temp;
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$
DECLARE head signal_control.store; source_catalog text;
BEGIN
    IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control')
        IS DISTINCT FROM current_user THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_DENIED';
    END IF;
    SELECT * INTO head FROM signal_control.store WHERE singleton;
    IF NOT FOUND OR head.ready OR head.revision NOT IN (4,5) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
    END IF;
    IF (SELECT count(*) FROM (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_control' AND c.relkind IN ('r','v','m','f','p') LIMIT 18) bounded_tables) <> (CASE head.revision WHEN 4 THEN 16 ELSE 17 END) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
    END IF;
    SELECT (SELECT encode(sha256(convert_to(jsonb_agg(v ORDER BY v->>'table')::text,'UTF8')),'hex')
FROM (
 SELECT jsonb_build_object('table',c.relname,'kind',c.relkind,'persistence',c.relpersistence,
 'rls',c.relrowsecurity,'forced_rls',c.relforcerowsecurity,
 'columns',(SELECT jsonb_agg(jsonb_build_object('number',a.attnum,'name',a.attname,
     'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'identity',a.attidentity,
     'generated',a.attgenerated,'dropped',a.attisdropped,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
     FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=c.oid AND a.attnum>0),
 'constraints',(SELECT jsonb_agg(jsonb_build_object('name',k.conname,'type',k.contype,
     'definition',pg_get_constraintdef(k.oid),'deferrable',k.condeferrable,'deferred',k.condeferred,'validated',k.convalidated) ORDER BY k.conname)
     FROM pg_constraint k WHERE k.conrelid=c.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_indexdef(i.indexrelid),
     'valid',i.indisvalid,'ready',i.indisready) ORDER BY pg_get_indexdef(i.indexrelid))
     FROM pg_index i WHERE i.indrelid=c.oid)) AS v
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='signal_control' AND c.relkind IN ('r','v','m','f','p')
) inventory) INTO source_catalog;
    IF source_catalog IS DISTINCT FROM (CASE head.revision WHEN 4 THEN 'fbcf31c88fa0980cddabdfb31475799d00e8ca7351daa7c71b17d00cba2cc1e8' WHEN 5 THEN 'f0db9d3765ee6698e5b6f4e70989007db422955bde7b69fca0bf20bd7e90191c' END)
        OR (SELECT count(*) FROM signal_control.migrations)<>head.revision
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=1 AND artifact='001.sql' AND sha256=decode('d0abe90a8a38c7b79f6ced20e3be8ccc882822ec1185a80f78e94f02bc4f734d','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=2 AND artifact='002-functions.sql' AND sha256=decode('8106d8e021dde8d02d6fc6e4851e56d21ae389094e0541bcee2774b48f92c4cf','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=3 AND artifact='003-administration.sql' AND sha256=decode('8f998a7eb937a58cdbd1f0256dcba79a5b9cbe8ab2fe60a07546ef4326b9aad9','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=4 AND artifact='005-catalog.sql' AND sha256=decode('20d5751d9a3259614469e7bed7871abd44f3f106339bd0993432ca7c584ae1c7','hex'))
        OR (head.revision=5 AND NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=5 AND artifact='006-catalog-restore.sql' AND sha256=decode('7ce74bb561f8574d707859fa03339e19d579a5808a42cf43686af681a5776949','hex')))
        OR head.schema_sha256<>decode('d0abe90a8a38c7b79f6ced20e3be8ccc882822ec1185a80f78e94f02bc4f734d','hex')
        OR (head.revision=4 AND head.routines_sha256<>decode('20d5751d9a3259614469e7bed7871abd44f3f106339bd0993432ca7c584ae1c7','hex'))
        OR (head.revision=5 AND head.routines_sha256<>decode('7ce74bb561f8574d707859fa03339e19d579a5808a42cf43686af681a5776949','hex')) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
    END IF;
END $$;
DO $$
DECLARE catalog text;
BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control') IS DISTINCT FROM current_user
  OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_finding_scope') IS DISTINCT FROM current_user THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_DENIED'; END IF;
 IF NOT EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND NOT ready AND revision IN (4,5)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_finding_scope') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 SELECT (SELECT encode(sha256(convert_to(jsonb_agg(v ORDER BY v->>'table')::text,'UTF8')),'hex')
FROM (
 SELECT jsonb_build_object('table',c.relname,'kind',c.relkind,'persistence',c.relpersistence,
 'rls',c.relrowsecurity,'forced_rls',c.relforcerowsecurity,
 'columns',(SELECT jsonb_agg(jsonb_build_object('number',a.attnum,'name',a.attname,
     'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'identity',a.attidentity,
     'generated',a.attgenerated,'dropped',a.attisdropped,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
     FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=c.oid AND a.attnum>0),
 'constraints',(SELECT jsonb_agg(jsonb_build_object('name',k.conname,'type',k.contype,
     'definition',pg_get_constraintdef(k.oid),'deferrable',k.condeferrable,'deferred',k.condeferred,'validated',k.convalidated) ORDER BY k.conname)
     FROM pg_constraint k WHERE k.conrelid=c.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_indexdef(i.indexrelid),
     'valid',i.indisvalid,'ready',i.indisready) ORDER BY pg_get_indexdef(i.indexrelid))
     FROM pg_index i WHERE i.indrelid=c.oid)) AS v
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='signal_finding_scope' AND c.relkind IN ('r','v','m','f','p')
) inventory) INTO catalog;
 IF catalog IS DISTINCT FROM '1c39d1b13076b974fc7c81c1d7c13c427c2e25a06a1c8c9df6ed053ca3a12614' THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
END $$;
CREATE TABLE signal_finding_scope.requests (
 partition_id uuid NOT NULL,
 commit_id uuid NOT NULL,
 claims bytea NOT NULL CHECK(octet_length(claims) BETWEEN 1 AND 131072),
 claims_sha256 bytea NOT NULL CHECK(octet_length(claims_sha256)=32),
 PRIMARY KEY(partition_id,commit_id),
 FOREIGN KEY(partition_id,commit_id) REFERENCES signal_control.commits(partition_id,id)
);
REVOKE ALL ON signal_finding_scope.requests FROM PUBLIC;

CREATE FUNCTION signal_finding_scope.publish(t jsonb, raw bytea, raw_claims bytea, resolve_only boolean,
 expected_schema bytea, expected_routines bytea, expected_catalog text, expected_functions text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE h signal_control.store; p signal_control.partitions; a signal_finding_scope.activation;
 cfg signal_finding_scope.profile; producer signal_finding_scope.producers; retained signal_finding_scope.requests;
 r jsonb; c jsonb; v jsonb; f jsonb; metadata jsonb; payload bytea; identity uuid; sequence bigint;
 catalog text; routines text; result jsonb; count_producers bigint; count_facts bigint; count_requests bigint;
 used bigint; charge bigint; new_count bigint:=1; first_seq bigint; last_seq bigint; existing signal_control.findings;
BEGIN
 IF raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 1048576 OR raw_claims IS NULL
  OR octet_length(raw_claims) NOT BETWEEN 1 AND 131072 OR resolve_only IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 -- Same global first lock order as core publication and stopped enrollment.
 SELECT * INTO h FROM signal_control.store WHERE singleton FOR UPDATE;
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF (SELECT count(*) FROM (SELECT 1 FROM pg_class x JOIN pg_namespace n ON n.oid=x.relnamespace WHERE n.nspname='signal_finding_scope' AND x.relkind IN ('r','v','m','f','p') LIMIT 6) x)<>5
  OR EXISTS(SELECT 1 FROM pg_class x JOIN pg_namespace n ON n.oid=x.relnamespace WHERE n.nspname='signal_finding_scope' AND (pg_get_userbyid(x.relowner)<>current_user OR EXISTS(SELECT 1 FROM pg_trigger tr WHERE tr.tgrelid=x.oid AND NOT tr.tgisinternal)))
  OR (SELECT count(*) FROM (SELECT 1 FROM pg_proc x JOIN pg_namespace n ON n.oid=x.pronamespace WHERE n.nspname='signal_finding_scope' LIMIT 2) x)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 SELECT (SELECT encode(sha256(convert_to(jsonb_agg(catalog_value ORDER BY catalog_value->>'table')::text,'UTF8')),'hex')
FROM (
 SELECT jsonb_build_object('table',catalog_relation.relname,'kind',catalog_relation.relkind,'persistence',catalog_relation.relpersistence,
 'rls',catalog_relation.relrowsecurity,'forced_rls',catalog_relation.relforcerowsecurity,
 'columns',(SELECT jsonb_agg(jsonb_build_object('number',catalog_attribute.attnum,'name',catalog_attribute.attname,
     'type',format_type(catalog_attribute.atttypid,catalog_attribute.atttypmod),'notnull',catalog_attribute.attnotnull,'identity',catalog_attribute.attidentity,
     'generated',catalog_attribute.attgenerated,'dropped',catalog_attribute.attisdropped,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY catalog_attribute.attnum)
     FROM pg_attribute catalog_attribute LEFT JOIN pg_attrdef d ON d.adrelid=catalog_attribute.attrelid AND d.adnum=catalog_attribute.attnum WHERE catalog_attribute.attrelid=catalog_relation.oid AND catalog_attribute.attnum>0),
 'constraints',(SELECT jsonb_agg(jsonb_build_object('name',k.conname,'type',k.contype,
     'definition',pg_get_constraintdef(k.oid),'deferrable',k.condeferrable,'deferred',k.condeferred,'validated',k.convalidated) ORDER BY k.conname)
     FROM pg_constraint k WHERE k.conrelid=catalog_relation.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_indexdef(i.indexrelid),
     'valid',i.indisvalid,'ready',i.indisready) ORDER BY pg_get_indexdef(i.indexrelid))
     FROM pg_index i WHERE i.indrelid=catalog_relation.oid)) AS catalog_value
 FROM pg_class catalog_relation JOIN pg_namespace n ON n.oid=catalog_relation.relnamespace
 WHERE n.nspname='signal_finding_scope' AND catalog_relation.relkind IN ('r','v','m','f','p')
) inventory) INTO catalog;
 SELECT encode(sha256(convert_to(string_agg(pg_get_functiondef(x.oid),E'\n' ORDER BY x.proname,pg_get_function_identity_arguments(x.oid)),'UTF8')),'hex') INTO routines
  FROM pg_proc x JOIN pg_namespace n ON n.oid=x.pronamespace WHERE n.nspname='signal_finding_scope';
 IF catalog IS DISTINCT FROM expected_catalog OR routines IS DISTINCT FROM expected_functions THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 SELECT * INTO cfg FROM signal_finding_scope.profile WHERE singleton FOR UPDATE;
 IF NOT FOUND OR cfg.schema_version<>1 OR cfg.artifact_sha256<>decode('59e56397ef880f3912118adff934da2be82224e71e1fa97a4cc332d7cec8367e','hex') THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 SELECT * INTO a FROM signal_finding_scope.activation WHERE singleton;
 IF NOT FOUND OR a.store_id<>h.store_id OR a.store_generation<>h.generation OR a.prefix_position>h.feed_position
  OR (a.prefix_position=0 AND a.prefix_digest<>sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||decode(replace(h.store_id::text,'-',''),'hex')))
  OR (a.prefix_position>0 AND NOT EXISTS(SELECT 1 FROM signal_control.findings WHERE position=a.prefix_position AND cursor_digest=a.prefix_digest)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 c:=convert_from(raw_claims,'UTF8')::jsonb; r:=convert_from(raw,'UTF8')::jsonb;
 PERFORM signal_control.require_keys(c,ARRAY['schema_version','scope_generation','startup','wal_floor','findings']);
 IF c->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(c->'findings') IS DISTINCT FROM 'array'
  OR jsonb_array_length(c->'findings')>128 OR (c->>'scope_generation')::uuid IS DISTINCT FROM a.scope_generation
  OR jsonb_typeof(c->'startup') IS DISTINCT FROM 'string' OR (c->>'startup')::uuid='00000000-0000-0000-0000-000000000000'
  OR jsonb_typeof(c->'wal_floor') IS DISTINCT FROM 'number' OR (c->>'wal_floor')::bigint<0 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 first_seq:=(r->>'first_sequence')::bigint; last_seq:=(r->>'last_sequence')::bigint;
 SELECT count(*) INTO count_producers FROM (SELECT 1 FROM signal_finding_scope.producers LIMIT 129) x;
 SELECT count(*) INTO count_facts FROM (SELECT 1 FROM signal_finding_scope.facts LIMIT 65537) x;
 SELECT count(*) INTO count_requests FROM (SELECT 1 FROM signal_finding_scope.requests LIMIT 65537) x;
 IF count_producers>cfg.max_producers OR count_facts+count_requests>cfg.max_rows THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 SELECT 400+count_producers*320
  +(SELECT COALESCE(sum(512+COALESCE(octet_length(source),0)+COALESCE(octet_length(account),0)+COALESCE(octet_length(resource),0)),0) FROM signal_finding_scope.facts)
  +(SELECT COALESCE(sum(256+octet_length(claims)),0) FROM signal_finding_scope.requests) INTO used;
 IF cfg.used_producers<>count_producers OR cfg.used_rows<>count_facts+count_requests OR cfg.used_bytes<>used
  OR EXISTS(SELECT 1 FROM signal_finding_scope.requests WHERE claims_sha256<>sha256(claims)) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
 SELECT * INTO retained FROM signal_finding_scope.requests WHERE partition_id=p.id AND commit_id=(r->>'id')::uuid;
 IF FOUND THEN
  IF retained.claims<>raw_claims OR retained.claims_sha256<>sha256(raw_claims) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
 ELSE
  IF resolve_only THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_UNCERTAIN'; END IF;
  IF EXISTS(SELECT 1 FROM signal_control.commits WHERE partition_id=p.id AND id=(r->>'id')::uuid) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
  SELECT * INTO producer FROM signal_finding_scope.producers WHERE partition_id=p.id;
  IF NOT FOUND OR producer.scope_generation<>a.scope_generation OR producer.stream<>p.stream
   OR producer.startup_id IS DISTINCT FROM (c->>'startup')::uuid OR producer.wal_floor IS DISTINCT FROM (c->>'wal_floor')::bigint THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 END IF;
 charge:=256+octet_length(raw_claims);
 IF (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(c->'findings') x)<>jsonb_array_length(c->'findings') THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 FOR v IN SELECT x FROM jsonb_array_elements(c->'findings') x LOOP
  PERFORM signal_control.require_keys(v,ARRAY['id','event_id','sequence','source','account','resource','binding_digest']);
  identity:=(v->>'id')::uuid; sequence:=(v->>'sequence')::bigint;
  IF jsonb_typeof(v->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'event_id') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'sequence') IS DISTINCT FROM 'number'
   OR identity IS NULL OR identity='00000000-0000-0000-0000-000000000000' OR (v->>'event_id')::uuid IS NULL
   OR (v->>'event_id')::uuid='00000000-0000-0000-0000-000000000000' OR sequence IS NULL
   OR sequence NOT BETWEEN first_seq AND last_seq OR sequence<=(c->>'wal_floor')::bigint
   OR octet_length(signal_control.hex_bytes(v->'binding_digest',32))<>32
   OR jsonb_typeof(v->'source') NOT IN ('string','null') OR jsonb_typeof(v->'account') NOT IN ('string','null') OR jsonb_typeof(v->'resource') NOT IN ('string','null')
   OR EXISTS(SELECT 1 FROM (VALUES(v->>'source'),(v->>'account'),(v->>'resource')) z(value) WHERE value IS NOT NULL AND (octet_length(value)>256 OR btrim(value)='')) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  SELECT x INTO f FROM jsonb_array_elements(r->'findings') x WHERE (x->>'id')::uuid=identity;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  payload:=signal_control.hex_bytes(f->'bytes',65536);
  metadata:=jsonb_build_object('schema_version',1,'generation',a.scope_generation::text,'binding_digest',v->>'binding_digest','source',v->'source','account',v->'account','resource',v->'resource');
  IF (convert_from(payload,'UTF8')::jsonb->'attributes'->'signal.scope.v1') IS DISTINCT FROM metadata
   OR (convert_from(payload,'UTF8')::jsonb->'event_ids') IS DISTINCT FROM jsonb_build_array((v->>'event_id')::uuid) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
  SELECT * INTO existing FROM signal_control.findings WHERE id=identity;
  IF FOUND THEN
   IF existing.content<>payload OR existing.content_sha256<>sha256(payload) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
   IF EXISTS(SELECT 1 FROM signal_finding_scope.facts s WHERE s.finding_id=identity AND (s.scope_generation<>a.scope_generation OR s.event_id<>(v->>'event_id')::uuid OR s.binding_digest<>signal_control.hex_bytes(v->'binding_digest',32) OR s.finding_sha256<>sha256(payload)
    OR s.source IS DISTINCT FROM (v->>'source') OR s.account IS DISTINCT FROM (v->>'account') OR s.resource IS DISTINCT FROM (v->>'resource'))) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
   IF retained.commit_id IS NOT NULL AND existing.commit_id=retained.commit_id AND existing.partition_id=p.id
    AND NOT EXISTS(SELECT 1 FROM signal_finding_scope.facts WHERE finding_id=identity) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
  ELSE
   new_count:=new_count+1;
   charge:=charge+512+COALESCE(octet_length(v->>'source'),0)+COALESCE(octet_length(v->>'account'),0)+COALESCE(octet_length(v->>'resource'),0);
  END IF;
 END LOOP;
 -- Unclaimed reserved metadata may only replay already retained exact bytes.
 FOR f IN SELECT x FROM jsonb_array_elements(r->'findings') x LOOP
  payload:=signal_control.hex_bytes(f->'bytes',65536);
  IF (convert_from(payload,'UTF8')::jsonb->'attributes') ? 'signal.scope.v1'
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(c->'findings') x WHERE x->>'id'=f->>'id')
   AND NOT EXISTS(SELECT 1 FROM signal_control.findings WHERE id=(f->>'id')::uuid AND content=payload AND content_sha256=sha256(payload)) THEN
   RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
 END LOOP;
 IF retained.commit_id IS NULL AND (cfg.used_rows+new_count>cfg.max_rows OR cfg.used_bytes+charge>cfg.max_bytes) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
 result:=signal_control.publish(t,raw,resolve_only,expected_schema,expected_routines);
 IF retained.commit_id IS NULL THEN
  FOR v IN SELECT x FROM jsonb_array_elements(c->'findings') x LOOP
   SELECT * INTO existing FROM signal_control.findings WHERE id=(v->>'id')::uuid;
   IF existing.partition_id=p.id AND existing.commit_id=(r->>'id')::uuid THEN
    IF existing.position<=a.prefix_position THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
    INSERT INTO signal_finding_scope.facts VALUES(existing.id,p.id,a.scope_generation,(v->>'event_id')::uuid,v->>'source',v->>'account',v->>'resource',signal_control.hex_bytes(v->'binding_digest',32),existing.content_sha256);
   END IF;
  END LOOP;
  INSERT INTO signal_finding_scope.requests VALUES(p.id,(r->>'id')::uuid,raw_claims,sha256(raw_claims));
  UPDATE signal_finding_scope.profile SET used_rows=used_rows+new_count,used_bytes=used_bytes+charge WHERE singleton;
 END IF;
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
 RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) FROM PUBLIC;
-- The owner explicitly grants schema USAGE and this function's EXECUTE to
-- enrolled pipeline roles. No supplemental table SELECT/INSERT/UPDATE is granted.
COMMIT;

-- Additive scope-authority extension, not a replacement core catalog profile.
-- Explicit stopped schema owner only. No runtime installs or implicit grants.
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
CREATE SCHEMA signal_finding_scope;
REVOKE ALL ON SCHEMA signal_finding_scope FROM PUBLIC;

-- Independent authority charges. A future authenticated host API must enforce
-- aggregate counters atomically; direct runtime writes remain denied meanwhile.
CREATE TABLE signal_finding_scope.profile (
    singleton boolean PRIMARY KEY CHECK(singleton),
    schema_version integer NOT NULL CHECK(schema_version=1),
    artifact_sha256 bytea NOT NULL CHECK(octet_length(artifact_sha256)=32),
    max_producers integer NOT NULL CHECK(max_producers BETWEEN 1 AND 128),
    max_rows bigint NOT NULL CHECK(max_rows BETWEEN 1 AND 65536),
    max_bytes bigint NOT NULL CHECK(max_bytes BETWEEN 4096 AND 67108864),
    used_producers integer NOT NULL DEFAULT 0 CHECK(used_producers BETWEEN 0 AND max_producers),
    used_rows bigint NOT NULL DEFAULT 0 CHECK(used_rows BETWEEN 0 AND max_rows),
    used_bytes bigint NOT NULL DEFAULT 0 CHECK(used_bytes BETWEEN 0 AND max_bytes)
);
CREATE TABLE signal_finding_scope.activation (
    singleton boolean PRIMARY KEY CHECK(singleton) REFERENCES signal_finding_scope.profile(singleton),
    store_id uuid NOT NULL REFERENCES signal_control.store(store_id),
    store_generation uuid NOT NULL CHECK(store_generation<>'00000000-0000-0000-0000-000000000000'),
    scope_generation uuid NOT NULL UNIQUE CHECK(scope_generation<>'00000000-0000-0000-0000-000000000000'),
    prefix_position bigint NOT NULL CHECK(prefix_position>=0),
    prefix_digest bytea NOT NULL CHECK(octet_length(prefix_digest)=32)
);
CREATE TABLE signal_finding_scope.producers (
    partition_id uuid PRIMARY KEY REFERENCES signal_control.partitions(id),
    scope_generation uuid NOT NULL REFERENCES signal_finding_scope.activation(scope_generation),
    stream uuid NOT NULL CHECK(stream<>'00000000-0000-0000-0000-000000000000'),
    startup_id uuid NOT NULL UNIQUE CHECK(startup_id<>'00000000-0000-0000-0000-000000000000'),
    wal_floor bigint NOT NULL CHECK(wal_floor>=0),
    UNIQUE(partition_id,scope_generation)
);
CREATE TABLE signal_finding_scope.facts (
    finding_id uuid PRIMARY KEY,
    partition_id uuid NOT NULL,
    scope_generation uuid NOT NULL,
    event_id uuid NOT NULL CHECK(event_id<>'00000000-0000-0000-0000-000000000000'),
    source text CHECK(source IS NULL OR octet_length(source)<=256),
    account text CHECK(account IS NULL OR octet_length(account)<=256),
    resource text CHECK(resource IS NULL OR octet_length(resource)<=256),
    binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
    finding_sha256 bytea NOT NULL CHECK(octet_length(finding_sha256)=32),
    FOREIGN KEY(partition_id,finding_id) REFERENCES signal_control.findings(partition_id,id),
    FOREIGN KEY(partition_id,scope_generation) REFERENCES signal_finding_scope.producers(partition_id,scope_generation)
);
REVOKE ALL ON ALL TABLES IN SCHEMA signal_finding_scope FROM PUBLIC;
-- No profile/activation is synthesized and the core remains stopped. Host
-- authority, complete logical inventory and current store generation must be
-- verified before any future scoped startup or write/read operation.
COMMIT;

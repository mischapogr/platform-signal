-- Explicit owner-installed additive contract. Never part of runtime bootstrap.
CREATE SCHEMA signal_custody_restore;
REVOKE ALL ON SCHEMA signal_custody_restore FROM PUBLIC;
CREATE TABLE signal_custody_restore.contract (
    singleton boolean PRIMARY KEY CHECK(singleton),
    schema_version integer NOT NULL CHECK(schema_version=1),
    owner name NOT NULL,
    artifact_sha256 bytea NOT NULL CHECK(octet_length(artifact_sha256)=32),
    routine_sha256 bytea NOT NULL CHECK(octet_length(routine_sha256)=32)
);
REVOKE ALL ON signal_custody_restore.contract FROM PUBLIC;
CREATE FUNCTION signal_custody_restore.resolve(t jsonb, raw bytea, expected_schema bytea,
    expected_routines bytea, expected_artifact bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,signal_control,signal_custody_restore,pg_temp AS $$
DECLARE p signal_control.partitions; item signal_control.receipts;
    lineage signal_control.restore_record; cfg signal_custody_restore.contract;
    r jsonb; reference bytea; description jsonb; origin jsonb; actual bytea;
BEGIN
    SELECT * INTO cfg FROM signal_custody_restore.contract WHERE singleton;
    SELECT sha256(convert_to(pg_get_functiondef('signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea)'::regprocedure),'UTF8')) INTO actual;
    IF cfg.schema_version IS DISTINCT FROM 1 OR cfg.artifact_sha256 IS DISTINCT FROM expected_artifact
        OR cfg.routine_sha256 IS DISTINCT FROM actual OR octet_length(expected_artifact) IS DISTINCT FROM 32
        OR NOT EXISTS(SELECT 1 FROM pg_namespace n JOIN pg_roles o ON o.oid=n.nspowner
            WHERE n.nspname='signal_custody_restore' AND o.rolname=cfg.owner
            AND EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace=n.oid AND c.relname='contract' AND c.relowner=n.nspowner)
            AND EXISTS(SELECT 1 FROM pg_proc routine WHERE routine.pronamespace=n.oid
                AND routine.oid='signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea)'::regprocedure
                AND routine.proowner=n.nspowner AND routine.prosecdef))
        OR pg_has_role(session_user,cfg.owner,'MEMBER') THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
    END IF;
    p:=signal_control.check_token(t,expected_schema,expected_routines);
    SELECT * INTO lineage FROM signal_control.restore_record WHERE singleton;
    IF p.kind<>'pipeline' OR lineage.complete IS DISTINCT FROM true
        OR lineage.generation IS DISTINCT FROM (t->'scope'->>'generation')::uuid
        OR lineage.seal IS DISTINCT FROM signal_control.restore_record_seal(lineage)
        OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 1048576 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
    END IF;
    r:=convert_from(raw,'UTF8')::jsonb;
    PERFORM signal_control.require_keys(r,ARRAY['schema_version','id','prepared_count','source_record_count','reference']);
    IF r->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR r->'prepared_count' IS DISTINCT FROM '0'::jsonb
        OR r->'source_record_count' IS DISTINCT FROM '0'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
    END IF;
    reference:=signal_control.hex_bytes(r->'reference',65536);
    SELECT * INTO item FROM signal_control.receipts WHERE partition_id=p.id AND id=(r->>'id')::uuid FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
    IF item.retained_request IS DISTINCT FROM raw OR item.reference IS DISTINCT FROM reference
        OR item.reference_sha256 IS DISTINCT FROM sha256(reference) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT';
    END IF;
    IF item.prepared_count<>0 OR item.source_record_count<>0 OR item.verified_prefix<>0
        OR item.commit_id IS NOT NULL OR item.state<>'retained' THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
    END IF;
    r:=convert_from(reference,'UTF8')::jsonb; description:=r->'description'; origin:=description->'scope';
    IF r->>'kind' IS DISTINCT FROM 'object_custody_v1'
        OR description->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR (description->>'id')::uuid IS DISTINCT FROM item.id
        OR origin->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR (origin->>'generation')::uuid IS DISTINCT FROM lineage.old_generation
        OR origin->>'store_id' IS DISTINCT FROM t->'scope'->>'store_id'
        OR origin->>'tenant' IS DISTINCT FROM p.tenant
        OR (origin->>'stream')::uuid IS DISTINCT FROM p.stream
        OR (origin->>'partition_id')::uuid IS DISTINCT FROM p.id THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
    END IF;
    PERFORM signal_control.check_token(t,expected_schema,expected_routines);
    RETURN jsonb_build_object('schema_version',1,'id',item.id,'prepared_count',0,
        'source_record_count',0,'verified_prefix',0);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;
REVOKE ALL ON FUNCTION signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea) FROM PUBLIC;

-- Revision2: execute only through the explicit bounded administrator transaction.
-- Exact001/002 source checks and stopped-writer locks precede all DDL. The
-- administrator records all three SHA256 identities and revision only on success.
CREATE TABLE signal_control.migrations (
    ordinal integer PRIMARY KEY CHECK(ordinal BETWEEN 1 AND 3),
    artifact text NOT NULL UNIQUE CHECK(octet_length(artifact) BETWEEN 1 AND 128),
    sha256 bytea NOT NULL CHECK(octet_length(sha256)=32)
);
REVOKE ALL ON signal_control.migrations FROM PUBLIC;
ALTER TABLE signal_control.store DROP CONSTRAINT store_revision_check;
ALTER TABLE signal_control.store ADD CONSTRAINT store_revision_check CHECK(revision IN (1,2));
CREATE OR REPLACE FUNCTION signal_control.check_scope(s jsonb, require_lease boolean, expected_schema bytea, expected_routines bytea)
RETURNS signal_control.partitions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp
AS $$
DECLARE head signal_control.store; part signal_control.partitions;
BEGIN
    IF expected_schema IS NULL OR octet_length(expected_schema) <> 32
        OR expected_routines IS NULL OR octet_length(expected_routines) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    IF s IS NULL OR jsonb_typeof(s) IS DISTINCT FROM 'object'
        OR octet_length(s::text) > 4096 OR s->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR NOT (s ?& ARRAY['schema_version','store_id','generation','tenant','stream','partition_id'])
        OR (SELECT count(*) FROM jsonb_object_keys(s)) <> 6 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    SELECT * INTO head FROM signal_control.store WHERE singleton FOR UPDATE;
    IF NOT FOUND OR head.revision<>2 OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=1 AND artifact='001.sql' AND sha256=expected_schema)
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=2 AND artifact='002-functions.sql' AND sha256=decode('8106d8e021dde8d02d6fc6e4851e56d21ae389094e0541bcee2774b48f92c4cf','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=3 AND artifact='003-administration.sql' AND sha256=expected_routines)
        OR (SELECT count(*) FROM signal_control.migrations)<>3 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
    END IF;
    IF NOT FOUND OR NOT head.ready OR head.store_id IS DISTINCT FROM (s->>'store_id')::uuid
        OR head.generation IS DISTINCT FROM (s->>'generation')::uuid OR head.schema_sha256 IS DISTINCT FROM expected_schema
        OR head.routines_sha256 IS DISTINCT FROM expected_routines THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    SELECT * INTO part FROM signal_control.partitions
        WHERE id=(s->>'partition_id')::uuid AND tenant=s->>'tenant'
          AND stream=(s->>'stream')::uuid FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM signal_control.principals
        WHERE role_name=session_user AND partition_id=part.id
          AND tenant=part.tenant AND stream=part.stream) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    IF require_lease AND (part.owner IS NULL OR part.lease_until <= clock_timestamp()) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    RETURN part;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
END $$;

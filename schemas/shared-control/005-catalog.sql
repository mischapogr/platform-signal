-- Revision4 catalog profile, installed only by a stopped explicit administrator.
-- Revision2 is its source. Frozen001..004 are unchanged. Restored revision3 is
-- incompatible: it requires a separate qualified migration/restore profile.
ALTER TABLE signal_control.migrations DROP CONSTRAINT migrations_ordinal_check;
ALTER TABLE signal_control.migrations ADD CONSTRAINT migrations_ordinal_check CHECK(ordinal BETWEEN 1 AND 4);
ALTER TABLE signal_control.store DROP CONSTRAINT store_revision_check;
ALTER TABLE signal_control.store ADD CONSTRAINT store_revision_check CHECK(revision IN (2,4));
CREATE TABLE signal_control.catalog_snapshots (
    id uuid PRIMARY KEY REFERENCES signal_control.snapshots(id),
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    generation uuid NOT NULL,
    head uuid,
    checkpoint bigint NOT NULL CHECK(checkpoint>=0),
    manifest_ids_sha256 bytea NOT NULL CHECK(octet_length(manifest_ids_sha256)=32),
    seal bytea NOT NULL CHECK(octet_length(seal)=32),
    FOREIGN KEY(partition_id,head) REFERENCES signal_control.commits(partition_id,id),
    CHECK((head IS NULL AND checkpoint=0) OR (head IS NOT NULL AND checkpoint>0))
);
REVOKE ALL ON signal_control.catalog_snapshots FROM PUBLIC;
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
    IF NOT FOUND OR head.revision<>4 OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=1 AND artifact='001.sql' AND sha256=expected_schema)
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=2 AND artifact='002-functions.sql' AND sha256=decode('8106d8e021dde8d02d6fc6e4851e56d21ae389094e0541bcee2774b48f92c4cf','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=3 AND artifact='003-administration.sql' AND sha256=decode('8f998a7eb937a58cdbd1f0256dcba79a5b9cbe8ab2fe60a07546ef4326b9aad9','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=4 AND artifact='005-catalog.sql' AND sha256=expected_routines)
        OR (SELECT count(*) FROM signal_control.migrations)<>4 THEN
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

CREATE FUNCTION signal_control.catalog_snapshot_seal(q signal_control.catalog_snapshots) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,signal_control,pg_temp AS $$
    SELECT sha256(convert_to('SIGNAL-CATALOG-SNAPSHOT-V1','UTF8')||convert_to((to_jsonb(q)-'seal')::text,'UTF8'));
$$;

CREATE FUNCTION signal_control.read_catalog_snapshot(s jsonb, identity uuid, lifetime integer,
    expected_schema bytea, expected_routines bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions; binding signal_control.object_scopes;
    q signal_control.catalog_snapshots; pin signal_control.snapshots;
    c record; ids uuid[]:='{}'; previous_id uuid;
    previous_sequence bigint:=0; packed bytea; expiry_time timestamptz;
    remaining integer; snapshot jsonb; reply jsonb; existing boolean;
BEGIN
    IF current_setting('transaction_isolation')<>'repeatable read'
        OR identity IS NULL OR identity='00000000-0000-0000-0000-000000000000'
        OR lifetime IS NULL OR lifetime NOT BETWEEN 1 AND 5000 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    p:=signal_control.check_scope(s,false,expected_schema,expected_routines);
    IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    binding:=signal_control.object_scope(p.id);
    SELECT * INTO q FROM signal_control.catalog_snapshots WHERE id=identity;
    existing:=FOUND;
    IF existing THEN
        IF q.partition_id<>p.id OR q.generation IS DISTINCT FROM (s->>'generation')::uuid THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF q.seal IS DISTINCT FROM signal_control.catalog_snapshot_seal(q) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
        SELECT * INTO pin FROM signal_control.snapshots WHERE id=identity;
        IF NOT FOUND OR pin.partition_id<>p.id OR pin.generation<>q.generation THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
        IF pin.expires_at<=clock_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_SNAPSHOT_EXPIRED'; END IF;
        IF pin.pin_ms<>lifetime THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF sha256(pin.manifest_ids) IS DISTINCT FROM q.manifest_ids_sha256 OR
            pin.objects_sha256 IS DISTINCT FROM signal_control.reader_object_seal(pin.id,pin.partition_id,pin.generation,pin.manifest_ids,pin.expires_at,pin.pin_ms,pin.object_hashes) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
        packed:=pin.manifest_ids;
        IF packed<>decode('00','hex') THEN
            IF octet_length(packed)%16<>0 OR octet_length(packed)>2048 THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
            FOR i IN 0..octet_length(packed)/16-1 LOOP
                ids:=array_append(ids,encode(substring(packed FROM i*16+1 FOR 16),'hex')::uuid);
            END LOOP;
        ELSIF q.head IS NOT NULL OR q.checkpoint<>0 OR cardinality(pin.object_hashes)<>0 THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
    ELSE
        -- An explicit-ID pin cannot impersonate complete dynamic catalog discovery.
        IF EXISTS(SELECT 1 FROM signal_control.snapshots WHERE id=identity) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        FOR c IN SELECT id,generation,previous,first_sequence,last_sequence
            FROM signal_control.commits WHERE partition_id=p.id ORDER BY first_sequence LIMIT 129 LOOP
            IF cardinality(ids)=128 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
            IF c.generation IS DISTINCT FROM (s->>'generation')::uuid
                OR c.previous IS DISTINCT FROM previous_id OR c.first_sequence<>previous_sequence+1
                OR c.last_sequence<c.first_sequence THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
            ids:=array_append(ids,c.id);
            previous_id:=c.id; previous_sequence:=c.last_sequence;
        END LOOP;
        IF previous_id IS DISTINCT FROM p.head OR previous_sequence<>p.checkpoint THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
        q.id:=identity; q.partition_id:=p.id; q.generation:=(s->>'generation')::uuid;
        q.head:=p.head; q.checkpoint:=p.checkpoint;
    END IF;
    IF cardinality(ids)>0 THEN
        -- This verifies every retained request, manifest, exact backend object set,
        -- reply budget and fixed pin before committing. No object I/O is done here.
        snapshot:=signal_control.read_snapshot(s,identity,ids,lifetime,expected_schema,expected_routines);
        SELECT * INTO STRICT pin FROM signal_control.snapshots WHERE id=identity;
        IF ids[cardinality(ids)] IS DISTINCT FROM q.head THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    ELSE
        IF NOT existing THEN
            PERFORM signal_control.assert_retention_integrity();
            UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+321
                WHERE singleton AND used_rows<max_rows AND 321<=max_bytes-used_bytes;
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
            packed:=decode('00','hex'); expiry_time:=clock_timestamp()+lifetime*interval '1 millisecond';
            INSERT INTO signal_control.snapshots(id,partition_id,generation,manifest_ids,expires_at,pin_ms,object_hashes,objects_sha256)
                VALUES(identity,p.id,q.generation,packed,expiry_time,lifetime,'{}',
                    signal_control.reader_object_seal(identity,p.id,q.generation,packed,expiry_time,lifetime,'{}'::bytea[]))
                RETURNING * INTO pin;
        END IF;
        snapshot:=jsonb_build_object('schema_version',1,'id',identity,'scope',s,'remaining_ms',1,'manifests','[]'::jsonb);
    END IF;
    IF NOT existing THEN
        -- Keep mode/head/checkpoint and ID-list digest as a permanent320-byte row;
        -- expired snapshot payload compaction may never recreate this identity.
        UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+320
            WHERE singleton AND used_rows<max_rows AND 320<=max_bytes-used_bytes;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
        q.manifest_ids_sha256:=sha256(pin.manifest_ids); q.seal:=signal_control.catalog_snapshot_seal(q);
        INSERT INTO signal_control.catalog_snapshots VALUES(q.*);
    END IF;
    remaining:=floor(extract(epoch FROM (pin.expires_at-clock_timestamp()))*1000)::integer;
    IF remaining<=0 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_SNAPSHOT_EXPIRED'; END IF;
    snapshot:=jsonb_set(snapshot,'{remaining_ms}',to_jsonb(remaining));
    PERFORM signal_control.check_scope(s,false,expected_schema,expected_routines);
    reply:=jsonb_build_object('schema_version',1,'backend_id',binding.backend_id,'head',q.head,'checkpoint',q.checkpoint,'snapshot',snapshot);
    IF octet_length(reply::text)>1048576 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
    RETURN reply;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
END $$;
REVOKE ALL ON FUNCTION signal_control.catalog_snapshot_seal(signal_control.catalog_snapshots) FROM PUBLIC;
REVOKE ALL ON FUNCTION signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea) FROM PUBLIC;

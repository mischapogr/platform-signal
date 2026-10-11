-- Explicit runtime-routine installation by the administrative schema owner.
-- Library opens must bind both 001.sql and this exact routines bundle checksum.
BEGIN;
SET LOCAL lock_timeout = '1s';
SET LOCAL statement_timeout = '5s';
ALTER TABLE signal_control.store ADD COLUMN routines_sha256 bytea
    CHECK (routines_sha256 IS NULL OR octet_length(routines_sha256) = 32);
CREATE TABLE signal_control.principals (
    role_name name NOT NULL,
    tenant text NOT NULL CHECK (octet_length(tenant) BETWEEN 1 AND 256),
    stream uuid NOT NULL,
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    PRIMARY KEY (role_name, partition_id)
);
REVOKE ALL ON signal_control.principals FROM PUBLIC;

CREATE FUNCTION signal_control.check_scope(s jsonb, require_lease boolean, expected_schema bytea, expected_routines bytea)
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

CREATE FUNCTION signal_control.acquire(s jsonb, actor uuid, lease_ms integer, expected_schema bytea, expected_routines bytea)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp
AS $$
DECLARE part signal_control.partitions;
BEGIN
    IF actor IS NULL OR actor='00000000-0000-0000-0000-000000000000'
        OR lease_ms IS NULL OR lease_ms < 15000 OR lease_ms > 60000 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    part:=signal_control.check_scope(s,false,expected_schema,expected_routines);
    IF part.owner IS NOT NULL AND part.lease_until > clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    IF part.epoch=9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL';
    END IF;
    UPDATE signal_control.partitions SET epoch=epoch+1, owner=actor,
        lease_until=clock_timestamp()+lease_ms*interval '1 millisecond'
        WHERE id=part.id RETURNING * INTO part;
    RETURN jsonb_build_object('scope',s,'owner',part.owner,'epoch',part.epoch);
END $$;

CREATE FUNCTION signal_control.check_token(t jsonb, expected_schema bytea, expected_routines bytea)
RETURNS signal_control.partitions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp
AS $$
DECLARE part signal_control.partitions;
BEGIN
    IF t IS NULL OR jsonb_typeof(t) IS DISTINCT FROM 'object' OR octet_length(t::text)>8192 OR (SELECT count(*) FROM jsonb_object_keys(t))<>3
        OR NOT (t ? 'scope' AND t ? 'owner' AND t ? 'epoch') THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    part:=signal_control.check_scope(t->'scope',true,expected_schema,expected_routines);
    IF part.owner IS DISTINCT FROM (t->>'owner')::uuid
        OR part.epoch IS DISTINCT FROM (t->>'epoch')::bigint THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    RETURN part;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
END $$;

CREATE FUNCTION signal_control.renew(t jsonb, lease_ms integer, expected_schema bytea, expected_routines bytea)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp
AS $$
DECLARE part signal_control.partitions;
BEGIN
    IF lease_ms IS NULL OR lease_ms<15000 OR lease_ms>60000 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    part:=signal_control.check_token(t,expected_schema,expected_routines);
    UPDATE signal_control.partitions SET lease_until=clock_timestamp()+lease_ms*interval '1 millisecond'
        WHERE id=part.id AND owner=part.owner AND epoch=part.epoch
          AND lease_until>clock_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    RETURN t;
END $$;
-- Publication extensions are installed only with the explicit routines bundle.
ALTER TABLE signal_control.partitions ADD COLUMN head uuid;
ALTER TABLE signal_control.partitions ADD FOREIGN KEY(id,head) REFERENCES signal_control.commits(partition_id,id);
ALTER TABLE signal_control.commits ADD COLUMN request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 1048576);
ALTER TABLE signal_control.commits ADD COLUMN feed_position bigint NOT NULL CHECK(feed_position>=0);
ALTER TABLE signal_control.commits ADD COLUMN feed_digest bytea NOT NULL CHECK(octet_length(feed_digest)=32);
ALTER TABLE signal_control.receipts ADD COLUMN retained_request bytea NOT NULL CHECK(octet_length(retained_request) BETWEEN 1 AND 1048576);
ALTER TABLE signal_control.outbox ADD UNIQUE(id);

CREATE FUNCTION signal_control.require_keys(v jsonb, keys text[]) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, signal_control, pg_temp AS $$
BEGIN
    IF v IS NULL OR jsonb_typeof(v) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    IF NOT(v ?& keys) OR (SELECT count(*) FROM jsonb_object_keys(v))<>cardinality(keys) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
END $$;
CREATE FUNCTION signal_control.hex_bytes(v jsonb, maximum integer) RETURNS bytea
LANGUAGE plpgsql SET search_path = pg_catalog, signal_control, pg_temp AS $$
DECLARE text_value text;
BEGIN
    IF jsonb_typeof(v) IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    text_value:=v#>>'{}';
    IF octet_length(text_value)<2 OR octet_length(text_value)>maximum*2
        OR text_value !~ '^([0-9a-f]{2})+$' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    RETURN decode(text_value,'hex');
END $$;
CREATE FUNCTION signal_control.feed_cursor(store uuid, feed_index bigint, digest bytea) RETURNS text
LANGUAGE sql SET search_path = pg_catalog, signal_control, pg_temp AS $$
    SELECT replace(translate(encode(decode('01'||replace(store::text,'-','')||lpad(to_hex(feed_index),16,'0'),'hex')||digest,'base64'),'+/','-_'),E'\n','');
$$;
CREATE FUNCTION signal_control.publication_result(c signal_control.commits, store uuid) RETURNS jsonb
LANGUAGE sql SET search_path = pg_catalog, signal_control, pg_temp AS $$
    SELECT jsonb_build_object('schema_version',1,'id',c.id,'first_sequence',c.first_sequence,
        'last_sequence',c.last_sequence,'cursor',signal_control.feed_cursor(store,c.feed_position,c.feed_digest),
        'request_sha256',encode(c.request_sha256,'hex'));
$$;
-- Administrator-enrolled canonical physical namespaces. All aliases must use the
-- same ID. No producer/backend spelling or runtime principal can enroll an alias.
CREATE TABLE signal_control.object_backends (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    canonical_id text NOT NULL UNIQUE CHECK(octet_length(canonical_id) BETWEEN 1 AND 256)
);
CREATE TABLE signal_control.object_scopes (
    partition_id uuid PRIMARY KEY REFERENCES signal_control.partitions(id),
    backend_id uuid NOT NULL REFERENCES signal_control.object_backends(id),
    key_prefix text NOT NULL CHECK(octet_length(key_prefix) BETWEEN 1 AND 512 AND right(key_prefix,1)='/')
);
ALTER TABLE signal_control.commits ADD COLUMN backend_id uuid NOT NULL REFERENCES signal_control.object_backends(id);
ALTER TABLE signal_control.commits ADD COLUMN object_hashes bytea[] NOT NULL CHECK(cardinality(object_hashes) BETWEEN 1 AND 128);
CREATE INDEX committed_objects ON signal_control.commits USING gin(object_hashes);
ALTER TABLE signal_control.snapshots ADD COLUMN object_hashes bytea[] NOT NULL CHECK(cardinality(object_hashes) BETWEEN 0 AND 128);
CREATE INDEX reader_objects ON signal_control.snapshots USING gin(object_hashes);
ALTER TABLE signal_control.tombstones ADD COLUMN request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 16384);
ALTER TABLE signal_control.tombstones ADD COLUMN request_sha256 bytea NOT NULL CHECK(request_sha256=sha256(request));
ALTER TABLE signal_control.tombstones ADD CHECK(reference_sha256=sha256(object_reference));
CREATE TABLE signal_control.object_pins (
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    id uuid NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    generation uuid NOT NULL, epoch bigint NOT NULL CHECK(epoch>0), owner uuid NOT NULL,
    kind text NOT NULL CHECK(kind IN ('restore','replay','evidence')),
    object_reference bytea NOT NULL CHECK(octet_length(object_reference) BETWEEN 1 AND 4096),
    reference_sha256 bytea NOT NULL CHECK(reference_sha256=sha256(object_reference)),
    request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 16384),
    request_sha256 bytea NOT NULL CHECK(request_sha256=sha256(request)),
    state text NOT NULL CHECK(state IN ('retained','released')),
    release_request bytea CHECK(octet_length(release_request) BETWEEN 1 AND 16384),
    release_sha256 bytea CHECK(release_sha256=sha256(release_request)),
    release_generation uuid, release_epoch bigint, release_owner uuid,
    PRIMARY KEY(partition_id,id),
    CHECK((state='retained' AND release_request IS NULL AND release_sha256 IS NULL AND release_generation IS NULL AND release_epoch IS NULL AND release_owner IS NULL)
       OR (state='released' AND release_request IS NOT NULL AND release_sha256 IS NOT NULL AND release_generation IS NOT NULL AND release_epoch IS NOT NULL AND release_epoch>0 AND release_owner IS NOT NULL))
);
CREATE INDEX retained_objects ON signal_control.object_pins(reference_sha256) WHERE state='retained';
REVOKE ALL ON signal_control.object_backends, signal_control.object_scopes, signal_control.object_pins FROM PUBLIC;

-- Integrity seals bind the indexed tuples to immutable metadata. Eligibility must
-- never rely on an omitted/corrupted index entry, shortened expiry or released bit.
CREATE FUNCTION signal_control.object_hash_bytes(hashes bytea[]) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE value bytea; packed bytea:=''::bytea;
BEGIN
    IF hashes IS NULL OR cardinality(hashes)>128 OR cardinality(hashes)<0
        OR (cardinality(hashes)>0 AND (array_ndims(hashes) IS DISTINCT FROM 1 OR array_lower(hashes,1) IS DISTINCT FROM 1)) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
    END IF;
    FOREACH value IN ARRAY hashes LOOP
        IF value IS NULL OR octet_length(value)<>32 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
        packed:=packed||value;
    END LOOP;
    RETURN packed;
END $$;
CREATE FUNCTION signal_control.commit_object_seal(backend uuid, manifest_hash bytea, hashes bytea[]) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,signal_control,pg_temp AS $$
    SELECT sha256(convert_to('SIGNAL-CONTROL-COMMIT-PINS-V1','UTF8')||uuid_send(backend)||manifest_hash||signal_control.object_hash_bytes(hashes));
$$;
CREATE FUNCTION signal_control.reader_object_seal(identity uuid, part uuid, generation uuid, ids bytea,
    expiry timestamptz, lifetime integer, hashes bytea[]) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,signal_control,pg_temp AS $$
    SELECT sha256(convert_to('SIGNAL-CONTROL-READER-PINS-V1','UTF8')||uuid_send(identity)||uuid_send(part)||uuid_send(generation)
        ||int4send(octet_length(ids))||ids||timestamptz_send(expiry)||int4send(lifetime)||signal_control.object_hash_bytes(hashes));
$$;
ALTER TABLE signal_control.commits ADD COLUMN objects_sha256 bytea NOT NULL CHECK(octet_length(objects_sha256)=32);
ALTER TABLE signal_control.snapshots ADD COLUMN objects_sha256 bytea NOT NULL CHECK(octet_length(objects_sha256)=32);

CREATE FUNCTION signal_control.object_scope(part uuid) RETURNS signal_control.object_scopes
LANGUAGE plpgsql SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE binding signal_control.object_scopes;
BEGIN
    SELECT * INTO binding FROM signal_control.object_scopes WHERE partition_id=part;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
    RETURN binding;
END $$;
CREATE FUNCTION signal_control.object_reference(o jsonb) RETURNS bytea
LANGUAGE plpgsql SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE backend uuid; key_name text; version_name text;
BEGIN
    PERFORM signal_control.require_keys(o,ARRAY['schema_version','backend_id','key','version']);
    IF o->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR jsonb_typeof(o->'backend_id') IS DISTINCT FROM 'string'
        OR jsonb_typeof(o->'key') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'version') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
    END IF;
    backend:=(o->>'backend_id')::uuid; key_name:=o->>'key'; version_name:=o->>'version';
    IF backend='00000000-0000-0000-0000-000000000000'
        OR octet_length(key_name) NOT BETWEEN 1 AND 512 OR octet_length(version_name) NOT BETWEEN 1 AND 256
        OR key_name ~ '[[:cntrl:]]' OR version_name ~ '[[:cntrl:]]' OR key_name ~ '[\\%?#]'
        OR left(key_name,1)='/' OR key_name ~ '(^|/)(\.|\.\.)(/|$)' OR position('//' IN key_name)>0 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
    END IF;
    RETURN convert_to('SIGNAL-CONTROL-OBJECT-V1','UTF8')||uuid_send(backend)||int4send(octet_length(key_name))||convert_to(key_name,'UTF8')||int4send(octet_length(version_name))||convert_to(version_name,'UTF8');
END $$;
CREATE FUNCTION signal_control.manifest_objects(binding signal_control.object_scopes, m jsonb) RETURNS bytea[]
LANGUAGE plpgsql SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE item jsonb; ref bytea; digest bytea; refs bytea[]:='{}'; total integer;
BEGIN
    IF jsonb_typeof(m->'files') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
    END IF;
    total:=jsonb_array_length(m->'files')+CASE WHEN m->'previous'='null'::jsonb THEN 0 ELSE 1 END;
    IF total NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
    FOR item IN SELECT x->'object' FROM jsonb_array_elements(m->'files') AS x
        UNION ALL SELECT m->'previous'->'object' WHERE m->'previous' IS DISTINCT FROM 'null'::jsonb LOOP
        PERFORM signal_control.require_keys(item,ARRAY['key','version','etag','bytes','sha256']);
        IF left(item->>'key',length(binding.key_prefix)) IS DISTINCT FROM binding.key_prefix THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
        END IF;
        ref:=signal_control.object_reference(jsonb_build_object('schema_version',1,'backend_id',binding.backend_id,'key',item->'key','version',item->'version'));
        digest:=sha256(ref);
        IF EXISTS(SELECT 1 FROM signal_control.tombstones WHERE reference_sha256=digest) THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
        END IF;
        refs:=array_append(refs,digest);
    END LOOP;
    RETURN ARRAY(SELECT h FROM unnest(refs) AS h ORDER BY h);
END $$;
CREATE FUNCTION signal_control.assert_retention_integrity() RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.object_pins; t signal_control.tombstones; original jsonb; released jsonb;
BEGIN
    IF EXISTS(SELECT 1 FROM signal_control.commits WHERE manifest_sha256<>sha256(manifest) OR request_sha256<>sha256(request)
        OR objects_sha256 IS DISTINCT FROM signal_control.commit_object_seal(backend_id,manifest_sha256,object_hashes))
        OR EXISTS(SELECT 1 FROM signal_control.snapshots WHERE objects_sha256 IS DISTINCT FROM
            signal_control.reader_object_seal(id,partition_id,generation,manifest_ids,expires_at,pin_ms,object_hashes)) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
    END IF;
    -- History is bounded by the store row/byte ceilings and the original statement,
    -- transaction and operation budgets. Incomplete validation cannot grant retirement.
    FOR p IN SELECT * FROM signal_control.object_pins LOOP
        original:=convert_from(p.request,'UTF8')::jsonb;
        IF p.request_sha256<>sha256(p.request) OR p.reference_sha256<>sha256(p.object_reference)
            OR signal_control.object_reference(original->'object') IS DISTINCT FROM p.object_reference
            OR original->>'kind' IS DISTINCT FROM p.kind OR (original->>'id')::uuid IS DISTINCT FROM p.id
            OR original->>'operation' IS DISTINCT FROM 'pin'
            OR (p.state='released' AND (p.release_request IS NULL OR p.release_sha256 IS NULL
                OR p.release_sha256<>sha256(p.release_request) OR p.release_generation IS NULL OR p.release_epoch IS NULL
                OR p.release_epoch<1 OR p.release_owner IS NULL)) THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
        END IF;
        IF p.state='released' THEN
            released:=convert_from(p.release_request,'UTF8')::jsonb;
            IF released->'schema_version' IS DISTINCT FROM '1'::jsonb
                OR released->>'operation' IS DISTINCT FROM 'release' OR (released->>'id')::uuid IS DISTINCT FROM p.id THEN
                RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
            END IF;
        END IF;
    END LOOP;
    FOR t IN SELECT * FROM signal_control.tombstones LOOP
        original:=convert_from(t.request,'UTF8')::jsonb;
        IF t.request_sha256<>sha256(t.request) OR t.reference_sha256<>sha256(t.object_reference)
            OR signal_control.object_reference(original->'object') IS DISTINCT FROM t.object_reference
            OR (original->>'id')::uuid IS DISTINCT FROM t.id OR original->>'operation' IS DISTINCT FROM 'retire'
            OR t.state<>'retired' THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
        END IF;
    END LOOP;
END $$;
CREATE FUNCTION signal_control.object_control(t jsonb, raw bytea, expected_schema bytea, expected_routines bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions; binding signal_control.object_scopes; r jsonb; op text; identity uuid;
    pin signal_control.object_pins; tomb signal_control.tombstones; ref bytea; digest bytea; charge bigint; state_name text;
BEGIN
    p:=signal_control.check_token(t,expected_schema,expected_routines);
    IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 16384 THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
    END IF;
    binding:=signal_control.object_scope(p.id);
    r:=convert_from(raw,'UTF8')::jsonb; op:=r->>'operation';
    IF op='pin' THEN PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','id','object','kind','reference']);
    ELSIF op='release' THEN PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','id','reason']);
    ELSIF op='retire' THEN PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','id','object','reason']);
    ELSE RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
    IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'id') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
    END IF;
    identity:=(r->>'id')::uuid;
    IF identity='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END IF;
    IF op='release' THEN
        PERFORM signal_control.hex_bytes(r->'reason',4096);
        SELECT * INTO pin FROM signal_control.object_pins WHERE partition_id=p.id AND id=identity FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF pin.reference_sha256<>sha256(pin.object_reference) OR pin.request_sha256<>sha256(pin.request) THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
        END IF;
        -- The original binding is pinned inside the retained exact request.
        IF (convert_from(pin.request,'UTF8')::jsonb->'object'->>'backend_id')::uuid IS DISTINCT FROM binding.backend_id THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
        END IF;
        IF signal_control.object_reference(convert_from(pin.request,'UTF8')::jsonb->'object') IS DISTINCT FROM pin.object_reference
            OR left(convert_from(pin.request,'UTF8')::jsonb->'object'->>'key',length(binding.key_prefix)) IS DISTINCT FROM binding.key_prefix THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
        END IF;
        digest:=pin.reference_sha256; state_name:='released';
        IF pin.state='released' THEN
            IF pin.release_request<>raw THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
            IF pin.release_sha256<>sha256(raw) THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT'; END IF;
        ELSE
            charge:=octet_length(raw);
            UPDATE signal_control.store SET used_bytes=used_bytes+charge WHERE singleton AND charge<=max_bytes-used_bytes;
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
            UPDATE signal_control.object_pins SET state='released',release_request=raw,release_sha256=sha256(raw),
                release_generation=(t->'scope'->>'generation')::uuid,release_epoch=p.epoch,release_owner=p.owner
                WHERE partition_id=p.id AND id=identity;
        END IF;
    ELSE
        ref:=signal_control.object_reference(r->'object'); digest:=sha256(ref);
        IF (r->'object'->>'backend_id')::uuid IS DISTINCT FROM binding.backend_id
            OR left(r->'object'->>'key',length(binding.key_prefix)) IS DISTINCT FROM binding.key_prefix THEN
            RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
        END IF;
        IF op='pin' THEN
            IF jsonb_typeof(r->'kind') IS DISTINCT FROM 'string' OR r->>'kind' NOT IN ('restore','replay','evidence') THEN
                RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
            END IF;
            PERFORM signal_control.hex_bytes(r->'reference',4096);
            IF EXISTS(SELECT 1 FROM signal_control.tombstones WHERE reference_sha256=digest) THEN
                RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
            END IF;
            SELECT * INTO pin FROM signal_control.object_pins WHERE partition_id=p.id AND id=identity FOR UPDATE;
            IF FOUND THEN
                IF pin.request<>raw OR pin.state<>'retained' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
                IF pin.request_sha256<>sha256(raw) OR pin.object_reference<>ref OR pin.reference_sha256<>digest OR pin.kind<>r->>'kind' THEN
                    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
                END IF;
            ELSE
                charge:=512+octet_length(ref)+octet_length(raw);
                UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+charge
                    WHERE singleton AND used_rows<max_rows AND charge<=max_bytes-used_bytes;
                IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
                INSERT INTO signal_control.object_pins(partition_id,id,generation,epoch,owner,kind,object_reference,reference_sha256,request,request_sha256,state)
                    VALUES(p.id,identity,(t->'scope'->>'generation')::uuid,p.epoch,p.owner,r->>'kind',ref,digest,raw,sha256(raw),'retained');
            END IF;
            state_name:='retained';
        ELSE
            PERFORM signal_control.hex_bytes(r->'reason',4096);
            PERFORM signal_control.assert_retention_integrity();
            SELECT * INTO tomb FROM signal_control.tombstones WHERE partition_id=p.id AND id=identity FOR UPDATE;
            IF FOUND THEN
                IF tomb.request<>raw THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT'; END IF;
                IF tomb.object_reference<>ref OR tomb.reference_sha256<>digest OR tomb.request_sha256<>sha256(raw) OR tomb.state<>'retired' THEN
                    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
                END IF;
            ELSE
                IF EXISTS(SELECT 1 FROM signal_control.tombstones WHERE reference_sha256=digest) THEN
                    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT';
                END IF;
                -- All committed history is retained in revision1, including current
                -- roots and exact replay/evidence; do not silently release it.
                IF EXISTS(SELECT 1 FROM signal_control.commits WHERE object_hashes @> ARRAY[digest])
                    OR EXISTS(SELECT 1 FROM signal_control.snapshots WHERE object_hashes @> ARRAY[digest] AND expires_at>clock_timestamp())
                    OR EXISTS(SELECT 1 FROM signal_control.object_pins WHERE reference_sha256=digest AND state='retained') THEN
                    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT';
                END IF;
                charge:=512+octet_length(ref)+octet_length(raw);
                UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+charge
                    WHERE singleton AND used_rows<max_rows AND charge<=max_bytes-used_bytes;
                IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF;
                INSERT INTO signal_control.tombstones(partition_id,id,generation,epoch,object_reference,reference_sha256,state,request,request_sha256)
                    VALUES(p.id,identity,(t->'scope'->>'generation')::uuid,p.epoch,ref,digest,'retired',raw,sha256(raw));
            END IF;
            state_name:='retired';
        END IF;
    END IF;
    PERFORM signal_control.check_token(t,expected_schema,expected_routines);
    RETURN jsonb_build_object('schema_version',1,'id',identity,'reference_sha256',encode(digest,'hex'),'state',state_name,'request_sha256',encode(sha256(raw),'hex'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
END $$;

CREATE FUNCTION signal_control.record_receipt(t jsonb, raw bytea, expected_schema bytea, expected_routines bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp AS $$
DECLARE p signal_control.partitions; r jsonb; item signal_control.receipts; ref bytea;
    identity uuid; prepared bigint; source_count bigint; charge bigint;
BEGIN
    p:=signal_control.check_token(t,expected_schema,expected_routines);
    IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 1048576 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    r:=convert_from(raw,'UTF8')::jsonb;
    PERFORM signal_control.require_keys(r,ARRAY['schema_version','id','prepared_count','source_record_count','reference']);
    IF jsonb_typeof(r->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'prepared_count') IS DISTINCT FROM 'number'
        OR jsonb_typeof(r->'source_record_count') IS DISTINCT FROM 'number' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    identity:=(r->>'id')::uuid; prepared:=(r->>'prepared_count')::bigint; source_count:=(r->>'source_record_count')::bigint;
    ref:=signal_control.hex_bytes(r->'reference',65536);
    IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR identity IS NULL OR identity='00000000-0000-0000-0000-000000000000'
        OR prepared IS NULL OR prepared NOT BETWEEN 0 AND 4096 OR source_count IS NULL OR source_count NOT BETWEEN 0 AND 4096 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    SELECT * INTO item FROM signal_control.receipts WHERE partition_id=p.id AND id=identity FOR UPDATE;
    IF FOUND THEN
        IF item.retained_request<>raw THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF item.reference<>ref OR item.reference_sha256<>sha256(ref) OR item.prepared_count<>prepared OR item.source_record_count<>source_count THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
    ELSE
        charge:=256+octet_length(ref)+octet_length(raw);
        UPDATE signal_control.store SET used_rows=used_rows+1, used_bytes=used_bytes+charge
            WHERE singleton AND used_rows<max_rows AND charge<=max_bytes-used_bytes;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
        INSERT INTO signal_control.receipts(partition_id,id,prepared_count,source_record_count,state,reference,reference_sha256,retained_request)
            VALUES(p.id,identity,prepared,source_count,'retained',ref,sha256(ref),raw) RETURNING * INTO item;
    END IF;
    PERFORM signal_control.check_token(t,expected_schema,expected_routines);
    RETURN jsonb_build_object('schema_version',1,'id',item.id,'prepared_count',item.prepared_count,
        'source_record_count',item.source_record_count,'verified_prefix',item.verified_prefix);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
END $$;

CREATE FUNCTION signal_control.publish(t jsonb, raw bytea, resolve_only boolean, expected_schema bytea, expected_routines bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp AS $$
DECLARE p signal_control.partitions; h signal_control.store; r jsonb; m jsonb; v jsonb; content jsonb;
    c signal_control.commits; prior signal_control.commits; old_state signal_control.state;
    found_finding signal_control.findings; found_work signal_control.outbox; receipt signal_control.receipts;
    identity uuid; previous_id uuid; first_seq bigint; last_seq bigint; raw_manifest bytea; revision bytea;
    binding signal_control.object_scopes; object_refs bytea[];
    normalizer text; payload bytea; rows_charge bigint:=1; bytes_charge bigint; key_name text;
    new_findings uuid[]:='{}'; feed_pos bigint; feed_hash bytea; progress bigint:=0; hash_json jsonb;
BEGIN
    p:=signal_control.check_token(t,expected_schema,expected_routines);
    IF p.kind<>'pipeline' OR raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 1048576 OR resolve_only IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    r:=convert_from(raw,'UTF8')::jsonb;
    PERFORM signal_control.require_keys(r,ARRAY['schema_version','id','previous','first_sequence','last_sequence','manifest','rule_revision','normalizer_revision','states','findings','work','receipts']);
    IF r->'schema_version' IS DISTINCT FROM '1'::jsonb THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    IF jsonb_typeof(r->'id') IS DISTINCT FROM 'string'
        OR jsonb_typeof(r->'first_sequence') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'last_sequence') IS DISTINCT FROM 'number'
        OR jsonb_typeof(r->'normalizer_revision') IS DISTINCT FROM 'string'
        OR jsonb_typeof(r->'previous') NOT IN ('string','null') THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    identity:=(r->>'id')::uuid; previous_id:=(r->>'previous')::uuid;
    first_seq:=(r->>'first_sequence')::bigint; last_seq:=(r->>'last_sequence')::bigint;
    raw_manifest:=signal_control.hex_bytes(r->'manifest',262144);
    revision:=signal_control.hex_bytes(r->'rule_revision',32); normalizer:=r->>'normalizer_revision';
    IF identity IS NULL OR identity='00000000-0000-0000-0000-000000000000' OR first_seq IS NULL OR last_seq IS NULL
        OR first_seq<1 OR last_seq<first_seq OR last_seq-first_seq>=4096 OR octet_length(revision)<>32
        OR normalizer IS NULL OR octet_length(normalizer) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    FOREACH key_name IN ARRAY ARRAY['states','findings','work','receipts'] LOOP
        IF jsonb_typeof(r->key_name) IS DISTINCT FROM 'array' OR jsonb_array_length(r->key_name)>128 THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
        END IF;
    END LOOP;
    binding:=signal_control.object_scope(p.id);
    m:=convert_from(raw_manifest,'UTF8')::jsonb;
    object_refs:=signal_control.manifest_objects(binding,m);
    SELECT * INTO c FROM signal_control.commits WHERE partition_id=p.id AND id=identity FOR UPDATE;
    IF FOUND THEN
        IF c.request<>raw OR c.request_sha256<>sha256(raw) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
        END IF;
        IF c.backend_id<>binding.backend_id OR c.object_hashes IS DISTINCT FROM object_refs
            OR c.objects_sha256 IS DISTINCT FROM signal_control.commit_object_seal(c.backend_id,c.manifest_sha256,c.object_hashes)
            OR c.manifest<>raw_manifest OR c.manifest_sha256<>sha256(raw_manifest) OR c.rule_revision<>revision
            OR c.normalizer_revision<>normalizer OR c.first_sequence<>first_seq OR c.last_sequence<>last_seq
            OR c.previous IS DISTINCT FROM previous_id OR p.checkpoint<c.last_sequence THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        SELECT * INTO h FROM signal_control.store WHERE singleton;
        IF h.feed_position<c.feed_position OR (c.feed_position=0 AND c.feed_digest<>sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||decode(replace(h.store_id::text,'-',''),'hex')))
            OR (c.feed_position>0 AND NOT EXISTS(SELECT 1 FROM signal_control.findings WHERE position=c.feed_position AND cursor_digest=c.feed_digest)) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        FOR v IN SELECT x FROM jsonb_array_elements(r->'findings') AS x LOOP
            SELECT * INTO found_finding FROM signal_control.findings WHERE id=(v->>'id')::uuid;
            IF NOT FOUND OR found_finding.content<>signal_control.hex_bytes(v->'bytes',65536) OR found_finding.content_sha256<>sha256(found_finding.content) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
            END IF;
        END LOOP;
        FOR v IN SELECT x FROM jsonb_array_elements(r->'work') AS x LOOP
            SELECT * INTO found_work FROM signal_control.outbox WHERE id=(v->>'id')::uuid;
            IF NOT FOUND OR found_work.finding_id IS DISTINCT FROM (v->>'finding_id')::uuid OR found_work.plan<>signal_control.hex_bytes(v->'bytes',65536) OR found_work.plan_sha256<>sha256(found_work.plan) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
            END IF;
        END LOOP;
        FOR v IN SELECT x FROM jsonb_array_elements(r->'receipts') AS x LOOP
            SELECT * INTO receipt FROM signal_control.receipts WHERE partition_id=p.id AND id=(v->>'id')::uuid;
            IF NOT FOUND OR receipt.verified_prefix<(v->>'verified_prefix')::bigint OR receipt.reference_sha256<>sha256(receipt.reference) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
            END IF;
        END LOOP;
        PERFORM signal_control.check_token(t,expected_schema,expected_routines);
        RETURN signal_control.publication_result(c,(t->'scope'->>'store_id')::uuid);
    END IF;
    IF resolve_only THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_UNCERTAIN'; END IF;
    IF (p.checkpoint=0)<>(p.head IS NULL) THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    IF p.checkpoint=9223372036854775807 OR first_seq<>p.checkpoint+1 OR previous_id IS DISTINCT FROM p.head THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
    END IF;
    m:=convert_from(raw_manifest,'UTF8')::jsonb;
    IF m->'schema_version' IS DISTINCT FROM '1'::jsonb OR m->'storage_schema_version' IS DISTINCT FROM '1'::jsonb
        OR (m->>'stream_id')::uuid IS DISTINCT FROM p.stream OR (m->>'first_sequence')::bigint IS DISTINCT FROM first_seq
        OR (m->>'last_sequence')::bigint IS DISTINCT FROM last_seq OR (m->>'events')::bigint IS DISTINCT FROM last_seq-first_seq+1
        OR m->>'normalizer_revision' IS DISTINCT FROM normalizer THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    IF previous_id IS NULL THEN
        IF m->'previous' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
    ELSE
        SELECT * INTO prior FROM signal_control.commits WHERE partition_id=p.id AND id=previous_id;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF prior.last_sequence<>p.checkpoint OR prior.manifest_sha256<>sha256(prior.manifest) OR prior.request_sha256<>sha256(prior.request) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        SELECT jsonb_agg(get_byte(prior.manifest_sha256,i) ORDER BY i) INTO hash_json FROM generate_series(0,31) AS i;
        IF m->'previous'->>'first_sequence' IS DISTINCT FROM prior.first_sequence::text
            OR m->'previous'->>'last_sequence' IS DISTINCT FROM prior.last_sequence::text
            OR m->'previous'->'object'->'sha256' IS DISTINCT FROM hash_json
            OR (m->'previous'->'object'->>'bytes')::bigint IS DISTINCT FROM octet_length(prior.manifest)::bigint THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
        END IF;
    END IF;
    SELECT * INTO h FROM signal_control.store WHERE singleton;
    feed_pos:=h.feed_position; feed_hash:=h.feed_digest;
    IF feed_pos=0 THEN
        IF feed_hash<>sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||decode(replace(h.store_id::text,'-',''),'hex')) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
    ELSIF NOT EXISTS(SELECT 1 FROM signal_control.findings WHERE position=feed_pos AND cursor_digest=feed_hash) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
    END IF;
    bytes_charge:=512+octet_length(raw)+octet_length(raw_manifest)+octet_length(normalizer)+32*cardinality(object_refs);
    -- The store lock serializes all children; explicit canonical orders remain fixed.
    IF (SELECT count(DISTINCT x->>'key') FROM jsonb_array_elements(r->'states') AS x)<>jsonb_array_length(r->'states')
        OR (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(r->'findings') AS x)<>jsonb_array_length(r->'findings')
        OR (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(r->'work') AS x)<>jsonb_array_length(r->'work')
        OR (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(r->'receipts') AS x)<>jsonb_array_length(r->'receipts') THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'states') AS x ORDER BY x->>'key' LOOP
        PERFORM signal_control.require_keys(v,ARRAY['key','revision','bytes']);
        key_name:=v->>'key'; payload:=signal_control.hex_bytes(v->'bytes',65536);
        IF jsonb_typeof(v->'key') IS DISTINCT FROM 'string' OR key_name IS NULL OR octet_length(key_name) NOT BETWEEN 1 AND 256 OR signal_control.hex_bytes(v->'revision',32)<>revision THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
        END IF;
        SELECT * INTO old_state FROM signal_control.state WHERE partition_id=p.id AND key=key_name FOR UPDATE;
        IF FOUND THEN
            IF old_state.revision<>revision THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
            bytes_charge:=bytes_charge+octet_length(payload)-octet_length(old_state.value);
        ELSE rows_charge:=rows_charge+1; bytes_charge:=bytes_charge+192+octet_length(key_name)+octet_length(payload); END IF;
    END LOOP;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'findings') AS x ORDER BY x->>'id' LOOP
        PERFORM signal_control.require_keys(v,ARRAY['id','bytes']);
        payload:=signal_control.hex_bytes(v->'bytes',65536); identity:=(v->>'id')::uuid;
        content:=convert_from(payload,'UTF8')::jsonb;
        IF jsonb_typeof(v->'id') IS DISTINCT FROM 'string' OR identity IS NULL OR identity='00000000-0000-0000-0000-000000000000' OR content->'schema_version' IS DISTINCT FROM '1'::jsonb
            OR (content->>'id')::uuid IS DISTINCT FROM identity THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
        SELECT * INTO found_finding FROM signal_control.findings WHERE id=identity FOR UPDATE;
        IF FOUND THEN
            IF found_finding.content<>payload OR found_finding.content_sha256<>sha256(payload) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
            END IF;
        ELSE
            new_findings:=array_append(new_findings,identity);
            rows_charge:=rows_charge+1; bytes_charge:=bytes_charge+256+octet_length(payload);
        END IF;
    END LOOP;
    IF cardinality(new_findings)>9223372036854775807-feed_pos THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL';
    END IF;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'work') AS x ORDER BY x->>'id' LOOP
        PERFORM signal_control.require_keys(v,ARRAY['id','finding_id','bytes']);
        payload:=signal_control.hex_bytes(v->'bytes',65536); identity:=(v->>'id')::uuid;
        IF jsonb_typeof(v->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'finding_id') IS DISTINCT FROM 'string'
            OR (v->>'finding_id')::uuid IS NULL OR (v->>'finding_id')::uuid='00000000-0000-0000-0000-000000000000'
            OR identity IS NULL OR identity='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
        SELECT * INTO found_work FROM signal_control.outbox WHERE id=identity FOR UPDATE;
        IF FOUND THEN
            IF found_work.finding_id IS DISTINCT FROM (v->>'finding_id')::uuid OR found_work.plan<>payload OR found_work.plan_sha256<>sha256(payload) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
            END IF;
        ELSE
            IF NOT((v->>'finding_id')::uuid=ANY(new_findings)) THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
            rows_charge:=rows_charge+1; bytes_charge:=bytes_charge+256+octet_length(payload);
        END IF;
    END LOOP;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'receipts') AS x ORDER BY x->>'id' LOOP
        PERFORM signal_control.require_keys(v,ARRAY['id','expected_prefix','verified_prefix']);
        IF jsonb_typeof(v->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'expected_prefix') IS DISTINCT FROM 'number'
            OR jsonb_typeof(v->'verified_prefix') IS DISTINCT FROM 'number'
            OR (v->>'expected_prefix')::bigint NOT BETWEEN 0 AND 4096 OR (v->>'verified_prefix')::bigint NOT BETWEEN 1 AND 4096 THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
        END IF;
        SELECT * INTO receipt FROM signal_control.receipts WHERE partition_id=p.id AND id=(v->>'id')::uuid FOR UPDATE;
        IF NOT FOUND OR receipt.prepared_count=0 OR receipt.verified_prefix IS DISTINCT FROM (v->>'expected_prefix')::bigint
            OR (v->>'verified_prefix')::bigint<=receipt.verified_prefix OR (v->>'verified_prefix')::bigint>receipt.prepared_count
            OR receipt.state NOT IN ('retained','admitted') THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        progress:=progress+(v->>'verified_prefix')::bigint-receipt.verified_prefix;
    END LOOP;
    IF jsonb_array_length(r->'receipts')>0 AND progress<>last_seq-first_seq+1 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
    UPDATE signal_control.store SET used_rows=used_rows+rows_charge, used_bytes=used_bytes+bytes_charge
        WHERE singleton AND rows_charge<=max_rows-used_rows AND bytes_charge<=max_bytes-used_bytes AND used_bytes+bytes_charge>=0;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
    INSERT INTO signal_control.commits(partition_id,id,generation,epoch,request_sha256,request,first_sequence,last_sequence,manifest,manifest_sha256,rule_revision,normalizer_revision,previous,feed_position,feed_digest,backend_id,object_hashes,objects_sha256)
        VALUES(p.id,(r->>'id')::uuid,(t->'scope'->>'generation')::uuid,p.epoch,sha256(raw),raw,first_seq,last_seq,raw_manifest,sha256(raw_manifest),revision,normalizer,previous_id,feed_pos,feed_hash,binding.backend_id,object_refs,signal_control.commit_object_seal(binding.backend_id,sha256(raw_manifest),object_refs));
    FOR v IN SELECT x FROM jsonb_array_elements(r->'states') AS x ORDER BY x->>'key' LOOP
        INSERT INTO signal_control.state(partition_id,key,revision,value) VALUES(p.id,v->>'key',revision,signal_control.hex_bytes(v->'bytes',65536))
            ON CONFLICT(partition_id,key) DO UPDATE SET value=EXCLUDED.value;
    END LOOP;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'findings') AS x ORDER BY x->>'id' LOOP
        identity:=(v->>'id')::uuid;
        IF identity=ANY(new_findings) THEN
            payload:=signal_control.hex_bytes(v->'bytes',65536); feed_pos:=feed_pos+1;
            feed_hash:=sha256(convert_to('SIGNAL-FINDINGS-RECORD-V1','UTF8')||feed_hash||decode(lpad(to_hex(feed_pos),16,'0')||lpad(to_hex(octet_length(payload)),8,'0'),'hex')||payload);
            INSERT INTO signal_control.findings(partition_id,commit_id,id,position,cursor_digest,content,content_sha256)
                VALUES(p.id,(r->>'id')::uuid,identity,feed_pos,feed_hash,payload,sha256(payload));
        END IF;
    END LOOP;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'work') AS x ORDER BY x->>'id' LOOP
        payload:=signal_control.hex_bytes(v->'bytes',65536);
        INSERT INTO signal_control.outbox(partition_id,finding_id,id,plan,plan_sha256,status)
            VALUES(p.id,(v->>'finding_id')::uuid,(v->>'id')::uuid,payload,sha256(payload),'pending') ON CONFLICT(id) DO NOTHING;
    END LOOP;
    FOR v IN SELECT x FROM jsonb_array_elements(r->'receipts') AS x ORDER BY x->>'id' LOOP
        UPDATE signal_control.receipts SET commit_id=(r->>'id')::uuid,verified_prefix=(v->>'verified_prefix')::bigint,state='admitted'
            WHERE partition_id=p.id AND id=(v->>'id')::uuid;
    END LOOP;
    -- Recheck database-clock eligibility at the final publication under held locks.
    PERFORM signal_control.check_token(t,expected_schema,expected_routines);
    UPDATE signal_control.partitions SET checkpoint=last_seq,head=(r->>'id')::uuid,feed_position=feed_pos WHERE id=p.id;
    UPDATE signal_control.store SET feed_position=feed_pos,feed_digest=feed_hash WHERE singleton;
    UPDATE signal_control.commits SET feed_position=feed_pos,feed_digest=feed_hash
        WHERE partition_id=p.id AND id=(r->>'id')::uuid RETURNING * INTO c;
    RETURN signal_control.publication_result(c,h.store_id);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
END $$;

-- Read pins are installed explicitly with the checksum-bound fresh-schema bundle.
ALTER TABLE signal_control.snapshots ADD COLUMN pin_ms integer NOT NULL CHECK(pin_ms BETWEEN 1 AND 5000);
CREATE FUNCTION signal_control.read_snapshot(s jsonb, identity uuid, ids uuid[], lifetime integer,
    expected_schema bytea, expected_routines bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp AS $$
DECLARE p signal_control.partitions; pin signal_control.snapshots; c signal_control.commits;
    selected_id uuid; packed bytea := ''::bytea; items jsonb := '[]'::jsonb;
    m jsonb; objects integer := 0; reply_charge bigint := 256; charge bigint;
    remaining integer; removed_bytes bigint; reply jsonb; binding signal_control.object_scopes; refs bytea[]:='{}'; selected_refs bytea[]; expiry_time timestamptz;
BEGIN
    IF current_setting('transaction_isolation') <> 'repeatable read' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    IF identity IS NULL OR identity='00000000-0000-0000-0000-000000000000'
        OR ids IS NULL OR array_ndims(ids) IS DISTINCT FROM 1 OR array_lower(ids,1) IS DISTINCT FROM 1
        OR cardinality(ids) NOT BETWEEN 1 AND 128 OR lifetime IS NULL OR lifetime NOT BETWEEN 1 AND 5000
        OR EXISTS(SELECT 1 FROM unnest(ids) AS i WHERE i IS NULL OR i='00000000-0000-0000-0000-000000000000')
        OR (SELECT count(DISTINCT i) FROM unnest(ids) AS i) <> cardinality(ids) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
    END IF;
    p:=signal_control.check_scope(s,false,expected_schema,expected_routines);
    IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    binding:=signal_control.object_scope(p.id);
    FOREACH selected_id IN ARRAY ids LOOP
        packed:=packed||uuid_send(selected_id);
        SELECT * INTO c FROM signal_control.commits WHERE partition_id=p.id AND id=selected_id;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF c.generation IS DISTINCT FROM (s->>'generation')::uuid
            OR c.manifest_sha256<>sha256(c.manifest) OR c.request_sha256<>sha256(c.request) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        m:=convert_from(c.manifest,'UTF8')::jsonb;
        IF m->'schema_version' IS DISTINCT FROM '1'::jsonb OR m->'storage_schema_version' IS DISTINCT FROM '1'::jsonb
            OR (m->>'stream_id')::uuid IS DISTINCT FROM p.stream
            OR (m->>'first_sequence')::bigint IS DISTINCT FROM c.first_sequence
            OR (m->>'last_sequence')::bigint IS DISTINCT FROM c.last_sequence
            OR jsonb_typeof(m->'files') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        IF jsonb_array_length(m->'files')<1 THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        selected_refs:=signal_control.manifest_objects(binding,m);
        IF c.backend_id<>binding.backend_id OR c.object_hashes IS DISTINCT FROM selected_refs
            OR c.objects_sha256 IS DISTINCT FROM signal_control.commit_object_seal(c.backend_id,c.manifest_sha256,c.object_hashes) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        refs:=refs||selected_refs;
        objects:=objects+jsonb_array_length(m->'files')+CASE WHEN m->'previous' IS NULL OR m->'previous'='null'::jsonb THEN 0 ELSE 1 END;
        reply_charge:=reply_charge+2*octet_length(c.manifest)+512;
        IF objects>128 OR reply_charge>1048576 THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL';
        END IF;
        items:=items||jsonb_build_array(jsonb_build_object('id',c.id,'manifest',encode(c.manifest,'hex'),'sha256',encode(c.manifest_sha256,'hex')));
    END LOOP;
    SELECT * INTO pin FROM signal_control.snapshots WHERE id=identity;
    IF FOUND THEN
        IF pin.partition_id<>p.id OR pin.generation IS DISTINCT FROM (s->>'generation')::uuid THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
        END IF;
        IF pin.objects_sha256 IS DISTINCT FROM signal_control.reader_object_seal(pin.id,pin.partition_id,pin.generation,pin.manifest_ids,pin.expires_at,pin.pin_ms,pin.object_hashes) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        IF pin.expires_at<=clock_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_SNAPSHOT_EXPIRED';
        END IF;
        IF pin.manifest_ids<>packed OR pin.object_hashes IS DISTINCT FROM refs OR pin.pin_ms<>lifetime THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT';
        END IF;
        IF pin.expires_at<=clock_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_SNAPSHOT_EXPIRED';
        END IF;
    ELSE
        -- Validate the authorized reader catalog before compaction; an altered
        -- expiry cannot be laundered into a newly sealed expired marker.
        IF EXISTS(SELECT 1 FROM signal_control.snapshots WHERE partition_id=p.id AND objects_sha256 IS DISTINCT FROM
            signal_control.reader_object_seal(id,partition_id,generation,manifest_ids,expires_at,pin_ms,object_hashes)) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
        END IF;
        -- Compact at most128 expired authorized pins. Keep permanent ID/expiry
        -- markers, so cleanup can never turn an old request into a renewed pin.
        WITH expired AS (SELECT id,octet_length(manifest_ids)-1+32*cardinality(object_hashes) AS bytes
            FROM signal_control.snapshots WHERE partition_id=p.id
            AND expires_at<=clock_timestamp() AND octet_length(manifest_ids)>1 ORDER BY id LIMIT 128),
        removed AS (UPDATE signal_control.snapshots SET manifest_ids=decode('00','hex'),object_hashes='{}',objects_sha256=signal_control.reader_object_seal(snapshots.id,snapshots.partition_id,snapshots.generation,decode('00','hex'),snapshots.expires_at,snapshots.pin_ms,'{}'::bytea[])
            FROM expired WHERE snapshots.id=expired.id RETURNING expired.bytes)
        SELECT coalesce(sum(bytes),0) INTO removed_bytes FROM removed;
        UPDATE signal_control.store SET used_bytes=used_bytes-removed_bytes
            WHERE singleton AND used_bytes>=removed_bytes;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
        charge:=320+octet_length(packed)+32*cardinality(refs);
        UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+charge
            WHERE singleton AND used_rows<max_rows AND charge<=max_bytes-used_bytes;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
        expiry_time:=clock_timestamp()+lifetime*interval '1 millisecond';
        INSERT INTO signal_control.snapshots(id,partition_id,generation,manifest_ids,expires_at,pin_ms,object_hashes,objects_sha256)
            VALUES(identity,p.id,(s->>'generation')::uuid,packed,expiry_time,lifetime,refs,signal_control.reader_object_seal(identity,p.id,(s->>'generation')::uuid,packed,expiry_time,lifetime,refs))
            RETURNING * INTO pin;
    END IF;
    -- Floor and recheck the DB-clock remainder. Rust subtracts all queue/network time
    -- conservatively by anchoring this remainder before admission, never after COMMIT.
    remaining:=floor(extract(epoch FROM (pin.expires_at-clock_timestamp()))*1000)::integer;
    IF remaining<=0 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_SNAPSHOT_EXPIRED'; END IF;
    PERFORM signal_control.check_scope(s,false,expected_schema,expected_routines);
    reply:=jsonb_build_object('schema_version',1,'id',identity,'scope',s,'remaining_ms',remaining,'manifests',items);
    IF octet_length(reply::text)>1048576 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL';
    END IF;
    RETURN reply;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
END $$;

-- Original claims are immutable; one completion (or interruption) is retained
-- per globally unique attempt. Runtime has EXECUTE only, never table authority.
CREATE TABLE signal_control.notification_attempts (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    partition_id uuid NOT NULL,
    work_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 10),
    generation uuid NOT NULL CHECK(generation<>'00000000-0000-0000-0000-000000000000'),
    owner uuid NOT NULL CHECK(owner<>'00000000-0000-0000-0000-000000000000'),
    epoch bigint NOT NULL CHECK(epoch>0),
    plan_sha256 bytea NOT NULL CHECK(octet_length(plan_sha256)=32),
    claim_request bytea NOT NULL CHECK(octet_length(claim_request) BETWEEN 1 AND 4096),
    outcome text NOT NULL CHECK(outcome IN ('intent','uncertain','retryable','delivered','permanent')),
    completion_request bytea CHECK(octet_length(completion_request) BETWEEN 1 AND 16384),
    completion_generation uuid,
    completion_owner uuid,
    completion_epoch bigint,
    seal bytea NOT NULL CHECK(octet_length(seal)=32),
    FOREIGN KEY(partition_id,work_id) REFERENCES signal_control.outbox(partition_id,id),
    UNIQUE(work_id,ordinal),
    CHECK ((outcome='intent' AND completion_request IS NULL AND completion_generation IS NULL AND completion_owner IS NULL AND completion_epoch IS NULL) OR
      (outcome<>'intent' AND completion_request IS NOT NULL AND completion_generation IS NOT NULL AND completion_owner IS NOT NULL AND completion_epoch IS NOT NULL AND completion_epoch>0))
);
REVOKE ALL ON signal_control.notification_attempts FROM PUBLIC;
CREATE FUNCTION signal_control.notification_seal(a signal_control.notification_attempts) RETURNS bytea
LANGUAGE sql SET search_path = pg_catalog, signal_control, pg_temp AS $$
    SELECT sha256(convert_to('SIGNAL-NOTIFICATION-V1'||jsonb_build_object(
        'id',a.id,'partition_id',a.partition_id,'work_id',a.work_id,'ordinal',a.ordinal,
        'generation',a.generation,'owner',a.owner,'epoch',a.epoch,'plan_sha256',encode(a.plan_sha256,'hex'),
        'claim_request',encode(a.claim_request,'hex'),'outcome',a.outcome,
        'completion_request',encode(a.completion_request,'hex'),'completion_generation',a.completion_generation,
        'completion_owner',a.completion_owner,'completion_epoch',a.completion_epoch)::text,'UTF8'));
$$;
CREATE FUNCTION signal_control.check_notification(w signal_control.outbox) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, signal_control, pg_temp AS $$
DECLARE a signal_control.notification_attempts; latest signal_control.notification_attempts; n integer:=0;
    c signal_control.commits; original jsonb; expected text;
BEGIN
    IF w.plan_sha256 IS DISTINCT FROM sha256(w.plan) THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    -- Bind the original opaque plan and delivery key to the first finding commit.
    SELECT commits.* INTO c FROM signal_control.commits commits JOIN signal_control.findings f ON f.partition_id=commits.partition_id AND f.commit_id=commits.id
        WHERE f.partition_id=w.partition_id AND f.id=w.finding_id;
    IF NOT FOUND OR c.request_sha256 IS DISTINCT FROM sha256(c.request) THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    SELECT v INTO original FROM jsonb_array_elements(convert_from(c.request,'UTF8')::jsonb->'work') v WHERE (v->>'id')::uuid=w.id;
    IF original IS NULL OR (original->>'finding_id')::uuid IS DISTINCT FROM w.finding_id OR decode(original->>'bytes','hex') IS DISTINCT FROM w.plan THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    FOR a IN SELECT * FROM signal_control.notification_attempts WHERE work_id=w.id ORDER BY ordinal LOOP
        n:=n+1;
        IF a.partition_id<>w.partition_id OR a.ordinal<>n OR a.plan_sha256<>w.plan_sha256 OR a.seal IS DISTINCT FROM signal_control.notification_seal(a)
            OR convert_from(a.claim_request,'UTF8')::jsonb IS DISTINCT FROM jsonb_build_object('schema_version',1,'operation','claim','work_id',w.id,'attempt_id',a.id) THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
        latest:=a;
    END LOOP;
    IF n<>w.attempts THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    IF n=0 THEN
        IF w.status<>'pending' OR w.attempt_id IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    ELSE
        expected:=CASE WHEN n=10 AND latest.outcome IN ('retryable','uncertain') THEN 'exhausted' ELSE latest.outcome END;
        IF w.status<>expected OR w.attempt_id IS DISTINCT FROM latest.id OR w.claim_generation IS DISTINCT FROM latest.generation
            OR w.claim_owner IS DISTINCT FROM latest.owner OR w.claim_epoch IS DISTINCT FROM latest.epoch THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    END IF;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
END $$;
CREATE FUNCTION signal_control.notification(t jsonb, raw bytea, expected_schema bytea, expected_routines bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, signal_control, pg_temp AS $$
DECLARE p signal_control.partitions; r jsonb; op text; work uuid; identity uuid;
    w signal_control.outbox; a signal_control.notification_attempts; charge bigint; next_status text; evidence bytea;
BEGIN
    p:=signal_control.check_token(t,expected_schema,expected_routines);
    IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED'; END IF;
    IF raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 16384 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    r:=convert_from(raw,'UTF8')::jsonb; op:=r->>'operation';
    IF op IN ('claim','resolve') THEN
        PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','work_id','attempt_id']);
    ELSIF op='finish' THEN
        PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','work_id','attempt_id','outcome','evidence']);
    ELSIF op='interrupt' THEN
        PERFORM signal_control.require_keys(r,ARRAY['schema_version','operation','work_id','attempt_id','evidence']);
    ELSE RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    IF r->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'work_id') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'attempt_id') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    work:=(r->>'work_id')::uuid; identity:=(r->>'attempt_id')::uuid;
    IF work IS NULL OR identity IS NULL OR work='00000000-0000-0000-0000-000000000000' OR identity='00000000-0000-0000-0000-000000000000' THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
    SELECT * INTO w FROM signal_control.outbox WHERE partition_id=p.id AND id=work FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED'; END IF;
    PERFORM signal_control.check_notification(w);
    SELECT * INTO a FROM signal_control.notification_attempts WHERE id=identity;
    IF op='claim' THEN
        -- Claims are deliberately non-replayable. Resolving a lost reply never
        -- produces another send permission, even for an identical original request.
        IF FOUND OR w.status NOT IN ('pending','retryable','uncertain') THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
        IF w.attempts>=10 THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
        charge:=512+octet_length(raw);
        UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+charge
            WHERE singleton AND used_rows<max_rows AND charge<=max_bytes-used_bytes;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
        a.id:=identity; a.partition_id:=p.id; a.work_id:=work; a.ordinal:=w.attempts+1;
        a.generation:=(t->'scope'->>'generation')::uuid; a.owner:=p.owner; a.epoch:=p.epoch;
        a.plan_sha256:=w.plan_sha256; a.claim_request:=raw; a.outcome:='intent'; a.seal:=signal_control.notification_seal(a);
        INSERT INTO signal_control.notification_attempts SELECT (a).*;
        UPDATE signal_control.outbox SET status='intent',attempts=a.ordinal,attempt_id=a.id,claim_generation=a.generation,claim_owner=a.owner,claim_epoch=a.epoch
            WHERE partition_id=p.id AND id=work RETURNING * INTO w;
    ELSE
        IF NOT FOUND OR a.partition_id<>p.id OR a.work_id<>work THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED'; END IF;
        IF op<>'resolve' THEN
            IF op='finish' THEN
                IF a.generation IS DISTINCT FROM (t->'scope'->>'generation')::uuid OR a.owner<>p.owner OR a.epoch<>p.epoch THEN
                    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED'; END IF;
                next_status:=r->>'outcome';
                IF next_status IS NULL OR next_status NOT IN ('uncertain','retryable','delivered','permanent') THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID'; END IF;
            ELSE next_status:='uncertain'; END IF;
            evidence:=signal_control.hex_bytes(r->'evidence',4096);
            IF a.outcome<>'intent' THEN
                IF a.completion_request IS DISTINCT FROM raw OR a.completion_generation IS DISTINCT FROM (t->'scope'->>'generation')::uuid
                    OR a.completion_owner<>p.owner OR a.completion_epoch<>p.epoch THEN
                    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CONFLICT'; END IF;
            ELSE
                IF w.attempt_id<>identity THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED'; END IF;
                charge:=octet_length(raw);
                UPDATE signal_control.store SET used_bytes=used_bytes+charge WHERE singleton AND charge<=max_bytes-used_bytes;
                IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF;
                a.outcome:=next_status; a.completion_request:=raw; a.completion_generation:=(t->'scope'->>'generation')::uuid;
                a.completion_owner:=p.owner; a.completion_epoch:=p.epoch; a.seal:=signal_control.notification_seal(a);
                UPDATE signal_control.notification_attempts SET outcome=a.outcome,completion_request=a.completion_request,
                    completion_generation=a.completion_generation,completion_owner=a.completion_owner,completion_epoch=a.completion_epoch,seal=a.seal WHERE id=identity;
                UPDATE signal_control.outbox SET status=CASE WHEN attempts=10 AND next_status IN ('uncertain','retryable') THEN 'exhausted' ELSE next_status END
                    WHERE partition_id=p.id AND id=work RETURNING * INTO w;
            END IF;
        END IF;
    END IF;
    PERFORM signal_control.check_token(t,expected_schema,expected_routines);
    RETURN jsonb_build_object('schema_version',1,'work_id',w.id,'attempt_id',a.id,'ordinal',a.ordinal,
        'claim_generation',a.generation,'claim_owner',a.owner,'claim_epoch',a.epoch,'outcome',a.outcome,'work_status',w.status,
        'plan',encode(w.plan,'hex'),'plan_sha256',encode(w.plan_sha256,'hex'),'request_sha256',encode(sha256(raw),'hex'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_INVALID';
END $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA signal_control FROM PUBLIC;
COMMIT;

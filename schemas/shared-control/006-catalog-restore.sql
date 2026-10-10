-- Explicit stopped catalog restore profile. Frozen001..005 remain unchanged.
-- The bounded administrator validates exact stopped revision4 and independently
-- verified permits before executing this transactional upgrade. Runtime never installs it.
ALTER TABLE signal_control.migrations DROP CONSTRAINT migrations_ordinal_check;
ALTER TABLE signal_control.migrations ADD CONSTRAINT migrations_ordinal_check CHECK(ordinal BETWEEN 1 AND 5);
ALTER TABLE signal_control.store DROP CONSTRAINT store_revision_check;
ALTER TABLE signal_control.store ADD CONSTRAINT store_revision_check CHECK(revision IN (4,5));
CREATE TABLE signal_control.restore_record (
    singleton boolean PRIMARY KEY CHECK(singleton),
    destination_id uuid NOT NULL,
    old_generation uuid NOT NULL,
    generation uuid NOT NULL UNIQUE CHECK(generation<>old_generation),
    checkpoint_sha256 bytea NOT NULL CHECK(octet_length(checkpoint_sha256)=32),
    inventory_sha256 bytea NOT NULL CHECK(octet_length(inventory_sha256)=32),
    approval_id uuid NOT NULL,
    custody_sha256 bytea NOT NULL CHECK(octet_length(custody_sha256)=32),
    credential_binding_sha256 bytea NOT NULL CHECK(octet_length(credential_binding_sha256)=32),
    source_progress_sha256 bytea NOT NULL CHECK(octet_length(source_progress_sha256)=32),
    notification_history_sha256 bytea NOT NULL CHECK(octet_length(notification_history_sha256)=32),
    consumers_sha256 bytea NOT NULL CHECK(octet_length(consumers_sha256)=32),
    attempted_work integer NOT NULL CHECK(attempted_work BETWEEN 0 AND 65536),
    post_checkpoint_sha256 bytea NOT NULL CHECK(octet_length(post_checkpoint_sha256)=32),
    complete boolean NOT NULL DEFAULT false,
    seal bytea NOT NULL CHECK(octet_length(seal)=32)
);
REVOKE ALL ON signal_control.restore_record FROM PUBLIC;
ALTER TABLE signal_control.outbox ADD COLUMN restore_generation uuid REFERENCES signal_control.restore_record(generation);
ALTER TABLE signal_control.outbox ADD COLUMN restore_attempts integer CHECK(restore_attempts BETWEEN 1 AND 10);
ALTER TABLE signal_control.outbox ADD COLUMN restore_sha256 bytea CHECK(octet_length(restore_sha256)=32);
ALTER TABLE signal_control.outbox ADD CONSTRAINT outbox_restore_frame CHECK(
    (restore_generation IS NULL AND restore_attempts IS NULL AND restore_sha256 IS NULL) OR
    (restore_generation IS NOT NULL AND restore_attempts IS NOT NULL AND restore_sha256 IS NOT NULL));
CREATE FUNCTION signal_control.restore_record_seal(r signal_control.restore_record) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,signal_control,pg_temp AS $$
    SELECT sha256(convert_to('SIGNAL-RESTORE-RECORD-V1','UTF8')||convert_to((to_jsonb(r)-'seal')::text,'UTF8'));
$$;
CREATE FUNCTION signal_control.restore_work_seal(w signal_control.outbox) RETURNS bytea
LANGUAGE sql STABLE STRICT SET search_path=pg_catalog,signal_control,pg_temp AS $$
    SELECT sha256(convert_to('SIGNAL-RESTORE-WORK-V1','UTF8')||uuid_send(w.partition_id)||uuid_send(w.id)||w.plan_sha256||uuid_send(w.restore_generation)||int4send(w.restore_attempts)||a.seal)
    FROM signal_control.notification_attempts a WHERE a.work_id=w.id AND a.ordinal=w.restore_attempts;
$$;

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
    IF NOT FOUND OR head.revision<>5 OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=1 AND artifact='001.sql' AND sha256=expected_schema)
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=2 AND artifact='002-functions.sql' AND sha256=decode('8106d8e021dde8d02d6fc6e4851e56d21ae389094e0541bcee2774b48f92c4cf','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=3 AND artifact='003-administration.sql' AND sha256=decode('8f998a7eb937a58cdbd1f0256dcba79a5b9cbe8ab2fe60a07546ef4326b9aad9','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=4 AND artifact='005-catalog.sql' AND sha256=decode('20d5751d9a3259614469e7bed7871abd44f3f106339bd0993432ca7c584ae1c7','hex'))
        OR NOT EXISTS(SELECT 1 FROM signal_control.migrations WHERE ordinal=5 AND artifact='006-catalog-restore.sql' AND sha256=expected_routines)
        OR (SELECT count(*) FROM signal_control.migrations)<>5 THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
    END IF;
    IF NOT FOUND OR NOT head.ready OR head.store_id IS DISTINCT FROM (s->>'store_id')::uuid
        OR head.generation IS DISTINCT FROM (s->>'generation')::uuid OR head.schema_sha256 IS DISTINCT FROM expected_schema
        OR head.routines_sha256 IS DISTINCT FROM expected_routines THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM signal_control.restore_record r WHERE singleton AND r.complete
        AND r.generation=head.generation AND r.seal=signal_control.restore_record_seal(r)) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
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

CREATE OR REPLACE FUNCTION signal_control.check_notification(w signal_control.outbox) RETURNS void
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
        IF w.status<>'pending' OR w.attempt_id IS NOT NULL OR w.restore_generation IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    ELSE
        expected:=CASE WHEN n=10 AND latest.outcome IN ('retryable','uncertain') THEN 'exhausted' ELSE latest.outcome END;
        IF w.restore_generation IS NOT NULL THEN
            IF w.restore_attempts>n OR w.restore_sha256 IS DISTINCT FROM signal_control.restore_work_seal(w)
                OR NOT EXISTS(SELECT 1 FROM signal_control.restore_record r JOIN signal_control.store h ON h.singleton
                    WHERE r.singleton AND r.generation=w.restore_generation AND h.generation=r.generation
                        AND r.seal=signal_control.restore_record_seal(r))
                OR NOT EXISTS(SELECT 1 FROM signal_control.notification_attempts historical JOIN signal_control.restore_record r ON r.singleton
                    WHERE historical.work_id=w.id AND historical.ordinal=w.restore_attempts AND historical.generation=r.old_generation) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
            IF n=w.restore_attempts THEN expected:=CASE WHEN n=10 THEN 'exhausted' ELSE 'uncertain' END; END IF;
        END IF;
        IF w.status<>expected OR w.attempt_id IS DISTINCT FROM latest.id OR w.claim_generation IS DISTINCT FROM latest.generation
            OR w.claim_owner IS DISTINCT FROM latest.owner OR w.claim_epoch IS DISTINCT FROM latest.epoch THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    END IF;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
END $$;

CREATE OR REPLACE FUNCTION signal_control.notification(t jsonb, raw bytea, expected_schema bytea, expected_routines bytea) RETURNS jsonb
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
            -- A restored historical intent is evidence, never a new completion seat.
            IF w.restore_generation IS NOT NULL AND a.ordinal<=w.restore_attempts THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FENCED'; END IF;
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

CREATE OR REPLACE FUNCTION signal_control.read_snapshot(s jsonb, identity uuid, ids uuid[], lifetime integer,
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
        IF (c.generation IS DISTINCT FROM (s->>'generation')::uuid AND NOT EXISTS(
            SELECT 1 FROM signal_control.restore_record r WHERE r.singleton AND r.complete
                AND r.generation=(s->>'generation')::uuid AND r.old_generation=c.generation
                AND r.seal=signal_control.restore_record_seal(r)))
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

REVOKE ALL ON FUNCTION signal_control.restore_record_seal(signal_control.restore_record),signal_control.restore_work_seal(signal_control.outbox) FROM PUBLIC;

-- Original catalog request rows, seals and generation/expiry remain immutable.
-- New authorized identities can read retained history only through the restore seal.
CREATE OR REPLACE FUNCTION signal_control.read_catalog_snapshot(s jsonb, identity uuid, lifetime integer,
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
            IF (c.generation IS DISTINCT FROM (s->>'generation')::uuid AND NOT EXISTS(
                SELECT 1 FROM signal_control.restore_record r WHERE r.singleton AND r.complete
                    AND r.generation=(s->>'generation')::uuid AND r.old_generation=c.generation
                    AND r.seal=signal_control.restore_record_seal(r)))
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

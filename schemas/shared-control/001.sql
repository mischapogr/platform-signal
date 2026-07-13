-- Explicit administrative migration only. Runtime code must verify its checksum
-- and schema/store identity; startup must never auto-create/reset these tables.
BEGIN;
SET LOCAL lock_timeout = '1s';
SET LOCAL statement_timeout = '5s';
CREATE SCHEMA signal_control;
REVOKE ALL ON SCHEMA signal_control FROM PUBLIC;

CREATE TABLE signal_control.store (
    singleton boolean PRIMARY KEY CHECK (singleton),
    store_id uuid NOT NULL UNIQUE CHECK (store_id <> '00000000-0000-0000-0000-000000000000'),
    generation uuid NOT NULL CHECK (generation <> '00000000-0000-0000-0000-000000000000'),
    revision integer NOT NULL CHECK (revision = 1),
    ready boolean NOT NULL DEFAULT false,
    feed_position bigint NOT NULL DEFAULT 0 CHECK (feed_position >= 0),
    feed_digest bytea NOT NULL CHECK (octet_length(feed_digest) = 32),
    schema_sha256 bytea NOT NULL CHECK (octet_length(schema_sha256) = 32),
    max_rows bigint NOT NULL CHECK (max_rows BETWEEN 1 AND 1000000),
    max_bytes bigint NOT NULL CHECK (max_bytes BETWEEN 1 AND 1073741824),
    used_rows bigint NOT NULL DEFAULT 0 CHECK (used_rows >= 0 AND used_rows <= max_rows),
    used_bytes bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0 AND used_bytes <= max_bytes)
);

CREATE TABLE signal_control.partitions (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    tenant text NOT NULL CHECK (octet_length(tenant) BETWEEN 1 AND 256),
    stream uuid NOT NULL CHECK (stream <> '00000000-0000-0000-0000-000000000000'),
    kind text NOT NULL CHECK (kind IN ('pipeline', 'notification', 'maintenance')),
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    owner uuid,
    lease_until timestamptz,
    checkpoint bigint NOT NULL DEFAULT 0 CHECK (checkpoint >= 0),
    feed_position bigint NOT NULL DEFAULT 0 CHECK (feed_position >= 0),
    UNIQUE (tenant, stream, kind),
    CHECK ((owner IS NULL AND lease_until IS NULL) OR
           (owner IS NOT NULL AND owner <> '00000000-0000-0000-0000-000000000000' AND lease_until IS NOT NULL AND epoch > 0))
);

CREATE TABLE signal_control.commits (
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    generation uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    first_sequence bigint NOT NULL CHECK (first_sequence > 0),
    last_sequence bigint NOT NULL CHECK (last_sequence >= first_sequence),
    manifest bytea NOT NULL CHECK (octet_length(manifest) BETWEEN 1 AND 262144),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    rule_revision bytea NOT NULL CHECK (octet_length(rule_revision) = 32),
    normalizer_revision text NOT NULL CHECK (octet_length(normalizer_revision) BETWEEN 1 AND 256),
    previous uuid,
    PRIMARY KEY (partition_id, id),
    UNIQUE (partition_id, first_sequence),
    FOREIGN KEY (partition_id, previous) REFERENCES signal_control.commits(partition_id, id)
);

CREATE TABLE signal_control.receipts (
    partition_id uuid NOT NULL,
    commit_id uuid,
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    prepared_count bigint NOT NULL CHECK (prepared_count BETWEEN 0 AND 4096),
    source_record_count bigint NOT NULL CHECK (source_record_count BETWEEN 0 AND 4096),
    verified_prefix bigint NOT NULL DEFAULT 0 CHECK (verified_prefix >= 0 AND verified_prefix <= prepared_count),
    state text NOT NULL CHECK (state IN ('retained', 'admitted', 'ack_intent', 'ack_uncertain', 'ack_confirmed')),
    reference bytea NOT NULL CHECK (octet_length(reference) BETWEEN 1 AND 65536),
    reference_sha256 bytea NOT NULL CHECK (octet_length(reference_sha256) = 32),
    PRIMARY KEY (partition_id, id),
    FOREIGN KEY (partition_id, commit_id) REFERENCES signal_control.commits(partition_id, id),
    CHECK (commit_id IS NOT NULL OR state = 'retained' OR prepared_count = 0)
);

CREATE TABLE signal_control.state (
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    key text NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 256),
    revision bytea NOT NULL CHECK (octet_length(revision) = 32),
    value bytea NOT NULL CHECK (octet_length(value) BETWEEN 1 AND 65536),
    PRIMARY KEY (partition_id, key)
);

CREATE TABLE signal_control.findings (
    partition_id uuid NOT NULL,
    commit_id uuid NOT NULL,
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    position bigint NOT NULL CHECK (position > 0),
    cursor_digest bytea NOT NULL CHECK (octet_length(cursor_digest) = 32),
    content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 65536),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    PRIMARY KEY (partition_id, id),
    UNIQUE (position),
    UNIQUE (id),
    FOREIGN KEY (partition_id, commit_id) REFERENCES signal_control.commits(partition_id, id)
);

CREATE TABLE signal_control.outbox (
    partition_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    plan bytea NOT NULL CHECK (octet_length(plan) BETWEEN 1 AND 65536),
    plan_sha256 bytea NOT NULL CHECK (octet_length(plan_sha256) = 32),
    status text NOT NULL CHECK (status IN ('pending', 'intent', 'uncertain', 'retryable', 'delivered', 'permanent', 'exhausted')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    attempt_id uuid,
    claim_generation uuid,
    claim_epoch bigint,
    claim_owner uuid,
    PRIMARY KEY (partition_id, id),
    FOREIGN KEY (partition_id, finding_id) REFERENCES signal_control.findings(partition_id, id),
    CHECK ((attempt_id IS NULL AND claim_generation IS NULL AND claim_epoch IS NULL AND claim_owner IS NULL) OR
           (attempt_id IS NOT NULL AND claim_generation IS NOT NULL AND claim_epoch IS NOT NULL AND claim_epoch > 0 AND claim_owner IS NOT NULL)),
    CHECK (status <> 'intent' OR attempt_id IS NOT NULL),
    CHECK (attempts = 0 OR attempt_id IS NOT NULL)
);

CREATE TABLE signal_control.snapshots (
    id uuid PRIMARY KEY,
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    generation uuid NOT NULL,
    manifest_ids bytea NOT NULL CHECK (octet_length(manifest_ids) BETWEEN 1 AND 4096),
    expires_at timestamptz NOT NULL
);

CREATE TABLE signal_control.tombstones (
    partition_id uuid NOT NULL REFERENCES signal_control.partitions(id),
    id uuid NOT NULL,
    generation uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    object_reference bytea NOT NULL CHECK (octet_length(object_reference) BETWEEN 1 AND 4096),
    reference_sha256 bytea NOT NULL CHECK (octet_length(reference_sha256) = 32),
    state text NOT NULL CHECK (state IN ('retired', 'delete_intent', 'deleted', 'blocked')),
    PRIMARY KEY (partition_id, id),
    UNIQUE (reference_sha256)
);
REVOKE ALL ON ALL TABLES IN SCHEMA signal_control FROM PUBLIC;
COMMIT;

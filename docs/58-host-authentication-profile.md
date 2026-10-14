# Selected structured host/application authentication profile

`signal-agent --format auth-json` selects the strict version1 authentication
record normalizer in `signal_collector_sdk::host_auth`. It reuses the bounded
file/stdin input workers, durable spool, file cursor, authenticated outbound
delivery and rejection metrics. Plain/auto/JSON formats retain their behavior.
Private producers own identity mapping, source logging settings and redaction.

Required record fields: `schema_version:1`, RFC3339 `timestamp`, `outcome`
(`success`/`failure`), `identity_authority`, `principal_id`, `target_id`, `method`,
`session_id` and `producer`. The optional `client_ip` must be a valid IP literal.
Methods are `password`, `public_key`, `mfa`, `token`, `federated` or `other`;
these are classifications and do not carry authentication material. Producer
fields are `boot_id`, unsigned `sequence`, unsigned `checkpoint` and unsigned
`dropped_events`. Identity strings are nonempty, at most256bytes, have no control
characters and no surrounding whitespace. The record limit is64KiB, also bounded
by the configured input line limit. Duplicate/missing/unknown fields and invalid
types are rejected; credentials or unknown extensions are not copied through.
No freeform message is accepted. Trusted private producers must not encode secrets
as identity values; semantic redaction cannot be inferred from a field name.

Source time becomes canonical `timestamp`; receiver time becomes `observed_at`.
Success/failure become informational/warning events with fixed messages. The
structured identities, method, optional client IP and producer continuity values
remain under `attributes.authentication` and `attributes.producer`. Source identity
comes from the agent's configured source, never from an input record. Event UUIDs
are assigned on normalization and retained by pending input/spool retry semantics.
The producer checkpoint is source-declared metadata; the durable file cursor is
separate and advances through the existing spool admission contract.

The evidence profile is `host-auth-json-v1`. Every event declares
`attributes.evidence.runtime_sensor_coverage: "not_assessed"`. File/stdin records,
boot IDs and declared drop counters grant no kernel/runtime coverage, permissions,
freshness or transport identity. Controlled success/failure fixtures establish
only the selected synthetic producer path. An independent trusted observer must
verify actual source logging, timestamp/delivery continuity and health before
coverage can be current. Actor/target/session identity remains distinct from
client IP, which supplies context and never substitutes for a principal.

HOST-AUTH's authentication source slice is locally runnable. Runtime execution,
protected-file access and egress capture require separately selected sensor hooks,
capabilities, process-start identities and independent dropped-event/health proof.
This implementation does not claim those S06 sensor capabilities. The full ledger
item remains open until the selected host/runtime profile is also qualified.

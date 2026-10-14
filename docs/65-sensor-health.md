# Independent missing-telemetry detector

SENSOR-HEALTH is in progress. The bounded evaluator, signed observer adapter and
atomic local journal are integrated into Small Main. Whole-item acceptance still
requires the remaining history, Standard and qualification work described below.

Private configuration pins an expected-source inventory, complete binding digest,
independent observer identity, expectation start, configuration/rule revision,
heartbeat interval, grace and observer freshness budgets. Expectations must be
authorized before silence. A trusted adapter authenticates each independent probe;
constructing or deserializing an observation supplies no authentication authority.
No incoming telemetry or self-reported healthy flag can replace that adapter.

A healthy, current observer with a verified heartbeat produces NoMatch until the
heartbeat interval plus grace expires. A collection-gap Match requires a current
independent observation at or after that deadline, still reporting an overdue
verified heartbeat receipt. A report from before the deadline cannot establish
later absence: the result is Indeterminate even while that report remains within
its freshness budget. A Match attributes no compromise or cause. Heartbeat times
are the independent observer's verified receipt times, not collector-supplied
timestamps. If no heartbeat has ever
been verified, the expectation start supplies the deadline. Missing or unknown
expected inventory refuses configuration; the host must expose unavailable,
indeterminate coverage. Missing/stale/unhealthy observer evidence or a required
missing checkpoint yields Indeterminate. Silence from an unobservable collector
is never healthy silence.

Source/binding/observer/revision, observation sequence/time, heartbeat and checkpoint
are pinned. Changed identity reuse, regressions and future timestamps are refused.
Exact replay does not refresh either heartbeat or observer verification. A fresh
independent observation of the same old heartbeat may refresh observer health,
but cannot postpone its source deadline. Evaluation clocks cannot move backwards,
including after restoring a snapshot. Expiry is checked at evaluation time.

Inventory and state bytes are finite. Each expected source retains at most one
observation plus its last verified heartbeat/checkpoint. One evaluation returns at
most one assessment per source. The pure stage owns no worker, queue or scheduler;
the embedding host must bound cadence, operations, retained outputs and I/O.
Versioned snapshots bind the exact policy/inventory and validate all retained
observations before restoration. Persisted snapshots alone are not independently
current evidence.

Completion requires the authenticated independent-observer adapter, native
Main lifecycle, persisted original assessment/finding outbox and checkpoint in one
transaction, replay/lost-reply/crash recovery, bounded history/retention/metrics,
focused source review and applicable frozen workspace/process/native gates. A
counter or pure evaluator alone cannot close SENSOR-HEALTH. Production observer
independence remains an explicit environment qualification boundary.

## Signed observer adapter

The server library exposes `sensor_health::Verifier`. Owner-selected enrollment
maps each independently operated observer UUID to an Ed25519 public key. The
inventory's exact observer set must be enrolled; duplicate, extra, missing, zero
or unsupported-version key entries are refused. The signer and private key stay
outside the server. Key enrollment requires owner authorization; a valid signature
does not itself prove operational independence from the monitored collector.

A v1 envelope contains `schema_version`, `observer_id`, `payload_base64` and
`signature_base64`. The payload contains `schema_version: 1`, `policy_sha256` (a
32-byte array) and the versioned `observation`. The policy digest is SHA256 of the
compact serde_json encoding of the complete validated Policy, whose expected
sources are in ascending UUID order. The signature covers the exact payload bytes
prefixed by `platform-signal/sensor-health-observer/v1` and one NUL byte. Unknown
fields and duplicate JSON fields are refused. Reserializing signed JSON cannot
replace verification of its original bytes.

Envelopes are capped at 8192 bytes and decoded payloads at 4096 bytes before
copying or retaining evidence. Enrolled key, signed policy digest, source binding,
observer identity, schema, sequence and receiver/observation clocks must agree.
Validity is the half-open interval from the signed observation time to that time
plus the policy's observer-freshness budget, exactly matching the evaluator.
Re-verification does not extend validity. V1 has no independent per-report expiry.

The complete enrollment digest additionally binds the policy digest and all keys
in ascending observer UUID order. SHA256 receives the domain
`platform-signal/sensor-health-enrollment/v1` plus NUL, the 32-byte policy digest,
the eight-byte big-endian key count, then each 16-byte observer UUID and 32-byte
public key. Durable native state must pin this digest so key rotation cannot
silently reauthorize an old snapshot. The native session pins this binding.

The verified result retains the original envelope, payload digest, policy digest,
enrollment digest, observation and derived expiry. Its fields are private and it cannot be
deserialized as verified evidence. This library seam owns no I/O or worker. Main
configuration, canonical observation admission, atomic state/outbox/checkpoint
and runtime recovery are implemented for Small Main; broader qualification and
the remaining whole-item requirements still precede item acceptance.

Verification is stateless: it validates a positive sequence, while Monitor checks
monotonic progress. The durable host must also compare the original signed payload
digest and canonical references when reconciling a retained sequence. Equality of
decoded observations alone cannot authorize replacement of its original evidence.

## Atomic journal primitive

`signal_rules::state_journal` provides a bounded local state/outbox/checkpoint
transaction for the pending native integration. Its exact versioned configuration
pins the WAL stream, complete host scope/generation binding and observer enrollment
digest, plus record/state/output count and byte budgets. SQLite FULL synchronous
transactions retain original opaque state and output bytes together. A SHA256
frame checksum detects corruption; filesystem-owner custody remains mandatory.
The primitive validates its own framing and limits; the native host must validate
the monitor state, signed originals, canonical references and delivery body schema.

Commits require the expected revision and a non-regressing checkpoint. Unchanged
checkpoints permit timer assessments. Exact lost-reply retries preserve the
original frame; pending outputs must remain its exact prefix until a confirmed
publication receipt retires that prefix at the expected revision. Retirement keeps
state/checkpoint intact and cannot delete a later result with an old receipt.

One retained worker owns SQLite and the filesystem writer lease. Its single
operation slot stays reserved through physical I/O after cancellation, timeout or
future drop. Window and generic state journals share the existing process cap of
16 physical workers. Queue depth/capacity and unsuccessful calls are exposed;
confirmed shutdown closes SQLite and releases the writer lease before replying.
Only absolute paths in a mode0700 directory and mode0600 single-link regular files
are accepted. Symlink paths/sidecars, unknown schemas, oversized stored frames and
changed bindings/configuration are refused. The native session validates domain
state and original signed evidence. Bounded assessment history/retention and
Standard ownership still remain required for SENSOR-HEALTH completion.

## Native Small Main work in progress

The current implementation integrates the typed native session with Small
Main. Owner-controlled `sensor_health.config` / `SIGNAL_SENSOR_HEALTH_CONFIG`
selects a strict JSON document, capped at512KiB, with an absolute journal path,
nonzero owner generation, bounded cadence and complete detector policy, keys,
canonical source scopes and evidence/output budgets. Native identity and continuous
WAL delivery are required. Standard mode refuses this configuration until its
own integration is qualified.

Signed canonical input is checked before WAL admission. The consumer evaluates
data and idle cadence, commits original evidence/state/finding outbox/checkpoint,
publishes original scoped findings, retires confirmed outputs and only then
acknowledges the WAL. Expiry between admission and consumption advances the
checkpoint without granting observer health or creating a historical finding.
Startup, expiry and failed work expose unknown coverage through21 fixed numeric
`signal_sensor_health_*` metrics without identity labels. Shutdown closes the
physical journal under the original drain deadline.

Local process evidence at`target/sensor-health-native-20261015/main-process-06/`
passes7sensor scenarios plus8onboarding checks with actual native HTTP/TLS
identity, SQLite, WAL, findings and SIGKILL. Independent observer authority is
synthetic. Original gap evidence/body survives interrupted publication, recovery
does not renew observer authority, and changed owner generation refuses startup.
Focused tests and Clippy are evidence for this worktree only. Bounded assessment
history/retention, Standard integration and current native release qualification
remain required; slice acceptance is recorded separately from item or release
acceptance.

## Bounded assessment history work in progress

Native configuration additionally requires `max_history_assessments`(1–65536),
`max_history_bytes`(1024–8MiB, within `max_state_bytes`) and
`history_retention_ms`(1–86400000). These limits join the complete persisted
configuration binding. Native state uses schema version2; earlier native state
and missing history configuration are refused. This unpublished development
change supplies no automatic migration or permission to discard retained evidence.

History retains original assessment transitions, rule revision and up to3original
signed canonical proofs per source assessment. Repeated unchanged assessments
do not add rows while the previous entry remains retained. Once it expires, the
next evaluation records a new sample. Recovery reconstructs and verifies each
historical assessment at its original assessment time. History never contributes
to the current-session observer authority set.

At evaluation time, entries expire at `assessed_at_ms + history_retention_ms`.
Oldest entries are evicted to meet row, history-byte and shared state-byte limits;
expiry and capacity eviction have separate persisted counters. Current state and
the latest new assessment must still fit, otherwise the entire transaction is
refused. History limits never expire or evict the original unpublished finding
outbox or its retained evidence. History changes, counters, monitor state, current
proofs, original finding outbox and checkpoint commit atomically. Exact replay
preserves the original committed record.

Fixed numeric metrics expose `history_assessments`, `history_assessment_capacity`,
`history_bytes`, `history_byte_capacity`, `history_expired_total` and
`history_evicted_total`, each prefixed with `signal_sensor_health_`. No source,
account, rule or evidence identifiers become metric labels. This history work
still needs frozen phase acceptance; Standard integration and whole-item release
qualification remain open.

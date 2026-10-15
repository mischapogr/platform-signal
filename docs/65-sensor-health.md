# Independent missing-telemetry detector

SENSOR-HEALTH is in progress. The first slice implements bounded, deterministic
heartbeat assessments; it does not yet install a running detector in Main or
grant durable finding/checkpoint recovery acceptance.

Private configuration pins an expected-source inventory, complete binding digest,
independent observer identity, expectation start, configuration/rule revision,
heartbeat interval, grace and observer freshness budgets. Expectations must be
authorized before silence. A trusted adapter authenticates each independent probe;
constructing or deserializing an observation supplies no authentication authority.
No incoming telemetry or self-reported healthy flag can replace that adapter.

A healthy, current observer with a verified heartbeat produces NoMatch until the
heartbeat interval plus grace expires. Once overdue, it produces Match for a
collection gap, without attributing compromise or cause. If no heartbeat has ever
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

Completion still requires the authenticated independent-observer adapter, native
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
silently reauthorize an old snapshot. That recovery integration remains pending.

The verified result retains the original envelope, payload digest, policy digest,
enrollment digest, observation and derived expiry. Its fields are private and it cannot be
deserialized as verified evidence. This library seam owns no I/O or worker. Main
configuration, canonical observation admission, atomic state/outbox/checkpoint
and actual runtime recovery still need integration before item acceptance.

Verification is stateless: it validates a positive sequence, while Monitor checks
monotonic progress. The durable host must also compare the original signed payload
digest and canonical references when reconciling a retained sequence. Equality of
decoded observations alone cannot authorize replacement of its original evidence.

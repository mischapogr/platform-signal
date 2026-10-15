# Independent missing-telemetry detector

SENSOR-HEALTH passes local simulation acceptance — 2026-10-16. Small and Standard
Main, bounded history, atomic original outputs/checkpoints, idle maintenance and
fresh-generation restore pass current source-bound qualification. See
`target/sensor-health-standard-20261016/ACCEPTANCE.json`. Current native release
CI/container/cluster and external observer/environment/publication gates remain
separate. Dated slices below retain their original evidence boundaries.

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
WAL delivery are required. Standard uses the explicit shared schema2 configuration
described below; its complete qualification remains in progress.

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
account, rule or evidence identifiers become metric labels. The Small history
slice has local frozen acceptance at
`target/sensor-health-history-20261015/ACCEPTANCE.json`; Standard integration and
whole-item release qualification remain open.

## Standard foundation in progress

The journal-free native engine prepares immutable candidates and confirms exact
physically committed records. Preparation, metadata hydration and restart never
renew independent observer authority. Shared framing pins complete control scope,
generation, state key, rule revision and checkpoint; the original enrollment floor
cannot exceed the process's captured admission floor. Restart preserves the
original enrollment while a later process floor excludes retained reports from
current observer authority. Original proof, history and pending-output bodies
are detached into bounded canonical references without discarding evidence.

Shared recovery borrows the existing control/object workers. One original deadline
covers the live catalog capability, fenced state read, exact object/version and
canonical-body recovery, domain validation and restricted replay pins. Partial or
uncertain pin work remains retained; an error cannot establish readiness or permit
pin release. Fresh-generation restore must explicitly validate original scoped
outputs; this helper refuses silent scope rebinding.

The stopped `019-sensor-replay-pin.sql` addon grants no general object control or
retirement. It permits replay holds only for an exact committed sensor state and
current activated producer generation, with a matching committed manifest object,
version, length and digest. Local actual PostgreSQL primitive qualification is
retained at `target/sensor-health-standard-20261015/postgres-03/report.json`;
sensor payloads in that fixture are synthetic. This is not Standard Main proof.

The explicit producer credential profile selects sensor and WINDOW independently.
Sensor selection requires the narrow pin grant and verifies its exact routine
identity. Ordinary producer, WINDOW-only and read-only profiles reject sensor
grants. Database/table/schema authority, owner membership, grant options and
unexpected functions reachable through member roles or PUBLIC are refused.
Standard startup selects this profile and includes the complete detector and
owner/shared-settings binding in its rule revision. Enabled sensor-only execution
has local process evidence below; complete lifecycle qualification remains open.

Configuration schema1 selects the absolute Small `database` path. Schema2 selects
`shared` with `state_key`, explicit optional `bootstrap_checkpoint`, and `recovery`
limits for files, object/decoded/result bytes and scanned rows. Exactly one storage
form is required. Canonical result bytes are capped at1MiB. Both forms retain
owner generation, cadence and complete detector configuration. Runtime/storage
mismatches fail before persistence opens. Explicit shared sensor execution is
locally enabled. Mixed WINDOW has the process baseline below; uncertain maintenance,
restored-generation and final whole-item qualification remain required.

Standard data-path wiring is present. One consumer owns
the sensor engine, protected originals and health state. Admission validates signed
reports before WAL writes. WINDOW and sensor candidates enter one v4 publication,
each retaining its own prior state and finding provenance; exact known findings
keep their original bytes. Confirmation follows the atomic control commit and
verified WAL checkpoint. Replay-pin depth/capacity and sensor metrics use fixed
numeric names without identity labels.

The actual existing WINDOW Main regression passes eight scenarios on this path,
including protected delayed anchors, exact retry, quota refusal, original scoped
findings and SIGKILL recovery. Evidence is retained at
`target/sensor-health-standard-20261015/window-consumer/report.json` with292matching
source bindings and owned cleanup. That run predates the latest sensor-only fixture
changes and needs a final source-bound refresh. The enabled sensor-only Main run
at `target/sensor-health-standard-20261015/sensor-main-06/report.json` passes six
scenarios in62.26s with297 matching source hashes, exact binary binding and owned
cleanup: zero-event initialization/idle, signed current and causal overdue
observations, atomic original gap and idle retirement, forged input rejection,
SIGKILL/restart replay remaining unknown, and fresh post-restart health. PostgreSQL
TLS, native HTTP identity, WAL, Parquet and findings are actual; independent
observer and S3 authority are synthetic. The mixed baseline below adds coexistence;
ambiguous maintenance and fresh-generation restore qualification remain open.
SENSOR-HEALTH is not accepted.

The mixed Main baseline at
`target/sensor-health-standard-20261015/mixed-main-06/report.json` passes five
scenarios in84.19s with300 matching source hashes, exact executable binding and
owned cleanup. Sensor metadata initializes at checkpoint0; WINDOW state first
persists with its first authentication event. Both states coexist with independent
priors: a sensor gap preserves the unsealed authentication attempts, then a signed
source watermark seals the WINDOW finding without changing the sensor finding.
Retries and actual SIGKILL/restart preserve both original finding bodies and
canonical sequence maps through checkpoint9; replay leaves sensor authority
unknown. The synthetic process heartbeat interval is5s to observe current health
through the two-state publication before causal expiry; production deadlines are
unchanged. This is local PostgreSQL/TLS/WAL/Parquet process proof with synthetic
observer/S3 authority, not maintenance COMMIT ambiguity or fresh-generation restore.

The stopped `020-sensor-maintenance.sql` addon maintains an existing committed
sensor state without changing the manifest head, findings or WAL checkpoint.
It checks exact prior bytes/revision, current scope/generation and lease, permits
only original canonical references, and retires only an original outbox prefix
whose persisted finding bodies match. State-byte growth consumes the existing
store quota. Failures roll back the whole transaction. Byte-identical target-state
replay returns that state without another mutation; a later divergent state
conflicts, so an uncertain caller cannot infer success or retry blindly.

The existing single consumer now owns idle cadence and retirement; no additional
worker or queue is created. Candidate confirmation precedes follow-up cleanup
under new contexts. Startup reports the recovered original proof/history/outbox
counts while keeping observer coverage unknown. Actual PostgreSQL mechanism
qualification at `target/sensor-health-standard-20261015/postgres-07/report.json`
passes with synthetic sensor metadata, including quota/late-write rollback,
installer and retirement refusals and unchanged head/checkpoint replay. This
does not prove the enabled native sensor process. Ambiguous maintenance COMMIT
recovery and maintenance growth quota are covered by the native baselines below.
Final process qualification and explicit fresh-generation restoration of original
scoped outputs remain open.

Explicit initial state is now supported by the stopped
`021-sensor-bootstrap.sql` addon. The owner-selected `bootstrap_checkpoint` must
match the current control/WAL checkpoint. Only an absent state key may be created;
an identical target is an idempotent echo and a different existing state refuses
replacement. Initial state has no canonical references, verified observations or
pending findings. Its row/bytes consume the existing store quotas. No event,
manifest, findings cursor or checkpoint is created or advanced.

Checkpoint0 uses a null head and empty canonical maps. Startup confirms this
initial unknown assessment before readiness; the same consumer can then persist
idle evaluations before any input. Recovery validates the original frame and
remains unknown. Source regressions cover empty-state recovery, an idle tick and
the first signed event afterward. Actual PostgreSQL empty-partition qualification
passes at `target/sensor-health-standard-20261015/postgres-08/report.json` with
synthetic enrollment/state,132matching source bindings and owned cleanup. The
sensor-only Main baseline above now executes this path; complete native process
qualification remains open.

Prepared engine candidates retain their original deadline/cancellation context.
A fresh caller context cannot authorize confirmation after original cancellation
or expiry. Detached metadata reuses one fully validated native state; capacity
refusal does not bypass original history or signature checks.


The native maintenance baseline at
`target/sensor-health-standard-20261015/maintenance-main-03/report.json` passes
nine sensor-only Main scenarios in72.08s with297 matching source hashes, exact
binary binding and owned cleanup. An owned fixture lock holds an actual deferred
maintenance COMMIT; the oracle observes the exact producer session blocked by
that lock before the server is killed. After release, the database stores the
original target bytes and expected byte-charge delta without changing head,
checkpoint, commit count or original findings. The retained CAS prior and target
bytes also pass typed TLS worker exact replay, cancelled-call and stale-owner
refusal. After restart advances native state at the same head/checkpoint, replay
of the old target conflicts and preserves the original findings. Observer authority
remains unknown after recovery. Fixture triggers, functions and tables are removed
before restart; no production routine or worker is replaced.

This campaign also proves actual native bootstrap refusal under an exhausted
store quota: no sensor row, event, manifest, finding, checkpoint or charged bytes
are created. The subsequent campaign below adds maintenance growth quota and
original-deadline uncertainty after observed COMMIT. The earlier six-case
sensor-only and five-case mixed reports precede these fixture changes; a final
frozen process refresh remains required. Fresh-generation restore must still
preserve original output scope/body. SENSOR-HEALTH remains in progress.


The final bounded maintenance-failure campaign at
`target/sensor-health-standard-20261015/late-maintenance-main-03/report.json`
passes ten scenarios in78.47s with298 matching source hashes, exact binary binding
and owned cleanup. Saved Main prior/target frames drive actual typed TLS worker
calls in the owned stopped fixture. After an exact COMMIT observation, caller
cancellation returns uncertain and the target commits; original-deadline expiry
returns uncertain and the exact prior remains after rollback. The oracle accepts
only those complete original inventories, then a fresh-context exact-target call
reconciles either outcome. It never confirms an expired native candidate.

The same fixture hydrates the native engine from original canonical events and
prepares bounded idle candidates. A genuine one-byte state growth is refused by
an exhausted quota with the complete prior inventory unchanged. Restoring fixture
capacity permits the original candidate to commit; native confirmation occurs
only after that physical commit. No event, finding, head or WAL checkpoint is
invented by this maintenance. Forty helper checks, strict control/server Clippy,
formatting and14workspace boundaries pass. This does not replace final frozen
workspace/process/native acceptance.

The supported Standard restore changes physical `Scope.generation` while keeping
logical `scope_generation` and original finding-scope producer/fact rows. Sensor
restore must preserve that logical generation, original detector ownership and
pending finding IDs/bodies. The explicit stopped owner migration in
[the upgrade contract](56-upgrade-compatibility.md) now handles the physical state
binding; runtime recovery never silently rebinds it. Changed logical finding
generation remains outside that restore contract. Actual native sensor restore
integration and its process qualification remain open.


Native Standard sensor restore passes a bounded local campaign — 2026-10-16.
`target/sensor-health-standard-20261016/SENSOR-RESTORE-BASELINE.json` binds four
actual Main scenarios,300matching source hashes, server/offline executable
identities and owned cleanup in55.07s. A fixture-only conditional retirement
refusal retains a real atomic sensor publication with one original pending/known
finding. After stopping Main, a fresh database receives trusted compiled DDL and
original rows; current scoped restore verifies the pinned objects and sealed
lineage. The explicit stopped owner migration changes physical scope generation,
keeping logical finding generation, native snapshot/outbox and canonical originals.
The restored Main retires that original pending output without changing the
finding bytes; duplicate replay remains unknown and a fresh signed observation
restores current health through WAL checkpoint4. Native PostgreSQL TLS, WAL,
Parquet and Main are actual; observer/restore authority and S3 custody are
synthetic. This is a restore slice, not whole SENSOR-HEALTH or release acceptance.
The complete staged PostgreSQL campaign and frozen Small/Standard/workspace
refresh remain required after these source changes.

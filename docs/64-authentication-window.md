# Bounded authentication-failure window

Current status — 2026-10-15:WINDOW is `passed_simulated` at bounded local LinuxAMD64
scope. Six frozen workspace gates and current Small/Standard/shared runtime gates
pass. Exact requirement audit, source identities and limits:
`target/window-20261014/ACCEPTANCE.json`. Current remote/native/container release
qualification and external/version/publication gates remain separate.

The implementation record below preserves earlier intermediate states. Its
pending/in-progress statements describe those historical evidence boundaries;
the current accepted scope is recorded above and in the final entry.

WINDOW implementation is in progress. HOST-AUTH now has selected native/local
acceptance; this item still requires event-time and atomic recovery qualification.
The public mechanism accepts private versioned policy. N=3 and W=60seconds belong
only to laboratory fixtures. Authority/principal/target identify an authentication
attempt; IP alone never supplies a key.

The selected detector operates on an explicitly bound partition and rule revision.
A source watermark seals event-time anchors; lateness is bounded. It counts distinct
producer attempts, preserving canonical references for replay. Missing fields,
unknown/expired coverage, excess lateness and capacity exhaustion yield an explicit
indeterminate result. None of these means a clean window. Policy changes require
an explicit new revision and recovery boundary, not silent reinterpretation.

State includes source checkpoint, watermark, finite per-key attempts, dedup
identities and finalized assessments/findings. Keys, per-key attempts, total bytes,
TTL, dedup entries and pending output are bounded. Atomic publication must commit
state, findings/outbox and source checkpoint together; admission or in-memory
mutation does not grant recovery acceptance. A lost commit reply reloads the
committed state before processing again. Replay preserves finding identities and
never counts an attempt twice. Physical disk work retains capacity through timeout
or cancellation; host/database partition fencing remains mandatory for Standard.

Acceptance requires positive/negative/missing-data fixtures, exact boundary and
late-event behavior, watermark/TTL progression, duplicate/conflicting identities,
limits/overflow, revision mismatch and actual durable crash/restart/lost-reply
state/finding/checkpoint recovery. The atomic journal/server integration and these
checks remain required; a counter-only implementation cannot close WINDOW.

The current in-progress Rust slice has 27 WINDOW regressions and 50 total
signal-rules tests, with crate Clippy passing. The journal stores detector state,
its deterministic finding outbox and checkpoint in one SQLite transaction. Tests
cover reopening after a committed result was discarded and stale revision
refusal; this is not process-crash qualification. Cancelled or dropped callers
retain the physical operation slot, and failures include busy/closed refusals.
Stored payload reads allocate at most the configured snapshot byte limit plus
one byte to detect overflow. Missing identity retains a visible persisted coverage
gap even when no keyed assessment can be formed. Hosts may retire a published
assessment prefix only after durable publication, then commit retirement with the
next source checkpoint. The local monolith is wired; full acceptance remains open. Evidence:
`target/window-20261014/evidence-and-scope.log`,
`evidence-and-scope-clippy.log` and `HANDOFF.json`.

Canonical inputs are retained with each pending assessment, including after attempt
TTL reclamation, and contribute to the same finite state byte budget. Restore
checks their event references, authority/principal/target, outcome and event-time
membership. The generic multi-event finding constructor requires complete,
ordered, distinct canonical references sharing source/account/resource; it refuses
reserved caller scope metadata. The host must establish authenticated admission
for every contributing event before granting publication scope.

The local journal requires a mode0700 parent directory and mode0600 singly linked
files, refuses symlink paths, and retains a single writer lease. Confirmed shutdown
closes the database and releases that lease before answering. These checks and
scope derivation and history pass focused Rust regressions (45 rules tests in the latest history campaign).
They do not establish shared-control database fencing or process-crash acceptance.

## Optional local monolith configuration

`SIGNAL_WINDOW_CONFIG`, or `window: {config: /private/window.json}` in the server
configuration, selects a strict private JSON document. Its fields are
`schema_version: 1`, an absolute `database` path in an existing mode0700 directory,
and a complete versioned `policy` object containing the fields of
`signal_rules::window::Policy`. Threshold, duration, revision, title, severity and
all capacity bounds are explicit private deployment inputs; there are no production
policy defaults. The rule ID must be distinct from loaded stateless rule IDs.
The signed onboarding policy must include that ID in its exact detection inventory.
WINDOW requires native identity, independently configured onboarding/coverage, and
continuous WAL delivery; `drop_oldest` is refused. Standard uses the explicit shared configuration described below; whole-item
release acceptance remains pending.

The journal pins the WAL stream and the onboarding source/account/resource scope,
observer-history binding, verification key and coverage profile. A mismatched
checkpoint or binding refuses startup. The consumer first publishes Parquet, then
commits window state, canonical assessment evidence, deterministic finding outbox
and source checkpoint atomically, then publishes scoped findings, then acknowledges
the WAL. A replay reloads that committed outbox and preserves its finding IDs.
Only newly authenticated, in-scope events with current verified source coverage can
contribute to a new scoped finding. Existing retained WAL cannot acquire authority
from a newly valid report.

The signed source interval end minus private lateness supplies the watermark.
Every sealed lookback must fit wholly inside that interval. Partial lookbacks are
indeterminate and retain an explicit coverage gap. Assessment evidence survives
attempt TTL cleanup and remains subject to the finite byte/output bounds.

Focused verification: 80 server tests (two unrelated environment tests ignored),
42 rules tests and 46 findings tests pass; strict Clippy for these crates and
formatting pass. The new signed-report/actual-finding-store test verifies atomic
outbox publication, restart/replay duplicate identity, retained-WAL authority
refusal and WAL/account binding changes. Logs are
`target/window-20261014/server-unit.log`, `rules-findings-integrated.log` and
`integrated-clippy.log`.

WINDOW remains pending. The server archives assessments atomically and retires published pending outputs.
Retained-history and pending-output quota exhaustion fail closed. A bounded local-owner history reader is implemented; public HTTP history authorization
is not part of this slice. Shared-control support, actual process crash/SIGKILL and stalled
physical-I/O recovery, focused review and full frozen acceptance remain required.

## Window health metrics

The existing `/metrics` endpoint exposes `signal_window_operations` and
`signal_window_operation_capacity`, retained attempt/assessment depths and
capacities, snapshot bytes and byte capacity, journal failures, rejected/duplicate
counts, indeterminate assessment depth, `signal_window_coverage_gap` and
`signal_window_closed`. The projection contains no rule name, source/account,
principal, event reference or original evidence. Queue capacity remains reserved
until physical work ends even if its caller leaves.

A fresh process reports a coverage gap until verified source coverage is assessed.
The gap gauge also covers expired last-verified coverage, retained active evidence
loss, failed/cancelled evaluations and a closed worker. Restart/replay preserves
old findings but does not claim fresh current source health. Metrics read only
bounded in-memory state; they do not read observer files or perform disk work.
An independently updated report is used at the next detector evaluation.

The actual HTTP metrics regression and signed-report server regression pass,
including startup unknown, verified capacity/depth, cancelled evaluation and
physical shutdown visibility. The ingest HTTP suite passed all 19 tests before
the final closed-worker addition; its affected metrics regression was rerun after
that addition. Workspace/all-target Clippy and formatting also pass. Evidence:
`target/window-20261014/window-metrics-http-full.log`,
`window-metrics-http.log`, `window-metrics-server.log` and
`window-metrics-workspace-clippy.log`. Full frozen acceptance remains open.

## Durable assessment custody and retirement

Private policy now also requires `max_history_assessments`, `max_history_bytes`
and `history_retention_ms`. These are positive finite bounds, capped at16384 rows,
32MiB of archived payload and one year respectively. Each archive record retains
the canonical assessment inputs, complete detector policy/revision, WAL stream,
source/configuration binding, first source checkpoint, custody time and expiry.
SHA256 identifies its canonical payload. Startup and mutations validate archive
hashes, source/policy bindings, expiry metadata and pending-outbox references.

Assessment archive, detector state, finding outbox and source progress commit in
one synced SQLite transaction. Count or byte exhaustion rolls that entire
transaction back. The consumer publishes all findings before retiring the exact
revision-bound assessment prefix in another synced transaction at the same source
checkpoint. A stale completion receipt cannot retire a newer result. Retirement
clears pending outputs while retaining their archive records and replay dedup state.

Replay preserves original custody and expiry metadata. Published expired history
is reclaimed at the next source commit. Pending outputs retain their recovery
records until publication is confirmed; this recovery pin does not extend the
recorded expiry. This mechanism does not implement independently configured legal
holds. History depths and byte capacities are exposed through the existing
identity-free window metrics. The local-owner archive read/export primitive is described below.

Sealing additionally waits until the consumer reaches its observed WAL tail.
This prevents a signed coverage interval from finalizing a prefix while later
already-admitted inputs are still awaiting consumption. The split-batch signed
observer regression produces the same finding ID as single-batch processing.
Future source arrivals still require the private bounded-lateness/continuity
preconditions; an observed receiver tail alone is not source delivery proof.

Latest focused verification:45rules tests,80server tests(two unrelated environment
tests ignored), and the affected HTTP metrics regression pass. Workspace/all-target
Clippy and formatting pass. Tests include original expiry preservation across
pending replay, published expiry, count/byte quota atomic refusal, archive
corruption refusal, revision-bound retirement and retained evidence after output
clearance. Evidence: `target/window-20261014/history-rules-full.log`,
`history-server-full.log`, `history-metrics-http.log` and
`history-workspace-clippy.log`. These do not establish process-crash, shared-control
or complete WINDOW acceptance.

## Bounded retained-history reads

`Journal::history(limit, max_bytes, context)` and `history_after(cursor, ...)`
read/export retained assessments through the same single physical worker and
operation slot as writes. Requests allow1..128records and256bytes..32MiB of encoded
response. The serialized envelope and pagination cursor count toward that limit.
An individual record that cannot fit is refused; it is never silently replaced by
an empty clean result. This is a trusted local filesystem-owner SDK primitive,
not a new public HTTP route or an authorization grant.

Pages preserve canonical inputs, detector policy/revision, source bindings, source
checkpoint and original custody/expiry metadata. Records order by descending first
checkpoint and digest. A versioned cursor pins journal revision, source stream and
source binding. Concurrent commit/retirement, foreign cursors, unsupported cursor
versions or missing cursor records are refused rather than silently mixing exports.
The caller restarts an export after a revision conflict.

Expired records retain metadata with `evidence: null`; original inputs are withheld.
Expiry is checked during response assembly and again before worker delivery.
`missing_evidence` is explicit for empty, expired or truncated pages; absence of
retained evidence never means a clean detector result. `truncated` and `next`
identify a bounded subset of currently retained history. Source health and complete
historical coverage cannot be inferred from an archive page.

The history reader regression covers actual worker reads, page/cursor export,
stale and foreign cursor refusal, cancelled requests, byte/count limits, empty
history and expired evidence. Latest rules suite:46tests pass, including23WINDOW
regressions; crate/all-target Clippy and formatting pass. Evidence:
`target/window-20261014/history-reader-rules.log` and `history-reader-clippy.log`.
Process crash/stalled-I/O, shared-control support and full acceptance remain open.

## Local physical recovery qualification

The owned process regression SIGKILLs a child at four boundaries: before the next
commit, during an uncommitted SQLite transaction with a rollback journal, after
commit, and after publication retirement. Reopening validates the exact old or
complete new state, findings, source checkpoint and retained assessments. The
child helper is ignored by the ordinary harness because its parent invokes it
explicitly for each boundary; it is not a skipped recovery gate.

A unit-test-only SQLite busy callback marks actual writer-lock contention and
retains the blocked physical operation until explicitly released. Three scenarios
cover cancelled/refused writes, cancelled callers followed by a physical commit,
and deadline expiry followed by a physical commit. While blocked, the operation
slot remains occupied and additional calls are counted as busy refusals. After
release, reload distinguishes no mutation from the exact committed snapshot and
archive. There are no production failpoint environment variables or callbacks.

The latest rules suite passes48tests, including25WINDOW regressions and both
recovery parents; the owned child helper is the single ignored helper. Crate
Clippy and formatting pass. Evidence:
`target/window-20261014/window-recovery-rules-full.log` and
`window-recovery-clippy.log`. These qualify local SQLite/process behavior, not
power loss, prolonged physical-device stability, full monolith process recovery,
shared-control support or current-revision native ARM64/container acceptance.

## Shared-control metadata recovery foundation

Standard publication already accepts revisioned state, atomically fenced with
manifest, finding and source-checkpoint publication. A state item is limited to
64KiB. Standard control state cannot contain the full canonical event payloads
retained in the local SQLite profile; canonical payload custody stays in immutable
objects and their reachability pins.

`State::encode_metadata(max_bytes)` projects a versioned bounded recovery envelope
without attempt event bodies or assessment evidence bodies.
`State::metadata_event_ids` lists the exact required canonical references.
`State::restore_metadata` requires the complete retained inputs and restores the
original state, including dedup, watermark, finalized assessments and gaps. It
checks policy/revision, canonical identities/content and original state bounds;
missing evidence fails recovery. Hydration charges every repeated reference before
cloning input values, so output references cannot evade the byte bound.

The metadata projection itself grants no source authority, lease or commit permit.
The Standard host must pin object references for all required inputs, read the
metadata under the current partition fence and publish its next state with findings
and checkpoint in the existing transaction. PostgreSQL recovery reads, retained
object lookup/pins and Standard consumer wiring are still required. Standard WINDOW
remains explicitly unsupported pending these steps and their qualification.

Two metadata regressions cover exact restoration, absent raw payload, retained
assessment references after TTL, missing/changed evidence, embedded payload,
revision and byte-bound refusal. Latest rules suite:50tests pass, including27WINDOW
regressions; crate/all-target Clippy and formatting pass. Evidence:
`target/window-20261014/window-metadata-rules-full.log` and
`window-metadata-clippy.log`. This foundation does not establish shared-control
WINDOW acceptance.

## Fenced PostgreSQL metadata recovery reads

`ControlClient::read_state` accepts a validated lease token, one bounded state key
and the expected committed head. The stopped additive installation
`schemas/shared-control/009-state-read.sql` adds a read routine without modifying
frozen core publication/restore routines or identities. The existing schema owner
installs it while readiness is stopped and explicitly grants schema usage/function
execution to the selected runtime role; runtime startup never creates it.

Reads use the existing bounded control worker and original deadline. Before
calling the routine, the client verifies its exact body, signature, owner,
language, search path and relevant execution properties. The routine checks the
current store, principal, tenant, stream, partition, lease owner/epoch and expected
head, then checks the lease again before returning. Missing state is explicit
unavailable evidence, not authorization to bootstrap an empty detector. Values
retain the existing64KiB item bound; response keys, revisions and checkpoint/head
relationships are validated. Recovery data does not grant publication authority.

The owned PostgreSQL17.5/TLS qualification passes, including missing state,
stale/foreign fencing, head conflict, stopped installation and routine tampering,
as well as existing publication/snapshot/retention/lease/cancellation/privilege
gates. Its report pins the new SQL source and requires the new read marker:
`target/window-20261014/state-read-postgres-final/report.json` (`passed_simulated`,
synthetic scope/retention policy with actual local PostgreSQL behavior).
Control crate tests, strict crate Clippy and formatting pass;37runner validator
regressions pass. Earlier unavailable-image, bounded-storage, installer and source
drift attempts are retained and provide no acceptance claims.

The owned runner now bounds tmpfs to256MiB and container memory to512MiB; the
expanded existing database matrix exceeded its former96MiB tmpfs before reaching
state-read checks. This is a fixture resource change, not product sizing evidence.
Canonical immutable object lookup/pins, Standard WINDOW publication wiring and
full monolith process recovery remain open before complete WINDOW acceptance.

## Pinned canonical-object recovery

`recover_canonical_rows` retrieves required canonical IDs from a live committed
catalog pin using exact version/digest object reads and bounded Parquet inspection.
It bounds selected files, compressed bytes, decoded bytes, scanned rows and returned
canonical bytes. It scans the complete bounded selection to detect conflicting
canonical identities and requires every requested ID. It preserves original WAL
sequence, event envelope and nested attributes. The original caller deadline and
catalog-pin lifetime apply before/after object and codec operations. Results grant
neither source authority nor publication permission.

Metadata recovery now retains a typed, order-independent digest for every required
canonical input, including assessment references after attempt TTL cleanup. A
changed input is refused even when its attempt entry has already been reclaimed.
The control metadata still excludes original event message/attribute bodies.

The owned PostgreSQL/immutable-Parquet fixture passes exact recovery, older-pin
missing-ID refusal, duplicate request, response quota and cancellation cases, plus
existing crash/takeover/privilege gates. Report:
`target/window-20261014/canonical-recovery-postgres/report.json` (`passed_simulated`,
actual local PostgreSQL/Parquet with synthetic object backend and policies).
All50rules tests,37runner regressions, fixture compilation, strict rules/control
Clippy and formatting pass. Standard consumer/publication wiring and lifetime
object retention pins remain required; this recovery primitive does not activate
Standard WINDOW or establish AWS object/version/retention acceptance.

## Retained recovery-object protection

`recover_canonical_inputs` returns a nonserializable original recovery result
containing canonical rows, exact object references, scope/backend and the original
catalog/operation deadline. Its rows cannot be read after that deadline.
`retain_canonical_inputs` accepts the current lease and installs replay pins only
for objects that supplied requested inputs. It refuses a foreign scope and uses
the same original deadline for all operations.

Pin identity is stable across exact retry and binds scope, private state key,
rule revision, metadata digest and exact object/version/content descriptor.
The existing PostgreSQL object-pin operation verifies current ownership and bounds
its recorded provenance. The helper neither publishes state nor automatically
releases pins. Partial or uncertain completion keeps installed protection; release
requires a separate explicit decision after confirmed state transition and all
remaining recovery/evidence uses are accounted for.

The owned PostgreSQL/Parquet fixture passes retained replay-pin creation and exact
retry, foreign-scope refusal, and an object retirement conflict. That object is
also protected by its committed reference and live catalog pin; the retirement
case does not isolate the replay pin as the sole reason for refusal. Report:
`target/window-20261014/canonical-pins-postgres/report.json` (`passed_simulated`,
actual local database/object behavior with synthetic policies/backend). Existing
shared-control gates pass and the owned container is removed. Fixture compilation,
strict control-crate Clippy and37runner-validator regressions pass. Standard
consumer state/findings/checkpoint wiring and safe obsolete-pin release remain open.

## Multi-event scoped-publication evidence foundation

The frozen scoped publication contract accepts exactly one event per finding and
its schema inspector enforces that invariant. WINDOW cannot use that contract by
substituting an anchor event or hiding its other evidence references. Frozen
single-event SQL and Rust validation remain unchanged.

`MultiEventFindingClaims` provides a separate version2 host-evidence format.
It binds all referenced canonical event IDs/sequences, the current anchor,
producer scope generation/startup/floor and scoped finding payload. Current rows
must be contiguous and identities distinct. Reconstruction checks the complete
ordered reference set and one canonical source/account/resource scope. Inputs at
or below the startup floor require prior-state provenance covering their sequence.
Older retained inputs require the prior checkpoint and matching scope generation.
Counts and encoded bytes are finite; reversed/missing/conflicting evidence refuses.

This builder is preparation for an additive fenced transaction, not a publication
method or an authentication grant. The future transaction must verify protected
prior-state key/revision/value hash and canonical reference membership, together
with current enrollment, ownership, checkpoint, quotas and exact replay. It must
also provide compatible scoped reads, inspectors and consistent restore before
Standard WINDOW can be enabled. Existing single-event publishers cannot accept
these version2 claims.

Two focused multi-event regressions and all70control-crate tests pass; strict
Clippy and formatting pass. Evidence:
`target/window-20261014/multi-claims-control-full.log` and
`multi-claims-clippy.log`. Standard publication wiring remains unfinished.

## Exact multi-event request and replay validation

Version2 claims now validate their serialized form: source/enrollment headers,
bounded distinct findings/references, current anchors, original scoped metadata
and prior-floor coverage. `verify_rows` reconstructs claims from the captured
producer and complete canonical rows without renewing admission or enrollment.

`MultiEventFindingClaims::bind` attaches original finding bytes to a publication
that updates the selected state key at the same rule revision. It checks current
anchor/reference ranges and prior checkpoint continuity.
`MultiEventPublicationInput::verify` additionally requires the exact current source
span and reconstructs the original attachment. Roundtripped serialized requests
must satisfy the same checks as newly prepared requests.

All72control-crate tests pass, including four multi-event/request regressions;
strict Clippy, formatting and diff checks pass. Evidence:
`target/window-20261014/multi-publication-control-full.log` and
`multi-publication-clippy.log`. This request type remains excluded from existing
client submission APIs. Additive SQL ownership/enrollment/prior-state checks,
atomic publication and compatible scoped reads/inspection/restore are still
required before Standard WINDOW is enabled.

## Additive publication installer and SQL claims

`MultiEventPublicationInput::encode_sql_claims` renders the seven-field companion
request expected by the additive SQL routine. It keeps original finding bytes in
the core publication, encodes prior revision/content hashes as hex, checks the
selected state attachment and applies the 128KiB claims bound. This encoder does
not grant host admission or submission authority.

The draft `010-multi-event-publication.sql` remains outside automatic startup.
Actual owned PostgreSQL17.5 verifies refusal while ready, stopped installation
by the core schema owner, the security-definer search path, no synthesized
profile, denied runtime table access and complete installation rollback. The
source-bound campaign passes in110.28seconds with owned container cleanup;
evidence is `target/window-20261014/multi-install-postgres/report.json` and
its `command-26.log`. Four focused request tests, strict control-crate Clippy,
formatting and37runner checks also pass. SQL publication itself, catalog/routine
identity binding, compatible scoped readers/restore and Standard consumer wiring
remain unqualified. WINDOW remains pending and Standard WINDOW stays disabled.

The additive routine now has actual PostgreSQL coverage for a fresh two-event
finding: original bytes, state and checkpoint, companion facts/claims and quota
counters publish together. Existing activation/enrollment foreign keys and
store-generation checks bind the new profile/facts to current scope. Exact
ordinary replay and resolution return the original result without changing rows
or counters. Absent resolution, stale epoch, quota exhaustion, changed replay
claims and an injected late failure after core publication refuse; complete
core/companion witnesses prove failure rollback. The enclosing fixture rolls
back its new schema and publication so existing qualification continues against
the original state.

The source-bound campaign at
`target/window-20261014/multi-atomic-postgres-fixed/report.json` passes with
actual PostgreSQL17.5 and synthetic canonical events/object descriptors. Four
focused request tests, strict control-crate Clippy and37runner checks pass.
The first run exposed an ambiguous fixture column before publication; its
failure is retained under `multi-atomic-postgres`. Protected prior-state reference
qualification, module catalog/routine identity, reader/restore compatibility and
Standard integration remain required. This does not close WINDOW.

## Protected prior-state publication

The selected state now uses a strict version1 `MultiEventStateEnvelope` containing
scope generation, publication checkpoint, detector metadata and a canonical
event-ID-to-sequence inventory. Rust and SQL require matching hash/sequence keys,
32-byte hashes, positive sequences no later than the checkpoint, at most4096
references and a64KiB encoded state. Raw event bodies remain outside control
metadata. The host must still recover and verify their canonical content.

For fresh publication, SQL verifies prior checkpoint continuity, state key,
rule revision, exact protected value hash and scope generation. Every retained
reference must match both an ID and its sequence in that protected value.
Actual PostgreSQL tests combine two retained events with one current event;
changed prior checkpoint/revision/hash/generation, missing protected IDs and
false prior sequences refuse with unchanged complete core/companion witnesses.
Exact replay of both the new and older commits works after state replacement
without republishing or updating counters.

Evidence: `target/window-20261014/multi-prior-postgres/report.json` passes with
owned container cleanup and synthetic canonical metadata/object descriptors;
`multi-prior-unit-complete.log` records73control tests, and strict Clippy and
37runner checks pass. Additive module identity, scoped read/inspection/restore
compatibility, Standard wiring and full WINDOW acceptance remain unfinished.

## Bounded client and additive module identity

`ControlClient::publish_multi_event` and `resolve_multi_event_publication` now
use the existing finite publication worker, transaction deadlines, cancellation,
rollback/uncertain-result handling and original publication reply verification.
They validate the request scope and state envelope before queue admission.
The worker locks current fenced store/partition authority before checking the
additive module's canonical table catalog, ownership, unexpected triggers and
exact routine source/signature/language/owner/search path. Frozen single-event
publication retains its existing path.

The catalog checksum derived from exact additive DDL in an isolated PostgreSQL
fixture matches the full installed core. Actual low-privilege client tests refuse
a missing module, altered table inventory and altered routine search path;
absent resolution remains uncertain and publication quota exhaustion leaves
complete core/companion witnesses unchanged. The owned fixture restores its
original core state and drops the temporary module afterward.

Evidence: `target/window-20261014/multi-module-postgres/report.json` passes with
owned cleanup;73control tests, strict control-crate Clippy and37runner checks
pass. Fresh successful publication and exact replay currently have direct SQL
coverage; successful bounded-client commit/replay, compatible scoped readers,
inspectors/restore and Standard WINDOW integration still require qualification.
Standard WINDOW remains disabled and WINDOW remains pending.

Successful bounded-client commit/replay is now qualified in an owned database
cloned from the existing scoped fixture. The worker publishes a two-event finding,
original state and checkpoint; direct retained reads verify the original event
references and finding content hash. Ordinary replay and resolution preserve the
complete core/companion witness, while stale tokens and changed retained claims
refuse. Closing all clients precedes removal of this isolated database, preserving
the existing single-event restore/restart fixtures.

The matching campaign at
`target/window-20261014/multi-client-positive-postgres-fixed/report.json` passes
with container cleanup; strict Clippy and37runner checks pass. The first campaign
stopped before publication because the fixture batched database creation with
a grant; that failed run is retained under `multi-client-positive-postgres`.
These are actual local PostgreSQL/client transactions with synthetic events and
object descriptors. Scoped reader/inspection/restore compatibility, Standard
consumer wiring and full WINDOW review/acceptance remain required.

## Scoped multi-event reads

The scoped list reader now validates an installed optional multi-event module
before selecting its facts alongside existing single-event facts. It checks
explicit SELECT authority on the three companion tables and
`signal_control.commits`, current scope generation, quotas/counters, original
content hashes, prefix position, absence of overlapping single-event facts and
the exact ordered references/selectors in the original finding. Inventory reads
fetch at most8 bounded fact/finding bodies per batch. Missing module privileges
refuse; the module supplies no request grant.

Paired source/account/resource permissions are applied before query filters and
limits. Actual PostgreSQL tests with separate read credentials verify permitted
original two-event findings, exclusion of crossed account/resource pairs and
refusal of altered selectors even when the companion hash is recomputed. Restoring
the original fact restores the permitted result. The fixture uses separate roles
for separate scope pairs, as required by the existing policy contract.

Evidence: `target/window-20261014/multi-read-postgres-paired/report.json` passes
with owned database/container cleanup;74control tests, strict Clippy and37runner
checks pass. Failed fixture/diagnostic campaigns remain retained. Temporary
library diagnostics were removed. Administrative/producer inspectors, consistent
restore, Standard consumer wiring and full WINDOW acceptance remain unfinished.

## Existing inspector and restore participation

Administrative and read-only producer scope inspection now include optional
multi-event inventory validation. The scoped list reuses that validation in its
fixed snapshot. Read-only producer inspection additionally refuses schema CREATE,
table mutation and routine EXECUTE privileges on the companion module, preserving
separation from publication credentials. Administrative inspection retains its
existing explicit schema-owner role; no read-only credential acquires that role.

Actual PostgreSQL tests verify the same checkpoint/enrollment through both
inspectors, refusal of semantic fact corruption, refusal of producer-read UPDATE
or publication EXECUTE grants, and successful inspection after those grants are
revoked. The complete campaign at
`target/window-20261014/multi-inspect-postgres/report.json` passes with owned
cleanup;74control tests, strict Clippy and37runner checks pass.

Restore now locks the optional companion tables with the scoped core and includes
their complete row hashes in source checkpoint and post-restore hashes. A core-only
restore profile refuses an installed companion module. Existing restore regression
campaigns pass, but populated-module copy/omission/tamper/fresh-generation restore
qualification remains required. Standard WINDOW remains disabled; these changes
do not close WINDOW or the release-candidate goal.

## Populated multi-event consistent restore

A fresh scoped fixture now publishes a two-event finding and detector metadata
against actual locally written Parquet. Restore custody reads and verifies the
exact file version, byte count and checksum through the existing local immutable
version fixture. Source checkpoint approval is captured separately before copying;
the fixture enrolls an empty external consumer set explicitly.

Actual PostgreSQL tests reject omission of the companion module against that
captured checkpoint and reject altered selectors even with recomputed hashes and
quota counters. A matching stopped copy restores under a fresh store generation,
preserving original finding bytes, references and detector-state bytes. The old
token is fenced. A current lease reads the original checkpoint/state and resolves
the exact historical publication without republishing it. Historical resolution
changes only the current control-scope binding; it confers no fresh admission.

Evidence: `target/window-20261014/multi-restore-postgres/report.json` passes with
owned database/container cleanup; strict control-crate Clippy and37runner checks
pass. Parquet content and PostgreSQL transactions are actual local operations;
authority, immutable-version and retention policy are fixture simulations.
This is control-module restore qualification, not whole-server/WAL or AWS recovery.
Standard WINDOW consumer/recovery integration, obsolete pin release, process
qualification and full review/acceptance remain required.

## Standard host metadata adapter

`signal_server::shared_window::SharedWindowBinding` now renders WINDOW state into
the bounded control envelope and hydrates it from a fenced state read plus complete
canonical rows. The inner metadata pins store, tenant, partition, stream and the
onboarding source binding, while preserving the private policy and canonical
content hashes. Store generation may change through authorized restore; the
logical source identity and source binding must still match.

The adapter exposes validated required event IDs for bounded catalog recovery,
checks exact original sequences and canonical bodies, and returns the original
protected value hash/revision/checkpoint as prior-state provenance. It charges
canonical payload bytes before cloning, excludes raw message/attribute bodies
from control metadata and refuses missing state or incomplete evidence. These
data helpers grant no new admission, read authority or publication permit.

Two focused server-library regressions and strict server Clippy pass:
`target/window-20261014/shared-window-tests-recovery.log` and
`shared-window-clippy-recovery.log`. They cover exact outcome/state round-trip,
original provenance, missing/changed inputs, sequence changes, policy/checkpoint
mismatch and foreign source binding/store/tenant. This is an in-memory adapter
check; runtime PostgreSQL/catalog/consumer composition remains required. Standard
WINDOW configuration remains disabled until publication/recovery, bounded history
and pin lifecycle are integrated and qualified.

## Shared publisher multi-event drafts

`MultiEventPublicationDraft` now captures the original producer header, claims,
selected state key and bounded retained canonical inputs before upload. Retained
payloads are charged before cloning and limited to1MiB/4096rows, with a versioned
checksum covering their original sequences and bytes. Deserialized drafts recheck
that checksum, current/retained rows, prior key/revision/checkpoint continuity and
the selected state envelope before object preparation. These checks confer no
new source authority.

`SharedPublisher` now prepares and commits multi-event requests while retaining
the existing admission seat, original deadline and immutable object references.
Exact resolution uses the multi-event control routine; recommit rereads the
original referenced versions and follows the existing fenced publisher lifecycle.
Single-event publication keeps its existing path.

Eleven server-library tests and74control tests pass, with strict server Clippy:
`target/window-20261014/multi-publisher-qualified-lib.log`,
`multi-draft-prior-tests.log`, `multi-publisher-control-lib.log` and
`multi-publisher-settled-clippy.log`. The new regressions verify draft round-trip,
original finding bytes, current/retained input tampering, foreign scope, prior-key
mismatch and invalid state refusal. They qualify draft logic only. Actual publisher
upload/commit/recommit, durable multi-event recovery-ledger phases and Standard
consumer/history/pin lifecycle integration remain required; Standard WINDOW stays
disabled.

## Durable multi-event publication ledger

`SharedRecovery` now syncs version3 multi-event draft and prepared-request phases.
Prepared records retain bounded original producer/retained-input evidence without
duplicating the whole draft. Resume checks original WAL row hashes and revalidates
the captured inputs before any missing-commit retry. Exact prepared requests
resolve under current authority; an acknowledged prefix permits only existing
resolution. Confirmed publication precedes WAL checkpoint and ledger reclamation,
using the existing uncertain-result and physical-worker lifecycle.

The server fixture runs the actual WINDOW engine and source-bound metadata adapter
over six actual WAL events and Parquet publication. Three cases pass: dropped
prepared operation before commit, commit before WAL acknowledgement, and already
acknowledged WAL with a retained ledger record. Each preserves original request
identity and state, reconciles exactly once and clears the record only after the
confirmed checkpoint. Retained prior canonical inputs contribute across batches.

The full source-bound server campaign at
`target/window-20261014/multi-ledger-postgres-all-prebuilt/report.json` passes,
including existing HTTP/provider/native admission checks and owned cleanup.
Strict server Clippy,11server-library tests and37runner checks pass. Earlier
campaigns retained compilation/provider deadline failures; prebuilding all server
test targets resolves them without changing runtime limits. Admission and object
versions in the new ledger fixture are simulated; WAL, detector, Parquet and
PostgreSQL operations are actual. Multi-event SIGKILL/lost-reply cases, Standard
configuration/consumer integration, bounded history and obsolete-pin lifecycle
remain required. Standard WINDOW remains disabled.

Multi-event recovery now also qualifies actual caller cancellation after
PostgreSQL COMMIT is observed executing. The fixture adds a deferred half-second
commit pause, observes `COMMIT`/`PgSleep`, then cancels the original operation.
The caller receives an uncertain result; WAL remains at its previous checkpoint
and the exact prepared record remains synced. After removing the fixture pause,
fresh exact reconciliation confirms the original request and advances/checkpoints
the WAL once. All four ledger scenarios preserve original identity and state.

The full source-bound campaign at
`target/window-20261014/multi-lost-reply-postgres/report.json` passes, including
HTTP/provider/native checks and owned cleanup. Strict server Clippy and37runner
checks pass. This is observed COMMIT cancellation with actual PostgreSQL/WAL;
multi-event SIGKILL and full Standard WINDOW process recovery remain separate
requirements. Standard configuration, bounded history and obsolete pin release
remain unfinished.

Multi-event prepared-request recovery now qualifies three actual producer SIGKILL
boundaries: before commit, after commit and after WAL acknowledgement. Parent
publishers/clients/WAL close first; the owned child opens the retained slot, reaches
a synced marker and remains alive until the parent kills and reaps it. Reopened
WAL preserves the expected checkpoint and original record. Exact reconciliation
then confirms the original request and reclaims the record once. The parent-retained
object backend remains a simulated version service; this is not object-process
durability or whole-server recovery proof.

The complete campaign at
`target/window-20261014/multi-sigkill-postgres/report.json` passes with owned child,
database and container cleanup. The observed COMMIT-cancellation, existing
HTTP/provider and native admission gates also pass; strict server Clippy and37
runner checks pass. The pre-upload multi-event draft SIGKILL boundary, Standard
configuration/consumer integration, bounded history and pin lifecycle remain open.

The pre-upload multi-event draft SIGKILL boundary is now qualified as well.
The fixture syncs its original draft while PostgreSQL publication is fenced and
proves the object-I/O processed count is unchanged. An owned child opens that
version3 draft, reaches a synced marker, then is killed and reaped. Reopened WAL
retains the original plan and previous checkpoint; recovery publishes the same
request ID, exact finding bytes and detector state before acknowledging it.
All five ledger scenarios now compare persisted detector bytes and findings.

The complete campaign at
`target/window-20261014/multi-draft-crash-postgres/report.json` passes with owned
cleanup, all four multi-event SIGKILL boundaries, observed COMMIT cancellation,
HTTP/provider/native gates, strict Clippy and37runner checks. Object versions and
admission remain simulated in the ledger fixture. Standard WINDOW configuration
and consumer integration, bounded history and obsolete-pin lifecycle remain open;
these component checks do not establish full Main recovery or WINDOW acceptance.

## Composed shared WINDOW recovery

`SharedWindowRecovery` now performs one bounded recovery operation: validate the
captured binding/limits, pin the current catalog, read detector state against its
exact head, require matching checkpoints, recover complete canonical Parquet rows,
hydrate the source-bound state and install replay pins before returning. Every
step retains the original catalog deadline. Missing state refuses recovery;
initializing a new detector remains an explicit host decision. Installed pins are
not automatically released on error, cancellation or drop.

The actual server fixture now uses this composed path between publication batches,
compares hydrated rows to their original admitted values and verifies that all
returned replay pins remain installed. The complete source-bound campaign at
`target/window-20261014/shared-window-recovery-postgres/report.json` passes with
owned cleanup, all ledger/process/HTTP/provider/native regressions, strict server
Clippy and37runner checks. The version backend and admission remain simulated;
Parquet, WAL and PostgreSQL operations are actual local operations. Explicit
obsolete-pin release, bounded history and running Standard consumer/configuration
integration remain unfinished. Standard WINDOW stays disabled.

## Conservative replay-pin transfer

The explicit stopped-installed `011-replay-pin-transfer.sql` routine and bounded
`release_replaced_replay_pin` client release an old replay pin only while a retained
replacement protects the identical object/version. One fenced transaction verifies
current head, selected state revision/content hash/checkpoint, pin kind, source
scope, state key, original checksums and replacement metadata binding. Complete
transfer bytes are preserved in the core release reason; the wrapper reply binds
the transfer request digest. No provider retirement/delete operation occurs.

Actual PostgreSQL tests verify successful transfer, exact replay, stale head/hash
refusal and rejection of a reverse transfer that would remove the remaining
protection. Read-only producer inspection also rejects the new routine's EXECUTE
authority. The complete campaign at
`target/window-20261014/replay-transfer-postgres-bounded/report.json` passes with
owned cleanup, strict server Clippy and37runner checks. Earlier encoding/reply
contract failures and a finite server-subtest timeout remain retained. Added cases
require a45second server subtest; individual operation deadlines and the240second
parent budget remain unchanged.

This qualifies redundant same-object pin transfer only. Releasing obsolete object
versions still requires complete current-state/history accounting. Bounded shared
assessment history and Standard WINDOW consumer/configuration remain unfinished.


## Shared assessment archive and pending expiry

The explicitly owner-installed `012-window-history.sql` adds per-state private
row, byte and retention enrollment and an atomic trigger on the additive
multi-event request ledger. It archives metadata-only assessments, exact canonical
hash/sequence references and private policy/source bindings in the publication
transaction. Runtime producers receive no direct history-table permissions.
The client checks the installed catalog, function body and exact trigger identity.
Quota exhaustion rolls back state, checkpoint, findings and request insertion.

An assessment still present in the selected state's pending outputs retains its
original archive record after expiry. Repeated publication cannot renew that
record's custody time, checkpoint or expiry. Expired records are reclaimed when
those outputs are retired. This recovery hold does not grant permission to return
expired evidence. History readers must enforce expiry independently.

The actual local PostgreSQL/server campaign at
`target/window-20261014/shared-history-expiry-postgres/report.json` passes all
50 checks, including match/no-match retention, atomic quota rollback and an
owner-controlled rolled-back trigger regression for expired pending replay and
post-retirement reclamation. The expiry regression invokes the installed trigger
through a temporary fixture table; it does not establish whole-monolith runtime
integration. Focused strict server Clippy, formatting and37runner tests pass.
The earlier successful archive campaign and diagnostic failures remain retained.

Shared history reads/cursors, Indeterminate qualification, stopped-restore
inventory participation and complete history/object retention accounting remain
unfinished. The pending-output regression does not qualify arbitrary resurrection
of a retired assessment in a later publication. Standard WINDOW configuration and
consumer integration, whole-process qualification and final review remain open.


## Shared history stopped-restore custody

Stopped scoped-catalog restore now locks both optional history tables together
with the core and multi-event tables. The history profile and assessment rows
participate in the separately captured source checkpoint and the before/after
data fingerprint. A history schema without its multi-event dependency is refused;
a core-only restore cannot accept this supplemental inventory.

The populated PostgreSQL/actual Parquet restore fixture now includes an explicitly
owner-seeded expired archive record. It verifies refusal of a missing history
schema, deleted records with corrected counters, rewritten payloads with recomputed
IDs/checksums/counters, and shifted custody/expiry timestamps. Successful fresh
store-generation restore preserves the original record ID, checkpoint, payload,
checksum, custody time and already-expired deadline. These tests qualify archive
custody during restore; production detector-to-archive derivation is covered by
the separate server fixture, not by the owner-seeded restore record.

The source-bound complete campaign at
`target/window-20261014/shared-history-restore-postgres-prebuilt/report.json`
passes50checks in173.68seconds with container removal and no cleanup errors.
Focused control strict Clippy, formatting and37runner tests pass. The preceding
campaign's restore/server gates passed, but its native-admission wrapper timed out
because compilation plus the passing test exceeded15seconds. All server test
targets were prebuilt before the successful rerun; no deadline was increased.

Shared history reads/cursors, independent Indeterminate archive qualification,
retired-assessment resurrection refusal, complete object-use accounting/general
obsolete-pin release and Standard WINDOW configuration/consumer integration remain
open. This slice does not close WINDOW or provide release/native-ARM64/AWS proof.


## Retired assessment replay fence

The explicit history profile now retains a monotonic sealed watermark independently
of its prunable archive rows. A candidate assessment at or before that watermark
must already have its original retained archive record. Otherwise the enclosing
publication is fenced. This prevents a retired, expired and reclaimed assessment
from being inserted again with a new custody/expiry term. Existing pending replay
continues to retain the original record and expiry; advancing the watermark and
archive counters occurs in the same publication transaction. Stopped restore
fingerprints include the watermark fields.

Whole UTC seconds and fractional nanoseconds are stored separately. The SQL parser
strips the fraction before PostgreSQL timestamp conversion and parses its digits
independently, avoiding PostgreSQL's microsecond rounding. The current parser
accepts canonical UTC timestamps with four-digit years and non-leap seconds;
other representations fail closed. Broader canonical timestamp compatibility
remains to be resolved before full WINDOW acceptance.

The owner-controlled rolled-back trigger regression now reintroduces retired
outputs after reclamation and requires `SIGNAL_FENCED` with no archive insertion.
A one-nanosecond advance is accepted and the corresponding regression is refused.
The source-bound complete PostgreSQL/server/native-HTTP campaign at
`target/window-20261014/shared-history-resurrection-postgres/report.json` passes
50checks in175.47seconds, with owned container removal and no cleanup errors.
All174recorded campaign source hashes still match. Focused Clippy, formatting and
37runner tests pass. An isolated installed-trigger smoke test caught a variable
binding error before the full campaign; its corrected result is retained.

WINDOW remains pending. The next shared-history read contract is captured in
`target/window-20261014/SHARED-HISTORY-READ-NEXT.json`. Reads/cursors/expiry delivery,
Indeterminate archive qualification, complete history/object use accounting,
general obsolete-pin release, Standard configuration/consumer integration and
full source-frozen review/process/native qualification remain open.


## Bounded shared history reads

The explicitly stopped owner-installed `013-window-history-read.sql` and
`ControlClient::read_window_history` expose retained metadata under the current
pipeline lease, exact head and selected state key. Installation grants no runtime
permissions. The runtime needs an explicit function grant; direct archive-table
permissions remain unnecessary. Installed function source/signature/owner/path
and archive catalog/trigger identities are verified before use. No public HTTP
read authorization is introduced.

Pages contain at most128records and1MiB of response/export data; individual
archived payloads remain bounded at64KiB. State/source/policy bindings, counters,
checksums and custody/expiry consistency are checked. Strict versioned cursors
bind store generation, partition/stream, head, state key/content and the complete
bounded archive fingerprint. Foreign/stale or missing positions refuse
continuation. Empty, truncated and expired history explicitly report missing
evidence; metadata-only exports identify their evidence as canonical references.
Canonical event hydration and provider custody remain separate operations.

Returned pages retain the caller's original cancellation/deadline, not the
worker's submission token. Database-reported remaining lease time and record
retention are anchored before the SQL request onto monotonic deadlines; client
clock disagreement cannot extend them. Export withholds expired metadata, checks
cancellation/deadline again after serialization and refuses bytes whose included
metadata expired during assembly. Raw retained payloads are private to the page.

The complete real PostgreSQL/server/native-HTTP campaign at
`target/window-20261014/shared-history-reader-corrected-postgres/report.json`
passes51checks in207.32seconds with owned cleanup. All176recorded source hashes
match. Actual cases cover missing grants, pagination, foreign scope/head/cursor,
archive mutation invalidating a cursor, expired metadata withholding, corruption,
original-context cancellation and installed-routine tampering. All78control unit
tests (including four reader boundary tests), focused strict control/server Clippy,
formatting and37runner checks pass. A pre-correction campaign exposed the worker
submission-token lifetime bug; its failure and cleanup are retained. One existing
15msrestore test failed in a parallel unit run and passed in the complete serial
rerun; its timeout was not changed.

This is local AMD64 read/retention evidence. Full WINDOW acceptance still requires
Indeterminate archive qualification, broader watermark timestamp compatibility,
complete history/object use accounting and general obsolete-pin release, Standard
configuration/consumer integration, whole-process qualification and final review.


## Indeterminate archive and obsolete replay-pin accounting

The actual detector fixture now seals a batch with unverified coverage, publishes
its Indeterminate assessments through the shared transaction and reads the
original outcome through the bounded history API. The pre-existing Match and
NoMatch cases continue to pass. Admission and the version backend remain explicit
fixture simulations; detector, PostgreSQL, Parquet and WAL operations are real.

The explicitly stopped-installed `014-obsolete-replay-pin.sql` and
`release_obsolete_replay_pin` add a bounded release decision for a selected replay
pin. The transaction fences current scope/lease/head and selected state revision/
content. It validates the complete dynamic committed catalog, every supported
Window state and every retained archive in the partition, including expired
archive rows not yet reclaimed. Canonical ID/hash/sequence maps are checked before
accounting. Unknown state formats, missing profile/state pairs, corrupt metadata,
unknown objects and exceeded bounds refuse release.

A pin remains protected if any retained state/history sequence lies in a commit
whose exact object set includes its immutable object version. This conservatively
retains all files of a needed commit; it does not claim minimal per-file liveness.
The scope is bounded to128states/profiles,65536archive rows/unique sequences,
64MiB of archive payload and the existing128commit catalog. Original operation
budgets and physical worker ownership remain in force. No replacement object is
required when the complete supported accounting excludes the old version.

An original release intent has a deterministic catalog identity and is preserved
in the core release reason. Exact existing-only replay resolves the original
result without granting a new mutation, even after its catalog pin expires or
the head advances. This does not retire or delete an object. Existing committed
history, reader pins, evidence/restore pins and provider custody remain independent
holds. The host must resolve its publication/recovery ledger before invoking
cleanup; automatic Standard cleanup is still unimplemented.

The actual fixture proves that an object absent from current state is still held
by retained history. A real sixth publication, after fixture-controlled expiry,
reclaims old history and moves beyond the attempt TTL; the old replay pin then
releases and replays exactly. Current protection and stale head/content requests
are refused. The source-bound complete campaign at
`target/window-20261014/obsolete-pin-postgres/report.json` passes52checks in203.94s
with owned cleanup. Focused strict Clippy, formatting,79control tests and37serial
runner tests pass. Earlier readiness-helper tests timed out while compilation was
active; the unchanged suite passed serially. Isolated SQL smoke checks explicitly
stub authority/catalog/release and do not substitute for the real campaign.

The expanded server fixture has a60second harness budget (actual36.06s in this
campaign); production operation deadlines and the240second parent budget are
unchanged. Standard consumer/configuration integration, ledger-aware cleanup,
whole-process qualification, timestamp compatibility and final acceptance remain
open. WINDOW is not accepted and no release is ready.


## Standard configuration and protected delayed-anchor foundation

Small configuration schema1 retains its required absolute SQLite database path.
The new strict schema2 instead carries `policy` and a `shared` object with
`state_key`, optional `bootstrap_checkpoint`, and explicit `recovery` limits
(`files`, `object_bytes`, `decoded_bytes`, `scanned_rows`, `result_bytes`). Mixed
local/shared documents, wrong versions and invalid limits are refused. The shared
source binding includes the host binding, state key and explicit bootstrap
boundary. Standard rule/audit revision construction includes the Window policy
and that source binding. At this foundation boundary the Standard consumer path
was still unimplemented; the later Main qualification below supersedes that limit.

`015-window-profile.sql` is an explicit stopped owner installation without grants
or enrollment. `ControlClient::read_window_state` uses the existing bounded state
read operation to verify all required additive routines, original lease/head,
explicit runtime grants and enrolled scope/quotas. An absent state requires an
explicit matching bootstrap checkpoint and an unused empty history profile with
no prior watermark. Existing state instead receives full archive validation.
The method returns retained metadata, not independent publication authority.

A detector can persist an unsealed batch and seal its anchors only after a later
batch reaches the WAL tail. Claims schema3 and
`from_retained_anchor_host` support those delayed anchors only under exact
protected prior state and original canonical identity/sequence membership. The
anchor must still be above the producer's original WAL floor. Claims schema2
keeps its current-batch-anchor restriction; single-event publication is unchanged.
The outer multi-event publication/recovery layout remains schema2, carrying the
explicit nested claims version. Before cloning retained inputs, both draft
constructors preserve the existing1MiB byte preflight.

The real fixture commits an unsealed first batch, then seals and publishes a
prior anchor in the second batch, including original-byte SIGKILL recovery and
quota rollback. Explicit bootstrap absence/mismatch, missing grants and quota
mismatch are refused; valid initial and existing-state profile reads pass. The
complete campaign at
`target/window-20261014/standard-window-foundation-postgres/report.json` passes
53checks in201.29s with owned cleanup. All80control tests, two configuration tests,
strict default and `s3-query` control/server Clippy, formatting and37runner tests
pass. The isolated profile SQL smoke uses stubbed authority and is only a shape
check. These results do not qualify an enabled Standard WINDOW Main process.

The next work at that foundation boundary was the single-writer Standard state holder, startup bootstrap/recovery,
consumer multi-event transaction, confirmed-idle pin cleanup and metrics, then
actual Main process qualification. Concrete entry points remain in
`target/window-20261014/STANDARD-WINDOW-NEXT.json`. Full WINDOW/release acceptance,
broader timestamp compatibility and current native/remote gates remain open.


## Standard startup and consumer wiring

`standard_window.rs` now owns the single-consumer policy, source binding, exact
prior provenance, hydrated canonical inputs and candidate state. Startup calls
the explicit profile reader at the reconciled head/WAL checkpoint, then either
uses the configured unused-profile bootstrap boundary or recovers original
canonical inputs and replay pins. Recovery reuses the existing publisher workers;
it creates no separate queue or worker pool.

The consumer clones a candidate, retires previously confirmed outputs, admits
only host-bound rows above the captured authentication/bootstrap floors and seals
only at its observed WAL tail with a live trusted source interval. It publishes
Window metadata and stateless/Window findings through the protected-anchor
multi-event recovery path. Only confirmed publication, matching WAL ACK and an
empty recovery slot permit installing the candidate as the next in-memory state.
Same-timestamp assessments with identical finding IDs/bodies collapse to one
finding; conflicting bodies refuse publication.

After that confirmed-idle boundary, cleanup considers only the bounded replay-pin
set returned by this process's startup recovery. Required history/current-state
holds remain pinned; uncertain/partial pins outside that set remain untouched.
Cleanup never deletes objects. Cleanup errors hold the consumer. Identity-free
metrics include Window health, actual archive row/byte usage and cleanup queue
size/capacity. Coverage is unknown before a fresh interval and after expiry or
stop. `HistoryPage::usage` supplies lease/context-bound aggregate counts without
exposing raw retained bytes. Shared configuration now rejects recovery results
above the existing1MiB multi-event retained-input budget instead of clipping them.

Both strict default and `s3-query` Clippy checks pass.80control tests, two Window
configuration tests and two new Standard consumer boundary tests pass, including
actual rule-to-claims same-timestamp deduplication and expiry/stop health. The
refreshed underlying PostgreSQL/server/native-HTTP campaign at
`target/window-20261014/standard-window-consumer-postgres/report.json` passes
53checks in180.56s with owned cleanup and181matching source hashes;37runner tests
and formatting also pass. This campaign exercises the shared primitives and
history protocol, not an enabled Standard Main Window path.

## Actual Standard Main qualification — 2026-10-15

Strict schema2 is now wired through actual Standard Main. Schema1 SQLite input
is refused by Standard; shared input is refused by Small. The initial explicit
bootstrap checkpoint must equal the reconciled WAL/database checkpoint and use an
unused enrolled profile. Keep that configured boundary unchanged across restarts:
it is part of the captured source binding. No owner grants or private policy are
installed by Main.

The stopped owner installs009..017 and explicitly enrolls multi-event/history
quotas. The WINDOW producer profile permits the current-lease fencing RPC plus
named additive routines, with a separate `signal_window_pin.retain` grant for
recovery. That helper permits only replay pins bound to the exact current state
hash/revision/scope and a committed object/version/length/digest; it cannot release,
retire or delete objects. General `signal_control.object_control` remains forbidden.
The read-only findings role also needs SELECT on committed manifests and the
multi-event companion tables. Credential checks reject table/schema mutation,
object-control grants and nullable allowlist bypasses when optional modules are
absent. Ordinary producers retain their separate grant profile.

Exact canonical retries preserve original retained sequences. Recovery chooses
protected ID/sequence pairs and refuses changed canonical content. The bounded
lease/head-bound016 lookup filters already committed equivalent findings without
changing their original opaque bytes or promoting legacy unknown scope. Stateless
readiness decisions exclude the separately evaluated Window inventory; startup
still validates the complete signed detection inventory.

The actual Main campaign proves three initial bootstrap/quota refusals, same-time
attempts split across batches, signed source-watermark sealing with protected prior
anchors, exact retries, confirmed-state SIGKILL/restart, and SIGKILL while a synced
multi-event request is blocked in PostgreSQL. Restart preserves original SQL
publication/claims/manifest/finding bytes and the database/WAL checkpoint, including
original canonical positions in duplicate-bearing Parquet. Source/binary bindings
and owned cleanup are retained in
`target/window-20261014/window-main-process-v7/report.json` (six scenarios,
137.91s,265 matching source hashes). The refreshed53-check shared campaign passes
177.87s with245 matching source hashes and owned cleanup:
`target/window-20261014/window-main-shared-final/report.json`.81control tests,
38runner guards, focused mixed-inventory evaluation, strict control/server
`s3-query` Clippy and formatting pass.

These are local AMD64 process proofs with actual PostgreSQL/Parquet/WAL and
simulated object/host authority. WINDOW remains in progress. The Small Main process proof below closes that specific crash/restart gate.
Broader canonical timestamp compatibility, remaining consumer edge cases, focused
review and frozen workspace/all-feature/process/native acceptance are still required. No alpha/release, AWS/EKS or publication claim follows.

## Actual Small Main crash qualification — 2026-10-15

The native identity/onboarding fixture now has an explicit `--window` mode. It
runs same-time attempts in separate WAL batches, then restarts with a findings
quota that permits existing repeats but refuses the new Window finding. A single
bounded incomplete HTTP body keeps graceful drain live long enough to observe and
SIGKILL the actual process after its atomic SQLite outbox commit. The exact pending
SQLite payload and original findings-journal prefix survive; the WAL checkpoint
remains behind. Restart with capacity restored publishes the original scoped
outbox once, retires pending outputs and preserves finding bytes through a second
SIGKILL. Current evidence is not substituted for the outbox's original authority.

A real SQLite writer then holds the next atomic commit. The fixture observes an
owned journal operation and the preceding stateless finding, kills Main with the
journal and WAL checkpoint unchanged, releases the database lock, and restarts.
That uncommitted retained event remains excluded from verified Window attempts and
produces an explicit coverage gap. It cannot acquire fresh native authority merely
because the independent host report is current again. Every requested kill must
have an actual SIGKILL exit; a normally exited process cannot satisfy the check.

Five WINDOW checks, the inherited native identity/onboarding campaign and four
ownership failure regressions pass. Evidence:
`target/window-20261014/SMALL-MAIN-ACCEPTANCE.json`. This is actual local Small Main,
SQLite/findings/WAL and TLS identity-provider execution with synthetic signed host
coverage. It does not close full WINDOW, timestamp compatibility, review, current
native/remote gates or release acceptance.

### Canonical archive clocks — 2026-10-15

SQL012 parses canonical UTC clocks into the same POSIX-second/nanosecond pair as
Chrono. Bounded proleptic Gregorian arithmetic supports years-262143through262142,
including year zero and expanded years. Leap seconds retain second59 with
nanoseconds in[1000000000,1999999999]; carrying them into the next POSIX second
would change ordering. Both watermark and anchor guards use the private helper,
whose source/signature/owner/configuration are verified. The table fingerprint
includes the widened nanosecond constraint. Exact monotonicity and retired-output
resurrection refusal remain mandatory.

`target/window-20261014/CLOCK-ACCEPTANCE.json` records46Chrono pair comparisons,
11invalid clocks and7installed-trigger progressions plus one-nanosecond regression
refusals. These owner-side rollback fixtures qualify clock guards, not detector
derivation for synthetic dates. The refreshed53-check PostgreSQL/WAL/Parquet
campaign passes183.25s with245source hashes and owned cleanup. Whole WINDOW
acceptance still requires remaining consumer edges, review and full frozen gates.

### Standard consumer guard qualification — 2026-10-15

The private reconciliation helper used by Main has six regressions for identical
scoped retries, first WAL position, original unknown-scope bytes, distinct rows,
changed body/generation/canonical scope and malformed duplicate refusal. Unknown
scope never gains authority from a later authenticated retry. The actual Main
campaign adds missing replay-pin permission and changed policy-revision startup
refusals. Its owner oracle compares committed states/findings/commits/requests/
checkpoint before and after both refusals. Revision is refused by retained-state
identity before detector policy validation. All8scenarios pass169.97s under the
unchanged180s deadline;266source hashes match and owned cleanup succeeds.

`target/window-20261014/CONSUMER-ACCEPTANCE.json` records exact evidence, focused
writer review and harness corrections. This qualifies local process behavior with
simulated object/host authority. Whole-WINDOW review and full frozen acceptance
remain required before staging or commit.

### Review: zero-failure assessments — 2026-10-15

A successful authentication can anchor a window containing zero failed attempts.
Its NoMatch assessment has no failure IDs/evidence and creates no finding. An
Indeterminate assessment may likewise have no failure evidence; absence alone
does not establish a clean interval. SQL012 and SQL014 now agree with these core
shapes: zero references are allowed only for NoMatch/Indeterminate, canonical maps
are empty objects, and Match requires nonempty references. Bounds, map integrity,
watermark/resurrection and replay-pin reachability guards remain enforced.

Both mismatches were reproduced. A canonical successful-login input in the actual
publication fixture now yields a zero-failure archive and passes full recovery,
history and protected/obsolete replay-pin checks. The refreshed53-check campaign
passes206.78s with246matching source hashes and owned cleanup. Exact evidence and
diagnostic scopes: `target/window-20261014/REVIEW-CORRECTIONS.json`. Whole-WINDOW
review and full frozen acceptance remain required; no release claim is made.

### Read-only enrollment boundary — 2026-10-15

Existing-enrollment inspection rejects mutation authority in the protected core
and optional WINDOW schemas, even when a role receives it through PUBLIC or
non-inheriting, SET-capable membership. The check includes schema ownership/CREATE,
routine EXECUTE, table/column mutation and sequence USAGE/UPDATE. SELECT authority
remains separate from native admission and does not enable a detector.

A real PostgreSQL fixture first reproduced acceptance of history UPDATE, then
verified seven grant/revoke cases and safe SELECT-only inspection after each.
The complete8-case Main campaign passes175.08s with266source bindings and owned
cleanup: `target/window-20261014/READER-ACCEPTANCE.json`. This is local evidence
with simulated host/object authority; whole-WINDOW frozen acceptance is pending.

## Final local acceptance — 2026-10-15

WINDOW passes local simulation acceptance — 2026-10-15. Bounded authentication event-time/watermark/lateness, canonical replay identity, key/event/byte/TTL/output/history limits, unknown coverage and atomic state/findings/checkpoint recovery are qualified. Six frozen workspace gates pass1048default/1117all-feature tests, both strict Clippy modes, formatting and14workspace boundaries. Actual Small Main passes5WINDOW/8onboarding checks; Standard Main passes8scenarios; shared recovery passes53checks in206.73s. Runtime source bindings109/266/246 match; retained Small/Standard executable identities match and owned cleanup succeeds. Writer review closed three reproduced findings; it is not independent release review. Evidence:`target/window-20261014/ACCEPTANCE.json`; [contract64](64-authentication-window.md). LinuxAMD64 with actual SQLite/PostgreSQL/Parquet/WAL and SIGKILL; signed host/object authority is synthetic. Inventory35accepted/17unfinished. Current remote/native/container/Kubernetes, AWS/EKS, released dependencies, version and publication remain separate. Next local dependency-ready detector:SENSOR-HEALTH; Phase9 AWS collection requires a separate task.

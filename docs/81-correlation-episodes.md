# Bounded correlation episodes

Implementation contract. CORRELATION D11/D14 now passes bounded local simulation;
acceptance is recorded in `target/correlation-d14-20261026/ACCEPTANCE.json`.
Both rules and their full replay/coverage tests qualify only the stated local scope. Existing YAML remains unchanged. Private policy
selects thresholds, windows, source inventory, classifications and response.
Correlation creates an investigative candidate, not causal root cause, compromise
or proof of exfiltration. No Main activation or new publication authority is
implied by this contract.

## D11 authentication episode

Consume actual selected native authentication projections, preserving identity
authority/principal/target, method/session, source binding and native producer
boot/sequence. Never join solely by IP. A qualifying burst contains at least the
private threshold N distinct failures spanning no more than W, followed by a
distinct success for the same identity/target within C of the burst's last
failure. Failure and success timestamps must establish order; tied timestamps
without verified source ordering cannot establish "followed by".

Evaluate event time rather than arrival order. Buffer bounded late/reordered
inputs until a host-verified watermark can seal the relevant history. Pin an
explicit deterministic burst selection and episode identity before implementing
matching. Empty or insufficient history supports no_match only when the required
lookback and all selected success/failure streams have complete current coverage.
Catalog booleans such as qualifying_failure_burst are fixture descriptions, not
runtime evidence or authority.

The existing host_auth normalizer preserves authentication/session and native
producer identity. WINDOW already distinguishes native boot/sequence from the
canonical UUID and hashes native content without id/observed_at. Re-normalizing
one native attempt may produce a different canonical UUID; it must not increase
the failure count or create another success episode. Reuse of either identity
with conflicting source content must refuse. Keep the first admitted original
canonical evidence for a native identity throughout replay.

## D14 protected read and egress

Join actual successful protected credential READ and subsequent suspicious egress
within private C using exact host, boot, process-start and applicable execution
identity. Historical versioned asset and destination decisions must cover each
operation time and bind authenticated native input. File-open is insufficient to
prove successful credential read; process names, current PID/path, a producer's
protected_read flag and unsigned source coverage are insufficient. Never collect
credential contents. Different hosts, reused PID/boot/execution, absent streams,
stale/ambiguous policy or unsupported read semantics cannot complete an episode.
Complete supported positive and negative native profiles and their preconditions
before accepting D14; source-capture limitations remain explicit.

## Authority, bounds and replay

The host supplies fresh independently verified source/identity/coverage and
policy context for every contributor. Serialized episode/history/coverage data
never becomes fresh authority. Bind complete source/configuration/policy/key
revisions and operation-time validity. Missing or unsupported evidence remains
indeterminate with an explicit gap. Valid positive evidence may retain a match
with degraded coverage; no_match must not be inferred from missing evidence.

Select finite bounds for streams, keys, retained events/native IDs, bytes,
lookback/window/lateness/TTL, assessments, pending effects and history. Watermarks
must account for every required stream and refuse regression or unsupported
coverage. Overflow or lateness loss must remain visible; eviction cannot silently
create a clean episode or erase dedup identity. Retain exact original inputs,
source references, host verification, selected evidence and policy/rule revisions.

Stable episode/finding identities must bind the selected native episode and
rule/policy revision independently of delivery/WAL position. Replays across
intervening events, uncertain commits, restart and policy changes recover the
original outcome and bytes. Atomic journal commits coordinate state, contributing
source frontiers and effect/outbox. Publish original effects before retirement
and source ACK. Verify the exact predecessor as well as revision CAS; history
pruning and generation handoff need explicit protected custody/current authority
and exclusive writer semantics. Retain old authority as data only.

Finding schema already supports several event references. Existing
DerivedFinding::from_events requires all inputs to share canonical
source/account/resource. It must not be bypassed by deriving scope from the first
input, dropping contributors or trusting reserved attributes. A multi-stream
Episode must retain every contributing scope and require the consuming host to
authorize all of them before publication/read. Implement the smallest generic
boundary if needed; do not widen existing grants or change private policy here.

## Acceptance

For each rule: real normalizer composition plus catalog positive/negative/missing
outcomes; same/different identities, native duplicates/conflicts, stream changes,
arrival permutations, exact time boundaries, late/missing/expired coverage,
watermark regression, TTL/capacity/encoded-byte refusal and source/policy mismatch.
Prove cancellation/deadline preservation, immutable originals and stable episode
identities through actual owned process kill or lost-commit recovery, including
intervening inputs and newer policy. Then independent source review and frozen
workspace/default/all-feature, boundary/helper and applicable process gates.
Do not promote local synthetic authority to actual provider/kernel coverage,
current ARM64/CI/image, prolonged operation or release/publication acceptance.

## D11 implementation decisions and remaining lifecycle work

The deterministic selector visits preceding failure anchors newest first within
C, choosing the latest anchor whose inclusive W interval contains N distinct
failures. Select its N most recent failures, ordered by timestamp/native identity.
One episode belongs to each distinct native success; commit its rule/policy,
identity, success and selected native references into stable IDs. Proof order and
newly sealed episode order are normalized. Tied failure/success timestamps cause
a gap when independent ordering is absent. Compare full timestamp precision.

Source positions are contiguous host delivery ordinals for this selected stream,
independent of native producer sequence. Unknown input must consume the next
ordinal; known duplicate redelivery can reuse an old ordinal or consume the next.
The journal delivery checkpoint likewise advances exactly once per Admit; Seal
preserves it. Do not pass unchecked shared-WAL offsets or skip unrelated records
without an explicit processed-prefix disposition in a consuming adapter.
Sealing verification names the exact processed position of every configured
stream, not merely an observed time. Retain the complete all-stream verification
and recompute the scalar watermark on decode. Time frontiers cannot regress.
Every retained proof source is in the episode authorization inventory, including
streams with no selected event; such proofs still contribute to the watermark.

The current draft caps128 original events,256 canonical aliases,64 keys,
64 episodes,8streams,64KiB per input/episode,4MiB state and32MiB complete journal
record; private configuration may select smaller supported bounds. Depth/capacity
and durable late exclusions are available without identity labels. Refusal is
atomic and never erases an older identity. Epoch lifetime/cancellation stays
pinned through predecessor reads and commit. These are implementation limits,
not production scale evidence.

D11 protected retirement is accepted as a local slice in the progress/ledger.
Exact original effect bytes are retained separately
from typed episodes. A drained state can be exported with its complete config,
journal revision/checkpoint, source frontiers, original evidence and effects.
The private host durably publishes original bytes AND complete cumulative indexes
for both canonical aliases and native identities before supplying a receipt.
Publication claims bind exact export, previous root and index digest; lookup
claims bind the exact query, root and both answers. Neither retained proof nor an
archive constructs fresh authority. Expiry/cancellation bounds the whole read/
prepare/commit path, and actual predecessor comparison precedes revision CAS.

Only inactive facts at or before the committed watermark minus TTL are pruned.
Published episodes move into protected custody; bounded completion markers stop
still-active successes/invalid inputs from resealing. Active failures remain
available to later successes. Late-input totals survive reclamation. New hot
aliases retain the lookup proof/query binding; native-known replay with a new UUID
reserves that alias atomically with delivery progress without reintroducing old
facts or renewing coverage. Canonical-only malformed inputs use explicit native
NotApplicable lookup. Missing/partial/expired/prior-root lookup refuses; conflicting
canonical/native witnesses or absent answers contradicting known IDs conflict.

A quiescent policy/key handoff requires all old success/invalid candidates sealed
and the outbox drained. Fresh current custody authority covers the full old export
and cumulative indexes; fresh new source verification covers the exact carried
positions. Source bytes are rechecked before destination commit into an empty,
separately enrolled journal. New active facts start empty with a degraded lookback
floor; original effects and both identity indexes remain available under the
archive root. Reconcile uncertainty before independently activating one generation.
This is a host-owned single-writer protocol, not distributed fencing.

The library supplies mechanism boundaries, not a protected archive/index service,
automatic Main activation or multi-scope publication/read authorization. Test hosts
use actual local files/fsync, SQLite and owned SIGKILL processes with synthetic
source/custody authority. D14 and matching full-item acceptance remain required.

D11 v1 serialization retains the existing dependency-feature profile: sorted
JSON maps in isolated builds, insertion-ordered maps when workspace dependencies
enable `serde_json/preserve_order`. Both pre-refactor byte profiles have immutable
golden fixtures. This refactor preserves each profile; cross-profile archive/state
migration is unsupported and must not be inferred from these compatibility tests.

## D14 hot admission checkpoint — 2026-10-26

RuntimeState now uses the common bounded observation/alias/position engine. Its
schema2 observations retain exact native projection, capture/sequence identity,
operation intervals and the first classification decision or explicit absence.
Native redelivery may add a canonical alias and advance a contiguous delivery
position; it cannot replace the original classification or source proof. Runtime
process identities are counted directly, without authentication keys. Decode
rebuilds native commitments from the original event and treats all retained
proofs as historical data. A present null runtime marker is invalid.

This is a focused prerequisite checkpoint, not D14 acceptance. At this historical checkpoint RuntimeState exposed hot admission/encode/decode/metrics
only and refused imported seals/history pending full source AND policy proof validation. Native capture is retained from
the earlier owned x86_64 cases; these new state tests use synthetic source/policy
authority. Evidence: `target/correlation-d14-20261026/HOT-ADMISSION-CHECKPOINT.json`.
The next slice implements interval-aware deterministic episodes, persisted
all-contributor sealing proofs, then shared journal/outbox/history/carry and
actual crash/lost-commit replay. CORRELATION remains in_progress.

## D14 interval-aware sealing checkpoint — 2026-10-26

RuntimeState now seals through the common lifecycle and persists all runtime
source and proof-only policy frontiers. The minimum frontier minus lateness is
recomputed on decode; exact processed source positions and per-policy monotonicity
are required. Runtime history/custody fields remain refused pending integration.
One assessment anchors each successful socket connect; native Gap is also
visible without a connect. Exec/End and failed connects are not egress anchors.
EOF/failed/socket reads cannot count as protected reads or independently create a gap.

Choose the newest definite classified positive regular-file read for the exact
process/execution identity, ordered by operation exit/native identity/canonical ID.
A newer uncertain or unclassified read cannot hide an older definite match. The
pair requires both original execution and clock continuity proofs; later complete
coverage cannot repair that original uncertainty. Other incomplete provenance
remains an explicit gap on a definite match. NoMatch requires complete lookback;
missing classification, operation uncertainty or capture gaps stay Indeterminate.

Use operation end for sealing and TTL with full precision. A long operation may
have a possible separation within C but exceed conservative whole-interval C;
that relation remains uncertain. Metadata output time cannot establish order or
extend TTL. Protected retirement must also preserve pending connect entry-C
lookback; it is not implemented yet.

Independent focused review,49focused regressions,26workspace-profile checks and
strict rules Clippy/fmt/14boundaries pass. Evidence:
`target/correlation-d14-20261026/SEALING-CHECKPOINT.json`. This does not complete
D14. At that checkpoint, shared journal/outbox, protected history/carry and
whole-item native/crash/review/frozen gates still remained.

## D14 shared journal checkpoint — 2026-10-26

RuntimeAction/recover_runtime/prepare_runtime use the actual runtime enrollment
and share the same predecessor/CAS, original effect/outbox and recovery mechanism
as D11. Preparation and commit preserve caller, epoch, actual runtime-input,
classification-proof and classification-original-input cancellation/deadlines.
An unused replacement decision on a native duplicate has no authority role and
cannot change the first classification or add a new assessment.

A real blocked SQLite predecessor-read test exercises independent classification
cancellation tokens and physical slot retirement. Actual owned SIGKILL cases cut
before seal commit, after durable commit, and after fsynced original publication
before retirement. Reopen recovers exact original effects; a distinct intervening
input and native alias cannot republish them. The host publishes original bytes
before retirement; any uncertain physical mutation must be reconciled against
exact prepared bytes before ACK/retry. A fresh read may recover original results
after old authority expires; it never renews the old commit permit.

Evidence: `target/correlation-d14-20261026/JOURNAL-CHECKPOINT.json`,55focused
regressions,32workspace-profile tests,3actual LinuxAMD64 process kills and
independent focused review. Metadata inputs and private/source/policy authority
are synthetic. This is not native capture composition, current ARM64/CI/images
or whole D14 acceptance. Next: real runtime archive/index custody, protected
retirement with operation-end/pending-connect lookback, quiescent carry, native
journal composition and whole-item review/frozen gates.

## D14 protected history checkpoint — 2026-10-26

The common Authority/Query/Archive/prune/carry path now accepts the real runtime
enrollment. Schema2 retains typed RuntimeConfig and uses distinct archive/namespace
domains; schema and enrollment must agree. D11 v1 field order,bytes and domains
remain unchanged in both supported feature profiles. Runtime namespace pins
partition and actual native source/capture configuration. It deliberately excludes
mutable policy/key revisions so the same cumulative identity indexes remain useful
through an authorized handoff. Changed capture configuration requires a new namespace.

Cold resolution requires fresh complete canonical AND native index answers at
the exact current custody root before any new classification. Missing,negative
and positive original outcomes/effects remain unchanged across native aliases
and key/scope rollover. Old policy scopes remain in original artifacts; new
classification scopes cannot replace their publication/read requirements.

Runtime pruning retains pending connect/Gap candidates and every fact overlapping
their entry-C lookback. TTL uses operation end. Retired facts extend a durable
entry-based degradation floor through end+C; a later long operation cannot turn
pruned evidence into clean NoMatch. Carry requires completed old candidates,
drained outbox,exact source/configuration recheck and empty destination. New
source AND policy proofs cover the carried prefix; active facts start empty with
a floor covering both the watermark and every processed old operation through
newC. This includes facts ahead of a slower source/policy watermark. Original
custody/decision/epoch/input lifetimes remain pinned through all expensive work
and actual source/destination reads and commits. Host quiescence is still required.

Focused independent review,63regressions,40workspace-profile checks and strict
rules Clippy/fmt/14boundaries pass. Evidence:
`target/correlation-d14-20261026/HISTORY-CHECKPOINT.json`. Actual SQLite/blocking
I/O tests use synthetic native projections and private/source/custody authority.
No new history/carry SIGKILL or native composition evidence is implied. Next:
actual native composition through the complete lifecycle,history/index/carry
crash/lost-reply cuts,whole D14 review and frozen acceptance.

## D14 reviewed implementation checkpoint — 2026-10-26

Retained native lifecycle composition now passes21cases/66raw records through
journal, original publication, protected indexes, pruning, key/scope carry and
cold aliases. Three actual owned SIGKILL cuts cover indexed, pruned and carried
state. Original catalog envelopes are preserved in explicit native augmentation;
missing identity links remain Indeterminate. Source/private/custody authority is
synthetic. Raw/process records, capture source/ELFs and the executed test binary
are digest-bound under `target/correlation-d14-20261026/native-lifecycle/`.

Independent mechanism/catalog review and13frozen workspace/helper/process gates
pass1312default/1382all-feature tests. Evidence:
`target/correlation-d14-20261026/whole-qualification/gates.json`. Validation uses
an isolated proposed tree excluding unrelated WINDOW/configuration/presentation
changes. These settled documentation updates follow the frozen runtime campaign.
Whole-item final criteria review now passes; CORRELATION/D14 is passed_simulated.
Final source/evidence bindings and limits: `target/correlation-d14-20261026/ACCEPTANCE.json`.
No current ARM64, CI, image, AWS, production or release qualification is claimed.

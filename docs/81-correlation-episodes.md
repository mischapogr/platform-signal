# Bounded correlation episodes

Implementation contract, not acceptance. CORRELATION is in_progress after STATE;
complete D11 first, then D14. Both rules and their full replay/coverage tests are
required for the ledger item. Existing YAML remains unchanged. Private policy
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

D11 now implements protected retirement, but remains unaccepted until independent
final review and frozen gates. Exact original effect bytes are retained separately
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

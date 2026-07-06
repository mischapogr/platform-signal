# Implementation progress

## Current state — 2026-10-07

Phases 0–7 are implemented and locally verified, including rules, durable
findings, server wiring, the Compose demonstration, edge collection, generic
extension SDK and separate external overlay proof. The full 7-B gates passed on
Linux AMD64. Phase 8 packaging is also implemented and verified locally on
AMD64. Phase 10 hardening campaigns, measured load profiles, an actual storage
create-failure/replay test and release documentation now have local evidence;
final independent review passed with no unresolved findings. The offline restore
addition and native image-to-parser/pipeline runner also passed independent
review. The prior workspace gate had 228 passing tests; the current settled
workspace gate has 300, including 24 SDK SourceCoverage tests and 45 local-store/intake/correction
tests. The preceding source revision's AMD64 image has container, Helm, supply-chain and native
qualification evidence. The new local kind campaign is blocked by kube-proxy
resource exhaustion before the application starts; the preceding image retains
its passing kind evidence. The native CI matrix
records measured campaigns and retains their reports. Native ARM64, EKS, remote CI,
released dependencies and the complete v0.1.0 qualification remain outstanding.
Phase 9 AWS work remains post-MVP. The 2026-10-07 dev0 candidate preview also
passed local offline-integrity, relocation/source-path-graph and packaged-chart
checks; it does not change release readiness. See
[unpublished candidate preparation](23-local-candidate.md).
Use `04-implementation-plan.md` for phase order and `06-definition-of-done.md`
for the full release gate.

The workspace has ten library crates and three apps at `0.1.0-dev.0`, licensed
Apache-2.0. `signal-server` accepts authenticated single/batch HTTP events into a
bounded synced WAL, coalesces bounded Parquet batches, and checkpoints only after
event storage, rule evaluation and required finding persistence complete.
Replay verifies stored sequence content. Health/readiness and
Prometheus metrics include WAL and storage limits. `GET /v1/events` queries
persisted data; `GET /v1/findings` returns durable rule findings. The Phase 6
`signal-agent` durably spools bounded stdin/file events and forwards verified
HTTP admission prefixes; its delivery is at least once.

Run `cargo run -p signal-server`; see [HTTP examples](09-phase1-ingest.md),
[WAL configuration](10-phase2-wal.md), [storage configuration](12-phase3-storage.md),
and [query configuration](13-phase4-query.md).

## Ingestion architecture audit — 2026-10-07

The owner-requested [audit](26-ingestion-architecture-audit.md) compares the
implemented baseline `dd4a1cd` with AWS-native, EKS, SaaS and site syslog ingestion.
It retains four operational roles and the monolith, prioritizes durable source
receipts/checkpoints, scoped publisher identity and protected originals, and
preserves the v1 envelope. Vendor documentation corrections include Firehose's
distinct HTTP protocol, Microsoft 365 API selection, NLB TLS coverage and Cato's
finite marker horizon. Cloudflare remains in the source inventory.

Overview status is corrected for the implemented coverage intake/retry/correction
library; pruning/scans/observers remain open. Proposed post-MVP order starts with
CloudTrail S3/SQS and source receipts, then selected CloudWatch/EKS profiles, site
syslog and SaaS. Immediate implementation remains bounded payload-prefix pruning.

Documentation acceptance: 13-package boundary guard; catalog structural guard
(15 requirements, seven profiles, 45 cases, five native predicates); shared vendor
fixtures (11 families, 55 cases, seven negative guards); Markdown links and diff
whitespace. Retained 300-test Rust evidence was inspected, not rerun for this
documentation-only task. No new runtime, cloud, release or private-overlay proof
is claimed. Evidence and single-writer review:
`target/ingestion-architecture-audit-20261007/`.

## SourceCoverage bounded correction admission — 2026-10-07

PS-01 now admits one immutable `correction_of` link through the existing worker.
The new assertion must pass normal validation/authority/age policy. Its direct
target must already be committed with available original evidence under the same
full binding/observer. Half-open intervals must overlap and verification must be
strictly later, with nanosecond precision. Self, missing/future, unavailable or
cross-binding targets reject before mutation. Target expiry alone permits a new
correction while original bytes remain available. No source/backfill proof is
authenticated by these checks.

The new report, immutable link, receipt and accounting commit together under the
existing prefix encoding. Earlier failed/unknown evidence and receipts remain
unchanged. Only the direct target is inspected; a correction of a correction never
traverses ancestors. Retained correction replay preserves its original link and
receipt without rechecking target availability, renewing deadlines or allocating
sequence. The store does not resolve corrections into current health.

All 45 focused library tests and 300 workspace tests pass locally on Linux AMD64,
plus formatting, strict all-target Clippy and the 13-package boundary guard.
Fourteen additional regressions cover actual frozen correction-chain admission,
all ten target-binding dimensions, half-open/later-verification nanoseconds,
self/missing/future references, quotas/concurrent duplicate admission, target/link
corruption, queued cancellation and SIGKILL after row insertion, before commit and
after commit with response loss. Recovery preserves complete links and original
bytes; lost-response replay keeps the receipt. A manually constructed pre-pruned
persisted fixture rejects new links to unavailable payloads while allowing retained
correction replay and one-hop links to an available correction. It does not test
an implemented pruning operation or physical power loss.

One boundary fixture initially put verification one nanosecond beyond observation;
its observation is now aligned with the existing SDK contract. No dependencies,
database schema, event model or frozen codecs changed. One-writer review covers
all 14 areas; no independent review is claimed. Evidence, actual October 7 times,
usage and handoff: `target/source-coverage-corrections-20261007/`. The authorized
local Conventional Commit on `develop` assigns both Git dates July 7 21:15 Berlin,
fifteen minutes after the intake commit. Private overlay and `0.1.0-dev.0` versions
remain unchanged; no push, main merge, tag or publication follows.

Next implement bounded payload-prefix pruning, then identity pruning and frontier
scans as separate slices. The complete 56 planned outcomes, credentials/source
observers/current-health supervision and cloud/server wiring remain unqualified.
Earlier image/candidate evidence still binds its own source revision. Current kind,
native ARM64, actual EKS, remote CI, released dependencies and publication remain
open.

## SourceCoverage trusted intake and original-receipt replay — 2026-10-07

The next PS-01 library slice adds `submit`, `retry` and `get_authorized` to the
existing bounded SQLite worker. An application supplies a fresh grant only after
authenticating the observer and authorizing the complete binding. The library
checks the original full binding before disclosing retained bytes or receipts;
it provides no credential/revocation service. Low-level prepared append/inspection
remain trusted primitives. No server, agent, collector or private overlay is wired
to this store.

New assertions enforce observed-time admission age and configured/profile skew.
Finite unsigned-second retention durations receive fixed checked deadlines with
nanosecond precision. Fresh reports about expired verification and valid failed,
partial, unknown or unsupported assertions remain historical evidence. Retained
identical bytes/link replay the original receipt even with a retired profile or
full new-write quota; changed bytes conflict. Receipts cannot renew sequence,
deadlines, verification or clock floor. Backward receiver time rejects intake;
authorized historical reads remain available. Explicit retry rejects missing or
divergent history, positions, prefixes or immutable metadata instead of admitting
the record again. New `replayed` and existing rejection counters distinguish these
outcomes without deriving current source health.

All 31 focused tests and 286 workspace tests pass locally on Linux AMD64, along
with formatting, strict all-target Clippy and the 13-package boundary guard.
Thirteen new real-SQLite regressions cover all ten binding dimensions, exact-byte
receipt roundtrip, concurrent duplicate admission, quota/restart, retired/conflicting
profiles, nongreen history, age/skew/deadline nanoseconds, receiver regression,
policy overflow and missing/divergent references. The existing SIGKILL test now
replays the recovered lost-response receipt; queued cancellation exercises intake.
Frozen encodings, root build inputs and dependency graph remain unchanged.
One-writer review covers all 14 areas; it is not independent review.

The restricted workspace attempt failed on existing local socket/stream tests;
the permitted local rerun passes. Workspace feature unification exposed an
ambiguous compact-JSON test fixture; explicitly changed formatting now guarantees
the intended byte conflict. Review also ensures rejected preflight receipts are
counted. Evidence, actual October 7 times, usage and handoff:
`target/source-coverage-intake-20261007/`. One local Conventional Commit on
`develop` uses both deliberately assigned July 7 21:00 Berlin Git dates, following
the private commit by fifteen minutes. Push, main merge, tag and publication remain
separate.

At that acceptance, correction admission was next; prefix pruning and frontier scans follow as separate
bounded tasks. The complete 56 planned history outcomes are not qualified. Source
observers, current-health supervision, credentials, protected S3 evidence and cloud
wiring remain separate. Prior image/candidate reports bind their earlier source
revision and remain historical; this host-library acceptance does not refresh them.
Current kind, native ARM64, actual EKS, remote CI, released-dependency and publication
gates remain open. Versions remain `0.1.0-dev.0` in both public and private packages.

## Vendor fixtures and current-source release refresh — 2026-10-07

The [public synthetic corpus](../examples/logs/README.md) contains 55 native and
canonical reference records across CloudTrail, CloudWatch, RDS, ALB, NLB, EKS,
ECS, Cloudflare, Microsoft 365, Cato VPN and FortiGate. Each family has five cases
including benign and security scenarios. Log severity is separate from illustrative
finding severity. Hash/native-envelope/aggregate checks and seven negative guards
pass. The private application aligns with `0.1.0-dev.0`; formatting, strict Clippy,
three tests and the CLI pass. Its new test deserializes/validates all 55 events,
preserves evidence during enrichment and verifies one intended private IAM finding.
This is sibling-source proof; no live vendor adapters or released dependency are
qualified. Cato field/subtype values require tenant schema confirmation.

The current-source AMD64 image is
`sha256:59fc118e167047e8c4287c35581b581a1d5444b9db1ff70b918b912819fba8b9`.
Container auth/health/restart/replay and cleanup pass. All six supply-chain gates
pass: 341 locked Cargo packages and 15 image packages inventoried, zero RustSec
vulnerabilities and zero HIGH/CRITICAL image occurrences; 23 MEDIUM and eight LOW
remain. Native host/daemon/image/ELF checks, nine parser/property cases, seven
pipeline profiles and both 120-second 1 KiB/4 KiB soaks pass. They are finite local
AMD64 measurements. The coverage SQLite library is not linked into `signal-server`;
its 18 host-library tests are distinct from image-runtime proof.

Three fresh kind attempts fail at Helm installation with an unbound PVC. Retained
diagnostics identify kube-proxy startup failure (`failed complete: too many open
files`) and the provisioner's resulting API connection timeout. SIGNAL never
starts in those attempts. One further disposable infrastructure diagnosis confirms
the same kube-proxy error; all owned clusters are removed. No host sysctl, shared
cluster or network setting was changed. The current kind gate remains open;
preceding-image kind evidence is historical. The helper now retains bounded,
redacted failure diagnostics; all five helper regressions pass.

Source export now supports the current 13-package graph and includes all six
compile-time/public contract JSON files and only the explicitly named public
vendor corpus files. Twenty-one candidate regressions pass, including historical
12-package support, missing compile-time fixture rejection and one-image Docker
inspection-array normalization. A real export attempt exposed the latter report
shape mismatch; it was corrected and the failed output retained. An actual exported
source tree passed offline metadata, three contract/catalog guards and all 53
SDK/store tests. Runtime/build inputs still match the accepted 273-test workspace
result, reused here rather than repeated after tooling/data changes.

Evidence: `target/release-gates-20261007/` and
`target/vendor-samples-20261007/`. GitHub CLI is unauthenticated and the remote
head read returns no advertised branches. No CI execution is claimed. The owner
explicitly authorized local Conventional Commits on `develop`, with both Git dates
assigned July 7 evening Berlin time at fifteen-minute intervals. Actual evidence
times remain October 7. Public/private histories remain separate; no push, main
merge, tag, release selection or publication is authorized by those commits.
Native ARM64, actual EKS, current kind, remote CI, released dependencies and
publication remain open. Next restore the local kind host-resource preconditions
without affecting concurrent workloads, then rerun that gate; external gates
need their respective runner/environment/credentials and authority.

## SourceCoverage local library slice — 2026-10-07

PS-01's [`signal-coverage`](../crates/signal-coverage/README.md) implements the
bounded persistence slice selected by [ADR-015](adr/015-source-coverage-store.md).
Explicit initialization creates a private root and stable identity; open requires
established files and checks exact schema, pins, original bytes, prefix, anchors
and accounting. One ordinary SQLite worker holds root ownership through physical
exit. Atomic prepared append commits profile/binding pins, original report,
receipt metadata and state together. Trusted one-row inspection cross-checks
references, bytes, semantics and the local prefix link.

The workspace locks `rusqlite` 0.40.2 with bundled/limits/hooks,
`libsqlite3-sys` 0.38.2 (SQLite 3.53.2) and `sha2` 0.11.0. Every open verifies
DELETE/EXTRA, 4096-byte pages, foreign keys, cache-spill/mmap/temp/VM settings and
finite page limits. Count/key/pin/ledger, journal reserve, operation slots, worker
memory allowance, VM steps and deadlines are explicit finite limits. They do not
establish physical disk or whole-process RSS guarantees. Cancellation before
mutation prevents it from starting; uncertain active work closes admission and
retains its slot/lock until it settles. Shutdown cannot kill a blocked syscall.

All 18 focused tests pass, including unchanged frozen vectors, initialized/missing
root behavior, profile/ID/clock rejection, reduced caps, actual SQLite page
exhaustion, eight corruption/path cases, live prefix damage, closed relocation
and worker cancellation races. A subprocess is killed after entry insertion,
before commit and after commit with the response lost; acknowledged bytes and
receipts survive, and recovery selects the complete transaction prefix. This
tests process loss, not device power loss. Bundled build options/source ID and
amalgamation hash are retained; pinned Unix-VFS/pager source review and observed
journal bounds are limited local evidence. VFS write/sync failure injection and
deployment storage qualification remain open.

Formatting, strict all-target Clippy and all 273 workspace tests pass locally on
Linux AMD64. The boundary guard validates 13 packages; SDK/agent/server remain
free of coverage-store dependencies. Existing coverage/catalog/reference guards
pass. The 65 baseline Rust source/build inputs and frozen vector fixture remain
unchanged. Focused self-review covered all 14 areas and corrected cancellation
arbitration/ownership, control-wake capacity, receipt size/boxing, read corruption
checks and bounded deadline arithmetic. This is one writer's review, not
independent review. New dependencies/build inputs require refreshed image,
supply-chain and native qualification; prior campaigns remain historical.

Evidence is retained in `target/source-coverage-store-20261007/`, including task,
validation, dependency build, review, usage and handoff records. At that acceptance,
the next item was to implement
trusted local intake/authorization, checked report-age/retention policy and exact
original-byte receipt replay without renewing deadlines or sequence. Correction
admission, prefix pruning and scans are separate tasks. The 56 history outcomes
remain planned; this library adds no observer, endpoint, source/cloud integration,
current-health claim or service split. At this slice acceptance the work was
unstaged/uncommitted; the subsequent owner authorization permits local commits
on `develop`, while push, main merge, tag and publication remain separate.

## SourceCoverage backend/encoding decision — 2026-10-07

PS-01's [ADR-015](adr/015-source-coverage-store.md) selects SQLite through bundled
`rusqlite` on one ordinary worker. It specifies rollback-journal `DELETE` with
`EXTRA` synchronization, explicit private-root initialization/ownership, atomic
append and pruning, fixed original receipts, and bounded recovery/accounting.
It freezes domain-separated canonical profile/binding/commit/prefix/state bytes,
the persistent identity sidecar, and 8-byte BLOB sequences spanning unsigned u64.
The SDK remains pure. This decision's handoff selected the library slice now
implemented and recorded above.

[Frozen vectors](../tests/fixtures/source-coverage/backend-vectors.json) cover
three profiles, five bindings, three chains/five chained commits, two standalone
unsigned/calendar boundary commits, four times, three states and one identity.
The [reference checker](../scripts/check-source-coverage-backend.py) passes all
vectors, 33 rejection guards and four relationship checks. Its bounded Python/
system-SQLite 3.45.1 projection passes 13 mechanics checks: controlled SIGKILL
before/after commit and during prefix pruning, surviving anchors/frontiers,
page-cap rejection, transaction/OS lock contention, unsigned BLOB ordering and
closed-database relocation. These are real local SQLite operations, not the Rust
store, trusted intake, receipt-policy runtime or the 56 planned history outcomes.
Device power loss, VFS journal-reserve geometry, native ARM64 and complete worker
cancellation/lifetime ownership still require implementation qualification.

Offline SourceCoverage/catalog checks, the 12-package boundary guard, helper
syntax/CLI checks and owned Markdown links pass. All 67 Rust source/build inputs
match this task's baseline; Cargo is not rerun and the prior 255-test result
remains scoped to the pure validator. Focused self-review covered 14 areas;
corrections include sidecar/missing-store behavior, exact byte/profile encoding,
unsigned positions, conservative active-journal reserves and evidence scope.
This is one writer's review, not independent review or release qualification.

Evidence is retained in `target/source-coverage-backend-20261007/`, including
`backend-acceptance.json`, task/validation/review/handoff records and usage.
At this design acceptance, no Rust store, new endpoint, observer, source/cloud
integration or service split was added. The selected library implementation is
recorded above; intake/retry, pruning and scans remain separate. All new work
remains unstaged/uncommitted on `develop`; no push or `main` merge.

## SourceCoverage intake/history contract — 2026-10-07

PS-01's [bounded intake/history contract](source-coverage-history-contract.md) is
written with [linked fixtures](../tests/fixtures/source-coverage/history.json).
It defines exact raw-byte submission identity, original receipt replay, immutable
profile pins/correction links, finite payload/identity horizons, count/key/byte
reserves, explicit pruning/unavailable evidence, bounded prefix-aware scans,
commit uncertainty, restart/restore and single-writer ownership. It keeps receipt
durability separate from current source health, source proofs and M2/M3/M4.

Offline acceptance passes 16 requirement links, 12 candidate encodings, 56 planned
history cases and 24 rejection guards. Guards reject false runtime/prefix-vector
claims, replay renewal, guaranteed rollback for uncertain commits, invalid quotas,
receipt/hash/retention mismatches and broken references. Focused self-review covered
all 14 areas, correcting uncertainty expectations and requiring retained profile
fingerprints. No history state machine, disk sync, process crash or prefix vector
was executed. The pure validator's Rust files/build inputs are unchanged; retained
255-test workspace evidence remains scoped to that earlier implementation.

The structural coverage/catalog checks and 12-package boundary guard pass.
Evidence is retained under `target/source-coverage-history-contract-20261007/`,
including input hashes, mutation checks, focused self-review, usage and handoff.
That handoff selected the local backend/format ADR recorded above, with runnable
atomicity/quota/pruning/ownership and prefix/fingerprint golden-vector acceptance.
No observer/store/server/API/cloud integration was implemented. Work remains
unstaged/uncommitted on `develop`; no additional commits, push or `main` merge.

## SourceCoverage validator and local Git baseline — 2026-10-07

PS-01's pure validator/assessment is implemented in
[`signal-collector-sdk::coverage`](../crates/signal-collector-sdk/src/coverage.rs).
It admits at most 65,536 raw UTF-8 bytes, rejects duplicate/unknown keys and
missing required nullable fields, validates calendar/UUID/text/profile bounds,
preserves nanosecond time comparisons and checks gaps/summary/proof/checkpoint
consistency. Exact trusted bindings, observer identity, future-clock guards,
current expiry/health and historical interval semantics follow the
[v1 contract](source-coverage-contract.md). Rejected input cannot become verified.

The 24 new integration tests execute all 60 record cases (21 valid/21 semantic
rejects/18 structural rejects), 39 assessments and seven pure transition sequences,
plus boundary regressions. Final fmt, strict workspace/all-target Clippy,
locked workspace build, 255 workspace tests (40 result lines, zero failures),
offline structural/catalog checks and 12-package guard pass on local Linux AMD64.
The first workspace run was blocked by sandbox socket permissions; the permitted
local rerun passed. Focused self-review covered all 14 review areas and corrected
missing-profile guard precedence. This was one writer, not independent review.

There is no new dependency, event field, observer, durable coverage store, source
adapter, server endpoint or detection wiring. Image/native qualification below
belongs to the preceding baseline; no new image or external qualification ran.
That handoff selected a bounded coverage intake/history contract for immutable
IDs/retries, content conflicts, cardinality, retention, expiry and ownership;
the contract is accepted offline above, with storage implementation still separate.

The owner authorized development on `develop` and local baseline commits. `origin`
already targets `git@github.com:mischapogr/platform-signal.git`; a successful remote
head check found no branches. Three baseline commits were created:
`b43cede` (pipeline), `e56985f` (tooling), `8d705d2` (security contracts).
At the owner's request, author/committer metadata is 2026-07-07 19:00, 19:15 and
19:30 Europe/Berlin (+02:00). Actual validation occurred on 2026-10-07.
The new validator and documentation remain unstaged/uncommitted; the index is
empty. Nothing was pushed, merged to `main`, tagged or published. The version
remains `0.1.0-dev.0`, with release gates still open.

Evidence: `target/source-coverage-validator-20261007/` holds logs, input hashes,
baseline path manifests/commit metadata, focused review, usage and handoff.

## SourceCoverage contract — 2026-10-07

PS-01's [formal SourceCoverage contract](source-coverage-contract.md) defines
standalone record/profile JSON schemas, precise interval/expiry/binding semantics,
component reduction, bounded gaps and recovery history. It adds generic synthetic
fixtures without modifying the server or existing event envelope.

Offline acceptance: two profiles, 60 record cases (42 structural accepts and 18
intentional rejects), 39 planned assessment cases and seven linked transition
sequences. Twenty-one structural accepts are intentionally expected to fail
semantic validation. The checker tests only its owned structural keyword subset;
semantic assessments, cryptographic source proofs and a running observer are not
qualified. The existing 15-detection catalog and 12-package boundary guard pass.
No Rust/build inputs changed; the earlier 231-test workspace result is unchanged.

Evidence lives under `target/source-coverage-contract-20261007/`, with input hashes,
structural/guard/document checks, focused review, usage and handoff. The next
locally selected task was the bounded semantic validator/assessment function,
accepted above. This earlier contract evidence remains historical.
Source observer/storage/adapters and external ARM64/EKS/CI/released-dependency
qualification remain separate; nothing was staged, committed or provisioned.

## Security requirements design — 2026-10-07

The owner-requested [source/detection catalog](source-detection-catalog.md),
[logical architecture](logical-architecture.md) and
[failure-domain contract](failure-domains.md) are written. They define 15 generic
requirements across five evidence domains, SourceCoverage semantics, independent
protected evidence, acknowledgement milestones M0–M7, failure domains F1–F7 and
bounded critical-stream/HA assumptions. MVP scope and the PS-01–PS-06 roadmap
preserve one server process and the existing release gates. Company approvals,
account topology, operational policy and real telemetry remain private.

Local design acceptance validates seven source profiles and 45 synthetic fixture
cases. Five native predicate rules ran against the existing Linux AMD64 server:
15 normalized events persisted with exactly five findings, preserved through
SIGKILL/restart and clean SIGTERM. The catalog's 30 window/state/correlation
cases are future contracts, not runtime passes; even the predicate missing-data
cases do not qualify coverage-aware assessments. No raw source collector,
SourceCoverage runtime, independent S3 evidence, protected reserve, findings feed,
notification or new service was implemented.

Retained evidence: `target/security-architecture-20261007/`, including the task
packet, runtime reports, focused review, document checks, usage snapshots and
handoff. This is design/synthetic acceptance, not a new Rust phase or release;
the settled workspace test count remains 231. That design handoff selected
PS-01's SourceCoverage schema/fixture contract, accepted above. ARM64/EKS/remote CI/released
dependencies and publication remain open; no staging or commits occurred.

## Phase 8 local evidence — 2026-10-06

Production packaging, public Helm chart, native AMD64 runtime, owned local kind
cluster and supply-chain checks passed. See [packaging](19-packaging.md),
[SBOM/scans](18-supply-chain.md) and [ADR-014](adr/014-packaging.md).

| Check | Result |
| --- | --- |
| Initial image | Fresh locked Rust release build: 7m46s; image `cbf2746cf81fe6aced3c0627df9d1f483a24b0171d7b6a3dddd97b10ee39c745`. Native container gate passed; security policy failed with 65 HIGH and 4 CRITICAL occurrences (25 distinct IDs). Earlier evidence retained. |
| Runtime remediation | Verified pinned distroless Debian 13 C++ image replaces Debian 12 shell/package manager/curl. Cached application build reused; bounded standalone Rust probe compiled. `/tmp/signal-phase8-remediated-build.log`, session 29346 exited 0. |
| Qualified image | `sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97`; native Linux AMD64. |
| Native container | `/tmp/signal-phase8-remediated-container-gate.log`, session 58309 exited 0. Nonroot 65532, read-only root/config/rules, writable owned data, dropped capabilities, no privilege escalation, 1 GiB/2 CPU/128 PID bounds, healthy probe, server+agent version checks. One event/finding survived SIGTERM, SIGKILL and authenticated restart. Owned Compose resources removed. Agent collection is qualified separately by Phase 6. |
| Helm | Strict default/optional/private-values lint and render passed with Helm 3.19.0. Schema/template reject multiple writers, invalid rule keys and unsupported values. All 12 rendered Count fields are plain decimal integers. |
| Local Kubernetes | Owner-selected local Kubernetes milestone completed: `/tmp/signal-phase8-kubernetes-gate.log`, session 23358 exited 0. kind 0.30.0 and kubectl 1.34.0, pinned Kubernetes 1.34 node image. Actual external local Helm values used. CRI identity matches qualified image. One canonical event/finding persisted through container SIGKILL and stop/wait/replacement on the same PVC. Auth 401/202, separate metrics, nonroot/read-only and owned cluster cleanup passed. This is local kind evidence, not actual EKS/AWS storage/runtime qualification. |
| Concrete chart corrections | Actual startup rejected ConfigMap symlink projections, fixed with read-only regular subPath config/rule files; scientific numeric interpolation rejected by strict Count parser, fixed with decimal int64 rendering. Initial failed cluster logs retained; strict core loaders unchanged. |
| Regressions | Two standalone Rust TCP health tests (including trickled absolute deadline); three Python Kubernetes cleanup tests pass. CI runs both groups explicitly. |
| Fresh security report | `target/supply-chain/reports/20261006T184541.680363Z/`, session 46933 exited 0. Cargo audit: 327 dependencies, zero vulnerabilities. Cargo SPDX 328 packages; image SPDX 15 packages. Trivy: HIGH 0, CRITICAL 0, MEDIUM 23, LOW 8; all severities retained and no ignored advisories. Database updated 2026-10-06T13:07:05.606377799Z. |
| CI source | Native AMD64/ARM64 jobs build once per architecture, run container/kind/scanners, preserve reports; pinned tool checksums/actions. Cached Actionlint 1.7.7 exited 0. Jobs have not run remotely under the no-commit/no-push instruction. |
| Independent review | All 14 areas reviewed; image selection and cleanup findings fixed. Runtime/probe and regular-file/decimal rendering corrections reviewed. Final container/scan identities reconciled; no unresolved source finding. |

Actual native ARM64 and EKS execution remain unavailable. EKS deployment needs
an authorized environment and private values; no cloud resources were created.
Image/report digests are unsigned local evidence, not registry publication or
SLSA attestations. Medium/low findings and scanner coverage limits remain visible.
Local packaging implementation is accepted for continuation into Phase 10;
external architecture/cloud/release qualification remains open.

## Phase 7 progress — 2026-10-06

Phase 7-A `signal-collector-sdk` is locally complete on Linux AMD64. The root
gate passed build, formatting, Clippy, workspace tests, and the package-boundary
check after correcting the existing WAL `BlockWithTimeout` near-deadline bug.
The SDK source and final 14-area review approved the implementation with no
unresolved blocker, high, medium, or low findings. See the [Collector and
Enricher SDK contract](16-collector-sdk.md) and [ADR-013](adr/013-extension-sdk.md).

| Check | Result |
| --- | --- |
| Phase 7-A root gate log | `/tmp/signal-phase7-final-gates.log`; session 86552 exited 0 |
| `cargo build --workspace --locked` | Passed |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 212 tests, 0 failures, parsed from 34 test-result lines |
| `python3 scripts/check-workspace.py` | Passed: 12 packages and dependency/source boundaries |
| Test scope | Phase 7-A root evidence: previous Phase 6 coverage retained (203 tests, including 36 agent library tests and 1 agent process test); six SDK public integration tests; `signal-buffer` 26 tests (7 unit, 19 recovery, including 3 new deterministic regressions); `signal-server` 21 tests including 4 process cases, 11.12 s; current agent process case, 4.66 s. See the separate Phase 7-B result below for the updated workspace count. |
| Independent review | SDK source and final 14-area review approved; no unresolved blocker/high/medium/low finding |

The workspace failure was reproduced deterministically as a full-queue
`BlockWithTimeout` append self-notifying near its deadline and returning
`Unavailable`. The fix separates durable-occupancy and command-slot waiters:
durable-space wakeups follow an actual occupancy decrease on ack/reclaim;
command-space wakeups follow actual dequeue and normal operation-permit
release. Failed enqueue suppresses its own permit notification; closure/failure
wakes both waiter sets. Three deterministic regression cases now pass. When
physical mutation status is uncertain, the operation fails closed and leaves
the queue unchanged.

Phase 7-B implementation uses the separate
`platform-signal-private/overlays/example` checkout. Provider schemas, metadata,
rules, expected outputs and fixtures remain in that repository. The generic
external gate is documented in [03](03-demo-company-overlay.md) and
[17](17-external-overlay.md); it exercises the private runner with the normal
OSS server and checks persistence across forced restart.

| Phase 7-B check | Result |
| --- | --- |
| OSS workspace | `/tmp/signal-phase7b-workspace-gates.log`; session 63476 exited 0. Build, format, strict Clippy, workspace tests and package/source boundaries passed; 217 tests, 0 failures, 35 result lines. SDK coverage is 11 tests (six earlier tests plus five provider tests). |
| Private package | `/tmp/signal-phase7b-private-gates.log`; session 97021 exited 0. Build, format, strict Clippy and tests passed: 2 tests, 0 failures, 4 result lines. The separate package has one reader-retention unit test and one multi-assertion integration test. |
| External normal-server gate | `python3 scripts/check-overlay.py --runner ../platform-signal-private/target/debug/platform-signal-private --overlay ../platform-signal-private/overlays/example` passed in 0.55 seconds; one event and one finding survived SIGKILL recovery, then SIGTERM shutdown succeeded. Log: `/tmp/signal-phase7b-process-gate.log`. |
| Repository/dependency boundary | Private package is in a separate Git repository; its four OSS dependencies resolve through the documented relative paths. Both Git indexes were empty and both repositories had zero commits at verification. |
| Independent review | Final 14-area source review found no unresolved blocker, high, medium or low findings. A reviewer also verified bounded output with a 20+ KiB unread-pipe payload: the CLI exited 1 in 0.314 seconds. |

Phase 7 is complete as local Linux AMD64 mechanism and source-path proof.
This Phase 7 result establishes source-path compatibility. Subsequent Helm and
local Kubernetes proof is recorded under Phase 8 above; released dependencies,
EKS, native ARM64 and full `v0.1.0` qualification remain open.

## Phase 6 evidence — 2026-10-06

Implemented scope: Linux stdin and regular-file collection, JSON/plain parsing,
bounded source cursors, a CRC-framed durable spool, quota-aware backpressure,
verified partial HTTP admission and retry, optional bounded metrics, token
redaction, and deadline-based shutdown. See the [Phase 6 contract](15-phase6-agent.md)
and [ADR-012](adr/012-agent-spool.md).

| Check | Result |
| --- | --- |
| `cargo build --workspace --locked` | Passed |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 203 tests, including 36 agent library tests (19 spool, 7 input, 8 HTTP, 1 config, 1 runtime) and 1 agent process test; prior 166-test workspace coverage retained |
| `python3 scripts/check-workspace.py` | Passed: 12 packages and dependency/source boundaries |
| Agent process gate | Passed offline in 4.61 s on Linux AMD64. Covered spool quota and SIGKILL recovery through the 13th append; authentication and token redaction; across spool quota, one server-accepted event and one canonical oversize rejection without rereading; stdin large integers; file partial lines, rename rotation, copy-truncate, idle follow, SIGTERM and server restart |
| Spool directory bootstrap | New spool directory uses mode 0700. Initial bootstrap syncs the bounded parent chain (at most 128 components / 4,096 bytes), including pre-existing empty ancestor directories, before state publication |
| Independent review | Final 14-area review closed all high findings and approved the source |

These results establish local Linux AMD64 behavior only. ARM64, process RSS,
an agent container build, and actual power-loss tests were not run. Source-ordering
checks are not power-loss proof. The successful local gate does not complete the
full `v0.1.0` release gate or the external Phase 7 overlay proof.

## Phase 5 evidence — 2026-10-06

Implemented scope: strict schema-versioned configuration, bounded rule loading,
stateless rule matching, stream-bound durable findings, integrated
persist/evaluate/findings-before-WAL-ack pipeline, findings HTTP API,
coordinated shutdown, optional separate metrics listener and bounded structured
stderr logging. See [Phase 5 contract](14-phase5-core.md) and
[ADR-011](adr/011-rules-findings.md).

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed after final rule-limit correction |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed after final rule-limit correction |
| `cargo test --workspace` | Passed: 166 tests (23 buffer, 10 event, 16 findings, 15 ingest, 11 protocol, 29 query, 9 rules, 31 storage, 21 server/process, 1 doctest) |
| `python3 scripts/check-workspace.py` | Passed: 12 packages and dependency/source boundaries |
| Real process/restart gate | Passed after final correction in 3.58 s; five canonical events, four findings, query/findings auth and filters, config/rule validation, secret redaction, SIGKILL replay and SIGTERM drain, fail-closed finding-quota behavior, and no early WAL ack |
| Fresh production image | Built successfully in 6m54s from Rust 1.94.1 bookworm / Debian runtime, Linux AMD64; image ID `1520e56ee38fa4c670eb87a3674cd6610de79ccde1b56550ac7a481ee07bc6ae` |
| Compose harness | Passed `python3 scripts/check-compose.py`: ingest/query/findings, SIGTERM and SIGKILL restart, optional authentication, large integers/nanosecond timestamps, metrics listener isolation, security settings, bounded/redacted logs, and resource cleanup |
| Independent review | 14-area review and Phase 5 source approval reported no open blocker/high; independent Compose harness review closed identified gaps |

These gates prove local Linux AMD64 behavior only. They do not qualify ARM64,
remote CI, power-loss behavior, throughput or process RSS, and do not complete
the v0.1.0 release gate. One full workspace rerun during Docker LTO build load
hit a time-sensitive buffer test; a targeted rerun and the subsequent full
workspace rerun without build load passed. No root cause is claimed for that
transient failure.

## Phase 4 evidence — 2026-10-06

- 04-A: URL validation/contracts and shared attribute lookup completed.
- 04-B/C: DataFusion queries and resource/cancellation bounds completed;
  validated manifest file selection uses the storage seam.
- 04-D: HTTP integration and real query/restart fixtures completed.
- Dependency lock, shared metrics and phase evidence completed; a separate Sol
  high reviewer completed the 14-area review.

DataFusion is pinned to 55.1.0 with Parquet/string features and compatible Arrow
59 components. Phase 4 is accepted locally after its implementation, workspace
gates, real-process gate and independent review.

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 127 tests (23 buffer, 10 event, 15 ingest, 11 protocol, 28 query, 31 storage, 8 server/process, 1 doctest) |
| `python3 scripts/check-workspace.py` | Passed: 12 packages and dependency/source boundaries |
| Real query process gate | Four canonical events; authentication, filters, ordering and limit verified; response resource limit returned 413; SIGKILL/restart retained and re-served persisted query results |
| Independent review | Separate Sol high reviewed 14 areas; no new blocker/high/medium/low finding |

After the full workspace run, a wrapped physical-I/O capacity error was corrected
to classify as query saturation (429), with byte/listing resource errors kept at
413. Post-fix `cargo test -p signal-query` passed 29 tests (15 unit, 14
integration), and targeted Clippy passed with warnings denied. The 127-test
aggregate predates that focused correction; no aggregate count is claimed after
the correction while Phase 5 source work is in flight.

The synchronous stderr writer medium inherited from Phase 1 was addressed in
Phase 5 with bounded logging. Phase 4 does not establish throughput, process RSS
ceiling, ARM64, container, power-loss or production qualification.

## Phase 3 evidence — 2026-10-06

Implemented scope: Arrow/Parquet v1 codec, replaceable `EventStore` and shared
filter seam, bounded locked filesystem worker, date/hour files and immutable
commit manifests, stream-bound content-checked replay, storage quotas/metrics,
coalescing consumer, persist-before-ack and one shutdown deadline. The WAL now
publishes its UUID atomically and reserves 128 metadata bytes. Direct Arrow and
Parquet are 59.2.0; compatible Arrow components resolve to 59.3.0. DataFusion
55.1.0 is selected for Phase 4 and remains absent from this phase's runtime.

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 80 tests (23 buffer, 8 event, 15 ingest, 26 storage, 7 server/process, 1 documentation) |
| `python3 scripts/check-workspace.py` | Passed: 12 packages and dependency/source boundaries |
| Canonical storage codec | 7 tests: nested/exact large numbers, nulls/optional resources, correlation, negative epochs, years 0000/9999, leap seconds, nanoseconds; corrupt versions/schema/projections rejected |
| Real filesystem storage | 16 tests: all three codecs, UTC partitions, restart, changed replay batch boundaries, content conflict and sequence gaps, byte/entry quotas, ownership/lock/symlink checks, orphan/partial quota publications |
| Resource/cancellation failure cases | 3 bounded-worker tests plus 4 pre-allocation regressions within the filesystem tests: forged footer lists, schema child counts, compressed columns and page headers |
| Consumer/recovery ordering | Storage quota never acks; restart after publish before ack keeps exact rows without duplicates; drop_oldest interleaving does not ack newer events; partial batches coalesce and flush on drain |
| Shared shutdown budget | Stalled consumer with a 50 ms deadline returns within 300 ms test tolerance, leaves checkpoint zero and the exact event replayable |
| Real HTTP/process gate | Auth 401; durable 202; partial 429 retry accounting; SIGKILL after HTTP admission; graceful drain/restart; lock/config/stream-reset failures; secret redaction; Rust verifies 101 canonical persisted events |
| Streaming million-event gate | Exactly 1,000,000 regenerated canonical events, IDs, timestamps/observed_at and sequences match after shutdown/reopen; no corpus-wide ID set |
| Independent review | Separate Sol 6.1 high checked all 14 checklist areas; no unresolved new blocker/high; corrections and remaining limitations below |

### Million-event run

```bash
cargo build --release -p signal-storage --example million-roundtrip
/usr/bin/time -v target/release/examples/million-roundtrip
```

Linux AMD64, Rust 1.94.1; 1,000-row / 2 MiB batches, Snappy, 4 GiB disk cap,
100,000 entry cap and 120 s operation deadline. This is a storage acceptance
measurement, excluding HTTP/WAL/query/rules and compiler memory.

| Measurement | Observed |
| --- | ---: |
| Verified events | 1,000,000 |
| Parquet files / regular files / total entries | 1,028 / 2,030 / 2,062 |
| Stored file bytes | 169,188,021 |
| Write | 86.735 s; 11,529.3 events/s |
| Reopen | 32.178 s |
| Read and full verification | 38.852 s; 25,738.6 events/s |
| Whole runtime | 2:37.88 |
| Maximum resident memory | 16,292 KiB |
| User / system CPU | 84.27 / 17.80 s |
| Swap | None |

Temporary gate data was cleaned. The measured reopen exceeded the proposed 30 s
deadline; library/server defaults were adjusted to 120 s, matching the successful
gate configuration. Larger data or slower storage may need explicit limits.

### Review corrections and remaining boundaries

- High: WAL identity now uses synced temporary publication/recovery instead of
  writing the final UUID in place; interrupted Phase 2 upgrade preserves backlog.
- High: Parquet footer/container/schema/page checks run before allocations and
  decompression; adversarial regressions cover the discovered paths.
- Medium: one captured shutdown deadline spans HTTP, drain, flush and workers;
  coalescing uses configured row/interval bounds and drain bypasses the interval.
- Medium: ADR-004 now matches all 20 columns and their exact types/nullability.
- At Phase 3 acceptance, synchronous stderr tracing could stall the runtime if
  the log pipe filled. Phase 5 subsequently added bounded logging and a
  stalled-consumer regression.
- Publication evidence combines real quota partial writes, owned orphan recovery,
  source ordering, publish-before-ack restart and SIGKILL after HTTP acceptance.
  Deterministic process kills at every individual fsync/rename stage were not run.
- AMD64 local filesystem/process proof does not qualify ARM64, current containers,
  remote CI, filesystem power-loss behavior, production or the full MVP release.

The Phase 5 follow-up work identified at this checkpoint is now complete;
current evidence is recorded above.

## Phase 2 evidence — 2026-10-06

Implemented scope: durable `signal-buffer`, generic metrics extension in protocol,
WAL metrics in ingest, real server admission, process/recovery tests, ADR-006 and
current configuration/status documentation. The volatile sink remains an ingest
test fixture. No storage/query/rule consumer has been implemented early.

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 48 tests (22 buffer, 8 event, 15 ingest, 2 executable/process, 1 documentation) |
| `python3 scripts/check-workspace.py` | Passed: 12 packages, dependency direction and source guardrails |
| Actual SIGKILL/restart | One acknowledged HTTP event recovered with matching ID and checked on-disk CRC; no graceful shutdown substituted for kill |
| Actual saturation/restart | Capacity 10: one initial event + batch of 12 gave 9 accepted/3 rejected; all ten accepted IDs preserved through SIGTERM/restart |
| WAL file recovery | Rotation; repeatable bounded reads; checkpoint/reclaim and sequence after all files reclaimed; replay with nested/large-number attributes |
| Crash consistency/error gates | Partial final record/segment recovery; interior truncation/gap failure; header/payload/checkpoint CRC; valid-CRC invalid canonical event rejection; stale checkpoint temp and post-checkpoint/pre-reclaim state |
| Capacity/failure gates | Count/byte/disk/segment limits; all three admission policies; lowered replay capacity; disk-size/record-length preflight; actual checkpoint I/O failure closes admission without reclaim |
| Worker bounds/deadlines | Bounded commands, waiters and outstanding replies; queued abort/close/deadline skip writes; active deadline survives caller abort; shutdown wait bounded |
| Ownership/security | Real process exclusive directory lock; unexpected-file/symlink rejection; invalid/corrupt startup fails; process logs redact request/token secrets |
| Git state | Empty index; no commits created |

All Cargo gates ran in the normal sandbox, with offline dependency resolution for
verification. Downloading new packages required approved network/cache access.
Locked additions: CRC32 runtime library 1.5.2 and temporary-directory test library
3.27.0 (plus four transitive packages). Library APIs were fetched through Context7
for Tokio, CRC32 and test-directory support; std file sync/lock behavior was checked
against primary Rust documentation and actual compilation on Rust 1.94.1.

The tests prove local Linux AMD64 process recovery. They do not establish power-loss
or network-filesystem behavior, current container runtime, ARM64, throughput or exact
RSS. CI remains unrun because all changes are uncommitted/unpushed. Phase 0 container
results below are historical; Phase 2 container build/runtime are unverified.

## Phase 2 review

Reviewed all 14 checks in `05-implementation-prompts.md`:

| Area | Finding and disposition |
| --- | --- |
| Correctness | Ordered sequences and repeatable prefix reads; durable checkpoint only after consumer ack; preserved identity and at-least-once replay. Server never auto-acks a backlog without a consumer. |
| Memory/disk | Pending count/encoded bytes, record size, segment count/content bytes, channel, waiters and outstanding replies bounded. Oversized files/lengths checked before replay allocation. RSS/block/inode overhead is explicitly unmeasured. |
| Async/blocking | Filesystem operations confined to one dedicated worker. Async calls have deadlines and cancellation flags; queued cancelled work is skipped. In-progress syscalls complete on that same tracked worker, with uncertain caller outcome documented. An overdue active operation closes readiness, even after client abort. |
| Crash consistency | Versioned CRC framing; final incomplete tails only; fsynced file/directory creation, atomic checkpoint rename and directory sync before reclamation. Sequence survives full reclaim. Mid-reclaim and temporary-checkpoint states tested with real files. |
| Data loss | Default reject policy retains accepted records; graceful/forced process gates pass. Explicit drop policy durably counts intentional loss before new append. I/O errors stop admission; no detached writer can reuse a partial segment. |
| API/schema | Generic `EventSink` remains storage-independent. Event/API version 1 unchanged; WAL format version 1 recorded in ADR-006. Snapshot structs are in-process state, not serialized contracts. |
| Security/secrets | Dedicated directory rejects symlinks/unexpected entries, advisory exclusive ownership, new files 0600 and directories 0700. Static contextual errors never print payload or config/token values. Actual process redaction passes. Existing ancestors/directories remain operator-managed. |
| Dependencies | One runtime CRC dependency plus one test-only temporary-directory dependency; std supplies locking/fsync. No buffer -> ingest/storage coupling; source guard passes. |
| OSS/ARM64 | Generic mechanisms only; no private namespace in runtime sources. Architecture-neutral Rust and runtime CRC feature detection; ARM64 execution remains pending. |
| Tests | 48 workspace tests, including real WAL files and real HTTP/SIGKILL/SIGTERM. Worker pause controls test scheduling only; WAL I/O is not mocked. |
| Observability | Queue, WAL byte/segment, replay/drop/truncation/corruption, command, outstanding operation, waiter and timeout metrics. Startup corruption is a typed stderr failure, since no metric listener is started. |
| Performance | Per-event fsync and bounded payload copying deliberately favor correctness; no unsupported throughput/RSS claim. Benchmarking/group commit/replay cache decisions remain hardening work. |

Concrete review fixes: parent sync for newly created directories; preflight replay
file size before payload reads; retained-reply permit bound; active deadline tracking
independent of caller polling; explicit startup error classification and timeout
accounting. Regression coverage is included above. No unresolved blocker/high
findings for Phase 2's local-WAL scope.

Remaining medium item carried from Phase 1: synchronous stderr tracing may block
on a stalled log consumer. Implement a bounded observable logging path and its
stalled-consumer test before production/load qualification. Full release acceptance
also requires container/ARM64 and profiling evidence in the later gates.
Power-loss behavior remains unproven by process-kill tests.

## Phase 1 evidence — 2026-10-06

Implemented scope: `signal-event`, `signal-protocol`, `signal-ingest`,
`apps/signal-server`, their tests, ADR-003, configuration examples and CI container
smoke adjustment. No later-phase business functionality is included.

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 26 tests (8 event, 15 ingest, 2 executable/process, 1 documentation) |
| `python3 scripts/check-workspace.py` | Passed: all 12 packages, dependency direction and source guardrails |
| Real TCP 10,000-event gate | 100 batches; 5037 accepted, 4963 rejected, 5037 unique accepted IDs |
| Real process gate | Startup, token auth, retained queue depth, SIGTERM exit 0, discarded count, log redaction, invalid config |
| Resource/cancellation gates | Count/byte limits, streamed body limit, request/connection concurrency, header/body/admission deadlines, client abort and shutdown cancellation |
| Git state | No staged files, no commits created |

Documentation was fetched through Context7 for Axum, Tokio and Hyper, with primary
UUID/Chrono references and installed dependency source inspection. Dependencies
are centralized and locked; resolved versions include Axum 0.8.9, Tokio 1.53.2,
Chrono 0.4.45 and UUID 1.27.0. `signal-event` has no Tokio/HTTP dependency. Cargo
package downloads required approved network/cache access; Rust tests run in the
normal sandbox. CI has not run while changes remain uncommitted/unpushed.

Phase 1 container smoke now passes `--version` so CI does not hang on the new
server executable. The Phase 0 AMD64 container evidence below is historical;
Phase 1 image runtime/build and ARM64 have not been locally verified. Native
ARM64 CI remains configured. Compose, persistence/restart and Kubernetes are
future phase gates. The benchmark harness remains a baseline, not performance proof.

## Phase 1 review

Reviewed all 14 checks in `05-implementation-prompts.md`:

| Area | Finding and disposition |
| --- | --- |
| Correctness | Complete batch validation precedes admission; partial saturation/timeout returns exact accepted IDs and remainder counts. Real HTTP/process gates pass. |
| Memory/disk | Queue count and canonical encoded bytes, in-flight bodies and connection tasks are bounded. Encoding counts bytes without a second event-sized allocation. RSS overhead is explicitly unmeasured. No disk pipeline exists yet. |
| Async/blocking | No filesystem operations or awaits occur under the short memory-queue mutex. Network reads/writes have header/request/connection/shutdown bounds. Console tracing uses the standard synchronous stderr writer; a stalled log consumer is a remaining hardening concern. |
| Crash/data loss | Volatile admission is documented and startup/shutdown logs expose it; graceful shutdown stops admission first and reports discarded events. WAL/replay/durable acknowledgment begin in Phase 2. |
| API/schema | ADR-003 defines version 1 defaults, UUID identity, RFC3339 UTC serialization, nested/large-number attributes and independent HTTP response versioning. |
| Security/secrets | Typed errors never echo body/token values. Duplicate auth headers fail; comparison uses `subtle`. Config Debug redacts token. Process tests inspect actual logs for leakage. |
| Dependencies | Runtime-independent event/protocol seams; only used runtime/test libraries are added. Hyper adds bounded HTTP/1 transport using already shared Axum dependencies. |
| OSS/ARM64 | Generic resource fields and attributes only; source boundary check passes. No architecture-specific runtime code; ARM64 execution remains unverified. |
| Tests | 26 tests, including full validation, overload, cancellation and real process/TCP proof. No mocks stand in for storage/WAL; neither is implemented yet. |
| Observability | Accepted/rejected events and requests, queue count/bytes/capacities/drops, in-flight limits and connection error/timeout gauges/counters exposed as Prometheus text. |
| Performance | No throughput claim or optimization from speculative benchmarks. Bounded JSON work runs in handlers; profiling remains a release gate. |

No unresolved blocker/high findings for Phase 1's explicitly volatile scope.
Remaining medium hardening item: `apps/signal-server/src/main.rs` logging writer
can block on a stalled stderr consumer. Before production/load qualification,
introduce a bounded observable logging path and a stalled-consumer regression
that proves ingest/shutdown deadlines remain enforceable. This is not evidence
that the current implementation is ready for production.

## Phase 10 local evidence — 2026-10-06

| Check | Observed result |
| --- | --- |
| Final workspace | Build, formatting, strict all-target Clippy and tests passed: **227 tests, zero failures, 39 result summaries**. `/tmp/signal-phase10-final-workspace.log` records exec session 16822 and the captured results. The final chained boundary command had a filename typo; the correct `python3 scripts/check-workspace.py` ran separately with exit 0 and verified all 12 packages (`/tmp/signal-phase10-workspace-boundaries.log`). |
| Bounded parser/WAL campaign | Nine new tests are included in the workspace count. Focused campaign passed in 15.971 s: 512 event roundtrips, 512 URL transports, 512 independent rule truth models, 104 WAL record mutations, 28 checkpoint mutations, 303 final-record cuts and nine acknowledgement-prefix models. Source/log hashes and counts: `target/phase10-hardening/20261006T185925.121730Z/campaign.json`. No new production dependencies or production parser changes. |
| Actual storage OS failure | `/tmp/signal-phase10-storage-failure.log`: focused test passed in 2.52 s and passed again in the workspace. A test-owned existing temp file causes real `create_new` EEXIST after durable HTTP 202. The server fails closed, preserves the sentinel, publishes no Parquet and keeps checkpoint zero. Removing only that sentinel permits exact event/finding replay, checkpoint one and a further stable restart. This is not ENOSPC, hardware failure or power-loss proof. |
| Release-binary load profiles | Eight finite native AMD64 profiles used the same qualified Phase 8 release binary: 13,994 attempted events, 3,217 HTTP-confirmed admissions, 3,223 durable WAL/Parquet events and 197 findings; zero transport failures/drops. Six uncertain deadline events became durable beyond returned prefixes. The eight-slot pressure profile reached 8/8 with 48 accepted and 9,952 capacity-rejected events. All 160 query samples succeeded. See [BENCHMARKS.md](../BENCHMARKS.md) for exact measurements, commands and artifact hashes. |
| CPU/RSS observations | Sampled peak RSS 43.36–57.02 MiB and CPU 1.52–16.54% of one core on a shared workstation. These finite samples do not establish a universal memory ceiling, prolonged soak, physical disk throughput or function-level bottleneck attribution. Configured high EPS targets were not attained; no speculative optimization was made. |
| Bounded native soak | Native AMD64 soak-only campaign completed 120 seconds per 1 KiB/4 KiB profile at 100 EPS target: 11,170 and 9,680 accepted/WAL/persisted/rule-evaluated events, 559 and 484 findings, 20 successful event queries each, zero rejections, uncertainty or failures. Actual rates were 93.017/80.628 EPS; 121 samples per profile across 12 buckets. Load RSS and process I/O intervals are detailed in [BENCHMARKS.md](../BENCHMARKS.md). This remains finite local observation, not prolonged stability or physical-device throughput proof. |
| Buffered Parquet header read | A fixed 1 KiB `BufReader` at two Parquet header-reading sites preserves limits, CRC/formats and cancellation guards; three regressions cover read-ahead skips, logical byte limits and cancellation. On the same 20 files/40 events, matched release-image binaries recorded 37,920 read calls (37,698 successful one-byte) before and 702 (zero one-byte; 480 successful 1,024-byte calls) after. The comparison is structural; `strace` adds overhead, so no time/capacity ratio is claimed. Process-returned bytes increased 532,926→968,300, not physical-device I/O. See [BENCHMARKS.md](../BENCHMARKS.md). |
| 600-second soak attempt | Both 1 KiB/4 KiB profiles ran 600 seconds at 20 EPS, accepted and durably processed 12,000 events each with 600 findings and zero rejections/uncertainty, then failed their first event query with HTTP 408; zero planned event queries completed. Both servers exited cleanly. These retained reports are failed diagnostics, not a passing soak gate. |
| Agent deadline fixture | An unchanged spool deadline test failed twice with `ErrorTimeout` around fixture open/close; the prior focused test passed. A test-only budget adjustment from 100 ms to 1 s and contextual fixture errors preserved held-worker/capacity assertions and passed in the final workspace. The exact timeout phase remains unproven; no production agent behavior changed. |
| Current workspace | `target/phase10-header-buffer-20261006/workspace-final.json`: fmt, strict Clippy, build, all 231 workspace tests and 12-package boundaries passed. The three new storage regressions are included in 231; the former 228-test gate remains historical. |
| Refreshed release image | Original Dockerfile image `sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1`; extracted release binary SHA256 `338561e7bbfb4fd639d5a5bad0ae6f51a7716bce9bddc385f765d4751a93efed`. The standalone run-3 matched syscall profile uses this binary; `extraction/origin.json` binds it to the image. |
| Container, Kubernetes, Helm and supply chain | Container gate passed nonroot/read-only/auth, health and SIGTERM/SIGKILL persistence. Local kind 1.34 passed one event/finding, SIGKILL and replacement-PVC recovery with auth/separate metrics and owned cleanup. Fresh Helm default and optional template renders exited 0. All six supply-chain checks passed: zero RustSec findings, SPDX 328 Cargo/15 image packages, Trivy HIGH 0/CRITICAL 0/MEDIUM 23/LOW 8. Artifacts: `container.log`, `kubernetes-final.log`, `helm-default-render.yaml`, `helm-optional-render.yaml`, `target/phase10-longer-soak-20261006/review/helm-render-validation.json`, `supply-chain/20261006T211924.305016Z/`. |
| Refreshed native qualification | `target/phase10-header-buffer-20261006/native/20261006T211925.268888Z-edd4602c/qualification.json`: passed AMD64 native campaign, `full_qualification: true`, all owned cleanup passed. Reviewer validated the exact accounting. Seven pipeline profiles: 13,480 attempts/3,175 HTTP-confirmed/3,176 durable/191 findings/140 queries; zero transport uncertainty or drops. Queue pressure accepted 56/rejected 9,944. |
| Refreshed soak | The same native campaign includes two 120-second profiles: 8,050/6,490 accepted and durably processed events, 403/325 findings, 20 queries each, zero rejection/uncertainty/query failures; 67.030/54.059 EPS observed. The earlier soak-only 120-second result remains historical and is not merged into this run. |
| Longer soak and remaining external gates | Earlier old-image 600-second profiles failed first queries with HTTP 408 after persisting 12,000 events each. Both refreshed-image 600-second profiles passed with 12,000 accepted/WAL/storage/rule events, 600 findings and 20 queries each, zero rejection/uncertainty/errors, and clean exit; independent paired-result validation and final 14-area review passed with no findings (`target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`). Each captured 600 load samples across 12 buckets. This finite run does not establish prolonged stability or a universal plateau. Native ARM64 remains unavailable; EKS is not qualified and remote CI has not run. |
| Documentation | [Threat model](20-threat-model.md), [release audit](21-release-readiness.md), [upgrade/versioning policy](../UPGRADING.md) and [Unreleased notes](../CHANGELOG.md) bind current mechanisms to proof and disclose remaining qualification. Private metadata, rules and fixtures remain external. |
| CI validation | Final workflow passed cached Actionlint 1.7.7 (`/tmp/signal-phase10-actionlint.log`); required jobs have not run remotely. |
| Campaign cleanup regression | An owned process session/group now receives bounded TERM grace, then KILL and leader reap; the leader remains unreaped until KILL to reserve its group identity. `scripts/test-hardening.py` passed independently for root and reviewer in 2.210 s (`/tmp/signal-phase10-hardening-cleanup.log`): both owned parent/sleeper stop and an unrelated sentinel survives. One standalone test, separate from the 227 Cargo tests; registered in CI. |
| Independent review | Final Sol high review passed with no unresolved findings. Property-source/log hashes and both immutable benchmark hashes/counts reconciled. Timeout cleanup and admission-policy documentation findings fixed and verified; threat model, storage failure/replay, upgrade policy and Unreleased notes reviewed. |

The campaign runner's successful original report remains evidence for its fixed
test sources; the runner cleanup change passed its focused regression separately.
Container/Kubernetes/scans qualified the release production binary; Phase 10
initially added test/harness/documentation files without changing that qualified
binary. The later Parquet header-reader correction changes production read
behavior; the refreshed original-Dockerfile AMD64 image and native campaign
have since passed their local image qualification gates.

## Remaining release qualification

Use [the release audit](21-release-readiness.md) and [definition of
done](06-definition-of-done.md) for exact open gates. Native ARM64 runtime and
benchmarks, EKS persistent restart, actual remote CI and released dependency
integration need their corresponding environment or publication evidence.
The bounded 120-second-per-size AMD64 soak is recorded in
[BENCHMARKS.md](../BENCHMARKS.md). The old-image 600-second-per-size diagnostic
completed event admission and persistence but failed both post-load queries.
Both refreshed-image 600-second profiles passed with 12,000 durable events, 600
findings and 20 queries each; independent pair validation is retained in the
benchmark evidence. This finite result does not establish a universal resource
plateau or prolonged stability.
Physical-device disk profiling remains unmeasured. The local
same-binary offline restore rehearsal below adds scoped backup evidence; it does
not qualify cross-version migration or production backup operations.
No image/crate/release was published, no cloud resource was created,
and no file was staged or committed. Phase 9 AWS collection remains post-MVP.

## Offline restore continuation — 2026-10-06

Added a synthetic stopped-data backup/restore gate to the existing agent process
test target. No production Rust code or disk format changed. The gate preserves
the original and backup, checks 18 copied files plus directory modes/ownership,
and restores server data/configuration/rules, source fixture and agent spool into
separate directories using the same local development binaries.

| Check | Observed result |
| --- | --- |
| Retained rehearsal | `target/phase10-restore-qualified/report.json` records native x86_64, 5.522 seconds before binary hashing, server/agent version and binary SHA-256, harness/inventory SHA-256 and exact counts. Logs and all three data trees remain in the owned output directory. `/tmp/signal-phase10-restore-process.log` records success. |
| Pending server WAL | One HTTP-202 event is left unpublished by an owned EEXIST fault; checkpoint remains two. Copying occurs after all processes exit and only the fault fixture is removed. Restore replays the exact canonical event and creates its finding, advancing checkpoint to three. The prior event/finding and stream identity are unchanged. |
| Pending agent spool | The offline agent exits after SIGTERM with two pending records retained. Restore drains these through idle stdin without reading any original source; canonical IDs, timestamps and nested attributes match the copied records. Spool acknowledgement and cursor state survive. |
| Source cursor | A copied fixture has a new inode and rereads three lines with new IDs. The subsequent run against that restored file adds no rows; one appended line adds exactly one row. This is documented at-least-once behavior, not source relocation with exactly-once delivery. |
| Final persistence | Nine events, two exact findings and WAL checkpoint nine remain stable through another graceful server restart. Original and backup inventories remain unchanged. Auth 401/202 and token redaction pass. |
| Workspace | Build, formatting, strict all-target Clippy and workspace tests pass: **228 tests, zero failures** in `/tmp/signal-phase10-restore-workspace.log`. Twelve-package boundary gate passes in `/tmp/signal-phase10-restore-boundaries.log`. |
| Review | Initial local review was followed by independent Sol high review and a focused successful repeat (6.993 s wall; report 4.761 s before hashing). Evidence is retained in `target/phase10-restore-review-20261006/`. Original/backup inventories and harness/binary hashes matched; no unresolved source issue. No native ARM64 execution is claimed. |

This proves synthetic local same-binary offline restore on the same filesystem
and user. It does not prove cross-version migration, backup-media power-loss
durability, another storage/ownership environment or production operator
acceptance. The external release gates above remain open.

## Native qualification continuation — 2026-10-06

Closed the remaining CI coverage gap: each native matrix job now runs the
bounded parser and measured release-pipeline campaign against its already-built
image and retains reports even on failure. The Phase 0 loop benchmark remains
a separate harness smoke. See [22-native-qualification.md](22-native-qualification.md).
One Sol medium writer implemented this gate; one Sol high reviewer checked
source invariants, the restore addition and exact retained reports. No new
production dependencies or Rust runtime changes were made.

| Check | Observed result |
| --- | --- |
| Fresh workspace gates | Exec session 39993 exited zero: build, formatting, strict all-target Clippy, 228 tests with zero failures, 39 result summaries and 12-package boundaries. Complete log: `target/native-qualification/local-gates/workspace.log`. Some earlier `/tmp` logs have disappeared; their citations remain historical observations, not retained evidence. |
| Native AMD64 campaign | Exec session 35588 exited zero. `target/native-qualification/20261006T195653.677830Z-3f2af04a/qualification.json`: all seven commands passed, exact image `sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97`, binary SHA256 `6dfbf81f61a6f7a415c2518b7c3f008471bc281a64552334f40cc4ca4ea09ed5`, Linux host/daemon/image/ELF AMD64 checks passed, owned container/temp directory removed. No build or pull. |
| Parser/load proof | Nine property tests passed in 12.979 s including command overhead; seven load profiles in 52.634 s. 13,584 attempts, 3,542 HTTP-confirmed admissions, 3,544 durable/persisted/evaluated events, 230 findings, 140 successful queries; zero transport failures/drops. Two uncertain deadline appends became durable beyond returned prefixes. Eight-slot overload reached 8/8: 96 accepted, 9,904 rejected. High configured EPS targets were not attained. Source/command/report hashes retained. |
| Cancellation regressions | Review reproduced child-custody gaps around spawn/initialization and repeat interruption during cleanup. Fixed with protected ownership registration, bounded pending signal state and final kill/reap/descriptor closure. Current root run: fifteen focused tests pass in 8.026 s with ResourceWarning treated as error; existing hardening cleanup one test passes in 2.209 s. Logs: `target/native-qualification/local-gates/{native-runner-tests-final.log,hardening-cleanup-final.log}`. These are outside the 228 Cargo tests. |
| Measurement scope | Successful full profiles used the recorded script versions before the subsequent cancellation-only corrections. No measurement/configuration changes were made. Root and reviewer accepted the immutable campaign reports with final validators; all report and seven command-log hashes match. The load campaign was not repeated for cleanup changes. `full_qualification: true` refers to this native Phase 10 campaign, not release acceptance. |
| CI source validation | Cached read-only/no-network Actionlint 1.7.7 passed after final workflow changes. `target/native-qualification/local-gates/actionlint.log`. Native AMD64/ARM64 jobs reuse one image and upload native/supply-chain reports for 14 days; remote jobs remain unexecuted. |
| Checklist recovery | `docs/06-definition-of-done.md` unexpectedly contained 6,713 bytes of invalid UTF-8 binary data during this continuation. Preserved exactly in `target/checklist-recovery-20261006/06-definition-of-done.corrupt` (SHA256 `441b23786c1110a0cb23d0d57087546c5665b7efeaef1153161cc997cc1922d7`); restored from the previously read specification and evidence ledger, then independently reviewed. Cause is unknown. No open release gate was checked by the restoration. |
| Independent acceptance | Final source review found no unresolved blocker/high/medium/low findings for restore/native runner and nested harness cleanup. Independent fifteen-test run passed in 8.078 s; stable reviewer logs under `target/native-qualification/review-20261006/`. |

The owner confirmed that no ARM64 host is available. Native ARM64, approved EKS,
actual remote CI and released-dependency integration still need their own
environments/publication evidence. No remote job or cloud action was performed;
no file was staged or committed. The current local evidence is recorded under
ignored `target/`; preserve it before cleaning build artifacts.

## Bounded native soak continuation — 2026-10-06

| Check | Observed result |
| --- | --- |
| Native AMD64 soak-only campaign | `target/phase10-soak-team-20261006/final/20261006T203345.246930Z-6640d177/qualification.json` and `soak.json`; 6/6 commands passed, exact previously qualified image/binary, both owned resources removed. Scope `native-soak`; `full_qualification: false`. SHA256: qualification `137c29454fd732235b2b910692ceac08c926ccaf967165af73a2320b740d7ebc`, soak `32e951e9158ce8aa72e6e3cd505c9b3ca388f1c5a74f48d041cc06862d229e60`. |
| Two load profiles | At 100 EPS target for 120 seconds each: 1 KiB accepted/WAL/persisted/rules 11,170, findings 559, actual 93.017 EPS; 4 KiB accepted/WAL/persisted/rules 9,680, findings 484, actual 80.628 EPS. Zero rejection, transport uncertainty, query failure/timeout or event/storage/rule failure; 20 event query samples each. |
| Resource accounting | 121 samples each across 12 buckets, no sample failure; largest observed sample gaps 1.0061/1.0063 s. Load-only RSS range 14,024,704–19,005,440 B and 13,893,632–20,615,168 B; warmup-to-final mean drift +1,693,211.927/+1,772,711.564 B. Load CPU 7.97/8.09 s. Load-only and load-through-query process I/O deltas have distinct intervals; exact counters are in [BENCHMARKS.md](../BENCHMARKS.md). These bounded observations do not establish a universal memory plateau, longer stability or physical-device throughput. |
| Query-budget diagnostic | Earlier 4 KiB profile with 64 MiB query memory returned HTTP 413 `resource_limit` after load/drain. The failed report is preserved at `target/phase10-soak-team-20261006/diagnostic-4k-verified/soak.json` with completed observations. Long soak config now explicitly records 256 MiB query memory; no cause beyond the reported response is asserted, and no production optimization/configuration change was made. |
| Validation and review | Final workspace formatting, strict Clippy and 228 tests passed; 12-package boundary check passed. Native qualification regressions: 18 passed; soak regressions: 17 passed. Independent Sol 6.1 high review accepted all 14 checklist areas with no unresolved findings, including source/runtime hashes, accounting and documentation. Acceptance: `target/phase10-soak-team-20261006/review/final-review.json`. |

The one-shot run added bounded AMD64 evidence without completing full native
qualification. Native ARM64, prolonged soak/resource plateau, physical
device I/O profiling, remote CI, EKS and released dependency gates remain open.

## Phase 0 evidence

Environment: Linux AMD64, Rust 1.94.1, Cargo 1.94.1, Node 24.12.0, Codex CLI
0.160.1, Claude Code 2.1.291, Docker Compose 5.6.0. The exact Rust toolchain was
installed without changing the default toolchain. Rustup performed its automatic
self-update during installation. No global Codex or Claude configuration changed
(configuration file hashes matched before/after setup).

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed across all 12 packages |
| `cargo test --workspace` | Passed: 1 executable integration smoke test; no event/runtime tests yet |
| `python3 scripts/check-workspace.py` | Passed: 12 packages; dependency direction and production-source guardrails |
| `cargo bench -p signal-server --bench harness --locked` | Passed: bounded harness baseline only, no pipeline performance claim |
| TOML/JSON/CI YAML parsing; launcher `bash -n` | Passed |
| `docker build -f deploy/docker/Dockerfile -t platform-signal:foundation .` | Passed locally for AMD64; image not published |
| `docker run --rm --read-only --cap-drop=ALL --network=none platform-signal:foundation` | Passed: version output; AMD64 image configured as user `65532:65532` |
| Context7 4.1.1 installation + npm audit | Installed locally and locked; 0 reported vulnerabilities |
| `python3 scripts/ai/check-mcp.py` | Passed: MCP initialize and tools/list (`resolve-library-id`, `query-docs`) |
| `python3 scripts/ai/check-mcp.py --live` | Passed: actual Tokio library lookup through Context7 |
| `codex mcp get context7 --json` | Project stdio launcher loaded with startup/tool deadlines |
| `claude mcp get context7` | Project config discovered; interactive approval pending in Claude Code |
| Git index/history | No staged files; no commits created |

Sandbox-required access was granted for npm installation/live MCP lookup, exact
Rust toolchain installation, protected project `.codex/config.toml`, and Docker.
These verified checks use host access beyond the default sandbox. Rust checks,
local MCP startup and dependency-direction validation run inside the sandbox.

At Phase 0, GitHub Actions was configured for native AMD64/ARM64 Rust gates and container
smokes, plus a separate local MCP handshake job. **CI has not run** because this
change is uncommitted/unpushed. ARM64, multi-platform image export, Compose, Helm,
Kubernetes and EKS runtime proof remained pending at that phase. Current local
Compose/Helm/Kubernetes evidence is recorded above; native ARM64, remote CI and
EKS remain unverified.

## Phase 0 review

Reviewed against the 14 checks in `05-implementation-prompts.md`.

- Correctness/API: real executable smoke; contracts remain unimplemented rather
  than represented by misleading placeholder public structs.
- Resource bounds/async/crash consistency/data loss: no runtime queues or I/O
  pipeline exist. The verification RPC reader has a 2 MiB response cap and a
  60-second deadline; the benchmark loop has a finite validated count. WAL and
  persistence failure tests are deferred to their phases, not claimed as passed.
- Security/secrets/dependencies: unsafe Rust is forbidden; production unwrap and
  expect are denied by Clippy. No runtime third-party dependencies yet. MCP tooling
  is pinned/locked, initialized from the installed package and audited; no secret
  values are tracked or logged. Docker context uses a whitelist and runtime user
  is non-root. Dedicated security/moderation contacts are not yet designated.
- OSS boundary/portability: crate direction is checked; runtime sources contain
  no company namespace. CI covers both architectures; only AMD64 is locally proven.
- Tests/observability/performance: one foundation integration test; runtime metrics
  and component benchmarks begin as implementations land. Harness timing is not
  a throughput or memory measurement. No speculative optimization was added.

No unresolved blocker/high findings for the foundation change set. Release
limitations above remain explicit and must be completed in their phases.

Do not stage, commit, push, publish or create the private overlay unless requested.


## Project AI tooling — 2026-10-07

The owner-approved project setup uses Sol 6.1/medium/Standard for new Codex
sessions and Sonnet/medium for Claude, with Context7 as the configured baseline.
Three focused project skills and a read-only usage snapshot/delta helper support
compact task/validation/handoff workflows. Shared platform launchers were applied
to SIGNAL, IPAM and the separate private overlay; global settings, private policy
and product behavior were preserved. Fresh native SIGNAL config/skill discovery,
MCP parsing/Context7 handshake, launcher argument/root checks and usage-helper
failure/delta checks passed. See [development tooling](08-development-tooling.md).
These are tooling checks, not additional ARM64/EKS/remote-CI or release acceptance.

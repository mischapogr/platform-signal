# Finite execution ledger

Current inventory — 2026-10-26: **40 accepted / 12 unfinished** (14 passed_local,
24 passed_simulated, 2 passed_external, 7 pending, 1 in_progress and 4 external_pending).
STATE is passed_simulated for D04/D06/D08/D09/D13; D12 remains explicitly deferred
to AWS-PROFILES. Independent source/criteria reviews, eight frozen gates,
1238default/1308all-feature tests and five actual SIGKILL/original replay/policy
generation cases pass. Evidence:`target/scoped-state-20261026/ACCEPTANCE.json`;
[contract80](80-scoped-state.md). Source/private authority are synthetic; hosts own
protected archives/index and exclusive activation. Next: CORRELATION (in_progress),
D11 accepted as a slice (`target/correlation-20261026/D11-ACCEPTANCE.json`);
D14 in_progress, whole CORRELATION stays unfinished. Older dated inventories below
describe their own revisions.
D14 capture/SDK focused checkpoint:21owned native x86_64 cases,seven SDK tests,
retained-native composition and D11 exact-byte golden compatibility; see
`target/correlation-d14-20261026/SDK-CHECKPOINT.json`. Classification/join/replay
and whole-item acceptance remain open; inventory unchanged. Typed historical
classification/seven core tests plus21case SDK/core bridge now pass focused checks;
`target/correlation-d14-20261026/CORE-CHECKPOINT.json`. Shared state/journal next.

Dependency rewrite — 2026-10-23. EKS-AUDIT now depends on SMALL-PILOT (Kubernetes audit
normalization; the EKS CloudWatch transport stays with CLOUDWATCH), BASELINES drops
AWS-PROFILES (D01/D02/D03/D05 use CloudTrail adapters already accepted; D07 uses
Kubernetes audit) and STATE adds K8S-CONTEXT (D08/D09 snapshots) and defers D12 to
AWS-PROFILES. The 52 IDs are unchanged and no acceptance criterion was removed. LOCAL-CANDIDATE
no longer reaches CLOUDWATCH, AWS-PROFILES or any EXT-* item. Unfinished path, in order:
K8S-CONTEXT, BASELINES, STATE, CORRELATION, SOC-UX, PROFILE-LOAD,
SCALE-DECISION, RELEASE-TRUST, then LOCAL-CANDIDATE. Reasons are in each item's
`dependency_rewrite` in the JSON and in [68](68-mvp-closure.md).

Current local SHARED-RUNTIME acceptance: independently reviewed `b9c58da` closes
SHARED-METRICS-1. Current source-bound 919 default / 976 all-feature tests, both
strict Clippy modes, formatting and 14 workspace boundaries pass. Real PostgreSQL
18-case/server/native HTTP qualification passes in 190.91s; five Standard
scenarios and the metrics scrape pass in 180.44s. Audit/private/restored5 refreshes
pass in 53.10s / 42.80s / 75.26s with current source/executable bindings and cleanup.
Review: `target/shared-runtime-refresh-20261012/INDEPENDENT-LOCAL-ACCEPTANCE.json`.
The 52 IDs and dependencies are unchanged. Current local Standard Kubernetes
passes141.13s with167source bindings, regular runtime/TLS Secret files, original
WAL/checkpoint2/database facts and same-PVC SIGKILL/pod replacement recovery,
plus owned cleanup: `target/standard-kubernetes-20261012/ACCEPTANCE.json`.
STANDARD-RECOVERY passes local simulation on2026-10-14:12frozen gates,935default/
996all-feature tests and native historical restore79.66s/PG matrix122.76s/actual
server-local loss75.55s. Replacement17.61s/RPO0 applies only to the4byte custody
fixture. Source/binary/cleanup and exact original receipt/control/object/WAL/
private progress are audited. Next:ONBOARDING; external/production gates remain.

Current inventory:13 passed_local,19 passed_simulated,2 passed_external,13 pending/1in_progress,
4 external_pending. Native Standard cluster CI wiring now passes local direct
process/bundle/kind acceptance181.93s/170.05s; exact remote results are next:
`target/standard-kind-ci-20261012/ACCEPTANCE.json`. Local provider/custody
simulation does not close corrected native/current CI, AWS/EKS or release gates.
OBJECT-CUSTODY is passed_simulated at its local boundary — 2026-10-14.
All12frozen gates pass:932default/993all-feature tests, authenticated native API/SDK
13.56s and actual Standard Main custody38.34s, source/binary bindings and cleanup.
Evidence: `target/object-custody-api-20261012/ACCEPTANCE.json`. Provider retention
is simulated; actual AWS/account/AZ loss and current external/release gates remain.
Next runnable dependency-ordered item:STANDARD-RECOVERY.
ONBOARDING is in progress — 2026-10-14. Its bounded SDK current-readiness slice
passes8focused regressions and6frozen gates:943default/1004all-feature tests,
both strict Clippy modes, formatting and14workspace boundaries. Historical/stale
coverage and missing/unknown permission/category/state, unsupported or unloaded
rules block readiness. Authenticated host integration, console and actual engine
gating remain open. Evidence:`target/onboarding-sdk-20261014/ACCEPTANCE.json`.
Its generic rule execution gate also passes4new regressions and6frozen gates:
947default/1008all-feature and both Clippy/fmt/workspace. Explicit complete loaded
inventory suppresses blocked matching rules and preserves enabled findings.
Main/host/API/console integration remains open; current-health history stays
unknown. Evidence:`target/onboarding-rules-20261014/ACCEPTANCE.json`.
Current host integration supersedes the unwired status: pinned signed evidence
gates both Main paths and an authorized read API/console.13frozen gates pass
952default/1013all-feature,7actual Small checks,5onboarding/26existing browser
checks and corrected exact Standard baseline81.17s. Full ONBOARDING stays
in_progress until Standard-enabled and composed browser/native qualification.
Evidence:`target/onboarding-host-20261014/ACCEPTANCE.json`.
ONBOARDING now passes local simulated acceptance:37launcher guards,14workspace
boundaries, actual enabled Standard50.31s with14named scenarios/11WAL checkpoints
and7composed real browser/native checks over verified backend mTLS. The local
requirement audit closes states, unsupported and permission/category/state
blockers, signature/expiry/scope/revocation/restart. Unchanged952default/1013all-
feature Rust and exact binaries remain applicable. Vendor/source checks are
synthetic; external/release gates stay open. Next: RELEASE-REVIEW. Evidence:
`target/onboarding-standard-20261014/ACCEPTANCE.json`.
RELEASE-REVIEW passes focused local acceptance — 2026-10-14. Independent review covers durability, replay, cancellation, scope, quotas and production hazards. Account binding, ACK retry deadline and outdated security responsibilities are corrected. Frozen 9 gates pass: 954 default / 1015 all-feature tests, both strict Clippy modes, formatting, 14 workspace boundaries, actual Small and enabled Standard/browser regressions. Evidence: `target/release-review-20261014/ACCEPTANCE.json`. Current inventory: 26 accepted / 26 unfinished (13 local, 13 simulated, 20 pending, 6 external). Next: UPGRADE; current native CI, actual AWS/EKS/vendor and release gates remain open.

UPGRADE passes local simulated acceptance — 2026-10-14. The explicit development compatibility matrix binds supported exact schema migrations, fresh-generation restore and refusal of unknown/divergent history. Actual PostgreSQL 18-case matrix, isolated stopped Small WAL/spool/Parquet/findings restore and current native Standard restored custody pass with owned cleanup. Original/backup remain unchanged; the Small fixture ends at 9 events, 2 findings and checkpoint9. Evidence: `target/upgrade-20261014/ACCEPTANCE.json`; [compatibility contract](56-upgrade-compatibility.md). Current inventory:27 accepted/25 unfinished (13local/14simulated/19pending/6external). Released-to-released upgrade, actual AWS/EKS/provider and publication remain unqualified. Next release slice: current-revision KIND/remote CI qualification.

Native CI test isolation correction — 2026-10-14. Verified public AMD64/ARM64 artifacts at8d4dc06 show positive onboarding fixtures racing the intentionally occupied configuration worker. Test-only shared fixture guards isolate four worker users; production capacity and fail-closed behavior remain unchanged. Six frozen gates pass:954default workspace and84all-feature server tests with16threads, both strict Clippy modes, formatting and14workspace boundaries. Evidence: `target/release-ci-20261014/ACCEPTANCE.json`. Corrected-revision remote CI/native container/Kubernetes qualification remains open; ledger counts remain27accepted/25unfinished.

RELEASE-TRUST offline mechanism slice — 2026-10-14. Externally pinned Ed25519 inventory verification passes21real crypto/unsigned/tamper/key/domain/schema/path/capacity/symlink/FIFO checks over current OSS lock/rule and explicitly unattested local provenance. Private fixture keys are removed. Workflow lint and14workspace boundaries pass; both native CI jobs run the bounded gate. [Contract57](57-offline-release-trust.md), evidence:`target/release-trust-20261014/ACCEPTANCE.json`. Full RELEASE-TRUST remains pending baseline/current SBOM/builder/released artifact qualification. No runtime signature enforcement, update installation or publication authority; counts remain27accepted/25unfinished.

HOST-AUTH structured authentication slice — 2026-10-14. Opt-in agent auth-json and version1 SDK normalizer preserve source timestamp, authority/principal/target/method/session and producer checkpoints; unknown credential fields reject statically. Four focused regressions and8frozen gates pass:958default/1019all-feature, both strict Clippy modes/fmt/14workspace boundaries, current all-feature binaries and real agent/server process acceptance. Controlled success/failure and2invalid records traverse file/spool/authenticated server/Parquet; cursor restart adds no events and rejected credential bytes stay out of output/logs. [Contract58](58-host-authentication-profile.md), evidence:`target/host-auth-20261014/ACCEPTANCE.json`. File/stdin grants no runtime sensor coverage; full HOST-AUTH remains pending selected sensor qualification. Counts remain27accepted/25unfinished.

Rustls security correction — 2026-10-14. Native ARM supply-chain atc1535f1 exposes four newly published Rustls0.23.45 advisories. All five exact pins and the lock now select0.23.46 with unchanged features, following the [upstream security release](https://github.com/rustls/rustls/releases/tag/v/0.23.46). Current unfiltered Cargo audit reports0vulnerabilities against fresh RustSec data. Eleven frozen gates pass958default/1019all-feature, both Clippy modes/fmt/14boundaries,21offline trust checks and current native mTLS/onboarding plus PostgreSQL/TLS/S3/Standard matrices. Evidence:`target/rustls-security-20261014/ACCEPTANCE.json`. Matching patched native CI/images/scans/Kubernetes still required; counts remain27accepted/25unfinished.

Current native CI and ARM64 qualification accepted — 2026-10-14. Complete [run38583003350](https://github.com/mischapogr/platform-signal/actions/runs/38583003350) at reviewed e1555a4 succeeds. Both architectures pass48Rust gates/1019tests and18container gates. Primary GitHub artifact digests,181Standard source hashes, original/stripped executable bundle lineage and exact images match. Standard kind recovery passes114.53sAMD64/104.48sARM64 with original WAL checkpoint2/PVC replacement and owned cleanup. Cargo audit0 and containerHIGH/CRITICAL0;23MEDIUM/8LOW remain. Evidence:`target/rustls-security-20261014/EXTERNAL-ACCEPTANCE.json`. EXT-CI/EXT-ARM64 are passed_external. Inventory:29accepted/23unfinished (13local/14simulated/2external accepted/19pending/4external pending). Actual AWS/EKS/vendor, released-dependency, version and publication gates remain open; synthetic provider and finite-soak limits are retained.

Earlier entries below retain their original historical evidence boundaries.

Owner-authorized persistent Goal, frozen 2026-10-07. The machine-readable
[ledger](31-execution-ledger.json) is the item inventory; each item records
dependencies, executable acceptance and evidence paths. Pending evidence paths
are destinations, not proof that reports exist. Existing progress/release
reports remain authoritative for accepted results.

This reconciles [product scope](27-product-architecture.md),
[implementation order](04-implementation-plan.md), [routing](11-model-work-plan.md),
[current progress](07-progress.md) and [release gates](21-release-readiness.md).
The newer progress/routing acceptance supersedes old “UI then pruning” next-step
text: UI-01/UI-02, coverage pruning/scans and initial source receipts are done.
OBJECT-READER, FINDINGS-CURSOR and DISPOSITIONS pass locally. AWS-DELIVERY,
COVERAGE-OBSERVERS and OUTBOX pass local simulation. EVIDENCE now passes simulation:
independent protected native originals/complete receipt/current-owner custody,
actual observability outage with M2 ACK gating, lost archive reply/exact replay,
actual server and source crashes, uncertainty/reconciled reopen and fresh ACK.
Private77 strict tests plus exact parent1 compound process gate and review pass;
public588/622 remains unchanged. All source completeness, AWS/TLS/HA/shared-runtime
and release exceptions stay visible. S3-QUERY is passed_simulated: default641/all-feature686 strict gates, source review, six helper regressions and eleven persistent S3/monolith scenarios pass. Four exact events/findings survive data-orphan and manifest-before-reply process crashes. RETENTION is passed_simulated: policy/report, stopped-cache, logical retirement, explicit exact-version query reclamation and bounded query measurements pass. Strict default659/all-feature710 remain unchanged;33 source-bound query samples over2,048 events/8hours and four failure helpers pass. Time pruning16→2 data GETs; cache remains rebuildable with mandatory remote reauthentication. Optional indexes deferred on measured evidence. Continue SECURITY-ACCESS; actual cloud/native/CI/kind/shared/custody/image/release gates stay open.


SECURITY-ACCESS is passed_simulated. Native coverage original-byte/actor/cursor
acceptance and request-local expiry join trusted findings, composed native event
admission/query and actual established Keycloak/OIDC/browser acceptance. Eleven
compound browser/provider checks, eight harness failure regressions and independent
review pass. Unchanged strict718/769 source-bound Rust gates remain applicable.
Absent evidence/admin/rules/audit routes remain404; sign-in uses an established
external client and the existing console token field. See
`target/goal-execution-20261007/SECURITY-ACCESS/idp-acceptance.json` and the
[local IdP contract](43-local-idp-qualification.md). Continue SECURITY-TRANSPORT;
real native/full-CI/cloud/live-tenant/image/release gates remain separate.

SECURITY-TRANSPORT is passed_simulated for its frozen local scope: native mTLS,
shared collector publishing and protected loopback exec health/readiness probes.
Actual19 process/3 current-binary nonroot container/7 chart checks, strict733/784,
both Clippy/fmt/workspace13 and review pass. Current full image/cluster, PKI,
native/fullCI/cloud/vendor/release gates remain separate. Continue SECURITY-AUDIT.
See [transport contract](44-transport-security.md) and
`target/goal-execution-20261007/SECURITY-TRANSPORT/probe-acceptance.json`.

SECURITY-AUDIT is in_progress. Its bounded record/ACK/live actor-reference protocol
passes locally with 6 regressions, strict 739/790 gates and review. Continue the
independent destination/native hooks and secrets/encrypted-storage seams. No
operative collection or encryption proof is inferred. See [audit](45-independent-audit.md).

The restricted audit client/trait is locally accepted. SECURITY-AUDIT stays
in_progress for durable outbox/receiver/native hooks and encryption/secrets seams.
Develop pushes are now owner-authorized; remote CI/native runtime remain gates.

EXT-CI remains external_pending. Pushed880b31e failed both native test jobs;
container/kind were skipped. Locally accepted bounded public Cargo-target failure
classification disables workflow-command parsing around retained raw output.
Six subprocess regressions, five candidate helpers, two actual retained failure
classifications, syntax/workspace13 and review pass. No Rust changes or remote
failure cause is claimed; continue the durable audit outbox/native hooks.

The durable control outbox mechanism is passed_local with nine regressions,
eleven actual subprocess crash boundaries, strict752/803 checks and source review.
SECURITY-AUDIT remains in_progress for native hooks/receiver/health/encryption.
See `target/goal-execution-20261007/SECURITY-AUDIT/outbox-acceptance.json`.
Pushed57c1d1e passes both native Rust Tests steps, but full CI fails the ARM legacy
candidate helper and AMD IdP/browser gate. Partial success closes no full gate.
Continue the reproduced fixture correction and remaining audit integration.

## EXT-CI legacy candidate fixture correction — 2026-10-09

Two fake-Docker legacy candidate tests now explicitly select their intended Linux
AMD64 fixture host. Both actual AMD64 and simulated aarch64 suites pass25/25; a
new negative regression proves production rejects Linux/aarch64 and Darwin before
Docker, retains the failed manifest and preserves unrelated data. The production
legacy helper and dedicated dual-architecture CI helper are unchanged. Five CI
candidate/six diagnostic regressions, syntax/workspace13 and focused review pass.
Rust is unchanged; strict752/803 acceptance remains source-applicable.

Evidence: `target/goal-execution-20261007/EXT-CI/arm-fixture-acceptance.json`,
`arm-fixture-validation/validation.json`, `arm-fixture-review.json`. This corrects a
reproduced local fixture defect; inaccessible remote logs prevent attributing the
exact earlier remote failure. Full remote/native/container/kind gates stay open.
Continue the AMD IdP diagnostics and native audit hooks without a routine stop.

## EXT-CI reported IdP failure stages — 2026-10-09

The CI wrapper now promotes only a fixed public stage enum from a failed IdP
harness's final bounded diagnostic line. It emits the reported stage after the
command-disabled raw output resumes; report paths/free-form payloads are excluded.
This is a reported diagnostic, not authenticated outcome or root-cause evidence.
Eight actual diagnostic regressions, five candidate helpers, syntax/workspace13
and focused review pass. A Unicode character-versus-byte cap review finding was
reproduced, fixed with a UTF-8 byte guard, and passes the final campaign. No Rust,
workflow or IdP behavior changed; strict752/803 acceptance remains applicable.

Evidence: `target/goal-execution-20261007/EXT-CI/idp-stage-acceptance.json`,
`idp-stage-validation-reviewed/validation.json`, `idp-stage-review.json` and
`idp-stage-byte-red/validation.json`. Full remote/native gates remain open.
Continue actual CI inspection and native audit integration.

## Native CI status — 2026-10-09

Run37892977827 on3b172b70 passes both complete native Rust jobs, both production
image builds and basic container runtime/persistence. Both native parser/pipeline/
finite-soak steps fail; kind/supply-chain/candidate stages are skipped. Public
annotations expose only exit1, and anonymous detailed logs return403. The exact
failure cause is unconfirmed. One current-debug AMD64 quick profile passes488
admissions/durable events and20 queries; it cannot qualify either remote image.
Query hook revisionfe5acf3 is pushed; run37895779773 is still in progress as of
07:08UTC. Complete reviewed-revision EXT-CI/EXT-ARM64 remain external_pending.
Evidence: `target/goal-execution-20261007/EXT-CI/idp-stage-remote-jobs-2.json`,
`soak-triage-public/report.json` and `query-hooks-remote-jobs-1.json`.

## SHARED-RUNTIME current continuation — 2026-10-11

The [current runtime](48-shared-control-runtime.md) records source-bound catalog/
query, coordinated profile4-to5 restore and server publication coordinator slices.
The coordinator requires matching final review/gates. Standard startup/WAL/global
findings/private consumers, operational restore/retirement and independent review
remain open. Continue those slices; SHARED-RUNTIME stays in_progress. Older
measurements below retain their original evidence authority and dates.

## SHARED-CONTRACT accepted — 2026-10-09

Bounded Standard schema/transaction/fencing/migration/current-authority restore
contract passes28 negative checks, seven actual isolated PostgreSQL schema checks,
workspace13 and independent review. Exact feed prefix/global deduplication and
zero-prepared receipt semantics remain compatible. Two bounded checks are added
to the existing native CI matrix. This is passed_local design only; continue
SHARED-RUNTIME without enabling replicas or claiming HA. See [47](47-shared-control-contract.md).

## SMALL-PILOT accepted — 2026-10-09

Actual one-record protected/S3/finding-feed/private-notification composition passes
in20.196s with two objects, one finding/page/delivery, three attempts and final
checkpoint1/drop0. Private77 strict tests,12 helper regressions, workspace13 and
independent retained-witness/source review pass. Source coverage remains Unknown;
cloud/native/image/capacity/shared/release gates stay separate. Continue the frozen
SHARED-CONTRACT; no new services or public policy. See [46](46-small-pilot.md).

## SECURITY-AUDIT local closeout — 2026-10-09

Restricted actual four-UID receiver/monolith/producer/health composition passes
62checks/12 original receipts,18 guard tests and complete witness/source review.
28 wrapped role/rotation helpers and unchanged workflow structure pass. Earlier
hook/store/health/IdP/DAC, credential recovery and KMS request-policy seams combine
into passed_simulated local acceptance; external encrypted-media/provider/cloud/
current-image/full-native-CI gates remain. Continue SMALL-PILOT, then the frozen
shared-control contract. See [audit contract](45-independent-audit.md).

## Current browser readiness and native CI — 2026-10-09

The reproduced partial port-file race is corrected within the same10s clock;
14/12 helper tests,11 actual current-binary local browser/IdP checks and review
pass. Latest153dafd complete ARM64 Rust job passes; AMD64 tests pass but full job
fails reported browser-start, native downstream skipped. No remote cause claim.
See [CI contract](40-oss-ci-and-cloud-qualification.md);52 unchanged.

## Current audit rotation and recovery seam — 2026-10-09

Actual explicit-host credential capture/revocation/current-authority restore passes
45checks/six original receipts,10 helper tests and review. Exact pending replay,
fresh query pair and complete witness checks pass; provenance guards were corrected.
No actual cloud secret provider, encryption or independently fresh restore claim.
Continue networked distinct-UID qualification inside SECURITY-AUDIT;52 unchanged.
See [audit contract](45-independent-audit.md).

## Current fixed pipeline diagnostics — 2026-10-09

Fixed profile/check/kind sidecar plus native/CI propagation passes5/19/16/5 helper
tests, independent FIFO-guard review and workflow wiring with11/24 audit helpers.
Qualification assertions/limits stay intact; reported phase is not remote cause.
315 ARM failure target is signal-agent --test process, inner assertion unknown.
EXT-CI remains external_pending; continue SECURITY-AUDIT;52 unchanged.

## Current explicit S3 KMS request selection — 2026-10-09

Optional bounded explicit key/bucket-key selection passes four new feature
regressions,819/874 strict checks and review. Signed write policy, pinned older
reads and denied-write nonfallback are local facts, not encrypted-media proof.
Dedicated secret rotation/current-authority restore and role composition remain
inside SECURITY-AUDIT. See [audit contract](45-independent-audit.md);52 unchanged.

## Current verified identity/audit composition — 2026-10-09

Actual local Keycloak/native ingest-query/independent receiver composition passes
32checks,17 synced receipts,102 health observations,11 new/eight existing helpers
and review. SameUID/debug/manual health scope; distinct-UID role composition and
secrets/encryption remain. See [audit contract](45-independent-audit.md);52 unchanged.

## Current restricted receiver file-access proof — 2026-10-09

Twenty-seven native checks,36 actual EACCES denials,24 guard regressions and
review qualify the partial distinct-UID DAC fixture. Other identities run probes;
actual distinct-UID monolith/producer/health TLS and outage composition follows.
Secrets/encryption remain. See [audit contract](45-independent-audit.md);52 unchanged.

## Current reusable receiver health probe — 2026-10-09

Strict unchanged version1 aggregate and separately authenticated bounded SDK probe
passed_local with five new compound HTTP/mTLS/protocol/clock regressions,
819/870strict tests and review. Original physical receipt time, independent probe
worker, held503 observation and failed-probe nonrenewal retain private owner's
assessment/expiry boundary. Permission/IdP/secrets/encryption checks remain inside
SECURITY-AUDIT;52 unchanged. See [audit contract](45-independent-audit.md).

## Current automatic target diagnostic — 2026-10-09

CI public target inventory includes automatic integration tests with incremental
bounded scanning, cycle/outside-root refusal and source-only annotations.
15helper tests and review pass. No pastfailurecause or full native/release gate
is inferred; EXT-CI remains external_pending,52 unchanged. Continue SECURITY-AUDIT.

## Current independent receiver composition — 2026-10-09

Real monolith/receiver/separate health-owner passed37 local process checks,11
actual receipts and16 current health observations. SIGKILL survival, selected
query outage503/no private result, exact pending replay then fresh activations/
query evidence pass. SameUID/debug/synthetic only; permission/healthSDK/IdP/
secrets/encryption remain within SECURITY-AUDIT. Frozen52 unchanged.

## Current independent receiver host — 2026-10-09

Explicit isolated role and initializer passed_local with seven actual HTTP/store
regressions,814/865strict tests and review. Finite fixed authenticated producer
membership, distinct health credential/TLS roots, bounded original clocks/body,
no-store exact ACK and no-disk aggregate health retain existing monolith boundary.
Actual independent native/health-owner/permission/IdP/secrets/encryption acceptance
remains within SECURITY-AUDIT;52 unchanged. See [audit contract](45-independent-audit.md).

## Current independent HTTP transport — 2026-10-09

Generic engine passed_local: four new lease/lifetime/abort/pipeline regressions,
44focused and807/858strict tests, both Clippy/fmt/workspace13 and source review.
No fabricated ingest service or readiness; original clock and socket lifetime
own the operation lease. Actual receiver authentication/health host remains next
within SECURITY-AUDIT. See [audit contract](45-independent-audit.md);52 unchanged.

## Current independent receipt store — 2026-10-09

Bounded SDK journal passed_local:11 compound regressions, five actual crash stages,
final strict 803/854 and review. High length-growth deletion and medium prewrite
cancellation races reproduced red and fixed; original bytes/exact retries survive.
Receiver host/TLS/separate health/permissions/native IdP/secrets/encryption remain
next inside frozen SECURITY-AUDIT. Store hashes/ACK do not prove current restore
or complete collection. See [audit contract](45-independent-audit.md);52 unchanged.

## Current startup activation slice — 2026-10-09

Actual prepared runtime resource/rules startup activation passed_simulated:
strict 792/843, six source regressions, review and 88 actual
AMD64/mTLS/fsynced-peer checks. One original60s selected preparation/confirmation
clock; fresh exact records before consumer/transport enable; installed state only.
Runtime revision exclusions and receiver/health/native IdP/secrets/encryption
follow-on are explicit in [audit contract](45-independent-audit.md). Continue the
bounded independent receiver mechanism inside SECURITY-AUDIT; frozen52 unchanged.

## Current rules revision primitive — 2026-10-09

Bounded retained-rule projection passed_local: eight regressions, strict 786/837,
review, both Clippy/fmt/workspace13. No whole projection/tree clone or reread;
private typed definitions feed only a caller-owned memory/hash sink under the
original clock/cancellation and hard64MiB cap. Actual startup activation is next.
Parent SECURITY-AUDIT stays in_progress; frozen item/counts do not change.
See [audit contract](45-independent-audit.md) and `rules-revision-acceptance.json`.

## Current native ingest audit slice — 2026-10-09

Selected ingest uses a generic consuming session and the same bounded monolith
Control/outbox. Strict 778/829, review and 50 actual AMD64/mTLS process
checks pass. Lost/late replies withhold receipts through retry uncertainty while
actual WAL effects/counters survive; no rollback. Parent remains in_progress for
runtime/rule activation, IdP/audit composition, receiver/health/secrets-encryption.
See [audit contract](45-independent-audit.md); frozen item/counts stay unchanged.

## Current native CI diagnostic slice — 2026-10-09

Fixed native stages are reported after cleanup and allowlisted after disabled raw
workflow output. CI10/native19/candidate5 helpers, syntax/workspace13 and review
pass, including a red/green late interruption that can no longer preserve success.
Remote cause and full qualification remain open. Resume native ingest audit hooks.
See `target/goal-execution-20261007/EXT-CI/native-stage-acceptance.json`.

## Current native coverage audit slice — 2026-10-09

Selected query/findings/feed/coverage read-write hooks share one bounded control
outbox/session. Coverage passed_simulated: strict768/819, review and
93 actual AMD64/mTLS/fsynced-peer checks. Parent remains in_progress for
ingest/runtime activation hooks, receiver/independent health and secrets/encryption.
See [audit contract](45-independent-audit.md); no frozen item/count changes.

## Current native findings audit slice — 2026-10-09

Selected query/findings/feed hooks share one bounded outbox/session. Findings
slice passed_simulated: five new regressions, strict763/814, focused reviews and
59 actual AMD64/mTLS/fsynced-peer checks. Parent SECURITY-AUDIT remains in_progress
for coverage/ingest/runtime activation hooks, receiver/health and secrets/encryption.
Native IdP composition and full current-revision CI/release qualification stay open.
See [audit](45-independent-audit.md) and `findings-hooks-acceptance.json`.

## Current native audit query slice — 2026-10-09

Query-only hook passed_simulated: six focused regressions, strict758/809 checks,
source review and27 actual AMD64 monolith/mTLS/fsynced-peer checks. No-store
review failure corrected. Continue findings/coverage/ingest and runtime/rule
activation hooks, then receiver/independent health/secrets-encryption within the
existing SECURITY-AUDIT item. Scope remains query-only; enabled IdP and production
receiver qualification are not inferred. See [audit](45-independent-audit.md).

## Execution and evidence

One coherent writer change set at a time. Verify, resolve focused review, record
evidence and continue the next dependency-ready item without a routine approval
stop. This Goal authorizes post-MVP implementation and bounded independent
review/testing; it does not authorize external provisioning or publication.
Use statuses `pending`, `in_progress`, `passed_local`, `passed_simulated`,
`passed_external`, `external_pending`. `passed_external` requires actual external
execution matching the item and exact producing revision; local/synthetic evidence
cannot substitute. A dependency with both local and external aspects must be
split: local simulation acceptance never satisfies the real environment gate.
Do not convert complexity or ordinary test failure into an external exception.

The ledger fixes capabilities, not hypothetical scale promises. Contracts for
unimplemented capabilities must be made executable within their existing item
before code. Profile claims require actual measurements. Scale worker separation
is conditional on evidence; a justified no-split decision satisfies that item.
Advanced SOC UX remains post-MVP; universal SOAR/AI RCA/APM and other explicit
product non-goals are excluded. Actual enabled policy/configuration/routing and
private fixtures stay in the private repository. Its writes require the correct
writable scope, not a reverse dependency or copied private data in public core.

Simulations use isolated local endpoints and synthetic identities. Test relevant
rate limits, paging, duplicates, malformed data, scope denial, crashes, replay,
uncertain effects and retention exhaustion. Local evidence is never native
ARM64, actual AWS/EKS, live vendor or remote CI evidence. No full release claim
while these gates remain open. Retain final candidate bindings and documented
external exceptions even after the local Goal is complete.

The frozen retirement contract requires a confirmed source ACK. Therefore ACK
control follows the qualified owner-handover/reconciled-open substeps, then
retirement completes RECEIPT-RECOVERY. This corrects the initial dependency order
without adding capabilities or claiming general recovery from copied bits.

## Frozen inventory

| Item | Status | Depends on | Outcome |
| --- | --- | --- | --- |
| CORE | passed_local | — | Core phases 0–8, bounded phase 10 and minimal SecOps UI |
| COVERAGE | passed_local | CORE | Bounded SourceCoverage history/intake/corrections/pruning/scans |
| RECEIPT-BASE | passed_local | CORE | CloudTrail normalization/profile and initial receipt store |
| RECEIPT-PROGRESS | passed_local | RECEIPT-BASE | Atomic verified-prefix progress and immutable suffix replay |
| RECEIPT-RECOVERY | passed_local | RECEIPT-PROGRESS, SOURCE-ACK | Retirement, owner takeover and restore reconciliation |
| SOURCE-ACK | passed_local | RECEIPT-PROGRESS | Source acknowledgement and selected custody seam |
| OBJECT-READER | passed_local | RECEIPT-RECOVERY | Bounded CloudTrail gzip object reader/preparation |
| AWS-DELIVERY | passed_simulated | SOURCE-ACK, OBJECT-READER | CloudTrail S3/SQS collector and local delivery simulation |
| COVERAGE-OBSERVERS | passed_simulated | COVERAGE, AWS-DELIVERY | Source observers, health and SDK/server integration |
| FINDINGS-CURSOR | passed_local | CORE | Durable public findings cursor runtime |
| OUTBOX | passed_simulated | FINDINGS-CURSOR | Private transactional finding cursor/outbox and notification simulation |
| DISPOSITIONS | passed_local | OUTBOX | Disposition/outcome backend seam |
| EVIDENCE | passed_simulated | AWS-DELIVERY | Independent protected original route and validation simulation |
| S3-QUERY | passed_simulated | CORE | Object-backed Parquet and committed query manifests |
| RETENTION | passed_simulated | S3-QUERY, EVIDENCE | Selective query acceleration, retention and cost controls |
| SECURITY-ACCESS | passed_simulated | CORE | OIDC/trusted identity, scoped credentials and RBAC |
| SECURITY-TRANSPORT | passed_simulated | SECURITY-ACCESS | mTLS and credential/certificate rotation |
| SECURITY-AUDIT | in_progress | SECURITY-ACCESS, EVIDENCE | Restricted independent audit and secrets/encryption integration seams |
| SMALL-PILOT | pending | AWS-DELIVERY, COVERAGE-OBSERVERS, OUTBOX, EVIDENCE, S3-QUERY, SECURITY-TRANSPORT | Small source→evidence→finding→notification simulation |
| SHARED-CONTRACT | pending | SMALL-PILOT | PostgreSQL shared-control schema, transactions, fencing and migration contract |
| SHARED-RUNTIME | in_progress | SHARED-CONTRACT | Shared-control implementation and local PostgreSQL qualification |
| OBJECT-CUSTODY | pending | SHARED-RUNTIME, S3-QUERY | Versioned object-backed custody receipt |
| STANDARD-RECOVERY | pending | OBJECT-CUSTODY, SECURITY-AUDIT | Standard ownership, failover and consistent restore simulation |
| ONBOARDING | pending | COVERAGE-OBSERVERS, SECURITY-ACCESS, SHARED-RUNTIME | Secure scoped onboarding and coverage/detection activation |
| CLOUDWATCH | pending | SMALL-PILOT | Bounded CloudWatch managed-log intake |
| AWS-PROFILES | pending | CLOUDWATCH, OBJECT-READER | AWS RDS/ALB/NLB/ECS/VPC/DNS/WAF/security-event profiles |
| EKS-AUDIT | passed_simulated | SMALL-PILOT | Kubernetes audit normalization and bound agent file delivery; actual kind/D07/uncertain-ACK replay accepted locally ([71](71-kubernetes-audit-agent.md)); EKS CloudWatch remains deferred |
| K8S-CONTEXT | in_progress | EKS-AUDIT | Independently reviewed API/kind,CRI,rooted filesystem and durable spool prerequisites pass ([77](77-kubernetes-node-spool.md)); dedicated node producer and actual collection/recovery remain |
| HOST-AUTH | pending | SMALL-PILOT | Selected host/runtime and authentication source profiles |
| SYSLOG | pending | SECURITY-TRANSPORT, SOURCE-ACK | Site TCP/TLS syslog and FortiGate normalization |
| M365 | pending | SMALL-PILOT | Selected Microsoft 365 audit/authentication API feeds |
| CATO | pending | M365 | Cato API event collection |
| CLOUDFLARE | pending | OBJECT-READER, SMALL-PILOT | Cloudflare object-delivery normalization |
| BASELINES | pending | EKS-AUDIT | Versioned generic baseline predicate packs |
| WINDOW | passed_simulated | FINDINGS-CURSOR, HOST-AUTH, COVERAGE-OBSERVERS | First bounded window detector D10 |
| STATE | pending | WINDOW, BASELINES, K8S-CONTEXT | Scoped state lookup detectors D04/D06/D08/D09/D13 (D12 deferred to AWS-PROFILES) |
| SENSOR-HEALTH | in_progress | COVERAGE-OBSERVERS, WINDOW | Independent missing-telemetry detector D15 |
| CORRELATION | pending | STATE, DISPOSITIONS, CATO, M365, SYSLOG | Bounded multi-stream episodes D11/D14 |
| SOC-UX | pending | CORRELATION, DISPOSITIONS, SECURITY-ACCESS | Planned advanced SOC case/disposition/workbench workflows |
| PROFILE-LOAD | pending | STANDARD-RECOVERY, CORRELATION | Resource/profile and controlled-outage qualification |
| SCALE-DECISION | pending | PROFILE-LOAD | Measured Scale profile worker-separation decision |
| KIND | pending | CORE | Current-revision local Kubernetes persistence/restart gate |
| RELEASE-REVIEW | passed_local | RECEIPT-PROGRESS | Independent source review and resolve findings |
| RELEASE-TRUST | pending | BASELINES, SECURITY-TRANSPORT | SBOM, provenance and signed release/rule verification |
| UPGRADE | passed_simulated | SHARED-RUNTIME, STANDARD-RECOVERY | Supported migration/rollback/restore local rehearsals |
| LOCAL-CANDIDATE | pending | SOC-UX, SCALE-DECISION, KIND, RELEASE-REVIEW, RELEASE-TRUST, UPGRADE | Final current-revision local release candidate |
| EXT-ARM64 | passed_external | — | Native ARM64 qualification |
| EXT-AWS | external_pending | — | Actual AWS/EKS/storage/IAM/KMS/Object Lock qualification |
| EXT-VENDORS | external_pending | — | Live SaaS/network-provider qualification |
| EXT-CI | passed_external | — | Remote CI for reviewed revision |
| EXT-DEPENDENCY | external_pending | — | Private overlay against actual released public dependency |
| EXT-PUBLICATION | external_pending | — | Owner-directed version, publication and main merge |

CLOUDFLARE selected object profile passes simulated acceptance — 2026-10-14. Shared bounded complete-gzip decoding preserves CloudTrail behavior; selected http_requests RFC3339 records enforce five fields, configured account/zone scope and explicit unknown completeness. Four new and seven existing object regressions and six frozen gates pass (962 default / 1023 all-feature tests). Late malformed rows, gzip corruption, limits, cancellation and deadline reject; exact pinned context replays byte-identical events. Evidence: `target/cloudflare-profile-20261014/ACCEPTANCE.json`; [profile contract](59-cloudflare-logpush-profile.md). Actual vendor delivery, durable private custody/ACK and coverage remain external. Inventory:30 accepted /22 unfinished ({'passed_local': 13, 'passed_simulated': 15, 'pending': 18, 'passed_external': 2, 'external_pending': 4}).

SYSLOG parser/framing slice — 2026-10-14. Four new SDK fixtures and eight frozen gates pass: 966 default / 1027 all-feature tests, both strict Clippy modes, formatting,14workspace boundaries and actual agent/server process recovery. Bounded octet-counting handles split/coalesced UTF8 byte frames and refuses malformed lengths/incomplete EOF. Selected FortiGate native time/severity stays separate from configured source authority. Two valid/two rejected records qualify real file/spool/server outage/SIGKILL exact canonical replay and cursor restart. [Contract60](60-syslog-fortigate-profile.md), evidence:`target/syslog-20261014/ACCEPTANCE.json`. Full SYSLOG remains pending site TCP/TLS listener/source identity/connection and read bounds/composed outage replay; UDP best effort. Inventory remains30accepted/22unfinished.

SYSLOG passes local simulated acceptance — 2026-10-14. Dedicated TCP/mTLS selected FortiGate receiver binds configured source to an authenticated, exact-pinned client leaf, rejects missing/expired/untrusted/wrong peers, and bounds connections/frames/bytes. Actual native fixture qualifies saturated spool backpressure, split/coalesced frames, malformed/EOF refusals, original partial-frame deadline, WAN outage/SIGKILL exact canonical replay and cancellation of active TLS during shutdown. Eleven composed checks and8frozen gates pass:967default/1028all-feature, both strict Clippy modes, formatting,14workspace boundaries and fresh binaries. Native CI now includes the syslog gate on both architectures; matching results are pending. [Contract60](60-syslog-fortigate-profile.md), evidence:`target/syslog-transport-20261014/ACCEPTANCE.json`. Synthetic devices/certificates; actual firmware/buffers/customer coverage/site loss/raw-original custody remain unqualified. Plaintext loopback-only; UDP best effort/unsupported. Inventory:31accepted/21unfinished (13local/16simulated/2external accepted/17pending/4external pending). Next dependency-ready release item:M365; Phase9 AWS collection remains separately scoped.

Native ARM cancellation fixture correction — 2026-10-14. Primary GitHub-digest-verified parser run38601684472 at9bbfce6 fails query admission_saturation_cancellation_and_expiry_release_capacity with Busy. The test assumed physical I/O retirement immediately after front cancellation; the neighboring dropped-future test already observes the retained lease. Correction waits finitely for physical io_depth0, checks running/depth capacities and preserves immediate front-depth0, exact original event and rejection/timeout/cancellation counters. Five frozen gates pass:967default workspace tests,17all-feature query regressions, strict Clippy/fmt/14workspace boundaries. No production change. Evidence:`target/query-cancel-ci-20261014/ACCEPTANCE.json`; matching current nativeCI remains pending. SYSLOG remains passed_simulated; inventory31accepted/21unfinished.

M365 passes selected local provider simulation — 2026-10-14. Bounded Management Activity Audit.AzureActiveDirectory HTTP composes token refresh/429/5xx/outage and finite paged originals/prepared outbox/checkpoints through a trusted private journal hook. Actual filesystem sync/lost commit reply/fresh reload and owned child SIGKILL preserve canonical values and cursor; dedup/conflicts/malformed content/window changes/cycles/expiry refuse without durable advancement. Documented v1 continuation, equivalent UTC window spellings and missing publisher are handled while preserving raw cursor/effective request and exact source scope. Prepared IDs bind window/publisher/source/native identity. Six frozen gates pass979default/1040all-feature, both strict Clippy modes, formatting and14workspace boundaries;11integration and1delivery-identity regressions. [Contract61](61-m365-activity-profile.md), evidence:`target/m365-20261014/ACCEPTANCE.json`. Actual Microsoft permissions/subscriptions/credential exchange/current independent coverage and private host custody remain separate. Inventory32accepted/20unfinished (13local/17simulated/2external accepted/16pending/4external pending). Matching current nativeCI remains pending. Next dependency-ready source:CATO; Phase9 AWS remains separately scoped.

CATO passes selected local provider simulation — 2026-10-14. One-account Security eventsFeed POST uses current official schema, configured account/TLS/key hook and explicit latest/resume. Original deadlines/cancellation bound retries, key retrieval and complete entity capture; complete page originals/prepared events/checkpoints commit through a trusted private atomic journal. Actual fsync/lost reply/fresh reload and child SIGKILL retain exact canonical values and cursor. Scope/GraphQL/malformed/cycle/expired/capacity refusals preserve durable bytes; chunked-body limits and single-slot admission are qualified. Six frozen gates pass990default/1051all-feature, both strict Clippy modes, formatting and14workspace boundaries;11integration tests. [Contract62](62-cato-eventsfeed-profile.md), evidence:`target/cato-20261014/ACCEPTANCE.json`. Opaque marker validity/independent completeness, cross-page native dedup, actual Cato permissions/retention and private custody/publication remain unqualified. Inventory33accepted/19unfinished (13local/18simulated/2external accepted/15pending/4external pending). Matching current nativeCI remains pending. Next authorized source slice:HOST-AUTH native runtime sensor coverage; Phase9 AWS remains separately scoped.

HOST-AUTH runtime foundation passes local simulation — 2026-10-14. Selected Falco0.44.1 SDK syscall/process-start and explicit drop/lookup/boot/start/reload health counters compose agent falco-json with configured host/boot binding. Real local file/spool/SIGKILL/server/query replay retains five synthetic canonical records exactly. Missing/duplicate identities, credential-bearing/freeform fields, obsolete evt.dir, wrong engine and missing counters refuse; file opens do not prove credential reads. Pinned CLI field/rule validation passes without kernel capabilities; native ephemeral GitHub capture is wired for both architectures with finite output/deadline/PID/parent/interval/counter/cleanup checks. Nine frozen gates pass994default/1055all-feature, both strict Clippy modes, formatting,14workspace boundaries, fresh binaries, simulated delivery and workflow lint. [Contract63](63-falco-runtime-profile.md), evidence:`target/host-runtime-20261014/ACCEPTANCE.json`. Full HOST-AUTH remains pending actual matching native capture and coverage qualification. Inventory stays33accepted/19unfinished; no native sensor or production current coverage granted by synthetic records.

Native runtime probe wiring passes locally — 2026-10-14. Separate hosted AMD64/ARM64 workflow obtains actual owned Falco capture before compiling only the collector SDK and invoking an explicitly native-only projection test. Three refusal checks prevent non-CI capture, simulation-as-native and absent-manifest projection. Nine frozen gates pass994default/1055all-feature, both Clippy modes, formatting,14workspace boundaries, workflow lint and exact five-record simulated delivery. Evidence:`target/host-runtime-probe-20261014/ACCEPTANCE.json`. Native probe and original full composed CI remain required; HOST-AUTH stays pending and inventory stays33accepted/19unfinished. This shortens native schema feedback without replacing full server/spool/replay qualification.

Native runtime probe corrections pass locally — 2026-10-14. Primary-digest-verified AMD64/ARM64 run38624220049 at20aff08 fails before kernel capture because no rule file is loaded. Explicit owned minimal Falco configuration and -c/-r selection now pass capability-free dry-run. A separately reproduced Cargo crate-working-directory failure is corrected with workspace-root capture resolution; four refusal checks pass. Nine frozen gates pass994default/1055all-feature, both Clippy modes, formatting,14workspace boundaries, workflow lint and exact five-record simulated delivery. Evidence:`target/host-runtime-probe-fix-20261014/ACCEPTANCE.json`; original artifacts:`target/host-runtime-probe-20261014/failed-native/`. Corrected native capture/SDK projection and full original composed CI remain required. HOST-AUTH stays pending; inventory33accepted/19unfinished.

Verified native runtime schema correction passes locally — 2026-10-14. Primary-digest-verified run38626726116 at eece8c0 captures real execution/file-open/connection hooks on both native architectures with zero kernel drops and explicit lookup counters; later SDK projection fails on actual Falco shape. Corrected SDK accepts only the fixed internal metric literal, checks injected evt.time equality, and validates boot/reload/capture/event bounds without assuming reload follows capture start. Both real captures project locally; fresh current agent/server retains nine canonical records each exactly through synced offline spool/SIGKILL/restart/query. Eleven frozen gates pass995default/1056all-feature, both Clippy modes, formatting,14workspace boundaries, fresh build, both retained native delivery campaigns, refusal checks and workflow lint. Evidence:`target/host-native-schema-20261014/ACCEPTANCE.json`. Local replay is distinct from current native ARM64 execution. Develop pushes supersede obsolete same-ref CI; tag/release workflows are unchanged. Matching current native projection/full composed CI and independent coverage remain open; HOST-AUTH pending, inventory33accepted/19unfinished.

HOST-AUTH passes selected local/native simulation acceptance — 2026-10-14. Primary-digest-verified run38630135235 at42df283 provides both actual native AMD64/ARM64 kernel execution/file-open/connect capture, explicit drop/lookup counters and exact nine-record complete agent/spool/SIGKILL/server/query replay per architecture. Source/raw hashes, boot/process-start/PID/parent bindings, unique retained IDs and capture cleanup are verified. Authentication source remains qualified by its strict local profile. Evidence:`target/host-native-schema-20261014/HOST-AUTH-ACCEPTANCE.json`; [contract63](63-falco-runtime-profile.md). Production independent coverage, full-host visibility, credential-read proof, actual customer setup and prolonged/physical-device behavior are not assessed. Inventory34accepted/18unfinished; next authorized dependency-ready item:WINDOW event-time detector. Full current native container/Kubernetes/supply-chain qualification and external release gates remain separate.

WINDOW is in_progress — 2026-10-15. Actual Standard Main bootstrap/quota refusal,
split-batch watermark, exact retry and confirmed/blocked-publication SIGKILL
recovery pass six scenarios (137.91s); the refreshed53-check shared campaign passes
177.87s with owned cleanup. Evidence is linked in the machine ledger. Whole Small
Main crash qualification, timestamp compatibility, review and full acceptance
remain; inventory stays34accepted/18unfinished.

WINDOW passes local simulation acceptance — 2026-10-15. Bounded authentication event-time/watermark/lateness, canonical replay identity, key/event/byte/TTL/output/history limits, unknown coverage and atomic state/findings/checkpoint recovery are qualified. Six frozen workspace gates pass1048default/1117all-feature tests, both strict Clippy modes, formatting and14workspace boundaries. Actual Small Main passes5WINDOW/8onboarding checks; Standard Main passes8scenarios; shared recovery passes53checks in206.73s. Runtime source bindings109/266/246 match; retained Small/Standard executable identities match and owned cleanup succeeds. Writer review closed three reproduced findings; it is not independent release review. Evidence:`target/window-20261014/ACCEPTANCE.json`; [contract64](64-authentication-window.md). LinuxAMD64 with actual SQLite/PostgreSQL/Parquet/WAL and SIGKILL; signed host/object authority is synthetic. Inventory35accepted/17unfinished. Current remote/native/container/Kubernetes, AWS/EKS, released dependencies, version and publication remain separate. Next local dependency-ready detector:SENSOR-HEALTH; Phase9 AWS collection requires a separate task.

SENSOR-HEALTH foundation advances — 2026-10-15. A bounded pure evaluator now pins
expected inventory, source binding, observer identity and policy revision. It
separates overdue heartbeats from unknown/stale/unhealthy observers, preserves
original freshness through replay/restore, refuses clock/checkpoint/identity
regressions and caps inventory/state bytes. Eleven focused regressions and four
frozen workspace gates pass: 1,059 tests, zero failures, strict Clippy, formatting
and 14 workspace boundaries. Writer review and exact evidence:
`target/sensor-health-20261015/ACCEPTANCE.json`; [contract65](65-sensor-health.md).
SENSOR-HEALTH is in progress; the authenticated independent-observer adapter,
Main lifecycle, atomic outbox/checkpoint and actual crash recovery remain required.
Inventory stays 35 accepted / 17 unfinished. WINDOW native CI at `57024b7` remains
live and unqualified; hold another develop push to preserve that campaign.

SENSOR-HEALTH signed observer seam advances — 2026-10-15. The server library now
verifies bounded original payload bytes with an owner-enrolled Ed25519 observer
key and separate signature domain. Exact policy/source/observer binding and
half-open freshness agree with the evaluator; replay cannot renew verification.
A complete enrollment digest includes all keys for the pending durable recovery
binding. Twelve crypto/bridge regressions, eleven evaluator regressions and four
frozen workspace gates pass: 1,071 tests, zero failures, strict Clippy, formatting
and 14 workspace boundaries. Evidence and writer review:
`target/sensor-health-adapter-20261015/ACCEPTANCE.json`; [contract65](65-sensor-health.md).
This is a verification-library slice. SENSOR-HEALTH remains in progress until
native Main admission/cadence, atomic original outbox/checkpoint, bounded history
and actual crash recovery are qualified. Inventory stays 35 accepted / 17 unfinished.
GitHub reports both Small/Standard WINDOW steps passed on AMD64/ARM64 at `57024b7`;
full native/container CI and primary artifact verification are still pending.

SENSOR-HEALTH atomic journal primitive advances — 2026-10-15. A single retained
worker now commits opaque detector state, original outbox bytes and checkpoint in
one SQLite transaction, with exact source/enrollment/config binding, revision CAS,
immutable pending prefixes and explicit confirmed-publication retirement. Actual
SIGKILL before/after commit and SQLite cancellation/drop/timeout prove complete
frame recovery and retained physical capacity. Journals share the existing
16-worker process cap. Review reproduced and fixed a literal SQLite internal-name
prefix bug; the earlier campaign is superseded. Eleven journal regressions and four
corrected frozen gates pass: 1,082 tests, zero failures, strict Clippy, formatting
and 14 workspace boundaries. Evidence:
`target/sensor-health-journal-20261015/ACCEPTANCE.json`; [contract65](65-sensor-health.md).
This is the storage/worker primitive. Typed native evidence validation, Main
admission/cadence, history/metrics, Standard integration and actual detector recovery
remain required. SENSOR-HEALTH stays in progress; inventory 35 accepted / 17 unfinished.

WINDOW native evidence at `57024b7` — 2026-10-15. Both native Rust jobs and the complete
[CI run38697027736](https://github.com/mischapogr/platform-signal/actions/runs/38697027736)
pass, including both container/Kubernetes jobs. Primary-digest-verified Rust
archives qualify five Small WINDOW checks, eight onboarding checks and eight
Standard scenarios per architecture. All 269 unique source blobs match that
revision; 109/266 per-report source bindings and Small/Standard executable hashes
match. Each Small fixture reaps 15 children with four actual SIGKILL exits;
Standard cleanup and seven reader-permission refusals pass. Standard elapsed:
156.78s AMD64 / 157.13s ARM64. Exact bounded proof:
`target/window-ci-20261015/VERIFIED-NATIVE-WINDOW.json`. Host/object authority is
synthetic. Final container artifact inspection and later SENSOR-HEALTH revisions
remain separate; no AWS/EKS/released dependency/version/publication claim.

Journal writer-lease CI correction — 2026-10-15. Run38703433824 at `a37f795`
passes ARM64 Rust but fails AMD64 tests on an immediate journal reopen returning
Busy after owner drop; downstream container jobs are skipped. The primary-digest-
verified failure archive and a deterministic duplicated-descriptor regression
reproduce the same lingering-lock mechanism. Explicit shared-description unlock
now follows physical SQLite close in both generic and Window journals; genuine
contention remains Busy, other lock errors remain journal failures. Exact remote
subprocess inheritance was not observed and remains an inference. No timeout
increase or retry was added. An isolated checkout of that revision plus only the
five-file correction passes six frozen gates: 1,083 default / 1,152 all-feature
tests, both strict Clippy modes, formatting and 14 workspace boundaries. Evidence:
`target/ci-journal-lease-20261015/ACCEPTANCE.json`. Fresh native CI is required.
The uncommitted SENSOR-HEALTH native-session/causal-deadline work is excluded from
this correction and its acceptance. Inventory stays 35 accepted / 17 unfinished.

## Sensor-health Small native integration — 2026-10-15

SENSOR-HEALTH Small Main slice passes locally — 2026-10-15. Strict owner-controlled configuration and signed canonical admission, independent observer cadence, atomic original evidence/state/finding outbox/checkpoint, publication before WAL ACK, expiry-safe numeric metrics and original-deadline shutdown are integrated. Seven frozen gates pass 1097default/1166all-feature tests, both strict Clippy modes, formatting and14workspace boundaries in581.59s. Actual Small Main passes7sensor/8onboarding checks with122matching source bindings and actual SIGKILL/pending-outbox recovery. Writer review corrected causal deadline, file-loader ceiling, admitted-report expiry and an all-feature audit initializer; it is not independent release review. Evidence:`target/sensor-health-native-20261015/ACCEPTANCE.json`; [contract65](65-sensor-health.md). LinuxAMD64/SQLite/WAL/findings are actual; observer/identity authority is synthetic. Bounded history/retention, Standard integration and whole/current native release qualification remain required. SENSOR-HEALTH stays in_progress; inventory 35accepted/17unfinished. No release or publication acceptance.

## Sensor-health retained history — 2026-10-15

SENSOR-HEALTH bounded history slice passes locally — 2026-10-15. Original assessment changes, rule revision and signed canonical evidence are retained with explicit row/byte/TTL limits and persisted expiry/oldest-eviction counters. Shared state capacity evicts old history before refusing current progress; single unrepresentable assessments roll back atomically. Historical NoMatch never renews observer authority, and expiry preserves the original pending finding outbox. Native schema2 and changed history limits refuse silent recovery. Seven frozen gates pass1103default/1172all-feature tests, both strict Clippy modes, formatting and14workspace boundaries in529.75s. Actual Small Main passes8sensor/8onboarding checks with123matching source bindings,21numeric sensor metrics and actual SIGKILL recovery. The campaign also corrected an existing test-only retirement witness race by publishing synced witness bytes through atomic rename; production storage is unchanged. Evidence:`target/sensor-health-history-20261015/ACCEPTANCE.json`; writer review is not independent release review. Standard integration and whole/current native qualification remain open; SENSOR-HEALTH stays in_progress,35accepted/17unfinished.

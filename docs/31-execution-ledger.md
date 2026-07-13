# Finite execution ledger

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
`external_pending`. A dependency with both local and external aspects must be
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
| SHARED-RUNTIME | pending | SHARED-CONTRACT | Shared-control implementation and local PostgreSQL qualification |
| OBJECT-CUSTODY | pending | SHARED-RUNTIME, S3-QUERY | Versioned object-backed custody receipt |
| STANDARD-RECOVERY | pending | OBJECT-CUSTODY, SECURITY-AUDIT | Standard ownership, failover and consistent restore simulation |
| ONBOARDING | pending | COVERAGE-OBSERVERS, SECURITY-ACCESS, SHARED-RUNTIME | Secure scoped onboarding and coverage/detection activation |
| CLOUDWATCH | pending | SMALL-PILOT | Bounded CloudWatch managed-log intake |
| AWS-PROFILES | pending | CLOUDWATCH, OBJECT-READER | AWS RDS/ALB/NLB/ECS/VPC/DNS/WAF/security-event profiles |
| EKS-AUDIT | pending | CLOUDWATCH | EKS/Kubernetes audit adapter |
| K8S-CONTEXT | pending | EKS-AUDIT | Node/workload context and cluster collector mode |
| HOST-AUTH | pending | SMALL-PILOT | Selected host/runtime and authentication source profiles |
| SYSLOG | pending | SECURITY-TRANSPORT, SOURCE-ACK | Site TCP/TLS syslog and FortiGate normalization |
| M365 | pending | SMALL-PILOT | Selected Microsoft 365 audit/authentication API feeds |
| CATO | pending | M365 | Cato API event collection |
| CLOUDFLARE | pending | OBJECT-READER, SMALL-PILOT | Cloudflare object-delivery normalization |
| BASELINES | pending | EKS-AUDIT, AWS-PROFILES | Versioned generic baseline predicate packs |
| WINDOW | pending | FINDINGS-CURSOR, HOST-AUTH, COVERAGE-OBSERVERS | First bounded window detector D10 |
| STATE | pending | WINDOW, BASELINES | Scoped state lookup detectors D04/D06/D08/D09/D12/D13 |
| SENSOR-HEALTH | pending | COVERAGE-OBSERVERS, WINDOW | Independent missing-telemetry detector D15 |
| CORRELATION | pending | STATE, DISPOSITIONS, CATO, M365, SYSLOG | Bounded multi-stream episodes D11/D14 |
| SOC-UX | pending | CORRELATION, DISPOSITIONS, SECURITY-ACCESS | Planned advanced SOC case/disposition/workbench workflows |
| PROFILE-LOAD | pending | STANDARD-RECOVERY, CORRELATION | Resource/profile and controlled-outage qualification |
| SCALE-DECISION | pending | PROFILE-LOAD | Measured Scale profile worker-separation decision |
| KIND | pending | CORE | Current-revision local Kubernetes persistence/restart gate |
| RELEASE-REVIEW | pending | RECEIPT-PROGRESS | Independent source review and resolve findings |
| RELEASE-TRUST | pending | BASELINES, SECURITY-TRANSPORT | SBOM, provenance and signed release/rule verification |
| UPGRADE | pending | SHARED-RUNTIME, STANDARD-RECOVERY | Supported migration/rollback/restore local rehearsals |
| LOCAL-CANDIDATE | pending | SOC-UX, SCALE-DECISION, KIND, RELEASE-REVIEW, RELEASE-TRUST, UPGRADE | Final current-revision local release candidate |
| EXT-ARM64 | external_pending | — | Native ARM64 qualification |
| EXT-AWS | external_pending | — | Actual AWS/EKS/storage/IAM/KMS/Object Lock qualification |
| EXT-VENDORS | external_pending | — | Live SaaS/network-provider qualification |
| EXT-CI | external_pending | — | Remote CI for reviewed revision |
| EXT-DEPENDENCY | external_pending | — | Private overlay against actual released public dependency |
| EXT-PUBLICATION | external_pending | — | Owner-directed version, publication and main merge |

# Release readiness audit

Current snapshot: 2026-10-27. **No alpha or release is ready or published.**
The package remains `0.1.0-dev.0`; no release version/date has been selected.
Current local inventory is41accepted/11unfinished; SOC-UX is in_progress.
See [progress](07-progress.md), [ledger](31-execution-ledger.json) and
[next task](11-model-work-plan.md). Local simulations do not establish production.

## Current evidence

| Scope | Accepted evidence | Limit |
| --- | --- | --- |
| SOC-UX reference/internal inventory — 2026-10-27 | Independent review/8frozen gates,1340default/1410all-feature tests,73focused findings checks and3owned SIGKILL cuts; `target/soc-ux-20261026/references/ACCEPTANCE.json` | Host-only exact physical provenance/private metadata and bounds; no grant,client serialization or actual API/RBAC/disposition/console/browser/Standard/external qualification |
| SOC-UX Small case backend — 2026-10-27 | Independent review/8frozen gates,1330default/1400all-feature tests,17case/boundary/lifetime probes and3owned SIGKILL cuts; `target/soc-ux-20261026/backend/ACCEPTANCE.json` | Backend prerequisite only; host authority synthetic. No API/RBAC/disposition/evidence console/browser/Standard or current external/release qualification; whole SOC-UX remains in_progress |
| CORRELATION D11/D14 — 2026-10-26 | Independent mechanism/catalog/final criteria reviews,13frozen gates,1312default/1382all-feature tests and helper/process recovery; retained native21cases/66records,3native custody/3runtime journal SIGKILL cuts; `target/correlation-d14-20261026/ACCEPTANCE.json` | Bounded local mechanisms; source/private/coverage/identity-link/custody authority synthetic. Protected complete indexes,all-contributor grants and exclusive activation remain host obligations. No automatic Main activation,full-host/currentARM64/CI/image/AWS/production/release qualification |
| STATE historical lookups — 2026-10-26 | Independent source/criteria review; eight frozen gates,1238default/1308all-feature tests;15catalog outcomes,three native composition/three helper tests and five actual SIGKILL/original replay/intervening-event/generation reopen cases; `target/scoped-state-20261026/ACCEPTANCE.json` | D04/D06/D08/D09/D13 only;D12 deferred. Synthetic source/private authority through production library/journal; private protected archive/index/exclusive handoff. No Main automatic activation,current AWS/ARM64/CI/image or release claim.40accepted/12unfinished; CORRELATION next |
| BASELINES public pack — 2026-10-26 | Independent source/criteria review; six gates,1221tests/27ignores;15catalog assessments,41CloudTrail/8K8s native cases, exact packagedSmall15events5findings/checkpoint15/SIGKILL restart and cleanup; `target/baselines-20261025/ACCEPTANCE.json` | Source/host readiness simulated. Library returns assessments; Main runs privately selected YAML without automatic assessment persistence.39accepted/13unfinished; STATE next,D12 deferred; no AWS/current ARM64/CI/release claim |
| K8S-CONTEXT full local item — 2026-10-25 | Independent source/criteria review; six gates,1212tests/27ignores; actual node hostPath/nonroot/permissions/rotation/deletion/recreation/SIGKILL replay,323rows322unique, process and legacy regressions with cleanup; `target/kubernetes-node-producer-20261025/ACCEPTANCE.json` | Bounded local AMD64; explicit supplemental group0 grant; runtime UID is unverified API association. AWS/EKS,current ARM64/remote CI/production-image and release remain open.38accepted/14unfinished; next BASELINES |

## Required gates still open

Latest qualified runtime:`7fa481e`, complete nativeAMD64/ARM64 CI, images,
finite-soak, Standard kind and unsigned candidate integrity/relocation proof;
exact evidence is in the final dated entry.

| Gate | Remaining requirement |
| --- | --- |
| Final LOCAL-CANDIDATE prerequisites | SOC-UX, SCALE-DECISION and RELEASE-TRUST remain unfinished on the AWS-free dependency graph; a CI development bundle does not close these ledger items |
| Independent current-source release review | Source-bound reviewer assessment of the current durability/sensor/restore changes; read-only scope is prepared and current-task delegation authorization is pending |
| Actual EKS/AWS/vendor | Authorized environments and actual provider/storage/identity/runtime evidence; kind and synthetic endpoints do not close these gates |
| Released external dependency | Private application against the actual released public version and locked dependency graph |
| Version/publication/main merge | Owner-selected version and explicit authority, with applicable trust/security/restore/package/SBOM review |

<details>
<summary>Earlier gate snapshot, superseded by the current dated evidence</summary>

| Gate | Remaining requirement |
| --- | --- |
| Standard Kubernetes | Complete27281e3 run38246315239 and primary-digest/source/bundle/image-bound native profiles pass107.40s AMD64/114.57s ARM64: native TLS/probes, regular Secret files, original CRC/WAL checkpoint2/floor0/database facts and same-PVC SIGKILL/pod replacement recovery/cleanup; `target/standard-kind-ci-20261012/NATIVE-STANDARD-ACCEPTANCE.json`. Synthetic identity/S3; actual EKS/AWS and later current-revision CI remain open; no replicas or remote DELETE |
| Native ARM64 | Full architecture-specific runtime/pipeline/container/Kubernetes/benchmark evidence; partial passing Rust CI is insufficient |
| Current container/kind/supply chain | Fresh matching reviewed source/config/image; prior current-kind attempts hit PVC/host-resource exhaustion |
| Actual EKS/AWS | Authorized environment, namespace, storage and persistent restart evidence; none is available currently; local kind cannot close this gate |
| Reviewed-revision remote CI | Reviewed metrics revision b9c58da run38237870960 succeeds. Later0c73951 run38243101139 passes both976-test/five Standard process jobs and AMD64 full native qualification; ARM64 passes container/pipeline/soak/kind but a pinned security-tool download returns HTTP504, leaving supply-chain/full CI unqualified. New Standard cluster workflow27281e3 run38246315239 is active and requires matching results |
| Released external dependency | Private application against the actual released version and locked dependency graph |
| Release review/version/publication | Applicable trust/security/restore/package/SBOM review, owner-selected version and explicit release authority |


</details>

Public OSS server/agent image publication is prepared in
[the GHCR release workflow](50-ghcr-publication.md). It requires the exact
owner-approved ready tag, matching version and fresh complete native CI before
publishing. Signed provenance/platform SBOMs and anonymous public visibility
checks precede stable `latest`. Workflow preparation does not close remote CI,
native ARM64, public package visibility or release authority gates.

The first 2026-10-10 server scan failed three Cargo advisories (`h2` and
`quick-xml`). The patched released object_store0.14.2/quick-xml0.41.0 graph removes
h2 and preserves the custom HTTP1 S3 transport and compatible local DataFusion
filesystem types. Matching AMD64 agent/server images pass native role checks,
SBOMs and scans: zero vulnerable Cargo dependencies, zero HIGH/CRITICAL container
findings (8LOW/23MEDIUM retained). Formatting, both strict Clippy configurations,
857default/912all-feature tests and workspace14 boundaries pass. Interrupted and
failed fixture campaigns remain retained; the corrected bounded readiness wait
has20 guard tests and its own reviewed actual PostgreSQL acceptance. Exact combined
source/image/report evidence must match `target/release-security-20261010T133648Z/acceptance.json`.
This is local qualification; fresh kind, ARM64/EKS, full independent review and
remote release gates remain open. Earlier images remain historical for this graph.

The query selection lifetime adapter has actual Parquet/DataFusion expiry
regressions and an owned PostgreSQL pin-binding fixture. Its source-bound writer
review and final campaign must match
`target/goal-execution-20261007/SHARED-RUNTIME/query-pin-20261010/`. Canonical
shared manifest/object selection and Standard runtime wiring are still required;
the adapter alone grants neither content nor tenant authority.

The owner authorized reviewed scoped commits and pushes on2026-10-11, using free
public GitHub runners. Release publication remains held; no version is selected.
SSH push works; public report archives can be verified against GitHub digests.
A core-MVP preview may defer advanced SOC UX/post-MVP scope; applicable release
qualification still applies. A preview claiming all planned architecture also
requires the frozen post-MVP ledger. Actual vendor/AWS acceptance stays visible.

## Security and operational limits

HTTP202 means synced WAL admission; persisted Parquet/findings precede checkpoint
advancement. Current local identity, mTLS, role and independent audit mechanisms
have bounded evidence; trusted extensions, environment policy, real provider
rotation/encrypted-media and production authority need their own qualifications.
Historical scans are inventory of exact images, not a blanket current security
claim. Finite shared-host load/soak results establish neither a universal resource
plateau nor physical-device throughput. Preserve separate evidence scopes.


## Complete current native qualification — 2026-10-16

Native CI and artifact verification pass for runtime revision`e1763e3` — 2026-10-16, [run38882944855](https://github.com/mischapogr/platform-signal/actions/runs/38882944855). All five jobs pass. Both nativeAMD64/ARM64 Rust jobs pass1,191tests, all18PostgreSQL crash/restore cases,8Small sensor checks and Standard WINDOW/sensor/mixed/restore scenarios8/10/5/4. Primary GitHub archive digests, exact source maps, actual ELF bytes and original/stripped executable identities are verified. Both production images pass native host/daemon/image architecture, hardening, seven pipeline profiles, two120s finite-soak profiles, supply-chain gates and Standard kind original-WAL/PVC recovery with owned cleanup110.83s/108.46s. Evidence:`target/sensor-health-standard-20261016/ci-e1763e3/NATIVE-ACCEPTANCE.json`. Identity/observer/restore authority and S3 remain synthetic; kind is not EKS/AWS and finite soak is not prolonged production stability or physical-device throughput. Runtime qualification is pinned to`e1763e3`; documentation-only status updates do not change its build inputs. Inventory36accepted/16unfinished. Independent current-source release review, actual AWS/EKS/vendor, released dependency and owner-selected version/publication/main merge remain open. No alpha or release is published.


## Candidate cleanup serialization correction — 2026-10-16

Candidate run38892772326 at`5850dfa` completes AMD64 Rust qualification but fails
ARM64 mixed recovery after original checkpoint9. Verified primary artifact bytes
show a PostgreSQL concurrent-update serialization abort in obsolete replay-pin
cleanup; the consumer holds and query returns503. Downstream native container
and candidate jobs are skipped. The previous`e1763e3` finite native evidence is
retained at its exact source; it does not accept this failure or the correction.

The correction has writer-reviewed local acceptance: deterministic PostgreSQL
red-to-green retirement race, exact three-round exhaustion without releasing the
pin, cancelled/expired refusal and idempotent replay; full server/native HTTP
campaign60checks190.67s; actual Standard mixed recovery5scenarios60.13s with
303source bindings and owned cleanup. Frozen acceptance passes1,121default/
1,191all-feature tests, both strict Clippy modes, formatting,43helper checks and
14workspace boundaries. `target/candidate-replay-retry-20261016/ACCEPTANCE.json`
retains source and binary bindings. Fresh native candidate qualification, artifact
integrity, independent current-source review and every external/owner gate above
remain open. These are unsigned development artifacts, not an approved release.


## Verified current native candidates — 2026-10-16

All five jobs at`7fa481e` in
[run38898992993](https://github.com/mischapogr/platform-signal/actions/runs/38898992993)
pass. All eight official artifact digests are verified. Each architecture passes
1,191tests/18PostgreSQL cases and exact native sensor/WINDOW/mixed/restore
process/source/ELF bindings. Both images pass hardening, seven pipeline profiles,
two120s finite-soak profiles, supply-chain and Standard kind original-WAL/PVC
recovery with cleanup108.17s/105.91s. Exact image IDs, payload IDs, hashes and
limits:`target/candidate-replay-retry-20261016/NATIVE-ACCEPTANCE.json`.

Both unsigned candidates pass the closed nine-payload inventory plus manifest/
checksums, all11packaged chart files, saved-image config/27ordered-layer hashes,
source payload and offline14-package/37-path-dependency relocation. Source
comparison accepts equivalent gzip encoding but rejects changed source or
escaping links. ZIP-normalized execute permissions are restored after checksums;
the running self-gate snapshot is matched to the finalized passed gate, and its
log to the final log prefix. One empty owned-fixture hidden lock marker is
verified explicitly; all other evidence is byte-compared to verified reports.
These are consumer-format checks, not changes to qualified product source.

The broader ledger remains36accepted/16unfinished:12product and4external items.
Final LOCAL-CANDIDATE dependencies, independent current-source review and all
external/owner gates remain open. Package version stays`0.1.0-dev.0`; no alpha,
release version, registry publication or main merge is selected or approved here.

## Historical evidence and compatible anchors

[Exact 21-release-readiness-history-20261010.md](21-release-readiness-history-20261010.md).
[Exact 21-release-readiness-history-20261026.md](21-release-readiness-history-20261026.md).

Dated archives preserve original evidence, counts, limits and source identities.

<a id="shared-control-publication-primitives-locally-qualified--2026-10-10"></a>[Historical detail](21-release-readiness-history-20261010.md#shared-control-publication-primitives-locally-qualified--2026-10-10)
<a id="shared-control-lease-foundation-under-implementation--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#shared-control-lease-foundation-under-implementation--2026-10-09)
<a id="standard-shared-control-contract-accepted--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#standard-shared-control-contract-accepted--2026-10-09)
<a id="small-composed-pilot-accepted-locally--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#small-composed-pilot-accepted-locally--2026-10-09)
<a id="restricted-role-audit-composition-and-local-closeout--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#restricted-role-audit-composition-and-local-closeout--2026-10-09)
<a id="bounded-browser-readiness-correction--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#bounded-browser-readiness-correction--2026-10-09)
<a id="audit-credential-rotation-and-restored-data-authority--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#audit-credential-rotation-and-restored-data-authority--2026-10-09)
<a id="fixed-pipeline-failure-diagnostics--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#fixed-pipeline-failure-diagnostics--2026-10-09)
<a id="explicit-s3-sse-kms-request-selection--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#explicit-s3-sse-kms-request-selection--2026-10-09)
<a id="local-verified-identity-and-independent-audit-composition--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#local-verified-identity-and-independent-audit-composition--2026-10-09)
<a id="restricted-receiver-file-access-qualification--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#restricted-receiver-file-access-qualification--2026-10-09)
<a id="bounded-independent-receiver-health-probe--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#bounded-independent-receiver-health-probe--2026-10-09)
<a id="automatic-rust-target-diagnostics--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#automatic-rust-target-diagnostics--2026-10-09)
<a id="native-ci-status--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#native-ci-status--2026-10-09)
<a id="ext-ci-native-failure-diagnostics--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#ext-ci-native-failure-diagnostics--2026-10-09)
<a id="independent-receiver-composition--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#independent-receiver-composition--2026-10-09)
<a id="independent-audit-receiver-host--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#independent-audit-receiver-host--2026-10-09)
<a id="independent-audit-http-transport--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#independent-audit-http-transport--2026-10-09)
<a id="independent-audit-receipt-journal--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#independent-audit-receipt-journal--2026-10-09)
<a id="native-startup-activation-audit--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#native-startup-activation-audit--2026-10-09)
<a id="validated-rule-revision-primitive--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#validated-rule-revision-primitive--2026-10-09)
<a id="native-ingest-control-audit--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#native-ingest-control-audit--2026-10-09)
<a id="native-coverage-access-audit--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#native-coverage-access-audit--2026-10-09)
<a id="native-findings-access-audit--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#native-findings-access-audit--2026-10-09)
<a id="security-audit-native-query-hook--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-audit-native-query-hook--2026-10-09)
<a id="ext-ci-reported-idp-failure-stages--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#ext-ci-reported-idp-failure-stages--2026-10-09)
<a id="ext-ci-legacy-candidate-fixture-correction--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#ext-ci-legacy-candidate-fixture-correction--2026-10-09)
<a id="security-audit-durable-control-outbox--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-audit-durable-control-outbox--2026-10-09)
<a id="ext-ci-failure-diagnostics--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#ext-ci-failure-diagnostics--2026-10-09)
<a id="security-audit-destination-client-slice--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-audit-destination-client-slice--2026-10-09)
<a id="security-audit-protocol-slice--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-audit-protocol-slice--2026-10-09)
<a id="security-transport-complete-locally--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-transport-complete-locally--2026-10-09)
<a id="security-transport-shared-collector-tls--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-transport-shared-collector-tls--2026-10-09)
<a id="security-transport-native-mtls-slice--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-transport-native-mtls-slice--2026-10-09)
<a id="security-access-established-idp-acceptance--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-established-idp-acceptance--2026-10-09)
<a id="security-access-coverage-identity-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-coverage-identity-boundary--2026-10-09)
<a id="security-access-finding-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-finding-boundary--2026-10-09)
<a id="security-access-composed-server-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-composed-server-boundary--2026-10-09)
<a id="security-access-producer-route-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-producer-route-boundary--2026-10-09)
<a id="security-access-query-grant-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-query-grant-boundary--2026-10-09)
<a id="security-access-native-backend-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-native-backend-boundary--2026-10-09)
<a id="security-access-introspection-profile-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-introspection-profile-boundary--2026-10-09)
<a id="security-access-grant-only-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#security-access-grant-only-boundary--2026-10-09)
<a id="retention-parent-localsimulation-acceptance--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#retention-parent-localsimulation-acceptance--2026-10-09)
<a id="exact-query-version-reclamation-boundary--2026-10-09"></a>[Historical detail](21-release-readiness-history-20261010.md#exact-query-version-reclamation-boundary--2026-10-09)
<a id="logical-query-retirement-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#logical-query-retirement-boundary--2026-10-08)
<a id="stopped-derived-cache-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#stopped-derived-cache-boundary--2026-10-08)
<a id="advisory-retention-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#advisory-retention-boundary--2026-10-08)
<a id="monolithic-s3-query-simulation-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#monolithic-s3-query-simulation-boundary--2026-10-08)
<a id="committed-object-query-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#committed-object-query-boundary--2026-10-08)
<a id="selected-query-s3-adapter-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#selected-query-s3-adapter-boundary--2026-10-08)
<a id="small-query-publication-boundary--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#small-query-publication-boundary--2026-10-08)
<a id="public-repository-and-partial-native-ci--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#public-repository-and-partial-native-ci--2026-10-08)
<a id="object-parquet-cpu-seam--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#object-parquet-cpu-seam--2026-10-08)
<a id="object-query-manifest-contract--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#object-query-manifest-contract--2026-10-08)
<a id="protected-route-composition-acceptance--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#protected-route-composition-acceptance--2026-10-08)
<a id="protected-authenticated-role-transport--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#protected-authenticated-role-transport--2026-10-08)
<a id="native-originalreceipt-and-conservative-coverage--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#native-originalreceipt-and-conservative-coverage--2026-10-08)
<a id="retained-native-proof-history-and-independent-current-head--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#retained-native-proof-history-and-independent-current-head--2026-10-08)
<a id="bounded-independent-archive-mechanism--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#bounded-independent-archive-mechanism--2026-10-08)
<a id="independent-receipt-custody-and-fenced-source-ack--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#independent-receipt-custody-and-fenced-source-ack--2026-10-08)
<a id="native-cloudtrail-byte-proofs-and-read-only-capture--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#native-cloudtrail-byte-proofs-and-read-only-capture--2026-10-08)
<a id="scoped-audited-disposition-backend--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#scoped-audited-disposition-backend--2026-10-08)
<a id="private-bounded-notification-delivery--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#private-bounded-notification-delivery--2026-10-08)
<a id="private-outbox-transaction--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#private-outbox-transaction--2026-10-08)
<a id="durable-findings-cursor--2026-10-08"></a>[Historical detail](21-release-readiness-history-20261010.md#durable-findings-cursor--2026-10-08)
<a id="evidence-ledger"></a>[Historical detail](21-release-readiness-history-20261010.md#evidence-ledger)
<a id="documentation-map"></a>[Historical detail](21-release-readiness-history-20261010.md#documentation-map)
<a id="sensor-health-small-native-integration--2026-10-15"></a>[Historical detail](21-release-readiness-history-20261026.md#sensor-health-small-native-integration--2026-10-15)
<a id="sensor-health-retained-history--2026-10-15"></a>[Historical detail](21-release-readiness-history-20261026.md#sensor-health-retained-history--2026-10-15)
<a id="sensor-health-whole-local-acceptance--2026-10-16"></a>[Historical detail](21-release-readiness-history-20261026.md#sensor-health-whole-local-acceptance--2026-10-16)
<a id="native-window-fixture-correction--2026-10-16"></a>[Historical detail](21-release-readiness-history-20261026.md#native-window-fixture-correction--2026-10-16)

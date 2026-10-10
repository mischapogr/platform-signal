# Implementation progress

Current snapshot: 2026-10-11. Read [release boundaries](21-release-readiness.md) and [finite ledger](31-execution-ledger.json).
Prior record: [progress history](07-progress-history-20261010.md).

## Standard server startup, publication and WAL recovery — 2026-10-11
The server component binds Parquet uploads to fenced atomic manifest/finding/state/work/receipt publication.
Exact replay preserves results; lost COMMIT resolves only the retained request. Host scope/backend, bounded admission and original budgets remain explicit.
Explicit catalog/WAL startup: `target/shared-startup-20261010T224833Z/`; durable original draft/request recovery and checkpoint: `target/shared-recovery-20261010T230503Z/`. Matching final gates required.
[Publication acceptance](48-shared-control-runtime.md#standard-server-publication-coordinator--2026-10-11): `target/shared-server-publication-20261010T215920Z/`; matching final gates required.
Native CI prebuilds default-feature fixtures and includes `--server` on both architectures.
Local configuration/guard/prebuild: `target/shared-server-ci-20261010T224545Z/`; remote CI/ARM64 proof remains open.
Global feed library/restore/restart: `target/shared-global-feed-20261011T015956+0200/`; [read authority](48-shared-control-runtime.md#global-findings-database-reads--2026-10-11), matching final gates required. HTTP/scoped integration remains open.
Shared feed wire/explicit HTTP route: `target/shared-feed-http-20261011T022929+0200/`; authorized live HTTP/TLS/audit: `target/shared-feed-roundtrip-20261011T025437+0200/`; matching final gates required. Scope schema: `target/shared-finding-scope-schema-20261011T031740+0200/`; host API: `target/shared-finding-scope-host-20261011T034549+0200/`; matching final gates required. Sealed canonical payload: `target/shared-scoped-payload-20261011T042000+0200/`; matching final gates required. Atomic scoped publication: `target/shared-scoped-publication-20261011T043519+0200/`; matching final gates required. Original scoped server/WAL recovery: `target/shared-scoped-recovery-20261011T052009+0200/`; corrected native crash qualification passed, matching final gates required. Main/scoped host APIs/private consumers, operational restore/retirement and independent/external gates remain open; no replicas enabled.

## Public OSS image publication prepared — 2026-10-10

The [GHCR workflow](50-ghcr-publication.md) gates native agent/server publication
on owner readiness, CI, scans, attestations and public pulls; stable-only `latest`.
Patched AMD64 role images/runtime/SBOM/scans and857default/912all-feature tests pass.
Evidence: `target/release-security-20261010T133648Z/`; no remote publication.

## Shared-control crash/restore matrix locally qualified — 2026-10-10

All eighteen frozen failure cases have explicit executable outcomes in the owned
PostgreSQL fixture. New producer processes exercise abrupt loss after synced
upload, before COMMIT and during COMMIT; actual statement timeout permits takeover
without partial publication. A synthetic loopback receiver accepts exact plan/key
bytes durably and loses its reply; uncertainty and retry preserve original history.
An abrupt restart of the owned persistent PostgreSQL volume preserves complete
control and restored-destination metadata, followed by a fresh-client probe.

Evidence and case-by-case audit live under
`target/goal-execution-20261007/SHARED-RUNTIME/matrix-20261010/`. Final acceptance
requires its source-bound writer review and matching passed serial campaign;
the first native run is diagnostic evidence until those checks settle.
SHARED-RUNTIME remains **in_progress**. Standard server/query/private-consumer
integration is the next separate goal. Synthetic receiver effects are local proof;
remote object DELETE, real notifications and external/release authority stay held.

## Coordinated stopped restore locally qualified — 2026-10-10

The explicit stopped restore adapter binds a coherent supported checkpoint and
exact immutable versions to independently current approval/custody/credentials.
Fresh generation fences old handles, original attempt evidence and delivery plans
remain intact, and every supported dependent cursor must reconcile before READY.
Actual PostgreSQL tests cover inconsistent progress, restored schema tampering,
DDL rollback and lost COMMIT resolution. No reset or historical redetection occurs.

Details: [restore runtime](48-shared-control-runtime.md#coordinated-stopped-restore--2026-10-10).
Source-bound writer review and final gates are recorded under
`target/goal-execution-20261007/SHARED-RUNTIME/restore-20261010/`; acceptance requires
its matching passed campaign. SHARED-RUNTIME stays **in_progress**. The bounded crash/restore matrix is recorded above;
Standard integration is next; no external restore or release authority.

## Shared-control administrative migration locally qualified — 2026-10-10

Explicit administrative initialization and a populated checksummed revision1-to2
upgrade preserve retained requests, receipts, rule/normalizer pins, findings cursor
history, delivery plans and historical attempts. Stopped readiness/leases and full
writer locks are required. Unknown/corrupt/partial sources fail without reset;
DDL rollback and uncertain COMMIT resolution have actual local PostgreSQL evidence.
Migration leaves readiness false. Frozen001 and notification002 are unchanged.

Details: [administrative runtime](48-shared-control-runtime.md#explicit-initialization-and-populated-migration--2026-10-10).
Matching writer review and required gates:
`target/goal-execution-20261007/SHARED-RUNTIME/migration-20261010/acceptance.json`.
SHARED-RUNTIME remains **in_progress**; the bounded restore slice is recorded above.

## Shared-control notification fencing locally qualified — 2026-10-10

Claims commit unique bounded attempts under current pipeline authority. Original
delivery IDs/plans and claim fences remain retained; interrupted intents become
uncertain through explicit recovery. Stale owner/generation completions fail.
Claim replay cannot grant another send; read-only resolution handles lost claim
and completion replies. All history and completion evidence remains charged;
ten attempts exhaust retryable/uncertain work. Remote effects remain at least once.

Details and boundaries: [notification runtime](48-shared-control-runtime.md#notification-fencing-and-retained-attempts--2026-10-10).
Source-bound writer review, workspace gates and actual local PostgreSQL fixture:
`target/goal-execution-20261007/SHARED-RUNTIME/notifications-20261010/acceptance.json`.
SHARED-RUNTIME remains **in_progress**. No server adapter or real sends; coordinated stopped restore, full crash/restore and Standard integration follow.

## Shared-control retirement and retention locally qualified — 2026-10-10

Canonical backend/key/exact-version tombstones now use the current complete owner
fence and global retention checks. Committed current/history roots, finite reader
pins and explicit restore/replay/evidence holds block retirement. Sealed indexes
and reader expiry prevent corrupted metadata or cleanup from dropping protection.
Exact replay, explicit audited release/takeover, quota/final-expiry rollback,
alias serving/republishing denial and both lifecycle races have owned PostgreSQL
17.5/AMD64 evidence. Eligible orphan versions retire logically; committed history
remains protected, and remote DELETE stays disabled.

Source-bound final gates, writer review, exact counts and handoff live under
`target/goal-execution-20261007/SHARED-RUNTIME/retirement-20261010/`. SHARED-RUNTIME remains **in_progress**; no Standard readiness or release claim.

## Shared-control read snapshots locally qualified — 2026-10-10

The bounded read-pin slice adds restricted repeatable-read snapshots of exact
committed manifest bytes, fixed database-clock expiry, non-renewing replay and
finite expired-list compaction with permanent identity markers. Whole-operation
retries require confirmed rollback, stop at three rounds and preserve original
budgets. Actual PostgreSQL17.5/AMD64 exercises scope, corruption, all four capacity
limits, expiry/counters and concurrent-update/retry-exhaustion rollback.

Source-bound final gates, writer review, exact counts and handoff live under
`target/goal-execution-20261007/SHARED-RUNTIME/snapshots-20261010/`. The server/query adapter remains unwired; this is no shared-readiness,
HA or release claim. SHARED-RUNTIME stays **in_progress**.

## Shared-control publication primitives locally qualified — 2026-10-10

SHARED-RUNTIME remains **in_progress**. Fenced publication now commits manifest,
head/checkpoint, revision-pinned state, exact-byte findings/cursor, immutable work
and receipt prefixes atomically. Zero-prepared receipts remain metadata-only.
Actual owned PostgreSQL 17.5 on Linux AMD64 proves exact replay, quota/conflict
rollback, concurrent publication, corrupt retained/predecessor pins, final lease
expiry and delayed COMMIT reconciliation. The source-bound fixture passed in
70.22 seconds / 43 commands including Cargo lock wait; executed integration took
7.75 seconds, and owned cleanup passed.

Strict final gates: 836 default tests (11 ignored), 891 all-feature tests
(12 ignored), both Clippy checks, formatting and workspace guard (14 packages).
Eleven fixture guards and 28 contract guards pass. Review was performed by the
writer; no independent agent reviewed this continuation.

Evidence: `target/goal-execution-20261007/SHARED-RUNTIME/publication-20261010/`
contains acceptance, review, handoff, PostgreSQL and final validation reports.
See [runtime contract](48-shared-control-runtime.md) and
[shared-control contract](47-shared-control-contract.md).

## Next runnable work

Continue SHARED-RUNTIME with coordinated stopped restore under independently
current authority and a fresh generation, then full crash/restore qualification and
Standard integration. Prepare one bounded task packet and read the relevant
contract before choosing the exact next slice. No server replicas or shared
readiness are enabled by the library acceptance.

The unchanged 52-item ledger has 10 passed_local, 10 passed_simulated,
1 in_progress, 25 pending and 6 external_pending. Item statuses and dependencies
live in the ledger; passing one slice does not complete its parent item.

## Current evidence boundaries

Core phases 0–8 and bounded Phase 10 have local Linux AMD64 evidence. Historical
container, kind, soak, supply-chain and candidate results retain their original
source/image bindings. They do not qualify newer Rust changes automatically.
Actual EKS, full native ARM64 runtime/pipeline, reviewed-revision remote CI and
released-dependency/publication gates remain separate.

Latest recorded public CI `132f2b2` passes native AMD64/ARM64 Rust jobs and basic
container runtime/persistence steps. Both native pipeline jobs fail;
kind/supply-chain are skipped. Annotations report AMD64 `1k-10000 / configuration /
last-entered` and ARM64 `4k-1000 / configuration / last-entered`. Older cached-image
local profiles establish no remote cause. This is retained evidence, not a fresh
remote CI observation.

The dev0 candidate is unpublished and is neither alpha nor release. The owner
holds staging, commits, pushes and publication until alpha or first minor
readiness; no release version is selected. Local kind is authorized local proof,
not EKS/AWS acceptance. Phase 9 AWS collection requires a separately scoped task.

## AI execution workflow

Use the [current routing plan](11-model-work-plan.md) and
[bounded workflow](49-ai-execution-workflow.md) for task packets, source-bound
review, serial acceptance, usage measurement and autonomous continuation.
Do not reread the complete historical logs for each task.

<details>
<summary>Historical heading links (compatibility index)</summary>

- <a id="shared-control-lease-foundation-under-implementation--2026-10-09"></a>[Shared-control lease foundation under implementation — 2026-10-09](07-progress-history-20261010.md#shared-control-lease-foundation-under-implementation--2026-10-09)
- <a id="standard-shared-control-contract-accepted--2026-10-09"></a>[Standard shared-control contract accepted — 2026-10-09](07-progress-history-20261010.md#standard-shared-control-contract-accepted--2026-10-09)
- <a id="small-composed-pilot-accepted-locally--2026-10-09"></a>[Small composed pilot accepted locally — 2026-10-09](07-progress-history-20261010.md#small-composed-pilot-accepted-locally--2026-10-09)
- <a id="restricted-role-audit-composition-and-local-closeout--2026-10-09"></a>[Restricted-role audit composition and local closeout — 2026-10-09](07-progress-history-20261010.md#restricted-role-audit-composition-and-local-closeout--2026-10-09)
- <a id="bounded-browser-readiness-correction--2026-10-09"></a>[Bounded browser readiness correction — 2026-10-09](07-progress-history-20261010.md#bounded-browser-readiness-correction--2026-10-09)
- <a id="audit-credential-rotation-and-restored-data-authority--2026-10-09"></a>[Audit credential rotation and restored-data authority — 2026-10-09](07-progress-history-20261010.md#audit-credential-rotation-and-restored-data-authority--2026-10-09)
- <a id="fixed-pipeline-failure-diagnostics--2026-10-09"></a>[Fixed pipeline failure diagnostics — 2026-10-09](07-progress-history-20261010.md#fixed-pipeline-failure-diagnostics--2026-10-09)
- <a id="explicit-s3-sse-kms-request-selection--2026-10-09"></a>[Explicit S3 SSE-KMS request selection — 2026-10-09](07-progress-history-20261010.md#explicit-s3-sse-kms-request-selection--2026-10-09)
- <a id="local-verified-identity-and-independent-audit-composition--2026-10-09"></a>[Local verified identity and independent audit composition — 2026-10-09](07-progress-history-20261010.md#local-verified-identity-and-independent-audit-composition--2026-10-09)
- <a id="restricted-receiver-file-access-qualification--2026-10-09"></a>[Restricted receiver file-access qualification — 2026-10-09](07-progress-history-20261010.md#restricted-receiver-file-access-qualification--2026-10-09)
- <a id="bounded-independent-receiver-health-probe--2026-10-09"></a>[Bounded independent receiver health probe — 2026-10-09](07-progress-history-20261010.md#bounded-independent-receiver-health-probe--2026-10-09)
- <a id="automatic-rust-target-diagnostics--2026-10-09"></a>[Automatic Rust target diagnostics — 2026-10-09](07-progress-history-20261010.md#automatic-rust-target-diagnostics--2026-10-09)
- <a id="native-ci-status--2026-10-09"></a>[Native CI status — 2026-10-09](07-progress-history-20261010.md#native-ci-status--2026-10-09)
- <a id="ext-ci-native-failure-diagnostics--2026-10-09"></a>[EXT-CI native failure diagnostics — 2026-10-09](07-progress-history-20261010.md#ext-ci-native-failure-diagnostics--2026-10-09)
- <a id="independent-receiver-composition--2026-10-09"></a>[Independent receiver composition — 2026-10-09](07-progress-history-20261010.md#independent-receiver-composition--2026-10-09)
- <a id="independent-audit-receiver-host--2026-10-09"></a>[Independent audit receiver host — 2026-10-09](07-progress-history-20261010.md#independent-audit-receiver-host--2026-10-09)
- <a id="independent-audit-http-transport--2026-10-09"></a>[Independent audit HTTP transport — 2026-10-09](07-progress-history-20261010.md#independent-audit-http-transport--2026-10-09)
- <a id="independent-audit-receipt-journal--2026-10-09"></a>[Independent audit receipt journal — 2026-10-09](07-progress-history-20261010.md#independent-audit-receipt-journal--2026-10-09)
- <a id="native-startup-activation-audit--2026-10-09"></a>[Native startup activation audit — 2026-10-09](07-progress-history-20261010.md#native-startup-activation-audit--2026-10-09)
- <a id="validated-rule-revision-primitive--2026-10-09"></a>[Validated rule revision primitive — 2026-10-09](07-progress-history-20261010.md#validated-rule-revision-primitive--2026-10-09)
- <a id="native-ingest-control-audit--2026-10-09"></a>[Native ingest control audit — 2026-10-09](07-progress-history-20261010.md#native-ingest-control-audit--2026-10-09)
- <a id="native-coverage-access-audit--2026-10-09"></a>[Native coverage access audit — 2026-10-09](07-progress-history-20261010.md#native-coverage-access-audit--2026-10-09)
- <a id="native-findings-access-audit--2026-10-09"></a>[Native findings access audit — 2026-10-09](07-progress-history-20261010.md#native-findings-access-audit--2026-10-09)
- <a id="security-audit-native-query-hook--2026-10-09"></a>[SECURITY-AUDIT native query hook — 2026-10-09](07-progress-history-20261010.md#security-audit-native-query-hook--2026-10-09)
- <a id="ext-ci-reported-idp-failure-stages--2026-10-09"></a>[EXT-CI reported IdP failure stages — 2026-10-09](07-progress-history-20261010.md#ext-ci-reported-idp-failure-stages--2026-10-09)
- <a id="ext-ci-legacy-candidate-fixture-correction--2026-10-09"></a>[EXT-CI legacy candidate fixture correction — 2026-10-09](07-progress-history-20261010.md#ext-ci-legacy-candidate-fixture-correction--2026-10-09)
- <a id="security-audit-durable-control-outbox--2026-10-09"></a>[SECURITY-AUDIT durable control outbox — 2026-10-09](07-progress-history-20261010.md#security-audit-durable-control-outbox--2026-10-09)
- <a id="ext-ci-failure-diagnostics--2026-10-09"></a>[EXT-CI failure diagnostics — 2026-10-09](07-progress-history-20261010.md#ext-ci-failure-diagnostics--2026-10-09)
- <a id="security-audit-destination-client-slice--2026-10-09"></a>[SECURITY-AUDIT destination client slice — 2026-10-09](07-progress-history-20261010.md#security-audit-destination-client-slice--2026-10-09)
- <a id="security-audit-protocol-slice--2026-10-09"></a>[SECURITY-AUDIT protocol slice — 2026-10-09](07-progress-history-20261010.md#security-audit-protocol-slice--2026-10-09)
- <a id="security-transport-complete-locally--2026-10-09"></a>[SECURITY-TRANSPORT complete locally — 2026-10-09](07-progress-history-20261010.md#security-transport-complete-locally--2026-10-09)
- <a id="security-transport-shared-collector-tls--2026-10-09"></a>[SECURITY-TRANSPORT shared collector TLS — 2026-10-09](07-progress-history-20261010.md#security-transport-shared-collector-tls--2026-10-09)
- <a id="security-transport-native-mtls-slice--2026-10-09"></a>[SECURITY-TRANSPORT native mTLS slice — 2026-10-09](07-progress-history-20261010.md#security-transport-native-mtls-slice--2026-10-09)
- <a id="security-access-established-idp-acceptance--2026-10-09"></a>[SECURITY-ACCESS established IdP acceptance — 2026-10-09](07-progress-history-20261010.md#security-access-established-idp-acceptance--2026-10-09)
- <a id="security-access-coverage-identity-boundary--2026-10-09"></a>[SECURITY-ACCESS coverage identity boundary — 2026-10-09](07-progress-history-20261010.md#security-access-coverage-identity-boundary--2026-10-09)
- <a id="security-access-trusted-finding-scopes--2026-10-09"></a>[SECURITY-ACCESS trusted finding scopes — 2026-10-09](07-progress-history-20261010.md#security-access-trusted-finding-scopes--2026-10-09)
- <a id="security-access-composed-server-identity--2026-10-09"></a>[SECURITY-ACCESS composed server identity — 2026-10-09](07-progress-history-20261010.md#security-access-composed-server-identity--2026-10-09)
- <a id="security-access-producer-admission--2026-10-09"></a>[SECURITY-ACCESS producer admission — 2026-10-09](07-progress-history-20261010.md#security-access-producer-admission--2026-10-09)
- <a id="security-access-mandatory-query-grants--2026-10-09"></a>[SECURITY-ACCESS mandatory query grants — 2026-10-09](07-progress-history-20261010.md#security-access-mandatory-query-grants--2026-10-09)
- <a id="security-access-native-https-backend--2026-10-09"></a>[SECURITY-ACCESS native HTTPS backend — 2026-10-09](07-progress-history-20261010.md#security-access-native-https-backend--2026-10-09)
- <a id="security-access-introspection-response-profile--2026-10-09"></a>[SECURITY-ACCESS introspection response profile — 2026-10-09](07-progress-history-20261010.md#security-access-introspection-response-profile--2026-10-09)
- <a id="security-access-bounded-grant-contract--2026-10-09"></a>[SECURITY-ACCESS bounded grant contract — 2026-10-09](07-progress-history-20261010.md#security-access-bounded-grant-contract--2026-10-09)
- <a id="retention-bounded-querycache-measurements-and-parent-acceptance--2026-10-09"></a>[RETENTION bounded query/cache measurements and parent acceptance — 2026-10-09](07-progress-history-20261010.md#retention-bounded-querycache-measurements-and-parent-acceptance--2026-10-09)
- <a id="retention-exact-retired-query-version-reclamation--2026-10-09"></a>[RETENTION exact retired query-version reclamation — 2026-10-09](07-progress-history-20261010.md#retention-exact-retired-query-version-reclamation--2026-10-09)
- <a id="retention-logical-query-retirement-horizon--2026-10-08"></a>[RETENTION logical query-retirement horizon — 2026-10-08](07-progress-history-20261010.md#retention-logical-query-retirement-horizon--2026-10-08)
- <a id="retention-stopped-derived-cache-maintenance--2026-10-08"></a>[RETENTION stopped derived-cache maintenance — 2026-10-08](07-progress-history-20261010.md#retention-stopped-derived-cache-maintenance--2026-10-08)
- <a id="retention-policy-and-advisory-reachability--2026-10-08"></a>[RETENTION policy and advisory reachability — 2026-10-08](07-progress-history-20261010.md#retention-policy-and-advisory-reachability--2026-10-08)
- <a id="s3-query-monolith-and-persistent-simulation--2026-10-08"></a>[S3-QUERY monolith and persistent simulation — 2026-10-08](07-progress-history-20261010.md#s3-query-monolith-and-persistent-simulation--2026-10-08)
- <a id="bounded-committed-object-queries--2026-10-08"></a>[Bounded committed object queries — 2026-10-08](07-progress-history-20261010.md#bounded-committed-object-queries--2026-10-08)
- <a id="selected-bounded-s3-adapter--2026-10-08"></a>[Selected bounded S3 adapter — 2026-10-08](07-progress-history-20261010.md#selected-bounded-s3-adapter--2026-10-08)
- <a id="small-object-publication-and-committed-recovery--2026-10-08"></a>[Small object publication and committed recovery — 2026-10-08](07-progress-history-20261010.md#small-object-publication-and-committed-recovery--2026-10-08)
- <a id="bounded-object-io--small-ownership--2026-10-08"></a>[Bounded object I/O / Small ownership — 2026-10-08](07-progress-history-20261010.md#bounded-object-io--small-ownership--2026-10-08)
- <a id="public-oss-ci-preparation--2026-10-08"></a>[Public OSS CI preparation — 2026-10-08](07-progress-history-20261010.md#public-oss-ci-preparation--2026-10-08)
- <a id="current-state--2026-10-08"></a>[Current state — 2026-10-08](07-progress-history-20261010.md#current-state--2026-10-08)
- <a id="s3-query-bounded-parquet-codec--2026-10-08"></a>[S3-QUERY bounded Parquet codec — 2026-10-08](07-progress-history-20261010.md#s3-query-bounded-parquet-codec--2026-10-08)
- <a id="s3-query-bounded-manifest-slice--2026-10-08"></a>[S3-QUERY bounded manifest slice — 2026-10-08](07-progress-history-20261010.md#s3-query-bounded-manifest-slice--2026-10-08)
- <a id="independent-protected-route-composition--2026-10-08"></a>[Independent protected route composition — 2026-10-08](07-progress-history-20261010.md#independent-protected-route-composition--2026-10-08)
- <a id="authenticated-protected-role-http--2026-10-08"></a>[Authenticated protected role HTTP — 2026-10-08](07-progress-history-20261010.md#authenticated-protected-role-http--2026-10-08)
- <a id="native-originalreceipt-linkage-and-conservative-coverage--2026-10-08"></a>[Native original/receipt linkage and conservative coverage — 2026-10-08](07-progress-history-20261010.md#native-originalreceipt-linkage-and-conservative-coverage--2026-10-08)
- <a id="retained-native-proof-history-and-independent-current-head--2026-10-08"></a>[Retained native proof history and independent current head — 2026-10-08](07-progress-history-20261010.md#retained-native-proof-history-and-independent-current-head--2026-10-08)
- <a id="bounded-independent-archive-mechanism--2026-10-08"></a>[Bounded independent archive mechanism — 2026-10-08](07-progress-history-20261010.md#bounded-independent-archive-mechanism--2026-10-08)
- <a id="independent-receipt-custody-and-fenced-source-ack--2026-10-08"></a>[Independent receipt custody and fenced source ACK — 2026-10-08](07-progress-history-20261010.md#independent-receipt-custody-and-fenced-source-ack--2026-10-08)
- <a id="native-cloudtrail-byte-proofs-and-read-only-capture--2026-10-08"></a>[Native CloudTrail byte proofs and read-only capture — 2026-10-08](07-progress-history-20261010.md#native-cloudtrail-byte-proofs-and-read-only-capture--2026-10-08)
- <a id="scoped-audited-disposition-backend--2026-10-08"></a>[Scoped audited disposition backend — 2026-10-08](07-progress-history-20261010.md#scoped-audited-disposition-backend--2026-10-08)
- <a id="private-bounded-notification-delivery--2026-10-08"></a>[Private bounded notification delivery — 2026-10-08](07-progress-history-20261010.md#private-bounded-notification-delivery--2026-10-08)
- <a id="private-outbox-transaction--2026-10-08"></a>[Private outbox transaction — 2026-10-08](07-progress-history-20261010.md#private-outbox-transaction--2026-10-08)
- <a id="durable-findings-cursor--2026-10-08"></a>[Durable findings cursor — 2026-10-08](07-progress-history-20261010.md#durable-findings-cursor--2026-10-08)
- <a id="independent-source-coverage-runtime--2026-10-08"></a>[Independent source coverage runtime — 2026-10-08](07-progress-history-20261010.md#independent-source-coverage-runtime--2026-10-08)
- <a id="scoped-monolith-coverage-integration--2026-10-08"></a>[Scoped monolith coverage integration — 2026-10-08](07-progress-history-20261010.md#scoped-monolith-coverage-integration--2026-10-08)
- <a id="durable-observerhistory-bridge--2026-10-08"></a>[Durable observer/history bridge — 2026-10-08](07-progress-history-20261010.md#durable-observerhistory-bridge--2026-10-08)
- <a id="regional-cloudtrail-configuration-observation--2026-10-08"></a>[Regional CloudTrail configuration observation — 2026-10-08](07-progress-history-20261010.md#regional-cloudtrail-configuration-observation--2026-10-08)
- <a id="bounded-source-observer-state--2026-10-08"></a>[Bounded source observer state — 2026-10-08](07-progress-history-20261010.md#bounded-source-observer-state--2026-10-08)
- <a id="signed-aws-source-transport--2026-10-08"></a>[Signed AWS source transport — 2026-10-08](07-progress-history-20261010.md#signed-aws-source-transport--2026-10-08)
- <a id="bounded-source-delivery-collector-driver--2026-10-08"></a>[Bounded source delivery collector driver — 2026-10-08](07-progress-history-20261010.md#bounded-source-delivery-collector-driver--2026-10-08)
- <a id="source-to-real-server-delivery-simulation--2026-10-08"></a>[Source-to-real-server delivery simulation — 2026-10-08](07-progress-history-20261010.md#source-to-real-server-delivery-simulation--2026-10-08)
- <a id="configured-http-receipt-publisher--2026-10-08"></a>[Configured HTTP receipt publisher — 2026-10-08](07-progress-history-20261010.md#configured-http-receipt-publisher--2026-10-08)
- <a id="retained-byte-bounded-batch-publication--2026-10-08"></a>[Retained-byte bounded batch publication — 2026-10-08](07-progress-history-20261010.md#retained-byte-bounded-batch-publication--2026-10-08)
- <a id="exact-version-bounded-capture-and-owned-preparation--2026-10-08"></a>[Exact-version bounded capture and owned preparation — 2026-10-08](07-progress-history-20261010.md#exact-version-bounded-capture-and-owned-preparation--2026-10-08)
- <a id="bounded-direct-s3-discovery--2026-10-08"></a>[Bounded direct S3 discovery — 2026-10-08](07-progress-history-20261010.md#bounded-direct-s3-discovery--2026-10-08)
- <a id="whole-object-pinned-receipt-preparation--2026-10-08"></a>[Whole-object pinned receipt preparation — 2026-10-08](07-progress-history-20261010.md#whole-object-pinned-receipt-preparation--2026-10-08)
- <a id="bounded-gzipnative-object-reader--2026-10-07"></a>[Bounded gzip/native-object reader — 2026-10-07](07-progress-history-20261010.md#bounded-gzipnative-object-reader--2026-10-07)
- <a id="receipt-retirementreclamation-and-explicit-slot-replacement--2026-10-07"></a>[Receipt retirement/reclamation and explicit slot replacement — 2026-10-07](07-progress-history-20261010.md#receipt-retirementreclamation-and-explicit-slot-replacement--2026-10-07)
- <a id="durable-process-local-source-ack-control--2026-10-07"></a>[Durable process-local source ACK control — 2026-10-07](07-progress-history-20261010.md#durable-process-local-source-ack-control--2026-10-07)
- <a id="receipt-owner-handover-and-checkpoint-gated-recovery-opening--2026-10-07"></a>[Receipt owner handover and checkpoint-gated recovery opening — 2026-10-07](07-progress-history-20261010.md#receipt-owner-handover-and-checkpoint-gated-recovery-opening--2026-10-07)
- <a id="persistent-goal-and-verified-source-receipt-progress--2026-10-07"></a>[Persistent Goal and verified source-receipt progress — 2026-10-07](07-progress-history-20261010.md#persistent-goal-and-verified-source-receipt-progress--2026-10-07)
- <a id="post-mvp-bounded-initial-source-receipt-store--2026-10-07"></a>[Post-MVP bounded initial source-receipt store — 2026-10-07](07-progress-history-20261010.md#post-mvp-bounded-initial-source-receipt-store--2026-10-07)
- <a id="post-mvp-source-receiptprogress-encoding-contract--2026-10-07"></a>[Post-MVP source-receipt/progress encoding contract — 2026-10-07](07-progress-history-20261010.md#post-mvp-source-receiptprogress-encoding-contract--2026-10-07)
- <a id="post-mvp-bounded-cloudtrail-record-normalizerprofile--2026-10-07"></a>[Post-MVP bounded CloudTrail record normalizer/profile — 2026-10-07](07-progress-history-20261010.md#post-mvp-bounded-cloudtrail-record-normalizerprofile--2026-10-07)
- <a id="post-mvp-cloudtrail-source-receiptprofile-design--2026-10-07"></a>[Post-MVP CloudTrail source-receipt/profile design — 2026-10-07](07-progress-history-20261010.md#post-mvp-cloudtrail-source-receiptprofile-design--2026-10-07)
- <a id="post-mvp-sourcecoverage-bounded-scans--2026-10-07"></a>[Post-MVP SourceCoverage bounded scans — 2026-10-07](07-progress-history-20261010.md#post-mvp-sourcecoverage-bounded-scans--2026-10-07)
- <a id="post-mvp-sourcecoverage-identity-prefix-pruning--2026-10-07"></a>[Post-MVP SourceCoverage identity-prefix pruning — 2026-10-07](07-progress-history-20261010.md#post-mvp-sourcecoverage-identity-prefix-pruning--2026-10-07)
- <a id="post-mvp-sourcecoverage-payload-prefix-pruning--2026-10-07"></a>[Post-MVP SourceCoverage payload-prefix pruning — 2026-10-07](07-progress-history-20261010.md#post-mvp-sourcecoverage-payload-prefix-pruning--2026-10-07)
- <a id="mvp-secops-ui-02--2026-10-07"></a>[MVP SecOps UI-02 — 2026-10-07](07-progress-history-20261010.md#mvp-secops-ui-02--2026-10-07)
- <a id="mvp-secops-ui-01--2026-10-07"></a>[MVP SecOps UI-01 — 2026-10-07](07-progress-history-20261010.md#mvp-secops-ui-01--2026-10-07)
- <a id="product-architecture-baseline--2026-10-07"></a>[Product architecture baseline — 2026-10-07](07-progress-history-20261010.md#product-architecture-baseline--2026-10-07)
- <a id="ingestion-architecture-audit--2026-10-07"></a>[Ingestion architecture audit — 2026-10-07](07-progress-history-20261010.md#ingestion-architecture-audit--2026-10-07)
- <a id="sourcecoverage-bounded-correction-admission--2026-10-07"></a>[SourceCoverage bounded correction admission — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-bounded-correction-admission--2026-10-07)
- <a id="sourcecoverage-trusted-intake-and-original-receipt-replay--2026-10-07"></a>[SourceCoverage trusted intake and original-receipt replay — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-trusted-intake-and-original-receipt-replay--2026-10-07)
- <a id="vendor-fixtures-and-current-source-release-refresh--2026-10-07"></a>[Vendor fixtures and current-source release refresh — 2026-10-07](07-progress-history-20261010.md#vendor-fixtures-and-current-source-release-refresh--2026-10-07)
- <a id="sourcecoverage-local-library-slice--2026-10-07"></a>[SourceCoverage local library slice — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-local-library-slice--2026-10-07)
- <a id="sourcecoverage-backendencoding-decision--2026-10-07"></a>[SourceCoverage backend/encoding decision — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-backendencoding-decision--2026-10-07)
- <a id="sourcecoverage-intakehistory-contract--2026-10-07"></a>[SourceCoverage intake/history contract — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-intakehistory-contract--2026-10-07)
- <a id="sourcecoverage-validator-and-local-git-baseline--2026-10-07"></a>[SourceCoverage validator and local Git baseline — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-validator-and-local-git-baseline--2026-10-07)
- <a id="sourcecoverage-contract--2026-10-07"></a>[SourceCoverage contract — 2026-10-07](07-progress-history-20261010.md#sourcecoverage-contract--2026-10-07)
- <a id="security-requirements-design--2026-10-07"></a>[Security requirements design — 2026-10-07](07-progress-history-20261010.md#security-requirements-design--2026-10-07)
- <a id="phase-8-local-evidence--2026-10-06"></a>[Phase 8 local evidence — 2026-10-06](07-progress-history-20261010.md#phase-8-local-evidence--2026-10-06)
- <a id="phase-7-progress--2026-10-06"></a>[Phase 7 progress — 2026-10-06](07-progress-history-20261010.md#phase-7-progress--2026-10-06)
- <a id="phase-6-evidence--2026-10-06"></a>[Phase 6 evidence — 2026-10-06](07-progress-history-20261010.md#phase-6-evidence--2026-10-06)
- <a id="phase-5-evidence--2026-10-06"></a>[Phase 5 evidence — 2026-10-06](07-progress-history-20261010.md#phase-5-evidence--2026-10-06)
- <a id="phase-4-evidence--2026-10-06"></a>[Phase 4 evidence — 2026-10-06](07-progress-history-20261010.md#phase-4-evidence--2026-10-06)
- <a id="phase-3-evidence--2026-10-06"></a>[Phase 3 evidence — 2026-10-06](07-progress-history-20261010.md#phase-3-evidence--2026-10-06)
- <a id="million-event-run"></a>[Million-event run](07-progress-history-20261010.md#million-event-run)
- <a id="review-corrections-and-remaining-boundaries"></a>[Review corrections and remaining boundaries](07-progress-history-20261010.md#review-corrections-and-remaining-boundaries)
- <a id="phase-2-evidence--2026-10-06"></a>[Phase 2 evidence — 2026-10-06](07-progress-history-20261010.md#phase-2-evidence--2026-10-06)
- <a id="phase-2-review"></a>[Phase 2 review](07-progress-history-20261010.md#phase-2-review)
- <a id="phase-1-evidence--2026-10-06"></a>[Phase 1 evidence — 2026-10-06](07-progress-history-20261010.md#phase-1-evidence--2026-10-06)
- <a id="phase-1-review"></a>[Phase 1 review](07-progress-history-20261010.md#phase-1-review)
- <a id="phase-10-local-evidence--2026-10-06"></a>[Phase 10 local evidence — 2026-10-06](07-progress-history-20261010.md#phase-10-local-evidence--2026-10-06)
- <a id="remaining-release-qualification"></a>[Remaining release qualification](07-progress-history-20261010.md#remaining-release-qualification)
- <a id="offline-restore-continuation--2026-10-06"></a>[Offline restore continuation — 2026-10-06](07-progress-history-20261010.md#offline-restore-continuation--2026-10-06)
- <a id="native-qualification-continuation--2026-10-06"></a>[Native qualification continuation — 2026-10-06](07-progress-history-20261010.md#native-qualification-continuation--2026-10-06)
- <a id="bounded-native-soak-continuation--2026-10-06"></a>[Bounded native soak continuation — 2026-10-06](07-progress-history-20261010.md#bounded-native-soak-continuation--2026-10-06)
- <a id="phase-0-evidence"></a>[Phase 0 evidence](07-progress-history-20261010.md#phase-0-evidence)
- <a id="phase-0-review"></a>[Phase 0 review](07-progress-history-20261010.md#phase-0-review)
- <a id="project-ai-tooling--2026-10-07"></a>[Project AI tooling — 2026-10-07](07-progress-history-20261010.md#project-ai-tooling--2026-10-07)

</details>

# Release readiness audit

Current snapshot: 2026-10-11. **No alpha or release is ready or published.**
The package remains `0.1.0-dev.0`; no release version/date has been selected.
The [full prior audit](21-release-readiness-history-20261010.md) preserves every
historical evidence row and image/source binding. Current implementation is
summarized in [progress](07-progress.md).

## Evidence ledger

| Scope | Accepted evidence | Limit |
| --- | --- | --- |
| Server publication coordinator | Actual rule/Parquet/atomic control/query, exact replay, cancellation/stale-owner orphan-only and observed lost COMMIT resolution; matching final gates required | Application component with emulated process-local versions; no Standard startup/WAL/custody/private-consumer qualification |
| Shared catalog restore/query | Explicit4-to5 restore, current authority/custody, original notification history/fencing, exact catalog checkpoints and actual Parquet/DataFusion after PostgreSQL restart; all18 cases/46commands; matching final campaign required | Local AMD64 library and emulated durable object versions; Standard integration and operational retirement remain open |
| Latest bounded crash/restore matrix | All18 frozen cases; actual producer SIGKILL/rollback/COMMIT resolution, timeout/takeover, synthetic accepted reply loss and persistent PostgreSQL restart/fresh client | Local AMD64/synthetic effects; matching writer review/final campaign required; Standard integration and independent full-item review remain open |
| Prior stopped restore slice | 36 control unit tests, actual PostgreSQL17.5/immutable-file restore and synthetic current-authority fixture; source-bound writer review/final campaign required | Local Linux AMD64 library; bounded crash/restore now recorded above; Standard integration and independent full-item review remain open |
| Prior shared administrative migration slice | Source-bound workspace acceptance; 26 control unit tests, actual PostgreSQL17.5 initialization/populated upgrade/rollback fixture and writer review | Local Linux AMD64 library, SHARED-RUNTIME still in_progress |
| Core phases 0–8 and bounded Phase 10 | Prior source-bound process/container/kind/scans/finite soaks and offline restore | Historical inputs; no automatic current-image or prolonged stability claim |
| Finite implementation ledger | 52 items: 10 passed_local, 10 passed_simulated, 1 in_progress, 25 pending, 6 external_pending | Simulated and local proof remain distinct from actual external acceptance |
| Completed public CI38b3c6f (run38119398746) | Both native Rust jobs pass and production images build; verified artifacts show AMD64 query413 and ARM64 atomic diagnostic monitor race in pipeline qualification | Harness corrections under `target/native-ci-fixes-20261011T095750+0200/` require matching final acceptance and fresh complete remote CI |
| Observed public CIc2bdf6c (run38120937629) | Both Rust jobs pass; ARM64 container job fails and AMD64 native qualification is still running at observation | Current1f2beff run38123061324 is queued; no complete reviewed-revision CI or ARM64 qualification claimed |

Exact latest evidence (valid only once its source-bound final campaign passes):
`target/goal-execution-20261007/SHARED-RUNTIME/matrix-20261010/acceptance.json`
with its matching passed campaign. Stopped restore evidence remains under `restore-20261010/`;
migration evidence remains under its separate
`migration-20261010/` directory.
Earlier named evidence IDs (W/P/I/B/S/D/Q/R/A/C/K/T/V/O/F/L/H/Z/N/J/Y/X
and later additions) retain their exact rows in the
[historical evidence ledger](21-release-readiness-history-20261010.md#evidence-ledger).
Its code acceptance remains tied to its source identities. Original progress/audit
bytes are now retained in the dated history files; those archives preserve the
older report's documentation identities without rewriting accepted reports.

## Required gates still open

| Gate | Remaining requirement |
| --- | --- |
| SHARED-RUNTIME | Standard startup/WAL/global findings/private consumers, operational restore/retirement integration and independent full-item review; no replicas enabled |
| Native ARM64 | Full architecture-specific runtime/pipeline/container/Kubernetes/benchmark evidence; partial passing Rust CI is insufficient |
| Current container/kind/supply chain | Fresh matching reviewed source/config/image; prior current-kind attempts hit PVC/host-resource exhaustion |
| Actual EKS/AWS | Authorized environment, namespace, storage and persistent restart evidence; none is available currently; local kind cannot close this gate |
| Reviewed-revision remote CI | All required jobs and retained matching report artifacts; last recorded pipeline jobs fail |
| Released external dependency | Private application against the actual released version and locked dependency graph |
| Release review/version/publication | Applicable trust/security/restore/package/SBOM review, owner-selected version and explicit release authority |

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

## Documentation map

Public contracts: [ingest](09-phase1-ingest.md), [WAL](10-phase2-wal.md),
[storage](12-phase3-storage.md), [query](13-phase4-query.md),
[core/rules](14-phase5-core.md), [agent](15-phase6-agent.md),
[SDK](16-collector-sdk.md), [overlay](17-external-overlay.md),
[packaging](19-packaging.md), [threat model](20-threat-model.md),
[native qualification](22-native-qualification.md), [candidate](23-local-candidate.md),
[shared contract](47-shared-control-contract.md), [runtime](48-shared-control-runtime.md).
See [definition of done](06-definition-of-done.md), [ledger](31-execution-ledger.json),
[routing](11-model-work-plan.md), [AI workflow](49-ai-execution-workflow.md),
[benchmarks](../BENCHMARKS.md), [changes](../CHANGELOG.md) and [upgrade policy](../UPGRADING.md).
Keep private policy, identity and environment values in the separate application.

<details>
<summary>Historical heading links (compatibility index)</summary>

- <a id="shared-control-publication-primitives-locally-qualified--2026-10-10"></a>[Shared-control publication primitives locally qualified — 2026-10-10](21-release-readiness-history-20261010.md#shared-control-publication-primitives-locally-qualified--2026-10-10)
- <a id="shared-control-lease-foundation-under-implementation--2026-10-09"></a>[Shared-control lease foundation under implementation — 2026-10-09](21-release-readiness-history-20261010.md#shared-control-lease-foundation-under-implementation--2026-10-09)
- <a id="standard-shared-control-contract-accepted--2026-10-09"></a>[Standard shared-control contract accepted — 2026-10-09](21-release-readiness-history-20261010.md#standard-shared-control-contract-accepted--2026-10-09)
- <a id="small-composed-pilot-accepted-locally--2026-10-09"></a>[Small composed pilot accepted locally — 2026-10-09](21-release-readiness-history-20261010.md#small-composed-pilot-accepted-locally--2026-10-09)
- <a id="restricted-role-audit-composition-and-local-closeout--2026-10-09"></a>[Restricted-role audit composition and local closeout — 2026-10-09](21-release-readiness-history-20261010.md#restricted-role-audit-composition-and-local-closeout--2026-10-09)
- <a id="bounded-browser-readiness-correction--2026-10-09"></a>[Bounded browser readiness correction — 2026-10-09](21-release-readiness-history-20261010.md#bounded-browser-readiness-correction--2026-10-09)
- <a id="audit-credential-rotation-and-restored-data-authority--2026-10-09"></a>[Audit credential rotation and restored-data authority — 2026-10-09](21-release-readiness-history-20261010.md#audit-credential-rotation-and-restored-data-authority--2026-10-09)
- <a id="fixed-pipeline-failure-diagnostics--2026-10-09"></a>[Fixed pipeline failure diagnostics — 2026-10-09](21-release-readiness-history-20261010.md#fixed-pipeline-failure-diagnostics--2026-10-09)
- <a id="explicit-s3-sse-kms-request-selection--2026-10-09"></a>[Explicit S3 SSE-KMS request selection — 2026-10-09](21-release-readiness-history-20261010.md#explicit-s3-sse-kms-request-selection--2026-10-09)
- <a id="local-verified-identity-and-independent-audit-composition--2026-10-09"></a>[Local verified identity and independent audit composition — 2026-10-09](21-release-readiness-history-20261010.md#local-verified-identity-and-independent-audit-composition--2026-10-09)
- <a id="restricted-receiver-file-access-qualification--2026-10-09"></a>[Restricted receiver file-access qualification — 2026-10-09](21-release-readiness-history-20261010.md#restricted-receiver-file-access-qualification--2026-10-09)
- <a id="bounded-independent-receiver-health-probe--2026-10-09"></a>[Bounded independent receiver health probe — 2026-10-09](21-release-readiness-history-20261010.md#bounded-independent-receiver-health-probe--2026-10-09)
- <a id="automatic-rust-target-diagnostics--2026-10-09"></a>[Automatic Rust target diagnostics — 2026-10-09](21-release-readiness-history-20261010.md#automatic-rust-target-diagnostics--2026-10-09)
- <a id="native-ci-status--2026-10-09"></a>[Native CI status — 2026-10-09](21-release-readiness-history-20261010.md#native-ci-status--2026-10-09)
- <a id="ext-ci-native-failure-diagnostics--2026-10-09"></a>[EXT-CI native failure diagnostics — 2026-10-09](21-release-readiness-history-20261010.md#ext-ci-native-failure-diagnostics--2026-10-09)
- <a id="independent-receiver-composition--2026-10-09"></a>[Independent receiver composition — 2026-10-09](21-release-readiness-history-20261010.md#independent-receiver-composition--2026-10-09)
- <a id="independent-audit-receiver-host--2026-10-09"></a>[Independent audit receiver host — 2026-10-09](21-release-readiness-history-20261010.md#independent-audit-receiver-host--2026-10-09)
- <a id="independent-audit-http-transport--2026-10-09"></a>[Independent audit HTTP transport — 2026-10-09](21-release-readiness-history-20261010.md#independent-audit-http-transport--2026-10-09)
- <a id="independent-audit-receipt-journal--2026-10-09"></a>[Independent audit receipt journal — 2026-10-09](21-release-readiness-history-20261010.md#independent-audit-receipt-journal--2026-10-09)
- <a id="native-startup-activation-audit--2026-10-09"></a>[Native startup activation audit — 2026-10-09](21-release-readiness-history-20261010.md#native-startup-activation-audit--2026-10-09)
- <a id="validated-rule-revision-primitive--2026-10-09"></a>[Validated rule revision primitive — 2026-10-09](21-release-readiness-history-20261010.md#validated-rule-revision-primitive--2026-10-09)
- <a id="native-ingest-control-audit--2026-10-09"></a>[Native ingest control audit — 2026-10-09](21-release-readiness-history-20261010.md#native-ingest-control-audit--2026-10-09)
- <a id="native-coverage-access-audit--2026-10-09"></a>[Native coverage access audit — 2026-10-09](21-release-readiness-history-20261010.md#native-coverage-access-audit--2026-10-09)
- <a id="native-findings-access-audit--2026-10-09"></a>[Native findings access audit — 2026-10-09](21-release-readiness-history-20261010.md#native-findings-access-audit--2026-10-09)
- <a id="security-audit-native-query-hook--2026-10-09"></a>[SECURITY-AUDIT native query hook — 2026-10-09](21-release-readiness-history-20261010.md#security-audit-native-query-hook--2026-10-09)
- <a id="ext-ci-reported-idp-failure-stages--2026-10-09"></a>[EXT-CI reported IdP failure stages — 2026-10-09](21-release-readiness-history-20261010.md#ext-ci-reported-idp-failure-stages--2026-10-09)
- <a id="ext-ci-legacy-candidate-fixture-correction--2026-10-09"></a>[EXT-CI legacy candidate fixture correction — 2026-10-09](21-release-readiness-history-20261010.md#ext-ci-legacy-candidate-fixture-correction--2026-10-09)
- <a id="security-audit-durable-control-outbox--2026-10-09"></a>[SECURITY-AUDIT durable control outbox — 2026-10-09](21-release-readiness-history-20261010.md#security-audit-durable-control-outbox--2026-10-09)
- <a id="ext-ci-failure-diagnostics--2026-10-09"></a>[EXT-CI failure diagnostics — 2026-10-09](21-release-readiness-history-20261010.md#ext-ci-failure-diagnostics--2026-10-09)
- <a id="security-audit-destination-client-slice--2026-10-09"></a>[SECURITY-AUDIT destination client slice — 2026-10-09](21-release-readiness-history-20261010.md#security-audit-destination-client-slice--2026-10-09)
- <a id="security-audit-protocol-slice--2026-10-09"></a>[SECURITY-AUDIT protocol slice — 2026-10-09](21-release-readiness-history-20261010.md#security-audit-protocol-slice--2026-10-09)
- <a id="security-transport-complete-locally--2026-10-09"></a>[SECURITY-TRANSPORT complete locally — 2026-10-09](21-release-readiness-history-20261010.md#security-transport-complete-locally--2026-10-09)
- <a id="security-transport-shared-collector-tls--2026-10-09"></a>[SECURITY-TRANSPORT shared collector TLS — 2026-10-09](21-release-readiness-history-20261010.md#security-transport-shared-collector-tls--2026-10-09)
- <a id="security-transport-native-mtls-slice--2026-10-09"></a>[SECURITY-TRANSPORT native mTLS slice — 2026-10-09](21-release-readiness-history-20261010.md#security-transport-native-mtls-slice--2026-10-09)
- <a id="security-access-established-idp-acceptance--2026-10-09"></a>[SECURITY-ACCESS established IdP acceptance — 2026-10-09](21-release-readiness-history-20261010.md#security-access-established-idp-acceptance--2026-10-09)
- <a id="security-access-coverage-identity-boundary--2026-10-09"></a>[SECURITY-ACCESS coverage identity boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-coverage-identity-boundary--2026-10-09)
- <a id="security-access-finding-boundary--2026-10-09"></a>[SECURITY-ACCESS finding boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-finding-boundary--2026-10-09)
- <a id="security-access-composed-server-boundary--2026-10-09"></a>[SECURITY-ACCESS composed-server boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-composed-server-boundary--2026-10-09)
- <a id="security-access-producer-route-boundary--2026-10-09"></a>[SECURITY-ACCESS producer-route boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-producer-route-boundary--2026-10-09)
- <a id="security-access-query-grant-boundary--2026-10-09"></a>[SECURITY-ACCESS query-grant boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-query-grant-boundary--2026-10-09)
- <a id="security-access-native-backend-boundary--2026-10-09"></a>[SECURITY-ACCESS native-backend boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-native-backend-boundary--2026-10-09)
- <a id="security-access-introspection-profile-boundary--2026-10-09"></a>[SECURITY-ACCESS introspection-profile boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-introspection-profile-boundary--2026-10-09)
- <a id="security-access-grant-only-boundary--2026-10-09"></a>[SECURITY-ACCESS grant-only boundary — 2026-10-09](21-release-readiness-history-20261010.md#security-access-grant-only-boundary--2026-10-09)
- <a id="retention-parent-localsimulation-acceptance--2026-10-09"></a>[RETENTION parent local/simulation acceptance — 2026-10-09](21-release-readiness-history-20261010.md#retention-parent-localsimulation-acceptance--2026-10-09)
- <a id="exact-query-version-reclamation-boundary--2026-10-09"></a>[Exact query-version reclamation boundary — 2026-10-09](21-release-readiness-history-20261010.md#exact-query-version-reclamation-boundary--2026-10-09)
- <a id="logical-query-retirement-boundary--2026-10-08"></a>[Logical query-retirement boundary — 2026-10-08](21-release-readiness-history-20261010.md#logical-query-retirement-boundary--2026-10-08)
- <a id="stopped-derived-cache-boundary--2026-10-08"></a>[Stopped derived-cache boundary — 2026-10-08](21-release-readiness-history-20261010.md#stopped-derived-cache-boundary--2026-10-08)
- <a id="advisory-retention-boundary--2026-10-08"></a>[Advisory retention boundary — 2026-10-08](21-release-readiness-history-20261010.md#advisory-retention-boundary--2026-10-08)
- <a id="monolithic-s3-query-simulation-boundary--2026-10-08"></a>[Monolithic S3 query simulation boundary — 2026-10-08](21-release-readiness-history-20261010.md#monolithic-s3-query-simulation-boundary--2026-10-08)
- <a id="committed-object-query-boundary--2026-10-08"></a>[Committed object-query boundary — 2026-10-08](21-release-readiness-history-20261010.md#committed-object-query-boundary--2026-10-08)
- <a id="selected-query-s3-adapter-boundary--2026-10-08"></a>[Selected query S3 adapter boundary — 2026-10-08](21-release-readiness-history-20261010.md#selected-query-s3-adapter-boundary--2026-10-08)
- <a id="small-query-publication-boundary--2026-10-08"></a>[Small query publication boundary — 2026-10-08](21-release-readiness-history-20261010.md#small-query-publication-boundary--2026-10-08)
- <a id="public-repository-and-partial-native-ci--2026-10-08"></a>[Public repository and partial native CI — 2026-10-08](21-release-readiness-history-20261010.md#public-repository-and-partial-native-ci--2026-10-08)
- <a id="object-parquet-cpu-seam--2026-10-08"></a>[Object Parquet CPU seam — 2026-10-08](21-release-readiness-history-20261010.md#object-parquet-cpu-seam--2026-10-08)
- <a id="object-query-manifest-contract--2026-10-08"></a>[Object-query manifest contract — 2026-10-08](21-release-readiness-history-20261010.md#object-query-manifest-contract--2026-10-08)
- <a id="protected-route-composition-acceptance--2026-10-08"></a>[Protected route composition acceptance — 2026-10-08](21-release-readiness-history-20261010.md#protected-route-composition-acceptance--2026-10-08)
- <a id="protected-authenticated-role-transport--2026-10-08"></a>[Protected authenticated role transport — 2026-10-08](21-release-readiness-history-20261010.md#protected-authenticated-role-transport--2026-10-08)
- <a id="native-originalreceipt-and-conservative-coverage--2026-10-08"></a>[Native original/receipt and conservative coverage — 2026-10-08](21-release-readiness-history-20261010.md#native-originalreceipt-and-conservative-coverage--2026-10-08)
- <a id="retained-native-proof-history-and-independent-current-head--2026-10-08"></a>[Retained native proof history and independent current head — 2026-10-08](21-release-readiness-history-20261010.md#retained-native-proof-history-and-independent-current-head--2026-10-08)
- <a id="bounded-independent-archive-mechanism--2026-10-08"></a>[Bounded independent archive mechanism — 2026-10-08](21-release-readiness-history-20261010.md#bounded-independent-archive-mechanism--2026-10-08)
- <a id="independent-receipt-custody-and-fenced-source-ack--2026-10-08"></a>[Independent receipt custody and fenced source ACK — 2026-10-08](21-release-readiness-history-20261010.md#independent-receipt-custody-and-fenced-source-ack--2026-10-08)
- <a id="native-cloudtrail-byte-proofs-and-read-only-capture--2026-10-08"></a>[Native CloudTrail byte proofs and read-only capture — 2026-10-08](21-release-readiness-history-20261010.md#native-cloudtrail-byte-proofs-and-read-only-capture--2026-10-08)
- <a id="scoped-audited-disposition-backend--2026-10-08"></a>[Scoped audited disposition backend — 2026-10-08](21-release-readiness-history-20261010.md#scoped-audited-disposition-backend--2026-10-08)
- <a id="private-bounded-notification-delivery--2026-10-08"></a>[Private bounded notification delivery — 2026-10-08](21-release-readiness-history-20261010.md#private-bounded-notification-delivery--2026-10-08)
- <a id="private-outbox-transaction--2026-10-08"></a>[Private outbox transaction — 2026-10-08](21-release-readiness-history-20261010.md#private-outbox-transaction--2026-10-08)
- <a id="durable-findings-cursor--2026-10-08"></a>[Durable findings cursor — 2026-10-08](21-release-readiness-history-20261010.md#durable-findings-cursor--2026-10-08)

</details>

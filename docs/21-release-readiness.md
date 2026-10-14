# Release readiness audit

Current snapshot: 2026-10-14. **No alpha or release is ready or published.**
The package remains `0.1.0-dev.0`; no release version/date has been selected.
The [full prior audit](21-release-readiness-history-20261010.md) preserves every
historical evidence row and image/source binding. Current implementation is
summarized in [progress](07-progress.md).

## Evidence ledger

| Scope | Accepted evidence | Limit |
| --- | --- | --- |
| Local SHARED-RUNTIME | Independent full-item review closes at b9c58da with SHARED-METRICS-1 resolved; current 919default/976all-feature, bothstrictClippy,18-case/server/nativeHTTP190.91s, Standard/scrape180.44s, audit/private/restored5 refresh53.10s/42.80s/75.26s; `target/shared-runtime-refresh-20261012/INDEPENDENT-LOCAL-ACCEPTANCE.json` | Local AMD64 with actual PostgreSQL and simulated S3/custody; Standard Kubernetes, corrected native/currentCI, AWS/EKS/released dependency/version/publication remain separate |
| Native Standard executable | Run38212500862 at16ca254 passes AMD64/ARM64 Rust jobs; GitHub artifact digests, matching native ELF/binary identities,159current runtime source hashes and five Standard scenarios per architecture verified;170.97s/168.97s with owned cleanup; `target/native-ci-monitor-20261012/VERIFIED-NATIVE-STANDARD.json` | Real PostgreSQL TLS and simulated versioned S3 process scope; excludes Standard Kubernetes, private consumer/restore, actual AWS, independent full-item review and release acceptance |
| Stopped Standard lifecycle | Writer-reviewed750b004;919default/976all-feature tests, both strict Clippy,36guards, catalog4/restored5 campaigns181.75s/76.30s; source binding at`target/stopped-retirement-20261011/ACCEPTANCE.json` | Earlier local AMD64 slice; current independent full-item review recorded above; external retention/custody and release gates remain; no remote DELETE |
| Standard executable and fresh scoped restore | Writer-reviewed pushed1273054;914default/971all-feature tests, both strict Clippy modes,36guards, all18matrix cases and actual pipeline/audit/private/restore process campaigns; exact binding at`target/standard-main-20261011T104031+0200/ACCEPTANCE.json` | Earlier local AMD64/loopback S3/private-destination slice; current independent full-item review recorded above; external/release gates remain |
| Server publication coordinator | Actual rule/Parquet/atomic control/query, exact replay, cancellation/stale-owner orphan-only and observed lost COMMIT resolution; matching final gates required | Application component with emulated process-local versions; no Standard startup/WAL/custody/private-consumer qualification |
| Shared catalog restore/query | Explicit4-to5 restore, current authority/custody, original notification history/fencing, exact catalog checkpoints and actual Parquet/DataFusion after PostgreSQL restart; all18 cases/46commands; matching final campaign required | Local AMD64 library and emulated durable object versions; Standard integration and operational retirement remain open |
| Latest bounded crash/restore matrix | All18 frozen cases; actual producer SIGKILL/rollback/COMMIT resolution, timeout/takeover, synthetic accepted reply loss and persistent PostgreSQL restart/fresh client | Local AMD64/synthetic effects; matching writer review/final campaign required; Standard integration and independent full-item review remain open |
| Prior stopped restore slice | 36 control unit tests, actual PostgreSQL17.5/immutable-file restore and synthetic current-authority fixture; source-bound writer review/final campaign required | Local Linux AMD64 library; bounded crash/restore now recorded above; Standard integration and independent full-item review remain open |
| Prior shared administrative migration slice | Source-bound workspace acceptance; 26 control unit tests, actual PostgreSQL17.5 initialization/populated upgrade/rollback fixture and writer review | Earlier local Linux AMD64 library slice; current local SHARED-RUNTIME acceptance recorded above |
| Core phases 0–8 and bounded Phase 10 | Prior source-bound process/container/kind/scans/finite soaks and offline restore | Historical inputs; no automatic current-image or prolonged stability claim |
| Native CI harness diagnostic refresh — 2026-10-14 | GitHub-digest-verified763099c artifacts identify stale AMD64 PostgreSQL summary guard and an ARM64 transport failure. Corrected exact3-filtered guard:36helper checks,19local transport checks and18-case PostgreSQL matrix149.50s; `target/native-ci-corrections-20261014/ACCEPTANCE.json` | Local tooling acceptance only; sanitized failure location is exposed for the next native run. Actual ARM64 correction and full matching current CI remain open |
| Custody-only consistent restore roots — 2026-10-14 | 933default/994all-feature tests, both strict Clippy modes and18-case actual PostgreSQL matrix121.29s; protected custody-only roots, omission/missing-byte refusal and exact copied receipt bytes; `target/restore-custody-roots-20261014/ACCEPTANCE.json` | Local synthetic object/current-authority slice; native restored-generation fresh custody, production authority, AWS/HA and complete release acceptance remain open |
| Existing-only restored custody lineage — 2026-10-14 | 7frozen gates933default/994all-feature, both strict Clippy modes and18-case PostgreSQL matrix137.01s; exact historical resolution under sealed lineage/current owner, absent/conflicting/tampered/stale refusal, unchanged receipt/quota; `target/restored-custody-lineage-20261014/ACCEPTANCE.json` | Owner-installed additive module; metadata only. Native fresh object verification/API/SDK reconfirmation and production custody remain open |
| Corrected native Rust scope at0991cdf | Both AMD64/ARM64 jobs pass993tests and18-case matrices121.45s/102.10s; primary artifact ZIP digests and cleanup verified; `target/native-ci-monitor-20261014/VERIFIED-CORRECTED-NATIVE-RUST.json` | Earlier exact revision; newer restore changes, full current container/Kubernetes and release qualification remain open |
| Fresh restored confirmation — 2026-10-14 | 7frozen gates935default/996all-feature and18-case PostgreSQL matrix124.66s; three lineage checks/two fresh retained reads, original identity and receipt/quota preservation, cancellation/missing-object refusal; `target/restored-custody-confirmation-20261014/ACCEPTANCE.json` | Generic current-owner coordinator with synthetic file retention/authority; configured native API/SDK reconfirmation remains open |
| Complete native container/Standard kind scope at0991cdf | Both architectures pass container/supply-chain and Standard kind121.37s/98.31s, primary artifact/bundle report hashes, WAL checkpoint2/database facts, replacement recovery and cleanup; `target/native-ci-monitor-20261014/VERIFIED-CORRECTED-NATIVE-CONTAINERS.json` | Exact earlier0991cdf revision; later restore changes and actual AWS/EKS/version/publication remain separate |
| Selected restored startup access — 2026-10-14 | 10frozen gates935default/996all-feature, PostgreSQL143.37s and actual native restored Standard77.36s; exact readonly addon/resolve grants, artifact/routine/ownership validation, ordinary-mode denial and cleanup; `target/restored-custody-startup-20261014/ACCEPTANCE.json` | Startup access checks only; native API/SDK historical confirmation is not yet configured. Provider authority/retention and full external/release gates remain separate |
| Complete local STANDARD-RECOVERY simulation — 2026-10-14 | 12current-source frozen gates935default/996all-feature, native historical restore79.66s/18-case PG122.76s/server-local-loss75.55s; exact control/4objects/WAL/private cursor and immutable receipt, fresh native SDK confirmation, stale owner/invalid backup/missing object/cancellation refusal, owned cleanup; `target/native-restored-custody-20261014/ACCEPTANCE.json` | Replacement17.61s/RPO0 limited to4byte local custody fixture. Trusted authority/retention simulated; actual AWS/AZ/account/HA, physical/prolonged load and current native/CI/images/EKS/released dependencies/version/publication remain open |
| ONBOARDING SDK slice — 2026-10-14 | 8focused regressions and6frozen gates:943default/1004all-feature, both strict Clippy/fmt/workspace; current coverage and per-rule missing/unknown prerequisites, unsupported/unloaded blockers; `target/onboarding-sdk-20261014/ACCEPTANCE.json` | Pure trusted-host snapshot only. Authenticated source/host API, actual engine gating and console qualification remain open; full ONBOARDING not accepted |
| ONBOARDING generic rule gate — 2026-10-14 | 4new regressions and6frozen gates:947default/1008all-feature, both Clippy/fmt/workspace; exact inventory refusal, actual blocked predicate suppression and unchanged enabled finding identities; `target/onboarding-rules-20261014/ACCEPTANCE.json` | Library execution path only. Both Main paths, fresh trusted scoped evidence, authorized assessment and console remain unwired; full ONBOARDING in progress |
| ONBOARDING host/Small/console slice — 2026-10-14 | 13frozen gates:952default/1013all-feature, both Clippy/fmt/workspace,5host regressions,7actual Small TLS-identity/WAL/findings checks,5onboarding/26existing Chromium checks; corrected exact Standard baseline81.17s with cleanup; `target/onboarding-host-20261014/ACCEPTANCE.json` | Both Main paths wired, but Standard onboarding enabled and composed browser/native qualification remain open. Vendor checks/retention synthetic; no AWS/release claim. Full ONBOARDING in progress |
| Complete local ONBOARDING simulation — 2026-10-14 | 37launcher guards/14workspace boundaries, enabled Standard50.31s,14named scenarios/11WAL checkpoints/7actual console-native checks over verified backend mTLS; unchanged952default/1013all-feature and exact binaries; `target/onboarding-standard-20261014/ACCEPTANCE.json` with requirement audit | Signed source/vendor checks and retention synthetic. No actual AWS/vendor, current native/CI/EKS/released-dependency/publication claim; release goal remains open |
| Focused independent RELEASE-REVIEW — 2026-10-14 | Six-domain source and correction reviews, 9 frozen gates, 954/1015 Rust tests and actual Small/Standard/browser regressions; `target/release-review-20261014/ACCEPTANCE.json` | Bounded reviewed source/local AMD64 evidence. Upgrade/trust, current CI/native ARM64, actual AWS/EKS/vendor and publication remain separate |
| UPGRADE development compatibility — 2026-10-14 | Explicit supported state paths; real local PostgreSQL18-case matrix, Small stopped restore and current native Standard restored custody with cleanup; `target/upgrade-20261014/ACCEPTANCE.json` | No released-to-released, provider/AWS/EKS or production recovery proof; publication held |
| Native CI worker fixture correction — 2026-10-14 | Primary-digest-verified AMD64/ARM64 failure artifacts; corrected local six-gate acceptance,954default workspace/84all-feature server at16threads; `target/release-ci-20261014/ACCEPTANCE.json` | Test-only correction; exact corrected-revision remote CI/container/Kubernetes still unqualified |
| Offline RELEASE-TRUST mechanism slice — 2026-10-14 |21real pinned-key Ed25519 signature/tamper/refusal checks, workflow lint and14workspace boundaries; `target/release-trust-20261014/ACCEPTANCE.json` | Local-test inventories only. Full item/baselines/current SBOM/builder/released artifact qualification open; no runtime signature enforcement or publication |
| HOST-AUTH structured authentication slice — 2026-10-14 |958default/1019all-feature,8frozen gates and actual agent/file/spool/server/Parquet/cursor restart; `target/host-auth-20261014/ACCEPTANCE.json` | Synthetic authentication producer; selected runtime sensor capture/coverage and full item remain open |
| Rustls security correction — 2026-10-14 |Exact0.23.46 pins/lock, fresh unfiltered Cargo audit0vulnerabilities,11local gates/958default/1019all-feature and native TLS/Standard proof; `target/rustls-security-20261014/ACCEPTANCE.json` | c1535f1 native image audit fails newly published0.23.45 advisories. Patched image/scan/current native CI and release qualification remain open |
| Current native CI/ARM64 — 2026-10-14 | Complete reviewed e1555a4 run38583003350; both48Rust/1019tests and18container gates,181Standard source hashes/bundle/image/WAL/PVC/cleanup and Cargo audit0/containerHIGH-CRITICAL0; `target/rustls-security-20261014/EXTERNAL-ACCEPTANCE.json` | Actual native GitHub qualification; synthetic identity/S3, finite soaks. AWS/EKS/vendor/released-dependency/version/publication remain open |
| CLOUDFLARE selected profile — 2026-10-14 | Six frozen gates;962/1023 tests;11focused object regressions; `target/cloudflare-profile-20261014/ACCEPTANCE.json` | Synthetic selected-schema projection; live vendor delivery/custody/coverage remain separate |
| SYSLOG parser/framing slice — 2026-10-14 | Eight frozen gates; 966/1027 Rust tests; actual file/spool/server outage/SIGKILL exact replay/cursor restart | Synthetic native records. Full site TCP/TLS receiver and authenticated source/composed replay remain open |
| SYSLOG dedicated TCP/mTLS receiver — 2026-10-14 | Eight frozen gates;967/1028Rust tests;11actual local composed checks; `target/syslog-transport-20261014/ACCEPTANCE.json` | Synthetic peer/device. Source pin, limits, saturation/deadline/replay/shutdown qualified locally; current matching native CI, actual firmware/site/device loss/coverage remain separate |
| M365 selected Activity provider — 2026-10-14 | Six frozen gates;979/1040Rust tests;11integration/1identity regression; `target/m365-20261014/ACCEPTANCE.json` | Local HTTP/filesystem/crash simulation, trusted private journal/token hooks. Actual Microsoft permissions/subscriptions/coverage/host custody and matching nativeCI remain separate |
| CATO selected eventsFeed provider — 2026-10-14 | Six frozen gates;990/1051Rust tests;11integration tests; `target/cato-20261014/ACCEPTANCE.json` | Local HTTP/filesystem/SIGKILL simulation. Opaque marker validity, independent coverage, actual Cato permissions/retention/private custody and matching nativeCI remain separate |
| HOST-AUTH Falco runtime foundation — 2026-10-14 | Nine frozen gates;994/1055Rust tests; five synthetic records with exact actual spool/SIGKILL/query replay; pinned CLI fields/rules and workflow lint; `target/host-runtime-20261014/ACCEPTANCE.json` | Native capture gate wired on both architectures. Full HOST-AUTH, independent current sensor coverage and matching nativeCI remain pending |
| Separate native runtime probe wiring — 2026-10-14 | Nine frozen local gates994/1055tests, refusal checks, workflow lint and unchanged delivery simulation; `target/host-runtime-probe-20261014/ACCEPTANCE.json` | Actual native capture/SDK projection and full original composed CI still required; full HOST-AUTH remains pending |
| Separate native runtime probe wiring — 2026-10-14 | Nine frozen local gates994/1055tests, refusal checks, workflow lint and unchanged delivery simulation; `target/host-runtime-probe-fix-20261014/ACCEPTANCE.json` | Actual native capture/SDK projection and full original composed CI still required; full HOST-AUTH remains pending |
| Native runtime schema correction — 2026-10-14 | Eleven frozen local gates995/1056tests; actual verified AMD64/ARM64 input capture and nine-record exact local replay each; `target/host-native-schema-20261014/ACCEPTANCE.json` | Current native decoder/runtime and independent sensor coverage remain pending; no full HOST-AUTH closeout |
| HOST-AUTH selected complete local/native profile — 2026-10-14 | Both native kernel/SDK/agent/spool/SIGKILL/server/query paths, nine exact records each, primary digests/source/identity/cleanup; `target/host-native-schema-20261014/HOST-AUTH-ACCEPTANCE.json` | Selected finite fixture scope; production independent coverage/full-host/credential-read/prolonged behavior unqualified |
| Finite implementation ledger | 52 items: 13 passed_local, 20 passed_simulated, 2 passed_external, 13 pending, 0 in_progress, 4 external_pending | OBJECT-CUSTODY passes local simulation:932default/993all-feature tests; authenticated API/SDK13.56s and actual Standard custody38.34s with cleanup. Provider retention simulated; AWS/account/AZ loss and current external/release gates remain open. Whole implementation inventory includes later work, not a release-readiness percentage |
| Completed public CI38b3c6f (run38119398746) | Both native Rust jobs pass and production images build; verified artifacts show AMD64 query413 and ARM64 atomic diagnostic monitor race in pipeline qualification | Harness corrections under `target/native-ci-fixes-20261011T095750+0200/` require matching final acceptance and fresh complete remote CI |
| Observed public CIc2bdf6c (run38120937629) | Both Rust jobs pass; ARM64 container job fails and AMD64 native qualification is still running at observation | Current1f2beff run38123061324 is queued; no complete reviewed-revision CI or ARM64 qualification claimed |

The helper-fix`bee52db` run38206257117 passes both native Rust jobs. Verified,
primary-digest-matched reports show976tests per architecture and successful
PostgreSQL crash/restore; ARM64 native container, seven pipeline profiles, two
120-second soaks, kind and supply-chain reports are verified separately under
`target/native-ci-monitor-20261012/`. These are bounded Small/default runtime
results at the earlier source, not current Standard-enabled or EKS/release proof.

The newer Standard-enabled`f299633` run38208362422 fails ARM64 at the agent
process gate's offline recovery expectation. Its exact primary-digest-verified log
and a forced real accepted-reply-loss reproduction are retained under
`target/arm64-agent-process-20261012/`. Valid duplicate delivery exposed an
exactly-once test oracle inconsistent with ADR012; the original remote log does
not distinguish missing versus duplicated rows. Writer-reviewed`7d5d83f` enforces
complete logical events, stable original IDs/full payloads, original durable
spool/physical SIGKILL, actual uncertainty/exact replay and restart retention.
Five guard tests, full process/Cargo process tests and workflow checks pass.
Both native Rust jobs pass at16ca254, including the Standard executable fixture;
their digest-verified runtime reports are recorded above. Container/Kubernetes
jobs remain in progress at the retained observation. Latest-revision CI and full
matching qualification remain required.

Earlier matrix evidence (valid only once its source-bound final campaign passes):
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
| Standard Kubernetes | Complete27281e3 run38246315239 and primary-digest/source/bundle/image-bound native profiles pass107.40s AMD64/114.57s ARM64: native TLS/probes, regular Secret files, original CRC/WAL checkpoint2/floor0/database facts and same-PVC SIGKILL/pod replacement recovery/cleanup; `target/standard-kind-ci-20261012/NATIVE-STANDARD-ACCEPTANCE.json`. Synthetic identity/S3; actual EKS/AWS and later current-revision CI remain open; no replicas or remote DELETE |
| Native ARM64 | Full architecture-specific runtime/pipeline/container/Kubernetes/benchmark evidence; partial passing Rust CI is insufficient |
| Current container/kind/supply chain | Fresh matching reviewed source/config/image; prior current-kind attempts hit PVC/host-resource exhaustion |
| Actual EKS/AWS | Authorized environment, namespace, storage and persistent restart evidence; none is available currently; local kind cannot close this gate |
| Reviewed-revision remote CI | Reviewed metrics revision b9c58da run38237870960 succeeds. Later0c73951 run38243101139 passes both976-test/five Standard process jobs and AMD64 full native qualification; ARM64 passes container/pipeline/soak/kind but a pinned security-tool download returns HTTP504, leaving supply-chain/full CI unqualified. New Standard cluster workflow27281e3 run38246315239 is active and requires matching results |
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

WINDOW passes local simulation acceptance — 2026-10-15. Bounded authentication event-time/watermark/lateness, canonical replay identity, key/event/byte/TTL/output/history limits, unknown coverage and atomic state/findings/checkpoint recovery are qualified. Six frozen workspace gates pass1048default/1117all-feature tests, both strict Clippy modes, formatting and14workspace boundaries. Actual Small Main passes5WINDOW/8onboarding checks; Standard Main passes8scenarios; shared recovery passes53checks in206.73s. Runtime source bindings109/266/246 match; retained Small/Standard executable identities match and owned cleanup succeeds. Writer review closed three reproduced findings; it is not independent release review. Evidence:`target/window-20261014/ACCEPTANCE.json`; [contract64](64-authentication-window.md). LinuxAMD64 with actual SQLite/PostgreSQL/Parquet/WAL and SIGKILL; signed host/object authority is synthetic. Inventory35accepted/17unfinished. Current remote/native/container/Kubernetes, AWS/EKS, released dependencies, version and publication remain separate. Next local dependency-ready detector:SENSOR-HEALTH; Phase9 AWS collection requires a separate task.

WINDOW native CI wiring — 2026-10-15. Both existing AMD64/ARM64 Rust jobs now run
the actual Small `--window` recovery fixture and Standard `--standard-scenario window`
process fixture after exact all-feature builds. Existing fixture deadlines, pinned
PostgreSQL image and artifact retention apply; the copied Standard executable is
excluded from upload. Workflow lint and16CI-helper checks pass. Remote results
remain unqualified; no publication is enabled.

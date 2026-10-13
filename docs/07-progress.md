# Implementation progress

Current snapshot: 2026-10-14. No alpha/release is ready or published; package
version is`0.1.0-dev.0` and no release version is selected. Read
[release boundaries](21-release-readiness.md), [the finite ledger](31-execution-ledger.json)
and [next task/routing](11-model-work-plan.md).

Exact earlier records: [2026-10-12 progress archive](07-progress-history-20261012.md)
and [2026-10-10 progress archive](07-progress-history-20261010.md). Archives retain
all original counts, source identities, diagnostic failures and evidence limits.

## Current implementation and evidence

Standard integration is accepted locally at`1273054`; stopped lifecycle is
writer-reviewed at`750b004`. Exact source-bound evidence:
`target/standard-main-20261011T104031+0200/ACCEPTANCE.json` and
`target/stopped-retirement-20261011/ACCEPTANCE.json`.

The latter passes919default/976all-feature tests, both strict Clippy modes,
14workspace boundaries,36launcher guards and five real-WAL regressions. Current
catalog4/restored5 campaigns pass181.75s/76.30s with owned cleanup and original
WAL checkpoints2/3 unchanged. Strict separate maintenance credentials, current
complete fencing, explicit restore/replay/evidence holds, release/exact tombstones
and bounded retained shutdown are qualified. No provider DELETE or replicas are
enabled. Local AMD64/loopback provider and private-destination simulation do not
prove external custody, actual EKS or full native ARM64 release qualification.

## Current CI work

Native CI at`763099c` fails AMD64 on a stale PostgreSQL test-summary guard
(the actual test passed with3filtered tests) and ARM64 in transport. Digest-verified
artifacts:`target/native-ci-monitor-20261014/`. The corrected exact inventory
guard and sanitized transport failure location pass36helper checks,19local
transport checks and the18-case PostgreSQL matrix149.50s with owned cleanup:
`target/native-ci-corrections-20261014/ACCEPTANCE.json`. Both native Rust jobs at`0991cdf` now pass993tests and18-case PostgreSQL matrices
121.45s/102.10s with GitHub-digest-verified artifacts and cleanup:
`target/native-ci-monitor-20261014/VERIFIED-CORRECTED-NATIVE-RUST.json`.
At`0991cdf`, both complete native container/Standard kind jobs now also pass,
including supply-chain gates, bundle/source bindings, original WAL/PVC recovery
and cleanup121.37s/98.31s. Verified artifacts:
`target/native-ci-monitor-20261014/VERIFIED-CORRECTED-NATIVE-CONTAINERS.json`.
Later restore changes and current release CI remain open.

Earlier CI, agent-oracle and Helm preparation records are preserved in
[the2026-10-14 history](07-progress-history-20261014.md).
<a id="agent-recovery-oracle-correction--2026-10-12"></a>
<a id="standard-helm-runtime-configuration-prepared--2026-10-12"></a>

## Object custody and recovery — 2026-10-14

OBJECT-CUSTODY now passes locally as simulated acceptance — 2026-10-14.
All12frozen gates pass:932default/993all-feature tests, both strict Clippy modes,
36helper guards, authenticated PostgreSQL TLS/S3/mTLS API/SDK13.56s and actual
Standard Main custody38.34s with owned cleanup. Explicit custody permission and
producer SQL capability precede ready; fresh nonce and request-start expiry bind
confirmation. PUT-only/stopped copies stay retained; restart reuses the original
receipt ID before checked release. [Contract51](51-object-custody.md), evidence:
`target/object-custody-api-20261012/ACCEPTANCE.json`. Provider retention is simulated;
AWS/AZ/account loss and current release gates remain open. Next:STANDARD-RECOVERY.

STANDARD-RECOVERY passes locally as simulated acceptance — 2026-10-14.
All12corrected frozen gates pass:935default/996all-feature tests, both strict
Clippy modes and36helper checks. Actual native mTLS Main/SDK historical
restore79.66s,18-case PostgreSQL ownership/restore122.76s and actual server-local
loss/checkpoint recovery75.55s retain current source/binary identities and cleanup.
Replacement17.61s includes old lease expiry; RPO0 covers only the4byte custody
fixture with independently retained control/object/checkpoint domains.

Exact4-object/control/scope/WAL/private-progress restore preserves historical
receipt description/generation/digest; fresh SDK nonce, ingest-only/governance
hold and checked test-only release qualify the native path. Missing enrolled
WAL/corrupt backup/objects and stale generation/owner/cancelled or late control
completion refuse. Explicit restored_receipts mode validates selected addon
grants before ready; no runtime installation, replica increase or provider DELETE.
Evidence:`target/native-restored-custody-20261014/ACCEPTANCE.json` and its local
requirement audit. [Intermediate records](07-progress-history-20261014.md#earlier-incremental-standard-recovery-records).
Next:ONBOARDING. AWS/AZ/account/HA, physical/prolonged load and current native
CI/images/EKS/released-dependency/version/publication gates remain open.

## Actual local Standard Kubernetes accepted — 2026-10-12

Native CI now prepares one source/revision/architecture-bound executable bundle
per architecture and reuses it for the Standard cluster gate. Direct compiled
enrollment retains exact Rust test/phase assertions and avoids runtime Cargo.
Current frozen local process/kind campaigns pass181.93s/170.05s, bundle guards,
workflow lint and14workspace boundaries. A fresh build reproduces the exact
qualified image ID. Evidence: `target/standard-kind-ci-20261012/ACCEPTANCE.json`.
Run38246315239 at`27281e3` now succeeds on both native architectures. Primary
digests, producing-source/bundle/ELF/image bindings and Standard cluster recovery
are verified:107.40s AMD64/114.57s ARM64, original WAL checkpoint2/floor0/database
facts and owned cleanup. Evidence:
`target/standard-kind-ci-20261012/NATIVE-STANDARD-ACCEPTANCE.json`.
The later`cc3744a` bounded security-tool download retry fix is locally accepted;
its full current-revision CI remains active and unqualified. Next:OBJECT-CUSTODY.

Reviewed metrics revision`b9c58da` run38237870960 passes both native976-test jobs
and five Standard process scenarios each. Primary ZIP digests, native ELF/bytes,
Small container/kind/soak and supply-chain reports are verified under
`target/native-ci-monitor-20261012/VERIFIED-METRICS-*`; no Standard cluster claim.

The current S3-enabled image is qualified in an exclusively owned kind cluster
with native TLS/probes, identity-backed admission and PostgreSQL TLS. Runtime and
TLS documents mount as regular read-only Secret files. Explicit offline enrollment
and coverage initialization retain private modes; startup performs no bootstrap.
Two original events/findings, CRC-protected WAL checkpoint2, original stream/floor0
and database facts survive server SIGKILL and serial pod replacement on the same
PVC. Synthetic versioned objects remain on the PVC across replacement.

Frozen-source acceptance passes in141.13s with167source bindings, two original-
state guards, five Helm regressions, five cleanup guards,36shared helpers and
14workspace boundaries. The failed private-mode attempt and corrected138.08s
focused run are retained. All owned clusters/containers were removed.
Evidence: `target/standard-kubernetes-20261012/ACCEPTANCE.json`.
KIND is accepted locally; identity/S3 remain synthetic. Native Standard cluster
CI, actual EKS/AWS custody, released dependencies and publication remain open.

## Local SHARED-RUNTIME accepted independently — 2026-10-12

Independent review closes local SHARED-RUNTIME at `b9c58da`; the metrics finding
is resolved. Worker fence/deadline/lease accounting, prepared-reference candidate
outcomes and the complete Standard scrape are qualified without private labels.
Current 919 default / 976 all-feature tests, both strict Clippy modes and workspace
checks pass. PostgreSQL/server/native HTTP (18 cases) passes in 190.91s; five
Standard scenarios/scrape in 180.44s; audit/private/restored5 in 53.10s/42.80s/75.26s.
Exact review: `target/shared-runtime-refresh-20261012/INDEPENDENT-LOCAL-ACCEPTANCE.json`.
S3/custody remain simulated. Corrected native CI run38237870960 is in progress at
the retained observation; Standard Kubernetes and external release gates remain.

## Remaining work

The 52-item ledger now records12passed_local,10passed_simulated,23pending/1in_progress
and6external_pending:22accepted within their recorded scope and30unfinished.
Independent review closes local SHARED-RUNTIME at `b9c58da`. Continue with the
native Standard Kubernetes CI profile, then dependency/phase order.
Current native/container/supply-chain, actual EKS/AWS, complete remote CI,
released private dependency and owner-selected release/publication gates remain
open. Finite soaks and synthetic proof do not establish prolonged stability or
physical-device throughput. GHCR publication is prepared in
[the publication contract](50-ghcr-publication.md), with no publication performed.

## Earlier evidence links

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
- <a id="native-ci-cancellation-fixture-corrected--2026-10-12"></a>[native-ci-cancellation-fixture-corrected--2026-10-12](07-progress-history-20261012.md#native-ci-cancellation-fixture-corrected--2026-10-12)
- <a id="stopped-standard-lifecycle-accepted-locally--2026-10-11"></a>[stopped-standard-lifecycle-accepted-locally--2026-10-11](07-progress-history-20261012.md#stopped-standard-lifecycle-accepted-locally--2026-10-11)
- <a id="standard-integration-accepted-locally--2026-10-11"></a>[standard-integration-accepted-locally--2026-10-11](07-progress-history-20261012.md#standard-integration-accepted-locally--2026-10-11)
- <a id="standard-server-startup-publication-and-wal-recovery--2026-10-11"></a>[standard-server-startup-publication-and-wal-recovery--2026-10-11](07-progress-history-20261012.md#standard-server-startup-publication-and-wal-recovery--2026-10-11)
- <a id="public-oss-image-publication-prepared--2026-10-10"></a>[public-oss-image-publication-prepared--2026-10-10](07-progress-history-20261012.md#public-oss-image-publication-prepared--2026-10-10)
- <a id="shared-control-crashrestore-matrix-locally-qualified--2026-10-10"></a>[shared-control-crashrestore-matrix-locally-qualified--2026-10-10](07-progress-history-20261012.md#shared-control-crashrestore-matrix-locally-qualified--2026-10-10)
- <a id="coordinated-stopped-restore-locally-qualified--2026-10-10"></a>[coordinated-stopped-restore-locally-qualified--2026-10-10](07-progress-history-20261012.md#coordinated-stopped-restore-locally-qualified--2026-10-10)
- <a id="shared-control-administrative-migration-locally-qualified--2026-10-10"></a>[shared-control-administrative-migration-locally-qualified--2026-10-10](07-progress-history-20261012.md#shared-control-administrative-migration-locally-qualified--2026-10-10)
- <a id="shared-control-notification-fencing-locally-qualified--2026-10-10"></a>[shared-control-notification-fencing-locally-qualified--2026-10-10](07-progress-history-20261012.md#shared-control-notification-fencing-locally-qualified--2026-10-10)
- <a id="shared-control-retirement-and-retention-locally-qualified--2026-10-10"></a>[shared-control-retirement-and-retention-locally-qualified--2026-10-10](07-progress-history-20261012.md#shared-control-retirement-and-retention-locally-qualified--2026-10-10)
- <a id="shared-control-read-snapshots-locally-qualified--2026-10-10"></a>[shared-control-read-snapshots-locally-qualified--2026-10-10](07-progress-history-20261012.md#shared-control-read-snapshots-locally-qualified--2026-10-10)
- <a id="shared-control-publication-primitives-locally-qualified--2026-10-10"></a>[shared-control-publication-primitives-locally-qualified--2026-10-10](07-progress-history-20261012.md#shared-control-publication-primitives-locally-qualified--2026-10-10)
- <a id="read-only-standard-bootstrap-prerequisite--2026-10-11"></a>[read-only-standard-bootstrap-prerequisite--2026-10-11](07-progress-history-20261012.md#read-only-standard-bootstrap-prerequisite--2026-10-11)
- <a id="next-runnable-work"></a>[next-runnable-work](07-progress-history-20261012.md#next-runnable-work)
- <a id="current-evidence-boundaries"></a>[current-evidence-boundaries](07-progress-history-20261012.md#current-evidence-boundaries)
- <a id="ai-execution-workflow"></a>[ai-execution-workflow](07-progress-history-20261012.md#ai-execution-workflow)
- <a id="fresh-scoped-restore-and-restored-standard-main--2026-10-11"></a>[fresh-scoped-restore-and-restored-standard-main--2026-10-11](07-progress-history-20261012.md#fresh-scoped-restore-and-restored-standard-main--2026-10-11)
- <a id="scoped-restore-rollback-and-uncertain-commit-resolution--2026-10-11"></a>[scoped-restore-rollback-and-uncertain-commit-resolution--2026-10-11](07-progress-history-20261012.md#scoped-restore-rollback-and-uncertain-commit-resolution--2026-10-11)

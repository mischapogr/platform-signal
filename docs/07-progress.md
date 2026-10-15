# Implementation progress

Current snapshot: 2026-10-15. No alpha/release is ready or published; package
version is`0.1.0-dev.0` and no release version is selected. Read
[release boundaries](21-release-readiness.md), [the finite ledger](31-execution-ledger.json)
and [next task/routing](11-model-work-plan.md).

Exact earlier records: [2026-10-12 progress archive](07-progress-history-20261012.md)
and [2026-10-10 progress archive](07-progress-history-20261010.md). Archives retain
all original counts, source identities, diagnostic failures and evidence limits.

## Current implementation and evidence

Latest accepted item:WINDOW (`passed_simulated`),35accepted/17unfinished. Exact
local evidence and release boundaries are recorded in the final entry below.

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

## Onboarding SDK slice — 2026-10-14

ONBOARDING is in progress. The bounded current-readiness SDK assessment passes
8focused regressions and6frozen gates:943default/1004all-feature tests, both
strict Clippy modes, formatting and14workspace boundaries. Historical/stale or
unhealthy coverage cannot activate detections; missing/unknown permissions,
categories or state, unsupported and unloaded rules remain explicitly blocked.
This read-only snapshot trusts host checks and does not enable rules.
[Contract52](52-onboarding-readiness.md), evidence:
`target/onboarding-sdk-20261014/ACCEPTANCE.json`. Next: authenticated scoped host
integration, actual engine gating and console states/blockers; full ONBOARDING
and the release goal remain incomplete. Inventory:24accepted/28unfinished,
including1in-progress item. External/release boundaries remain open.

## Onboarding rule execution gate — 2026-10-14

The generic engine gate passes4new regressions and6frozen gates:947default/
1008all-feature tests, both strict Clippy modes, formatting and14workspace
boundaries. Exact full loaded inventory is required; blocked matching rules
produce no findings, enabled finding IDs/replay stay unchanged, invalid inventory
refuses before evaluation and cancellation/deadline checks remain effective.
[Contract53](53-onboarding-rule-gate.md), evidence:
`target/onboarding-rules-20261014/ACCEPTANCE.json`. This gate is not wired into
Main yet. Next coherent change: fresh trusted scoped host evidence, both Main
paths, authorized assessment reads and console blockers. Coverage history still
reports current_health=unknown and cannot substitute for a live health check.
Full ONBOARDING remains in progress; inventory remains24accepted/28unfinished.

## Onboarding host/Small Main/console integration — 2026-10-14

Opt-in pinned signed host evidence now gates both Main evaluation paths and
exposes an authorized scoped readiness API/console. Missing/forged/expired proof,
unhealthy coverage, missing prerequisites and unverified/mismatched event scope
block activation. No source-health inference from stored history or token entry.
The13frozen gates pass952default/1013all-feature tests, both Clippy/fmt/workspace,
5host regressions,7actual Small TLS-identity/WAL/finding checks,5onboarding and
26existing Chromium console checks. Exact newly built Standard fixture baseline
passes81.17s with cleanup. [Contract54](54-onboarding-host-integration.md), evidence:
`target/onboarding-host-20261014/ACCEPTANCE.json`. Full ONBOARDING remains in
progress: next qualify Standard with onboarding enabled and the composed
browser/native endpoint. Vendor checks/retention are simulated; actual provider
checks, current native CI and release gates remain open. Counts stay24accepted/
28unfinished (1in progress). Earlier integration status above is historical.

## ONBOARDING local acceptance — 2026-10-14

ONBOARDING passes simulated acceptance. The frozen tooling campaign passes
37launcher guards/14workspace boundaries and actual enabled Standard50.31s:
14named scenarios,11original WAL checkpoints and7real console/native checks
over verified backend mTLS. Connected/unverified, verified/active and unsupported
states, independent permission/category/state suppression, signature/expiry,
scope/revocation and restart are audited. Unchanged Rust/build inputs and exact
binaries retain952default/1013all-feature acceptance. [Contract55](55-onboarding-qualification.md), evidence:
`target/onboarding-standard-20261014/ACCEPTANCE.json` and requirement audit.
Earlier integration limits above describe their accepted revisions. Current
inventory:25accepted/27unfinished (12local/13simulated/21pending/0in-progress/
6external). Source/vendor checks and retention are synthetic, not actual AWS or
release proof. Next: RELEASE-REVIEW; Phase9 remains separately scoped.

## RELEASE-REVIEW local acceptance — 2026-10-14

RELEASE-REVIEW passes focused local acceptance — 2026-10-14. Independent review covers durability, replay, cancellation, scope, quotas and production hazards. Account binding, ACK retry deadline and outdated security responsibilities are corrected. Frozen 9 gates pass: 954 default / 1015 all-feature tests, both strict Clippy modes, formatting, 14 workspace boundaries, actual Small and enabled Standard/browser regressions. Evidence: `target/release-review-20261014/ACCEPTANCE.json`. Current inventory: 26 accepted / 26 unfinished (13 local, 13 simulated, 20 pending, 6 external). Next: UPGRADE; current native CI, actual AWS/EKS/vendor and release gates remain open.

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

## UPGRADE local acceptance — 2026-10-14

UPGRADE passes local simulated acceptance — 2026-10-14. The explicit development compatibility matrix binds supported exact schema migrations, fresh-generation restore and refusal of unknown/divergent history. Actual PostgreSQL 18-case matrix, isolated stopped Small WAL/spool/Parquet/findings restore and current native Standard restored custody pass with owned cleanup. Original/backup remain unchanged; the Small fixture ends at 9 events, 2 findings and checkpoint9. Evidence: `target/upgrade-20261014/ACCEPTANCE.json`; [compatibility contract](56-upgrade-compatibility.md). Current inventory:27 accepted/25 unfinished (13local/14simulated/19pending/6external). Released-to-released upgrade, actual AWS/EKS/provider and publication remain unqualified. Next release slice: current-revision KIND/remote CI qualification.

## Native CI fixture correction — 2026-10-14

Native CI test isolation correction — 2026-10-14. Verified public AMD64/ARM64 artifacts at8d4dc06 show positive onboarding fixtures racing the intentionally occupied configuration worker. Test-only shared fixture guards isolate four worker users; production capacity and fail-closed behavior remain unchanged. Six frozen gates pass:954default workspace and84all-feature server tests with16threads, both strict Clippy modes, formatting and14workspace boundaries. Evidence: `target/release-ci-20261014/ACCEPTANCE.json`. Corrected-revision remote CI/native container/Kubernetes qualification remains open; ledger counts remain27accepted/25unfinished.

## Offline release trust slice — 2026-10-14

RELEASE-TRUST offline mechanism slice — 2026-10-14. Externally pinned Ed25519 inventory verification passes21real crypto/unsigned/tamper/key/domain/schema/path/capacity/symlink/FIFO checks over current OSS lock/rule and explicitly unattested local provenance. Private fixture keys are removed. Workflow lint and14workspace boundaries pass; both native CI jobs run the bounded gate. [Contract57](57-offline-release-trust.md), evidence:`target/release-trust-20261014/ACCEPTANCE.json`. Full RELEASE-TRUST remains pending baseline/current SBOM/builder/released artifact qualification. No runtime signature enforcement, update installation or publication authority; counts remain27accepted/25unfinished.

## Structured authentication source slice — 2026-10-14

HOST-AUTH structured authentication slice — 2026-10-14. Opt-in agent auth-json and version1 SDK normalizer preserve source timestamp, authority/principal/target/method/session and producer checkpoints; unknown credential fields reject statically. Four focused regressions and8frozen gates pass:958default/1019all-feature, both strict Clippy modes/fmt/14workspace boundaries, current all-feature binaries and real agent/server process acceptance. Controlled success/failure and2invalid records traverse file/spool/authenticated server/Parquet; cursor restart adds no events and rejected credential bytes stay out of output/logs. [Contract58](58-host-authentication-profile.md), evidence:`target/host-auth-20261014/ACCEPTANCE.json`. File/stdin grants no runtime sensor coverage; full HOST-AUTH remains pending selected sensor qualification. Counts remain27accepted/25unfinished.

## Rustls security correction — 2026-10-14

Rustls security correction — 2026-10-14. Native ARM supply-chain atc1535f1 exposes four newly published Rustls0.23.45 advisories. All five exact pins and the lock now select0.23.46 with unchanged features, following the [upstream security release](https://github.com/rustls/rustls/releases/tag/v/0.23.46). Current unfiltered Cargo audit reports0vulnerabilities against fresh RustSec data. Eleven frozen gates pass958default/1019all-feature, both Clippy modes/fmt/14boundaries,21offline trust checks and current native mTLS/onboarding plus PostgreSQL/TLS/S3/Standard matrices. Evidence:`target/rustls-security-20261014/ACCEPTANCE.json`. Matching patched native CI/images/scans/Kubernetes still required; counts remain27accepted/25unfinished.

## Current native CI accepted — 2026-10-14

Current native CI and ARM64 qualification accepted — 2026-10-14. Complete [run38583003350](https://github.com/mischapogr/platform-signal/actions/runs/38583003350) at reviewed e1555a4 succeeds. Both architectures pass48Rust gates/1019tests and18container gates. Primary GitHub artifact digests,181Standard source hashes, original/stripped executable bundle lineage and exact images match. Standard kind recovery passes114.53sAMD64/104.48sARM64 with original WAL checkpoint2/PVC replacement and owned cleanup. Cargo audit0 and containerHIGH/CRITICAL0;23MEDIUM/8LOW remain. Evidence:`target/rustls-security-20261014/EXTERNAL-ACCEPTANCE.json`. EXT-CI/EXT-ARM64 are passed_external. Inventory:29accepted/23unfinished (13local/14simulated/2external accepted/19pending/4external pending). Actual AWS/EKS/vendor, released-dependency, version and publication gates remain open; synthetic provider and finite-soak limits are retained.

## Selected Cloudflare object profile — 2026-10-14

CLOUDFLARE selected object profile passes simulated acceptance — 2026-10-14. Shared bounded complete-gzip decoding preserves CloudTrail behavior; selected http_requests RFC3339 records enforce five fields, configured account/zone scope and explicit unknown completeness. Four new and seven existing object regressions and six frozen gates pass (962 default / 1023 all-feature tests). Late malformed rows, gzip corruption, limits, cancellation and deadline reject; exact pinned context replays byte-identical events. Evidence: `target/cloudflare-profile-20261014/ACCEPTANCE.json`; [profile contract](59-cloudflare-logpush-profile.md). Actual vendor delivery, durable private custody/ACK and coverage remain external. Inventory:30 accepted /22 unfinished ({'passed_local': 13, 'passed_simulated': 15, 'pending': 18, 'passed_external': 2, 'external_pending': 4}).

## Syslog framing and FortiGate parser slice — 2026-10-14

SYSLOG parser/framing slice — 2026-10-14. Four new SDK fixtures and eight frozen gates pass: 966 default / 1027 all-feature tests, both strict Clippy modes, formatting,14workspace boundaries and actual agent/server process recovery. Bounded octet-counting handles split/coalesced UTF8 byte frames and refuses malformed lengths/incomplete EOF. Selected FortiGate native time/severity stays separate from configured source authority. Two valid/two rejected records qualify real file/spool/server outage/SIGKILL exact canonical replay and cursor restart. [Contract60](60-syslog-fortigate-profile.md), evidence:`target/syslog-20261014/ACCEPTANCE.json`. Full SYSLOG remains pending site TCP/TLS listener/source identity/connection and read bounds/composed outage replay; UDP best effort. Inventory remains30accepted/22unfinished.

## Site syslog receiver local acceptance — 2026-10-14

SYSLOG passes local simulated acceptance — 2026-10-14. Dedicated TCP/mTLS selected FortiGate receiver binds configured source to an authenticated, exact-pinned client leaf, rejects missing/expired/untrusted/wrong peers, and bounds connections/frames/bytes. Actual native fixture qualifies saturated spool backpressure, split/coalesced frames, malformed/EOF refusals, original partial-frame deadline, WAN outage/SIGKILL exact canonical replay and cancellation of active TLS during shutdown. Eleven composed checks and8frozen gates pass:967default/1028all-feature, both strict Clippy modes, formatting,14workspace boundaries and fresh binaries. Native CI now includes the syslog gate on both architectures; matching results are pending. [Contract60](60-syslog-fortigate-profile.md), evidence:`target/syslog-transport-20261014/ACCEPTANCE.json`. Synthetic devices/certificates; actual firmware/buffers/customer coverage/site loss/raw-original custody remain unqualified. Plaintext loopback-only; UDP best effort/unsupported. Inventory:31accepted/21unfinished (13local/16simulated/2external accepted/17pending/4external pending). Next dependency-ready release item:M365; Phase9 AWS collection remains separately scoped.

## Native query cancellation fixture correction — 2026-10-14

Native ARM cancellation fixture correction — 2026-10-14. Primary GitHub-digest-verified parser run38601684472 at9bbfce6 fails query admission_saturation_cancellation_and_expiry_release_capacity with Busy. The test assumed physical I/O retirement immediately after front cancellation; the neighboring dropped-future test already observes the retained lease. Correction waits finitely for physical io_depth0, checks running/depth capacities and preserves immediate front-depth0, exact original event and rejection/timeout/cancellation counters. Five frozen gates pass:967default workspace tests,17all-feature query regressions, strict Clippy/fmt/14workspace boundaries. No production change. Evidence:`target/query-cancel-ci-20261014/ACCEPTANCE.json`; matching current nativeCI remains pending. SYSLOG remains passed_simulated; inventory31accepted/21unfinished.

## Microsoft365 activity provider local acceptance — 2026-10-14

M365 passes selected local provider simulation — 2026-10-14. Bounded Management Activity Audit.AzureActiveDirectory HTTP composes token refresh/429/5xx/outage and finite paged originals/prepared outbox/checkpoints through a trusted private journal hook. Actual filesystem sync/lost commit reply/fresh reload and owned child SIGKILL preserve canonical values and cursor; dedup/conflicts/malformed content/window changes/cycles/expiry refuse without durable advancement. Documented v1 continuation, equivalent UTC window spellings and missing publisher are handled while preserving raw cursor/effective request and exact source scope. Prepared IDs bind window/publisher/source/native identity. Six frozen gates pass979default/1040all-feature, both strict Clippy modes, formatting and14workspace boundaries;11integration and1delivery-identity regressions. [Contract61](61-m365-activity-profile.md), evidence:`target/m365-20261014/ACCEPTANCE.json`. Actual Microsoft permissions/subscriptions/credential exchange/current independent coverage and private host custody remain separate. Inventory32accepted/20unfinished (13local/17simulated/2external accepted/16pending/4external pending). Matching current nativeCI remains pending. Next dependency-ready source:CATO; Phase9 AWS remains separately scoped.

## Cato security eventsFeed local acceptance — 2026-10-14

CATO passes selected local provider simulation — 2026-10-14. One-account Security eventsFeed POST uses current official schema, configured account/TLS/key hook and explicit latest/resume. Original deadlines/cancellation bound retries, key retrieval and complete entity capture; complete page originals/prepared events/checkpoints commit through a trusted private atomic journal. Actual fsync/lost reply/fresh reload and child SIGKILL retain exact canonical values and cursor. Scope/GraphQL/malformed/cycle/expired/capacity refusals preserve durable bytes; chunked-body limits and single-slot admission are qualified. Six frozen gates pass990default/1051all-feature, both strict Clippy modes, formatting and14workspace boundaries;11integration tests. [Contract62](62-cato-eventsfeed-profile.md), evidence:`target/cato-20261014/ACCEPTANCE.json`. Opaque marker validity/independent completeness, cross-page native dedup, actual Cato permissions/retention and private custody/publication remain unqualified. Inventory33accepted/19unfinished (13local/18simulated/2external accepted/15pending/4external pending). Matching current nativeCI remains pending. Next authorized source slice:HOST-AUTH native runtime sensor coverage; Phase9 AWS remains separately scoped.

## Host runtime source foundation — 2026-10-14

HOST-AUTH runtime foundation passes local simulation — 2026-10-14. Selected Falco0.44.1 SDK syscall/process-start and explicit drop/lookup/boot/start/reload health counters compose agent falco-json with configured host/boot binding. Real local file/spool/SIGKILL/server/query replay retains five synthetic canonical records exactly. Missing/duplicate identities, credential-bearing/freeform fields, obsolete evt.dir, wrong engine and missing counters refuse; file opens do not prove credential reads. Pinned CLI field/rule validation passes without kernel capabilities; native ephemeral GitHub capture is wired for both architectures with finite output/deadline/PID/parent/interval/counter/cleanup checks. Nine frozen gates pass994default/1055all-feature, both strict Clippy modes, formatting,14workspace boundaries, fresh binaries, simulated delivery and workflow lint. [Contract63](63-falco-runtime-profile.md), evidence:`target/host-runtime-20261014/ACCEPTANCE.json`. Full HOST-AUTH remains pending actual matching native capture and coverage qualification. Inventory stays33accepted/19unfinished; no native sensor or production current coverage granted by synthetic records.

## Separate native runtime probe — 2026-10-14

Native runtime probe wiring passes locally — 2026-10-14. Separate hosted AMD64/ARM64 workflow obtains actual owned Falco capture before compiling only the collector SDK and invoking an explicitly native-only projection test. Three refusal checks prevent non-CI capture, simulation-as-native and absent-manifest projection. Nine frozen gates pass994default/1055all-feature, both Clippy modes, formatting,14workspace boundaries, workflow lint and exact five-record simulated delivery. Evidence:`target/host-runtime-probe-20261014/ACCEPTANCE.json`. Native probe and original full composed CI remain required; HOST-AUTH stays pending and inventory stays33accepted/19unfinished. This shortens native schema feedback without replacing full server/spool/replay qualification.

## Separate native runtime probe — 2026-10-14

Native runtime probe corrections pass locally — 2026-10-14. Primary-digest-verified AMD64/ARM64 run38624220049 at20aff08 fails before kernel capture because no rule file is loaded. Explicit owned minimal Falco configuration and -c/-r selection now pass capability-free dry-run. A separately reproduced Cargo crate-working-directory failure is corrected with workspace-root capture resolution; four refusal checks pass. Nine frozen gates pass994default/1055all-feature, both Clippy modes, formatting,14workspace boundaries, workflow lint and exact five-record simulated delivery. Evidence:`target/host-runtime-probe-fix-20261014/ACCEPTANCE.json`; original artifacts:`target/host-runtime-probe-20261014/failed-native/`. Corrected native capture/SDK projection and full original composed CI remain required. HOST-AUTH stays pending; inventory33accepted/19unfinished.

## Verified native runtime schema correction — 2026-10-14

Verified native runtime schema correction passes locally — 2026-10-14. Primary-digest-verified run38626726116 at eece8c0 captures real execution/file-open/connection hooks on both native architectures with zero kernel drops and explicit lookup counters; later SDK projection fails on actual Falco shape. Corrected SDK accepts only the fixed internal metric literal, checks injected evt.time equality, and validates boot/reload/capture/event bounds without assuming reload follows capture start. Both real captures project locally; fresh current agent/server retains nine canonical records each exactly through synced offline spool/SIGKILL/restart/query. Eleven frozen gates pass995default/1056all-feature, both Clippy modes, formatting,14workspace boundaries, fresh build, both retained native delivery campaigns, refusal checks and workflow lint. Evidence:`target/host-native-schema-20261014/ACCEPTANCE.json`. Local replay is distinct from current native ARM64 execution. Develop pushes supersede obsolete same-ref CI; tag/release workflows are unchanged. Matching current native projection/full composed CI and independent coverage remain open; HOST-AUTH pending, inventory33accepted/19unfinished.

## Selected host/runtime and authentication acceptance — 2026-10-14

HOST-AUTH passes selected local/native simulation acceptance — 2026-10-14. Primary-digest-verified run38630135235 at42df283 provides both actual native AMD64/ARM64 kernel execution/file-open/connect capture, explicit drop/lookup counters and exact nine-record complete agent/spool/SIGKILL/server/query replay per architecture. Source/raw hashes, boot/process-start/PID/parent bindings, unique retained IDs and capture cleanup are verified. Authentication source remains qualified by its strict local profile. Evidence:`target/host-native-schema-20261014/HOST-AUTH-ACCEPTANCE.json`; [contract63](63-falco-runtime-profile.md). Production independent coverage, full-host visibility, credential-read proof, actual customer setup and prolonged/physical-device behavior are not assessed. Inventory34accepted/18unfinished; next authorized dependency-ready item:WINDOW event-time detector. Full current native container/Kubernetes/supply-chain qualification and external release gates remain separate.


WINDOW shared history restore custody advances — 2026-10-15. Both optional archive
tables now participate in stopped-restore locks, source checkpoints and transition
fingerprints. Actual PostgreSQL/Parquet tests refuse omitted/deleted or
self-consistently rewritten archive data and changed custody times; a valid fresh
generation preserves original bytes/checkpoint/custody/expiry. Complete local
server/native-HTTP campaign passes50checks in173.68s with owned cleanup:
`target/window-20261014/shared-history-restore-postgres-prebuilt/report.json`.
The archive record is owner-seeded for restore qualification; detector derivation
is tested separately. WINDOW remains pending and inventory stays34accepted/
18unfinished. Shared history reads/replay guards, remaining pin lifecycle,
Standard integration and full acceptance remain open; see[contract64](64-authentication-window.md).


WINDOW bounded shared history reads advance — 2026-10-15. Explicit owner-installed
lease/head/state-bound reads now use the existing bounded control worker. Cursors
bind the archive inventory, and exports enforce original cancellation plus
monotonic lease/retention expiry. Actual PostgreSQL/server/native-HTTP51-check
campaign passes207.32s with owned cleanup:
`target/window-20261014/shared-history-reader-corrected-postgres/report.json`.
78control tests, focused strict Clippy and37runner tests pass. This adds no public
HTTP authority. WINDOW and the release goal remain incomplete; inventory stays
34accepted/18unfinished. Next: Indeterminate history qualification and complete
history/object use accounting before general obsolete-pin release and Standard
consumer integration. See[contract64](64-authentication-window.md).


WINDOW Indeterminate history and obsolete replay-pin accounting advance —
2026-10-15. Real detector-to-shared-archive/read Indeterminate outcomes pass.
A bounded fenced release routine accounts for all supported Window states and
retained history, holding complete commit object sets conservatively. The actual
fixture verifies history-only refusal, release after a sixth committed retention/
TTL transition, current protection, stale inputs and exact replay. Complete local
52-check PostgreSQL/server/native-HTTP campaign passes203.94s with owned cleanup:
`target/window-20261014/obsolete-pin-postgres/report.json`.79control tests, focused
strict Clippy and37serial runner tests pass. Automatic ledger-aware Standard
cleanup and consumer/configuration integration remain open. Inventory stays
34accepted/18unfinished; full WINDOW and release acceptance remain pending.


WINDOW Standard foundation advances — 2026-10-15. Strict shared configuration
schema2 preserves Small schema1 and adds no unused SQLite path. A lease-fenced
profile read checks explicit bootstrap, quotas and runtime grants. Nested claims
schema3 supports anchors sealed after an earlier batch's commit using exact prior
state; schema2 remains strict. Actual delayed-anchor publication/SIGKILL recovery,
bootstrap and grant cases pass in the complete53-check local campaign201.29s:
`target/window-20261014/standard-window-foundation-postgres/report.json`.
80control tests, two configuration tests, default/`s3-query` strict Clippy and
37runner tests pass. Standard startup/consumer wiring remains next; shared-WINDOW
runtime refusal stays enabled. Inventory stays34accepted/18unfinished.


WINDOW Standard startup/consumer wiring advances, still gated — 2026-10-15.
The single-consumer state holder now performs explicit bootstrap/recovery,
coverage/tail-bound candidate evaluation, multi-event commit/ACK reconciliation,
confirmed-idle known-pin cleanup and bounded health/history metrics. Same-timestamp
finding deduplication is covered.80control, two configuration and two consumer
boundary tests pass, with strict default/`s3-query` Clippy. Refreshed underlying
53-check shared campaign passes180.56s with owned cleanup:
`target/window-20261014/standard-window-consumer-postgres/report.json`.
This does not exercise enabled Standard Main Window. The runtime refusal remains;
actual Main startup/restart/batch/retry qualification is next. In particular,
repeated canonical IDs needed original-sequence/content-aware handling before
at-least-once retry acceptance; the following primitive slice addresses that
foundation. Inventory34accepted/18unfinished.

WINDOW retry foundation advances, still gated — 2026-10-15. Sequence-aware
Parquet recovery selects protected original ID/sequence pairs, tolerates identical
copies and refuses changed content; legacy ID-only recovery stays strict.
Claims3 preserve original retained sequences. Explicit owner-installed016 adds a
bounded lease/head-bound immutable finding comparison; the consumer filters known
repeats without changing stored bytes or promoting legacy unknown scope. Actual
Main batching/retry/restart qualification is still required.81control tests,
strict control/server `s3-query` Clippy, formatting and37runner tests pass.
The unchanged prebuilt53-check campaign passes204.83s with183 matching source
hashes and owned cleanup:
`target/window-20261014/window-retry-postgres-prebuilt/report.json`.
The first campaign's native-wrapper compilation timeout is retained separately;
no deadline was increased. Objects/host admission remain simulated; enabled
Standard Main WINDOW is untested. Inventory stays34accepted/18unfinished.

WINDOW actual Standard Main advances — 2026-10-15. Six composed scenarios pass
137.91s: explicit/bootstrap and enrolled-quota refusals, same-time split batches,
signed-watermark protected anchors, exact retries, confirmed-state SIGKILL/restart
and blocked prepared-publication SIGKILL with byte-exact original SQL request,
claims, manifest and findings recovery. The producer uses an explicit current-lease
fence and narrow state-bound replay-pin helper017; general object control, table
and schema mutation remain forbidden. Mixed stateless/Window readiness inventory
and nullable optional-module privilege checks are corrected. The refreshed53-check
shared campaign passes177.87s;81control tests,38runner guards, focused readiness
regression, strict control/server `s3-query` Clippy and formatting pass. Both process
campaigns have current source/binary bindings and owned cleanup:
`target/window-20261014/window-main-process-v7/report.json`,
`target/window-20261014/window-main-shared-final/report.json`.
Actual PostgreSQL/Parquet/WAL; object/host authority simulated. WINDOW is now
explicitly in_progress in the ledger; acceptance remains incomplete. Next: whole
Small Main crash qualification, broader timestamp compatibility, remaining edge
cases and full review/acceptance. Inventory34accepted/18unfinished.

WINDOW Small Main crash qualification advances — 2026-10-15. Five composed checks
verify split-batch sealing, actual SIGKILL after atomic outbox commit and before
finding publication/WAL ACK, exact pending SQLite bytes, one original scoped
finding after recovery, another confirmed-state SIGKILL, and real SQLite writer
contention before commit. An uncommitted retained event remains unverified after
restart. The inherited native identity/onboarding campaign and four ownership
failure regressions pass;15owned children are reaped, including four observed
SIGKILL exits across the full composition. Evidence:
`target/window-20261014/SMALL-MAIN-ACCEPTANCE.json`. Local Small Main with actual
SQLite/findings/WAL and TLS provider; host/source authority is synthetic. WINDOW
remains in_progress. Next: canonical timestamp compatibility, remaining edge cases,
focused review and full frozen acceptance. Inventory34accepted/18unfinished.

WINDOW canonical timestamp compatibility — 2026-10-15. SQL012 now preserves
Chrono's exact second/nanosecond pair for BCE/expanded years and leap seconds,
without PostgreSQL microsecond timestamp casts. Actual PostgreSQL compares46
canonical clocks against Chrono, rejects11invalid inputs and exercises7installed
trigger progressions with one-nanosecond regression refusal; existing retired
assessment resurrection guards still pass. The refreshed53-check shared campaign
passes183.25s with245matching source hashes, owned cleanup and no errors.
81control tests, strict control/server all-targets `s3-query` Clippy, formatting
and14workspace boundaries pass. Evidence:
`target/window-20261014/CLOCK-ACCEPTANCE.json`. Parser/trigger edge fixtures use
owner-side rollback and do not qualify detector derivation or host authority for
those synthetic dates. Actual local PostgreSQL/WAL/Parquet, simulated objects/host.
WINDOW remains in progress; remaining consumer edges, review and full frozen
acceptance are next. Inventory34accepted/18unfinished.

WINDOW consumer edges — 2026-10-15. Six focused tests verify first-sequence
retention, exact original bytes, unknown-scope preservation and changed
body/generation/canonical-scope refusal. Actual Standard Main now passes8scenarios
in169.97s under the unchanged180s deadline, including missing required replay-pin
permission and policy-revision startup refusals. The owner oracle compares
committed states/findings/commits/requests/checkpoint before and after refusal;
original crash/retry scenarios remain passing. All266source hashes match, owned
container cleanup passes without errors. Strict control/server all-targets
all-feature Clippy,6all-feature regressions,38runner guards, formatting and
14workspace boundaries pass. Consumer-only writer review and both harness
corrections are retained in `target/window-20261014/CONSUMER-ACCEPTANCE.json`.
Actual local PostgreSQL/TLS/WAL/Parquet; object/host authority simulated. Next:
whole-WINDOW focused review, freeze and full acceptance; no further implementation
is planned unless review exposes a defect. Inventory34accepted/18unfinished.

WINDOW review corrections — 2026-10-15. Whole-scope writer review found two
real boundary mismatches: a successful-login anchor can legitimately produce a
NoMatch with zero failed attempts, but archive insertion and replay-pin history
validation both rejected empty failure references. SQL012/014 now accept bounded
empty NoMatch/Indeterminate evidence with empty canonical maps; empty Match stays
invalid. The actual fixture now starts with a successful login and verifies its
zero-failure archive. Fresh53-check PostgreSQL/WAL/Parquet/crash/history/pin
qualification passes206.78s with246matching source hashes and clean owned cleanup.
51rules tests, strict rules/control/server all-targets `s3-query` Clippy, formatting
and14workspace boundaries pass. Evidence and pre-fix reproductions:
`target/window-20261014/REVIEW-CORRECTIONS.json`. Whole-WINDOW review is still in
progress; final frozen gates and acceptance remain open. The older eight-case
Standard Main report predates these corrections and needs refresh at final
acceptance. Inventory34accepted/18unfinished.

WINDOW reader review correction — 2026-10-15. The owner fixture reproduced
read-only enrollment inspection accepting UPDATE on optional WINDOW history. The
guard now inspects protected core/addon namespaces across reachable roles and
refuses schema/routine/table/column/sequence mutation authority, including PUBLIC
and SET-capable role memberships. Seven temporary-grant refusals pass; original
SELECT-only credentials work after each exact revoke. The complete8-scenario
Main campaign passes175.08s under the unchanged180s deadline, with266matching
source hashes and clean owned cleanup. Strict control/server all-targets
all-feature Clippy and38runner guards pass. Evidence:
`target/window-20261014/READER-ACCEPTANCE.json`. This closes the reproduced reader
review finding locally; whole-WINDOW final frozen acceptance remains pending.
Inventory34accepted/18unfinished.

WINDOW passes local simulation acceptance — 2026-10-15. Bounded authentication event-time/watermark/lateness, canonical replay identity, key/event/byte/TTL/output/history limits, unknown coverage and atomic state/findings/checkpoint recovery are qualified. Six frozen workspace gates pass1048default/1117all-feature tests, both strict Clippy modes, formatting and14workspace boundaries. Actual Small Main passes5WINDOW/8onboarding checks; Standard Main passes8scenarios; shared recovery passes53checks in206.73s. Runtime source bindings109/266/246 match; retained Small/Standard executable identities match and owned cleanup succeeds. Writer review closed three reproduced findings; it is not independent release review. Evidence:`target/window-20261014/ACCEPTANCE.json`; [contract64](64-authentication-window.md). LinuxAMD64 with actual SQLite/PostgreSQL/Parquet/WAL and SIGKILL; signed host/object authority is synthetic. Inventory35accepted/17unfinished. Current remote/native/container/Kubernetes, AWS/EKS, released dependencies, version and publication remain separate. Next local dependency-ready detector:SENSOR-HEALTH; Phase9 AWS collection requires a separate task.

WINDOW native CI wiring — 2026-10-15. Both existing AMD64/ARM64 Rust jobs now run
the actual Small `--window` recovery fixture and Standard `--standard-scenario window`
process fixture after exact all-feature builds. Existing fixture deadlines, pinned
PostgreSQL image and artifact retention apply; the copied Standard executable is
excluded from upload. Workflow lint and16CI-helper checks pass. Remote results
remain unqualified; no publication is enabled.

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

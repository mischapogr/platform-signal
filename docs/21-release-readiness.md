# Release readiness audit — 2026-10-07

The current checkout has local Linux AMD64 mechanism proof through Phase 8 and
Phase 10 hardening. It is
`0.1.0-dev.0`, with no published release, image or crate. **`v0.1.0` is not ready.**
The [definition of done](06-definition-of-done.md) marks observed local checks;
its checked boxes do not substitute for the remaining release gates below.
Phase 9 AWS collection remains post-MVP.

Release scope remains explicit. The next development snapshot needs a settled
reviewed change set and fresh matching CI/container/Kubernetes/package/SBOM
evidence. A first core-MVP preview may defer advanced SOC UX and other post-MVP
capabilities; it still requires the applicable release review, trust, restore,
native/remote and released-dependency gates plus an owner-selected version and
publication authority. A preview claiming all planned product architecture must
also finish the frozen post-MVP ledger. The existing dev0 candidate is older and
unpublished; no next release version or date has been selected. Actual AWS/EKS
and live-vendor checks must remain separately visible, never closed by simulation.







## Native CI status — 2026-10-09

Settledfe5acf377 run37895779773 passes both complete native Rust jobs, production
images and basic container/persistence checks; both native pipeline/finite-soak
steps fail, and kind/supply-chain/candidate stages are skipped. Settled1a8ab8cb
run37899784130 passes the complete ARM64 Rust job; AMD64 Rust Tests fails.
Annotations expose exit1 without a Rust target/cause; container/kind are skipped.
Anonymous detailed logs remain inaccessible. The local full seven-profile debug
pipeline passes140 queries with2417 confirmed admissions and2421 durable records
within the original admission uncertainty bound; it does not reproduce or explain
either remote failure and is not remote-image/native ARM64 qualification.

Develop7761c586 CI run37903398196 is in_progress as observed08:23UTC, with tooling
passed and both native Rust jobs running. Fixed public failure-stage diagnostics
are included in this pushed revision. Complete reviewed-revision EXT-CI/EXT-ARM64
remain external_pending. No release version/date or publication is selected.
Evidence: `target/goal-execution-20261007/EXT-CI/query-hooks-remote-jobs-2.json`,
`findings-hooks-remote-jobs-2.json`, `findings-hooks-amd64-annotations.json`,
`local-full-pipeline-diagnostic/report.json` and `native-stage-remote-jobs-1.json`.

## EXT-CI native failure diagnostics — 2026-10-09

The native qualification harness now records a fixed public stage and emits a
bounded final summary after report persistence/owned cleanup. The CI wrapper
promotes only a failed final exact-schema summary with a known stage into an
annotation after disabling workflow parsing around raw output. No path, payload
or free-form exception enters that annotation. The first operation failure is
preserved if cleanup also fails; missing summaries infer nothing.

10 CI/19 native/5 candidate helper tests, syntax/workspace13 and review pass.
A reproduced late interruption initially returned zero with passed metadata;
the exception path now unconditionally fails qualification. Red/green logs and
the prior review/campaign remain retained. Qualification validators, required
profiles/soaks and cleanup are unchanged. Rust behavior/build inputs are unchanged.

Evidence: `target/goal-execution-20261007/EXT-CI/native-stage-acceptance.json`,
`native-stage-validation-corrected/validation.json` and `native-stage-review.json`.
This is locally accepted tooling, not the cause of earlier remote failures or a
closed native/container/Kubernetes/supply-chain/release gate. Continue existing
SECURITY-AUDIT hooks and source-bound remote CI evidence without scope expansion.

## Native ingest control audit — 2026-10-09

The optional generic ingest seam now confirms a new decision before reading the
body or admitting WAL records, then matching completion before any prefix/ID
receipt disclosure. The monolith selects `ingest_events` alongside five existing
access operations and shares one bounded Control/outbox. Authentication runs once;
a live actor is captured while whole-batch canonical scope preflight remains before
first admission. Granted decision means request-processing capability, not approval
of an unexamined event. Original request clock/cancellation and live-grant checks
remain effective through the final reply. Every handled response is no-store.

Lost completion or late disclosure authority withholds all prefix/IDs through a
verifier-valid503 unknown-total retry response. Actual partial/full WAL effects and
admission counters remain truthful; retry may duplicate immutable IDs. Uncertainty
cannot become a permanent403 or an invalid full-prefix503. Dropped completions
count incomplete/failed requests without inventing rollback or detached completion.

Ten additional regressions, strict 778/829 tests, both Clippy/fmt/workspace13,
source review and 50 actual AMD64/mTLS process checks pass. The
native campaign retains 28 fsynced receipts and 6 clean ordinary logs, confirming
full/partial WAL effects, lost decision/completion, exact restart replay/fresh IDs
and shared selected-route/readiness failure. Actual queued-success late handoff and
native HTTPS grant expiry have separate source fixtures. Failed fixture campaigns
remain retained; no source/binary drift or cleanup errors. Native IdP plus actual
monolith auditing, production receiver/independent health/encryption and runtime/
rule activation remain unfinished. Parent SECURITY-AUDIT stays in_progress.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/ingest-hooks-acceptance.json`,
`ingest-hooks-validation/validation.json`, `ingest-hooks-review.json` and
`ingest-hooks-native-independent/report.json`. The frozen52 inventory/status counts
are unchanged; this is a bounded substep, not whole-item or release qualification.

## Native coverage access audit — 2026-10-09

The optional selected-operation profile now accepts `read_coverage` and
`write_coverage` alongside query/findings/feed, with one shared bounded session and
outbox. Coverage authorizes once and confirms a durable decision before journal
access, then matching completion before disclosing originals/history/aggregate or
receipts. Existing paired scope/writer authority, original request clocks and final
grant checks remain. A new coverage commit returns201; exact replay returns200.
Completion uncertainty can withhold a receipt for an already committed record;
an exact retry recovers it. A late authority denial preserves that503 uncertainty.
Every response is no-store; control records contain no coverage body/binding/IDs.

Five additional regressions, strict768/819 workspace tests, both Clippy,
fmt/workspace13, source review and 93 actual AMD64/mTLS process
checks pass. 54 fsynced receipts and 9 ordinary logs retain privacy proof.
The process campaign covers original bytes/receipts, separate write decision and
completion loss, read withholding, shared selected-route/readiness failure, exact
stopped replay/fresh operation identity and bounded fixed-frontier pagination.
Failed fixture campaigns and the uncertain-write red regression remain retained.
No source/binary drift or cleanup failure. This is finite bootstrap/synthetic proof;
IdP composition, production receiver/health/encryption and other hooks remain open.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/coverage-hooks-acceptance.json`,
`coverage-hooks-validation/validation.json`, `coverage-hooks-review.json` and
`coverage-hooks-native-independent/report.json`. Parent SECURITY-AUDIT stays
in_progress; the frozen52 item inventory and status counts do not change.

## Native findings access audit — 2026-10-09

Explicit selected-read auditing now supports only `query_events`, `read_findings`
and `read_findings_feed`, as a nonempty unique subset. They share one bounded
session/outbox. Findings list/feed confirm a durable decision before journal work
and matching completion before disclosure, preserving one authentication, scoped
list filtering, global-only feed authority and original deadlines/grant leases.
Unselected operations remain explicitly unselected. All responses are no-store.

Five additional regressions, strict763 default/814 all-feature tests (zero failures),
both Clippy/fmt/workspace13 and focused source reviews pass. The actual AMD64
monolith/independent mTLS peer passes59 checks with35 fsynced receipts and11 clean
ordinary logs: real rule-generated findings, denials/invalid input, lost decision
and completion ACKs for each endpoint, shared failure/readiness, exact restart
replay/new IDs, wrong ACK and explicit selection. No source/binary drift or cleanup
errors. Sandbox and failed campaigns remain retained. Two existing test fixtures
now synchronize startup/worker release; agent/worker production behavior is unchanged.
The idle failure cause is unestablished; the worker early-reply race was reproduced.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/findings-hooks-acceptance.json`,
`findings-hooks-validation-settled/validation.json`, the three focused review reports
and `findings-hooks-native-independent/report.json`. This is finite synthetic
bootstrap/local proof. Native IdP/audit composition, other hooks, production
receiver/independent health and secrets/encryption remain open; parent in_progress.

## SECURITY-AUDIT native query hook — 2026-10-09

Optional explicit query-only auditing now confirms a durable access decision
before execution and exact matching completion before response disclosure, using
one original deadline and existing authentication once. Dedicated mTLS/audit
credential configuration has no API-token fallback. Incomplete/uncertain sessions
hold selected readiness and expose finite unlabeled capacity/health metrics.

Six focused regressions, strict758/809 workspace tests (zero failures), both Clippy,
fmt/workspace13 and source review pass. The separate actual AMD64 monolith/mTLS
peer passes27 checks with14 fsynced receipts: query/denial, lost ACKs/no disclosure,
readiness, stopped exact replay/new operation IDs, bad ACK, independent peer
survival and startup negatives. Nine ordinary logs omit token/query canaries.
No production source/binary drift or cleanup errors. No-store failure was reproduced
and fixed; helper lint/sandbox/three fixture preparation failures remain retained.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/query-hooks-acceptance.json`,
`query-hooks-validation-corrected/validation.json`, `query-hooks-review.json` and
`query-hooks-native-independent/report.json`. Bootstrap/synthetic finite proof
qualifies this query slice; enabled IdP auditing, other access/config/rule hooks,
production receiver/health and secrets/encryption remain open. Parent stays
in_progress; continue next native access hooks. See [audit](45-independent-audit.md).

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

## SECURITY-AUDIT durable control outbox — 2026-10-09

The bounded Linux outbox now retains one immutable pending record, persistent
producer identity and an exact-ACK checkpoint. Pending publication is synced before
possible delivery; checkpoint publication is synced before reclamation. Lost replies
replay the original bytes/identity. Private fixed inventory, complete recovery
preflight, live temporary-control guards and one physically retained disk worker
preserve fail-closed ownership through crashes/cancellation/original deadlines.
No ordinary storage fallback, new dependency or service is introduced.

Nine meaningful regressions, including eleven actual subprocess crash boundaries,
strict752 default/803 all-feature workspace tests (zero failures), both Clippy,
fmt/workspace13 and focused review pass. Three review regressions failed before
correction and pass afterward. Interrupted/failed campaigns stay retained. The
inherited configuration fixture now synchronizes worker start/release/completion;
production is unchanged and the old isolated pass establishes no failure cause.
A mistaken exact filter ran zero tests and supplies no acceptance evidence.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/outbox-acceptance.json`,
`outbox-validation-final/validation.json`, `outbox-review.json`. Parent remains
in_progress: native operative hooks, independent durable receiver/outage health
and secrets/encrypted-storage seams follow. This is ordinary crash recovery, not
independently current restored-history, encryption or production qualification.

## EXT-CI failure diagnostics — 2026-10-09

Accepted develop revision880b31e ran public CI37886589245: both native AMD64 and
ARM64 failed the Tests step; tooling passed and downstream container/Kubernetes
jobs were skipped. Earlier3340234 also failed both test jobs. Anonymous metadata
does not expose the failing test; no remote failure cause is inferred.

The finite CI wrapper now records at most16 Cargo package/target failures verified
against bounded public manifests. Free-form test names/panic data cannot become
classification metadata. Raw output is retained with GitHub workflow commands
disabled using a fresh unpredictable stop/resume token, then validated annotations
are emitted. Six actual subprocess/inventory/command-injection regressions, five
candidate-report regressions, two retained real-failure classifications, Python
syntax/workspace13 and focused review qualify this tooling slice. Failed fixture
lifetime and mistaken helper-path attempts remain retained; both were corrected.
Rust is unchanged; existing strict743/794 acceptance remains source-applicable.

Evidence: `target/goal-execution-20261007/EXT-CI/failure-diagnostics-acceptance.json`,
`failure-diagnostic-validation-accepted/`, `failure-diagnostic-real-log-check-accepted.json`
and `failure-diagnostics-review.json`. EXT-CI/EXT-ARM64 remain external_pending;
SECURITY-AUDIT remains in_progress. Diagnostic revision57c1d1e is pushed.
Public CI37887706801 passes both native Rust Tests steps; ARM64 also passes the
IdP/browser and object/query simulations. The full run fails later: ARM64 fails
the legacy local-candidate helper and AMD64 fails the IdP/browser gate. Container/
Kubernetes jobs are skipped. Anonymous logs remain unavailable; exact remote
causes are not inferred. A local simulated-ARM fixture reproduction identifies
two missing host mocks in the legacy AMD64 helper tests; focused correction
follows. Partial native success does not close either full gate.

## SECURITY-AUDIT destination client slice — 2026-10-09

The runtime-independent AuditSink seam now has a restricted HTTP implementation.
Production construction requires explicit private mTLS identity/roots and an audit
credential; a separately named numeric-loopback HTTP constructor serves local
simulation only. One retained physical worker owns request/runtime teardown through
cancellation; lazy admission avoids body/credential clones for rejected callers.
Shared DNS retains its own physical ownership. Automatic protocol retry, proxy,
redirects and decompression are disabled; no ordinary API credential fallback.
Original immutable bytes and complete bounded exact ACKs determine confirmation;
missing/late replies remain uncertain and cancellation/rejection are counted.

Four new regressions cover finite configuration, original clock handoff, preclone
admission and actual HTTP/mTLS behavior (20 compound cases). Strict 743/794 default/
all-feature workspace checks, both Clippy, fmt/workspace 13 and focused review pass.
The failed inherited coverage fixture returned OutcomeUnknown; isolated diagnosis
passed but establishes no cause. Its startup watchdog now uses the store default
10 seconds instead of a test-specific one second; HTTP deadline stays one second.
No production coverage behavior changed. The subsequent audit peer BrokenPipe
failure is also retained: replies now require a complete bounded write before
readiness signals; only final half-close permits a peer disconnect. Valid/partial/
denial assertions remain unchanged; production audit transport was unchanged.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/destination-acceptance.json`,
`destination-validation-qualified/validation.json`, `destination-review.json`. This
accepts a client/trait. Durable receiver fsync, native hooks, independent health
and encrypted storage remain unqualified. SECURITY-AUDIT remains in_progress;
continue a durable bounded control outbox, native hooks and independent receiver.

Develop pushes of accepted commits are now owner-authorized. Protocol revision
3340234 is pushed. Snapshot `protocol-remote-jobs-1.json` records public CI
run37885218153 reaching native ARM64 formatting/lint/build and an AMD64 test
failure with generic metadata. Anonymous log access returned403; gh is not logged
in. No failure cause or remote/native runtime qualification follows. Main, tags
and release publication retain their existing authority boundaries.


## SECURITY-AUDIT protocol slice — 2026-10-09

Version 1 audit control records now distinguish access decisions, operation
completion/uncertainty and runtime/rule activation. 4 KiB records and 1 KiB ACKs have
strict object/field/version/time/UUID/sequence/hash validation, finite retained
metadata and secret-free typed diagnostics. Exact original bytes survive intake;
ACKs bind record/producer/sequence/body hash. Live verified grants produce framed,
domain-separated pseudonymous actor references without granting audit permission.

Six meaningful audit regressions, all existing protocol regressions, strict 739/790
default/all-feature workspace tests, both Clippy/fmt/workspace13 and independent
review pass. Tagged-unit extra-field acceptance and review array/spare-capacity
bugs were reproduced before fixing; failed evidence is retained. The inherited
healthy-probe test 100 ms budget failed under concurrent all-feature load. Production
correctly timed out; the test now uses production 2 s and proves a partial body was
sent/held open until expiry. No production probe behavior changed. No new dependency
or process is added. Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/protocol-acceptance.json`,
`protocol-validation-reviewed/validation.json`, `protocol-review.json` and red/green logs.

SECURITY-AUDIT stays in_progress. Next: bounded independent destination and native
access/config/rule activation hooks, then secret/encrypted-storage integration
checks. Protocol acceptance does not qualify operative auditing, independent
health, encryption, current image/cluster, native ARM/fullCI/cloud/release.


## SECURITY-TRANSPORT complete locally — 2026-10-09

The frozen local transport scope is passed_simulated. Quiet health/readiness modes
in the existing agent use the shared native HTTP/mTLS client, exact loopback IP
verification, one original two-second deadline and a complete bounded1KiB body.
No source/spool/token access or insecure/plaintext fallback is introduced. The
Docker adapter replaces itself without a shell/child; Helm uses exec probes and
separate existing-Secret probe identity, with three-second supervision. TLS metrics
require explicit CA/client/key/server-name references, never insecure scraping.

Actual monolith/agent19 compound checks, three current-binary nonroot container
adapter cases, seven positive/negative chart contracts, four harness regressions,
strict733/784 default/all-feature workspace tests, both Clippy/fmt/workspace13 and
independent review pass. The container substrate is the older14c56dc image with
current binaries mounted; this is not a current complete production image. The
first native trial failed an unrecorded query HTTP status; failure is retained,
the harness now records status, and subsequent strict/final gates pass. No cause
or prolonged stability claim is inferred. Test-only Clippy unwraps and two container
harness review findings were corrected; failed evidence stays visible.

Evidence: `target/goal-execution-20261007/SECURITY-TRANSPORT/probe-acceptance.json`,
`probe-validation-reviewed/validation.json`, `probe-process-final/qualification.json`,
`probe-container-qualified/qualification.json`, `probe-chart-qualified/validation.json`
and `probe-review.json`. Native ARM64/full remote CI, real PKI/cloud/live tenants,
current full-image/kind/release/publication remain separate. Continue SECURITY-AUDIT
restricted independent audit and secrets/encryption seams; no routine stop.


## SECURITY-TRANSPORT shared collector TLS — 2026-10-09

The collector SDK now owns the single native client TLS builder and retained
physical configuration/DNS workers. The agent keeps its public TLS API through
reexports and uses the same HTTP client policy; no duplicated client crypto or
worker implementation remains. Optional `HttpReceiptPublisher::with_tls` requires
HTTPS and preserves exact prepared batches. Original ExtensionContext deadlines
are checked before network polls and ready reply handoff. Proxy, redirect,
decompression and detached DNS behavior remain disabled; bounded endpoint/token
intake precedes client allocation.

Actual local TLS peers prove wrong server roots, foreign/missing client identity
produce zero HTTP requests and leave the exact receipt IDs/prefix unchanged after
reopening; valid mTLS commits the verified prefix. This tiny admission peer is a
simulation, not durable WAL proof. The actual monolith/agent gate independently
passes all16 compound checks using the shared client implementation. Strict730
+781 default/all-feature workspace tests, both strict Clippy, fmt/workspace13 and
independent review pass. Earlier native deadline red/green evidence remains
historical source-bound proof; the moved physical worker's regressions pass here.

SECURITY-TRANSPORT stays in_progress. Next: protected packaging/deployment
readiness/liveness probes. No real PKI/native/fullCI/cloud/live vendor/current-image/
release gate closes. Evidence: `target/goal-execution-20261007/SECURITY-TRANSPORT/shared-acceptance.json`,
`shared-validation-final/validation.json`, `shared-process-final/qualification.json`
and `shared-review.json`.


## SECURITY-TRANSPORT native mTLS slice — 2026-10-09

Optional bounded native mTLS now protects the monolith API and metrics listeners
and the outbound agent. Explicit private version1 DER roots/identity/CRLs use
stock Rustls/ring chain, hostname, time and signed revocation checks. There is no
plaintext/anonymous fallback when selected, session resumption or early data.
Transport certificates do not grant API capabilities or prove source completeness.
Startup validates private material before agent source/spool or server readiness.

The existing connection budget owns TLS and HTTP through teardown; original
absolute deadlines reject late polls and ready handoffs. Fixed retained physical
configuration/DNS workers keep capacity after caller timeout/cancellation. Actual
local agent/server qualification passes16 compound checks: valid named-endpoint
admission/WAL/Parquet/query, both-listener missing/foreign/expired peer denial,
independent API credentials, wrong server trust/hostname/time, signed CRL denial,
original spool IDs across retry and stopped root/certificate/token rotation,
trickling original-deadline expiry and shutdown of demonstrably active handshakes.
Four harness regressions, independent review, strict727default/778all-feature
workspace tests (zero failures), both strict Clippy, fmt and workspace13 pass.
Five regressions fail when deadline safeguards are disabled and pass after exact
source restoration. Failed preflight/early expectations remain failed evidence.

SECURITY-TRANSPORT stays in_progress: protected packaging/deployment health probes
and the collector publishing TLS seam remain required. No current production
image, native ARM64/full reviewed-revision remote CI, real PKI/cloud/vendor or
release claim follows. Evidence: `target/goal-execution-20261007/SECURITY-TRANSPORT/native-acceptance.json`,
`process-final/qualification.json`, `validation-final/validation.json`,
`red-green/report.json` and `review.json`. See [native transport contract](44-transport-security.md).


## SECURITY-ACCESS established IdP acceptance — 2026-10-09

SECURITY-ACCESS is passed_simulated for its frozen local scope. Actual pinned
Keycloak26.8.0, locked openid-client and Chromium156 sign in through authenticated
HTTPS authorization-code/PKCE/state/nonce. Fresh native introspection admits and
queries only complete scoped event/finding pairs. Eleven compound checks include
wrong audience/ID token/unbound identity/header denial, code replay, real session
revocation, observed pre-expiry admission then expiry denial, malformed callback,
actual provider pause/recovery and the existing SecOps console with no persisted
browser token. Eight meaningful harness failure regressions and source review pass.

Coverage's earlier actual TLS gate supplies authorized original coverage bytes,
actor binding, cursor isolation, revocation and unchanged receipts/replay. Evidence/
admin/rules/audit HTTP routes remain404 even with explicit corresponding grants;
this qualifies fail-closed absence, not operative services. Sign-in is an established
external IdP/client flow; the console uses its existing Access token field.

No Rust/runtime dependency or behavior changed. Strict718default/769all-feature
source-bound acceptance, both Clippy/fmt/build/workspace13 remain applicable.
Workflow syntax/workspace checks and the dated optional npm audit pass (zero
reported vulnerabilities). Both native GitHub Rust jobs now run this optional local
IdP gate; reviewed-revision remote execution remains unverified. Early failed
provider/audience/session/cleanup runs remain failed. An accidental shared browser
cache cleanup was corrected by restoring both affected revision1208 entries from
matching official archives; final acceptance uses the explicit project cache.

Evidence: `target/goal-execution-20261007/SECURITY-ACCESS/idp-acceptance.json`,
`idp-browser-final/qualification.json`, `idp-helper-final/`, `idp-review.json` and
`idp-preparation/cache-correction.json`. See [local IdP qualification](43-local-idp-qualification.md).
Next: SECURITY-TRANSPORT. Live IdP/rotation, native ARM64/full remote CI, real
AWS/EKS/vendors, current production image and release remain separate gates.

## SECURITY-ACCESS coverage identity boundary — 2026-10-09

Native coverage uses exact private binding selection, complete ReadCoverage or
WriteCoverage permission pairs, and the configured verified issuer/subject for
writes. There is no legacy-token fallback. Reads have separate authority; global
coverage metrics additionally require explicit all-scope ReadCoverage. Original
binding/profile pins, receipts, bytes, replay, cursors and unknown-health semantics
remain unchanged across restart. The selector header grants no identity.

A request-local UTC/monotonic lease follows authorization into queue admission,
physical reads/SQLite progress, the mutation/commit boundary and final response.
Expired reads retain physical capacity until retirement without poisoning storage;
started uncertain writes hold the owner and require reconciled reopening. Original
operation watchdogs remain separate. A late denied successful POST response is
reported as outcome_unknown; it must not imply definitely absent evidence.

Eight added Rust regressions, strict718default/769all-feature workspace tests,
formatting, both strict Clippy configurations, build/workspace13 and independent
review pass. Actual TLS/monolith checks include actor/read-write/cross-scope/cursor
denial, duplicate selectors, revocation, original receipt replay and SIGKILL/restart.
The corrected ready-reply and actual SQLite interruption regressions fail when
safeguards are temporarily disabled; source is restored exactly. Early socket,
fixture expectation and authentication-cache failures remain retained.
Evidence: `target/goal-execution-20261007/SECURITY-ACCESS/coverage-acceptance.json`,
`coverage-validation-final/validation.json`, `coverage-review.json` and
`coverage-red-green/report.json`.

SECURITY-ACCESS stays in_progress. Next: established local IdP/OIDC sign-in and
remaining capability contracts. No source completeness, historical authentication
upgrade, native ARM64/full remote CI, real cloud/live tenant, current-image or
release qualification follows.

## SECURITY-ACCESS finding boundary — 2026-10-09

Trusted canonical finding scopes and paired pre-limit reads pass 13 added Rust
regressions and actual TLS/monolith startup/restart with a real retained WAL backlog.
Historical findings stay unknown; new native admitted rows carry a prefix-bound
scope generation. Existing finding IDs/bytes and the complete feed stay exact on
replay. Invalid controls or post-open frame substitution fail closed.

Strict 710/761, both Clippy configurations, formatting/build/workspace13 and source
review pass. Review resolved unchecked list payloads, caller spare allocations and
visible-control sync recovery. Coverage binding, established OIDC sign-in and
remaining route contracts keep SECURITY-ACCESS in_progress. No legacy event
provenance upgrade, signed custody, current-image, native/cloud/remote-CI or release
claim follows. Evidence: `target/goal-execution-20261007/SECURITY-ACCESS/finding-acceptance.json`.

## SECURITY-ACCESS composed-server boundary — 2026-10-09

Private configuration, native authenticated durable admission and mandatory
persisted event-query scopes pass actual TLS/monolith/WAL/Parquet simulations.
Two integration checks include four bounded fixture failure cases; strict
697/748, both Clippy/build/fmt/workspace13, ten existing helper regressions,
15 persistent retirement scenarios and review pass. Full workspace evidence
reuses unchanged Rust/build files after a Python-only cleanup correction; both
focused integration configurations rerun on final fixture sources. A mistakenly
named optional helper command remains failed in its original report, replaced
by the existing retirement simulation in corrected acceptance.

Restricted historical findings, coverage identity bridging, established OIDC
sign-in and remaining route contracts are still required. Global finding reads
require their explicit all-scope capabilities; unavailable administrative/evidence
routes remain absent. SECURITY-ACCESS stays in_progress. This closes no native,
cloud, current image or release gate. See [access contract](42-access-control-contract.md)
and `target/goal-execution-20261007/SECURITY-ACCESS/server-acceptance.json`.

## SECURITY-ACCESS producer-route boundary — 2026-10-09

Five new producer-route regressions plus ten native tests pass. Strict694/745,
formatting, both Clippy configurations, build/workspace13 and review qualify
identity mode, whole-batch canonical scope preflight, denial without admission,
lease-expired exact prefix Retry, fresh suffix admission, revocation, timeout and
bounded metrics/readiness. Evidence uses actual Axum/TLS and a volatile memory
sink. SECURITY-ACCESS stays in_progress: composed server configuration and durable
WAL identity routes, remaining scope history/route enforcement and local IdP HTTP
acceptance remain unfinished. All cloud/native/remote/image/dependency/release
gates remain. See [access contract](42-access-control-contract.md) and
`target/goal-execution-20261007/SECURITY-ACCESS/admission-acceptance.json`.

## SECURITY-ACCESS query-grant boundary — 2026-10-09

The trusted-host authorized query entry point passes five actual committed
Parquet/DataFusion regressions and strict689default/740all-feature, formatting,
both Clippy configurations, build/workspace13 and independent review. Mandatory
complete scopes precede sort/limit; expiry, missing facts and paused-poll deadline
fail closed. SECURITY-ACCESS remains in_progress: whole-batch admission,
server identity configuration/routes and local IdP-backed HTTP scope/expiry/
revocation acceptance remain unfinished. HTTP routes still use legacy admission.
All actual cloud/native/remote/image/released-dependency/release gates remain.
See [access contract](42-access-control-contract.md) and
`target/goal-execution-20261007/SECURITY-ACCESS/query-acceptance.json`.

## SECURITY-ACCESS native-backend boundary — 2026-10-09

Fixed-provider native HTTPS introspection passes ten local TLS/ownership
regressions, strict default684/all-feature735, formatting, both Clippy
configurations, all-feature build, workspace13 and focused review. Fresh provider
revocation, exact profile/private subject binding, TLS failures and retained
physical worker capacity are qualified within the finite local fixture.
SECURITY-ACCESS stays in_progress: server route enforcement, OIDC sign-in and
local IdP-backed HTTP scope/revocation/expiry acceptance remain unfinished.
The synthetic physical lookup pause is not real DNS availability evidence.
All actual cloud/native/remote/image/released-dependency/release gates stay open.
See [access contract](42-access-control-contract.md), [progress](07-progress.md)
and `target/goal-execution-20261007/SECURITY-ACCESS/native-acceptance.json`.

## SECURITY-ACCESS introspection-profile boundary — 2026-10-09

SECURITY-ACCESS remains in_progress. Six selected response-profile fixtures and
nine paired-grant regressions pass with strict default674/all-feature725,
formatting, both Clippy configurations, all-feature build, workspace13 and focused
review. Object shape, active/issuer/audience/subject/Bearer type/expiry, finite
lease, future nbf/iat denial, duplicates/bounds and ignored role/scope extensions
are qualified as pure parsing. Fixed authenticated provider transport, opaque
credential validation, OIDC sign-in/revocation and actual HTTP scope enforcement
remain unfinished. Existing external/native/cloud/image/release gates stay open.
See [progress](07-progress.md), [access contract](42-access-control-contract.md)
and `target/goal-execution-20261007/SECURITY-ACCESS/introspection-acceptance.json`.

## SECURITY-ACCESS grant-only boundary — 2026-10-09

SECURITY-ACCESS remains in_progress. Nine pure authorization/resource regressions,
strict default668/all-feature719, both Clippy configurations, formatting,
all-feature build, workspace13 and focused independent review qualify explicit
paired grants and bounded host-trusted identity only. No HTTP authentication,
OIDC sign-in/revocation, route isolation or parent acceptance follows. Programmatic
spare capacities and serializer-before-length-validation findings are resolved.
Existing live/cloud/native/remote/image/release gates stay open. See
[progress](07-progress.md), [access contract](42-access-control-contract.md) and
`target/goal-execution-20261007/SECURITY-ACCESS/grant-acceptance.json`.

## RETENTION parent local/simulation acceptance — 2026-10-09

RETENTION is passed_simulated: policy/reachability, stopped-cache maintenance,
synced logical retirement, explicit exact-version query reclamation and bounded
query measurements are complete within the frozen item. Current Rust remains
strict default659/all-feature710;33 source-bound actual-server query samples over
2,048 synthetic events, four failure helpers, source review and workflow checks
pass. Selected UTC hour reduces data objects/GETs16→2; warm derived files remain
stable but every query reauthenticates remote bytes. Denial precedes data reads.
No optional field index or partial-event API is justified by this diagnostic.
This does not qualify AWS/cloud/native/CI/kind/EKS/shared/custody, current images,
production capacity or release. See [progress](07-progress.md),
`target/goal-execution-20261007/RETENTION/query-measurements-final/report.json`,
`measurement-review.json` and `measurements-acceptance.json`. Next: SECURITY-ACCESS.

## Exact query-version reclamation boundary — 2026-10-09

RETENTION stays in_progress. Strict default659/all-feature710, source review,
finite native wire and actual before/after-effect SIGKILL/reopen qualify the
explicit stopped Small versionId/If-Match query reclamation mechanism. Exact
NotFound, denial, replacement, lost replies and duplicate integrity headers
are conservative; originals/orphans/live data/manifests/WAL controls stay protected.
The native wire objects use RAM and do not prove AWS/disk durability. Fifteen
current-binary persistent S3/monolith non-regressions pass with exact findings and
all owned children reaped. Remaining bounded measurements, actual cloud/native/
shared/runtime and fresh image/release gates stay open. See [progress](07-progress.md),
`target/goal-execution-20261007/RETENTION/reclamation-validation-final/validation.json`,
`reclamation-review.json` and `reclamation-server-simulation/report.json`.

## Logical query-retirement boundary — 2026-10-08

RETENTION remains in_progress. Strict default658/all-feature703, source review,
actual SIGKILL at three control milestones and fifteen current-binary persistent
S3/monolith scenarios qualify a Small logical retirement horizon. Exact finding
history, reader ownership, pending-control preservation and the server's rollback
floor pass. The retirement-control server fixture is explicitly synthetic and
uses genuine synced WAL admission witnesses. Both native CI runners are wired;
remote execution, cloud/ARM64/HA/custody and release acceptance stay separate.
Remote query objects and protected originals are physically held; reclamation and
measurements remain unfinished. See [progress](07-progress.md),
`target/goal-execution-20261007/RETENTION/retirement-validation-final/validation.json`,
`retirement-review.json` and `retirement-server-simulation-final/report.json`.

## Stopped derived-cache boundary — 2026-10-08

RETENTION stays in_progress. Strict default651/all-feature696, focused127,
source review, actual cache SIGKILL/reopen and retained physical-reader ownership
qualify stopped derived-cache maintenance. Eleven current-binary persistent
S3/monolith scenarios also pass. Temporary controls, protected originals and
remote query objects are preserved; this closes no query-retirement, cloud/native,
remote CI/HA/custody or full release gate. See [progress](07-progress.md),
`target/goal-execution-20261007/RETENTION/cache-validation/validation.json`,
`cache-review.json` and `cache-server-simulation-final/report.json`.

## Advisory retention boundary — 2026-10-08

RETENTION remains in_progress. Strict default644/all-feature689 and focused
review qualify explicit bounded policies and a conservative exact-reference
report only. No retention report authorizes deletion or proves a supplied WAL
checkpoint current. Query retirement/cache pruning/rebuild and measurements stay
unfinished. Evidence: [progress](07-progress.md),
`target/goal-execution-20261007/RETENTION/policy-validation/validation.json`
and `policy-review.json`. External and full release gates remain open.

## Monolithic S3 query simulation boundary — 2026-10-08

S3-QUERY is passed_simulated with default641/all-feature686 strict gates, focused
source review, six process-bound/cleanup regressions and eleven actual persistent
S3/monolith scenarios. Checkpoint-gated orphan/manifest crash replay preserves
four exact canonical events/findings without duplicate query rows. See [progress](07-progress.md)
and `target/goal-execution-20261007/S3-QUERY/server-simulation-final-reviewed/report.json`.

Updated CI includes the bounded simulation on both architectures, and Docker now
builds optional S3 support explicitly. Local source/helper/workflow evidence does
not qualify a fresh image or remote execution. AWS/IAM/KMS/Object Lock/TLS runtime,
native ARM64/EKS/shared HA/custody and full release gates remain open. Continue
RETENTION; do not publish or select a release version from this acceptance.

## Committed object-query boundary — 2026-10-08

Default638/all-feature681 strict gates and focused review qualify eight object-query
and three cache regressions, including actual Parquet/DataFusion selection and
shutdown/cancellation physical ownership. Storage76/default and85/S3 pass. S3-QUERY
stays in_progress until monolithic wiring and persistent source/server process
simulation pass. No AWS/TLS/custody/HA/native/remote/release gate closes. See
[progress](07-progress.md) and `target/goal-execution-20261007/S3-QUERY/query-materialization-validation-resumed/validation.json`.

## Selected query S3 adapter boundary — 2026-10-08

Optional bounded S3 transport passes nine native-wire tests plus versionless
inventory checks: storage73/default and82/S3, default627/all-feature670 strict
workspace acceptance and focused review. Actual query/materialization/server and
persistent process simulation remain incomplete within S3-QUERY. This grants no
AWS/TLS runtime/custody/HA/native ARM64 or full release qualification. See
[progress](07-progress.md) and `target/goal-execution-20261007/S3-QUERY/s3-adapter-validation-accepted/validation.json`.

## Small query publication boundary — 2026-10-08

Storage72/default626/all-feature660 strict local gates and focused review now
qualify generic conditional publication, synced initialization/head controls and
bounded committed content recovery. The selected S3 adapter, actual query/cache/
server and process simulation remain unfinished within S3-QUERY. This provides no
source custody, shared fencing, AWS/HA or release qualification. See [progress](07-progress.md)
and `target/goal-execution-20261007/S3-QUERY/publication-validation-accepted/validation.json`.

## Public repository and partial native CI — 2026-10-08

Source publication is separate from publishing a qualified version/image/crate.
GitHub run37809129533 on accepted revision66a9ce7 passed native ARM64 formatting,
all-feature Clippy/build/tests/workspace boundaries, then failed a helper step;
AMD64 failed build/tests. Container, kind, native load and supply-chain steps
were skipped. Complete EXT-ARM64/EXT-CI stay open; exact test counts are unavailable.

Revised CI separates source/native jobs and retains bounded per-command diagnostics.
A read-only manual candidate workflow packages qualified native images without
publication. Local syntax/helper checks qualify tooling only; changed remote CI
and actual candidate execution still need evidence. See
[OSS CI and cloud qualification](40-oss-ci-and-cloud-qualification.md).

## Object Parquet CPU seam — 2026-10-08

The later object-I/O/Small-owner acceptance is storage55/default609/all-feature643
with strict gates and focused review. Its exact evidence and remaining publication/
query/adapter work are in [progress](07-progress.md) and
`target/goal-execution-20261007/S3-QUERY/io-validation-late-final/validation.json`.
It does not complete S3-QUERY or any external release gate.

S3-QUERY remains in_progress. Six actual codec regressions and default599/
all-feature633 strict workspace gates plus focused review qualify bounded input,
output, decoded metadata and raw JSON handling; see [progress](07-progress.md) and
`target/goal-execution-20261007/S3-QUERY/codec-validation-accepted/validation.json`.
This grants no object publication/query commitment, distributed custody or AWS/HA
qualification. Conditional publication/recovery and object query/cache/server
simulation continue inside the frozen item. All external release gates stay open.

## Object-query manifest contract — 2026-10-08

S3-QUERY is in_progress. Strict bounded manifest/reference and time-partition
pruning now pass four regressions, default592/all-feature626 strict workspace
gates and focused source review; see [progress](07-progress.md) and
`target/goal-execution-20261007/S3-QUERY/manifest-validation-final/validation.json`.
No object-backed runtime/storage-custody/cache/HA or AWS qualification is granted.
Continue conditional publication, committed recovery and actual query/server
simulation inside the frozen task. External release gates remain unchanged.

## Protected route composition acceptance — 2026-10-08

The frozen EVIDENCE item is passed_simulated: actual protected retention/native
custody continues while observability is down; required source ACK waits for M2;
archive lost HTTP reply/exact replay, actual server crash/recovery, actual source
post-delete/pre-reply crash, stale handle denial and fresh ACK recovery pass.
Private77 strict gates plus the exact parent1 process simulation, independent
review, native fixture regeneration, overlay crash and workspace guard pass.
See the [current progress](07-progress.md) and
`target/goal-execution-20261007/EVIDENCE/protected-composition-validation/validation.json`.
Public588/622 is unchanged. The local simulation does not close AWS/Object Lock/
IAM/KMS/TLS/account isolation/shared-runtime/native ARM64/EKS/live vendor/remoteCI/
released-dependency/publication gates. Source completeness remains Unknown.
Next frozen item: S3-QUERY, then RETENTION and remaining dependency-ready work.

## Protected authenticated role transport — 2026-10-08

Protected provider/producer/verifier/owner loopback roles now pass private77 strict
tests/build/lints, bounded stalled-reader/connection regressions, immutable
native custody and current-head authority, independent focused review, actual
overlay/server crash checks and the workspace guard. The verifier fetches only
host-selected authenticated captures; it accepts no uploaded source metadata or
trust policy. Archive201 remains distinct from server202 M2. Public Rust stays
at588/622. Evidence is in the [progress](07-progress.md) and
`target/goal-execution-20261007/EVIDENCE/protected-http-validation/validation.json`.
EVIDENCE remains in_progress for protected observability-outage/source-ACK/M2 and
crash/replay composition. Loopback role checks close no real AWS/TLS/account gate.

## Native original/receipt and conservative coverage — 2026-10-08

The native validation/continuity substep now passes locally: current-confirmed
exact native-log/receipt/custody binding and immutable SDK coverage. Full private
72-test strict acceptance, signed nonempty source fixtures/reproducibility,
actual overlay/server crash recovery and focused review pass. Public Rust remains
at accepted588/622. See the [current progress](07-progress.md) and
`target/goal-execution-20261007/EVIDENCE/native-link-validation/validation.json`.
Coverage remains Unknown overall and preserves original proof age. EVIDENCE is
still in_progress for authenticated provider/role HTTP and protected source-ACK/M2
outage composition. Simulation closes no real environment gate.

## Retained native proof history and independent current head — 2026-10-08

The private EVIDENCE native mechanism now retains exact native bundles, immutable
observations, predecessor hashes and an atomic compare-and-swap head. Optional
trusted source/key policy is pinned to the complete collector binding. Reopen
requires a fresh separately signed current-head grant and revalidates every
retained bundle/signature/reference/classification. Later contiguous delivery or
backfill cannot erase a known gap; backfill cannot advance the regular checkpoint.
Configuration, API-category coverage and collection completeness stay unknown.

A separately owned/keyed bounded supervisor retains exact archive-signed head
transitions and advances its own head by CAS. Challenge replies read actual
retained supervisor history. Explicit ahead-one recovery checks the exact prior
head, revalidates the entire archive chain and physically closes before returning
only a transition. Fresh supervisor confirmation precedes ordinary reconciled
reopen; exact-current uses that ordinary path and other divergence is denied.
Consistently restoring both owners remains an independent reconciliation boundary.

Private acceptance passes 70 tests, zero failures, four parent-invoked helpers,
fmt, strict Clippy, build and actual overlay/server SIGKILL/SIGTERM checks. Four
actual SIGKILL cases cover both sides of archive and supervisor commits. Revoked
grants retain physical ownership until disk work exits; changed retained bundle
bytes prevent signing. Independent OpenSSL fixture regeneration is byte-identical.
Public Rust inputs are unchanged from accepted default588/all-feature622 gates.
Evidence: `target/goal-execution-20261007/EVIDENCE/native-supervisor-validation/validation.json`,
`native-supervisor-review.json` and `native-supervisor-handoff.json` there. The two
review findings, strict lint and shared startup-fixture corrections are resolved;
failed acceptance attempts remain retained. Archive development schema2 pins
native policy; older schema1 is refused without implicit migration or reset.
UPGRADE remains a planned item.

EVIDENCE stays in_progress. Continue native-log/receipt linkage and conservative
SDK coverage, authenticated protected role HTTP, source-ACK/M2 replay and
observability/archive outage composition. No actual AWS/Object Lock/IAM/KMS,
ARM64/EKS, vendor, remote-CI, released-dependency or publication gate is closed.

## Bounded independent archive mechanism — 2026-10-08

The EVIDENCE archive mechanism passes local acceptance. A separate private
single-owner SQLite worker now retains exact complete receipt bytes, canonical
manifest, immutable version, original commit time and retention. Readback checks
the full source binding and frame/manifest pins before actual Ed25519 custody
signing. Replay cannot renew that record; wrong/expired challenges are denied.
There is no original-delete or retention-shortening operation.

One operation permit/command slot retains physical ownership through cancellation;
uncertain mutations fail closed until worker exit and explicit reopen. Private
root/file/descriptor/inode guards, exact table/index schema, owner/binding/key
revision and actual public key pins, checked EXTRA/DELETE, finite VM/page/time and
copy budgets are enforced. Unexpected allocating triggers/views/altered tables
and retained native rows with reset zero metadata are refused. Native tables
remain empty and consumed native checkpoint reconciliation is still unfinished.

Three generic SDK frame/deadline regressions and sixteen private archive tests
pass. Public default588/all-feature622 and private53 tests pass, zero failures;
six public/three private subprocess helpers retain parent-invoked scope. Required
fmt, strict default/all-feature Clippy, package guard, private build and the actual
overlay one-event/one-finding SIGKILL/SIGTERM gate pass. Independent review has no
remaining blocker/high after the history-reset and schema-memory corrections.
Evidence: `target/goal-execution-20261007/EVIDENCE/archive-validation/validation.json`,
`archive-private-validation/validation.json`, `archive-review.json` and
`archive-handoff.json` there. Initial focused import/handoff/type corrections and
strict-check attempts remain retained separately. Only already locked ring/chrono
direct private edges were added; versions and publication authority are unchanged.

EVIDENCE remains in_progress. Continue independently retained native-proof
history/checkpoint/current-authority CAS/restore and conservative coverage, then
authenticated role HTTP/protected outage/crash/redelivery composition. Custody
asserts retained bytes, not source completeness. These tests do not establish
IAM/KMS/Object Lock isolation, rollback absence from copied databases, AWS/AZ loss,
actual EKS/native ARM64/vendor/remote-CI/released-dependency/publication readiness
or final-candidate qualification.

## Independent receipt custody and fenced source ACK — 2026-10-08

The bounded EVIDENCE custody mechanism now passes local acceptance. An independent
Ed25519 authority signs the complete framed receipt and immutable archive manifest;
fresh challenges cannot renew its original commit time or retarget identity.
Strong ACK begin/finish/recovery each require fresh verification of the exact saved
witness. Trusted quarantine selection, pinned M2, full CAS/current-history and
recovery horizons remain mandatory. Worker I/O and tickets expire at the earliest
challenge/key/archive/context deadline. Transfer, poison and worker exit fence
retained tickets before new source credentials/HTTP work; dispatched remote effects
remain uncertain. Local retirement preserves custody and deletes no archive original.

Fourteen custody regressions and two optional source-fence regressions pass,
including six actual SIGKILL publication cases, syscall faults, physical-expiry
ownership, prequeue allocation limits, key/retention expiry, M2/quarantine and
reopen/handover. Public default585/all-feature619 and private37 tests pass, zero
failures; six public and three private subprocess helpers retain parent-invoked
scope. Required fmt, strict default/all-feature Clippy, package guard, private
build and the local overlay SIGKILL/SIGTERM gate pass. Independent review has no
remaining blocker/high. Evidence: `target/goal-execution-20261007/EVIDENCE/`
`custody-validation/validation.json`, `custody-private-validation/validation.json`,
`custody-review.json` and `custody-handoff.json`. Initial compilation/assertion,
sandbox loopback denial and strict enum-size corrections remain recorded separately.
No package version or release authority changed.

EVIDENCE remains in_progress. The next runnable slice is independently enforced
archive/version/retention/access and durable native-proof checkpoint/coverage
integration, including protected capture during observability outage and crash/
redelivery recovery. These are implementation requirements, not credential-only
exceptions. Signed assertions alone do not establish archive isolation, native
source completeness or real AWS/Object Lock/IAM/KMS qualification. The collector
driver remains explicitly process-local; final candidate and external gates stay open.

## Native CloudTrail byte proofs and read-only capture — 2026-10-08

EVIDENCE now has an accepted native mechanism slice: exact uncompressed-byte RSA
digest validation, complete referenced-log hashing, version/owner pins and
conservative anchored/bootstrap/unanchored/gapped/backfill classification. The
optional signed regional-key and exact-version S3 adapters retain native metadata,
finite responses, one active request and cancellation without retry/latest fallback.
The independent OpenSSL baseline and twelve proof/nine local HTTP regressions pass.

Public default571/all-feature603 and private37 tests pass, zero failures. Required
fmt, strict default/all-feature Clippy, package guard, private build and the local
overlay SIGKILL/SIGTERM recovery gate pass. Independent review has no remaining
blocker/high after the exact-time and owned-test-server lifecycle corrections.
Existing ignored subprocess helpers keep their parent-invoked scope. Evidence:
`target/goal-execution-20261007/EVIDENCE/native-validation/validation.json`,
`native-private-validation/validation.json` and `native-review.json` there.
Only existing locked ring/base64 dependency edges were added; no package version
or selected release changed. See [protected evidence contract](38-protected-evidence-contract.md).

EVIDENCE remains in_progress. Independent durable proof checkpoints/coverage,
protected-route outage/proof/crash recovery still need implementation and
acceptance. Whole-receipt custody/stronger ACK mechanisms have the later
local acceptance above; independent archive integration is still unfinished. These read-only byte proofs neither
establish complete collection nor close real AWS/Object Lock/IAM/KMS/native ARM64,
actual EKS/vendor/remote-CI/released-dependency/publication or final-candidate gates.
Continue EVIDENCE with independently enforced archive and retained native-proof
checkpoint/route integration; process-local quarantine ACK remains denied.

## Scoped audited disposition backend — 2026-10-08

DISPOSITIONS is passed_local. Public version-1 outcomes, stable finding references,
separate trusted actor/scope authority and a backend seam are implemented by the
existing private control worker. Each update atomically appends immutable audit
and advances exact revision; corrections retain history and exact operation
replay preserves original receipt time. Scope/unknown finding/stale revision
failures grant no progress. Missing/stale heads and substituted audit fail closed;
complete query envelopes obey byte limits with truthful bounded continuation.

Two public and nine private regressions pass, including actual process crashes
before/after audit/head commit. Default559/all-feature582 public tests and 37 private
tests pass, zero failures; the five existing public and three bounded private
subprocess helpers retain their parent-invoked scope. Required fmt, strict default/
all-feature Clippy, package guard, private build and overlay process recovery pass.
Independent review has no unresolved blocker/high. Evidence:
`target/goal-execution-20261007/DISPOSITIONS/public-validation/validation.json`,
`private-validation/validation.json` and `independent-review.json` in that directory.
An initial sandbox-denied loopback campaign is retained separately; permitted
unchanged-source rerun passes. See [the disposition contract](37-disposition-contract.md).

No writable HTTP/SOC UI, OIDC/RBAC authentication, shared fencing or independent
signed audit archive is claimed. Private development schema 3 refuses older
stores without reset; explicit migration remains UPGRADE. Existing native ARM64,
actual AWS/EKS/vendors/remote-CI/released-dependency/publication gates and fresh
final artifact qualification remain open. Next: EVIDENCE.

## Private bounded notification delivery — 2026-10-08

OUTBOX is passed_simulated. The separate private application persists attempting
intent before network, pins immutable plans and uses finite single-request
concurrency, deadlines, response bytes, attempts/backoff and exact-token outcome
CAS. Restart/crash uncertainty preserves retry identity; permission/redirect
failures and exhausted retries stay visible and quota-charged. Credentials remain
runtime-only; source cancellation wins before a ready network poll.

Nine local HTTP scenarios and three deterministic review regressions pass. The
full private suite has 28 passes, zero failures and two subprocess helpers
invoked by their parent tests. Actual process kill after destination receipt
recovers the identical pending payload/identity. Private fmt/strict Clippy/build
and the existing public/private process gate pass; source review has no high
findings. Evidence: `target/goal-execution-20261007/OUTBOX/dispatch-validation/validation.json`.
Public default557/all-feature580 source acceptance is retained unchanged.

Private schema 2 refuses older development stores without implicit migration or
reset; explicit migration remains UPGRADE work. These simulations do not qualify
live tenants, universal external deduplication, native ARM64, real AWS/EKS, remote
CI, released dependencies, publication or the final candidate. Next: DISPOSITIONS.

## Private outbox transaction — 2026-10-08

The separate private application now atomically commits a complete bounded page
of immutable delivery plans and its exact findings cursor in SQLite. Routing and
destination pins remain private; the public monolith and contracts are unchanged.
Input allocation bounds, physical worker/owner retention, EXTRA/DELETE durability
settings and exact retained-row replay checks are qualified locally. Thirteen new
private regressions pass; the complete private suite has 16 passes, zero failures
and one bounded subprocess helper invoked by its parent test. Process crashes
before/after commit recover an atomic plan/cursor; this is not hardware/power-loss
proof. Private fmt, strict Clippy/build and the existing process overlay gate pass.
Evidence: `target/goal-execution-20261007/OUTBOX/transaction-validation/validation.json`.

OUTBOX remains in_progress for bounded dispatch and notification simulations.
The public default557/all-feature580 accepted campaign is retained unchanged.
No native ARM64, actual AWS/EKS/vendors, remote CI, released-dependency,
publication or final-candidate gate is closed by this private slice.

AWS-DELIVERY now has simulated end-to-end source/receipt/M2/ACK acceptance,
including the optional official SigV4 SQS/S3 HTTP adapter. Current local gates:
default 500 and all-feature 512 tests, fmt, strict Clippy and package guard;
independent review has no blocker/high. Actual-wire signatures match an
independent witness and published AWS test vector; throttling, credential
rotation, durable failed-delete intent and redelivery recovery run against the
real local server. Evidence:
`target/goal-execution-20261007/AWS-DELIVERY/signed-transport-validation.json`.
CI checks optional features, but remote CI remains pending. This does not qualify
real AWS/IAM/TLS/trail/digests, source continuity or independent custody. Source
observers/server coverage integration are next. New optional dependencies and
the declared compiler minimum (matching the existing pin) require fresh final
package/SBOM/candidate evidence; old artifact reports retain their own bindings.

COVERAGE-OBSERVERS bounded state now has nine regressions, default 509/all-feature
521 passing tests and independent review. Immutable verification/record identity
and observer-owned current health are accepted locally. Native probes,
physical history/server integration and end-to-end degraded-silence simulation
remain local unfinished work. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/observer-validation.json`.
This acceptance does not change source proof, live-environment or release gates.

Regional CloudTrail configuration observation is accepted locally with eleven
native-source regressions and eleven unchanged S3/SQS signed-wire regressions.
Current gates pass default 509/all-feature 532 tests, strict Clippy/fmt/package
guard and focused independent review. Native point configuration checks retain
unknown continuity/digest/checkpoint/quiet completeness. Malformed selector and
existing query-test timing corrections have retained failing-before evidence.
COVERAGE-OBSERVERS stays open for history/server integration and independent
checkpoint/gap/degraded-silence simulation. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/native-probe-validation.json`.
Actual AWS/source custody and all existing release exceptions remain open.

The durable observer/history bridge is accepted locally: four new SDK and ten
physical-history regressions, default 523/all-feature 546 tests and required
format/lint/package gates pass. Independent review has no blocker/high. Exact
profile/global identity precede cache adoption; replay cannot heal health.
Evidence: `target/goal-execution-20261007/COVERAGE-OBSERVERS/history-bridge-validation.json`.
Scoped server configuration/authentication, lifecycle/API/metrics and independent
checkpoint/gap runtime simulation remain local work. No external or release gate
is closed and no old candidate/SBOM/image is qualified for these new source inputs.

Scoped monolith coverage intake/history/bootstrap/lifecycle now pass default535/
all-feature558 tests, twelve new focused/real-process checks and required local
format/lint/package gates. Source review has no blocker/high. Actual stalled-body
HTTP deadline, SIGKILL/reopen and startup credential rotation preserve originals,
receipts and unknown current health. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/server-integration-validation.json`.
Independent checkpoint/gap/quiet/degraded-silence simulation remains locally
unfinished. Native continuity/digest proofs were unimplemented/unqualified at that acceptance;
see the later native EVIDENCE acceptance above;
current source inputs require fresh final package/SBOM/image/candidate evidence.
Real AWS/ARM64/EKS/vendor/remote-CI/publication gates are unchanged.

Four actual-source/monolith HTTP simulations derive reports from separate bounded
synthetic source truth, rather than from successful telemetry admission. They
verify quiet coverage, a missing capture position despite HTTP 202, fresh backfill
correction with preserved historical failure, denied/throttled/malformed/oversize
source responses, blind intervals, expiry and arrival without renewed verification.
Lost history responses retain exact intent; server/observer restart and replay
cannot heal supervision. Scope/profile alias denials preserve original history.

Default 539/all-feature 562 tests pass, with zero failures and five existing
ignored helpers; format, strict Clippy and package checks pass. Independent review
has no blocker/high after two test-helper lifecycle corrections: owned bootstrap
children have a finite deadline, and source-task shutdown retains ownership through
abort/join. Evidence: `target/goal-execution-20261007/COVERAGE-OBSERVERS/runtime-validation.json`.
COVERAGE-OBSERVERS is passed_simulated; native CloudTrail checkpoint/continuity/
digest adapters were unimplemented/unqualified at that acceptance. Native byte-proof
mechanisms now have the EVIDENCE acceptance above; independent durable proof work remains
within EVIDENCE; simulation closes no real environment gate. Server history health
stays unknown without application-owned independent supervision. Next is the
bounded public findings cursor; historical artifacts need fresh final qualification.

## Durable findings cursor — 2026-10-08

`GET /v1/findings/feed` now provides bounded durable append-order pages, explicit
bootstrap and a versioned stream/position/exact-payload prefix digest. Existing
journal bytes, finding identity and filtered list order are preserved. Identical
replay creates no position; late findings remain visible. Missing/divergent/foreign
prefixes fail without replacement progress. Recovery syncs validated retained
frames before readiness. Requested frames are rechecked against their exact
indexed prefix before return; corruption closes the store.

Eighteen new protocol/store/HTTP/process regressions cover original JSON and
semantic duplicate frames, replay, paging, live corruption, response/memory/index
quotas, cancellation and retained physical leases. The actual monolith test
preserves cursors through SIGKILL/restart and rejects shorter/divergent restores.
Default 557/all-feature 580 tests pass, zero failures and five existing ignored
helpers, with fmt, strict Clippy and the 13-package guard. Independent review has
no unresolved blocker/high after exact-byte, startup-budget and empty-allocation
corrections. Evidence: `target/goal-execution-20261007/FINDINGS-CURSOR/validation.json`.

The index charge rises from 256 to 512 bytes per unique finding; preflight this
budget before upgrade. Server startup requires at least 288 query bytes to
represent the empty feed; smaller cursor-free library settings remain supported.
No locked package/version changes, service, destination or consumer ACK is added.
The cursor proves its consumed prefix, not an unseen suffix or writer fencing.
FINDINGS-CURSOR is passed_local; next is private transactional OUTBOX. Native
ARM64, actual AWS/EKS/vendors, remote CI, released dependencies and publication
remain open. Historical package/SBOM/candidate bindings need final requalification.

Minimal SecOps UI is now an owner-selected MVP requirement. UI-01/UI-02 have
local embedded-route, browser, exact-ID query, real-server/restart, current source
export and real-container acceptance. See [the UI contract](28-secops-ui.md).
Advanced SOC UX remains post-MVP. UI acceptance recorded 307 workspace tests,
26 fixture-browser checks and 14 real-container browser checks under
`target/secops-ui-evidence-20261007/`; the new immutable AMD64 image passes
container and all six supply-chain gates. Native qualification is recorded below;
local proof does not close the existing external release gates.

The earlier SourceCoverage SDK/store/intake/correction source passed 300 workspace tests and
the 13-package boundary guard. The preceding source revision's AMD64 image passes container, all six
supply-chain and native parser/pipeline/120-second-soak gates. The current kind
campaign fails before SIGNAL starts: kube-proxy reports `too many open files`,
and the PVC provisioner cannot reach the cluster API. The prior kind pass is
historical and does not close the current-image gate. Detailed counts and retained
paths are in [progress](07-progress.md#vendor-fixtures-and-current-source-release-refresh--2026-10-07).
The subsequent trusted intake/retry acceptance adds no dependencies or server
integration; its host-library proof is separate from the earlier image/candidate
reports, which still bind their own source revision. Bounded correction admission
adds atomic immutable links with available earlier full-binding targets and
overlap/later-verification checks. Payload/identity-prefix pruning and bounded scans are accepted locally with 96
coverage/358 workspace tests. Credential authentication and source observers remain open. This library is not integrated into the server and its proof does
not promote earlier image/candidate evidence.

The [CloudTrail source-receipt/profile design](29-cloudtrail-source-receipt.md)
adds offline native projection, identity/ACK witnesses and planned custody cases.
Local acceptance has 41 native projections, seven identity comparisons, two
prepared pins, 19 ACK witnesses and 26 independent tests/262 rejection checks;
19 custody scenarios remain unexecuted.
That design acceptance did not implement a Rust normalizer, source receipt store,
AWS collector, protected archive or source observer. Its 358-test workspace
result remains historical.
Design evidence is under `target/cloudtrail-receipt-design-20261007/`.

The subsequent pure SDK normalizer executes all 41 native record cases, with
16 parser/preparation tests and three actual native-to-finding profile tests.
D01's generic action filter is removed exactly as specified by the independently
reviewed design; root StopLogging yields D01+D02. At normalizer acceptance,
local Rust gates passed 377 tests, strict Clippy/fmt and the 13-package guard. Existing offline mutation
checks pass 26 tests/262 rejections. This is decoded-record/library evidence and
a focused writer review against prior independently reviewed requirements, not
a new independent source review, source custody, AWS collection or cloud proof.
SDK direct dependencies reuse already locked `sha2`/`uuid`; earlier image and
candidate evidence still bind their own source/build snapshots. Current evidence
is under `target/cloudtrail-normalizer-20261007/`.

The public synthetic corpus covers 55 cases across 11 requested source families.
The private overlay's version now matches `0.1.0-dev.0`; its three tests include
all 55 real Rust event validations and one intended private IAM finding. This is
source-path/local proof. The owner authorizes local Conventional Commits on
`develop` with deliberately assigned July evening Berlin dates; validation
reports retain actual October 7 times. No revision is pushed, merged to `main`,
tagged or published; no release version is selected. Local commits close no
release gate.

The [source-receipt/progress wire contract](30-source-receipt-contract.md) has
separate offline acceptance: three immutable and 20 progress vectors, 27
transition/seven reclaim cases, and 23 negative/relational tests with 180 rejection
checks. Evidence is `target/cloudtrail-receipt-schema-20261007/`. These witnesses
qualify schema/encoding decisions only, with focused writer review. They add no
Rust runtime, filesystem custody, source ACK, cloud qualification or fresh
independent source review. The previous 377-test Rust evidence retains its binding.

The bounded initial source-receipt SDK store has current local Rust/filesystem
acceptance: 21 new tests, including eight stage-specific process exits and eight
fault paths, alongside 398 workspace tests and the 13-package guard. Evidence is
`target/source-receipt-store-20261007/`. Exact initial wire/control pins, scope,
lock/quota/corruption, queued cancellation and lost-caller work are covered.
This is a focused writer review and surviving-filesystem process boundary only;
mutable progress/ACK/reclaim, source parsing/proof, live AWS and fresh independent
source review remain unimplemented or open. SDK edges reuse locked `libc` and
test-only `tempfile`; event/HTTP v1 and previous image/candidate bindings are unchanged.

The atomic verified-prefix receipt progress slice now has 410-test workspace
acceptance and focused independent source review after the revision-one
predecessor correction. Evidence is `target/goal-execution-20261007/`; the
[finite Goal ledger](31-execution-ledger.md) tracks remaining local work. Twelve
new tests include progress faults/crashes, queue/cancel/timeout and exact immutable
suffix recovery. Source ACK, ownership/reclaim/restore and transport remain
separate; current image/candidate reports retain their earlier source bindings.

Voluntary owner handover and independently-current-checkpoint opening now pass
422 workspace tests and independent source review. Evidence is
`target/goal-execution-20261007/RECEIPT-RECOVERY/validation.json`. These require
trusted application checkpoint authentication and retain the ordinary API’s
process-local limit. The subsequent SOURCE-ACK mechanism passes 436 workspace tests and independent
review: `target/goal-execution-20261007/SOURCE-ACK/validation.json`. Explicit
process-local intent/result/uncertainty carries in-memory handles only. M2/time/
first-transition reopen guards, stale authority/ticket fencing and six ACK crash
stages pass. It does not execute deletion or qualify provider identity, stronger
custody or account-loss recovery. Retirement/reclamation and explicit new-UUID replacement now pass 447 workspace
tests and independent review. Evidence: `target/goal-execution-20261007/RECEIPT-RECOVERY/retirement/validation.json`.
Ten retirement/seven replacement process-crash stages and actual unlink failure
exercise intent-before-removal, directory sync and retained-control recovery.
Unknown publication temp/orphan states still hold; checkpoints remain separately
authenticated. These mechanisms do not qualify source transport or stronger custody.

The subsequent OBJECT-READER parsing substep has 454-test workspace and independent
review acceptance: `target/goal-execution-20261007/OBJECT-READER/reader-validation.json`.
It validates bounded single-member gzip and exact native spans with all-record
validation before exposure. Whole-object preparation/quarantine subsequently passes 461 workspace tests and
independent review: `target/goal-execution-20261007/OBJECT-READER/validation.json`.
Seven new preparation tests include exact replay and aggregate payload limits.
AWS delivery and stronger custody remain pending.
The SDK now consumes existing locked flate2 1.1.10/zlib-rs directly; version
resolution is unchanged, but old image/SBOM/candidate bindings are still historical.

AWS-DELIVERY direct discovery subsequently passes 468 workspace tests and independent
review: `target/goal-execution-20261007/AWS-DELIVERY/discovery-validation.json`.
This parsing substep performs no fetch, source ACK or source completeness assertion.
Bounded capture/transport simulation remains runnable.

AWS-DELIVERY bounded capture/physical preparation subsequently passes 477 workspace
tests and independent review: `target/goal-execution-20261007/AWS-DELIVERY/capture-validation.json`.
The source stream seam is synthetic in these tests. A deterministic inherited-lock
regression resolves the exposed default-parallel handover failure; failed evidence
is retained. Collector/queue delivery simulation and actual provider auth remain
separate gates. Current-source images/SBOM/candidates still require their scheduled
rebuild; historical qualification is not transferred.

AWS-DELIVERY retained-byte batch publication subsequently passes 485 workspace tests
and independent review: `target/goal-execution-20261007/AWS-DELIVERY/publisher-validation.json`.
This uses synthetic publisher replies. Exact batch bytes, prefix/reopen and
concurrent stale-response holds qualify locally; network/provider source queue
simulation and source ACK remain separate.

AWS-DELIVERY configured HTTP publication subsequently passes 489 workspace tests
and independent review: `target/goal-execution-20261007/AWS-DELIVERY/http-publisher-validation.json`.
Four actual local TCP tests qualify exact authenticated request bytes, response
size bounds, redirects and cancellation. This adds an SDK edge to locked reqwest
0.12.28 without changing versions. Full source-to-M2/queue simulation, mTLS,
provider IAM and real AWS remain separate. Historical packaging is not rebased.

AWS-DELIVERY source HTTP/queue simulation and actual-server persistence/recovery
subsequently pass 492 workspace tests and independent review:
`target/goal-execution-20261007/AWS-DELIVERY/delivery-simulation-validation.json`.
Lost reply and create_new failure/replay reach exact queried rows, one finding
and checkpoint three. Source ACK/visibility/denial/throttle cases are simulated;
production polling, SigV4/TLS/IAM/real AWS and stronger custody remain separate.
Failed structural-test evidence and the test-budget-only correction are retained.
Historical packaging still requires the planned current-source rebuild.

AWS-DELIVERY bounded collector driver subsequently passes 500 workspace tests
and independent review: `target/goal-execution-20261007/AWS-DELIVERY/driver-validation.json`.
Seven SDK regressions and one real-server driver integration retain exact pins,
uncertain-ACK recovery and fresh authority. A high receipt substitution race was
reproduced and corrected with exact identity checks in publication/ACK replays;
failed/after-fix evidence is retained. Actual signed AWS transport remains a
locally runnable substep, while provider deployment/IAM/TLS/independent custody
remain separate. No candidate/image/SBOM qualification is transferred.

## Evidence ledger

| ID | Observed proof | Exact source or retained artifact |
| --- | --- | --- |
| W | Current local OSS formatting, strict all-target Clippy and locked/offline workspace tests: 500 tests, zero failures; boundary guard validates 13 packages. Includes seven bounded collector-driver tests and four source/real-server delivery simulations and four HTTP publisher tests, eight retained-batch publication tests, eight capture tests, one inherited-description lock regression, seven direct discovery tests, seven whole-object preparation tests, seven gzip/object reader tests, 11 retirement/replacement tests, 14 ACK control tests, 12 handover/reconciled-open tests, 12 verified-prefix progress tests and 21 initial source-receipt store tests, 16 bounded CloudTrail parser/preparation and three native-to-finding profile tests alongside existing coverage/UI/WAL/storage tests. | `target/goal-execution-20261007/AWS-DELIVERY/driver-validation.json` and independent review; prior 492-test delivery-simulation acceptance is `target/goal-execution-20261007/AWS-DELIVERY/delivery-simulation-validation.json`;  prior 489-test HTTP publisher acceptance is `target/goal-execution-20261007/AWS-DELIVERY/http-publisher-validation.json`;  prior 485-test publisher acceptance is `target/goal-execution-20261007/AWS-DELIVERY/publisher-validation.json`;  prior 477-test capture acceptance is `target/goal-execution-20261007/AWS-DELIVERY/capture-validation.json`; prior 468-test discovery acceptance is `target/goal-execution-20261007/AWS-DELIVERY/discovery-validation.json`; prior 461-test complete preparation acceptance is `target/goal-execution-20261007/OBJECT-READER/validation.json`; prior 454-test reader acceptance is `target/goal-execution-20261007/OBJECT-READER/reader-validation.json`; prior 447-test retirement acceptance is `target/goal-execution-20261007/RECEIPT-RECOVERY/retirement/validation.json`; prior 436-test ACK acceptance is `target/goal-execution-20261007/SOURCE-ACK/validation.json`; prior 422-test handover/open acceptance is `target/goal-execution-20261007/RECEIPT-RECOVERY/validation.json`; prior 410-test progress acceptance is `target/goal-execution-20261007/validation.json`;  prior 398-test initial receipt store and 377-test normalizer and 358-test coverage acceptance and previous image/candidate reports retain their own bindings. Bundled SQLite build evidence remains `target/source-coverage-store-20261007/sqlite-build.json`; [workspace guard](../scripts/check-workspace.py). |
| P | Separate private package: two tests; external normal-server process gate preserved one event/finding through SIGKILL and successful SIGTERM | `/tmp/signal-phase7b-private-gates.log`, `/tmp/signal-phase7b-process-gate.log`; [external overlay gate](17-external-overlay.md), [harness](../scripts/check-overlay.py) |
| I | Single/batch validation, bounded request/queue admission, auth, cancellation, overload and exact partial admission | [HTTP integration tests](../crates/signal-ingest/tests/http.rs), included in W; [ingest API](09-phase1-ingest.md) |
| B | Real WAL truncation/corruption/restart, bounded count/byte/segment quotas, block timeout, checkpoint I/O failure and replay | [WAL recovery tests](../crates/signal-buffer/tests/recovery.rs), included in W; [WAL contract](10-phase2-wal.md) |
| S | Parquet roundtrip, replay content checks, quotas and partial-publication cleanup on bounded-writer quota error; time partition pruning | [Storage tests](../crates/signal-storage/tests/store.rs), [codec tests](../crates/signal-storage/tests/codec.rs), included in W; [storage contract](12-phase3-storage.md) |
| D | Actual filesystem EEXIST create failure after durable HTTP 202: server fails closed, checkpoint remains zero, owned blocker stays unchanged; repair replays exact event/finding, advances checkpoint to one and a third restart remains stable | `/tmp/signal-phase10-storage-failure.log`, one focused process test passes in 2.52 s; [gate source](../tests/integration/phase10-storage-process.py), registered in [foundation tests](../tests/integration/foundation.rs) |
| Q | URL time/message/structured filters, ordering and bounded query responses; process restart | [Query tests](../crates/signal-query/tests/), [process gate](../tests/integration/phase4-process.py), included in W; [query API](13-phase4-query.md) |
| R | Invalid rules/config prevent startup; event→Parquet→rule→findings→checkpoint; finding-quota fail-closed recovery and redaction | [Phase 5 process gate](../tests/integration/phase5-process.py), included in W; [rules/findings/config](14-phase5-core.md) |
| A | Agent stdin/file, retry/spool/cursor/rotation/quota/restart and token redaction: 36 library tests plus one process case | [Agent contract and recorded gate](15-phase6-agent.md#phase-6-verification), [process source](../tests/integration/phase6-process.py); current W retains this coverage |
| C | Fresh native container runtime on the buffered-reader image: nonroot 65532, read-only root, healthy probe, auth, SIGTERM/SIGKILL persistence and owned cleanup | `target/phase10-header-buffer-20261006/container.log`; [container gate](../scripts/check-container.py); image `sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1`. Earlier C image remains historical. |
| K | Owner-selected local Kubernetes milestone completed using kind 1.34 and the refreshed exact image: one event/finding persisted, SIGKILL and replacement pod recovered via the same PVC; nonroot/read-only/auth/separate metrics and cleanup passed. This proves local kind behavior, not actual EKS/AWS storage/runtime. | `target/phase10-header-buffer-20261006/kubernetes-final.log`; [Kubernetes gate](../scripts/check-kubernetes.py); same image as C. |
| T | Helm 3.19.0 strict default/optional/private-values lint and render; single writer, regular-file config/rules mounts and decimal integer config | [Chart](../deploy/helm/signal/README.md), [packaging evidence](07-progress.md#phase-8-local-evidence--2026-10-06) |
| V | Refreshed image supply-chain run: all six checks passed; RustSec zero vulnerabilities; SPDX Cargo 328/image 15 packages; Trivy HIGH 0, CRITICAL 0, MEDIUM 23, LOW 8 | `target/phase10-header-buffer-20261006/supply-chain/20261006T211924.305016Z/`; image matches C; [supply-chain scope](18-supply-chain.md) |
| O | Structured bounded/redacted logging; health/readiness and finite queue/WAL/storage/query/rule/finding metrics | [Metrics source](../crates/signal-ingest/src/lib.rs), [logging](../apps/signal-server/src/logging.rs), R/C/K process gates; [architecture](01-architecture.md) |
| F | Focused deterministic parser/property campaign: nine tests pass in 15.971 s; 512 event/512 URL/512 rule models, 104 record and 28 checkpoint mutations, 303 tail cuts, nine ack prefixes | `target/phase10-hardening/20261006T185925.121730Z/{campaign.json,campaign.log}`; [threat model/campaign scope](20-threat-model.md); independently reviewed |
| L | Historical eight-profile finite load/CPU/RSS campaign: 13,994 attempts, 3,217 HTTP-confirmed/3,223 WAL/Parquet durable events, 197 findings; eight-slot queue reached 8/8 with 48 accepted/9,952 rejected | `/tmp/signal-phase10-pipeline.json`, `/tmp/signal-phase10-overload.json`; [measured benchmark report](../BENCHMARKS.md); native AMD64 on historical image `sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97`; independently reviewed |
| H | Hardening orchestrator cleanup kills/reaps its owned process group; current one-test regression passes in 2.209 s; native cancellation/identity/report suite passes fifteen tests separately from Cargo | `target/native-qualification/local-gates/{hardening-cleanup-final.log,native-runner-tests-final.log}`; [hardening regression](../scripts/test-hardening.py), [native regressions](../scripts/test-native-qualification.py); independently verified |
| Z | Synthetic same-binary offline restore on native AMD64: 18 copied files verified for SHA-256/mode/ownership, stopped original and backup unchanged; one pending WAL and two pending spool events retain canonical IDs, two findings stable, copied-source reread/cursor reuse and appended line verified, final checkpoint nine through another restart | Original `target/phase10-restore-qualified/`; independent repeat `target/phase10-restore-review-20261006/{review.log,rehearsal/report.json,rehearsal/inventory.json}`. [Gate](../tests/integration/phase10-restore-process.py), registered in the agent process target; subsequent independent review found no source issue. |
| N | Refreshed native AMD64 qualification passed: nine property tests and seven pipeline profiles, 13,480 attempts/3,175 HTTP-confirmed/3,176 durable events/191 findings/140 queries; zero transport uncertainty or drops. Eight-slot profile accepted 56/rejected 9,944; one event beyond an HTTP 408 prefix stayed within the uncertainty bound. | `target/phase10-header-buffer-20261006/native/20261006T211925.268888Z-edd4602c/{qualification.json,pipeline.json,hardening/campaign.json}`; image/binary match C. Runner scope is native qualification with `full_qualification: true`; this does not complete external release gates. |
| J | Refreshed native campaign included two 120-second profiles: 8,050/6,490 events accepted and WAL/persisted/rule-evaluated, 403/325 findings and 20 queries each; zero rejection, uncertainty, query or cleanup errors. Rates 67.030/54.059 EPS; campaign scope is native qualification, `full_qualification: true`. | Same native report directory as N, `soak.json` SHA256 `66b5e0b002b7ae6e3b14cba1326cb644709e7996e3e6e90ab721d66f0b3130f9`. The earlier 120-second soak-only result is historical `scope: native-soak`, `full_qualification: false`, preserved at `target/phase10-soak-team-20261006/final/20261006T203345.246930Z-6640d177/`. |
| Y | Fixed 1 KiB Parquet header `BufReader`, three storage regressions and matched release-image 20-file/40-event diagnostic: calls 37,920→702; successful one-byte reads 37,698→0; process-returned bytes 532,926→968,300. Old-image 600-second profiles failed their first query with HTTP 408. Refreshed-image 1 KiB/4 KiB 600-second profiles both passed with 12,000 durable events, 600 findings and 20 queries each; zero rejection, uncertainty or failures. | Syscall reports `target/phase10-query-reads-20261006/run-{1,3-image}/report.json`; old failed soak reports `target/phase10-longer-soak-20261006/{validation.json,soak-1024.json,soak-4096.json}`; refreshed reports and pair validation under `target/phase10-longer-buffered-20261006/` and `target/phase10-longer-soak-20261006/review/longer-pair-validation.json`; current 231-test workspace in W. The call reduction is structural; strace timings are not capacity evidence and returned bytes are not physical-device I/O. Finite load RSS does not establish a universal plateau or prolonged stability. |
| X | Final independent source approval: no unresolved findings; campaign/log/test hashes, both benchmark hashes/eight-profile counts, cleanup, storage EEXIST and threat-model/security/upgrade/changelog/audit claims checked | Consolidated review acceptance recorded in [progress](07-progress.md); local source/mechanism scope only |
| UI | Read-only embedded console and exact-ID evidence navigation: 307 Rust tests, 26 fixture-browser checks, four actual-server/restart checks, 14 real-container browser checks; source export, 24 candidate-helper regressions, strict Helm and focused independent review pass. Real delayed 10-day duplicate evidence and large numbers survive restart; shell does not bypass API auth. Fresh nonroot/read-only container auth/TERM/KILL and all six supply-chain checks pass. | `target/secops-ui-evidence-20261007/`; image `sha256:14c56dcf65bcbb41d95a7ee1a8ced9464732ec71db80c014b3fab734b21cbf55`; [UI contract](28-secops-ui.md). Earlier C/K/V/N/J/Y/LC snapshots retain their own historical image/source bindings. |
| NU | Fresh UI-image native AMD64 qualification: nine hardening tests, seven pipeline profiles (13,676 attempts, 3,666 HTTP-confirmed, 3,668 WAL-durable; two extra after HTTP 408 within allowed uncertainty) and 140 queries; two 120-second 1/4 KiB soaks retain 10,740/6,890 events, 537/345 findings and 20 queries each with zero rejection/transport uncertainty. Full native scope passes, owned cleanup passes. | `target/secops-ui-evidence-20261007/native/20261007T131955.011401Z-1b5080a4/qualification.json` and bound hardening/pipeline/soak reports; image matches UI. Finite shared-host proof, not scale-envelope, prolonged stability, ARM64 or AWS proof. |
| CP | Post-MVP SourceCoverage payload-prefix pruning: 58 library tests (13 new), 320 workspace tests, 13-package guard and independent review. Atomic eligible global prefix preserves identities/receipts/pins/links; actual queued timeout/cancellation and pre/post pruning SIGKILL pass. | `target/source-coverage-payload-pruning-20261007/`; [ADR-015](adr/015-source-coverage-store.md). Local AMD64 isolated library proof, not observer/source health, physical erasure, fsync cancellation, server integration or release qualification. |
| CI | Post-MVP SourceCoverage identity-prefix pruning: 74 library tests (16 new), 336 workspace tests, 13-package guard and independent review. Atomic global prefix/pin reclamation preserves tail/history/surviving corrections. Actual queued timeout/cancel and pre/post-commit SIGKILL, including final pin deletion/prune-all/next append, pass. | `target/source-coverage-identity-pruning-20261007/`; [ADR-015](adr/015-source-coverage-store.md). Isolated local AMD64 mechanism; scans were pending at this acceptance and are recorded in CS. Observers, server wiring and external release gates remain open. |
| CS | Post-MVP bounded SourceCoverage scans: 96 library tests (22 new), 358 workspace tests and independent review. Fixed-frontier scope/history/prefix/retention cursors, exact independent token vector, positive work/response budgets and retained-page operation permits pass; read-only state, divergent restores, pruning and queued timeout/cancel verified. | `target/source-coverage-scans-20261007/`; [ADR-015](adr/015-source-coverage-store.md). Isolated local AMD64 proof; no live sources, source-health inference, unread-history recertification, server/HTTP integration or external release qualification. |
| LC | The 2026-10-07 dev0 candidate preview passed local preparation, offline integrity verification, relocated source-path-graph checks and four packaged-chart checks. It preserves the accepted AMD64 image and remains `full_release: false`; this is not alpha, release or remote-dependency evidence. | `target/local-candidate-team-20261007/preview2/` and `preview2-relocated/{validation.json,bundled-offline-verify.json}`; [procedure and scope](23-local-candidate.md). Final candidate export/review is separate. |

W is the current full workspace result: the prior 231-test gate plus 24
SourceCoverage SDK, 96 local-store/intake/correction/payload/identity-pruning/scans, one UI route
and six exact-ID protocol/Parquet tests total the prior 358; adding 16 CloudTrail
parser/preparation and three native-to-finding profile tests gives 377; the 21
initial source-receipt tests bring current W to 398. Focused F/D/Z and Y results are
already included and must not be added again. Earlier phase counts
(including the 203-test Phase 6 run) remain historical evidence. The three
Kubernetes cleanup tests, two standalone health-helper tests and H's one
hardening cleanup test pass separately; they are not part of that Cargo count.
Some historical `/tmp` logs have disappeared; their references describe earlier
observations, not currently retained files. Current W/N and independently repeated
Z evidence is retained under ignored `target/` and needs preservation before
cleanup. Both OSS and private repositories were checked
during the earlier audit: zero index rows and zero commits. That zero-commit state is historical. The public and private repositories now
have owner-authorized local development histories; the current continuation also
aligns private versioning and validates the shared corpus. Neither is published.

The earlier 227-test final log records the first agent result separately and an
interleaved seven-test codec summary. The original combined command exited two
only after attempting nonexistent `scripts/check-boundaries.py`; the intended
`scripts/check-workspace.py` subsequently exited zero. Local Actionlint also
exited zero (`/tmp/signal-phase10-actionlint.log`). The cleanup finding is fixed
and its regression independently passed. Final independent source review found
no unresolved findings and accepted the scoped campaign and documentation
claims. The offline restore addition subsequently passed independent review and
a focused rerun against the same 14 areas. The native runner and cancellation
corrections also passed independent source review and fifteen focused tests,
separate from the 228 Cargo tests. Earlier approval X remains historical;
the continuation's acceptance is recorded in progress. Those approvals preceded
the buffered-reader change; the current reader preserves disk formats. The source
tree has no committed release revision; the local baseline commits are development
imports with deliberately assigned historical dates. Report hashes bind
recorded inputs/artifacts but are unsigned local evidence.

## Required gates still open

| Gate | Current boundary | Completion evidence needed |
| --- | --- | --- |
| Native ARM64 build/runtime/container/Kubernetes and measured hardening benchmarks | On3b172b70 both complete native Rust jobs, production image builds and basic container runtime/persistence pass. Both native pipeline steps fail; Kubernetes and supply-chain stages are skipped. fe5 CI remains in progress at the retained observation. | Native ARM64 runner logs and reviewed architecture-specific runtime, persistence and benchmark evidence |
| Current local kind deployment | Three attempts timed out on the PVC; owned-cluster diagnosis records kube-proxy `too many open files` and provisioner API timeout. Prior image proof is historical | Restore host-resource preconditions and pass the current-image standard-chart persistence/restart gate |
| EKS deployment | Deferred: no authorized EKS environment is available. The preceding kind milestone was local proof; the fresh kind gate is currently blocked by host-resource exhaustion. Neither establishes EKS or AWS storage/runtime behavior. | Actual approved cluster/namespace/storage/image/architecture evidence and persistent restart checks |
| Remote CI | Both native Rust jobs, image builds and basic runtime pass on3b172b70; native pipeline fails on both, kind/supply-chain skipped. Latest fe5 push CI is in progress | Successful required native jobs and retained report artifacts for the reviewed revision |
| Released external dependency | Private application uses separate checkout/source-path dependencies | External application build/test against the actual released version and locked dependency graph |
| Release artifacts/publication | Owner authorized local commits on `develop`; develop pushes are authorized; publication remains unapproved. No release version was selected or bumped; `main` receives changes only when release ready | Qualified release artifacts after required gates pass and the owner-directed release workflow; ARM64, EKS, remote CI and released dependencies remain external gates |

## Security and operational limits

The final container scan passes the HIGH/CRITICAL gate; it retains 23 MEDIUM and
eight LOW occurrences. Scanner coverage does not determine exploit reachability
or establish absence of vulnerabilities in static Rust executables; the separate
Cargo audit covers locked Rust dependencies. SPDX license metadata is inventory,
not legal approval. The first image's failed 65 HIGH/four CRITICAL report describes
the previous image and is retained separately; it must not be mixed into final
image qualification.

Historical MVP baseline below predates the locally accepted native OIDC/RBAC, mTLS and selected audit hooks above; it is not a statement of current capability.

Authentication was an optional static token. Keep it configured before exposing
admission outside trusted clients. There is no MVP OIDC/RBAC, per-tenant isolation,
TLS termination or arbitrary-extension sandbox. Extensions are trusted,
cooperative in-process code. Network exposure, certificate handling, credentials
and organization-specific policy are external deployment responsibilities.

This is one writer on a bounded local filesystem. ReadWriteOnce does not prevent
two writers on one node. Logical file-byte limits do not establish physical
block/inode exhaustion behavior or a whole-process RSS ceiling. Z establishes a
synthetic local offline restore with identical development binaries and the same
user/filesystem. Cross-version migration, backup-media crash durability, different
ownership/storage environments and production operator acceptance remain unqualified.
Copied source files have different inodes and can reread lines with new IDs;
the restored spool preserves its queued IDs. See the [upgrade policy](../UPGRADING.md).
Process SIGKILL
is not hardware power-loss proof. No HA, horizontal scaling, network-filesystem
qualification, retention/tiering or native S3 store is established. At-least-once
replay protects identical stored sequence content, while independent admissions
can duplicate event IDs.

The finite shared-host campaign L observed peak RSS 43.36–57.02 MiB and CPU
1.52–16.54% of one core; these are sampled process measurements, not a universal
memory ceiling or function-level CPU attribution. High configured EPS targets
were not attained. Deadline responses left six more events durable than
HTTP-confirmed across three profiles, within the recorded in-flight append
uncertainty bound. HTTP rejection/timeout counts therefore do not prove absence
from storage; retries must tolerate duplicates. The eight-slot pressure run
returned 100 partial 429 responses, preserved all 48 accepted events, dropped
none and shut down normally. J adds a 120-second-per-size AMD64 soak with
load-phase RSS sampling; it does not establish prolonged stability or a memory
plateau. The old-image pair of 600-second profiles completed load and
persistence but failed the first event query with HTTP 408. Both refreshed-image
600-second profiles subsequently passed and their paired results were
independently validated. This finite local run does not establish prolonged
stability or a memory plateau. The final 14-area review accepted the bounded
local evidence with no findings; record:
`target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`.
Native ARM64 and physical disk I/O profiling remain unqualified. D exercises a
real create-time EEXIST error, not
physical disk exhaustion, hardware EIO or power-loss behavior.

## Documentation map

Public usage/configuration already live in [ingest](09-phase1-ingest.md),
[WAL](10-phase2-wal.md), [storage](12-phase3-storage.md),
[query](13-phase4-query.md), [rules/findings/server YAML](14-phase5-core.md),
[agent](15-phase6-agent.md), [SDK](16-collector-sdk.md),
[external overlay](17-external-overlay.md), [packaging](19-packaging.md) and
[native qualification](22-native-qualification.md).
The [threat model and bounded campaign](20-threat-model.md) and
[measured benchmark report](../BENCHMARKS.md) record Phase 10 scope and limits.
The [Unreleased development notes](../CHANGELOG.md) describe the implemented
slice without claiming a publication.
The [upgrade/versioning policy](../UPGRADING.md) records independent versioned
contracts and a conservative offline restore rehearsal. The [architecture
reference](01-architecture.md) and [ADRs](adr/) describe the existing boundaries.
Keep private identity, metadata, policies, fixtures and environment values in the
separate application; this audit adds no company content to OSS.

# Implementation progress

## SECURITY-ACCESS native HTTPS backend — 2026-10-09

The generic identity mechanism in `signal-ingest::identity` authenticates each
opaque access token against one fixed operator-configured HTTPS introspection
endpoint. It validates the provider with established rustls hostname/expiry/trust
checks and authenticated client credentials, then applies the accepted response
profile and exact private issuer/subject policy. No provider role/header claims,
redirects, ambient proxies, retries or token/revocation cache supply authority.

Ten local regressions pass: finite actual TLS active/inactive/fresh recovery,
wrong issuer/audience/expiry/unbound subject, invalid response shapes/headers and
bounded/chunked body failures, certificate trust/name/expiry denial before
credentials, cancellation/abort, deadline clamping, fixed worker saturation and
explicit shutdown. A synthetic nonpreemptible lookup pause demonstrates that
frontend timeout cannot free an active physical lease; a short shutdown reports
failure while that work remains visible, and joins after its release. This is
not a stalled real OS resolver measurement. Review found a fixture handle could
be detached if its cleanup future was cancelled; retained handle ownership and
a pending-finish drop regression resolve it. Initial fixture compile/category
errors and the superseded pre-correction campaign remain retained.

Strict default684/all-feature735, formatting, both Clippy configurations,
all-feature build, workspace13 and focused review pass on the corrected source.
Evidence: `target/goal-execution-20261007/SECURITY-ACCESS/native-tests-tls-reviewed.log`,
`native-validation-corrected/validation.json`, `native-review.json` and
`native-acceptance.json`. Fresh synthetic TLS keys/certificates come from finite
OpenSSL subprocesses; fixtures own their tasks, ports and child cleanup.

SECURITY-ACCESS remains in_progress. No server route calls this backend yet;
OIDC sign-in, local IdP-backed HTTP expiry/revocation/cross-scope acceptance,
server readiness/configuration and route authorization remain unfinished.
External/native/remote/cloud/HA/custody/image/release gates stay open.
Next: mandatory query authorization before sorting/limits/serialization,
whole-batch admission checks, then server integration and remaining routes.

## SECURITY-ACCESS introspection response profile — 2026-10-09

SECURITY-ACCESS remains in_progress. A selected bounded OAuth2 response profile
requires an authenticated fixed-provider successful response before parsing.
Within that trust boundary it requires a JSON object, active token, exact issuer
and audience, bounded subject, valid expiry and Bearer token type. Optional nbf/iat
cannot be in the future or at/after expiry. Audiences use exact equality, permit
at most16 unique entries, and never supply role authority. Provider groups, roles,
username, scope strings and extensions do not assign SIGNAL capabilities.

Six adversarial fixture tests plus the earlier nine grant regressions pass.
Strict default674/all-feature725, formatting, default/all-feature Clippy,
all-feature build, workspace13 and independent review pass. Response body is
capped16KiB and the explicit1–300-second request lease ends at the earlier of
lease expiry or token expiry. There is no parser revocation cache or clock-skew
leeway. A review found Serde's positional sequence form could bypass the selected
object shape; complete otherwise-valid array regression and object guards now
cover both response parsing and private policy loading. The initial fixture's
integer-width compile error is retained as failed evidence.
Evidence: `target/goal-execution-20261007/SECURITY-ACCESS/introspection-tests-3.log`,
`introspection-validation-final/validation.json`, `introspection-review.json`
and `introspection-acceptance.json`. See [access contract](42-access-control-contract.md).

This parser cannot authenticate transport or prove an opaque credential is an
access token; the fixed authenticated provider must do that. It does not accept
client claims or implement OIDC sign-in, native HTTP/TLS, revocation or any server
route. Live/cloud/native/remote/HA/custody/image/release gates remain open.
Next: bounded fixed-provider native HTTPS introspection with local provider/TLS,
malformed/denial/timeout/cancellation/recovery tests, then server authorization.

## SECURITY-ACCESS bounded grant contract — 2026-10-09

SECURITY-ACCESS remains in_progress. The pure version1 grant model pairs each
operation with its exact source/account/resource scope, binds the exact verified
issuer/subject, and denies missing restricted facts, unknown identities, expiry
and use before grant issuance. Multiple roles cannot cross-combine operations
and account selectors. Canonical event source/resource fields supply facts;
arbitrary attributes never grant authority. Global feed/admin capabilities require
explicit all scopes; role names imply no privileges. Private bindings stay private.

Nine focused adversarial tests and strict default668/all-feature719 workspace
checks pass, with formatting, default/all-feature Clippy, all-feature build,
workspace13 and independent review. Programmatic policies receive nonallocating
nested length/count preflight before encoded-byte checks and lookup allocation;
retained vectors/strings discard spare capacity. Review found and resolved those
two resource issues. Errors remain static/redacted. The initial Clippy fixture
allowance omission and earlier-source campaigns remain historical, not final proof.
Evidence: `target/goal-execution-20261007/SECURITY-ACCESS/grant-tests-final.log`,
`grant-validation-preflight-final/validation.json`, `grant-review.json` and
`grant-acceptance.json`. See [access contract](42-access-control-contract.md).

This module does not authenticate HTTP requests, validate provider transport,
observe revocation or change the current server's optional single bearer token.
The verified-identity constructor is an explicit trusted-host boundary. Stored
canonical identity remains data that admission must bind to an authorized source;
matching an account field is not cloud ownership proof. Current-source native
ARM64/remote CI/kind, live IdP/cloud/custody/HA and fresh candidate/image/release
qualification remain separate. Next within this frozen item: selected bounded
OAuth2 introspection response validation, then native trusted transport and route
integration/local identity-provider denial/recovery simulations.

## RETENTION bounded query/cache measurements and parent acceptance — 2026-10-09

RETENTION is passed_simulated. The finite current-binary workload admits2,048
synthetic events in16 batches across8 UTC hours, with4KiB deterministic message
payloads and exact IDs/messages/nested attributes checked against an independent
oracle. All33 query samples pass; five serial repetitions are retained for warm
hourly/broad and source/severity/JSON predicates. This is an AMD64 debug/local
structural diagnostic, not production capacity, physical-device throughput,
AWS price/TCO or long-term memory evidence.

| Observation | Current finite result |
| --- | --- |
| Warm hourly / broad median wall time | 501.187ms / 2,937.896ms |
| Selected hourly / broad data objects and remote GETs per query | 2 / 16 |
| Warm source / severity / JSON predicate median wall time | 3,223.093ms / 3,372.393ms / 3,190.693ms |
| Empty-cache selected rebuild wall time / remote GETs | 585.714ms / 2 |
| Selected-file / decoded-byte denial | HTTP413; zero data GETs/scanned counter increase; no partial events |
| Query data / manifest objects | 16 / 16 |
| Parquet data / complete fixture bytes | 17,390,662 / 17,409,030 |
| Derived cache bytes | 17,390,662; warm identity/mtime/hash preserved |

The cache is rebuildable, but every selected query still authenticates remote
version/ETag/SHA bytes. Warm cache does not save S3 GETs. Whole canonical v1 event
responses and existing Parquet projections/predicates remain unchanged; no partial
field-response API or mandatory field index is added. Time pruning reduces chosen
objects8-fold in this workload. Defer optional indexes: these observations do not
establish an index benefit. History remains bounded; reaching finite manifest/
inventory/catalog limits holds progress rather than pruning authentication history.
A retired data policy never authorizes original/raw evidence removal.

Four failure-evidence helper regressions pass, including actual owned child reap
following a deterministically injected creation signal. Early spawn/missing logs,
late drain errors and late materialization cannot be called successful. Source
review, Python compilation, workspace13, workflow actionlint and exact current
Rust source bindings pass; the accepted default659/all-feature710 Rust campaign
is reused unchanged. Both native CI runners are wired to run the new helper and
measurement gate, without claiming remote execution. All5 owned workload children
are reaped; the stopped cache witness is preserved and rebuilding checks exact
bytes. Evidence: `target/goal-execution-20261007/RETENTION/query-measurements-final/report.json`,
`measurement-helper-tests-final.log`, `measurement-review.json`,
`measurement-actionlint.log` and `measurements-acceptance.json`.

Earlier attempts are retained as failed: the initial fixture used the wrong
single/batch envelope, assumed warm cache bypassed remote authentication, then
used a short1.8-second debug-workload deadline. The complete workload uses the
normal5-second server deadline and a bounded6-second HTTP client. No failed
attempt or earlier-source diagnostic is promoted. Actual cloud/version/IAM/KMS/
Object Lock/TLS, native ARM64/remote CI/kind/EKS/shared HA/custody, fresh image and
release gates remain open. Next frozen item: SECURITY-ACCESS.

## RETENTION exact retired query-version reclamation — 2026-10-09

RETENTION remains in_progress. Exact removal is an explicit trusted stopped-host
capability under the actual Small source owner and fresh stream-bound checkpoint.
The controller authenticates the synced retirement/whole committed prefix and
preflights all candidate pins before any removal. Only canonical retired query
Parquet with immutable non-null versions and exact non-wildcard ETags qualifies.
No producer/API deletion, automatic policy expiry, path-only fallback, raw evidence
removal, manifest removal or unknown-age orphan removal is introduced.

The explicit S3 adapter signs versionId plus If-Match through the existing fixed
physical I/O worker/original operation context. Ordinary query/ingest transport
continues rejecting DELETE. Permission/hold denial, replacement, redirects,
contradictory duplicate integrity headers and uncertain replies fail closed.
Absence in ListObjectsV2 never proves a pinned version absent: every retired pin
gets an exact authenticated read, with only NotFound counted absent. Retry derives
reachability again and distinguishes deletion acknowledgements from observed
absence. No partial successful report or WAL/control advancement follows failure.

Strict default659/all-feature710, formatting, default/all-feature Clippy,
all-feature build, workspace13 and focused read-only source review pass. Storage
has92 default/107 S3 tests; the ninth helper is ignored standalone but invoked by
an actual parent process-loss test. Finite native wire tests cover hidden old
versions, repeated removal, protected originals/orphans/live history, denied GET
and DELETE, replacement before deletion, lost reply after effect and actual child
SIGKILL before/after effect with exact retry/reopen. Physical object storage in this
native wire fixture is bounded RAM; the Small controls are real local files.
That proves owned process recovery, not remote disk/AWS durability. Fifteen current-
immutable-binary persistent S3/monolith scenarios also pass, with exact four-event/
finding identities, eight unchanged remote objects and all12 children reaped.
Evidence: `target/goal-execution-20261007/RETENTION/reclamation-validation-final/validation.json`,
`reclamation-review.json`, `reclamation-focused-5.log`,
`reclamation-native-headers-6.log`, `reclamation-server-simulation/report.json`
and `reclamation-candidate/binary.json`.

Retained failed attempts include compile corrections, a fresh-owner high-water
metric assertion and fixture Clippy collapse. Two review mediums were fixed:
listing absence was replaced with exact-version NotFound, and duplicate integrity
metadata is rejected. No failed attempt is promoted. Actual S3 version/conditional
semantics, IAM/KMS/Object Lock/TLS, remote native CI/kind, shared fencing/custody,
current image and release qualification stay open. Next: representative bounded
partition/cache/query measurements inside the same frozen RETENTION item.

## RETENTION logical query-retirement horizon — 2026-10-08

RETENTION remains in_progress. A trusted stopped host supplies a fresh exclusive,
stream-bound WAL checkpoint. Only complete committed batches wholly before the
query cutoff retire, as a contiguous prefix. Mixed retained/expired batches stop
advancement; unknown-age orphans remain held. A supported `drop_oldest` checkpoint
may exceed store high-water; the authenticated anchor must stay at/below it.
No HTTP producer retirement/deletion path is added.

Source state retains the actual Small owner through stopped publisher handles
and surviving physical readers, independently of successor cache configuration.
Actual paused-read regressions block successors with no cache or a different
cache directory after explicit shutdown. Retained snapshots also fence successors.
Owners must drop stopped handles before reopening. Recovery reads both current
and pending retirement controls without mutation, authenticates exact committed
anchors/whole prefixes/inventory, then promotes a complete pending record.
Forged candidate rejection preserves both byte arrays. Retired data may be absent;
missing live data fails closed, while manifests retain authentication history.
Replay at/below the retired floor is rejected. Server startup rejects a WAL
checkpoint below that floor before readiness/admission.

Seven parent retirement regressions, actual child SIGKILL at temporary-sync,
rename and directory-sync milestones, strict default658/all-feature703 (storage
91/default,100/S3; eight helpers ignored standalone), formatting, default/all-feature
Clippy, all-feature build, workspace13 and focused source review pass. Fifteen
current immutable-binary S3/monolith scenarios pass with all12 children reaped.
The extended simulation uses an explicitly synthetic chain-bound retirement
control and genuine synced WAL admissions captured at the base crash milestones.
It proves the old frontier checks accept a rollback without retirement, then the
retired-floor guard rejects the same restore. Exact canonical finding maps match
through retirement, negative-control replay and consistent restoration; all eight
remote objects remain unchanged. CI runs this simulation on both native runners.
Evidence: `target/goal-execution-20261007/RETENTION/retirement-validation-final/validation.json`,
`retirement-review.json`, `retirement-focused-5.log`,
`retirement-server-simulation-final/report.json` and `retirement-candidate/binary.json`.

Retained failed attempts include the initial large-response Clippy warning,
sandbox socket denial, an existing S3 reopen test retaining its stopped handle,
and the first simulation's reclaimed-WAL negative control. The corrections are
bounded response boxing, authorized loopback execution, explicit handle drop,
and genuine retained admission witnesses. No failed attempt is counted as passing.
No remote deletion, private-original custody, fresh image, cloud/native/HA or
release qualification follows. Next: exact conditional query reclamation and
representative bounded query measurements inside the same frozen RETENTION item.

## RETENTION stopped derived-cache maintenance — 2026-10-08

RETENTION stays in_progress. Stopped maintenance requires an existing exact
stream/backend binding, existing lock and exclusive cache ownership. Full finite
layout/control checks precede derived unlink; temporary/head/genesis/unknown
controls are rejected unchanged. Each unlink and completion sync precede success.
No remote query object, original or control is deleted. A partial failure leaves
rebuildable derived copies and requires ownership/layout revalidation on retry.

Source state retains the cache owner beyond explicit publisher shutdown, through
actual physical query jobs. An actual red/green test reproduces pruning during a
surviving read when that lease is disabled. Review also reproduced temporary
binding deletion by general owner recovery; strict maintenance preflight fixes
it, with preservation regressions. Actual child SIGKILL after the first synced
unlink, non-root unlink denial, cancellation, foreign/symlink/hardlink rejection,
corrupt-copy rebuild and quota recovery pass. Existing control and synthetic
protected-original bytes remain unchanged. Hosts drop stopped source/query
handles before maintenance or reopening a cache owner.

Strict formatting, default/all-feature Clippy, all-feature build, workspace guard
and default651/all-feature696 pass (storage84/default,93/S3; seven parent helpers
ignored standalone). Focused storage/query127 and independent source review pass.
The current immutable local server binary also passes all11 persistent S3/monolith
scenarios, preserving four canonical events/findings through both crash stages.
Evidence: `target/goal-execution-20261007/RETENTION/cache-validation/validation.json`,
`cache-review.json`, `cache-broad-focused-2.log`, `cache-owner-red.log`,
`cache-control-red.log` and `cache-server-simulation-final/report.json`.

The initial simulator invocation raced the default Cargo test binary rebuild and
correctly failed unsupported S3 configuration. Its failed report is retained;
sequential all-feature build and immutable candidate copying resolved invocation
identity, with no source/runtime failure inferred. Source and binary hashes are
retained in `cache-candidate/binary.json`. No fresh image, cloud/native ARM64/EKS,
remote CI, HA/custody or release qualification follows. Next: synced query
retirement/reclamation and bounded query measurements inside RETENTION.

## RETENTION policy and advisory reachability — 2026-10-08

RETENTION is in_progress. Explicit version1 raw/query/index policies validate
replay, evidence-reference and reader horizons without enabling default retention.
An authenticated committed snapshot yields a bounded read-only exact-reference
report. Expired query partitions require a separate retirement commit; incomplete
WAL checkpoints and unknown-age orphans remain blocked. No age report grants
object deletion, custody, owner fencing or checkpoint authority.

Three new regressions use actual publication/Parquet and cover conflicting
horizons, namespace/pin/duplicate bounds, original cancellation, clock overflow,
empty-report budgets and output limits. Review corrected header/pre-insert budget
checks and dedup lifetime; the actual regression passes. Strict default644/
all-feature689 (storage79/default,88/S3; six parent helpers ignored standalone)
pass formatting, both Clippy gates, all-feature build, workspace tests and the
workspace guard. Evidence:
`target/goal-execution-20261007/RETENTION/policy-validation/validation.json`
and `policy-review.json`; earlier compilation/review correction logs are retained.

The parent remains unfinished for synced query retirement/reclamation, stopped
cache pruning and rebuild, simulation and query measurements. Protected originals
are unaffected. No new image, AWS/TLS/native/remoteCI/HA or release gate closes.
Next: bounded exclusively owned cache pruning within RETENTION.

## S3-QUERY monolith and persistent simulation — 2026-10-08

S3-QUERY is passed_simulated. Optional `s3-query` backend selection stays inside
`signal-server`; default local storage and unsupported/configuration failure
behavior are preserved. Startup authenticates committed object state before the
existing WAL frontier check. Busy query/append contention is distinct from durable
quota: only Busy retries under the original batch deadline, and no unfinished
batch checkpoints. Queries drain before source release; failed drain/drop retains
the source through physical query jobs. The actual stalled-read red/green regression
and source review are retained.

Strict workspace acceptance passes default641/all-feature686 (storage76/default,
85/S3; six parent-invoked helpers ignored standalone). Final evidence:
`target/goal-execution-20261007/S3-QUERY/server-backend-validation-corrected/validation.json`
and `server-backend-review.json`. Earlier quota-fixture failures used an undersized
50ms physical-inventory deadline; corrected quota checks allow5s while contention
keeps its50ms original deadline. Superseded logs are preserved.

The real monolith and disk-backed bounded loopback S3 simulator pass11 scenarios:
committed search/findings/pruning, denied/corrupt/malformed/oversized/throttled/
unavailable reads, stopped cache deletion/rebuild, actual source/server SIGKILL
after unreferenced data publication, and a second crash after synced manifest but
before reply/local head. WAL checkpoints stay behind unfinished effects; recovery
preserves four exact canonical events/findings with four manifests/eight objects,
no duplicate query rows or altered prior events. Six helper regressions verify
hard output caps, creation interruption/evidence failure, SIGTERM, both-child
cleanup and failed-report nonzero. Evidence:
`target/goal-execution-20261007/S3-QUERY/server-simulation-final-reviewed/report.json`,
`server-simulation-checks/` and `server-simulation-review.json`.

CI runs these helper/process gates through its existing bounded wrapper on both
native architectures. Docker builds explicitly include `s3-query`; this source
change requires a fresh image/campaign. Actionlint passes locally. No remote CI
execution, fresh image, actual TLS/AWS/IAM/KMS/Object Lock, native ARM64/EKS,
shared HA, custody/completeness or release qualification is implied. Standard
shared fencing remains a later item. Next: RETENTION in the frozen ledger.

## Bounded committed object queries — 2026-10-08

Eight actual Parquet/DataFusion object-query regressions and three cache tests pass;
storage76/default and85/S3, default638/all-feature681 strict workspace gates and
focused source review pass. The generic `QueryFileSource` retains the existing
local constructor and URL filters. Committed UTC selection checks file/decoded
budgets before data GET, authenticates pinned bytes/schema, and materializes
immutable derived copies in a bounded, exclusively owned Small cache. Nested
attributes, account/source filters, pruning, cache deletion/rebuild, quota,
denial/corruption, cancellation and retained physical ownership are exercised.
No eviction or source-original deletion is authorized by the query cache.

A reproduced high review finding showed shutdown returning while remote selection
remained admitted. Shutdown now drains all admitted query lifetimes before local
I/O; the original deadline and cancellation remain binding. Cancelled publisher
commands retain admission until physical child workers actually drain. Red/green
logs and source hashes are retained. Final evidence:
`target/goal-execution-20261007/S3-QUERY/query-materialization-validation-resumed/validation.json`
and `query-materialization-review.json`. Completed unchanged-source formatting,
Clippy and build checks were reused after a session interruption; only unfinished
workspace tests and the workspace check were resumed, with interrupted logs kept.

S3-QUERY remains in_progress. Next: monolithic server backend/configuration,
query-before-source shutdown and bounded append/query contention, then persistent
source/server outage, SIGKILL and replay simulation. This slice provides no server
process, AWS/TLS/runtime/custody/HA/native ARM64 or release qualification.

## Selected bounded S3 adapter — 2026-10-08

The optional `signal-storage/s3` adapter passes nine native HTTP fixture tests
and one versionless-inventory guard regression. Storage73/default and82/S3,
default627/all-feature670 strict workspace gates and focused review pass. Six
parent-invoked helpers remain ignored standalone. Evidence:
`target/goal-execution-20261007/S3-QUERY/s3-adapter-validation-accepted/validation.json`
and `s3-adapter-review.json` in the same task directory. Failed earlier logs,
including socket-denied and fixture/protocol/expectation failures, are retained.
Accepted tests had authorized loopback access.

The original-context physical worker drives bounded HTTP/1 without a spawned
driver, pool, proxy, redirects or implicit retries. Explicit host credentials have
a redacted provider. Conditional PUT/pinned GET, pagination, actual IPv4/IPv6,
malformed/oversized headers/XML/chunks, denial/throttling/redirect and cancellation/
socket closure pass. Two native-wire commits, reopen and smaller-prefix exact
replay pass with versionless S3 listings. Matching nonempty ETag/length detects
current-object drift; any supplied version must match and exact reads retain
and verify the pinned version. Review corrected credential Debug/IP handling/
fixture ownership; the native fixture exposed absolute-form requests, corrected
to origin-form with signed Host/path/query preserved.

This is finite in-process wire simulation, not persistent process durability,
AWS/TLS runtime/IAM/KMS/Object Lock, shared HA, custody or production throughput.
S3-QUERY stays in_progress. Next: bounded committed query/materialization,
monolithic server wiring and persistent simulator outage/crash/replay. No release,
push, publication or external gate is closed.

## Small object publication and committed recovery — 2026-10-08

S3-QUERY remains in_progress. Synced stream/backend-bound initialization and exact
head controls, conditional immutable publication/readback, authenticated manifest
predecessors, bounded unique uncertain-tail recovery and actual-content replay now
pass storage72/default626/all-feature660 strict workspace gates and focused review.
Thirteen publication and four new head/genesis regressions cover split replay,
initial lost-response recovery, cancellation/late replies, conflicting content,
missing data/identity drift, unknown branches and exact-capacity orphan reuse.
Six existing subprocess helpers remain parent-invoked, not standalone proof. See
[object query contract](39-object-query-contract.md) and
`target/goal-execution-20261007/S3-QUERY/publication-validation-accepted/validation.json`.
The first workspace run was denied local sockets; its failed log is retained,
and the accepted campaign had authorized loopback/socket access.

Review corrected exact submitted receipt ranges, historical pinned identity
checks, and duplicate orphan quota reservation. Metadata snapshots are not event
results; trusted immutable backend identities and authenticated selected reads
remain required. The finite in-process fault fixture and owned control reopen
prove these mechanisms locally, not an actual process crash, durable S3 backend,
query/cache/server integration, source custody, Standard fencing or AWS/ARM64/HA.
Next: selected bounded S3 adapter and actual query/cache/server simulation inside
the same frozen item. No release, push or publication was performed.

## Bounded object I/O / Small ownership — 2026-10-08

S3-QUERY remains in_progress. Conditional Create, pinned exact readback, finite
discovery/listing, retained reply/physical work leases and a stream/backend-bound
Small control owner now pass storage55/default609/all-feature643 strict gates and
focused review. Six subprocess helpers keep parent-invoked scope. Nine I/O/owner
and eight codec regressions include actual late-reply deadline failure/fix,
non-cancellable ownership retention, inherited descriptor unlock, recovered synced
controls and unknown/mismatching control refusal. See
[object query contract](39-object-query-contract.md) and
`target/goal-execution-20261007/S3-QUERY/io-validation-late-final/validation.json`.
This qualifies no actual S3 durability/publication/query/custody/HA/AWS/ARM64 gate.
Next: actual conditional publication and committed recovery, then selected adapter,
query/cache and monolithic server simulation; continue the frozen parent.

## Public OSS CI preparation — 2026-10-08

Public revision66a9ce7 has partial native GitHub ARM64 Rust evidence; the complete
remote run failed, so container/kind/load/SBOM and EXT-CI/EXT-ARM64 stay open.
CI now separates Rust/native jobs, retains finite failure diagnostics and prepares
unsigned native candidates only after qualification. See
[OSS CI and cloud qualification](40-oss-ci-and-cloud-qualification.md) and retained
`target/goal-execution-20261007/GITHUB-OSS/` metadata/local tooling evidence.
Three workflow files pass actionlint1.7.12; 18 native-helper, two CI-wrapper and
five candidate-evidence regressions pass. Review's two medium findings are fixed
and accepted: candidate success follows checksums, and failed packaging retains
its small diagnostic files. This is tooling acceptance, not an executed native
candidate or completion of remote qualification. No Rust acceptance is inferred
for the separate unstaged object-I/O/owner work.
The frozen inventory remains unchanged; S3-QUERY implementation continues.

## Current state — 2026-10-08

Phases 0–7 are implemented and locally verified, including rules, durable
findings, server wiring, the Compose demonstration, edge collection, generic
extension SDK and separate external overlay proof. The full 7-B gates passed on
Linux AMD64. Phase 8 packaging is also implemented and verified locally on
AMD64. Phase 10 hardening campaigns, measured load profiles, an actual storage
create-failure/replay test and release documentation now have local evidence;
final independent review passed with no unresolved findings. The offline restore
addition and native image-to-parser/pipeline runner also passed independent
review. The prior workspace gate had 228 passing tests; the current settled
default workspace gate has 659; the all-feature gate has 710 (14 independent-custody and two source-ticket fence regressions, 12 native byte-proof and nine signed proof-source regressions, 11 regional CloudTrail observer regressions, 13 bounded observer regressions, 11 signed AWS transport regressions and one additional signed-source/real-server test), including seven bounded collector-driver tests and four source/real-server delivery simulations, four HTTP publisher tests, eight retained-batch publication tests, eight capture tests and one inherited-description lock test, seven direct notification discovery tests, seven whole-object preparation tests, seven gzip/object reader tests, 11 retirement/replacement tests, 14 source-ACK tests, 12 owner-handover/reconciled-open tests, 12 verified-prefix progress tests, 21 initial source-receipt store tests, 16 CloudTrail parser/preparation tests, three native-to-finding
profile tests, 24 SDK SourceCoverage tests, 106 local-store/intake/correction/
payload/identity-pruning/scan tests and seven UI/exact-ID regressions. The current UI revision's AMD64 image has container, Helm, supply-chain and native
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

## S3-QUERY bounded Parquet codec — 2026-10-08

Seven new regressions qualify actual Parquet preparation/inspection on one bounded
CPU worker. Borrowed typed input keeps caller spare capacity/deep invalid values
outside the worker; finite wire copies enter only after admission. Results and
physical work retain the sole permit through cancellation/timeouts/unpolled replies.
Output capacity, rows/partitions/sequences, exact SHA/metadata, decoded page budget
and raw JSON depth/nodes/bytes are checked before relevant decoding/allocation.
Every rejected public call is counted once. Storage45, default599/all-feature633
workspace tests, fmt, strict Clippy, ownership guard and independent focused review
pass. The decoded-preflight and owned-input review findings were corrected; early
compile/footer/Clippy logs remain beside accepted evidence:
`target/goal-execution-20261007/S3-QUERY/codec-validation-accepted/validation.json`
and `codec-review.json` there. No version changed; bytes uses an existing dependency.

This CPU-only seam performs no disk/network publication or query commitment.
The conditional-publication/recovery substep and S3-QUERY parent remain in_progress;
continue immutable create/readback, committed discovery and query/cache/server
simulation, then RETENTION. Real AWS/HA/custody/release gates remain open.

## S3-QUERY bounded manifest slice — 2026-10-08

The frozen object-query task is in_progress. Its first contract slice now passes:
strict versioned manifests, exact version/conditional ETag plus SHA256 references,
separate query namespace, predecessor/range/row/object/decoded-byte caps and
exclusive UTC-hour pruning. Four regressions and default592/all-feature626
workspace tests pass with fmt, strict workspace Clippy, ownership guard and
focused source review. No package version changed; ring adds only an existing
workspace dependency edge. Evidence:
`target/goal-execution-20261007/S3-QUERY/manifest-validation-final/validation.json`
and `manifest-review.json` there. The initial sandbox-denied local socket/pipe run
is retained separately; the scoped local-test run passes.

This validates shape/content binding only. Conditional object publication,
actual predecessor/Parquet validation, committed discovery/recovery, query/cache
and monolithic server simulation remain unfinished in the existing S3-QUERY item.
See [object-query contract](39-object-query-contract.md). Continue that item;
no new frozen scope, service split, custody or AWS/HA qualification follows.

## Independent protected route composition — 2026-10-08

EVIDENCE is now **passed_simulated** within the frozen local scope. Distinct
provider/archive/verifier/current-owner endpoints retain exact originals, native
proofs, versions, complete receipts and immutable retention while the actual
observability server is unavailable. Its source ACK is refused before required
server202 M2. Recovery publishes the exact prepared event, verifies the admission
prefix and preserves it through an actual server SIGKILL/restart.

The compound process gate also loses an archive HTTP reply after the actual
physical201 commit, then checks exact manifest replay. A separately owned source
queue commits deletion and is SIGKILLed before replying: the SDK records Uncertain,
reconciled reopen preserves the frozen receipt, restart rejects the stale handle,
fresh redelivery receives a new handle and each ACK phase obtains fresh native-
required independently current custody. Both source handles stay outside the
receipt spool. Source deletion confirms a lease operation, not original deletion
or proof that no duplicate can be redelivered.

Private acceptance:77 passed/zero failed/six parent-managed ignored helpers, fmt,
strict Clippy/build, seven byte-identical native fixtures; the exact parent gate
passes1 compound test. The actual overlay crash/SIGTERM gate and13-package public/
private guard pass. Independent review has no remaining blocker/high. The parent
pins source, fixtures, path dependencies and server bytes, caps output/deadlines,
and kills its owned process group on failure. Evidence:
`target/goal-execution-20261007/EVIDENCE/protected-composition-validation/validation.json`,
`protected-composition-process-qualified/validation.json`, and
`protected-composition-review.json` there.

Public Rust remains at accepted588/default and622/all-feature. Earlier native
archive/supervisor gates retain four actual SIGKILL boundaries; this composition
adds actual server and source crashes, not a new archive-process crash claim.
Local owner grants certify neither distributed/shared-runtime fencing nor
consistent rollback of both authorities. Source configuration/category coverage
and completeness stay Unknown; proof age is not renewed. AWS/IAM/Object Lock/KMS,
TLS/account isolation, ARM64/EKS/live tenants/remote CI/released dependencies and
publication remain unqualified. Continue S3-QUERY; no service split or release
approval follows this local simulation.

## Authenticated protected role HTTP — 2026-10-08

The private local stand-in now serves actual retained archive, provider, native
verifier and independent current-owner routes under distinct credentials. Native
requests select only a bounded capture ID; the verifier fetches host-selected
provider bytes with exact version/owner checks. Keys, scope, profile definition
and retention remain host configuration. Owner mutation needs its own credential;
the verifier holds only read-current permission. Archive201 means protected
retention, independently of server202 M2.

Every endpoint permits eight finite-lifetime connections and one active body/result.
Admission remains held through connection flush/exit, including stalled readers;
timeout/shutdown drops cancel work without refunding physical archive leases.
Five actual loopback regressions cover role/method/query/body denial, malformed
selectors, wrong/duplicate object metadata, current-head custody, immutable replay,
provider/owner outages, throttling, cancellation, slow responses and connection caps.

Private acceptance passes77 tests/zero failures/four parent-invoked helpers,
fmt, strict Clippy, build, seven byte-identical independently generated fixtures,
actual overlay/server SIGKILL/SIGTERM and the workspace ownership guard. The
focused review's response-memory lifetime finding is corrected and accepted.
Evidence: `target/goal-execution-20261007/EVIDENCE/protected-http-validation/validation.json`
and `protected-http-review.json` there. Public Rust remains unchanged at588/622.
EVIDENCE stays in_progress for protected observability-outage/source-ACK/M2 and
crash/replay composition. Loopback permissions certify no TLS/IAM/account isolation
or live source completeness; no external release gate is closed.

## Native original/receipt linkage and conservative coverage — 2026-10-08

The native-required private path now requires fresh supervisor confirmation,
revalidates retained native history, and matches the receipt's exact source bucket,
key, version, configured owner and compressed hash. Native proof retention must
cover receipt retention. The source proof is ephemeral: authority revocation and
its original operation deadline remain effective before/after custody signing.

SDK-valid coverage is immutable and Unknown overall. It records verified native
byte integrity while configuration/scope/continuity and gap completeness stay
unknown. Replays/reopen preserve original verification time and exact bytes;
expiry is bounded by profile age and proof retention. A signed nonempty digest and
complete synthetic root-login object now exercise this path. Wrong versions/keys,
altered compressed bytes, missing references, unconfirmed heads, short retention,
revocation and deadline renewal attempts are denied.

Full private acceptance passes72 tests/zero failures/four parent-invoked helpers,
fmt, strict Clippy, build, independent byte-identical seven-file regeneration and
the actual overlay/server SIGKILL/SIGTERM gate. Focused source review is accepted.
Public Rust is unchanged from accepted588/622. Evidence lives in
`target/goal-execution-20261007/EVIDENCE/native-link-validation/validation.json`,
`native-link-review.json` and `native-link-handoff.json` there.

The existing native validation/continuity substep is passed_local; parent EVIDENCE
stays in_progress for authenticated provider/role HTTP and protected source-ACK/M2
outage/replay composition. A signature/reference constructor or matching profile
name alone authenticates no producer, provider capture or profile definition.
No real-environment release gate is closed.

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

## Independent source coverage runtime — 2026-10-08

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

## Scoped monolith coverage integration — 2026-10-08

The existing server now opens optional bounded coverage history under explicit
startup configuration. A separate bootstrap command creates a new identity and
exits; missing/existing/locked history is never silently recreated. Observer
tokens authenticate unique exact bindings, independently of the event API token.
Authenticated original-byte intake/replay/corrections, exact retained-profile
reads, bounded frontier scans and aggregate resource metrics stay in the monolith.
Every response reports current health unknown: receipt/API success, replay and
scan exhaustion cannot promote source supervision.

Eleven API/configuration regressions and one real server process test cover
scope denial, strict input/body/output/resource limits, original bytes/pins,
retired-profile replay, finite paging/frontier, quota, cancellation, explicit
bootstrap and actual stalled-body deadline/SIGKILL/restart/credential rotation.
Default 535/all-feature 558 tests, zero failures, five existing ignored helpers,
strict format/lint/package gates and focused independent source review pass.
Evidence: `target/goal-execution-20261007/COVERAGE-OBSERVERS/server-integration-validation.json`.
No new locked package/version or service is added; the server now consumes the
existing coverage crate. Existing package/image/SBOM reports remain historical.
COVERAGE-OBSERVERS stays in progress for independent checkpoint/gap/quiet/degraded
runtime simulation; native continuity/digest proofs were unimplemented and
unqualified at that acceptance. See the later EVIDENCE native mechanism acceptance
above; independent durable proof integration stays pending. Scoped credential configuration is startup-pinned; live OIDC/RBAC,
secure transport and security auditing remain their separate pending ledger items.

## Durable observer/history bridge — 2026-10-08

Independent observers can now commit through the existing bounded coverage
history before adopting new cached evidence or healthy status. Fresh application
full-binding authorization, the exact original trusted profile and global
retained record identity are checked. Exact replay preserves prior health;
retired-profile replay cannot reinterpret the original receipt. Quota, denial,
malformed input, cancellation and uncertain outcomes retain previous evidence.
Dropping a pending poll leaves health unknown. No worker, queue, service,
credential discovery or wire-format change is added by this bridge.

Four SDK and ten physical SQLite regressions cover replay, older record identity,
profile retirement/alias rejection, permission revocation, quota, restart and
pending-authority cancellation/drop. Default 523/all-feature 546 tests, zero
failures, five existing ignored helpers, strict Clippy/fmt/package guard and
focused independent review pass. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/history-bridge-validation.json`.
COVERAGE-OBSERVERS remains in progress for scoped server configuration/API,
lifecycle/metrics and independent checkpoint/gap/degraded-silence simulation.
Historical package/image/candidate reports retain their original source bindings.

## Regional CloudTrail configuration observation — 2026-10-08

The optional AWS feature supplies a bounded independent regional configuration
probe: three actual signed JSON 1.1 reads for trail settings, logging status and
selectors, using fresh application credentials and the existing private signer
transport. Exact trusted trail/region/stream/observer binding precedes I/O. Actual
64 KiB reply caps, strict JSON, finite cancellation and static diagnostics hold.
Settings/selector checks preserve unknown continuity, digest authenticity,
checkpoint, data arrival and complete gap inventory; total coverage is never
verified by this point observation. Company policy/inventory stays outside core.

Eleven native-probe regressions cover signed wire/credential rotation, disabled
logging/configuration drift, selector defaults/read-write union/unsupported
filters, foreign scope, malformed native input, denial/throttling/outage,
actual declared/chunked caps and cancellation/deadline. Independent review
reproduced and corrected malformed optional selector fields. Eleven existing
S3/SQS wire regressions also pass after the behavior-preserving transport reuse.
A required workspace run exposed a pre-existing caller-drop query test race;
its test now waits finitely for actual physical I/O completion after asserting
immediate query-admission release. Production resource guards are unchanged.

Current gates pass: default 509/all-feature 532 tests, zero failures, strict
Clippy/fmt and 13-package boundary check. The earlier failing evidence is retained.
Evidence: `target/goal-execution-20261007/COVERAGE-OBSERVERS/native-probe-validation.json`.
COVERAGE-OBSERVERS remains in progress: complete independent checkpoint/gap
simulation and durable history/server integration with visible degraded silence.
Real AWS permissions/TLS, organization membership, continuity and native source
proofs are unqualified. Historical package/image/candidate bindings are unchanged.

## Bounded source observer state — 2026-10-08

COVERAGE-OBSERVERS remains in progress. Its first slice holds one bounded raw
SourceCoverage v1 report and validated interpretation per configured observer,
with exact full binding/profile/observer checks and independent probe health.
Dropped polls become unknown; failures retain immutable evidence and mark health
unhealthy. Later arrivals cannot renew verification, checkpoint, interval or
expiry. Reusing the retained record ID requires exact bytes; wider identity
history enforcement remains the physical store's responsibility.

Nine regressions pass, including denied/outage, scope mismatch, stale/future
verification, cancellation/deadline, dropped polling and immutable claim/identity
cases. Independent review resolved the reproduced identity conflict and added a
final context check after validation. Default 509 and all-feature 521 workspace
tests pass with zero failures, fmt, strict default/all-feature Clippy and the
13-package guard. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/observer-validation.json`.
See [the bounded observer contract](36-source-observers.md). Independent native
configuration/continuity probes, physical history/server integration and visible
degraded-silence runtime simulation remain authorized local work. This generic
seam does not authenticate native proofs or qualify any live source environment.

## Signed AWS source transport — 2026-10-08

The optional `aws-source` SDK feature now provides bounded actual SQS JSON
receive/delete and exact-version S3 GET using Amazon's SigV4 signer. The
application supplies fresh credentials, trusted queue/endpoints and current
binding; no environment/IMDS discovery, retry loop or new service is introduced.
HTTPS is required except explicit numeric-loopback HTTP test opt-in. Actual
response caps, finite context, no redirects/decompression/proxy and static errors
hold malformed, denied, expired, throttled or uncertain operations. Delete
checks the store-issued ticket's full binding before credentials/network.

Focused review resolved URL-normalized keys/buckets and a reserved-character
signing defect. The strengthened independent wire witness fails before the S3
encoding correction and passes afterward; it also matches AWS's published GET
signature vector. Exact key/version byte encoding preserves repeated slashes.
The local signed-source/real-server test exercises throttling, rotating
credentials, failed-delete durable intent, reopen/fresh redelivery without
republishing and crash/restart with two durable rows/one finding/checkpoint two.

All acceptance passes: default 500 and all-feature 512 tests, zero failures,
fmt, strict default/all-feature all-target Clippy, 13-package guard and focused
independent review. CI now checks optional features; remote CI is not executed.
Twenty-two optional packages are added without replacing locked versions. The
minimum is 1.94.1, matching the already pinned compiler, with no toolchain change.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/signed-transport-validation.json`.
AWS-DELIVERY is `passed_simulated`; continue COVERAGE-OBSERVERS. Real AWS/IAM/TLS,
source proofs/completeness and stronger custody remain separate. Historical
images, SBOMs and candidates keep their original bindings until final refresh.

## Bounded source delivery collector driver — 2026-10-08

`collect_delivery` receives one bounded message/reference, refreshes the complete
trusted binding at side-effect seams, captures exact bytes, physically prepares
M1 and publishes one retained batch. It waits for the full verified M2 prefix
before the receipt store can issue a process-local ACK ticket. Lost intent is
recovered uncertain under fresh application reconciliation; delete precedes a
fresh authorized finish. Handles remain ephemeral. Source credentials, current
history authentication, pin/retention policy, retry cadence and aggregate work
budget belong to the application; the driver adds no loop/queue/worker/service.
The read-only ACK-state getter reports validated control without asserting that
provider redelivery is impossible.

Review identified a same-binding receipt-substitution race across policy awaits.
A deterministic public retirement/replacement regression fails before correction.
Publication now checks exact store-issued receipt identity inside the replay used
to construct the request; ACK replay checks it again. Physical control CAS fences
later replacement. The corrected two-seam test prevents wrong publication/ACK and
preserves the replacement's prefix/state; original payload is dropped before ACK
I/O. Review has no remaining blocker/high.

Seven SDK tests plus one new actual-source/real-server driver test pass. The latter
settles uncertain deletion, reopens against the live fixture coordinator, accepts
fresh redelivery without redispatch and preserves two rows/one finding/checkpoint
two through server crash/restart. All acceptance passes: 500 tests, zero failures,
fmt, strict all-target Clippy and 13-package guard. Evidence:
`target/goal-execution-20261007/AWS-DELIVERY/driver-validation.json`.
At that acceptance the signed source adapter was next; its local acceptance is
recorded above. Simulated operations do not qualify actual AWS/IAM/TLS/provider
behavior or independent custody.
Historical image/SBOM/candidate bindings remain unchanged.

## Source-to-real-server delivery simulation — 2026-10-08

Three reproducible integration tests pass using a bounded loopback S3/SQS subset
and the actual `signal-server` process. Exact compressed originals become M1;
a deliberately lost valid admission reply preserves the prepared suffix. A real
Parquet create_new failure leaves checkpoint zero. Restart replays WAL, then
exact duplicate publication produces three stored rows with two event identities,
one deterministic root finding and checkpoint three. A further crash/restart
preserves those rows. Unauthorized ingest and source throttling/denial/missing/
outage/version mismatch/revoked scope/malformed gzip retain work.

Visibility expiry supplies a new ephemeral handle. Durable ACK intent precedes
delete; lost ticket/result is recovered uncertain before fresh redelivery.
Post-confirmation duplicate sends no additional event. The negative protocol
probe shows old-handle HTTP 200 can leave a message pending. No queue handles
appear in receipt files. Source operations are emulated, visibility uses a
logical clock, and the source adapter buffers one capped object; none qualifies
SigV4, TLS, IAM, real AWS or independent custody. Production polling is next.

Review's timeout-cleanup observation is resolved by aborting/awaiting the owned
source task. The workspace's existing 32 MiB structural gzip assertion hit a
short-context failure under parallel debug tests; its finite budget now matches
the adjacent 30-second ceiling case. Production and independent timeout/cancel
checks remain unchanged; failed evidence is retained. All acceptance passes:
492 tests, zero failures, fmt, strict all-target Clippy and 13-package guard;
independent review has no blocker/high. Evidence:
`target/goal-execution-20261007/AWS-DELIVERY/delivery-simulation-validation.json`.
Continue immediately with the bounded collector driver. AWS-DELIVERY remains
in_progress. Historical image/SBOM/candidate bindings do not transfer.

## Configured HTTP receipt publisher — 2026-10-08

The HTTP transport substep passes local acceptance: four actual TCP regressions,
489 workspace tests, formatting, strict all-target Clippy and the 13-package guard.
Authenticated requests preserve retained batch bytes; declared and incremental
response sizes are capped at 64 KiB. Redirects and automatic decompression are
disabled. Cancellation/deadline cover request and response reads; diagnostics do
not expose endpoint credentials or payloads. Endpoint/header configuration is
validated before use. Independent review has no blocker/high. The SDK adds only
an edge to existing locked reqwest 0.12.28, with no package version change.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/http-publisher-validation.json`.
Continue immediately with the complete source-to-M2/redelivery/ACK simulation.
AWS-DELIVERY remains in_progress; provider IAM, mTLS, real AWS and stronger custody
remain separate gates. Existing image/SBOM/candidate bindings are historical.

## Retained-byte bounded batch publication — 2026-10-08

AWS-DELIVERY's publication substep passes local acceptance. The batch envelope
copies exact retained event payloads without reserialization. Count/body-byte
selection includes envelope and commas before allocation. One invocation sends
one bounded batch using fresh trusted binding. Shared response verification
supplies retry classification; the physical store independently checks actual
reply/IDs and exact prior control before atomically advancing a verified prefix.
No publisher result grants source ACK or proves completed processing.

Eight tests execute exact payload preservation, count/byte/config limits, partial
admission/reopen/completion, uncertain/denied/reduce-batch zero progress, malformed/
oversized/duplicate/forged replies, stale scope/deadline/live cancel, empty/quarantine
suffix with ACK denial, and progress changed during an outstanding request. Default
limits match current ingest (1 MiB/1,000); external transport still owns endpoint
authentication, streamed-response bounds and I/O cancellation. Review has no
blocker/high; all workspace gates pass: 485 tests, zero failures, 13-package guard.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/publisher-validation.json`.
Continue with reproducible local network/source queue/redelivery/ACK simulation;
AWS-DELIVERY remains in_progress, actual AWS and stronger custody stay unqualified.

## Exact-version bounded capture and owned preparation — 2026-10-08

AWS-DELIVERY's capture substep passes local acceptance. `CaptureTransport` supplies
an application-authenticated stream with actual response version. `capture_object`
checks fresh full binding before open, response version and bounded headers, then
caps actual bytes at 8 MiB through EOF using finite cancellation/deadline reads.
Typed denied/missing/restore/throttle/outage/read failures retain source work.
`publish_capture` rechecks binding/preflights pins and uses the existing physical
receipt worker for preparation and atomic publication. A retained exact full
scope/bucket/key/version and byte match reuses pinned preparation and progress;
changed bytes fail closed and a distinct object/version cannot evict the slot.

Eight capture tests execute caps/EOF, fresh scope before open/publication, stream
failures and live cancellation, exact replay after reopen with changed supplied
pins, identity conflicts, quarantine/preflight and lost caller/queued cancellation
with physical lock retention. Workspace acceptance exposed an existing lock
lifetime defect during handover: a fork-inherited open description can retain
flock after the worker closes its File. A deterministic alias test fails before
and passes after an acquired-owner explicit unlock guard, including error paths
before Engine construction. Review accepts the correction without weakening
handover tests. Failed and corrected runs remain in evidence.

Formatting, strict workspace Clippy, locked/offline default-parallel tests and
13-package guard pass: 477 tests, zero failures; SDK has 93 passing library tests
and five parent-executed subprocess helpers. Evidence:
`target/goal-execution-20261007/AWS-DELIVERY/capture-validation.json`.
Continue with delivery/replay/queue simulation. Authentication, header bounds and
owned-I/O cancellation remain transport duties; no actual AWS/SigV4/IAM, queue ACK,
stronger custody or source completeness is established by this seam.

## Bounded direct S3 discovery — 2026-10-08

The AWS-DELIVERY direct-discovery substep passes local acceptance. One reference
per message is supported; the 16-reference parsing bound never grants multi-object
completion. Validate all references before return, form-decode keys once, require
non-null versions and exact trusted namespace, support numeric 2.x minor additions
and four ObjectCreated kinds. Test/wrapped/empty/malformed messages keep source
responsibility. Immutable discovery identity/digest does not authorize access;
native bucket ownerIdentity is not a trusted account identifier.

Seven focused tests cover versions/kinds/additions, actual-byte hash and UTF-8/form
keys, malformed late references, unsupported envelopes, scope/version/types,
body/key/depth/node limits, cancel/deadline and static diagnostics. Independent
source review has no blocker/high; all workspace gates pass: 468 tests, zero
failures, 13-package boundary. Evidence:
`target/goal-execution-20261007/AWS-DELIVERY/discovery-validation.json`.
AWS-DELIVERY remains in_progress; continue with bounded exact-version capture and
receipt/replay/delivery simulation. Real AWS gates remain external.

## Whole-object pinned receipt preparation — 2026-10-08

OBJECT-READER is accepted locally. `prepare_receipt` computes original and native
hashes, spans, dispositions and event mappings from actual bytes. Caller-pinned
IDs, full binding, capture/preparation times, normalizer fingerprint and retention
remain immutable. All records are validated before atomic preparation; encoded
wire executes the existing decoder before exposure. Poison objects yield bounded
original-only quarantine, while capture/time/cancellation failures preserve source
responsibility. Replay uses the retained bytes; quarantine ACK remains denied.

Seven new tests cover exact reproducible fixture encoding, malformed-late and
foreign/empty/gzip quarantine, pins and bounds, publication/reopen, observation
precision/offset equivalence and different-instant rejection, record/count limits
and the aggregate 16 MiB payload ceiling. The timestamp correction compares parsed
Event-v1 instants with canonical metadata; it rewrites no event bytes. Independent
source review has no blocker/high. All workspace gates pass: 461 tests, zero
failures, five process helpers run through parent tests; 13-package boundary guard.
Evidence: `target/goal-execution-20261007/OBJECT-READER/validation.json`.

Continue with AWS-DELIVERY discovery/capture/transport simulation. This acceptance
provides no provider credentials, source completeness, independent custody or
real-environment qualification. Previous images/SBOM/candidates keep their old
source bindings until rebuilt in their planned release items.

## Bounded gzip/native-object reader — 2026-10-07

The OBJECT-READER reader substep is accepted locally. `read_object` validates one
8 MiB-bounded gzip member, CRC/ISIZE, no trailing input and at most 32 MiB decoded
bytes. It stores exact native spans, validates every record before exposing a
result, bounds count/record/depth/nodes, and avoids a full-object DOM. Context checks
surround decompression/record parsing. Total depth 16 includes the two envelope
levels. It reuses the lockfile's existing flate2 1.1.10/zlib-rs versions through a
new direct SDK edge; no external package version changed.

Seven tests cover all 41 native fixture records, exact span/hash/escaped text,
invalid/truncated/CRC/trailing/concatenated gzip, malformed later records, duplicate
keys and foreign envelopes, count/depth/nodes/record-byte boundaries, capture/
decoded-bomb caps, cancellation/deadline and the exact 32 MiB decoded ceiling.
Independent read-only review accepts the reader with no blocker/high. Formatting,
strict workspace Clippy, locked/offline workspace tests and the 13-package guard
pass: 454 tests, zero failures. Evidence: `target/goal-execution-20261007/OBJECT-READER/reader-validation.json`.

This is bounded parsing proof. Receipt encoding/quarantine, source capture proof,
credentials, ACK and transport are separate. At reader acceptance, pinned whole-object preparation was next; its later
acceptance is recorded above.
Earlier images/candidates retain their source/dependency bindings.

## Receipt retirement/reclamation and explicit slot replacement — 2026-10-07

RECEIPT-RECOVERY is accepted locally. `retire` checks exact prior/full binding and
fresh independent current authority, confirmed ACK, complete prefix and pinned
elapsed `retain_until`. Both revisions are precomputed before side effects. It
commits intent before removing the local payload, syncs the directory before
completion and retains control. A missing active payload remains corruption;
intent with an absent payload can resume only under fresh checkpoint-gated opening.
Retired state blocks replay/ACK/ordinary publication. Read-only bounded snapshot
inspection supports application history reconciliation without granting permission.
Owner transfer preserves retired state. `publish_next` requires completion/current
authority and a different UUID, retaining old control until the new payload and
atomic initial-control replacement commit. Unknown temp/orphan states fail closed.

Eleven new tests cover retention, prefix/ACK/authority guards, two-revision overflow
preflight, corruption, retained-control/owner recovery, four injected fault stages,
ten retirement and seven replacement process-crash stages, an actual unlink syscall
failure and timeout with physical lock lifetime. Reopen review found actual ACK
preparation-time and positive generation checks; regressions now execute them.
Independent source review accepts the slice with no blocker/high. Formatting,
strict workspace/all-target Clippy, locked/offline workspace tests and the
13-package guard pass: 447 tests, zero failures; five crash helpers execute through
parent tests. Evidence: `target/goal-execution-20261007/RECEIPT-RECOVERY/retirement/`.

This removes local receipt files only. It does not delete S3 originals, authenticate
external checkpoints, qualify stronger custody or recover unknown publication
orphans automatically. Host/power/device/account-loss and external qualification
remain separate. Continue with bounded object reading/preparation, then AWS delivery.
The persistent Goal remains active across this accepted change.

## Durable process-local source ACK control — 2026-10-07

SOURCE-ACK is implemented as a bounded SDK control mechanism. A fresh full-binding,
exact-prior-control and independently current checkpoint authorize every transition.
Explicit process-local selection commits intent before returning an ephemeral ticket;
its handle is never serialized or logged. Finish consumes the receipt/owner/generation/
attempt/delivery-bound ticket with fresh current progress, so intervening admission
updates do not strand a valid intent. Lost tickets/replies recover to uncertain;
redelivery requires a new attempt/current adapter handle and preserves exact preparation.
Both fixed horizons, selected M2, active retirement and all quarantine exclusions
fail closed. Stronger custody is excluded; emitted indeterminate records remain eligible.

Fourteen new tests cover provider response shape, redelivery, exact reopen/payload
preservation, stale binding/checkpoint/ticket, owner fencing, M2 and nanosecond time
limits, corruption, three fault stages, six intent/result process-crash stages,
queue/cancellation and timeout/lost caller with physical lock lifetime. Review found
reopen M2/intent-budget/first-ACK gaps; rechecksummed regressions now enforce them.
Independent follow-up source review accepts the slice with no blocker/high.
Formatting, strict workspace/all-target Clippy, locked/offline workspace tests
and the 13-package boundary guard pass: 436 tests, zero failures. Four ignored
subprocess helpers are exercised by parent tests. Evidence and acceptance logs:
`target/goal-execution-20261007/SOURCE-ACK/`.

This is trusted-adapter response-shape and surviving-local-filesystem evidence.
It does not execute source deletion, prove handle freshness/authenticity, establish
stronger custody or close AWS/ARM64/cloud/release gates. Continue immediately with
RECEIPT-RECOVERY retirement/reclamation, then bounded object reading/delivery.

## Receipt owner handover and checkpoint-gated recovery opening — 2026-10-07

Two bounded RECEIPT-RECOVERY substeps are accepted locally. `transfer_owner`
consumes the old store, checks full binding/exact prior control and an independently
current application checkpoint under its physical lock, advances owner generation/
control revision exactly once, preserves immutable bytes and prefix, resets the
attempt, commits control and terminates the worker. Success waits for physical
exit; timeout or lost reply retains the lock until actual exit. New owner reopen
fences the old identity. `open_reconciled` requires the current trusted checkpoint
before exposing a store; older consistent, foreign, empty or missing state is
denied. Ordinary `open` retains its limited process-local assurance.

Twelve new tests cover before/partial/completed sends, old/new owner replay and
continued admission, full-scope/stale snapshot/current-witness denial, successor/
generation bounds, three fault and three process-crash milestones, timeout/drop/
cancellation and physical lock lifetime, plus checkpoint-gated boot. Independent
source review accepted both substeps with no blocker/high. Required formatting,
strict Clippy, locked/offline workspace and 13-package boundary checks pass: 422
Rust tests, zero failures. Three ignored helpers are executed by parent crash
tests. Evidence is `target/goal-execution-20261007/RECEIPT-RECOVERY/`.

The trusted application authenticates and reconciles the external checkpoint;
these constructors do not turn a copied checksum into authority. No source ACK,
retirement/reclamation, remote fencing or stronger custody is implemented here.
The finite ledger now places SOURCE-ACK control before retirement because the
frozen reclaim guard requires confirmed ACK; no capability was added. Continue
SOURCE-ACK, then finish RECEIPT-RECOVERY before object delivery. The Goal stays
active; image/candidate/native/cloud/publication boundaries remain unchanged.

## Persistent Goal and verified source-receipt progress — 2026-10-07

The owner started a persistent Goal for finite MVP/post-MVP/local release work.
The [52-item ledger](31-execution-ledger.md) reconciles current product/phase/routing
contracts, dependencies, acceptance and evidence. Three baseline items and
RECEIPT-PROGRESS have local acceptance; six external qualification/publication
items remain separate. Current source review confirmed the next task rather than
repeating accepted UI/pruning work.

The SDK exposes immutable suffix replay and exact store-issued progress tokens.
Actual bounded response bytes/status go through the existing agent verifier,
now shared in `signal-protocol`; only a verified leading ID/count/error-index
prefix advances. Complete binding, owner/generation and byte-exact prior control
are required. Temp sync, atomic control replacement and directory sync settle
progress without rewriting original/prepared bytes. Uncertain/permanent attempts
advance zero; unsupported custody/ACK/retirement changes still fail closed.

Twelve new receipt tests cover partial/restart/completion, invalid responses, stale
control/current-grant denial, corruption and revision overflow, quarantine, three
progress crash stages, three injected fault stages, queue rejection/cancellation,
caller timeout and lost reply while the physical worker retains its lock.
Independent review found revision one could claim an impossible predecessor;
exact initial checksum and zero starting prefix are now enforced and two
rechecksummed reopen mutations execute the correction. Follow-up source review
accepted it with no unresolved blocker/high.

Formatting, strict all-target Clippy, locked/offline workspace and 13-package
boundary checks pass: 410 Rust tests, zero failures. Two ignored subprocess
helpers are executed explicitly by parent tests (eight publication and three
progress crash stages). The 3/20/27/7 receipt/schema/transition/reclaim witnesses
and 15-requirement security catalog also pass offline. Evidence, independent
review, failed first checks and final logs are `target/goal-execution-20261007/`.
The initial sandbox run could not bind localhost; authorized local-process
acceptance outside that sandbox passed. No new dependency/version/event/HTTP v1
change or server service split. Historical image/candidate evidence retains its
own source binding.

Next is RECEIPT-RECOVERY: bounded retirement/ownership/restore reconciliation
before source transport. The Goal stays active across the writer transition.
This is surviving-local-filesystem process evidence; no source authentication,
AWS/EKS, native ARM64, higher-revision backup rollback proof or publication claim.

## Post-MVP bounded initial source-receipt store — 2026-10-07

`signal_collector_sdk::receipt` now validates the frozen immutable format and
publishes/reopens one receipt with its exact initial `SIGSCP01` control. One
physical blocking worker holds the private-root OS lock, with queue capacity one,
deadline/cancellation checks and counters. Full current scope and pinned owner/
generation are required. Payloads remain unchanged; initial namespace creation
uses exclusive hard-link/unlink rather than overwriting an injected destination.
Only verified receipt plus durably published root control exposes local admission.

Twenty-one new focused tests execute three exact receipt/control golden pairs,
eight publication-stage process exits and eight fault-injection boundaries.
Actual filesystem checks cover EEXIST no-clobber, corruption/missing/orphan data,
quota, lock/hardlink/symlink/root-inode/permissions, denied binding and occupied
slot. Queued cancellation, bounded queue rejection, caller timeout and lost
caller after publication retain the physical lock/work until settled. The shared
strict JSON decoder keeps previous CloudTrail behavior while giving metadata and
event readers explicit finite budgets and preserving literal number-marker keys.

Formatting, strict all-target Clippy and locked/offline workspace gates pass
398 Rust tests; the crash helper is intentionally ignored in normal enumeration
and invoked by its parent. The 13-package guard and existing security/native/
receipt contracts pass; offline regression counts remain 26/262 and 23/180.
Evidence/focused writer review is `target/source-receipt-store-20261007/`.
Existing `libc` and test-only `tempfile` dependencies are reused without changing
external versions, event/HTTP v1, crate count or the server data plane.

This slice accepts already prepared bytes; no gzip object parser, source transport,
mutable progress, ACK, takeover or reclamation is implemented. Non-initial
controls and unresolved publication fail closed. It proves bounded local process
recovery on the current filesystem, not host/power/device/AZ/account loss, source
proof or live coverage. Fresh independent source review and release gates remain
open. Next: atomic verified-prefix progress and replay, then retirement/takeover/
restore acceptance before source transport.

## Post-MVP source-receipt/progress encoding contract — 2026-10-07

[The v1 wire contract](30-source-receipt-contract.md) now freezes exact
`SIGSRC01` immutable metadata/original/event framing and `SIGSCP01` replaceable
progress. Full source binding, pinned retention/recovery budget, decoded record
spans, prepared IDs/content and ordered M2 prefix witnesses have finite fields
and encodings. Progress retains full binding/count/horizon after payload removal;
explicit retirement intent/completion prevents missing active bytes from being
mistaken for settled reclamation. Replay never regenerates original/prepared bytes.

Offline acceptance passes three receipt and 20 progress binary vectors, 27
transition cases and seven reclaim cases. Twenty-three focused negative/relational
tests pass 180 rejection checks, including noncanonical/duplicate JSON, exact
framing, numeric/Unicode/time bounds, full-binding changes, partial/uncertain
admission, required independent custody, source-ACK intent/redelivery and
retirement. A separate one-off reference encoder produced the checked-in pins;
this is not independent source review. Focused writer review/evidence is under
`target/cloudtrail-receipt-schema-20261007/`.

This is an offline contract and checker; no Rust store, gzip/object reader, source
ACK or AWS path is implemented. The previous 377-test Rust workspace and 13-package
baseline are unchanged; no Rust/build input changed or new runtime campaign ran.
Fresh source review and external release gates remain open. The next initial-store
slice at this schema acceptance is now recorded above; atomic progress/replay and
crash/reclaim qualification remain ahead of source transport.

## Post-MVP bounded CloudTrail record normalizer/profile — 2026-10-07

`signal_collector_sdk::cloudtrail::normalize_record` now performs pure, bounded
native management-record projection. Caller-provided scope, prepared UUIDs,
receipt UUID/ordinal and observation time are validated; no IDs or clock values
are generated. Original decoded record bytes are borrowed unchanged and hashed.
Canonical event/bytes are immutable through the result API and capped at 64 KiB.
The strict decoder bounds input at 256 KiB, depth at 16 and nodes at 16,384
(keys included), checking before each child allocation. Duplicate decoded keys,
malformed JSON/UTF-8, exponent overflow and trailing data reject explicitly.
SerDe number-marker strings remain ordinary native object keys.

All 41 original native cases execute in Rust, including typed scope, missing,
unsupported, new-minor, wrong-service/event-type and native MFA handling. Sixteen
SDK tests include two historical prepared-content pins, deterministic replay,
exact size/depth/node boundaries, literal boolean conditions, 64 independent JSON
models, large original integers and unknown-field retention without credential
projection. Three rule-pipeline tests execute actual native→canonical→finding
behavior. The D01 action filter is removed exactly as approved in the independent
design review; root StopLogging yields D01+D02 and root console login without MFA
D01+D03. Failed, missing and federated cases retain their negative expectations.

Formatting, strict all-target Clippy and locked/offline workspace tests pass:
377 Rust tests, zero failures; the 13-package guard and existing catalog/coverage/
backend checks pass. The 26 independently authored offline mutation tests still
pass all 262 rejection checks. This implementation used one writer and a focused
writer review against the previously independently reviewed design/fixtures;
it does not claim a new independent agent source review. Evidence and review
scope are retained in `target/cloudtrail-normalizer-20261007/`.

This helper is not wired into a collector or HTTP endpoint. Gzip/object parsing,
durable receipt/quarantine, source ACK, native proof validation, source observers
and authorized AWS qualification remain separate. No external dependency version,
event/HTTP schema, workspace crate or service is added; SDK direct edges reuse
existing `sha2`/`uuid`. Earlier image/candidate evidence retains its own bindings.

The next schema/vector item at this normalizer acceptance is now recorded above.
Bounded local receipt custody/replay remains ahead of S3/SQS delivery; fresh
source review and external release gates remain explicit.

## Post-MVP CloudTrail source-receipt/profile design — 2026-10-07

[The CloudTrail contract](29-cloudtrail-source-receipt.md) defines the next PS-02
slice before an AWS adapter is implemented: trusted source scope, original-byte
custody, pinned normalization revision/event IDs/bytes, and verified admission
prefix progress. Source receipts are distinct from coverage-history receipts.
HTTP M2 does not establish M3 protected evidence, M4 processing completion or
source completeness. Source acknowledgement requires custody for the selected
failure domain; local sync alone does not establish host/account-loss recovery.

The offline fixture checker and independent mutation regressions qualify only
the design's synthetic projections, identity/ACK witnesses and fixture inventory.
Acceptance passes 41 native projections, four object and three native-identity
comparisons, two prepared-byte pins, 19 ACK witnesses, and 26 independent tests
with 262 rejection checks. The 19 custody scenarios are explicitly unexecuted.
Crash, disk, fencing, cloud authentication, source proofs and native delivery
remain implementation/qualification work. At this design acceptance the Rust runtime and 358-test
workspace baseline were unchanged. Retained design evidence is under
`target/cloudtrail-receipt-design-20261007/`.

The next item at this design acceptance was the bounded Rust CloudTrail
management-event normalizer/profile, now recorded above, including the root-activity
predicate correction and D01/D02 overlap. Then implement source custody/replay
and S3/SQS delivery in separately reviewed slices. Neither the native normalizer
nor the AWS adapter is implemented by this design acceptance.

## Post-MVP SourceCoverage bounded scans — 2026-10-07

`CoverageStore::scan` reads one freshly authorized full binding at a fixed first-
page committed frontier. Later appends are excluded. Opaque canonical scan-v1
cursors bind history/full scope, frontier and consumed-prefix witnesses, plus
initial payload/identity markers. Continuations validate them before data or
terminal emptiness. Any marker advance returns `HistoryPruned` with bounded
availability; regressed/missing/divergent history rejects. The checksum is a
consistency check, not a grant/signature. The separate layout and independent
728-character golden token are frozen in [ADR-015](adr/015-source-coverage-store.md).

Positive matching/work-record/work-byte/response caps plus existing VM/deadline
limits bound each page. SQL length probes precede full integrity checks of examined
rows. Sparse pages can return empty with continuation. First work/response overflow
returns typed limits without progress; a later response-blocked row is examined
but unconsumed. Pages contain original receipt/optional raw bytes, avoiding repeated
profile/scope copies. Later assessment must resolve the exact retained profile.
No query language, timestamp cursor or source-health selection is introduced.

Non-cloneable pages retain operation slots and expose borrowed records/cursor;
holding all slots rejects another operation until a page drops. Conservative
response charge includes potential output cursor even when terminal. Maximum
page plus command charge is 684,544 of the existing 794,624-byte slot reserve,
with worker scratch separate. This is per-instance ownership, not global RSS.
Caller copies/new store instances are separate memory; post-shutdown snapshots
hold no filesystem lease. Reads mutate no clock/sequence/retention/accounting.

Independent review accepted; all 96 focused coverage and 358 workspace tests
pass with strict Clippy/fmt and the 13-package guard. Existing structural history
and frozen backend checkers pass unchanged; they do not execute the planned 56
history outcomes or verify this new cursor. Twenty independent scan tests and
two worker tests cover the golden encoding, bounded pagination/sparse pages,
per-page grants, pruning, restored divergent witnesses, retained-page capacity,
shutdown/restart, corruption, finite maximal-u64 fixtures and actual queued
timeout/cancellation/saturation rejection. One writer lint correction and two
fixture corrections resolved without changing production semantics. No actual
fsync cancellation/VFS/power-loss or complete unread-history recertification
is claimed; checked witnesses and examined rows are the bounded scope.

Evidence: `target/source-coverage-scans-20261007/`. This isolated post-MVP library
adds no dependency/schema/frozen-history encoding change or server/HTTP/cloud/
source-observer integration. Existing ARM64/EKS/local-kind/remote-CI/released-
dependency/publication gates remain open. At this scan acceptance the next item
was the bounded CloudTrail source-receipt/normalization-profile design, recorded
above before the first S3/SQS adapter. The read-only MVP
SecOps UI remains accepted; advanced SOC UX stays post-MVP.

## Post-MVP SourceCoverage identity-prefix pruning — 2026-10-07

`CoverageStore::prune_identities` reclaims only an expired global identity prefix
whose payloads are already unavailable. Positive record/selected-metadata budgets,
constant-memory point loads and existing VM/deadline/slot reserves bound work.
The first unexpired or oversized identity blocks younger rows. Each removed row
can reclaim at most one bounded binding/profile pin after checking surviving
references; shared pins remain. Equality is eligible, regression rejects and
no-op calls never advance the clock floor.

One transaction removes identities/newly unreferenced pins and updates marker/
anchor, counts, clock floor, logical charge and checksum. The history UUID,
committed sequence/tail, payload anchor and surviving immutable correction links/
receipts remain, including an empty store. Later append continues the old prefix.
A referenced retry at/below the identity marker returns `IdentityPruned`, after
current authorization and reference checks, and never becomes admission. The
marker witness is checked; below it, deleted originals cannot authenticate every
supplied receipt field. Unknown bare IDs carry no lifetime deduplication promise.
Metrics expose the durable identity marker and successful nonempty runtime counts.

Independent review accepted with no unresolved findings. All 74 focused coverage
and 336 workspace tests pass, with strict Clippy/fmt, the 13-package guard and
unchanged contract/reference-vector checkers. Sixteen new regressions include
nanosecond equality, payload/time obstruction, budgets, exact shared-pin accounting,
quota reuse, all-pruned restart/sequence continuity, stale-reference authorization,
receipt ordering, bare-ID limitations, surviving corrections, corruption, actual
queued timeout/cancellation and genuine SIGKILL before/after identity commit.
The dedicated prune-all crash case executes final binding/profile deletion and
checks empty-root recovery plus sequence-3 append. Generic active-worker ownership
remains distinct from queued cancellation/process loss; actual fsync cancellation,
VFS fault injection and physical power loss remain unqualified. One existing
receipt fixture was kept semantically ordered to preserve its exact-field mismatch
assertion; the independent malformed-time test covers the new early rejection.
No production correction was required; review added the targeted crash proof.

Evidence: `target/source-coverage-identity-pruning-20261007/`. No dependency,
schema/encoding change or server/HTTP/cloud/observer integration is added.
Maintenance uncertainty still requires owner exit/recovery and marker reconciliation;
repeating a call can prune another prefix. Logical reclamation does not promise
physical erasure, file shrinkage or a strict deletion deadline. At that acceptance,
fixed-frontier scans were next; their later acceptance is recorded above. Existing environment/release gates remain open.

## Post-MVP SourceCoverage payload-prefix pruning — 2026-10-07

`CoverageStore::prune_payloads` now reclaims only an expired global payload prefix.
Positive configured record/raw-byte limits, existing VM/deadline/slot reserves and
one-row streaming keep work/memory bounded. The oldest unexpired or oversized row
blocks younger rows across bindings. Selected raw lengths/hashes and metadata/
prefixes are checked before erasure; corruption fails closed. Equality at the
original replay deadline is eligible, regression rejects, and no-op calls never
advance the durable clock floor.

One transaction clears payloads and updates marker/anchor, clock floor, count,
logical charge and checksum. Identities, immutable receipts, profile/binding pins,
correction links and committed sequence/tail remain. Historical reads explicitly
return unavailable raw bytes. Already admitted corrections survive original
payload pruning; new links require available evidence. Runtime prune counters
cover successful nonempty calls; the marker survives restart. Unknown maintenance
outcomes require marker/accounting reconciliation after owner exit and recovery;
there is no durable maintenance receipt or exact-once retry guarantee.

Independent source review accepted after one stored-decoder error classification
fix; test-fixture corrections preserved established reduced-cap `Quota` behavior.
All 58 focused coverage tests and 320 workspace tests pass, with strict Clippy/fmt,
13-package guard and unchanged history/reference-vector checkers. Thirteen new
regressions cover frozen anchors/receipts, equality, global obstruction, budgets,
quota recovery, corrections, corruption, queued timeout/cancellation and actual
SIGKILL before/after pruning commit. Generic active-worker ownership proof remains
separate from actual pruning process loss; fsync cancellation, VFS fault injection
and physical power loss are unqualified.

Evidence: `target/source-coverage-payload-pruning-20261007/`. This post-MVP library
slice adds no dependency, wire/schema/encoding change or server/cloud/observer
integration. UI-image reports retain their own reviewed runtime binding; they do
not qualify the new library on ARM64 or in AWS. Logical reclamation is not secure
physical deletion or page-file shrinkage. At that acceptance, identity-prefix
pruning was next; its later acceptance is recorded above. Existing environment/release gates remain open.

## MVP SecOps UI-02 — 2026-10-07

Findings now open their referenced evidence by exact canonical non-nil UUID.
The optional `EventQuery.event_id` field preserves older serialized clients;
DataFusion applies equality together with the existing filters/budgets. Evidence
links clear event-time and unrelated filters because finding creation time is not
source event time. Independent same-ID admissions remain separate rows. Empty
results state only absence in retained/search scope; auth/resource errors remain
errors. Advanced SOC UX remains post-MVP.

Accepted locally: 307 workspace Rust tests, strict Clippy/fmt, 13-package boundary,
26 Chromium fixture checks, four actual-server/restart checks, 24 candidate-helper
regressions, current source export and strict Helm lint. Fourteen real-container
browser checks (seven before/after restart) verify current embedded asset bytes,
authentication, delayed 10-day duplicate evidence, large-number preservation,
hostile text, scoped absence and cleanup. Existing container auth/nonroot/read-only/
SIGTERM/SIGKILL persistence checks pass on image
`sha256:14c56dcf65bcbb41d95a7ee1a8ced9464732ec71db80c014b3fab734b21cbf55`.
All six supply-chain checks pass: Cargo/image SBOMs 341/15 packages, RustSec zero
vulnerabilities, Trivy HIGH/CRITICAL zero (MEDIUM 23, LOW 8).

Evidence: `target/secops-ui-evidence-20261007/`, including independently accepted
source/helper reviews, runtime reports and actual capture times. One test-only
Clippy assertion correction was required; the first restricted-sandbox workspace
run lacked socket permissions and its log is retained beside the passing run.
The optimized image contains the reviewed runtime source; a subsequent test-only
lint correction does not change its compiled production inputs.

Current-image native qualification also passes nine hardening tests, seven
pipeline profiles and two 120-second soaks. The pipeline admits 3,668 WAL-durable
events versus 3,666 HTTP-confirmed; two additional events after an HTTP 408 prefix
remain within the existing uncertainty bound. Both 1/4 KiB soaks retain 10,740/6,890
accepted events, 537/345 findings and 20 queries each, with zero rejection or
transport uncertainty. These are finite shared-host observations, not capacity
or long-term stability guarantees.

Remaining MVP work is the existing environment/release gates. A read-only host audit could not establish that the earlier kind
root/node resource failure is resolved; no global settings or unrelated resources
were changed. Native ARM64, actual EKS, remote CI, released dependencies and
publication remain open. Local UI acceptance does not make `v0.1.0` ready.
PS-01 payload-prefix pruning is the next post-MVP library slice after locally
runnable MVP acceptance; no SOC workflow or collector rollout has been added.

## MVP SecOps UI-01 — 2026-10-07

The owner classified minimal SecOps UI as MVP and advanced SOC UX as post-MVP,
then authorized team execution item by item. The server now embeds `/ui` and fixed
HTML/CSS/JavaScript assets with same-origin CSP/no-store/nosniff/referrer controls.
Read-only findings filters/detail and event search/detail use the existing APIs;
credentials stay in page memory and API authentication remains authoritative.
Client limits are 100 rows, 8 MiB decoded response and 30 seconds, with pane cancel,
disconnect cancellation and stale-response guards. Exact raw canonical row slices
preserve large JSON integers; no original-source authenticity claim is made.

Local acceptance: 301 workspace Rust tests, strict Clippy/fmt, 13-package boundary
guard, 21 actual-Chromium checks against fixture APIs, four real server/browser
checks including WAL/Parquet/finding restart, and 24 source-candidate regressions.
The real server returns exact current source asset bytes. Browser review fixed
mobile overflow; focused security review fixed a superseded/cancelled 401 race.
Candidate source closure now includes only the three exact embedded assets and
two explicit test helpers. No new production crate was added; the test harness
adds already-locked Tower to server dev dependencies.

Evidence: `target/secops-ui-20261007/` (browser, process-final, Rust logs, candidate
tests and focused review). Team-owned docs/browser/packaging changes were reviewed
with one product writer. Next: UI-02 exact event-ID evidence navigation, then
current-source package/container qualification. PS-01 payload/identity pruning and
scans remain parked post-MVP. Native ARM64, actual EKS, remote CI, released
dependencies and publication remain open; this is still `0.1.0-dev.0`.

## Product architecture baseline — 2026-10-07

The owner-requested [product architecture](27-product-architecture.md) defines
SIGNAL's small/mid-sized AWS customer envelope, shared DevOps/SecOps workflow,
Small/Standard/Scale profiles, reliability objectives, resource budgets and
non-goals. Rust, the v1 event contract and the monolith remain. Four role families
are deployable only where needed, not four required services. S3 owns retained
telemetry/evidence; separate durable control state remains necessary. Standard
selects a future shared PostgreSQL control backend with fenced ownership and
explicit object-backed custody before any multi-server HA claim.

The baseline makes production security controls profile-independent and adopts
generic opt-in detection packs while retaining company activation/routing/policy
privately. API availability targets and security evidence durability are separate.
Burst/resource figures are unqualified engineering targets: at 1 KiB per event,
200k events/s sustained is approximately 17.7 TB/day, outside the 5 TB/day primary
upper design envelope. Spool/catch-up sizing and archive retrieval behavior are
explicit. No language rewrite, new dependency, replica/config change or release
version is introduced. Existing release gates and next payload-pruning task remain.

Documentation acceptance: 13-package boundary guard, 15-requirement/45-case
detection catalog, 55 vendor cases across 11 families with seven rejection guards,
sizing arithmetic, local Markdown links and whitespace. No new Rust tests or
capacity/cloud measurements are claimed. Single-writer review and retained evidence:
`target/product-architecture-20261007/`.

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

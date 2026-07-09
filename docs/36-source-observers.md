# Bounded source observers

COVERAGE-OBSERVERS is passed_simulated in the frozen execution ledger. This contract
adds polling/current health to the existing SourceCoverage v1 validator and
physical history; it introduces no service or alternate coverage format.

## First implementation boundary

One `CoverageObserver` holds one trusted profile/full binding/observer identity
and at most one accepted raw report (64 KiB) plus its validated interpretation.
A mutable borrow permits one probe invocation at a time. A new bounded report
may coexist with the previous report during validation; caller-owned multiple
observers and returned buffers need an aggregate application budget. No internal
queue, retry loop, task or automatic polling schedule is created.

`CoverageProbe` is separate from telemetry `Collector`/`EventSink`. Its source
configuration, scope, continuity/checkpoint and optional integrity assertions
must come from independent authenticated observations. Successful event
admission, a source API HTTP 200, collector heartbeat or absence of events cannot
manufacture verified coverage. The application owns source credentials, native
proof validation, expected-stream policy and retry cadence. A generic probe seam
alone does not complete native source-probe or server-integration acceptance.

Each poll uses a bounded trusted current assessment request and one finite
`ExtensionContext`. It checks the exact configured binding/observer/profile
before dispatch. During the await health becomes unknown; dropping the poll
cannot leave a previously healthy state promoted indefinitely. Cancellation,
deadline, probe failure or malformed/foreign/future observation retain the last
raw report without modifying verification time, expiry, interval or checkpoint.
Completed failure marks health unhealthy; a well-formed independent response
marks the observer healthy, while source coverage still follows the response's
component statuses and freshness. No first report means unknown coverage.

The observer validates returned raw bytes against its configured profile rather
than a profile chosen by the probe. Verified time cannot move backward. At an
equal verification time the interval, checkpoint, validation/proof claims,
gap details and expiry remain pinned. Only record ID, last data-arrival time and
report provenance observation time may change. A newer data arrival never
renews coverage. Reusing the retained record ID requires exact original bytes;
changed reports require a new ID. The physical history/intake validates older
IDs beyond this one-report cache. A new verification may change claims only
after full semantic validation. Exact replay remains harmless; a rejected response preserves the
previous bytes. Expiry assessment uses the trusted caller's current clock.

Current assessment uses observer-owned health, never a caller's supplied healthy
flag. Historical assessment uses the existing history API and does not erase
past evidence when the observer fails. Identity/proof names are bounded inputs,
not authentication. Diagnostics contain only static errors/counters.

## Local acceptance

Nine observer regressions, default 509/all-feature 521 workspace tests, strict
Clippy/fmt/package guard and independent review pass. The identity-conflict
regression fails before its correction and passes afterward. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/observer-validation.json`.

## Remaining acceptance within this item

After bounded state acceptance, implement independent source-configuration and
checkpoint/proof adapters with local denied/throttled/outage/malformed/quiet/gap
simulations. Wire the existing bounded history/intake/scan API into the monolith
with validated configuration, scoped observer authentication, finite request and
response budgets, shutdown and metrics. Qualify restart/replay and visible
degraded silence end to end. Preserve v1 history/receipt encoding and the
public/private ownership boundary. Real AWS/vendor permissions, source proofs
and collection completeness remain separately documented external gates.

## Regional CloudTrail configuration probe

The optional `aws-source` feature supplies `CloudTrailConfigurationProbe`.
Its trusted version-1 input is closed JSON bounded to 64 KiB, with a commercial
trail ARN, exact observed region/root endpoint, destination bucket/prefix,
management read/write expectation and required settings. The current context
must use `aws.cloudtrail.trail`, that exact ARN, one `region` scope attribute and
`aws.cloudtrail.management.all`, `.read` or `.write` matching the expectation.
Observer/full binding/profile/config revision remain pinned. Organizations,
account inventories, production requirements and credentials are application
policy; setting an organization trail flag proves no membership inventory.

One poll makes three sequential signed AWS JSON 1.1 POSTs: `GetTrail`,
`GetTrailStatus`, `GetEventSelectors`. Fresh application credentials, the existing
private AWS signer transport, actual 64 KiB response caps, strict bounded JSON,
finite deadline/cancellation and no proxy/redirect/decompression/retry apply.
Both returned trail ARNs must match. The status read is for the configured
region; a multi-region flag does not turn it into a global status check.

This first adapter checks point-in-time logging/destination/configuration and
basic management selector scope. Optional selector members follow AWS's
specified defaults and types; read/write selectors may jointly cover both.
Malformed present fields fail before evidence promotion. Advanced selectors,
new filter semantics and unexpected continuation tokens stay unsupported; no
data-event coverage is inferred from a management selector. Disabled logging,
changed destination or missing required settings yield failed component checks.
A completed failed configuration check can still have a healthy observer.

The result always retains unknown continuity and source integrity, null data
arrival/checkpoint and an unknown gap inventory. It never returns verified total
coverage. The requested interval is a subject of assessment, not a claim that a
point-in-time API read proves interval-wide enabled logging. Enabling digest
delivery does not validate a digest. API reply hashes are bounded content
references, not stored proof objects, source signatures or independent custody.
The immutable history/intake and later evidence route must retain/authenticate
proofs needed by stronger profiles. API denial/throttling/outage/malformed input
retains prior evidence and degrades current observer health.

Protocol and optional-member semantics were checked against the official
[CloudTrail API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrail.html),
[regional status API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html),
[event selectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html),
[data resources](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DataResource.html)
and Amazon's [botocore protocol model](https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/cloudtrail/2013-11-01/service-2.json).
Context7 resolution hit its monthly quota; these primary sources are the
recorded fallback. Actual AWS IAM/TLS, organization coverage, complete source
continuity and authenticated native digest proofs remain unqualified.

Eleven native-probe regressions and eleven signed S3/SQS regressions pass;
current default 509/all-feature 532 workspace gates, strict Clippy/fmt/package
guard and independent review pass. Malformed optional selector regression fails
before its correction and passes afterward. A pre-existing query-drop test now
waits finitely for physical I/O after immediate admission release; production
capacity guards are unchanged. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/native-probe-validation.json`.
This is a locally accepted configuration slice, not completed server coverage
integration or authenticated interval continuity/source proof.

## Durable observer/history bridge

`CoverageObserver::poll_persisted` validates an independent report, then awaits
`CoverageReportSink` before adopting its bytes or healthy status. The generic
`HistoryReportSink` in `signal-coverage` uses the existing single-worker history
store. Its application-owned `CoverageIntakeProvider` must freshly authenticate
and authorize the complete binding and supply current receiver time, profile and
retention policy per operation. Report identities or proof hashes are no grant.

Direct bridge callers are semantically validated before input copies or authority
calls. The current trusted profile must match the SDK definition by all required
components and time/checkpoint limits; component order is immaterial. Retired
profiles may authorize exact retained replay without a current definition, but
the returned immutable receipt must match the original physical profile pin.
Global retained identity rejects changed older record IDs beyond the observer's
one-report cache. New reports require current profile policy. The basic poll seam
does not manufacture correction links; existing explicit intake handles backfill.

Accepted intake permits new health/evidence adoption. Replayed intake preserves
prior health and cannot heal unknown/unhealthy status or renew verification.
Finite cancellation/deadline guards apply before and after authority, physical
intake and receipt verification. Failure retains the prior immutable cache;
dropping a poll leaves health unknown. Physical uncertain-write/reopen guarantees
remain the store's existing contract, without a replacement worker or retry loop.

Thirteen SDK observer tests and ten bridge physical-history tests pass; current
default 523/all-feature 546 workspace gates and independent review pass. Evidence:
`target/goal-execution-20261007/COVERAGE-OBSERVERS/history-bridge-validation.json`.
This bridges libraries only. Server scoped authentication/configuration, request
budgets, lifecycle, metrics and runtime gap/degraded-silence qualification remain
open; no stored row is automatically selected as current source health.

## Scoped monolith coverage history API

Coverage is optional in the existing `signal-server`, with no extra service or
message broker. `coverage.config` in strict server YAML (or
`SIGNAL_COVERAGE_CONFIG`) names a closed version-1 JSON configuration read through
the existing one-worker, one-slot configuration reader. That file is capped at
64 KiB. Names, full bindings, profile definitions, authority revisions and actual
age/retention policy are deployment-owned; no company values are shipped in core.

The JSON contains `schema_version: 1`, `directory`, `limits` and `scopes`.
`limits` explicitly supplies the existing `CoverageConfig` fields except the
path, with `operation_timeout_ms` for duration. The library validates all finite
payload/identity/binding/ledger/database/journal/operation/memory/VM bounds.
Each of at most 32 scopes contains `binding_json`, `profile_json`,
`authority_revision`, `token_env`, `max_report_age_seconds`,
`max_clock_skew_seconds`, `payload_retention_seconds` and
`identity_retention_seconds`. Embedded JSON strings use the existing version-1
binding/profile parsers, preserving their budgets and duplicate-field checks.
`profile_json` is required; explicit null retires new writes while allowing
currently authorized exact retained replay. Configured profile ID/revision must
match its binding. Conflicting definitions under one configured ID/revision fail
configuration validation. A conflicting retained definition rejects physical new
admission; it never replaces a pin used by historical reads.

A scope token resolves only from its explicitly named environment variable.
Tokens are unique, 16–4096 ASCII graphic bytes; complete bindings are also unique.
They must differ from the generic API token. No token has a Debug/serialization
path. One token authenticates exactly one full binding and observer; every read
and write issues a fresh exact grant from that authenticated startup-pinned
configuration. Names in a report confer no authority. Rotation/revocation or
policy changes require restart in this first adapter; live OIDC/RBAC and secure
transport remain their separate planned items. Restrict deployment reachability
until those trust gates are qualified.

`signal-server --initialize-coverage [--config PATH]` explicitly creates a new
history identity and exits without opening HTTP/WAL/event services. It requires
a configured coverage file and an existing parent directory. Normal startup
only opens existing history. Missing, corrupt, already owned or partially
initialized roots fail; neither operation silently recreates or clears history.
The underlying private root, permissions, lock, transaction, physical-worker,
uncertain-outcome and reopen contracts remain unchanged.

| Route | Contract |
| --- | --- |
| `POST /v1/coverage/records/{record_id}` | Exact original JSON body, canonical nonnil UUID path, optional single `correction_of` UUID query. `201 accepted` or `200 replayed` returns the original durable receipt. This is coverage-history admission, separate from event M2 and source proof validation. |
| `GET /v1/coverage/records/{record_id}` | Exact authorized receipt, original JSON as a UTF-8 string (or null when pruned), and the retained `profile_json` definition. No current-catalog reinterpretation. |
| `GET /v1/coverage/history[?cursor=…]` | One record per finite page at the first page's committed frontier, opaque full-binding cursor, pruning markers and actual scan work. Sparse/terminal pages are not proof of healthy collection or absence of source events. |
| `GET /v1/coverage/metrics` | Authenticated aggregate store/request depths, capacities, accepts, replays, rejections, timeouts and failures. No source content, credentials, binding identity or proof reference. |

Authentication precedes request-body reads. Duplicate Authorization headers fail.
Original bodies are capped at 64 KiB and must have exactly one
`Content-Type: application/json`; content encoding is rejected. Query strings
are capped at 16 KiB with strict percent/UTF-8/schema/duplicate checks. The HTTP
adapter limits canonical binding bytes to 6 KiB at startup so every supported
full-binding cursor fits the URL/header budget; the library's larger binding
format remains unchanged. Four HTTP operation slots cover body reads through
serialization. Each physical store keeps its existing operation/command limits.
Actual serialized replies are capped at 512 KiB, including JSON escaping and
cursor overhead. Completed response buffers are further bounded by the existing
transport connection budget and lifetime timeout; the HTTP operation lease does
not claim to cover network writes. Successful/error coverage responses use
`Cache-Control: no-store`; errors are static and never echo input.

Requests own a child cancellation guard and finite deadline capped at ten
seconds and the configured server request timeout. Shutdown cancels coverage
admission before draining transport, then shuts down the same physical history
worker under the shared shutdown deadline. Enabled unavailable history makes
server readiness false; quota exhaustion is visible without replacing the worker.
The optional disabled path preserves existing event ingest semantics.

Every history/intake/metric reply currently exposes `current_health: unknown`.
API success, exact replay, receipt position or a selected stored assertion cannot
heal observer supervision. Independently supervised checkpoint/gap/quiet-stream
runtime acceptance remains separate. Do not choose the most recently appended
history row as current health. These routes preserve originals and pins; they do
not authenticate native proofs or establish protected independent custody.

This monolith slice passes eleven API/configuration tests and one real process
bootstrap/HTTP deadline/SIGKILL/reopen/rotation test. Default535/all-feature558
workspace tests, strict format/lint/package gates and focused source review pass.
Evidence: `target/goal-execution-20261007/COVERAGE-OBSERVERS/server-integration-validation.json`.
Current health remains unknown without qualified independent application
supervision. Native source continuity/digest proof adapters remain unimplemented
and unqualified; they are not made real by this local history/server acceptance.

## Independent source runtime acceptance

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
digest adapters remain unimplemented/unqualified. Applicable proof work remains
within EVIDENCE; simulation closes no real environment gate. Server history health
stays unknown without application-owned independent supervision. Next is the
bounded public findings cursor; historical artifacts need fresh final qualification.

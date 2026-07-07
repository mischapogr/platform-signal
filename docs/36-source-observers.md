# Bounded source observers

COVERAGE-OBSERVERS is in progress in the frozen execution ledger. This contract
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

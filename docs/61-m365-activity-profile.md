# Microsoft 365 selected Management Activity profile

The selected mechanism and its acceptance boundary are described here; current
qualification is recorded in [progress](07-progress.md). The profile uses the Management Activity API
`Audit.AzureActiveDirectory`; this does not imply Microsoft Graph sign-in,
Exchange, SharePoint, General, DLP, all-tenant or historical completeness.
Private applications own tenant/feed selection, permission evidence, registered
OAuth credentials and authorized subscription changes. Local qualification
creates no live tenant, subscription or cloud resource.

## Bounded transport foundation

`m365::ActivityClient` selects the public-cloud `manage.office.com` endpoint,
configured non-nil tenant UUID and existing caller-owned TLS trust. A separately
named local-fixture constructor accepts literal loopback HTTP only. Redirects,
ambient proxies and automatic decompression are disabled through the shared
transport. URL validation precedes token acquisition: origin, exact tenant path,
selected list feed and list/audit operations are pinned. Credentials, fragments,
backslashes, percent-encoded paths, foreign tenants and unsupported operations
fail closed. Encoded query values are allowed; government endpoints require a
separate profile. URI values are limited to4096bytes. The documented /api/v1/ alias is accepted
only for listing continuation; content operations retain /api/v1.0/ scope.

`TokenProvider` is a trusted private OAuth credential/refresh hook. Opaque tokens
have bounded printable ASCII syntax and no Debug/serialization implementation.
Initial token retrieval, at most one forced401refresh, all requests/body reads
and retry waits share the caller's original cancellation/deadline context. There
are at most5HTTP attempts.403denies; missing/expired content fails without cursor
reset;429and5xx retry within that same budget. Selected Retry-After syntax is
integer seconds up to60; other syntax refuses rather than renewing the budget.
Transport/provider errors are static and do not expose tokens, URIs or bodies.

A successful response captures exact entity bytes up to2MiB and an optional
validated NextPageUri header. Multiple or oversized continuation headers refuse
before copying; streaming growth is bounded even without Content-Length. Exact
entity capture is distinct from raw HTTP wire bytes and provider authenticity.
This transport alone never commits a checkpoint, advances a source cursor,
publishes an event, grants coverage or promises retained originals. The page driver below adds schema/window checks and durable checkpoint seams;
HTTP capture alone cannot qualify those guarantees.

The provider token hook remains responsible for actual tenant-bound OAuth scope,
credential safety and retained physical work after front cancellation. A valid
bearer token and a successful HTTP response do not establish independent source
coverage. Actual provider permissions/identity/feed completeness remain external.

## Bounded page journal and durable outbox

`ActivityClient::advance` processes one page per invocation and exclusively borrows
the client. `Window` pins an explicit nonempty source name, UTC interval up to24h
and private publisher UUID. Source API root/tenant/feed and window remain bound
to the journal. Equivalent UTC timestamp/date spellings are compared as instants.
A missing continuation PublisherIdentifier is restored from private configuration
on the effective outbound request; a conflicting publisher fails. Both received
cursor and actual request URI are retained. Changed or duplicated parameters, operation changes, cursor
cycles and unsupported page URIs fail without checkpoint progression. Content
availability time is constrained to that window; event times can be out of order.
Expired unavailable content fails with a gap rather than resetting the cursor.

A serialized schema-version1 `State` retains exact listing/content entity bytes,
request/next URIs, native content digests, bounded native event identity/digests
and canonical prepared events. There are at most32pages,64contents per page,
512distinct content IDs,1024records per blob and4096distinct event IDs per window.
Body/JSON/depth/node/canonical-event limits apply and serialized state is capped
at16MiB. Both retained state and the staging page count toward that cap before
fetching another blob. The state exposes depth/capacity; HTTP admission has one
active request slot, immediate Busy refusal and counters including abandoned
capture futures. There is no detached polling loop or completed-page queue.

Native audit Id, OrganizationId, CreationTime, Workload, operation and user fields
are validated against the selected tenant/AzureActiveDirectory profile. Native
UTC timestamps without an offset are interpreted as documented UTC. Source and
resource scope come from trusted configuration, with conflicting native tenant
claims refused. Original fields, including null ClientIP, remain under m365
attributes. Client IP and UserId are assertions. Severity is informational; a
Succeeded ResultStatus is not interpreted as proof of successful authentication.
Coverage declares this feed and independent completeness/Graph sign-ins unknown.

`PageJournal` is a trusted application-owned extension hook. Its commit must
atomically own the complete originals, prepared canonical values and next cursor,
with compare-and-swap revision. Returned errors or front cancellation may be
uncertain: the next invocation reloads durable state. Repeated native event IDs
reuse the first prepared canonical values. Prepared IDs bind window, publisher
and source as well as native audit identity, so overlapping windows have distinct
delivery IDs after their separate finite dedup horizons. Differing content/event payloads with
the same identity refuse. Dedup is finite within this retained window; no global
or indefinite dedup guarantee is made. The outbox remains readable after window
completion; downstream publication/checkpoint progress is separately owned by
the private application. HTTP202 does not advance this journal by itself.

Reload checks route/version/window, page chain/cycles, retained metadata and
content digests, native events and prepared canonical consistency. These checks
do not authenticate an attacker rewriting an entire journal. The private host
owns actual atomic persistence, disk quotas, physical worker retention after
front timeout, authorized journal access, protected original retention and
publication. No CloudTrail trail/queue binding is fabricated. No service, token
issuer or subscription is automatically created.

## Qualification scope

Focused local HTTP fixtures compose401refresh,429/5xx retries, paged content,
atomic filesystem receipt/checkpoint sync, lost commit reply, fresh-object disk
reload, overlapping content/event dedup and exact prepared-value reuse. A real
child is SIGKILLed after synced receipt commit and resumes from the saved cursor.
Negative windows/cycles/malformed records/expiry/scope/identity conflicts preserve
the prior durable state. These are selected local-provider simulations; actual
Microsoft tenant permissions/credential exchange/subscription/coverage and
cross-host custody remain external qualification requirements.

Context7's Microsoft365 repository returned no matching Activity API material;
primary Microsoft documentation was checked directly on2026-10-14:
[Activity API reference](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference),
[common/native schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema)
and [OAuth setup](https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis).

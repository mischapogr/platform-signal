# Selected Cato security eventsFeed profile

Profile selected on 2026-10-14. [Current progress](07-progress.md) records
source-bound acceptance and its evidence; this contract alone does not close CATO. Actual Cato credentials, permissions, retention and independent coverage
remain external qualification.

The selected POST endpoint is `https://api.catonetworks.com/api/v1/graphql2`,
with caller-owned TLS trust and private `x-api-key` retrieval. One configured
numeric account is sent using GraphQL variables; the query selects `Security`
events and `accounts { id errorString records { time fieldsMap } }`. No ambient
proxy, redirects, decompression, dynamic endpoint or multi-account collection.
An explicit literal-loopback HTTP constructor exists for provider simulation.

A single request slot rejects concurrent admission; depth/capacity and failures,
including abandoned futures, are exposed. Connect is bounded to five seconds;
key retrieval, all attempts, response chunks and retry waits share the original
extension deadline and cancellation. Maximum five attempts; 429/5xx/outage retry;
401/403 refuse without resetting credentials. Integer Retry-After values up to
60 seconds are supported; other syntax refuses. Complete response entity bytes
are bounded to 2MiB, including chunked responses. Error text excludes credentials,
markers, provider bodies and URLs.

Bootstrap requires an explicit `Latest` choice or a supplied opaque marker with
its private last durable receipt time. Latest means recent data, not historical
backfill. Resume markers are bounded to 4096 bytes. A locally known age of three
days or more, future timestamp, empty/control marker or provider error refuses;
there is no automatic fallback to latest. Cato can silently move invalid markers
to current data. Opaque marker validity cannot be proven from response syntax;
local age checks are a conservative safeguard, not a continuity guarantee.
Private qualification must independently assess gaps and current tenant behavior.

One capture epoch binds configured source name, nonnil private epoch UUID,
endpoint, account and explicit initial position. A trusted private PageJournal
loads bounded state and atomically commits original bytes, prepared events and
next marker using expected revision. Every advance reloads, including after a
lost commit reply. Host implementations own disk quotas, protected custody, CAS,
physical I/O ownership after cancellation and independent publication progress.
The SDK does not install a filesystem journal or retire outbox on HTTP202.

State serialization is version1. At most16 retained pages,3000 records/page,
64KiB native record,256 fields and16MiB serialized state are supported. Capacity
exhaustion refuses advancement; the host must explicitly manage custody and
outbox before creating another epoch. Complete-page validation precedes commit;
late malformed records, partial GraphQL errors, account errors, scope mismatch,
count disagreement and non-progressing/cycled markers preserve the checkpoint.
An empty response with unchanged marker is a valid idle poll and retains a page.

RFC3339 native record time supplies event timestamp. `fieldsMap.event_type`
must be Security; configured account binds resource scope, while any native
account assertion must agree. Event subtype supplies a bounded descriptive
message. Arbitrary bounded native fields are preserved under `attributes.cato`.
Severity remains Info; actions and threat scores are native assertions, not
inferred authentication outcomes or policy decisions. Coverage is filtered,
independent completeness and opaque marker validity are not assessed.

Prepared UUIDv8 identities bind configured endpoint/account/source/epoch,
complete original response digest and record ordinal. Pinned observed time and
prepared values are retained atomically and reconstructed on reload; alteration
refuses. Exact retained receipt replay preserves canonical IDs and values.
Distinct provider pagination may repeat native records; this profile makes no
cross-page native-ID dedup guarantee and downstream delivery remains at least
once. Private policy supplies detections, alert routing and customer identity.

Sources checked on 2026-10-14: Context7 Cato support docs, then current official
[GraphQL reference](https://api.us1.catonetworks.com/documentation/),
[eventsFeed](https://knowledge.catonetworks.com/docs/en/cato-api-eventsfeed-large-scale-event-monitoring),
[EventRecord](https://knowledge.catonetworks.com/docs/en/cato-api-eventsfeed-eventrecord-large-scale-event-monitoring)
and [April2025 marker change](https://knowledge.catonetworks.com/docs/en/product-update-april-28-2025).
The official schema supersedes conceptual field names in retrieved snippets.

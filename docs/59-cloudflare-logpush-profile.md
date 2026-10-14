# Selected Cloudflare Logpush object profile

The public SDK provides a bounded `cloudflare-http-requests` revision `v1`
projection for zone-scoped Logpush `http_requests` gzip NDJSON objects. The private
adapter owns the authorized destination/object route, account/zone identity,
job configuration, credentials, retained originals, pinned receipt/observed time,
publication/checkpoints and independent current coverage. This mechanism creates
no Logpush job, AWS resource or service and grants no source authorization.

The selected job must emit exactly `RayID`, `EdgeStartTimestamp`, `ClientIP`,
`ClientRequestMethod` and `EdgeResponseStatus`, with RFC3339 timestamps. Unknown
fields, cookies, headers and URI values are rejected rather than copied to public
prepared attributes. Other datasets, custom delimiters, transformed/renamed
fields and numeric timestamp modes are outside this revision. Account/zone scope
comes from explicitly configured object routing, never client IP, HTTP host or an
unverified native field. Those identifiers remain private deployment inputs.

Cloudflare permits field selection, sampling and filters. The profile explicitly
records a configured sample rate in parts per million and whether filtering is
enabled. Every event declares delivery completeness `not_assessed`; full sampling
and successful decoding are not independent proof of complete zone traffic.
Client IP is context, never an authenticated principal. HTTP status0 denotes no
classified client response in this projection;4xx/5xx map to warning/error,
other supported statuses to informational. Request IDs remain native context.

Shared `source_object::decode_gzip` is used by CloudTrail and this profile:
8MiB compressed/32MiB decoded, one complete validated gzip member, CRC/footer and
trailing-input checks, bounded allocation and original SHA256. The Logpush reader
adds64KiB records,1024records, UTF8/JSON/depth/node/duplicate-key checks and exact
native spans. A final line without LF and CRLF are supported; empty lines and
malformed JSON fail the complete object. CPU work belongs in an owned bounded
blocking worker with the caller's original cancellation/deadline context.

`prepare_object` validates all selected records before exposing any events, caps
aggregate canonical bytes at8MiB, and preserves source timestamps with separately
pinned observed time. IDs deterministically bind profile/configuration, receipt,
original-object digest, ordinal and pinned observed time. Replay must reuse that
exact pinned context; the helper owns no durable deduplication state. It preserves
exact decoded records and the original capture digest without interpreting a hash
as provider authenticity. Generic custody/checkpoint/ACK guarantees do not arise
from this pure projection. The existing v1 CloudTrail receipt binding remains
CloudTrail-specific; adapters must not fabricate a trail/queue identity for this
source. Collector extension hooks can publish fully prepared events after their
own durable original/route verification.

Sources checked2026-10-14: [HTTP request fields](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/),
[output options](https://developers.cloudflare.com/logs/logpush/logpush-job/log-output-options/)
and [S3-compatible destinations](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/s3-compatible-endpoints/).
Local fixtures qualify the selected schema/mechanisms; actual customer dataset,
plan, job selection and destination ownership remain EXT-VENDORS/EXT-AWS gates.

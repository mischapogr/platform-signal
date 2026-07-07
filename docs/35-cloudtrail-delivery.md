# CloudTrail delivery and local simulation

AWS-DELIVERY remains in progress in the frozen execution ledger. One reference
per message is the first qualified capacity; no additional service is required.

The first substep validates a direct S3 notification in at most 256 KiB, depth 16,
16,384 JSON nodes and 16 references, with duplicate/UTF-8/non-finite checks before
dispatch. Numeric version major 2 and minor at least 1 permit additive fields.
Only four ObjectCreated kinds are supported. Form-decode keys exactly once with
a 1,024-byte decoded cap; require bucket/current full binding namespace and a
non-null bounded version. Validate every reference, then hold a multi-reference
message explicitly without fetch or ACK. Wrappers, test/empty notifications,
invalid versions, malformed later references and unavailable versions never
become empty successful work. Static diagnostics do not echo source contents.

`ObjectDiscovery` exposes immutable in-memory identity and the actual discovery
digest, not access authority. Native bucket ownerIdentity is a legacy canonical
retail identity, not the trusted owner account. Fetch must use authenticated
transport with exact version and expected bucket owner; actual capture bytes,
timeouts/cancellation, freshness and selected custody are separate runtime gates.
Declared object size is diagnostic; it cannot replace capture bounds. URL-like
fields never select an endpoint. Quarantine still blocks source ACK.

Context7's Amazon S3 index had no relevant notification detail; official fallback
[notification structure](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html)
and [delivery semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html)
confirm version comparison, form encoding and duplicate/unordered delivery.
Real AWS/IAM/trail configuration and digest qualification remain external.

Direct discovery has local acceptance with seven new focused tests, 468 workspace
tests, formatting, strict Clippy and 13-package guard. Independent review has no
blocker/high. Evidence: `target/goal-execution-20261007/AWS-DELIVERY/discovery-validation.json`
and `discovery-independent-review.json`. Capture/delivery remain in progress.

## Exact version capture and owned preparation

`CaptureTransport` is an authenticated application-owned stream seam. It must
bound headers, request the exact key/version with expected bucket owner, preserve
compressed bytes, avoid untrusted redirects and cancel owned I/O when dropped.
It supplies the actual response version; copying request metadata is insufficient
source proof. Credentials, SigV4/STS and provider deployment are separate adapters.
The helper does not select endpoints or derive authority from native content.

`capture_object` compares the immutable discovery binding with fresh trusted
application input before opening, checks response version and bounded ETag,
then reads to actual EOF in bounded chunks. Empty/over-8-MiB captures fail; the
notification's declared size is diagnostic. Each open/read uses one finite
cancellation/deadline context. Typed denial/missing/restore/throttle/outage/read
errors retain source responsibility without producing M1 or source ACK. There is
no retry loop or new background worker; caller bounds active invocations/captures.

`publish_capture` rechecks fresh binding and preflights bounded pins before the
existing capacity-one receipt worker prepares and atomically publishes. Its
physical owner survives lost callers. Capture identity/digest cannot be replaced
through caller original metadata. Known replay compares full trusted scope,
bucket/key/version and exact compressed bytes before reusing retained preparation,
progress, IDs, times and fingerprint. Changed bytes under that identity fail
closed; another version/object holds as occupied, never evicts. Replay does not
rerun normalization. Source capture before publication has no durable local
receipt and keeps source replay responsibility. No stronger custody is implied.

Capture/publication has local acceptance: eight capture regressions plus one
inherited-description lock regression, 477 workspace tests, zero failures and
independent source review. The acquired OwnerLock explicitly unlocks only when its
physical owner ends, including opening-error paths. Caller loss cannot release a
live worker lock. Retained alias reproduces the former lock-after-exit defect.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/capture-validation.json`.
Delivery/replay/queue simulation remains runnable; no source ACK in this substep.

## Retained batch publication

`ReceiptReplay::batch` copies exact retained event bytes into the schema-v1 batch
envelope without reserialization. Count and complete-body byte bounds are selected
before allocation; an event that cannot fit holds work. Defaults match current
ingest configuration (1,000 events, 1 MiB); the caller must align remote limits.

`publish_receipt_batch` executes one request per invocation under fresh trusted
binding, with no retry loop or task spawning. The application-owned publisher
authenticates its endpoint, prevents untrusted redirects, bounds streamed responses
and cancels owned I/O. Response schema/counts/ordered IDs use the shared admission
verifier for retry classification and the physical store independently verifies
the actual response before atomic prefix progress. Lost/denied/oversized/malformed
responses never create phantom admission. Timeout/cancellation may race remote
admission; replay the retained suffix. An empty suffix, including quarantine,
does not authorize source ACK. Current history and selected custody remain separate.

Retained publication has local acceptance: eight new tests, 485 workspace tests,
zero failures, strict Clippy/format/boundary gates and independent source review.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/publisher-validation.json`.
Network/source-queue simulation remains runnable.

## Configured HTTP publisher

`HttpReceiptPublisher` implements the publisher seam for the existing ingest API.
It accepts a bounded configured HTTP/HTTPS base or exact batch endpoint, rejects
userinfo/query/fragment/foreign paths and unsafe/oversized token headers, marks
Authorization sensitive and never formats transport errors with endpoint/content.
It matches the agent's explicit no-proxy/redirect-none policy, disables automatic
response decompression and bounds its idle pool. Context covers connect/send/body
reads; actual response bytes are capped at 64 KiB irrespective of Content-Length.
A bounded extra request-body copy is retained while the request is active.

The SDK consumes already locked reqwest 0.12.28 via a new direct edge. Context7
documents redirect-none, no-decompression methods and incremental Response::chunk;
the actual 0.12.28 sources confirm those APIs. Local TCP tests exercise exact batch
and Authorization, declared/chunked overflow, redirected destinations receiving
neither body nor token and cancellation dropping a stalled response socket. This
does not establish mTLS, actual AWS endpoints, source queue ACK or production trust.

HTTP transport acceptance: four actual TCP regressions, 489 workspace tests,
formatting, strict all-target Clippy, 13-package guard and independent review
without blocker/high. Evidence:
`target/goal-execution-20261007/AWS-DELIVERY/http-publisher-validation.json`.

## Reproducible delivery simulation

Run `cargo test -p signal-server --test cloudtrail-delivery --locked --offline`.
The loopback S3/SQS subset has bounded requests/responses and explicit local
credentials, exact version/expected-owner checks, throttling/denial/outage modes,
logical visibility expiry, current/stale handles and uncertain deletion. It is
an integration-test adapter, not an AWS SDK client or cloud authentication proof.
The existing primitives drive exact capture/M1/publication/recovery/ACK against
the actual server binary. A real storage-create failure and restart expose the
M2 versus processing distinction; duplicate replay preserves pinned identities.
Production collector orchestration remains the next bounded substep.

Three tests and all workspace checks pass: 492 tests, zero failures; focused
source review has no blocker/high. Emulator shutdown timeout cleanup is resolved.
An existing 32 MiB structural-size test now uses the same finite 30-second test
budget as the exact-ceiling case, with expired/cancelled checks unchanged.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/delivery-simulation-validation.json`.
This does not qualify real AWS, independent custody, account/host loss or source
completeness. Source object bytes remain retained after deleting queue deliveries.

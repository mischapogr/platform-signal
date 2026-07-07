# CloudTrail delivery and local simulation

AWS-DELIVERY is passed_simulated in the frozen execution ledger. One reference
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

## One-poll collector driver

`collect_delivery` composes `SourceQueue`, `CaptureTransport`,
`HttpReceiptPublisher` and trusted `DeliveryPolicy` with the physical receipt
store. One call receives one delivery, captures one exact version, prepares M1,
sends at most one batch and attempts ACK only after full verified M2. No retry
loop or new service is introduced. Application code owns retry/backoff, aggregate
concurrency, credentials, current history reconciliation and configured custody.
Quarantine/stronger-custody/multi-reference ACK remains blocked. Errors can race
remote effects: reopen/reconcile and receive a fresh handle, never reconstruct a
ticket. `DeliveryStep::Settled` plus `SourceAckState` reports stored confirmed or
uncertain response handling, not proof of physical deletion or no redelivery.

`publish_pinned_receipt_batch` checks the published receipt identity in the same
replay used to form the batch, and the driver checks it before ACK replay. The
store's atomic control comparison protects later awaits. An authorized concurrent
retirement/replacement therefore cannot substitute another receipt under the
same binding. The two-seam regression fails before and passes after this review
correction; no alternate source delivery is accidentally acknowledged.

Seven SDK regressions and one additional real-server driver test pass with all
workspace acceptance: 500 tests, zero failures, independent review resolved.
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/driver-validation.json`.
At driver acceptance signed AWS transport still needed local qualification;
its later acceptance appears below.
actual AWS/permission/source-completeness and independent custody gates remain
external or separately planned. The fixture coordinator is not a restore witness.


## Optional signed AWS source transport

Enable `signal-collector-sdk`'s `aws-source` feature for `AwsSourceClient`.
`AwsSourceConfig` pins a commercial queue ARN/owner, queue URL, S3 region/endpoint
and finite visibility. `AwsCredentialsProvider` supplies bounded current
credentials for each request; credentials must outlive the remaining operation
budget. The adapter does not discover credentials or assume roles automatically.
One invocation issues one request with no retry loop. Application code owns
AssumeRole/STS/provider acquisition, aggregate concurrency and polling cadence.

SQS uses the AWS JSON ReceiveMessage/DeleteMessage targets and requests one
message. Replies are capped at actual 2 MiB before bounded decoding; Body stays
at 256 KiB, ID at 128 bytes and ephemeral handle at 16 KiB. Malformed/duplicate
JSON, multi-message replies, known error envelopes, denial/throttle/outage and
expired credentials never become idle success. Delete checks the ticket's full
binding before I/O and caps the actual reply at 64 KiB. Only 200 with an empty
body is confirmed response handling; stale-handle success and later redelivery
remain possible. Source errors leave physical intent recoverable, not confirmed.

S3 requests exact key/version and expected owner with path-style HTTPS, streamed
bounded original bytes and actual response version. It rejects URL-lossy key
segments/control bytes and invalid AWS bucket spelling before credentials.
Explicit AWS URI byte encoding preserves key slashes/repeated separators and
encodes reserved/UTF-8 bytes and version query values. Generic URL encoding is
insufficient, as the retained before-fix regression demonstrates. Source restore,
throttle, permission, missing-version and outage errors hold work. Redirects,
proxy lookup and automatic decompression are disabled. Numeric-loopback HTTP
requires an explicit test-only opt-in. Signing traces are locally suppressed;
credentials, payloads and receipt handles are never formatted in errors/logs.

Amazon's official signer is optional; no existing locked package version is
replaced. The declared Rust minimum now equals the already pinned 1.94.1.
The server forwards the feature for integration qualification; this adds no
collector startup mode, credentials or private configuration to the monolith.

```bash
cargo test -p signal-collector-sdk --features aws-source --locked --offline aws_tests
cargo test -p signal-server --features aws-source --locked --offline --test cloudtrail-delivery
cargo test --workspace --all-features --locked --offline
```

Eleven SDK regressions and one additional signed-source/real-server test pass;
default 500/all-feature 512 workspace tests, formatting, strict Clippy, package
guard and independent source review all pass. CI now includes optional features.
The independent wire witness also matches the [published AWS GET vector](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html).
Evidence: `target/goal-execution-20261007/AWS-DELIVERY/signed-transport-validation.json`
and `signed-transport-independent-review.json`. This is synthetic local protocol
proof, not actual AWS signature acceptance, TLS/IAM/KMS/permissions, source
configuration/digest/coverage or host/account-loss custody qualification.
Continue COVERAGE-OBSERVERS without closing EXT-AWS or the evidence-plane item.

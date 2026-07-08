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

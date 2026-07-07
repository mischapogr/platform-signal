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

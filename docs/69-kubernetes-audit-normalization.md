# Kubernetes audit normalization

Status: implementation slice, 2026-10-24. Part of EKS-AUDIT; live EKS delivery,
local Kubernetes capture, durable transport/replay and baseline rule integration
are separate acceptance. AWS qualification is deferred by the owner.

## Pure projection contract

`signal_collector_sdk::kubernetes_audit` accepts one `audit.k8s.io/v1` Event,
not an EventList, node log, webhook envelope or CloudWatch notification. The
application binds trusted cluster identity and audit-policy revision; records
cannot choose them. Caller-pinned event ID and observed time must be retained
across retries. No I/O, queues, clock reads, random IDs or grants are introduced.
Original bytes are borrowed with their SHA-256; the caller must retain protected
originals and transport position. Hashes do not authenticate source or coverage.

Input is limited to 256 KiB, depth 24 and 16,384 JSON nodes before child allocation,
using the existing strict decoder; duplicate keys and trailing JSON refuse.
Selected identity strings are limited to 256 bytes. Output contains selected
metadata, never request URI, tokens, annotations, groups, request/response bodies
or free-form status messages. Original sensitive bodies belong in separately
protected evidence storage. Parser errors contain static text only.

Preserve audit ID, stage, audit level, verb, authenticated and impersonated actor,
object reference, both native timestamps, status code, trusted cluster/policy
revision and profile revision. Event timestamp is stageTimestamp; native time
must not precede requestReceivedTimestamp. Do not use observed time as event time.
Different stages are distinct records; no deduplication or cross-stage merge is
performed. Original audit ID + stage + trusted cluster can inform a future durable
identity mapping; this helper does not allocate or persist that mapping.

## Conservative workload interpretation

Only core-group pods without subresources and create/update/patch verbs receive
`security.action=k8s.workload.write`. Successful writes require ResponseComplete
with a 2xx response. HTTP errors are failure; request, panic, missing status,
redirects and other stages stay unknown. No streaming-exec success inference.

`security.privileged` is present only for a successful RequestResponse event with
a versioned Pod response body matching objectRef name/namespace and UID (when
provided). Require a response UID and a nonempty containers list. Inspect containers,
initContainers and ephemeralContainers. Explicit true in any valid container is
privileged; absent securityContext/privileged defaults to false. Malformed entries,
duplicate names or nonboolean privileged make the whole spec indeterminate.
Dry-run query flags (including percent-encoded keys) suppress admitted-state
projection; the response can describe an object that was never persisted. The URI
is inspected up to 8 KiB and never copied to output. Request bodies never establish
admitted state; Metadata/Request level, missing or mismatched response bodies and unsupported workload types cannot report false.
This is a Pod-only projection, not complete pod security policy evaluation.

Kubernetes documents RequestObject as pre-admission and ResponseObject as the
returned object; Metadata omits both bodies. Stage definitions and API fields:
[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/),
[audit v1 API](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/).
[API dry-run semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run).
Consulted through Context7 on 2026-10-24.

## Acceptance and next slice

Focused native fixtures cover successful/denied/request-only/Metadata/mutated
pods, container types, identity mismatch, malformed/duplicate/bounded JSON,
original preservation, pinned replay and stage separation. Workspace fmt,
strict Clippy, tests and dependency-boundary checks apply. This slice does not
complete EKS-AUDIT, D05/D07 baseline integration or local cluster acceptance.
Next: project original local Kubernetes audit records through this helper and
qualify native D07 positive/negative/indeterminate behavior plus transport replay.

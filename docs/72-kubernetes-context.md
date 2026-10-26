# Kubernetes context and node collection

K8S-CONTEXT, 2026-10-25. Remains incomplete until bounded metadata reconciliation,
scoped authenticated API collection, node-local logs and actual cluster churn are
qualified. Cluster coordination, node capture and control-plane audit are distinct
roles ([27](27-product-architecture.md)); no new service split is required.

## Collection model

The SDK foundation selects one trusted cluster/resource-kind/namespace/node scope
per reconciler. Supported resource schemas are core v1 Pod/Node/Namespace and RBAC
v1 Role/ClusterRole/RoleBinding/ClusterRoleBinding. Cluster identity is caller-owned;
native names, labels and provider IDs grant no authority. Each collection has its
own list/watch revision and generation. Resource versions are opaque bounded strings,
used only for equality and sent unmodified to the API.

Only selected metadata is projected: UID, name/namespace, resourceVersion, labels,
owner UIDs and references, Pod node/service-account/container identities, RBAC rules,
role references, subjects and aggregation inputs. Pod command/env/volumes, annotations,
status messages, credentials and unrelated native bodies are not retained. RBAC is
snapshot data, not an effective permission solver. Aggregated/unsupported authorizer
semantics must remain indeterminate in future STATE evaluation.

All pages of a list must use one collection revision and exact continuation token
sequence. Stage pages under a new epoch; publish only the final complete inventory.
Conflicting identities, changed list revision, repeated/foreign tokens, capacity or
malformed input invalidate staging and mark the prior complete inventory stale.
No partial list or capacity eviction establishes authoritative absence.

A watch starts only from a complete unexpired list. The transport must supply its
exact collection epoch and contiguous local sequence numbers for that one stream.
They do not come from native record claims. Exact last-frame replay is idempotent
without refreshing time; conflicting replay, gaps or old-session input refuse.
ADDED/MODIFIED/DELETED preserve UID lifecycle and refuse conflicting same-revision
projected bytes. A delayed delete for an absent old UID never removes a same-name
replacement. Bookmarks advance only the resume revision and stream sequence.
They neither refresh object observation time nor prove independent source health.

HTTP410, permission/transport failures, incomplete watches, malformed/over-budget
records or lost continuity require invalidation and a full replacement list.
List freshness is pinned at the original list start, not its late final page or a
later bookmark. Watch updates retain each changed object's original observation
time; they do not renew the age of unchanged objects or the whole inventory.
Expired/clock-regressed context cannot satisfy an authoritative lookup. Snapshot
exports retain original observation times and explicit freshness; no restoration
API silently renews authority. This foundation is in-memory only.

## Bounds and qualification order

Independent bounds cover input page/record bytes, JSON depth/nodes, pages, objects,
projected-object bytes, total inventory bytes and watch frames/cumulative bytes.
The strict existing decoder refuses duplicate keys before child allocation. Retained
and staged inventories coexist only within their separately declared finite budgets.
Expose occupancy/capacity and rejection/invalidation counters. No implicit eviction,
background worker, queue, clock read, API operation or credential acquisition occurs
in the pure foundation.

Next add scoped list/watch transport using explicit TLS trust, token ownership,
original deadlines/cancellation and existing bounded DNS/client mechanisms. Then
qualify actual local Kubernetes updates, same-name recreation, RBAC changes and
read-only service-account permission denials. Bind API origin/trust/selector to the
collector's configuration, not native claims. Do not claim complete audit health
from metadata connectivity.

Node collection must separately use a bounded, non-escaping rooted `/var/log/pods`
strategy. Existing `O_NOFOLLOW` on a final file is insufficient for discovered
parent paths. Do not weaken it to follow `/var/log/containers` symlinks. Bound every
examined entry/file/worker and map cluster+PodUID+container/restart identity. Qualify
actual CRI stdout/stderr/partial framing, rotation/deletion, source-cursor/spool
recovery and read-only hostPath/permission denial on an owned local cluster.

Foundation regressions and independent review precede frozen workspace acceptance.
Full item acceptance additionally requires the API/TLS/scoped-permission/churn and
node-local campaigns above. Local Kubernetes is not AWS/EKS qualification. D08/D09
state evaluation and historical classification are later STATE work; today's
snapshot cannot classify an older audit event without valid historical evidence.

Kubernetes consistency and bookmark semantics were fetched through Context7:
[API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/),
[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/).

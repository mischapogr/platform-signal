# Owned Kubernetes context API qualification

This gate exercises the SDK authenticated context client against a disposable
local kind API server. It does not qualify node-local CRI discovery/collection,
AWS/EKS, production source coverage or release readiness.

`scripts/check-kubernetes-context.py` creates a uniquely named cluster using the
pinned node image and an isolated temporary kubeconfig. Two service accounts
separate namespace Pod/Role/RoleBinding reads from cluster Node/Namespace and
ClusterRole/ClusterRoleBinding reads. Both have only get/list/watch on their
selected resources. Explicit Bearer tokens, CA and bridge configuration remain
in a private temporary directory and are removed on exit. Tokens never enter
argv, reports or source. The bridge uses the production SDK collector directly;
admin kubectl creates and changes only the owned fixtures.

The two fixture Pods name nonexistent nodes, so their containers never run.
Actual API objects still have native UIDs and revisions. The native bridge lists
all seven selected kinds, checks actual permission and invalid-token refusals,
filters Pods by node, watches Pod label change/deletion/name recreation, watches
selected Role rules and RoleBinding subjects change, invalidates on watch drop
and relists. Namespace permission revocation must refuse a fresh API list while
retaining the original inventory as nonauthoritative history. The harness also
uses the actual namespace token to require HTTP403 for another namespace,
Secrets, Pod creation/patch/logs/exec. It compares selected native UID and changed
RBAC fields to admin observations; kubectl output alone does not accept the SDK.

Readiness markers precede watch establishment. Changes during establishment are
recovered from the completed list's resourceVersion, avoiding a header-flush
handshake dependency. Every request, marker wait, subprocess and bridge has a
finite timeout. Bridge markers publish atomically. Cleanup first terminates and
reaps an active bridge, then deletes only the attempted owned cluster and checks
that its name and labelled Docker nodes are absent. No caller kubeconfig is used.
The credential directory is removed by its temporary-directory owner even on
failure. Reports retain source/binary identities and explicit cleanup status. Bounded raw
selected-resource lists from the owned cluster are retained for schema evidence;
no Secret or token response is captured. HTTP redirects are refused before any
credential forwarding. Cluster deletion is attempted even if bridge reaping fails.

Run the seven ownership/failure regressions with:

```bash
python3 scripts/test-kubernetes-context.py
cargo test -p signal-collector-sdk --test kubernetes-context-live --no-run
python3 scripts/check-kubernetes-context.py --bridge <compiled-test-executable> --output target/<new-owned-campaign>
```

The ignored bridge is not proof until explicitly executed with the exclusively
owned cluster and retained campaign report. Existing native unit tests qualify
pagination, malformed/expired streams, byte limits and TLS failures separately;
this small cluster gate does not claim actual paginated lists or forced etcd
compaction. Full K8S-CONTEXT still needs node-local collection and recovery.

Native typed lists omit per-item apiVersion/kind. Only a missing field inherits
the exact validated outer list type; explicit null/conflicting item values refuse.
Watch objects still require their explicit types. The initial failed native
campaign and bounded captures retain this correction evidence.

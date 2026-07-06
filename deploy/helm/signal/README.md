# PLATFORM::SIGNAL Helm chart

This chart deploys one monolith with one persistent filesystem store. The schema
requires `replicaCount: 1`; `Recreate` upgrades stop the old writer before starting
the new writer. Upgrades and node disruptions therefore cause downtime. Do not
scale the Deployment or mount its store in another running server.

```sh
helm lint --strict deploy/helm/signal
helm template signal deploy/helm/signal
helm install signal deploy/helm/signal --namespace signal --create-namespace \
  --set image.repository=YOUR_REGISTRY/platform-signal \
  --set image.tag=YOUR_VERIFIED_TAG \
  --set auth.existingSecret=signal-auth \
  --set rules.existingConfigMap=signal-rules \
  --set 'rules.keys[0]=login-failure.yaml'
```

Create `signal-auth` separately in that namespace with an `api-token` key. The
chart reads it through `SIGNAL_API_TOKEN` and never renders a token value. Without
`auth.existingSecret`, API admission is anonymous. Keep the ClusterIP private and
configure authentication before making it reachable outside trusted clients.
Rules are disabled by default; create an external ConfigMap from your rule YAML
files, and list their keys in `rules.keys`. Config and rule files mount through
`subPath` as regular files because the server rejects symlinks; changes become
visible after a controlled restart. The public example is `rules/examples/login-failure.yaml`. Identity,
policy and deployment values for an organization belong in its external overlay.
Secret and external rule changes require a controlled Deployment restart; the
chart-owned server ConfigMap gets a checksum annotation on Helm upgrades.

`persistence.storageClass` defaults to the cluster's default dynamic provisioner.
The created ReadWriteOnce PVC is retained on Helm uninstall: archive or explicitly
remove it only when its data is no longer needed. Reinstallation can use
`persistence.existingClaim`. Storage-class choice, expansion, retention, backup,
restore and disk monitoring are operator responsibilities. Server storage/WAL/
findings caps in `limits` bound application usage; size the volume for all three,
plus filesystem overhead. This chart uses filesystem Parquet only.

The process runs as 65532 with a read-only root, dropped capabilities and bounded
128Mi `/tmp`; its data mount is writable. `fsGroup` permits access on supporting
CSI drivers. Probes use `/readyz` and `/healthz` on the API port; metrics have a
separate named port. Requests and limits are configurable. Graceful shutdown gets
30 seconds for the server's 10-second admission/flush shutdown budget.

The optional PDB defaults to disabled; when enabled, `maxUnavailable: 1` permits
single-pod node maintenance. Setting it to zero blocks voluntary evictions while
the sole replica is healthy and still cannot provide high availability.
ServiceMonitor is disabled unless the Prometheus Operator CRD is already installed;
set its labels to match the operator's selector. Affinity, topology spread,
node selectors and tolerations are optional scheduler inputs.

## Local Kubernetes gate

With a freshly built local image, Docker and checksum-verified Helm 3.19.0,
kind 0.30.0 and kubectl 1.34.0 installed:

```sh
python3 scripts/install-kubernetes-tools.py
python3 scripts/test-kubernetes-gate.py
python3 scripts/check-kubernetes.py --image platform-signal:phase8 \
  --helm target/kubernetes-tools/helm --kind target/kubernetes-tools/kind \
  --kubectl target/kubernetes-tools/kubectl
```

An external overlay values file can be exercised with `--values /path/to/values.yaml`.
Owned gate image, auth/rules references, PVC size and PDB settings override that
file. The gate creates an exclusively named kind cluster and temporary kubeconfig,
loads the specified image without pushing it, creates a temporary token Secret
and generic rules ConfigMap, verifies authenticated ingest/query/findings, kills
the container process with SIGKILL, verifies recovery, stops the replica and
waits for it to exit before starting a replacement pod, and
verifies the same PVC and canonical rows. It deletes only its own cluster on exit.
The node image is digest pinned from the
[kind 0.30.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.30.0).
This is local Linux architecture evidence; EKS and cross-architecture cluster
qualification need their own runs.

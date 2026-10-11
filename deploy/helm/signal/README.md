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
plus filesystem overhead. The default profile uses filesystem Parquet. Explicit
Standard selection retains the original WAL and query cache on this PVC; shared
metadata and immutable objects require separately provisioned dependencies.

## Explicit runtime configuration

`runtime.files` selects separately created Secret keys for `SIGNAL_SHARED_CONFIG`,
`SIGNAL_ACCESS_CONFIG`, `SIGNAL_COVERAGE_CONFIG` and `SIGNAL_AUDIT_CONFIG`.
Each key mounts read-only as a regular `subPath` file under `/etc/signal`, with
0440 permissions and the existing pod fsGroup. Only selected keys are projected.
Secret contents, identities, policy and deployment values belong in the external
overlay. The chart creates no runtime Secret, database schema or enrollment.

```yaml
runtime:
  existingSecret: runtime-config
  files:
    SIGNAL_SHARED_CONFIG: shared.json
    SIGNAL_ACCESS_CONFIG: access.json
  secretEnv:
    - {name: DB_PRODUCER_PASSWORD, secret: runtime-credentials, key: producer-password}
    - {name: DB_READER_PASSWORD, secret: runtime-credentials, key: reader-password}
    - {name: SIGNAL_IDENTITY_CLIENT_SECRET, secret: runtime-credentials, key: identity-client-secret}
    - {name: SIGNAL_S3_ENDPOINT, secret: runtime-credentials, key: object-endpoint}
    - {name: SIGNAL_S3_REGION, secret: runtime-credentials, key: object-region}
    - {name: SIGNAL_S3_BUCKET, secret: runtime-credentials, key: object-bucket}
    - {name: SIGNAL_S3_ACCESS_KEY, secret: runtime-credentials, key: object-access-key}
    - {name: SIGNAL_S3_SECRET_KEY, secret: runtime-credentials, key: object-secret-key}
```

This is a reference-only fragment, not a complete Standard deployment. The
operator supplies supported version1 documents, current scope/backend/catalog,
distinct least-privilege database roles and verified roots, matching credentials,
native HTTPS identity/probes, selected coverage and externally initialized
dependencies. Match the password environment names in the shared document.
Configure HTTPS object endpoints; loopback HTTP is an explicit laboratory option.
The server validates all selections before readiness and never initializes or
migrates shared metadata during startup. Use a qualified image with Standard
runtime and S3 support enabled.

Selecting `SIGNAL_SHARED_CONFIG` sets `SIGNAL_STORAGE_TYPE=s3` and the Standard
query cache to `/var/lib/signal/query-cache`.
`runtime.secretEnv` is bounded to16references, rejects duplicate names, reserved
process/logging variables, and overrides of chart-owned/config-selector settings.
Supported `SIGNAL_S3_*` references select the existing object adapter, and
`SIGNAL_IDENTITY_CLIENT_SECRET` supplies the native identity client credential. Other custom
secret variable names must not use the reserved `SIGNAL_` prefix. No environment
or credential values are rendered in the chart.

Perform a controlled restart after changes to external runtime Secrets.
Kubernetes [subPath Secret mounts do not receive updates](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod).
Single-replica `Recreate`, PVC ownership, resource limits and protected probes
remain required. Rendering this profile does not qualify its cluster runtime,
independent review, actual EKS/AWS custody or release readiness.

The process runs as 65532 with a read-only root, dropped capabilities and bounded
128Mi `/tmp`; its data mount is writable. `fsGroup` permits access on supporting
CSI drivers. Probes execute the existing `signal-agent --readycheck` or `--healthcheck` against
numeric loopback on the API port, with one original two-second client budget and
three-second kubelet supervision; metrics have a separate named port. Requests and limits are configurable. Graceful shutdown gets
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

For the owned Standard profile, first prebuild the all-feature server and exact
`standard_main` integration-test target outside the runtime deadline, and make
the local `python:3.13.5-alpine` fixture image available. Then run:

```bash
python3 scripts/check-shared-runtime.py --standard-only \
  --standard-kubernetes-image platform-signal:standard-local \
  --image postgres@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa \
  --output target/standard-kind-qualification
```

Use a freshly built S3-enabled server image at the supplied tag. This gate uses
explicit offline synthetic enrollment and coverage initialization, native TLS
probes, PostgreSQL TLS and bounded loopback identity/S3 sidecars. It retains the
original WAL, coverage and versioned fixture objects on the PVC, verifies both
server SIGKILL and serial pod replacement, and deletes its owned cluster and
database container. Synthetic services qualify the local profile only.

## Native authenticated probes

Set `tls.existingSecret` to a separately created Secret containing `server.json`
and `probe.json` (or override `serverKey`/`probeKey`). Each is the private version1
[transport document](../../../docs/44-transport-security.md), with distinct server
and probe leaf identities, explicit peer roots and optional signed CRLs. The
chart mounts these keys as read-only regular `subPath` files with0440 permissions
and pod fsGroup65532. Restart pods after changing either TLS document. Actual key contents never enter
values or rendered YAML. The server certificate must include `IP:127.0.0.1` SAN
for the local probe, as well as the intended external client DNS/IP names.

Missing/invalid probe credentials or expired/revoked/untrusted peers fail probes.
No HTTP, anonymous TLS, skipped certificate verification or sibling-pod fallback
exists. The probe identity does not assign API/RBAC grants and sends no API token.
Secret replacement is operator-controlled; restart the single server owner after
server identity/root changes. New probe processes read the selected current file.
A newer valid probe identity alone can be adopted between invocations when the
running server already trusts it. Rebuild older development images before using
the new exec modes.

With native TLS, enabling ServiceMonitor additionally requires
`serviceMonitor.tls.existingSecret` and `serviceMonitor.tls.serverName`. That
separate Secret in the ServiceMonitor namespace has PEM `ca.crt`, `tls.crt` and
`tls.key` keys (configurable). Its metrics identity must chain to the server's
explicit client trust; `serverName` must match the server certificate SAN. The
chart emits HTTPS with explicit CA/client certificate/key references and fails
rendering if TLS metrics credentials are missing. It never emits
`insecureSkipVerify`; the operator owns and restricts access to the metrics key.

Exec is used because Kubernetes' built-in HTTPS HTTP probes skip server
certificate verification; SIGNAL's native probe checks both peers instead.
See [Kubernetes probe documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/).
Local render/native/container checks do not replace actual kind/EKS qualification.

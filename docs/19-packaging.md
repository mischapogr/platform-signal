# Phase 8 — Packaging and qualification

For parser and measured pipeline reports from each already-built native image,
see [native qualification](22-native-qualification.md). CI runs this gate per
architecture and retains reports. Partial public native ARM64 Rust evidence
now exists; complete remote runtime qualification remains open. See
[OSS CI and cloud qualification](40-oss-ci-and-cloud-qualification.md).

The production image contains the monolith and edge agent. The public Helm chart
deploys one monolith with one writable data volume. Company values, rule content,
account mappings and environment identifiers belong in the separate overlay.
Current executed gates and remaining qualifications are recorded in
[implementation progress](07-progress.md).

## Native image and local Kubernetes checks

```bash
docker build -f deploy/docker/Dockerfile -t platform-signal:phase8 .
python3 scripts/check-container.py --image platform-signal:phase8 \
  --expect-architecture amd64
```

Run the native image check with `--expect-architecture arm64` on an ARM64 host
and Docker daemon. A manifest listing both architectures or an emulated run
does not establish native runtime proof. Each native CI runner builds and checks
its own image; configured CI is not evidence that a remote job ran.

See the [image instructions](../deploy/docker/README.md),
[chart instructions](../deploy/helm/signal/README.md), and
[supply-chain checks](18-supply-chain.md) for exact commands and dependencies.
The Kubernetes gate owns its temporary cluster and kubeconfig; it does not deploy
to an existing context or change global Kubernetes configuration.

## Filesystem and rollout contract

WAL, Parquet and findings share the persistent data mount. Configuration and
rule mounts are read-only. The pod runs as UID/GID 65532 with a read-only root,
dropped capabilities and no privilege escalation. Temporary files have a bounded
separate mount. Runtime event, disk and query budgets remain finite.

The chart requires a single replica and uses `Recreate`: another process must
not write the same WAL and stores concurrently. PDB and ServiceMonitor resources
are optional; enabling ServiceMonitor requires its CRD. Tokens are referenced
through existing Kubernetes Secrets, never embedded in Helm values. Retaining a
PVC prevents ordinary uninstall from deleting its claim; backup, recovery and
the storage class's volume reclaim policy need separate operational decisions.

## Existing EKS environment reference

EKS qualification requires an owner-authorized test cluster, namespace, image
location/digest, storage class, credentials, and private deployment values.
No cluster, IAM role, registry, storage class or cloud resources are created by
the local packaging gates. Keep those inputs in the private repository.

For an existing authorized environment:

1. Confirm the explicit kubeconfig/context identifies the intended test cluster.
2. Select a writable persistent claim or a storage class appropriate for that
   cluster. Standard EBS CSI and EKS Auto Mode use different provisioners;
   select the existing cluster's class. EBS volumes cannot back Fargate pods.
3. Render and lint the public chart with the owner-supplied external values.
4. Install in the authorized namespace with the qualified image digest, existing
   token Secret and private rules ConfigMap. Keep one replica.
5. Verify probes, authentication, event and finding queries, and the actual
   storage mount's permissions. Record pod/node architecture and image identity.
6. Exercise forced container restart and pod replacement, verifying exact event
   and finding identities persist on the same claim. Record cleanup ownership
   and preserve the owner's data and resources.

AWS documents the separate provisioners and Fargate storage restrictions in
[Use Kubernetes volume storage with Amazon EBS](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html).
ReadWriteOnce mounts allow one node; SIGNAL's single-writer requirement also
prevents simultaneous writers on that node. Storage scheduling must keep the
pod and zonal volume compatible; see
[EKS Auto Mode storage](https://docs.aws.amazon.com/eks/latest/userguide/create-storage-class.html).

Native ARM64, EKS, published artifacts, signing and the complete `v0.1.0`
qualification require their own evidence. Local packaging checks do not complete
those gates.

## Unpublished local candidate preparation

The owner-selected local kind 1.34 milestone and the current chart are the
approved local Kubernetes target; they do not qualify EKS or AWS storage. The
bounded development-candidate procedure is documented in
[local candidate preparation](23-local-candidate.md). Its 2026-10-07 preview
passed offline integrity, relocation/source-path-graph checks and four
packaged-chart checks (strict lint and default/optional renders). It preserves
the accepted runtime image without
building, pulling, tagging or publishing an image. This dev0 preview is not an
alpha or release artifact; native ARM64, actual EKS, remote CI, released
dependencies and the owner-held publication workflow remain open.

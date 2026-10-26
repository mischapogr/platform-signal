# Local Kubernetes audit and D07 gate

Bounded EKS-AUDIT qualification slice, 2026-10-24. Builds on the
[native projection contract](69-kubernetes-audit-normalization.md). Actual AWS,
EKS delivery and production audit-source health remain deferred and unqualified.

## Scope and ownership

`scripts/check-kubernetes-audit.py` creates one random-name kind cluster using
the pinned node image already used by `scripts/check-kubernetes.py`. It uses a
private temporary kubeconfig, never the caller's cluster context. API-server
file auditing is enabled only for Pod creates in three disposable namespaces;
all other resources have audit level None. The restricted namespace enforces
Pod Security admission. Fixture Pods have an intentionally absent nodeName and
imagePullPolicy Never; they exercise API admission without running workloads.

The fixture checks successful privileged/nonprivileged Pod admission, Metadata
without a body, server-side dry-run, a real denied privileged request and the
original RequestReceived stage of the successful request. Exact native JSON
lines are retained in a protected output directory with their hashes. Audit ID
and stage link native records; cluster identity and policy digest are supplied
by the gate. This is control-plane auditing, separate from node/application logs.

The Rust `kubernetes-audit` integration test projects these records through the
actual SDK and actual catalog D07 rule. Its normal test covers eight synthetic
positive/negative/indeterminate cases. The capture bridge is explicitly ignored
in ordinary tests: invoking it requires input/output paths and creates a new
projection file. Missing input, a stale existing output or a mismatched native
expectation fails; it cannot silently skip capture acceptance.

Gate-only IDs and observed time are pinned in the retained projection document.
They prove repeatability in this finite campaign, not a production source identity
allocator. Findings and canonical events are then sent to an actual Small server
through authenticated loopback HTTP. The gate waits for a CRC-valid, zero-drop
WAL checkpoint after persistence, SIGKILLs that server, restarts with its original
WAL/store/findings and redelivers the exact pinned canonical events. It requires
unchanged canonical bytes and one deterministic D07 finding; duplicate event
rows are permitted by at-least-once delivery. The checkpoint must advance by the
redelivered batch length. Shutdown must succeed.

## Running

Build current sources before using the compiled bridge and server:

```bash
cargo build -p signal-server --bin signal-server
cargo test -p signal-server --test kubernetes-audit --no-run
python3 scripts/test-kubernetes-audit.py
```

Use the integration-test executable path printed by Cargo for `--bridge`:

```bash
python3 scripts/check-kubernetes-audit.py \
  --bridge <compiled-kubernetes-audit-test-executable> \
  --server target/debug/signal-server \
  --output target/<new-owned-audit-campaign>
```

The output must be a new directory under repository `target/`. It retains native
records, selected capture/pins, projection, native bridge log, actual server
state/logs and source/binary-bound report. Kubeconfig credentials stay in the
temporary directory. Failed attempts retain a failed report. Deletion of the
exclusively owned cluster and absence of its Docker nodes are required on both
success and failure; cleanup failure prevents acceptance. No registry push,
external account, publication or production deployment runs.

## Evidence limits and continuation

This test-only bridge does not implement production file/object/webhook delivery,
source-position checkpointing or protection against caller pin reuse. It does not
establish complete resource/verb/cluster coverage, independent source health,
provider retention, EKS runtime or prolonged stability. Its raw activity is
synthetic; the Kubernetes API server, Pod Security admission, Rust projection,
predicate engine, Small process, WAL and restart are actual local components.
D05 remains covered by the existing CloudTrail path and is not a Pod audit rule.
Full EKS-AUDIT stays pending until the application delivery seam and remaining
item requirements are qualified. No whole ledger item is closed by this gate.

The kind audit configuration follows the current official
[kind auditing guide](https://kind.sigs.k8s.io/docs/user/auditing/) consulted through
Context7. The pinned image and fixture policy revision are retained in each report.

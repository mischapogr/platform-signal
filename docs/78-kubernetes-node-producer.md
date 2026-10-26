# Dedicated Kubernetes node producer

This contract composes the CRI, rooted filesystem and bound spool mechanisms
into the production agent. Full K8S-CONTEXT acceptance additionally requires
independent review, source-bound process checks, actual local node qualification
and the metadata/API requirements in contracts72–74. Evidence and acceptance
status are recorded separately in the execution ledger.

The dedicated `kubernetes-cri` mode takes explicit node-log root,node name and
cluster source name. It rejects mixed stdin/file/audit/syslog configuration and
uses the separately bound node spool profile with canonical512KiB capacity.
One retained physical worker owns rooted discovery,at most16 source slots/FDs,
bounded physical-line buffers and one immutable pending event/cursor. Tokio waits
have original deadlines/cancellation; dropped or timed-out callers cannot free
live physical work or spawn a replacement. Physical shutdown confirmation follows
root/FD/permit release and shares the runtime's original drain deadline.

Root preparation and profile binding precede spool opening. All saved cursor
identities are restored before sender polling. Discovery never renumbers old
slots. Matching uses logical runtime identity,device/inode,size and consumed-byte
offset anchor across active/plain-rotated candidates. Complete physical records
retain original P/F,stream,timestamp,CR and binary fragment bytes. A pending event
keeps its original ID/time until spool append/checkpoint and explicit commit.

Missing/compressed/changed/uncertain generations produce an explicit collector
gap event atomically with a terminal cursor before reuse. The collector event is
not fabricated application data or a source-coverage attestation. Unfinished
physical prefixes are retained as bounded base64 evidence; unknown dropped-record
counts are not invented. EOF alone is idle. Rotation drains the held old FD first,
then records uncertainty before transitioning to a new generation. Terminal
markers for still-present unchanged files remain reserved to avoid repeated gap
IDs or rereading an unchanged partial prefix. A changed/grown generation can be
read after that durable uncertainty decision.

`--once` freezes initial source-file cutoffs and reports only that finite slice;
later growth is left for a subsequent run. Concurrent disappearance during a
continuous discovery scan pauses source admission until a complete rescan; it
cannot establish absence from a partial scan. Hard capacity/unsafe filesystem
refusals remain fail-closed. Metrics expose only bounded aggregate occupancies,
capacities,scan/gap/refusal counts and logical/physical worker state.

Actual acceptance must use a running workload,read-only `/var/log/pods` hostPath,
nonroot permission refusal,churn/rotation and original SIGKILL/uncertain-ACK replay
on exclusively owned local kind. Legacy audit/file process regressions remain
required. Local AMD64/debug fixture images are not native ARM64,current production
image/CI,AWS/EKS or release qualification.

The local native fixture grants UID65532 the inspected node log-root group as a
supplemental group; it does not claim that an arbitrary nonroot process can read
host logs. Capabilities remain dropped, the hostPath is read-only, and a separate
fresh-process mode-000 source test must refuse before sending. The mount probe
must reach a writable target and observe EROFS, independently of directory access
permissions. Qualification must cover actual workload deletion, node-side source
absence, a durable gap and same-name recreation with a new runtime UID.

Runtime Pod UID remains an unverified kubelet path identity, not an automatic API
association. This mode does not implement historical state evaluation or prove
complete cluster log coverage. Use a dedicated spool: changing cluster, node,
namespace, physical root or decoding/discovery limits refuses prior state before
sending. All-namespace discovery is bounded by the same global source caps.

Example explicit configuration (API token supplied through the existing agent
environment variable):

```bash
signal-agent --server http://127.0.0.1:3000 --format kubernetes-cri \
  --node-log-root /var/log/pods --node-name example-node \
  --node-namespace example-namespace --source-name example-cluster \
  --spool-dir /var/lib/signal-agent/node-spool
```

The server must already be configured with matching authentication. `--once`
selects only the initial finite slice; omit it for continuous collection.

# Node-local Kubernetes container logs

K8S-CONTEXT remains in progress. This first slice defines the pure SDK source
identity and CRI normalization contract. Rooted discovery, agent/spool integration,
actual node collection and recovery must follow; a parser is not their acceptance.

## Source identity and trust

`kubernetes_log::LogIdentity` has schema_version1, namespace, Pod name, opaque
runtime_pod_uid, container and restart_count. It round-trips the kubelet-relative
`<namespace>_<pod-name>_<runtime-uid>/<container>/<restart>.log` identity. Namespace,
Pod and container use bounded Kubernetes name syntax; the complete Pod directory
is at most255bytes, container63bytes, UID128bytes and restart count u32 with
canonical decimal representation. Non-escaping opaque UIDs include the32hex
static-Pod form and hyphenated API-style values. No UUID equality is inferred.
Paths, controls, whitespace and unsupported component encodings refuse; bounds
are checked before cloning caller strings. Deserialization alone is not validation.

Cluster and node come from immutable `Profile` configuration. The canonical event
uses source type `kubernetes.container`, with selected versioned `kubernetes`
attributes. `pod.runtime_uid` is a runtime identifier, not an API Pod UID or
verified metadata association. API metadata matching must be independently
established by the host; a filename does not grant actor identity or source health.

## CRI framing and bounds

`normalize_record` accepts one LF-terminated native physical CRI record:

```text
RFC3339-timestamp stdout|stderr P|F payload\n
```

The three header separators are exact ASCII spaces. Payload bytes are preserved,
including leading/trailing spaces and CR. Embedded LF, missing terminator, unknown
stream/tag, invalid or out-of-range timestamps and leap-second representations
refuse. Valid offsets convert to UTC without changing the original timestamp
attribute. Observed time and event ID are caller-supplied original pins; nil ID,
out-of-range/leap observed time refuse. Replay with the same pins is byte-identical.

Every physical record produces its own canonical event. `log.framing` explicitly
says `cri_physical_record`; `log.tag` preserves P/F. F can finish a prior partial
record, and is not proof of a reconstructed whole message. There is no volatile
logical-message assembly. This permits atomic physical-cursor/event admission
even when stdout and stderr interleave. UTF8 payload appears exactly in message;
invalid UTF8, including a split multibyte character, uses lossless payload_base64
with a null message. A SHA256 covers the original physical record including LF.
Severity remains Info; stderr alone is not an application error classification.

Native records are bounded to64KiB; canonical events are independently checked
through a bounded JSON writer against512KiB. Base64 expands binary payloads and
JSON escaping can expand control bytes sixfold. The node agent must therefore
validate event, spool record/envelope and batch capacities for the canonical
ceiling. It must not inherit the existing64KiB event default and silently skip
otherwise valid node records. Near-limit binary/control/quote/backslash tests
exercise this expansion. The SDK neither advances a cursor nor performs I/O.

## Required following integration

The node producer must use a trusted `/var/log/pods` root and FD-relative opens
that prevent symlink/parent traversal on every discovery and rotation. Ordinary
file and audit modes keep their current semantics. Bound all inspected entries,
depth, selected files, FDs, retained workers, buffers and pending records. A failed
or capacity-limited scan cannot establish absence or silently retire a source.

Persist typed source identity in the cursor with a separate immutable root/cluster/
node/config binding. Restore source slots from durable state before discovery;
never use current sort order. Reuse only an absent, drained source with no pending
uncommitted record, or an explicit counted source gap. Existing spooled event
identity remains pinned during slot reuse. Recalculate cursor/envelope/state and
metadata temporary-file reserves; preflight prospective state before append so
admission cannot create a record whose cursor state cannot later be acknowledged.
Retain compatibility and quotas for existing non-node spools.

Actual acceptance still needs rooted traversal/symlink/FIFO and permission
refusals, changed discovery order, profile drift before sends, sixteen maximal
cursors, CRI partial/binary preservation, rename/copy-truncate/deletion/slot reuse,
SIGKILL under uncertain ACK with exact replay, empty restart, and real read-only
hostPath collection from a running workload on an exclusively owned kind cluster.
Neither this source identity nor API connectivity proves complete source coverage,
AWS/EKS behavior, native ARM64/current CI or release readiness.

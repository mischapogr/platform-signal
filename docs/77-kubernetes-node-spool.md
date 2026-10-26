# Durable node source cursors and spool profiles

This slice prepares the spool for the later node producer. It does not activate
node collection or close K8S-CONTEXT. The CLI and existing file/audit/syslog inputs
continue using the legacy profile until dedicated node configuration is wired.

## Durable profile and source identity

`SpoolConfig.cursor_profile` defaults to Legacy. Its state version1, absent optional
JSON fields,16KiB metadata reserve,8180byte state limit and640byte record/cursor
allowance remain unchanged. Existing bound audit cursors are still legacy cursors.
Both outer input validation and direct input-reader startup refuse typed node
cursors even if their source_binding happens to equal the legacy input binding.

`KubernetesNode` instead requires an explicit32byte source-profile binding. The
future node worker must derive it from immutable root/cluster/node/config and
physical root identity before opening the spool. State version2 persists that
exact binding even for an empty spool, before first admission. Mode or binding
mismatch refuses before recovery deletes temporary, acknowledged or torn-tail
files. Opening a node spool with another configuration cannot rebind old events.

`SourceCheckpoint.source_identity` is an optional versioned NodeSourceIdentity:
SDK LogIdentity, a safe bounded generation basename and optional finite terminal
disposition. It is omitted from legacy JSON. File names must derive from the same
canonical restart count and satisfy the rooted basename rules. Namespace and
opaque runtime UID remain distinct from verified API metadata. Node cursors also
require the exact profile hash and an anchor no longer than the offset. A terminal
marker describes a later producer's drained/gap decision; the spool does not
invent that decision or classify coverage from stored metadata.

Node append requires a typed bound cursor. Cursor-only checkpoints, recovered
state and every retained record validate profile and identity, including older
records whose cursors are not applied during replay. Historical slot identities
may differ from the current occupant: original canonical events retain their own
source metadata. The original state.next_sequence cutoff is fixed through the
replay pass, so older records cannot rewind a newer cursor-only slot replacement.

## Independent capacities and prospective state

Node mode reserves64KiB metadata,32756byte state and1536byte record/cursor
overhead. Both state and temporary-state frames fit within that metadata charge.
The event limit must be at least the SDK512KiB canonical ceiling, and batch capacity
must include the configured event bytes plus the sender's fixed/comma allowance.
Minimum disk quota includes metadata, event capacity, cursor allowance and frame.
Legacy minimal quotas and serialized state are preserved.

Before any append creates a record, the engine clones the complete prospective
state, advances next_sequence, replaces the cursor and validates/encodes the
result. It reserves maximal decimal ACK/sequence growth rather than only current
digits. Only after successful durable record admission does that exact state
become current. Thus admission cannot create a record whose state later fails
solely because ACK grew longer. State persistence uses the same checks for
cursor-only checkpoints and ACK. Actual Rust tests exercise sixteen maximally
escaped identities,64byte anchors,maximal scalar values,full record envelopes,
large binary/control payloads,minimum quotas and final sequence overflow.

Recovery validates the configured profile and retained records before committing
cleanup. It stages only bounded sequence numbers and one temporary-file flag,
not full directory paths per record; the allowed record count bounds this memory.
An incomplete uncommitted final record can still be discarded. Complete corruption,
foreign historical profile or invalid prospective state refuses without deleting
pending or temporary evidence. This is local fsync/restart proof, not power-loss
or physical filesystem block accounting.

## Following integration and acceptance

A dedicated retained node worker must still restore slots from durable identities,
perform descriptor-relative discovery and match generation using device/inode,
size and offset anchor. Reordered discovery must never allocate replacement slots
from current sort positions. Incomplete scans, missing/compressed/ambiguous unread
generations and uncertain rotation need explicit durable gap/refusal; no silent
reset. Root preparation precedes spool opening so the binding is known before any
backlog forwarding. Original ID/time pins stay pending until atomic spool admission
and explicit input commit. Reuse does not relabel historical pending events.

Read-only hostPath collection from a running owned kind workload,permission denial,
churn/rotation/deletion and SIGKILL/uncertain-ACK/exact replay remain mandatory for
whole node and K8S-CONTEXT acceptance. Existing ordinary/audit process regressions
must remain passing. AWS/EKS,current native ARM64/remote CI and release decisions
remain separate. See [75](75-kubernetes-node-cri.md) and
[76](76-kubernetes-node-root.md).

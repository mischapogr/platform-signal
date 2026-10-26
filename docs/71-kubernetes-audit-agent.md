# Kubernetes audit file delivery through the agent

Bounded EKS-AUDIT application slice, 2026-10-25. Uses the existing
[agent spool/cursor contract](15-phase6-agent.md) and
[native normalizer](69-kubernetes-audit-normalization.md). Actual AWS and EKS
transport remain deferred.

## Configuration and supported input

`--format kubernetes-audit-json --source-name <cluster> --audit-policy-sha256 <hex>`
selects the dedicated file mode. Require at least one explicit regular-file input;
stdin and mixed formats/profile flags refuse. The policy digest is exactly 64 hex
characters, normalized to lowercase. Source type is fixed to `kubernetes.audit`;
cluster and policy come from trusted configuration, never record annotations.
This digest identifies the operator-selected audit policy, not source authority.

This agent accepts native Event JSON lines up to its existing 64-KiB line ceiling,
a supported subset of the SDK's 256-KiB cap. Existing bounded parser/line/event
limits, oversized/malformed rejection counters and durable skip cursors apply.
No raw body, URI or token is added to projected events. Protect and retain the
original audit files independently; the spool contains derived canonical events.

## Durable identity and profile binding

The input worker creates ID/observed_at once in its pending record. Existing
spool admission atomically syncs canonical event and next file cursor before the
input worker commits. Quota retry reuses that pending record; uncertain HTTP ACK
and process restart replay the exact spooled canonical bytes. A crash before
spool admission may reparse with a new ID because no event was delivered yet.
No second identity journal or auditID-based exactly-once claim is introduced.

New-mode file cursors carry optional `source_binding`, a 64-character lowercase
SHA-256 of a versioned domain, input slot, absolute lexical path, line limit,
configured cluster and policy digest. Binding is checked against every persisted
cursor before any producer or sender future runs. Changing/removing/reordering a
bound source, changing its profile/line limit or switching parser modes refuses;
using this mode with an old unbound cursor also refuses. Use a separately owned
fresh spool after explicitly draining/retaining an old configuration. Never delete
pending spool records to bypass a refusal. Matching bindings do not weaken inode,
anchor, truncate or rotation checks.

The optional field defaults absent and is omitted for existing modes. Existing
unbound serialized cursor bytes remain unchanged. Old binaries reject bound
cursor fields rather than reinterpret them. This is an additive v1 spool format
extension, not a released-to-released upgrade guarantee. Cursor+record reserve
increases from 512 to 640 bytes; 16 worst-case bound cursors still fit the existing
state ceiling. Capacity validation must include the larger reserve.

Rotation/copy-truncate retain existing at-least-once reset behavior. The agent does
not discover an old rotated path after restart. Source retention/independent
coverage remain operator responsibilities, not inferred from delivery success.

## Acceptance

Qualify config/binding refusal, pending-record pin reuse, bound cursor persistence,
worst-case state/record capacity and native D07 event projection. Compose the real
agent with retained actual kind capture records, a loopback HTTP uncertainty
proxy and actual Small server. Force agent SIGKILL after forwarding a request
whose successful response is withheld; restart with the original spool and file.
Require exact pending event IDs/bytes, original finding IDs, file cursor resumption,
durable rejected-line progress, backlog-before-new-input ordering and cleanup.
Run focused agent regressions, existing agent process gate and frozen workspace
fmt/strict Clippy/tests/boundary checks. Source/review drift invalidates acceptance.
Local AMD64 proof does not qualify current native ARM64/CI, provider custody,
complete audit coverage or AWS/EKS deployment.

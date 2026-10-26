# Scoped historical state detectors

STATE implementation contract. Supported targets are D04/D06/D08/D09/D13;
D12 remains explicitly unsupported until AWS-PROFILES supplies database audit.
Complete all five before claiming the ledger item. Existing YAML and Finding
contracts remain unchanged; no new service or universal permission solver.

Source projections use separate opt-in state profiles. Legacy CloudTrail and
Kubernetes normalization retain their original bytes/semantics. The new profiles
select IAM actor/target identities and mutation names, RBAC writes and endpoint-
specific exec acceptance. No credentials, raw request/response bodies or command arguments are copied
into canonical projections; native originals remain separately owned custody. Effective identity under impersonation is an explicit host choice.
Runtime privilege and executable content/provenance come from process-specific
trusted state, never a path, PID or unsigned event claim.

The consuming host freshly authenticates source, identity authority, permissions,
coverage and private state. Non-deserializable trusted contexts are separate from
serializable retained evidence. A persisted snapshot or assessment never renews
authority. Bind exact canonical input/source, actor, target/locator, native change,
scope, state/policy revisions and original validity intervals. Missing/ambiguous,
stale, conflicting or unsupported evidence returns indeterminate plus an explicit
gap. Approval absence requires a complete authoritative scoped inventory.

D04 looks up event-time approval for credential creation. D06/D08 compare complete
before/after grants against approved additions, not operation names alone. The
initial IAM model is a finite literal permission universe with explicit absence
or supported accounting of restrictions. Conditions, wildcards, deny/NotAction/
NotResource, unresolved groups, boundaries, SCP/session policies are unsupported.
Initial RBAC supports literal resource grants/direct subjects/role references in
an explicit namespace universe. Aggregation, wildcards, nonresource URLs,
unresolved references or additional authorizers remain indeterminate.

D09 joins historical workload sensitivity and operator permission by trusted
cluster, actual API UID and actor at accepted-session time. A missing native UID
requires a complete authoritative historical locator-to-UID resolution; names or
current labels alone cannot supply it. D13 joins immutable host/boot/PID/start and
native execution identity to historical executable digest, privilege, approval
and provenance. State must cover the operation time, not merely its later arrival.

All input strings, nested canonical input, state entries/grants/history, output
bytes and retained journal state have finite caps. Use the caller's original
deadline/cancellation throughout. Retain original input/evidence and exact output
bytes atomically with checkpoint in the existing state_journal. Publish original
outbox bytes before retirement/ACK; after uncertain commit reload rather than
recompute. Newer policy cannot replace an original committed assessment/finding.

Acceptance requires the fifteen supported catalog outcomes, explicit D12 refusal,
native source composition, event-time/revision/identity reuse/mismatch cases,
unsupported IAM/RBAC semantics and independent approval versus unknown absence.
Prove cancellation/budgets/overflow without partial output and actual crash or
lost-commit replay after newer policy arrives. Local synthetic source/state
qualification does not establish live AWS/EKS/kernel/provenance, current native
ARM64/CI/production-image or release acceptance. Private hosts own protected
custody, retention, policy enablement and real source/state authority.

Native field/stage references were retrieved through Context7:
[CloudTrail identity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html),
[IAM access keys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html),
[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/),
[audit Event](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/).

IAM action comparison is ASCII case insensitive while literal resource/identity
comparison is exact. RBAC resource-name scopes use containment: narrowing an
all-name grant is not expansion. Named top-level create/deletecollection grants
are unsupported; named subresource create can be represented. Bindings retain
immutable role references; source create/delete/update must match exact object
presence transitions. Policy/config/authority revisions bind every snapshot.

Journal enrollment binds rule/source generation, complete private policy/config
and authority-key digests. Prepared outputs retain their original context and
exact decision/state seals. A fresh I/O budget can reconcile an uncertain past
commit but cannot renew expired/cancelled decision admission. Drain old generations
before policy/key rollover; recovery uses old bound bytes before any new decision.

Additional semantics references:
[IAM Action](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html),
[Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

Logical replay uses event UUID plus exact canonical input hash/bytes, independently
of WAL position. Retain up to128 immutable effects under a4MiB ledger ceiling;
the complete generic journal record must also fit its16MiB encoded ceiling.
Full history refuses admission rather than evicting an identity. After publishing
and retiring a pending output, a repeated event may advance the delivery checkpoint
without generating a new assessment. An intervening event cannot replace its
original effect. Mutation proposals verify the complete committed predecessor,
then use the journal revision CAS; a caller-supplied revision alone is insufficient.

A consuming host may durably publish history and a complete cumulative UUID index,
then supply fresh authenticated publication evidence to prune the hot cache. The
library does not implement that external protected archive/index. Every subsequent
unknown hot-cache identity requires an exact-root, source-bound complete lookup:
Known returns original bytes; Absent permits new admission; unavailable, partial,
stale or Unknown evidence refuses reassessment. UUID reuse with different bytes is
a conflict. Retain the original absence-verification evidence with the new effect.
Archive authority is non-deserializable, binds the exact current source/policy/key
enrollment, requires ready/current verification and pins its original monotonic
deadline and cancellation. Historic evidence never renews authority.

For policy/key rollover the host stops source admission, drains the old outbox and
keeps the source journal quiescent through destination commit. Explicit generation
carry verifies the actual source record, retains all original effects and the
complete archive anchor, and seeds an empty separately enrolled journal at the
same source checkpoint. Destination commit rechecks the source record. This is a
single-writer handoff, not a distributed writer-fencing protocol. Private hosts
own exclusive activation, protected archives, their complete index, and recovery
of publication/handoff uncertainty; absent fresh authority the library refuses.

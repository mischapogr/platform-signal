# Source and detection requirements

Status: proposed post-MVP requirements, 2026-10-07. This catalog contains generic
baseline requirements and synthetic fixtures. Company account lists, approvals,
asset sensitivity, severity overrides, retention durations, destinations and real
telemetry belong in the private application. It does not qualify an AWS/EKS/host
collector or turn the current MVP into a SIEM.

Read this together with [logical architecture](logical-architecture.md),
[failure domains](failure-domains.md), [MVP scope](02-mvp.md) and the
[derived roadmap](04-implementation-plan.md#security-requirements-roadmap).

## Executable scope

The [machine-readable catalog](../tests/fixtures/security-requirements/catalog.json)
is the requirement and fixture source. Fifteen detections each define a positive,
negative and missing-data case: 45 cases total. Five predicate requirements have
native MVP rules: SIG-D01, D02, D03, D05 and D07. Their 15 pre-normalized events
can be submitted to the existing server; exactly five findings should persist
and survive restart. The other 30 cases specify future acceptance and are not
runtime tests. The fixture profile uses nested `attributes.security.*`, preserving
the existing canonical event envelope; production normalization is not implemented.

```bash
python3 scripts/check-security-requirements.py
cargo build -p signal-server --locked
python3 scripts/check-security-requirements.py --server target/debug/signal-server \
  --output target/security-requirements-local
```

The runtime output directory must be new. The helper uses an owned loopback server,
bounded requests and deadlines; it never connects to AWS. Passing it proves native
predicate matching and existing event/finding persistence for these inputs only.
A missing predicate field currently produces no finding. The proposed assessment
layer must additionally return `indeterminate` and a coverage gap; that behavior
is not supplied by the current rule engine or this helper.

## Source profiles and semantic traps

Coverage is scoped by source, resource, stream, configuration revision and interval.
Source availability, producer sequence continuity, admitted-data durability and
source integrity are independent assertions. An API read role does not enable
logging. CloudTrail management-event selectors and exclusions must be verified;
management-event coverage does not imply data-event coverage.
[CloudTrail event selectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html).

CloudTrail `MFAUsed=No` and `mfaAuthenticated=false` for federated identities
can coexist with MFA performed by the external identity provider. SIG-D03 applies
only to IAMUser/Root console sign-ins; federated MFA requires an IdP source.
[CloudTrail console sign-in records](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html).

Kubernetes Metadata audit level has no request/response body. Privileged-workload
assessment requires adequate body/state evidence; streaming exec may use
ResponseStarted and endpoint-specific success classification. EKS audit export
must be enabled and verified for each intended cluster.
[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/),
[EKS control-plane logs](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html).

CloudTrail validation digests use source hashes/signatures and must actually be
validated. Enabling digest delivery alone does not validate stored evidence.
[CloudTrail integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html).

### S01 — AWS control-plane audit
- Required evidence: Original CloudTrail management events, account/region scope, selectors, delivery configuration and source digest validation where available.
- Coverage preconditions: Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope.
- Identity: Event account, actor principal/session and affected resource are separate identities.
### S02 — IAM and security configuration state
- Required evidence: Versioned inventory, before/after policies and security-control settings, approval records supplied by a private adapter.
- Coverage preconditions: Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- Identity: Principal, policy, account and revision keys; private approval decisions stay external.
### S03 — Kubernetes audit and workload state
- Required evidence: Audit records plus revisioned workload/RBAC metadata; retain stage, verb, user, objectRef and response status.
- Coverage preconditions: Audit collection explicitly enabled and delivered; policy includes required resources/verbs and adequate request/response detail. Metadata-only records cannot prove a privileged pod specification.
- Identity: Cluster identity + namespace + object UID; actor identity separate; auditID and stage distinguish duplicates.
### S04 — Application or host authentication
- Required evidence: Structured success/failure records, stable principal and target identity, authentication method and producer checkpoint.
- Coverage preconditions: Success and failure logging verified with controlled fixtures; source timestamps and delivery continuity bounded; no credentials or tokens captured.
- Identity: Identity authority + principal + target + session, with IP as context rather than sole identity.
### S05 — Database authentication
- Required evidence: Database audit/authentication records and privileged-role inventory with revision and validity interval.
- Coverage preconditions: Engine-specific audit settings and roles verified; managed-service access does not automatically enable database audit logs.
- Identity: Database resource + database principal + client/session.
### S06 — Host/runtime execution and access
- Required evidence: Process execution, protected-file access and egress records with boot/process identities, producer sequence and dropped-event counters.
- Coverage preconditions: Required kernel/runtime capabilities, permissions and capture hooks verified. File/stdin collection alone does not establish runtime coverage.
- Identity: Host + boot ID + process start identity, avoiding PID reuse; container/workload links carry confidence.
### S07 — Independent collection coverage observer
- Required evidence: Expected source inventory, configuration revision, probe/heartbeat and checkpoint observations, observer self-health.
- Coverage preconditions: Observer has independent failure visibility; expectations exist before silence; freshness and outage budgets bounded. An unhealthy observer yields unknown coverage.
- Identity: Source + collector + resource scope + expected stream + configuration revision.
## Detection overview

| ID | Requirement | Rule type | Current executable scope |
| --- | --- | --- | --- |
| [SIG-D01](#sig-d01) | Root identity activity | predicate | Normalized native predicate |
| [SIG-D02](#sig-d02) | Audit collection stopped or deleted | predicate | Normalized native predicate |
| [SIG-D03](#sig-d03) | Successful IAM or root console login without MFA | predicate | Normalized native predicate |
| [SIG-D04](#sig-d04) | Unexpected IAM credential creation | state | Future contract only |
| [SIG-D05](#sig-d05) | Security control disabled | predicate | Normalized native predicate |
| [SIG-D06](#sig-d06) | IAM effective permission expansion | state | Future contract only |
| [SIG-D07](#sig-d07) | Privileged Kubernetes workload admitted | predicate | Normalized native predicate |
| [SIG-D08](#sig-d08) | Kubernetes effective RBAC privilege grant | state | Future contract only |
| [SIG-D09](#sig-d09) | Unauthorized exec into sensitive workload | state | Future contract only |
| [SIG-D10](#sig-d10) | Authentication failure burst | window | Future contract only |
| [SIG-D11](#sig-d11) | Authentication failures followed by success | correlation | Future contract only |
| [SIG-D12](#sig-d12) | Unexpected privileged database login | state | Future contract only |
| [SIG-D13](#sig-d13) | Unauthorized privileged host execution | state | Future contract only |
| [SIG-D14](#sig-d14) | Protected credential access followed by suspicious egress | correlation | Future contract only |
| [SIG-D15](#sig-d15) | Expected host collector heartbeat absent | window | Future contract only |

## Assessment and bounded execution contract

A finding is separate from a raw event, an assessment, an alert and an incident.
The proposed assessment is `match`, `no_match` or `indeterminate`. `no_match`
requires the relevant fields, state and coverage preconditions for that assertion.
`match` can still be produced from valid positive evidence during a coverage gap,
but carries degraded coverage and cannot establish complete incident scope.
A benign SecOps disposition does not retroactively erase the recorded evidence.

Severity measures potential impact; confidence measures support for the claimed
condition. Neither is the log's severity. Root activity, configuration changes,
privileged execution and correlation candidates are not automatically compromise.

Every state/window/correlation implementation must choose finite key, event,
byte and time limits; watermark/lateness and expiry rules; duplicate identity;
and crash-consistent state/checkpoint/finding publication. Overflow, stale state
or unsupported semantics must degrade assessment explicitly. Counts, thresholds
and windows in fixtures are laboratory acceptance parameters, not deployment policy.
Do not extend the MVP YAML language silently to implement these requirements.

Evidence retention covers original source references, normalized inputs, source
coverage/configuration revision, normalization/rule/state revisions and disposition
history. Protected originals are separately authorized; query copies may be redacted
or expire sooner. Private policy chooses durations, holds and access. A missing
original is recorded as an evidence gap; do not fabricate an integrity assertion.

## Detailed requirements

<a id="sig-d01"></a>

### SIG-D01 — Root identity activity
- **Required sources:** S01.
- **Coverage preconditions:** Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope.
- **Normalization:** CloudTrail userIdentity.type -> actor_kind; eventName -> action; errorCode -> outcome; preserve eventID, recipient account, region, session and source identity.
- **Rule type / trigger:** `predicate` — A successful audited activity uses a Root identity. Confidence concerns the recorded activity, not whether it is malicious.
- **State requirements:** No cross-event state. Fixed-size field lookup and configured predicate limits suffice; normalization and coverage validity remain separate requirements.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; High for root activity; intent requires investigation.
- **Expected SecOps action:** Verify emergency/change authorization and affected resources; inspect adjacent activity before escalation.
- **Fixtures:** `SIG-D01-positive` → `match`, `SIG-D01-negative` → `no_match`, `SIG-D01-missing_data` → `indeterminate`.
- **Capability status:** `normalized_predicate_runnable`.

<a id="sig-d02"></a>

### SIG-D02 — Audit collection stopped or deleted
- **Required sources:** S01, S07.
- **Coverage preconditions:** Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope. Observer has independent failure visibility; expectations exist before silence; freshness and outage budgets bounded. An unhealthy observer yields unknown coverage.
- **Normalization:** StopLogging/DeleteTrail -> audit.stop/audit.delete; preserve trail ARN, actor, result and account/region. An API attempt is distinct from a successful change.
- **Rule type / trigger:** `predicate` — Successful stop/delete operation on an audit trail; independent observer separately verifies resulting collection state.
- **State requirements:** No cross-event state. Fixed-size field lookup and configured predicate limits suffice; normalization and coverage validity remain separate requirements.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested critical; High for successful operation; coverage impact independently verified.
- **Expected SecOps action:** Validate approved maintenance and current audit scope; restore collection through an authorized runbook and investigate actor.
- **Fixtures:** `SIG-D02-positive` → `match`, `SIG-D02-negative` → `no_match`, `SIG-D02-missing_data` → `indeterminate`.
- **Capability status:** `normalized_predicate_runnable`.

<a id="sig-d03"></a>

### SIG-D03 — Successful IAM or root console login without MFA
- **Required sources:** S01.
- **Coverage preconditions:** Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope.
- **Normalization:** ConsoleLogin -> identity.console_login; responseElements.ConsoleLogin -> outcome; userIdentity.type -> actor_kind; additionalEventData.MFAUsed -> mfa_used boolean only for IAMUser/Root. Missing/unsupported value stays absent. Federated MFA needs IdP evidence.
- **Rule type / trigger:** `predicate` — Successful ConsoleLogin, actor_kind IAMUser or Root, and explicit mfa_used=false. AssumedRole/federated No is not proof that IdP MFA was absent.
- **State requirements:** No cross-event state. Fixed-size field lookup and configured predicate limits suffice; normalization and coverage validity remain separate requirements.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; High for native IAM/root MFA observation; federated coverage unsupported without IdP source.
- **Expected SecOps action:** Validate identity and access policy; inspect session actions and investigate unapproved access.
- **Fixtures:** `SIG-D03-positive` → `match`, `SIG-D03-negative` → `no_match`, `SIG-D03-missing_data` → `indeterminate`.
- **Capability status:** `normalized_predicate_runnable`.

<a id="sig-d04"></a>

### SIG-D04 — Unexpected IAM credential creation
- **Required sources:** S01, S02.
- **Coverage preconditions:** Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** CreateUser/CreateAccessKey -> credential.create; target principal and credential identifier distinct from actor. Never retain secret key material.
- **Rule type / trigger:** `state` — Successful credential creation without a valid approval for target, actor and interval.
- **State requirements:** Bounded approval/inventory lookup keyed by account+target+change; revision, validity interval and timeout mandatory. Persist decision inputs for replay; stale state is indeterminate.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium until approval/state is authoritative.
- **Expected SecOps action:** Confirm owner/change intent, inspect new credential use and revoke only through an authorized response workflow.
- **Fixtures:** `SIG-D04-positive` → `match`, `SIG-D04-negative` → `no_match`, `SIG-D04-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d05"></a>

### SIG-D05 — Security control disabled
- **Required sources:** S01, S07.
- **Coverage preconditions:** Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope. Observer has independent failure visibility; expectations exist before silence; freshness and outage budgets bounded. An unhealthy observer yields unknown coverage.
- **Normalization:** Normalize supported successful disable/stop APIs for GuardDuty, Security Hub or Config to control.disable with service/resource and outcome; selectors/version define supported actions.
- **Rule type / trigger:** `predicate` — Successful supported control-disable operation. Independent coverage verifies actual impact.
- **State requirements:** No cross-event state. Fixed-size field lookup and configured predicate limits suffice; normalization and coverage validity remain separate requirements.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; High for operation; disabling one detector does not prove all regional/org coverage disabled.
- **Expected SecOps action:** Validate maintenance and affected scope; restore expected control configuration with approval.
- **Fixtures:** `SIG-D05-positive` → `match`, `SIG-D05-negative` → `no_match`, `SIG-D05-missing_data` → `indeterminate`.
- **Capability status:** `normalized_predicate_runnable`.

<a id="sig-d06"></a>

### SIG-D06 — IAM effective permission expansion
- **Required sources:** S01, S02.
- **Coverage preconditions:** Required accounts/regions and read/write selectors enabled; collector can read delivered originals; exclusions and delivery delay known. Data events are a separate opt-in scope. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** Policy/role/group changes identify affected principal and before/after revisions; retain boundaries, SCP/session/condition inputs and evaluator support limits.
- **Rule type / trigger:** `state` — A supported, verified before/after permission set expands beyond the approved scope. AttachPolicy alone is not an escalation verdict.
- **State requirements:** Bounded versioned snapshots and supported permission-diff evaluator, keyed by principal/account. Unsupported semantics or missing prior version remain indeterminate; no universal IAM solver assumed.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium/high only for supported semantics and complete inputs.
- **Expected SecOps action:** Review exact added actions/resources and approval; investigate follow-on use.
- **Fixtures:** `SIG-D06-positive` → `match`, `SIG-D06-negative` → `no_match`, `SIG-D06-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d07"></a>

### SIG-D07 — Privileged Kubernetes workload admitted
- **Required sources:** S03.
- **Coverage preconditions:** Audit collection explicitly enabled and delivered; policy includes required resources/verbs and adequate request/response detail. Metadata-only records cannot prove a privileged pod specification.
- **Normalization:** Audit objectRef/verb -> workload action; response classification -> outcome; request/response spec -> privileged. Preserve cluster/object UID, auditID, stage and policy revision. Read persisted/admitted spec where admission mutation matters.
- **Rule type / trigger:** `predicate` — Successful workload write whose admitted workload specification has privileged=true. A rejected request is not an admitted workload.
- **State requirements:** No cross-event state. Fixed-size field lookup and configured predicate limits suffice; normalization and coverage validity remain separate requirements.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; High with confirmed admitted spec; request-only is lower-confidence candidate.
- **Expected SecOps action:** Validate workload owner and approved exception; inspect container image and operator identity.
- **Fixtures:** `SIG-D07-positive` → `match`, `SIG-D07-negative` → `no_match`, `SIG-D07-missing_data` → `indeterminate`.
- **Capability status:** `normalized_predicate_runnable`.

<a id="sig-d08"></a>

### SIG-D08 — Kubernetes effective RBAC privilege grant
- **Required sources:** S03, S02.
- **Coverage preconditions:** Audit collection explicitly enabled and delivered; policy includes required resources/verbs and adequate request/response detail. Metadata-only records cannot prove a privileged pod specification. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** Role/binding changes -> rbac.change; subject/role/namespace plus role revisions; include aggregated roles and applicable authorization configuration.
- **Rule type / trigger:** `state` — Supported before/after authorization view grants privileges outside approved subject scope.
- **State requirements:** Bounded subject/role/binding snapshots, versioned authorization diff and approval lookup; unsupported authorizers/aggregation or stale revisions are indeterminate.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium/high for complete supported authorization inputs.
- **Expected SecOps action:** Review subject, role and namespace scope; validate operator change and inspect subsequent API actions.
- **Fixtures:** `SIG-D08-positive` → `match`, `SIG-D08-negative` → `no_match`, `SIG-D08-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d09"></a>

### SIG-D09 — Unauthorized exec into sensitive workload
- **Required sources:** S03, S02.
- **Coverage preconditions:** Audit collection explicitly enabled and delivered; policy includes required resources/verbs and adequate request/response detail. Metadata-only records cannot prove a privileged pod specification. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** pods/exec subresource with auditID, actor, cluster/object identity and endpoint-aware result; streaming ResponseStarted/upgrade can establish accepted session without waiting for ResponseComplete.
- **Rule type / trigger:** `state` — Accepted exec session into a workload classified sensitive, by an operator lacking valid authorization for that interval.
- **State requirements:** Bounded historical workload classification and operator authorization, keyed by cluster+object UID+actor. Persist revision and time-valid decision; namespace name alone is insufficient.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium/high with accepted session and authoritative asset/actor policy.
- **Expected SecOps action:** Validate break-glass activity; inspect commands/session context available from authorized sources.
- **Fixtures:** `SIG-D09-positive` → `match`, `SIG-D09-negative` → `no_match`, `SIG-D09-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d10"></a>

### SIG-D10 — Authentication failure burst
- **Required sources:** S04.
- **Coverage preconditions:** Success and failure logging verified with controlled fixtures; source timestamps and delivery continuity bounded; no credentials or tokens captured.
- **Normalization:** Authentication attempt -> auth.attempt; outcome and authority+principal+target keys; preserve producer ID/time and source context. Count distinct attempts, not replay copies.
- **Rule type / trigger:** `window` — At least N distinct failures for authority+principal+target within window W; laboratory threshold N=3, W=60 seconds.
- **State requirements:** Bound keys, per-key events/counters, bytes, TTL and lateness. Persist watermark, dedup IDs and rule revision together with recovery checkpoint; overflow degrades assessment.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested medium; Medium; shared client/NAT and legitimate failures need context.
- **Expected SecOps action:** Review principal/target and distributed-source context; validate user lockout and suspicious activity.
- **Fixtures:** `SIG-D10-positive` → `match`, `SIG-D10-negative` → `no_match`, `SIG-D10-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d11"></a>

### SIG-D11 — Authentication failures followed by success
- **Required sources:** S04.
- **Coverage preconditions:** Success and failure logging verified with controlled fixtures; source timestamps and delivery continuity bounded; no credentials or tokens captured.
- **Normalization:** Same identity authority+principal+target as SIG-D10; success session identity and source changes preserved. No correlation solely by IP.
- **Rule type / trigger:** `correlation` — Qualifying failure burst followed by a distinct success for the same identity/target within C; suggests compromised account, not proof.
- **State requirements:** Bounded failure-window state plus success join, event-time/lateness, TTL, stable evidence IDs and coordinated state checkpoint. Dedup findings by rule revision+episode.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium; legitimate recovery can produce the same pattern.
- **Expected SecOps action:** Confirm user/session legitimacy; inspect post-login actions and escalate when evidence supports compromise.
- **Fixtures:** `SIG-D11-positive` → `match`, `SIG-D11-negative` → `no_match`, `SIG-D11-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d12"></a>

### SIG-D12 — Unexpected privileged database login
- **Required sources:** S05, S02.
- **Coverage preconditions:** Engine-specific audit settings and roles verified; managed-service access does not automatically enable database audit logs. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** Engine-specific successful auth -> db.login; database resource, role/principal, client and session; map role privileges through versioned inventory.
- **Rule type / trigger:** `state` — Successful privileged-role login outside approved actor/source/time policy.
- **State requirements:** Bounded versioned privilege and authorization lookup by database+principal+client; freshness and historical validity required; source IP is context.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium/high for complete database audit and role state.
- **Expected SecOps action:** Validate DBA/change activity; inspect authorized query audit and affected data scope.
- **Fixtures:** `SIG-D12-positive` → `match`, `SIG-D12-negative` → `no_match`, `SIG-D12-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d13"></a>

### SIG-D13 — Unauthorized privileged host execution
- **Required sources:** S06, S02.
- **Coverage preconditions:** Required kernel/runtime capabilities, permissions and capture hooks verified. File/stdin collection alone does not establish runtime coverage. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** Runtime exec -> host.exec; host+boot+process start ID, executable identity/provenance, effective UID/capabilities, parent chain and capture-drop counters.
- **Rule type / trigger:** `state` — Privileged execution inconsistent with approved executable/workload/operator policy.
- **State requirements:** Bounded approval/provenance inventory and time-valid decision keyed by immutable process/executable identity; PID/path alone is insufficient. No automatic eBPF implementation implied.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium; privileged execution alone is common and not malicious.
- **Expected SecOps action:** Validate administrative activity and binary provenance; investigate host and parent process.
- **Fixtures:** `SIG-D13-positive` → `match`, `SIG-D13-negative` → `no_match`, `SIG-D13-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d14"></a>

### SIG-D14 — Protected credential access followed by suspicious egress
- **Required sources:** S06, S02.
- **Coverage preconditions:** Required kernel/runtime capabilities, permissions and capture hooks verified. File/stdin collection alone does not establish runtime coverage. Snapshot freshness and authority recorded; incomplete IAM conditions, boundaries, SCPs or session policies make effective-permission claims indeterminate.
- **Normalization:** File/runtime access and connection records share host+boot+process start identity; protected asset category and destination decision supplied by versioned policy. Never collect credential contents.
- **Rule type / trigger:** `correlation` — Same process successfully reads protected credential material then connects to a destination classified suspicious within C. This is an investigative candidate, not proof of exfiltration.
- **State requirements:** Bounded process join/window, dedup, historical asset/destination policy revisions, event-time/lateness and coordinated recovery checkpoint; missing either stream is indeterminate.
- **Missing-data behavior:** Missing required field or expired source coverage gives indeterminate assessment plus a coverage gap; never interpret absent evidence as a clean result. Existing predicates can only emit no finding.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence.
- **Severity / confidence:** Suggested high; Medium; sanctioned tooling and proxies can produce similar evidence.
- **Expected SecOps action:** Inspect process lineage and destination; preserve evidence and use an authorized isolation workflow if justified.
- **Fixtures:** `SIG-D14-positive` → `match`, `SIG-D14-negative` → `no_match`, `SIG-D14-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

<a id="sig-d15"></a>

### SIG-D15 — Expected host collector heartbeat absent
- **Required sources:** S07.
- **Coverage preconditions:** Observer has independent failure visibility; expectations exist before silence; freshness and outage budgets bounded. An unhealthy observer yields unknown coverage.
- **Normalization:** Independent observer maps expected source/collector/scope/configuration to last verified heartbeat/checkpoint and observation time; telemetry silence alone is insufficient.
- **Rule type / trigger:** `window` — A source expected active has no heartbeat within the configured interval while the independent observer remains healthy.
- **State requirements:** Bounded expected-source inventory, monotonic observation clock, grace period, last heartbeat/checkpoint and observer self-health; replay must not advance freshness. Preserve revision/expiry.
- **Missing-data behavior:** Unknown expected inventory or unhealthy/stale observer -> indeterminate coverage, not a source failure or compromise verdict.
- **Evidence retention:** Retain original reference, normalized input, source/configuration revision, rule version and assessment. Private policy supplies duration and legal hold; absent evidence reduces confidence. Retain coverage gaps and recovery boundaries even if no security event was recorded.
- **Severity / confidence:** Suggested high; High for independently observed collection gap; cause/compromise unknown.
- **Expected SecOps action:** Check deployment, connectivity and capacity; restore collection and identify irrecoverable gaps before security escalation.
- **Fixtures:** `SIG-D15-positive` → `match`, `SIG-D15-negative` → `no_match`, `SIG-D15-missing_data` → `indeterminate`.
- **Capability status:** `planned`.

## Capability consequences

The initial catalog needs source normalization and coverage before broader claims;
a durable findings delivery interface before alert automation; an independent
original-evidence path before security-account isolation claims; bounded windows
before failure bursts/heartbeat detection; and revisioned state before approval
or effective-permission assertions. Multi-stream correlation follows those pieces.
A topology graph, custom query language, eBPF agent, hot store and additional
server processes are not prerequisites for the first five predicate requirements.

Use [the roadmap](04-implementation-plan.md#security-requirements-roadmap) to
implement one bounded item at a time. New raw-source fixtures, provider receipts,
coverage transitions, window/state recovery and SecOps feedback require their own
acceptance; this catalog is the starting contract rather than their completion.

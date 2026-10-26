# Versioned generic baseline predicate pack

BASELINES implementation contract. The public v1 pack contains D01/D02/D03/D05/D07
and unchanged `signal.dev/v1` predicate documents. It is installed under
`rules/baselines/v1`; installation never activates it. Private host configuration
selects rule directories, scope, enablement, severity overrides and response.

Assessment bounds central validation to256tags and1MiB cumulative source/message/
resource/tag text before any trimming or tag iteration. Unrelated private
attributes remain borrowed and untouched; predicates use only their fixed paths.

A strict bounded manifest binds each exact rule file digest to its explanation,
source/profile requirements, typed fields, suggested severity, confidence limits
and investigation defaults. The pack content commitment includes descriptor
metadata as well as executable definitions. It is an identity, not a signature
or a release-trust claim. The v1 loader requires exact shipped executable
bytes, including when a changed rule has a recomputed manifest digest. Private
rule overrides continue through the generic RuleSet loader with their own identity. Do not add fields to the existing rule/finding language.

The reusable pure Rust pack loader takes bounded in-memory documents. Filesystem
loading and production activation continue through the existing bounded rule
loader. Cancellation and the original context deadline apply to pack work.

Assessment returns versioned per-rule match/no_match/indeterminate results with
original event ID, pack/revision/content binding, explicit applicability and gap
codes. Exact trusted-host readiness inventory and supported normalization profile
must be supplied afresh; serialized event attributes cannot authorize evaluation.
Host readiness includes source identity/scope, permissions, normalization,
independent current coverage and the manifest's per-detection preconditions.
The assessment API does not authenticate those host decisions. Reuse the existing
onboarding host checks; neither this manifest nor an old report is a grant.

Wrong-source or clearly unrelated-action inputs are outside applicability, not
clean source coverage. Applicable missing/null/wrong-type fields, unsupported
normalization or blocked host prerequisites are indeterminate with explicit gaps.
Federated/AssumedRole console records are outside native IAM/root MFA applicability;
MFA fields are required only within that supported identity subset. D07 requires
trusted admitted-spec normalization; request-only or Metadata audit evidence
cannot be promoted by an event's own readiness claim.

Acceptance must include strict inventory/digest/version/budget/cancellation cases,
all fifteen original fixture assessments, malformed and unsupported fields,
producer-forged readiness, native CloudTrail/Kubernetes normalization and actual
Small loading of packaged files with original findings surviving restart.
Synthetic fixtures and loopback processes do not qualify live AWS/EKS coverage.

Consuming hosts must retain the original input/reference, assessment, source and
configuration revisions, pack content commitment and host-readiness evidence.
Private policy owns retention and legal hold. The library returns assessments;
Main does not automatically produce or persist those assessment/gap records.
Main executes privately selected packaged YAML through its existing rule path.
For example, an owner can select the absolute pack directory with
`SIGNAL_RULE_DIRS=/absolute/path/rules/baselines/v1` alongside the existing server
configuration. The existing onboarding host remains the activation gate when
configured. The Small predicate campaign proves packaged rule execution and
finding persistence, not authenticated coverage or persisted assessments.

//! Versioned generic descriptors and assessments; trusted host readiness is external.
use crate::{RuleContext, RuleError, RuleLimits, RuleSet, lookup};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;
use signal_findings::Finding;
use std::collections::{BTreeMap, BTreeSet};

const IDS: [&str; 5] = ["SIG-D01", "SIG-D02", "SIG-D03", "SIG-D05", "SIG-D07"];
const SHIPPED_RULES: [&[u8]; 5] = [
    include_bytes!("../../../rules/baselines/v1/SIG-D01.yaml"),
    include_bytes!("../../../rules/baselines/v1/SIG-D02.yaml"),
    include_bytes!("../../../rules/baselines/v1/SIG-D03.yaml"),
    include_bytes!("../../../rules/baselines/v1/SIG-D05.yaml"),
    include_bytes!("../../../rules/baselines/v1/SIG-D07.yaml"),
];
const MAX_MANIFEST: usize = 65_536;
const MAX_DOCUMENT: usize = 65_536;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub pack_id: String,
    pub revision: String,
    pub activation: String,
    pub detections: Vec<Descriptor>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub id: String,
    pub rule_file: String,
    pub rule_sha256: String,
    pub source_type: String,
    pub normalization_profile: String,
    pub actions: Vec<String>,
    pub required_fields: Vec<Field>,
    pub source_profiles: Vec<String>,
    pub source_preconditions: Vec<String>,
    pub explanation: String,
    pub suggested_severity: String,
    pub confidence: String,
    pub investigation: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub path: String,
    pub kind: FieldKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    String,
    Boolean,
}

/// Construct afresh from trusted scoped onboarding/normalization checks, never
/// event attributes or a deserialized prior assessment. This API grants no trust.
pub struct HostDecision<'a> {
    pub rule_id: &'a str,
    pub ready: bool,
    pub normalization_profile: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Match,
    NoMatch,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    OutsideApplicability,
    HostPrerequisitesUnverified,
    UnsupportedNormalization,
    MissingOrInvalidField,
}

#[derive(Debug, Serialize)]
pub struct Assessment<'a> {
    pub schema_version: u32,
    pub pack_id: &'a str,
    pub pack_revision: &'a str,
    pub content_sha256: &'a str,
    pub rule_id: &'a str,
    pub rule_sha256: &'a str,
    pub event_id: uuid::Uuid,
    pub status: Status,
    pub applicable: bool,
    pub coverage_gap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'a str>,
    pub explanation: &'a str,
    pub confidence: &'a str,
    pub investigation: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<Finding>,
}

pub struct Pack {
    manifest: Manifest,
    rules: RuleSet,
    content_sha256: String,
}

fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Bound precisely the strings/tag iteration performed by central event validation.
// Unrelated private attribute trees remain borrowed and are never traversed here.
fn event_budget(event: &SignalEvent, context: &RuleContext) -> Result<(), RuleError> {
    context.check()?;
    if event.tags.len() > 256 {
        return Err(RuleError::Limit);
    }
    let mut remaining = 1024 * 1024usize;
    let mut charge = |value: &str| -> Result<(), RuleError> {
        context.check()?;
        remaining = remaining.checked_sub(value.len()).ok_or(RuleError::Limit)?;
        Ok(())
    };
    charge(&event.source.source_type)?;
    for value in [event.source.name.as_deref(), event.message.as_deref()]
        .into_iter()
        .flatten()
    {
        charge(value)?;
    }
    if let Some(resource) = &event.resource {
        charge(&resource.kind)?;
        charge(&resource.id)?;
        for value in [resource.account_id.as_deref(), resource.region.as_deref()]
            .into_iter()
            .flatten()
        {
            charge(value)?;
        }
    }
    for tag in &event.tags {
        charge(tag)?;
    }
    context.check()
}

impl Pack {
    /// Pure bounded loading. The caller owns any disk I/O and discards all output
    /// on failure. Exact manifest bytes and sorted rule bytes bind the identity.
    pub fn from_documents(
        manifest: &str,
        documents: &[(&str, &str)],
        limits: RuleLimits,
        context: &RuleContext,
    ) -> Result<Self, RuleError> {
        context.check()?;
        if manifest.len() > MAX_MANIFEST || documents.len() != IDS.len() {
            return Err(RuleError::Limit);
        }
        let descriptor: Manifest =
            serde_json::from_str(manifest).map_err(|_| RuleError::Invalid("pack manifest"))?;
        if descriptor.schema_version != 1
            || descriptor.pack_id != "security-baselines"
            || descriptor.revision != "1.0.0"
            || descriptor.activation != "private_explicit_selection"
            || descriptor.detections.len() != IDS.len()
        {
            return Err(RuleError::Invalid("pack version or inventory"));
        }
        let mut files = BTreeMap::new();
        for &(name, body) in documents {
            context.check()?;
            if name.len() != 12
                || !IDS.iter().any(|id| name.strip_suffix(".yaml") == Some(*id))
                || body.len() > MAX_DOCUMENT
                || files.insert(name, body).is_some()
            {
                return Err(RuleError::Invalid("pack documents"));
            }
        }
        let mut commitment = Sha256::new();
        commitment.update(b"PLATFORM::SIGNAL/baseline-pack/v1\0");
        commitment.update((manifest.len() as u64).to_be_bytes());
        commitment.update(manifest.as_bytes());
        for (index, (entry, expected)) in descriptor.detections.iter().zip(IDS).enumerate() {
            context.check()?;
            let kube = expected == "SIG-D07";
            if entry.id != expected
                || entry.rule_file != format!("{expected}.yaml")
                || entry.source_type
                    != if kube {
                        "kubernetes.audit"
                    } else {
                        "cloudtrail"
                    }
                || entry.normalization_profile
                    != if kube {
                        "kubernetes-audit-v1"
                    } else {
                        "cloudtrail-management-v1"
                    }
                || entry.actions.len() > 4
                || entry.required_fields.is_empty()
                || entry.required_fields.len() > 8
                || entry.source_profiles.is_empty()
                || entry.source_profiles.len() > 7
                || entry.source_preconditions.is_empty()
                || entry.source_preconditions.len() > 8
                || !["high", "critical"].contains(&entry.suggested_severity.as_str())
                || [&entry.explanation, &entry.confidence, &entry.investigation]
                    .iter()
                    .any(|s| !text(s, 4096))
                || entry.actions.iter().any(|s| !text(s, 256))
                || entry.source_profiles.iter().any(|s| !text(s, 128))
                || entry.source_preconditions.iter().any(|s| !text(s, 2048))
            {
                return Err(RuleError::Invalid("pack descriptor"));
            }
            let actions: &[&str] = match expected {
                "SIG-D01" => &[],
                "SIG-D02" => &["audit.stop", "audit.delete"],
                "SIG-D03" => &["identity.console_login"],
                "SIG-D05" => &["control.disable"],
                _ => &["k8s.workload.write"],
            };
            let mut required = vec![("attributes.security.outcome", FieldKind::String)];
            if ["SIG-D01", "SIG-D03"].contains(&expected) {
                required.push(("attributes.security.actor_kind", FieldKind::String));
            }
            if expected == "SIG-D03" {
                required.push(("attributes.security.mfa_used", FieldKind::Boolean));
            }
            if kube {
                required.push(("attributes.security.privileged", FieldKind::Boolean));
            }
            let sources: &[&str] = match expected {
                "SIG-D02" | "SIG-D05" => &["S01", "S07"],
                "SIG-D07" => &["S03"],
                _ => &["S01"],
            };
            if !entry
                .actions
                .iter()
                .map(String::as_str)
                .eq(actions.iter().copied())
                || !entry
                    .required_fields
                    .iter()
                    .map(|f| (f.path.as_str(), f.kind))
                    .eq(required)
                || !entry
                    .source_profiles
                    .iter()
                    .map(String::as_str)
                    .eq(sources.iter().copied())
            {
                return Err(RuleError::Invalid("pack applicability contract"));
            }
            let mut fields = BTreeSet::new();
            for field in &entry.required_fields {
                if !field.path.starts_with("attributes.security.")
                    || !text(&field.path, 256)
                    || field.path.split('.').any(str::is_empty)
                    || !fields.insert(&field.path)
                {
                    return Err(RuleError::Invalid("pack required fields"));
                }
            }
            let body = files
                .get(entry.rule_file.as_str())
                .ok_or(RuleError::Invalid("pack file inventory"))?;
            if hex(&Sha256::digest(body.as_bytes())) != entry.rule_sha256
                || SHIPPED_RULES
                    .get(index)
                    .is_none_or(|canonical| body.as_bytes() != *canonical)
            {
                return Err(RuleError::Invalid("pack rule digest"));
            }
            commitment.update((body.len() as u64).to_be_bytes());
            commitment.update(body.as_bytes());
        }
        let rules = RuleSet::from_yaml_documents(files.values().copied(), limits)?;
        if !rules.rule_ids().eq(IDS) {
            return Err(RuleError::Invalid("pack executable inventory"));
        }
        for (entry, rule) in descriptor.detections.iter().zip(&rules.rules) {
            if serde_json::to_value(rule.spec.severity).map_err(|_| RuleError::Finding)?
                != entry.suggested_severity
            {
                return Err(RuleError::Invalid("pack severity"));
            }
        }
        context.check()?;
        Ok(Self {
            manifest: descriptor,
            rules,
            content_sha256: hex(&commitment.finalize()),
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// Returns five bounded results. Readiness includes exact source/scope,
    /// freshness, permissions and descriptor preconditions checked by the host.
    /// These booleans and profile names are not authenticated by this pure API.
    pub fn assess(
        &self,
        event: &SignalEvent,
        decisions: &[HostDecision<'_>],
        context: &RuleContext,
    ) -> Result<Vec<Assessment<'_>>, RuleError> {
        context.check()?;
        event_budget(event, context)?;
        event.validate().map_err(|_| RuleError::Invalid("event"))?;
        if decisions.len() != IDS.len() {
            return Err(RuleError::Invalid("pack readiness inventory"));
        }
        let mut trusted = BTreeMap::new();
        for decision in decisions {
            if !IDS.contains(&decision.rule_id)
                || decision.normalization_profile.len() > 128
                || trusted.insert(decision.rule_id, decision).is_some()
            {
                return Err(RuleError::Invalid("pack readiness inventory"));
            }
        }
        let mut output = Vec::with_capacity(IDS.len());
        let mut readiness = Vec::with_capacity(IDS.len());
        for entry in &self.manifest.detections {
            context.check()?;
            let decision = trusted
                .get(entry.id.as_str())
                .ok_or(RuleError::Invalid("pack readiness inventory"))?;
            let mut status = Status::NoMatch;
            let mut applicable = event.source.source_type == entry.source_type;
            let mut reason = None;
            let mut field = None;
            if applicable && !entry.actions.is_empty() {
                match lookup(event, "attributes.security.action") {
                    Some(value) if value.is_string() => {
                        applicable = entry.actions.iter().any(|a| value.as_str() == Some(a));
                    }
                    _ => {
                        status = Status::Indeterminate;
                        reason = Some(Reason::MissingOrInvalidField);
                        field = Some("attributes.security.action");
                    }
                }
            }
            // Federated identities are not evidence about native IAM/root MFA.
            if applicable
                && entry.id == "SIG-D03"
                && let Some(actor) = lookup(event, "attributes.security.actor_kind")
                && let Some(actor) = actor.as_str()
                && [
                    "AssumedRole",
                    "FederatedUser",
                    "AWSService",
                    "AWSAccount",
                    "IdentityCenterUser",
                ]
                .contains(&actor)
            {
                applicable = false;
            }
            if !applicable {
                reason = Some(Reason::OutsideApplicability);
                status = Status::NoMatch;
                field = None;
            } else if !decision.ready {
                status = Status::Indeterminate;
                reason = Some(Reason::HostPrerequisitesUnverified);
                field = None;
            } else if decision.normalization_profile != entry.normalization_profile {
                status = Status::Indeterminate;
                reason = Some(Reason::UnsupportedNormalization);
                field = None;
            } else if status != Status::Indeterminate {
                for required in &entry.required_fields {
                    let valid =
                        lookup(event, &required.path).is_some_and(|v| match required.kind {
                            FieldKind::String => v.as_str().is_some_and(|s| {
                                if required.path == "attributes.security.outcome" {
                                    ["success", "failure"].contains(&s)
                                } else {
                                    [
                                        "Root",
                                        "IAMUser",
                                        "AssumedRole",
                                        "FederatedUser",
                                        "AWSService",
                                        "AWSAccount",
                                        "IdentityCenterUser",
                                    ]
                                    .contains(&s)
                                }
                            }),
                            FieldKind::Boolean => v.is_boolean(),
                        });
                    if !valid {
                        status = Status::Indeterminate;
                        reason = Some(Reason::MissingOrInvalidField);
                        field = Some(required.path.as_str());
                        break;
                    }
                }
            }
            readiness.push((
                entry.id.as_str(),
                applicable && status != Status::Indeterminate,
            ));
            output.push(Assessment {
                schema_version: 1,
                pack_id: &self.manifest.pack_id,
                pack_revision: &self.manifest.revision,
                content_sha256: &self.content_sha256,
                rule_id: &entry.id,
                rule_sha256: &entry.rule_sha256,
                event_id: event.id,
                status,
                applicable,
                coverage_gap: status == Status::Indeterminate,
                reason,
                field,
                explanation: &entry.explanation,
                confidence: &entry.confidence,
                investigation: &entry.investigation,
                finding: None,
            });
        }
        let findings = self
            .rules
            .evaluate_ready_with_context(event, context, &readiness)?;
        for finding in findings {
            let row = output
                .iter_mut()
                .find(|row| row.rule_id == finding.rule_id)
                .ok_or(RuleError::Invalid("pack finding inventory"))?;
            row.status = Status::Match;
            row.finding = Some(finding);
        }
        context.check()?;
        Ok(output)
    }
}

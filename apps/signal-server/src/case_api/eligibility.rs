//! Independent, freshly signed directory status. This never authenticates an actor.
use super::{Failure, reference::Inventory};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature;
use serde::Deserialize;
use signal_findings::{FindingContext, cases::CaseRequest};
use signal_protocol::access::{AccessPolicy, Operation, Permission, Role};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;

pub(super) const DOMAIN: &[u8] = b"PLATFORM::SIGNAL/soc-assignee-directory/v1\0";
const REPORT_BYTES: usize = 256 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub(super) issuer: String,
    pub(super) audience: String,
    pub(super) key_revision: String,
    pub(super) policy_revision: String,
    public_key_base64: String,
    report_path: PathBuf,
    max_age_seconds: u64,
    targets: Vec<Target>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    id: String,
    issuer: String,
    subject: String,
}
pub(super) struct Directory {
    configuration: Configuration,
    namespace: Uuid,
    key: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u16,
    payload_base64: String,
    signature_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u16,
    namespace: Uuid,
    issuer: String,
    audience: String,
    key_revision: String,
    policy_revision: String,
    directory_revision: String,
    observed_at: u64,
    expires_at: u64,
    subjects: Vec<Subject>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    issuer: String,
    subject: String,
    status: Status,
    permissions: Vec<Permission>,
}
#[derive(Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Active,
    Inactive,
    Unknown,
}
fn identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
impl Directory {
    pub(super) fn new(configuration: Configuration, namespace: Uuid) -> Result<Self, Failure> {
        if namespace.is_nil()
            || !configuration.report_path.is_absolute()
            || configuration.report_path.as_os_str().len() > 4096
            || !(1..=30).contains(&configuration.max_age_seconds)
            || configuration.targets.is_empty()
            || configuration.targets.len() > 128
            || [
                &configuration.issuer,
                &configuration.audience,
                &configuration.key_revision,
                &configuration.policy_revision,
            ]
            .iter()
            .any(|s| !identifier(s))
        {
            return Err(Failure::Invalid);
        }
        let key = STANDARD
            .decode(&configuration.public_key_base64)
            .map_err(|_| Failure::Invalid)?
            .try_into()
            .map_err(|_| Failure::Invalid)?;
        let mut ids = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for target in &configuration.targets {
            if !identifier(&target.id)
                || !identifier(&target.issuer)
                || !identifier(&target.subject)
                || !ids.insert(&target.id)
                || !identities.insert((&target.issuer, &target.subject))
            {
                return Err(Failure::Invalid);
            }
        }
        Ok(Self {
            configuration,
            namespace,
            key,
        })
    }
    fn verify(
        &self,
        text: &str,
        target: &str,
        inventory: &Inventory,
    ) -> Result<(u64, u64), Failure> {
        let envelope: Envelope = serde_json::from_str(text).map_err(|_| Failure::Unavailable)?;
        if envelope.schema_version != 1
            || envelope.payload_base64.len() > REPORT_BYTES
            || envelope.signature_base64.len() > 88
        {
            return Err(Failure::Unavailable);
        }
        let payload = STANDARD
            .decode(envelope.payload_base64)
            .map_err(|_| Failure::Unavailable)?;
        let signature = STANDARD
            .decode(envelope.signature_base64)
            .map_err(|_| Failure::Unavailable)?;
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, self.key)
            .verify(&signed, &signature)
            .map_err(|_| Failure::Unavailable)?;
        let report: Report = serde_json::from_slice(&payload).map_err(|_| Failure::Unavailable)?;
        let at = crate::access::now().ok_or(Failure::Unavailable)?;
        let c = &self.configuration;
        if report.schema_version != 1
            || report.namespace != self.namespace
            || report.issuer != c.issuer
            || report.audience != c.audience
            || report.key_revision != c.key_revision
            || report.policy_revision != c.policy_revision
            || !identifier(&report.directory_revision)
            || report.observed_at > at
            || report.expires_at <= at
            || report.expires_at.saturating_sub(report.observed_at) > c.max_age_seconds
            || report.observed_at.saturating_add(c.max_age_seconds) < at
            || report.subjects.len() > 128
        {
            return Err(Failure::Unavailable);
        }
        let target = c
            .targets
            .iter()
            .find(|t| t.id == target)
            .ok_or(Failure::Denied)?;
        let mut found = None;
        let mut identities = BTreeSet::new();
        for subject in &report.subjects {
            if !identifier(&subject.issuer)
                || !identifier(&subject.subject)
                || !identities.insert((&subject.issuer, &subject.subject))
                || subject.permissions.len() > 16
            {
                return Err(Failure::Unavailable);
            }
            // Validate the exact existing scope/operation schema without creating
            // any AuthenticatedIdentity or RequestGrant for a target principal.
            AccessPolicy {
                schema_version: 1,
                // The signed directory reports complete permission entries,
                // not actor roles. Validate each entry independently so two
                // legitimate scopes for an operation stay paired and supported.
                roles: subject
                    .permissions
                    .iter()
                    .enumerate()
                    .map(|(i, permission)| Role {
                        id: format!("directory-recipient-{i}"),
                        permissions: vec![permission.clone()],
                    })
                    .collect(),
                bindings: vec![],
            }
            .compile()
            .map_err(|_| Failure::Unavailable)?;
            if subject.issuer == target.issuer && subject.subject == target.subject {
                found = Some(subject);
            }
        }
        let subject = found
            .filter(|s| s.status == Status::Active)
            .ok_or(Failure::Denied)?;
        if !inventory.scopes.iter().all(|scope| {
            [Operation::ReadCases, Operation::ReadFindings]
                .iter()
                .all(|op| {
                    subject
                        .permissions
                        .iter()
                        .any(|p| p.operation == *op && p.scope.allows(scope.facts()))
                })
        }) {
            return Err(Failure::Denied);
        }
        Ok((report.observed_at, report.expires_at))
    }
    pub(super) async fn verify_target(
        self: &Arc<Self>,
        target: &str,
        request: &CaseRequest,
        inventory: &Inventory,
        context: &FindingContext,
    ) -> Result<TargetLease, Failure> {
        super::check(context)?;
        let directory = self.clone();
        let target_owned = target.to_owned();
        // Bound work before cloning data into the physically leased file reader.
        let inventory_owned = Inventory {
            references: inventory.references.clone(),
            scopes: inventory.scopes.clone(),
            digest: inventory.digest,
            ranges: inventory.ranges.clone(),
            leases: inventory.leases.clone(),
        };
        let (not_before, expires_at) = crate::config::read_limited_document(
            self.configuration.report_path.clone(),
            REPORT_BYTES,
            context.deadline,
            context.cancellation.clone(),
            move |text| {
                directory
                    .verify(text, &target_owned, &inventory_owned)
                    .map_err(|_| {
                        crate::config::ConfigError::Invalid("assignee eligibility unavailable")
                    })
            },
        )
        .await
        .map_err(|_| Failure::Unavailable)?;
        super::check(context)?;
        Ok(TargetLease {
            target: target.into(),
            case_id: request.case_id,
            operation_id: request.operation_id,
            inventory: inventory.digest,
            not_before,
            expires_at,
        })
    }
}
pub(super) struct TargetLease {
    target: String,
    case_id: Uuid,
    operation_id: Uuid,
    inventory: [u8; 32],
    pub(super) not_before: u64,
    pub(super) expires_at: u64,
}
impl TargetLease {
    pub(super) fn check(
        &self,
        request: &CaseRequest,
        inventory: &Inventory,
    ) -> Result<(), Failure> {
        let at = crate::access::now().ok_or(Failure::Unavailable)?;
        if request.case_id != self.case_id
            || request.operation_id != self.operation_id
            || inventory.digest != self.inventory
            || at < self.not_before
            || at >= self.expires_at
            || !matches!(&request.change, signal_findings::cases::CaseChange::Assign { assignee: Some(id) } if id == &self.target)
        {
            return Err(Failure::Denied);
        }
        Ok(())
    }
}

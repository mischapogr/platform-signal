//! Bounded historical state decisions. Fresh host authority is never deserialized.
mod evaluate;
mod input;
pub mod replay;
pub use evaluate::{assess, query};
pub use input::Input;

use crate::baseline::Status;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use signal_findings::Finding;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_STATE_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 65536;
pub const MAX_ENTRIES: usize = 128;
pub const MAX_GRANTS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Detection {
    #[serde(rename = "SIG-D04")]
    D04,
    #[serde(rename = "SIG-D06")]
    D06,
    #[serde(rename = "SIG-D08")]
    D08,
    #[serde(rename = "SIG-D09")]
    D09,
    #[serde(rename = "SIG-D12")]
    D12,
    #[serde(rename = "SIG-D13")]
    D13,
}
impl Detection {
    pub fn id(self) -> &'static str {
        match self {
            Self::D04 => "SIG-D04",
            Self::D06 => "SIG-D06",
            Self::D08 => "SIG-D08",
            Self::D09 => "SIG-D09",
            Self::D12 => "SIG-D12",
            Self::D13 => "SIG-D13",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    Aws { account: String },
    Kubernetes { cluster: String },
    Host { host: String, boot: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Impersonation {
    Reject,
    UseEffective,
}

/// Trusted source/state checks performed afresh by the consuming host. None of
/// these fields may come from event claims or a deserialized prior assessment.
pub struct HostContext {
    pub source_binding: [u8; 32],
    pub source_type: String,
    pub source_name: Option<String>,
    pub scope: Scope,
    pub source_config_revision: String,
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
    pub authority_keys_sha256: [u8; 32],
    pub state_authority_revision: String,
    pub verification_reference: String,
    pub verified_at: DateTime<Utc>,
    pub verified_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub ready: bool,
    pub impersonation: Impersonation,
}

/// Native source facts for a private lookup request, never an approval grant.
#[derive(Clone, Debug, Serialize)]
pub struct Query {
    pub applicable: bool,
    pub scope: Scope,
    pub actor: String,
    pub locator: String,
    pub native_target: Option<String>,
    pub change: String,
    pub action: String,
    pub outcome: String,
    pub namespace: String,
    pub name: String,
    pub resource: String,
    pub verb: String,
    pub process: Option<ProcessIdentity>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub host: String,
    pub boot: String,
    pub pid: u64,
    pub start_epoch_ns: u64,
    pub execution_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub from: DateTime<Utc>,
    pub until: DateTime<Utc>,
}
impl Interval {
    pub fn contains(&self, at: DateTime<Utc>) -> bool {
        self.from < self.until && self.from <= at && at < self.until
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub id: String,
    pub actor: String,
    pub target: String,
    pub action: String,
    /// Empty means an explicitly approved named operation within the interval.
    /// A nonempty value restricts it to one exact native change identity.
    pub change: String,
    pub validity: Interval,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Subject {
    User {
        name: String,
    },
    ServiceAccount {
        namespace: String,
        name: String,
    },
    /// Explicitly represent rather than silently expand unsupported group input.
    Group {
        name: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Permission {
    Iam {
        principal: String,
        action: String,
        resource: String,
    },
    Rbac {
        subject: Subject,
        api_group: String,
        resource: String,
        namespace: Option<String>,
        resource_name: Option<String>,
        verb: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unsupported {
    Conditions,
    Wildcards,
    Deny,
    NotAction,
    NotResource,
    Groups,
    Boundaries,
    OrganizationPolicies,
    SessionPolicies,
    Aggregation,
    NonResourceUrls,
    UnresolvedReferences,
    AdditionalAuthorizers,
    UnknownUniverse,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IamView {
    pub revision: String,
    pub principal_id: String,
    pub complete: bool,
    pub unsupported: Vec<Unsupported>,
    pub grants: Vec<Permission>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceGrant {
    pub api_group: String,
    pub resource: String,
    /// False denotes a cluster-scoped API resource, not an unknown scope.
    pub namespaced: bool,
    pub resource_name: Option<String>,
    pub verb: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub uid: String,
    pub revision: String,
    pub name: String,
    /// None is a ClusterRole. Namespaced roles cannot grant cluster resources.
    pub namespace: Option<String>,
    pub grants: Vec<ResourceGrant>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub uid: String,
    pub revision: String,
    pub name: String,
    pub namespace: Option<String>,
    pub cluster_role: bool,
    pub role_name: String,
    pub subjects: Vec<Subject>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RbacView {
    pub revision: String,
    pub complete: bool,
    pub unsupported: Vec<Unsupported>,
    /// Exact finite namespace universe, independently attested complete.
    pub namespaces: Vec<String>,
    pub roles: Vec<Role>,
    pub bindings: Vec<Binding>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadVersion {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub revision: String,
    pub validity: Interval,
    pub sensitive: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessVersion {
    pub host: String,
    pub boot: String,
    pub pid: u64,
    pub start_epoch_ns: u64,
    pub execution_sequence: u64,
    pub executable_sha256: [u8; 32],
    pub revision: String,
    pub validity: Interval,
    pub privileged: bool,
    pub provenance_verified: bool,
    pub approved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Data {
    Credentials {
        approvals: Vec<Approval>,
    },
    Iam {
        before: IamView,
        after: IamView,
        approved: Vec<Permission>,
    },
    Rbac {
        before: RbacView,
        after: RbacView,
        approved: Vec<Permission>,
    },
    Workload {
        history: Vec<WorkloadVersion>,
        approvals: Vec<Approval>,
    },
    Process {
        history: Vec<ProcessVersion>,
    },
}

/// Retained data, not fresh authority. The host separately attests this exact
/// input/scope/history and authority revision via non-deserializable HostContext.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u16,
    pub rule: Detection,
    pub source_binding: [u8; 32],
    pub input_sha256: [u8; 32],
    pub scope: Scope,
    pub authority_revision: String,
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
    pub authority_keys_sha256: [u8; 32],
    pub source_config_revision: String,
    pub revision: String,
    pub validity: Interval,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub complete: bool,
    pub actor: String,
    pub locator: String,
    pub change: String,
    /// Immutable principal/object identity; a name is only a locator.
    pub resolved_target: String,
    pub data: Data,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    DeferredDatabaseSource,
    HostUnverified,
    SourceMismatch,
    MissingSourceField,
    UnsupportedSource,
    UnsupportedSemantics,
    StateMissing,
    StateStale,
    StateMismatch,
    IncompleteInventory,
    AmbiguousHistory,
}

/// Historical verification record; deserializing it never constructs HostContext.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostEvidence {
    pub source_binding: [u8; 32],
    pub scope: Scope,
    pub source_type: String,
    pub source_name: Option<String>,
    pub source_config_revision: String,
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
    pub authority_keys_sha256: [u8; 32],
    pub state_authority_revision: String,
    pub verification_reference: String,
    pub verified_at: DateTime<Utc>,
    pub verified_until: DateTime<Utc>,
    pub assessed_at: DateTime<Utc>,
    pub ready: bool,
    pub effective_impersonation: bool,
}
impl HostContext {
    pub(crate) fn retained(&self) -> HostEvidence {
        HostEvidence {
            source_binding: self.source_binding,
            scope: self.scope.clone(),
            source_type: self.source_type.clone(),
            source_name: self.source_name.clone(),
            source_config_revision: self.source_config_revision.clone(),
            policy_revision: self.policy_revision.clone(),
            policy_config_sha256: self.policy_config_sha256,
            authority_keys_sha256: self.authority_keys_sha256,
            state_authority_revision: self.state_authority_revision.clone(),
            verification_reference: self.verification_reference.clone(),
            verified_at: self.verified_at,
            verified_until: self.verified_until,
            assessed_at: self.now,
            ready: self.ready,
            effective_impersonation: self.impersonation == Impersonation::UseEffective,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Decision {
    pub schema_version: u16,
    pub detector_revision: &'static str,
    pub rule: Detection,
    pub event_id: Uuid,
    pub input_sha256: [u8; 32],
    pub state_sha256: Option<[u8; 32]>,
    pub host_evidence: HostEvidence,
    pub source_binding: [u8; 32],
    pub source_config_revision: String,
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
    pub authority_keys_sha256: [u8; 32],
    pub state_revision: Option<String>,
    pub status: Status,
    pub applicable: bool,
    pub coverage_gap: bool,
    pub gap: Option<Gap>,
    pub target: Option<String>,
    pub approval_ids: Vec<String>,
    pub added_permissions: Vec<Permission>,
    pub finding: Option<Finding>,
    #[serde(skip)]
    pub(crate) seal: [u8; 32],
    #[serde(skip)]
    pub(crate) original_context: crate::RuleContext,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid scoped state input or configuration")]
    Invalid,
    #[error("scoped state capacity exceeded")]
    Capacity,
    #[error("scoped state original deadline or cancellation")]
    Cancelled,
    #[error("scoped state durable binding or replay conflict")]
    Conflict,
    #[error("scoped state journal operation failed; reload before retry")]
    Journal,
}

pub(crate) fn check(context: &crate::RuleContext) -> Result<(), Error> {
    context.check().map_err(|_| Error::Cancelled)
}
pub(crate) fn identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
pub(crate) fn scope_valid(scope: &Scope) -> bool {
    match scope {
        Scope::Aws { account } => {
            account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())
        }
        Scope::Kubernetes { cluster } => identity(cluster),
        Scope::Host { host, boot } => {
            identity(host) && identity(boot) && Uuid::parse_str(boot).is_ok_and(|b| !b.is_nil())
        }
    }
}

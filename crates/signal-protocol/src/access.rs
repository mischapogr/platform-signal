//! Bounded host-trusted identity and explicit operation/resource permissions.
//! This module does not authenticate tokens, headers, or provider transports.
pub mod introspection;

use serde::{Deserialize, Serialize};
use signal_event::SignalEvent;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::Arc,
};
use thiserror::Error;

pub const POLICY_BYTES: usize = 256 * 1024;
const MAX_ROLES: usize = 64;
const MAX_BINDINGS: usize = 1024;
const MAX_SUBJECT_ROLES: usize = 8;
const MAX_PERMISSIONS: usize = 16;
const MAX_SELECTORS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    IngestEvents,
    QueryEvents,
    ReadFindings,
    ReadFindingsFeed,
    ReadEvidence,
    ReadCoverage,
    WriteCoverage,
    Configure,
    ManageRules,
    ReadAudit,
}
impl Operation {
    // The current feed/global controls have no row-scope contract. Never imply
    // safe per-account filtering by accepting a restricted grant for them.
    fn global_only(self) -> bool {
        matches!(
            self,
            Self::ReadFindingsFeed | Self::Configure | Self::ManageRules | Self::ReadAudit
        )
    }
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "mode",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Selection {
    All,
    /// Exact UTF-8 equality only, with no glob/regex/prefix expansion.
    Only(Vec<String>),
}
impl Selection {
    fn compact(self) -> Self {
        match self {
            Self::All => Self::All,
            Self::Only(values) => Self::Only(compact_vec(
                values.into_iter().map(compact_string).collect(),
            )),
        }
    }
    fn preflight(&self) -> Result<(), AccessError> {
        if let Self::Only(values) = self {
            if values.is_empty() || values.len() > MAX_SELECTORS {
                return Err(AccessError::InvalidPolicy("selector count"));
            }
            if values.iter().any(|value| !identifier(value, 256)) {
                return Err(AccessError::InvalidPolicy("selector identity"));
            }
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), AccessError> {
        self.preflight()?;
        if let Self::Only(values) = self {
            let mut seen = BTreeSet::new();
            for value in values {
                if !seen.insert(value.as_str()) {
                    return Err(AccessError::InvalidPolicy("selector identity"));
                }
            }
        }
        Ok(())
    }
    fn allows(&self, fact: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::Only(values) => fact.is_some_and(|fact| values.iter().any(|value| value == fact)),
        }
    }
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScope {
    pub sources: Selection,
    pub accounts: Selection,
    pub resources: Selection,
}
impl ResourceScope {
    fn compact(self) -> Self {
        Self {
            sources: self.sources.compact(),
            accounts: self.accounts.compact(),
            resources: self.resources.compact(),
        }
    }
    /// Explicit operator/host choice, never an input/default scope.
    pub fn all() -> Self {
        Self {
            sources: Selection::All,
            accounts: Selection::All,
            resources: Selection::All,
        }
    }
    pub fn is_all(&self) -> bool {
        matches!(self.sources, Selection::All)
            && matches!(self.accounts, Selection::All)
            && matches!(self.resources, Selection::All)
    }
    pub fn allows(&self, facts: ScopeFacts<'_>) -> bool {
        self.sources.allows(facts.source)
            && self.accounts.allows(facts.account)
            && self.resources.allows(facts.resource)
    }
    fn validate(&self) -> Result<(), AccessError> {
        self.sources.validate()?;
        self.accounts.validate()?;
        self.resources.validate()
    }
    fn preflight(&self) -> Result<(), AccessError> {
        self.sources.preflight()?;
        self.accounts.preflight()?;
        self.resources.preflight()
    }
}
/// Facts from an authoritative host context, not forwarded identity headers.
/// Missing identity never satisfies a restricted selector.
#[derive(Clone, Copy)]
pub struct ScopeFacts<'a> {
    pub source: Option<&'a str>,
    pub account: Option<&'a str>,
    pub resource: Option<&'a str>,
}
impl<'a> ScopeFacts<'a> {
    /// Arbitrary event attributes do not participate in access-control identity.
    pub fn event(event: &'a SignalEvent) -> Self {
        Self {
            source: Some(&event.source.source_type),
            account: event
                .resource
                .as_ref()
                .and_then(|r| r.account_id.as_deref()),
            resource: event.resource.as_ref().map(|r| r.id.as_str()),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub operation: Operation,
    pub scope: ResourceScope,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub id: String,
    pub permissions: Vec<Permission>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectBinding {
    pub issuer: String,
    pub subject: String,
    pub roles: Vec<String>,
}
/// Operator-supplied policy. Real subjects, groups, roles and scopes stay private.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    pub schema_version: u16,
    pub roles: Vec<Role>,
    pub bindings: Vec<SubjectBinding>,
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum AccessError {
    #[error("invalid bounded access policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid authenticated identity")]
    InvalidIdentity,
    #[error("access denied")]
    Denied,
    #[error("authenticated identity expired or clock moved backwards")]
    Expired,
}
/// Immutable bounded compiled policy. There is no mutable producer-owned grant.
pub struct CompiledPolicy {
    roles: Vec<Role>,
    subjects: BTreeMap<String, BTreeMap<String, Vec<usize>>>,
}
impl AccessPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, AccessError> {
        if bytes.is_empty() || bytes.len() > POLICY_BYTES {
            return Err(AccessError::InvalidPolicy("document byte bound"));
        }
        if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
            return Err(AccessError::InvalidPolicy("document schema"));
        }
        serde_json::from_slice(bytes).map_err(|_| AccessError::InvalidPolicy("document schema"))
    }
    /// Validation precedes any compiled lookup/permission use. Empty policy is
    /// an explicit deny-all configuration; unknown role references fail closed.
    pub fn compile(self) -> Result<Arc<CompiledPolicy>, AccessError> {
        if self.schema_version != 1
            || self.roles.len() > MAX_ROLES
            || self.bindings.len() > MAX_BINDINGS
        {
            return Err(AccessError::InvalidPolicy("version or collection count"));
        }
        // Reject oversized programmatic strings/counts before the serializer
        // scans them (its writer byte limit alone cannot bound that CPU walk).
        for role in &self.roles {
            if !identifier(&role.id, 128)
                || role.permissions.is_empty()
                || role.permissions.len() > MAX_PERMISSIONS
            {
                return Err(AccessError::InvalidPolicy("role identity or permissions"));
            }
            for permission in &role.permissions {
                permission.scope.preflight()?;
            }
        }
        for binding in &self.bindings {
            if !identifier(&binding.issuer, 2048)
                || !identifier(&binding.subject, 256)
                || binding.roles.is_empty()
                || binding.roles.len() > MAX_SUBJECT_ROLES
                || binding.roles.iter().any(|role| !identifier(role, 128))
            {
                return Err(AccessError::InvalidPolicy("subject identity or roles"));
            }
        }
        // Programmatic input may have enormous spare capacities. Preflight its
        // logical bytes before building lookup maps, then compact retained data.
        let mut bytes = PolicyBytes(0);
        serde_json::to_writer(&mut bytes, &self)
            .map_err(|_| AccessError::InvalidPolicy("encoded document byte bound"))?;
        let mut role_ids = BTreeMap::new();
        for (index, role) in self.roles.iter().enumerate() {
            if !identifier(&role.id, 128)
                || role.permissions.is_empty()
                || role.permissions.len() > MAX_PERMISSIONS
                || role_ids.insert(role.id.as_str(), index).is_some()
            {
                return Err(AccessError::InvalidPolicy("role identity or permissions"));
            }
            let mut operations = BTreeSet::new();
            for permission in &role.permissions {
                permission.scope.validate()?;
                if !operations.insert(permission.operation)
                    || permission.operation.global_only() && !permission.scope.is_all()
                {
                    return Err(AccessError::InvalidPolicy(
                        "duplicate or unsupported scoped operation",
                    ));
                }
            }
        }
        let mut subjects: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
        for binding in &self.bindings {
            if !identifier(&binding.issuer, 2048)
                || !identifier(&binding.subject, 256)
                || binding.roles.is_empty()
                || binding.roles.len() > MAX_SUBJECT_ROLES
            {
                return Err(AccessError::InvalidPolicy("subject identity or roles"));
            }
            let mut seen = BTreeSet::new();
            let mut assigned = Vec::with_capacity(binding.roles.len());
            for role in &binding.roles {
                if !seen.insert(role.as_str()) {
                    return Err(AccessError::InvalidPolicy("duplicate assigned role"));
                }
                assigned.push(
                    *role_ids
                        .get(role.as_str())
                        .ok_or(AccessError::InvalidPolicy("unknown assigned role"))?,
                );
            }
            if subjects
                .entry(compact_string(binding.issuer.clone()))
                .or_default()
                .insert(
                    compact_string(binding.subject.clone()),
                    compact_vec(assigned),
                )
                .is_some()
            {
                return Err(AccessError::InvalidPolicy("duplicate subject binding"));
            }
        }
        // role_ids borrows the input; destroy it before adopting compact roles.
        drop(role_ids);
        let roles = compact_vec(
            self.roles
                .into_iter()
                .map(|role| Role {
                    id: compact_string(role.id),
                    permissions: compact_vec(
                        role.permissions
                            .into_iter()
                            .map(|permission| Permission {
                                operation: permission.operation,
                                scope: permission.scope.compact(),
                            })
                            .collect(),
                    ),
                })
                .collect(),
        );
        Ok(Arc::new(CompiledPolicy { roles, subjects }))
    }
}
fn compact_vec<T>(values: Vec<T>) -> Vec<T> {
    values.into_boxed_slice().into_vec()
}
fn compact_string(value: String) -> String {
    value.into_boxed_str().into_string()
}
fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
struct PolicyBytes(usize);
impl Write for PolicyBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= POLICY_BYTES)
            .ok_or_else(|| std::io::Error::other("access policy byte bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// A trusted backend's verified result. No Deserialize/Debug/serialization path
/// lets a network header/body turn itself into an authenticated identity.
pub struct AuthenticatedIdentity {
    issuer: String,
    subject: String,
    verified_at: u64,
    expires_at: u64,
}
impl AuthenticatedIdentity {
    /// Host trust boundary: caller must have authenticated the provider/token,
    /// exact issuer/audience, active status and expiry. This constructor itself
    /// proves none of those checks. Never call it with unverified HTTP claims.
    pub fn from_verified_backend(
        issuer: String,
        subject: String,
        verified_at: u64,
        expires_at: u64,
    ) -> Result<Self, AccessError> {
        if !identifier(&issuer, 2048)
            || !identifier(&subject, 256)
            || verified_at >= expires_at
            || expires_at > 253_402_300_799
        {
            return Err(AccessError::InvalidIdentity);
        }
        Ok(Self {
            issuer: compact_string(issuer),
            subject: compact_string(subject),
            verified_at,
            expires_at,
        })
    }
    fn valid_at(&self, now: u64) -> bool {
        self.verified_at <= now && now < self.expires_at
    }
}
/// Request-local host grant. It is not a signed token, persistent authorization
/// proof, revocation cache, or transport authentication. Recheck at use time.
pub struct RequestGrant {
    policy: Arc<CompiledPolicy>,
    identity: AuthenticatedIdentity,
    roles: Vec<usize>,
    issued_at: u64,
}
impl CompiledPolicy {
    pub fn grant(
        self: &Arc<Self>,
        identity: AuthenticatedIdentity,
        now: u64,
    ) -> Result<RequestGrant, AccessError> {
        if !identity.valid_at(now) {
            return Err(AccessError::Expired);
        }
        let roles = self
            .subjects
            .get(&identity.issuer)
            .and_then(|subjects| subjects.get(&identity.subject))
            .ok_or(AccessError::Denied)?
            .clone();
        Ok(RequestGrant {
            policy: self.clone(),
            identity,
            roles,
            issued_at: now,
        })
    }
}
impl RequestGrant {
    /// Exact backend-verified actor match for a private full-binding mapper.
    /// This is not a forwarded identity or permission; capability remains separate.
    pub fn subject_matches(&self, issuer: &str, subject: &str, now: u64) -> bool {
        now >= self.issued_at
            && self.identity.valid_at(now)
            && self.identity.issuer == issuer
            && self.identity.subject == subject
    }
    /// Host-only pseudonymous audit reference for the verified live issuer/subject.
    /// It is metadata, not a token, capability, revocation cache or identity proof.
    /// Framing prevents delimiter ambiguity; no bearer/header material is hashed.
    pub fn audit_subject_key(&self, now: u64) -> Option<String> {
        use sha2::{Digest, Sha256};
        if now < self.issued_at || !self.identity.valid_at(now) {
            return None;
        }
        let mut hash = Sha256::new();
        hash.update(b"signal.audit.subject.v1\0");
        hash.update((self.identity.issuer.len() as u64).to_be_bytes());
        hash.update(self.identity.issuer.as_bytes());
        hash.update((self.identity.subject.len() as u64).to_be_bytes());
        hash.update(self.identity.subject.as_bytes());
        Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }
    /// Immutable request-local lease bounds for a trusted downstream adapter.
    /// Never persist these timestamps as proof or extend them across requests.
    pub fn lease_bounds(&self) -> (u64, u64) {
        (self.issued_at, self.identity.expires_at)
    }

    /// Operation and scope stay paired. Never union operations and selectors
    /// independently across roles, which would cross-combine privileges.
    pub fn allows(&self, operation: Operation, facts: ScopeFacts<'_>, now: u64) -> bool {
        if now < self.issued_at || !self.identity.valid_at(now) {
            return false;
        }
        // Indices come only from validated immutable policy lookup; no external
        // input or mutable policy can invalidate them.
        self.roles.iter().any(|&index| {
            self.policy.roles[index]
                .permissions
                .iter()
                .any(|permission| {
                    permission.operation == operation && permission.scope.allows(facts)
                })
        })
    }
    /// Host-only query integration may read these exact paired selectors to
    /// impose mandatory row predicates before limits/serialization. Expired
    /// grants return no selectors; they never authorize an unfiltered fallback.
    pub fn scopes(&self, operation: Operation, now: u64) -> impl Iterator<Item = &ResourceScope> {
        let valid = now >= self.issued_at && self.identity.valid_at(now);
        self.roles
            .iter()
            .flat_map(move |&index| self.policy.roles[index].permissions.iter())
            .filter(move |permission| valid && permission.operation == operation)
            .map(|permission| &permission.scope)
    }
}
#[cfg(test)]
mod tests;

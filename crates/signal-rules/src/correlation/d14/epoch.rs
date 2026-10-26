//! Fresh independently verified capture and proof-only policy coverage.
use super::*;
use crate::correlation::binding::BindingView;

/// Retained assertions from a host verifier; serialized data is never fresh proof.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvidence {
    pub enrollment_sha256: [u8; 32],
    pub metadata_only: bool,
    pub execution_continuity: bool,
    pub clock_continuity: bool,
}
/// Private verifier results, not producer fields and not deserializable.
pub struct RuntimeVerification {
    pub source: crate::correlation::Verification,
    pub capture: CaptureEvidence,
}
/// Policy sources have an independent revision/range, not a runtime position.
pub struct PolicyCoverageVerification {
    pub enrollment_sha256: [u8; 32],
    pub authority: Uuid,
    pub authority_binding: [u8; 32],
    pub config_revision: String,
    pub authority_keys_sha256: [u8; 32],
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
    pub reference: String,
    pub verified_at: DateTime<Utc>,
    pub verified_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub coverage_from: DateTime<Utc>,
    pub frontier: DateTime<Utc>,
    pub complete: bool,
    pub authenticated: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyCoverageEvidence {
    enrollment_sha256: [u8; 32],
    pub(in crate::correlation) authority: Uuid,
    authority_binding: [u8; 32],
    config_revision: String,
    authority_keys_sha256: [u8; 32],
    policy_revision: String,
    policy_config_sha256: [u8; 32],
    reference: String,
    verified_at: DateTime<Utc>,
    pub(in crate::correlation) verified_until: DateTime<Utc>,
    pub(in crate::correlation) assessed_at: DateTime<Utc>,
    coverage_from: DateTime<Utc>,
    pub(in crate::correlation) frontier: DateTime<Utc>,
    complete: bool,
}
impl PolicyCoverageEvidence {
    /// Historical validation only, no fresh epoch or permission is constructed.
    pub fn validate_historical(&self, b: &RuntimeBinding, c: &RuleContext) -> Result<(), Error> {
        check(c)?;
        let a = b
            .config
            .policy_authorities
            .iter()
            .find(|a| a.id == self.authority)
            .ok_or(Error::Unverified)?;
        if self.enrollment_sha256 != b.digest
            || self.authority_binding != a.binding
            || self.config_revision != a.config_revision
            || self.authority_keys_sha256 != a.authority_keys_sha256
            || self.policy_revision != a.policy_revision
            || self.policy_config_sha256 != a.policy_config_sha256
            || !identity(&self.reference)
            || self.verified_at > self.assessed_at
            || self.assessed_at >= self.verified_until
            || self.coverage_from > self.frontier
            || self.frontier > self.assessed_at
        {
            return Err(Error::Unverified);
        }
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.complete
    }
    pub fn coverage_from(&self) -> DateTime<Utc> {
        self.coverage_from
    }
    pub fn frontier(&self) -> DateTime<Utc> {
        self.frontier
    }
}
pub(in crate::correlation) fn coverage_evidence(
    b: &RuntimeBinding,
    p: PolicyCoverageVerification,
    c: &RuleContext,
) -> Result<PolicyCoverageEvidence, Error> {
    check(c)?;
    if !p.authenticated {
        return Err(Error::Unverified);
    }
    let e = PolicyCoverageEvidence {
        enrollment_sha256: p.enrollment_sha256,
        authority: p.authority,
        authority_binding: p.authority_binding,
        config_revision: p.config_revision,
        authority_keys_sha256: p.authority_keys_sha256,
        policy_revision: p.policy_revision,
        policy_config_sha256: p.policy_config_sha256,
        reference: p.reference,
        verified_at: p.verified_at,
        verified_until: p.verified_until,
        assessed_at: p.now,
        coverage_from: p.coverage_from,
        frontier: p.frontier,
        complete: p.complete,
    };
    e.validate_historical(b, c)?;
    Ok(e)
}
/// Non-deserializable freshness boundary. Source/policy data never self-promote.
pub struct RuntimeEpoch {
    pub(in crate::correlation) inner: crate::correlation::Epoch,
}
impl RuntimeEpoch {
    pub fn new(
        b: &RuntimeBinding,
        sources: Vec<RuntimeVerification>,
        policies: Vec<PolicyCoverageVerification>,
        c: &RuleContext,
    ) -> Result<Self, Error> {
        check(c)?;
        if sources.len() > b.config.sources.len()
            || policies.len() > b.config.policy_authorities.len()
        {
            return Err(Error::Invalid);
        }
        let inner = crate::correlation::Epoch::new_with(
            &BindingView::runtime(b),
            sources
                .into_iter()
                .map(|s| (s.source, Some(s.capture)))
                .collect(),
            policies,
            c,
        )?;
        Ok(Self { inner })
    }
    pub fn watermark(
        &self,
        b: &RuntimeBinding,
        c: &RuleContext,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        self.inner.valid_with(&BindingView::runtime(b), c)?;
        Ok(self.inner.watermark_with(&BindingView::runtime(b)))
    }
    pub fn has_coverage_gap(&self, b: &RuntimeBinding, c: &RuleContext) -> Result<bool, Error> {
        Ok(self.watermark(b, c)?.is_none()
            || self.inner.evidence.iter().any(|p| !p.complete)
            || self.inner.policy.iter().any(|p| !p.complete))
    }
    /// Source authentication, scope and processed-prefix authorization only;
    /// classification, complete history and publication are separate checks.
    pub fn verify_input(
        &self,
        b: &RuntimeBinding,
        input: &Input,
        position: u64,
        c: &RuleContext,
    ) -> Result<(), Error> {
        self.inner.valid_with(&BindingView::runtime(b), c)?;
        check(&input.original)?;
        if input.binding != b.digest || position == 0 {
            return Err(Error::Conflict);
        }
        let p = self.inner.proof(input.stream)?;
        if position > p.position
            || input.event.timestamp < p.coverage_from
            || input.event.timestamp > p.frontier
        {
            return Err(Error::Unverified);
        }
        if let Some(i) = input.operation().interval() {
            let from = p
                .coverage_from
                .timestamp_nanos_opt()
                .ok_or(Error::Unverified)?;
            let through = p.frontier.timestamp_nanos_opt().ok_or(Error::Unverified)?;
            if from < 0 || through < 0 || (from as u64) > i.entry_ns || (through as u64) < i.exit_ns
            {
                return Err(Error::Unverified);
            }
        }
        Ok(())
    }
}

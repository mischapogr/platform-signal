//! One bounded independent probe, immutable evidence and observer-owned health.
//! Probe implementations/application policy authenticate native source proofs;
//! this module never derives coverage from telemetry admission or a heartbeat.
use super::*;
use crate::{ExtensionContext, ExtensionError, extension};

/// Static diagnostics exclude source contents, proof URLs and credentials.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProbeFailure {
    #[error("observer source permission denied")]
    Denied,
    #[error("observer source throttled")]
    Throttled,
    #[error("observer source unavailable")]
    Unavailable,
    #[error("observer source unsupported")]
    Unsupported,
    #[error("observer source response malformed")]
    Malformed,
}
#[derive(Debug, Error)]
pub enum ObserverError {
    #[error(transparent)]
    Validation(#[from] CoverageError),
    #[error(transparent)]
    Operation(#[from] ExtensionError),
    #[error(transparent)]
    Probe(#[from] ProbeFailure),
    #[error("observer current scope does not match configuration")]
    Scope,
    #[error("observer report verification is in the future")]
    Future,
    #[error("observer report verification moved backwards")]
    Regressed,
    #[error("observer report changed claims without new verification")]
    ChangedClaims,
    #[error("observer record ID conflicts with retained immutable bytes")]
    IdentityConflict,
}
/// One source assertion bounded before copying. Semantic/proof authentication is
/// not granted by constructing this type. No Debug, serialization or cloning.
pub struct ProbeReport(Vec<u8>);
impl ProbeReport {
    pub fn new(bytes: &[u8]) -> Result<Self, ObserverError> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(CoverageError::RecordBytesExceeded.into());
        }
        Ok(Self(bytes.to_vec()))
    }
}
/// Validated trusted current request, borrowed only for one probe invocation.
/// Names/profile references do not authenticate source or observer identity.
pub struct ProbeRequest<'a> {
    raw: &'a [u8],
    profile: &'a CoverageProfile,
}
impl ProbeRequest<'_> {
    pub fn context_bytes(&self) -> &[u8] {
        self.raw
    }
    pub fn profile(&self) -> &CoverageProfile {
        self.profile
    }
}
#[extension]
pub trait CoverageProbe: Send + Sync {
    /// Independently read effective source configuration/scope/checkpoints and
    /// proofs. Bound all input/I/O and cancel owned work on future drop.
    async fn probe(
        &self,
        request: &ProbeRequest<'_>,
        context: &ExtensionContext,
    ) -> Result<ProbeReport, ProbeFailure>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverHealth {
    Unknown,
    Healthy,
    Unhealthy,
}
/// Read-only native result; the report retains the versioned SourceCoverage v1
/// serialization. Assessment remains source status, distinct from probe health.
pub struct ObserverPoll {
    record_id: String,
    assessment: CoverageAssessment,
}
impl ObserverPoll {
    pub fn record_id(&self) -> &str {
        &self.record_id
    }
    pub fn assessment(&self) -> &CoverageAssessment {
        &self.assessment
    }
}
struct AcceptedReport {
    raw: Vec<u8>,
    validated: ValidatedCoverage,
}
/// One configured source and one retained bounded observation. A mutable poll
/// borrow supplies capacity one without tasks, queues or a background schedule.
/// Caller owns the aggregate budget for multiple instances/retained outputs.
pub struct CoverageObserver {
    profile: CoverageProfile,
    binding: Binding,
    observer_id: String,
    latest: Option<AcceptedReport>,
    health: ObserverHealth,
}
impl CoverageObserver {
    pub fn new(profile: CoverageProfile, trusted_context: &[u8]) -> Result<Self, ObserverError> {
        let context = CoverageContext::parse(trusted_context)?;
        if context.wire.mode != AssessmentMode::Current
            || context.wire.binding.coverage_profile.id != profile.id()
            || context.wire.binding.coverage_profile.revision != profile.revision()
        {
            return Err(ObserverError::Scope);
        }
        Ok(Self {
            profile,
            binding: context.wire.binding,
            observer_id: context.wire.observer_id,
            latest: None,
            health: ObserverHealth::Unknown,
        })
    }
    pub fn health(&self) -> ObserverHealth {
        self.health
    }
    pub fn latest_bytes(&self) -> Option<&[u8]> {
        self.latest.as_ref().map(|r| r.raw.as_slice())
    }
    pub fn retained_bytes(&self) -> usize {
        self.latest.as_ref().map_or(0, |r| r.raw.len())
    }
    /// Current assessment ignores a supplied healthy flag. Historical consumers
    /// use the separate immutable history API, not this one-report cache.
    pub fn assess(&self, trusted_context: &[u8]) -> Result<CoverageAssessment, ObserverError> {
        let mut context = self.context(trusted_context)?;
        context.wire.observer_status = self.status();
        Ok(self.latest.as_ref().map_or_else(
            || CoverageAssessment::unknown(CoverageReason::ObserverUnknown),
            |r| r.validated.assess(&context),
        ))
    }
    fn context(&self, bytes: &[u8]) -> Result<CoverageContext, ObserverError> {
        let context = CoverageContext::parse(bytes)?;
        if context.wire.mode != AssessmentMode::Current
            || context.wire.binding != self.binding
            || context.wire.observer_id != self.observer_id
        {
            return Err(ObserverError::Scope);
        }
        Ok(context)
    }
    fn validate_report(
        &self,
        report: ProbeReport,
        current: &CoverageContext,
    ) -> Result<AcceptedReport, ObserverError> {
        let validated = ValidatedCoverage::parse(&report.0, Some(&self.profile))?;
        if !validated.wire.matches(&self.binding)
            || validated.wire.provenance.observer_id != self.observer_id
        {
            return Err(ObserverError::Scope);
        }
        let skew = seconds(self.profile.0.max_clock_skew_seconds);
        if validated.verified.signed_duration_since(current.at) > skew
            || validated.observed.signed_duration_since(current.at) > skew
        {
            return Err(ObserverError::Future);
        }
        if let Some(previous) = &self.latest {
            if validated.record_id() == previous.validated.record_id() && report.0 != previous.raw {
                return Err(ObserverError::IdentityConflict);
            }
            if validated.verified < previous.validated.verified {
                return Err(ObserverError::Regressed);
            }
            if validated.verified == previous.validated.verified
                && !same_claims(&validated, &previous.validated)
            {
                return Err(ObserverError::ChangedClaims);
            }
        }
        Ok(AcceptedReport {
            raw: report.0,
            validated,
        })
    }
    fn status(&self) -> ObserverStatus {
        match self.health {
            ObserverHealth::Unknown => ObserverStatus::Unknown,
            ObserverHealth::Healthy => ObserverStatus::Healthy,
            ObserverHealth::Unhealthy => ObserverStatus::Unhealthy,
        }
    }
    pub async fn poll(
        &mut self,
        probe: &dyn CoverageProbe,
        trusted_context: &[u8],
        context: &ExtensionContext,
    ) -> Result<ObserverPoll, ObserverError> {
        let mut current = self.context(trusted_context)?;
        // Mutate before awaiting: a dropped invocation stays unknown; it cannot
        // refresh any evidence or leave the previous health flag promoted.
        self.health = ObserverHealth::Unknown;
        let request = ProbeRequest {
            raw: trusted_context,
            profile: &self.profile,
        };
        let result = async {
            context.check()?;
            let report = tokio::select! {
                biased;
                _ = context.cancellation().cancelled() => return Err(ExtensionError::Cancelled.into()),
                _ = tokio::time::sleep_until(context.deadline()) => return Err(ExtensionError::Timeout.into()),
                result = probe.probe(&request, context) => result?,
            };
            context.check()?;
            let accepted = self.validate_report(report, &current)?;
            context.check()?;
            Ok::<_, ObserverError>(accepted)
        }.await;
        match result {
            Ok(report) => {
                self.health = ObserverHealth::Healthy;
                current.wire.observer_status = ObserverStatus::Healthy;
                let result = ObserverPoll {
                    record_id: report.validated.record_id().into(),
                    assessment: report.validated.assess(&current),
                };
                self.latest = Some(report);
                Ok(result)
            }
            Err(error) => {
                self.health = ObserverHealth::Unhealthy;
                Err(error)
            }
        }
    }
}
fn same_claims(new: &ValidatedCoverage, old: &ValidatedCoverage) -> bool {
    new.start == old.start
        && new.end == old.end
        && new.expires == old.expires
        && new.wire.checkpoint == old.wire.checkpoint
        && new.wire.validation == old.wire.validation
        && new.wire.validation_status == old.wire.validation_status
        && new.wire.gaps == old.wire.gaps
        && new.wire.gap_summary == old.wire.gap_summary
        && new.wire.provenance.method == old.wire.provenance.method
        && new.wire.provenance.proof_refs == old.wire.provenance.proof_refs
}

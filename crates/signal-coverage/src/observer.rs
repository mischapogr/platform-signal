//! Generic observer-to-history bridge. The embedding application supplies a
//! fresh authenticated full-binding grant, receiver clock and pinned policy.
use crate::{
    CoverageError, CoverageStore, CoverageSubmission, IntakeContext, IntakeOutcome,
    OperationContext,
    format::{HistoryBinding, ProfileDefinition},
};
use signal_collector_sdk::{
    ExtensionContext,
    coverage::{
        CoverageProfile, ValidatedCoverage,
        observer::{CoverageReportSink, ProbeFailure, ReportCommit},
    },
};
use std::sync::Arc;
use uuid::Uuid;

#[signal_collector_sdk::extension]
pub trait CoverageIntakeProvider: Send + Sync {
    /// Reauthenticate/authorize current policy before each intake. Names and
    /// proof hashes in a source report never constitute a grant.
    async fn current(&self, context: &ExtensionContext) -> Result<IntakeContext, ProbeFailure>;
}
/// No worker, queue, retry loop or cached grant. The existing store owns finite
/// physical operation leases, global retained identity and uncertain outcomes.
pub struct HistoryReportSink {
    store: Arc<CoverageStore>,
    provider: Arc<dyn CoverageIntakeProvider>,
}
impl HistoryReportSink {
    pub fn new(store: Arc<CoverageStore>, provider: Arc<dyn CoverageIntakeProvider>) -> Self {
        Self { store, provider }
    }
}
#[signal_collector_sdk::extension]
impl CoverageReportSink for HistoryReportSink {
    async fn commit(
        &self,
        report: &[u8],
        profile: &CoverageProfile,
        context: &ExtensionContext,
    ) -> Result<ReportCommit, ProbeFailure> {
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        // The public seam also validates direct callers before copying raw input
        // or consulting a credential/authority provider.
        let validated =
            ValidatedCoverage::parse(report, Some(profile)).map_err(|_| ProbeFailure::Malformed)?;
        let record_id =
            Uuid::parse_str(validated.record_id()).map_err(|_| ProbeFailure::Malformed)?;
        let expected_pin = ProfileDefinition::parse(
            &profile
                .definition_bytes()
                .map_err(|_| ProbeFailure::Malformed)?,
        )
        .map_err(map_error)?;
        let (binding, _) = HistoryBinding::from_record(report).map_err(map_error)?;
        let intake = tokio::select! {
            biased;
            _ = context.cancellation().cancelled() => return Err(ProbeFailure::Unavailable),
            _ = tokio::time::sleep_until(context.deadline()) => return Err(ProbeFailure::Unavailable),
            result = self.provider.current(context) => result?,
        };
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        if intake.authority.binding.encoded() != binding.encoded()
            || intake
                .profile
                .as_ref()
                .is_some_and(|pin| !profile.same_definition(&pin.sdk))
        {
            return Err(ProbeFailure::Denied);
        }
        let submission = CoverageSubmission::new(record_id, report, None).map_err(map_error)?;
        let operation = OperationContext {
            deadline: context.deadline(),
            cancellation: context.cancellation().child_token(),
        };
        let outcome = self
            .store
            .submit(submission, intake, operation)
            .await
            .map_err(map_error)?;
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        let (receipt, disposition) = match outcome {
            IntakeOutcome::Accepted(receipt) => (receipt, ReportCommit::Accepted),
            IntakeOutcome::Replayed(receipt) => (receipt, ReportCommit::Replayed),
        };
        if receipt.profile_fingerprint != crate::format::hex(&expected_pin.fingerprint()) {
            return Err(ProbeFailure::Denied);
        }
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        Ok(disposition)
    }
}
fn map_error(error: CoverageError) -> ProbeFailure {
    match error {
        CoverageError::NotAuthorized | CoverageError::ProfileRevisionConflict => {
            ProbeFailure::Denied
        }
        CoverageError::Capacity | CoverageError::Quota => ProbeFailure::Throttled,
        CoverageError::Invalid(_)
        | CoverageError::Coverage(_)
        | CoverageError::IdContentConflict => ProbeFailure::Malformed,
        _ => ProbeFailure::Unavailable,
    }
}

//! Bounded local coverage persistence, trusted intake and observer bridge.
//! Credential authentication and observation cadence remain application-owned.
pub mod format;
mod intake;
mod observer;
mod scan;
mod store;
mod worker;

pub use intake::{
    AuthorizedBinding, CoverageSubmission, IntakeContext, IntakeOutcome, IntakePolicy,
};
pub use observer::{CoverageIntakeProvider, HistoryReportSink};
pub use scan::{
    MAX_SCAN_CURSOR_TOKEN_BYTES, MAX_SCAN_RESPONSE_BYTES, SCAN_PAGE_HEADER_BYTES,
    SCAN_RECORD_ALLOWANCE_BYTES, SCAN_WORK_ALLOWANCE_BYTES, ScanAvailability, ScanBudget,
    ScanCursor, ScanPage, ScanRecord,
};
pub use store::{
    AdmissionMetadata, CoverageConfig, CoverageError, CoverageMetrics, IdentityPruneBudget,
    IdentityPruneOutcome, PayloadPruneBudget, PayloadPruneOutcome, PreparedObservation, Receipt,
    StoredObservation,
};
pub use worker::{CoverageStore, OperationContext};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod intake_tests;

#[cfg(test)]
mod correction_tests;

#[cfg(test)]
mod pruning_tests;

#[cfg(test)]
mod identity_pruning_tests;

#[cfg(test)]
mod scan_tests;

#[cfg(test)]
mod observer_tests;

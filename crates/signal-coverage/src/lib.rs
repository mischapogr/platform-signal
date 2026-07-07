//! Bounded local coverage persistence and trusted intake. No credential authentication or observers.
pub mod format;
mod intake;
mod store;
mod worker;

pub use intake::{
    AuthorizedBinding, CoverageSubmission, IntakeContext, IntakeOutcome, IntakePolicy,
};
pub use store::{
    AdmissionMetadata, CoverageConfig, CoverageError, CoverageMetrics, PreparedObservation,
    Receipt, StoredObservation,
};
pub use worker::{CoverageStore, OperationContext};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod intake_tests;

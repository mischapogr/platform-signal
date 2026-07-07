//! Bounded local coverage persistence and trusted intake. No credential authentication or observers.
pub mod format;
mod intake;
mod store;
mod worker;

pub use intake::{
    AuthorizedBinding, CoverageSubmission, IntakeContext, IntakeOutcome, IntakePolicy,
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

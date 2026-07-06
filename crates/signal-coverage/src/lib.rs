//! Local prepared coverage persistence. No authentication, source observer or health selection.
pub mod format;
mod store;
mod worker;

pub use store::{
    AdmissionMetadata, CoverageConfig, CoverageError, CoverageMetrics, PreparedObservation,
    Receipt, StoredObservation,
};
pub use worker::{CoverageStore, OperationContext};

#[cfg(test)]
mod tests;

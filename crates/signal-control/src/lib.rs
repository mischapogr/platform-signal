//! Bounded shared-control mechanisms; private policy stays in external adapters.
//! Work in progress: this crate does not enable replicas or claim shared readiness.
mod custody;
mod notification;
mod restored_custody;
pub use custody::{
    CustodyFuture, ObjectCustodyDescription, ObjectCustodyPermit, ObjectCustodyReceipt,
    ObjectCustodyRecorder, ObjectCustodyVerifier, RestoredObjectCustodyResolver,
    RetainedObjectObservation, coordinate_object_custody, coordinate_restored_object_custody,
};
pub use notification::{
    NotificationAction, NotificationInput, NotificationOutcome, NotificationResult,
    NotificationState,
};
mod administration;
pub use administration::{
    AdministrativeResult, AdministrativeScope, ControlAdministrator, InitializeInput,
    MigrationInput, legacy_identity,
};
mod catalog;
mod finding_scope;
mod findings_feed;
pub use finding_scope::{
    FindingScopeAdministrator, FindingScopeBinding, FindingScopeLimits, FindingScopePin,
    FindingScopeProfile, ProducerEnrollment,
};
pub use findings_feed::{RetainedFinding, RetainedFindingsPage};
mod global_feed;
pub use global_feed::AuthorizedFindingsPage;
mod scoped_read;
pub use scoped_read::{AuthorizedFindingsList, ScopedFindingsBinding};
mod client;
pub use catalog::{CatalogInput, CatalogPin, catalog_schema_identity};
mod connection;
pub use client::{ControlClient, ControlMetrics, schema_identity};
mod publication;
mod scoped_publication;
pub use scoped_publication::{ScopedFindingClaims, ScopedPublicationInput};
mod query_source;
mod retention;
mod snapshot;
pub use query_source::{SharedQueryMetrics, SharedQuerySource};
pub use retention::{
    CanonicalObjectRef, ObjectControlResult, ObjectControlState, ReleasePinInput, RetentionKind,
    RetentionPinInput, RetirementInput,
};
mod postgres_restore;
pub use postgres_restore::{
    PostgresStoppedRestore, RestoreConsumers, RestoreDestination, restored_catalog_schema_identity,
    restored_schema_identity,
};
mod restore;
pub use restore::{
    ReconciledConsumers, RestoreAuthority, RestoreChallenge, RestoreConsumerCursor, RestoreCustody,
    RestoreDecision, RestoreFuture, RestoreInventory, RestoreObject, RestorePermit,
    RestoreReadyPermit, RestoreReceipt, RestoreRevision, RestoreSourceCursor,
    StoppedRestoreBackend, coordinate_stopped_restore, resume_stopped_restore,
};
mod types;
pub use connection::ConnectionSettings;
pub use publication::{
    PublicationInput, PublicationResult, ReceiptInput, ReceiptProgress, ReceiptResult,
};
pub use snapshot::{PinnedManifest, SnapshotInput, SnapshotPin};
pub use types::*;

/// Static error classes exclude database replies, credentials and private scope.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("invalid shared control input")]
    Invalid,
    #[error("shared control capacity exhausted")]
    Full,
    #[error("shared control operation cancelled")]
    Cancelled,
    #[error("shared control operation deadline exceeded")]
    Timeout,
    #[error("shared control authority is stale or denied")]
    Fenced,
    #[error("shared findings cursor position unavailable")]
    CursorPositionUnavailable,
    #[error("shared control request conflicts with retained state")]
    Conflict,
    #[error("shared control transaction requires a whole-operation retry")]
    Retryable,
    #[error("shared control snapshot expired")]
    SnapshotExpired,
    #[error("shared control backend unavailable")]
    Unavailable,
    #[error("shared control commit outcome uncertain")]
    Uncertain,
    #[error("shared control schema or retained state invalid")]
    Corrupt,
}

mod state_read;
pub use state_read::{StateReadInput, StateReadResult};

mod canonical_recovery;
pub use canonical_recovery::{
    CanonicalRecoveryLimits, RecoveredCanonicalInputs, recover_canonical_inputs,
    recover_canonical_inputs_at, recover_canonical_rows, retain_canonical_inputs,
    retain_window_canonical_inputs,
};

mod multi_event_claims;
mod multi_event_module;
mod replay_transfer;
mod window_history;
pub use multi_event_claims::{
    MultiEventFindingClaims, MultiEventPublicationInput, MultiEventStateEnvelope,
    PriorStateProvenance,
};
pub use replay_transfer::ReplayPinReplacement;

mod window_history_read;
pub use window_history_read::{HistoryCursor, HistoryInput, HistoryPage};

mod replay_release;
pub use replay_release::ObsoleteReplayPin;

mod window_profile;
pub use window_profile::WindowProfile;

mod finding_lookup;

mod window_pin;

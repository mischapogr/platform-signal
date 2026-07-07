//! Bounded, single-owner immutable source receipts with verified-prefix progress.
//! Includes bounded gzip preparation, ACK control and guarded local reclamation.
//! No network dispatch, source deletion or source proof.
//! A caller timeout/cancellation may race publication: reopen to settle it.
mod ack;
mod capture;
mod discovery;
mod driver;
mod format;
mod http_publisher;
mod preparation;
mod progress;
mod publisher;
mod retirement;
mod store;
pub use ack::{
    ReceiptAckCommit, ReceiptAckUpdate, SourceAckOutcome, SourceAckState, SourceAckTicket,
    SourceDelivery,
};
pub use capture::{
    CaptureError, CaptureFailure, CapturePreparation, CaptureStream, CaptureTransport,
    CapturedObject, MAX_CAPTURE_BYTES, capture_object,
};
pub use discovery::{
    DiscoveryError, MAX_DISCOVERY_BYTES, MAX_DISCOVERY_REFERENCES, ObjectDiscovery, discover_object,
};
pub use driver::{
    AckAuthorization, DeliveryError, DeliveryPolicy, DeliveryStep, QueueDelivery, SourceFailure,
    SourceQueue, collect_delivery,
};
pub use http_publisher::HttpReceiptPublisher;
pub use preparation::{
    OriginalCapture, PreparationError, ReceiptPreparation, ReceiptRetention, prepare_receipt,
};
pub use progress::{ReceiptAttempt, ReceiptProgress, ReceiptRecoveryGrant, ReceiptReplay};
pub use publisher::{
    AdmissionReply, PreparedBatch, PublishFailure, PublishStep, ReceiptBatchLimits,
    ReceiptPublisher, publish_pinned_receipt_batch, publish_receipt_batch,
};
#[cfg(all(test, unix))]
mod tests;

use crate::ExtensionContext;
use serde_json::Value;
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
pub const MIN_QUOTA_BYTES: u64 = 64 * 1024 * 1024;
pub const QUEUE_CAPACITY: usize = 1;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("invalid receipt configuration or owner")]
    Configuration,
    #[error("invalid receipt encoding: {0}")]
    Invalid(&'static str),
    #[error("receipt scope does not match current trusted binding")]
    Scope,
    #[error("receipt process owner does not match")]
    Owner,
    #[error("receipt root is not private, regular or stable")]
    Root,
    #[error("receipt root lock unavailable")]
    Locked,
    #[error("receipt quota exhausted")]
    Quota,
    #[error("receipt slot is occupied")]
    Occupied,
    #[error("retained receipt identity has different bytes")]
    IdentityConflict,
    #[error("receipt publication or recovery is uncertain")]
    Uncertain,
    #[error("custody or retirement progress is not supported by this store slice")]
    UnsupportedProgress,
    #[error("receipt progress snapshot is stale or belongs to another receipt")]
    StaleProgress,
    #[error("receipt history checkpoint does not match independent current authority")]
    History,
    #[error("invalid admission response; no prefix committed")]
    InvalidResponse,
    #[error("source acknowledgement preconditions or ticket do not match")]
    Ack,
    #[error("receipt is retiring or retired; replay and source ACK are blocked")]
    Retired,
    #[error("receipt retirement guard or replacement identity does not match")]
    Retirement,
    #[error("receipt operation cancelled; mutation outcome may be uncertain")]
    Cancelled,
    #[error("receipt deadline expired; mutation outcome may be uncertain")]
    Timeout,
    #[error("receipt worker queue full")]
    Busy,
    #[error("receipt worker closed")]
    Closed,
    #[error("receipt filesystem operation failed: {0:?}")]
    Io(io::ErrorKind),
}
pub(crate) fn io_error(e: io::Error) -> ReceiptError {
    ReceiptError::Io(e.kind())
}
pub(crate) fn check(ctx: &ExtensionContext) -> Result<(), ReceiptError> {
    if ctx.cancellation().is_cancelled() {
        return Err(ReceiptError::Cancelled);
    }
    if tokio::time::Instant::now() >= ctx.deadline() {
        return Err(ReceiptError::Timeout);
    }
    Ok(())
}

/// Bounded trusted application input, not a grant inferred from provider data.
/// Construct from canonical JSON of the complete v1 Binding object. Clone cost
/// is bounded at 64 KiB. It has no wire serialization or mutable field API.
#[derive(Clone, Debug, PartialEq)]
pub struct ReceiptBinding(Value);
impl ReceiptBinding {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let v = format::json(bytes, 65536, 16, 4096)?;
        format::validate_binding(&v)?;
        Ok(Self(v))
    }
}

#[cfg(test)]
type FaultHook = Arc<dyn Fn(store::Stage) -> Result<(), ReceiptError> + Send + Sync>;

#[derive(Clone)]
pub struct ReceiptConfig {
    root: PathBuf,
    quota: u64,
    #[cfg(test)]
    hook: Option<FaultHook>,
}
impl ReceiptConfig {
    /// Root must already exist, be empty on first use, and private (Unix 0700).
    /// Operations take explicit deadline/cancellation contexts. No eviction.
    pub fn new(root: PathBuf, quota_bytes: u64) -> Result<Self, ReceiptError> {
        if root.as_os_str().is_empty() || quota_bytes < MIN_QUOTA_BYTES {
            return Err(ReceiptError::Configuration);
        }
        Ok(Self {
            root,
            quota: quota_bytes,
            #[cfg(test)]
            hook: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptInfo {
    pub id: Uuid,
    pub checksum: [u8; 32],
    pub bytes: usize,
    pub prepared_count: usize,
}
/// One owned bounded result. Retaining multiple results/caller buffers requires
/// application aggregate budgeting. Original and event bytes are never rewritten.
pub struct StoredReceipt {
    bytes: Vec<u8>,
    metadata: Value,
    original: std::ops::Range<usize>,
    events: Vec<std::ops::Range<usize>>,
    info: ReceiptInfo,
    metadata_end: usize,
}
impl StoredReceipt {
    pub fn info(&self) -> ReceiptInfo {
        self.info
    }
    pub fn metadata_bytes(&self) -> &[u8] {
        &self.bytes[36..self.metadata_end]
    }
    pub fn original_bytes(&self) -> &[u8] {
        &self.bytes[self.original.clone()]
    }
    pub fn prepared_bytes(&self, index: usize) -> Option<&[u8]> {
        self.events.get(index).map(|r| &self.bytes[r.clone()])
    }
}

#[derive(Default)]
struct Metrics {
    depth: AtomicUsize,
    active: AtomicBool,
    rejected: AtomicU64,
    admitted: AtomicU64,
    replays: AtomicU64,
    stopped: AtomicBool,
    caller_uncertain: AtomicU64,
    unobserved_results: AtomicU64,
    progress_updates: AtomicU64,
    owner_transfers: AtomicU64,
}
#[derive(Clone, Copy, Debug)]
pub struct ReceiptMetrics {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub worker_active: bool,
    pub rejected: u64,
    pub admitted: u64,
    pub replays: u64,
    pub worker_stopped: bool,
    pub caller_uncertain: u64,
    pub unobserved_results: u64,
    pub progress_updates: u64,
    pub owner_transfers: u64,
}
impl Metrics {
    fn snapshot(&self) -> ReceiptMetrics {
        ReceiptMetrics {
            queue_depth: self.depth.load(Ordering::Acquire),
            queue_capacity: QUEUE_CAPACITY,
            worker_active: self.active.load(Ordering::Acquire),
            rejected: self.rejected.load(Ordering::Acquire),
            admitted: self.admitted.load(Ordering::Acquire),
            replays: self.replays.load(Ordering::Acquire),
            worker_stopped: self.stopped.load(Ordering::Acquire),
            caller_uncertain: self.caller_uncertain.load(Ordering::Acquire),
            unobserved_results: self.unobserved_results.load(Ordering::Acquire),
            progress_updates: self.progress_updates.load(Ordering::Acquire),
            owner_transfers: self.owner_transfers.load(Ordering::Acquire),
        }
    }
}

pub use store::ReceiptStore;

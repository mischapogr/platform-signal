//! Version 1 HTTP contracts and the runtime-independent admission seam.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use signal_event::SignalEvent;
use std::{future::Future, pin::Pin};
use thiserror::Error;
use uuid::Uuid;

pub mod query;
pub use query::{
    AttributeFilter, EventQuery, EventQueryResponse, QueryMetadata, QueryOrder,
    QueryValidationError, parse_event_query,
};

pub const API_SCHEMA_VERSION: u16 = 1;

/// Version 1 batch input. JSON values allow complete validation before admission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchInput {
    #[serde(default = "api_version")]
    pub schema_version: u16,
    pub events: Vec<Value>,
}

const fn api_version() -> u16 {
    API_SCHEMA_VERSION
}

/// Stable HTTP error classification; messages must never include supplied secrets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidJson,
    InvalidEvent,
    UnsupportedVersion,
    EmptyBatch,
    PayloadTooLarge,
    BatchTooLarge,
    Unauthorized,
    Full,
    RequestTimeout,
    Unavailable,
    Stopping,
    NotFound,
    MethodNotAllowed,
    UnsupportedMediaType,
}

/// Error detail within a schema-versioned [`IngestResponse`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}

/// All ingest results, including partially admitted batches, use this envelope.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IngestResponse {
    pub schema_version: u16,
    pub accepted: usize,
    pub rejected: usize,
    pub event_ids: Vec<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

/// Admission errors must not contain caller data or secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdmissionError {
    #[error("admission capacity is full")]
    Full,
    #[error("admission is stopped")]
    Closed,
    #[error("admission is unavailable")]
    Unavailable,
}

/// Metrics are a point-in-time state snapshot, not a serialization contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct SinkMetrics {
    pub findings: Option<FindingSinkMetrics>,
    pub logging: Option<LoggingSinkMetrics>,
    pub rules: Option<RuleSinkMetrics>,
    pub query: Option<QuerySinkMetrics>,
    pub storage: Option<StorageSinkMetrics>,
    pub depth: usize,
    pub capacity: usize,
    pub bytes: usize,
    pub byte_capacity: usize,
    pub accepted: u64,
    pub rejected: u64,
    pub dropped: u64,
    pub closed: bool,
    pub wal_bytes: u64,
    pub wal_byte_capacity: u64,
    pub wal_segments: usize,
    pub replayed: u64,
    pub corruptions: u64,
    pub truncated_records: u64,
    pub command_depth: usize,
    pub command_capacity: usize,
    pub operations_in_flight: usize,
    pub operation_capacity: usize,
    pub waiters: usize,
    pub waiter_capacity: usize,
    pub timeouts: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RuleSinkMetrics {
    pub loaded: usize,
    pub evaluated: u64,
    pub matches: u64,
    pub failures: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FindingSinkMetrics {
    pub findings: usize,
    pub finding_capacity: usize,
    pub bytes: u64,
    pub byte_capacity: u64,
    pub index_bytes: usize,
    pub index_capacity: usize,
    pub command_depth: usize,
    pub command_capacity: usize,
    pub operations: usize,
    pub operation_capacity: usize,
    pub inserted: u64,
    pub duplicates: u64,
    pub rejections: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub closed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LoggingSinkMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub bytes: usize,
    pub byte_capacity: usize,
    pub queued: usize,
    pub dropped: u64,
    pub full: u64,
    pub oversized: u64,
    pub closed_records: u64,
    pub written: u64,
    pub errors: u64,
    pub closed: bool,
}

/// Storage worker state exposed through the admission seam without crate coupling.
#[derive(Clone, Copy, Debug, Default)]
pub struct StorageSinkMetrics {
    pub persisted: u64,
    pub replayed: u64,
    pub bytes: u64,
    pub byte_capacity: u64,
    pub files: usize,
    pub file_capacity: usize,
    pub command_depth: usize,
    pub command_capacity: usize,
    pub operations_in_flight: usize,
    pub operation_capacity: usize,
    pub timeouts: u64,
    pub full: u64,
    pub failures: u64,
    pub high_water: u64,
    pub fail_closed: bool,
}

/// Query counters and resource limits exposed without a query/ingest dependency.
#[derive(Clone, Copy, Debug, Default)]
pub struct QuerySinkMetrics {
    pub io_queue_depth: usize,
    pub io_queue_capacity: usize,
    pub io_running: usize,
    pub io_worker_capacity: usize,
    pub io_depth: usize,
    pub io_capacity: usize,
    pub io_rejected: u64,
    pub io_bytes: usize,
    pub io_byte_capacity: usize,
    pub io_waiters: usize,
    pub io_waiter_capacity: usize,
    pub depth: usize,
    pub capacity: usize,
    pub requests: u64,
    pub completed: u64,
    pub failures: u64,
    pub rejected: u64,
    pub timeouts: u64,
    pub cancelled: u64,
    pub scanned_files: u64,
    pub selected_partitions: u64,
    pub latency_micros: u64,
    pub memory_bytes: usize,
    pub memory_capacity: usize,
}

pub type AdmissionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), AdmissionError>> + Send + 'a>>;

/// Successful admission transfers ownership. Cancellation must not create extra workers.
///
/// An implementation documents its commit boundary and durability guarantee. Once
/// committed or when already-started filesystem work must complete on a bounded
/// tracked worker, cancellation may leave the caller uncertain; replay consumers tolerate
/// duplicates. Ingest never knows about storage or WAL internals.
pub trait EventSink: Send + Sync + 'static {
    fn admit(&self, event: SignalEvent) -> AdmissionFuture<'_>;
    fn metrics(&self) -> SinkMetrics;
    /// Must stop new admission before returning; existing committed events remain owned.
    fn close(&self);
}

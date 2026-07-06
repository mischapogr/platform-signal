//! Validated, bounded HTTP ingestion through a storage-independent EventSink.
pub mod memory;
pub mod server;

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde_json::Value;
use signal_event::{IngestEvent, ValidationError};
use signal_protocol::{
    API_SCHEMA_VERSION, AdmissionError, ApiError, BatchInput, ErrorCode, EventSink, IngestResponse,
};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

/// Secret values are intentionally excluded from Debug and serialization.
#[derive(Clone)]
pub struct IngestConfig {
    pub max_request_bytes: usize,
    pub max_batch_events: usize,
    pub max_in_flight: usize,
    pub request_timeout: Duration,
    pub api_token: Option<String>,
}

impl fmt::Debug for IngestConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IngestConfig")
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_batch_events", &self.max_batch_events)
            .field("max_in_flight", &self.max_in_flight)
            .field("request_timeout", &self.request_timeout)
            .field("auth_enabled", &self.api_token.is_some())
            .finish()
    }
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 1_048_576,
            max_batch_events: 1000,
            max_in_flight: 64,
            request_timeout: Duration::from_secs(5),
            api_token: None,
        }
    }
}

impl IngestConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_request_bytes == 0
            || self.max_batch_events == 0
            || self.max_in_flight == 0
            || self.max_in_flight > Semaphore::MAX_PERMITS
        {
            return Err(ConfigError::Invalid(
                "request, batch and concurrency limits must be positive and supported",
            ));
        }
        if self.request_timeout.is_zero() || self.request_timeout > Duration::from_secs(3600) {
            return Err(ConfigError::Invalid(
                "request timeout must be between zero and one hour",
            ));
        }
        if let Some(token) = &self.api_token
            && (token.is_empty()
                || token.len() > 4096
                || !token.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(ConfigError::Invalid(
                "API token must contain 1..4096 printable non-space ASCII characters",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct HttpMetrics {
    requests: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    rejected_requests: AtomicU64,
    timed_out: AtomicU64,
    connections: AtomicU64,
    connection_capacity: AtomicU64,
    connection_timeouts: AtomicU64,
    connection_errors: AtomicU64,
}

struct Shared {
    config: IngestConfig,
    sink: Arc<dyn EventSink>,
    permits: Semaphore,
    stopping: CancellationToken,
    metrics: Arc<HttpMetrics>,
}

#[derive(Clone)]
pub struct IngestService {
    shared: Arc<Shared>,
}

impl IngestService {
    pub fn new(config: IngestConfig, sink: Arc<dyn EventSink>) -> Result<Self, ConfigError> {
        config.validate()?;
        let permits = Semaphore::new(config.max_in_flight);
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                sink,
                permits,
                stopping: CancellationToken::new(),
                metrics: Arc::new(HttpMetrics::default()),
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/events", post(single))
            .route("/v1/events/batch", post(batch))
            .route("/healthz", get(|| async { StatusCode::OK }))
            .route("/readyz", get(ready))
            .route("/metrics", get(metrics))
            .fallback(|| async {
                simple_error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    "route not found",
                )
            })
            .method_not_allowed_fallback(|| async {
                simple_error(
                    StatusCode::METHOD_NOT_ALLOWED,
                    ErrorCode::MethodNotAllowed,
                    "method not allowed",
                )
            })
            .with_state(self.clone())
    }

    /// Operational endpoints for an optional separate listener, without ingest routes.
    pub fn metrics_router(&self) -> Router {
        Router::new()
            .route("/healthz", get(|| async { StatusCode::OK }))
            .route("/readyz", get(ready))
            .route("/metrics", get(metrics))
            .with_state(self.clone())
    }

    /// Stops sink admission before signalling cancellation to waiting requests.
    pub fn stop_admission(&self) {
        self.shared.sink.close();
        self.shared.stopping.cancel();
    }

    /// A child token lets composed HTTP handlers stop without cancelling admission.
    pub fn cancellation(&self) -> CancellationToken {
        self.shared.stopping.child_token()
    }
}

// Drop accounting covers timeouts, aborted HTTP connections and normal responses alike.
struct Attempt {
    metrics: Arc<HttpMetrics>,
    total: usize,
    accepted: usize,
    ids: Vec<uuid::Uuid>,
    failed: bool,
}
impl Attempt {
    fn new(metrics: Arc<HttpMetrics>) -> Self {
        metrics.requests.fetch_add(1, Ordering::Relaxed);
        Self {
            metrics,
            total: 0,
            accepted: 0,
            ids: Vec::new(),
            failed: true,
        }
    }
    fn response(&mut self, status: StatusCode, error: Option<ApiError>) -> Response {
        self.failed = !status.is_success();
        let body = IngestResponse {
            schema_version: API_SCHEMA_VERSION,
            accepted: self.accepted,
            rejected: self.total - self.accepted,
            event_ids: std::mem::take(&mut self.ids),
            error,
        };
        tracing::info!(
            status = status.as_u16(),
            accepted = body.accepted,
            rejected = body.rejected,
            "ingest completed"
        );
        let mut response = (status, Json(body)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        }
        response
    }
    fn error(
        &mut self,
        status: StatusCode,
        code: ErrorCode,
        message: impl Into<String>,
        index: Option<usize>,
    ) -> Response {
        self.response(
            status,
            Some(ApiError {
                code,
                message: message.into(),
                index,
            }),
        )
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.metrics
            .rejected
            .fetch_add((self.total - self.accepted) as u64, Ordering::Relaxed);
        if self.failed {
            self.metrics
                .rejected_requests
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn single(State(service): State<IngestService>, request: Request) -> Response {
    ingest(service, request, false).await
}
async fn batch(State(service): State<IngestService>, request: Request) -> Response {
    ingest(service, request, true).await
}

async fn ingest(service: IngestService, request: Request, is_batch: bool) -> Response {
    let shared = &service.shared;
    let deadline = Instant::now() + shared.config.request_timeout;
    let mut attempt = Attempt::new(shared.metrics.clone());
    let Ok(_permit) = shared.permits.try_acquire() else {
        return attempt.error(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Full,
            "request concurrency is full",
            None,
        );
    };
    if shared.stopping.is_cancelled() || shared.sink.metrics().closed {
        return attempt.error(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Stopping,
            "admission is stopped",
            None,
        );
    }
    if !authorized(&shared.config, request.headers()) {
        return attempt.error(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "Bearer authentication required",
            None,
        );
    }
    if !request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|v| {
            let media = v.split(';').next().unwrap_or_default().trim();
            media.eq_ignore_ascii_case("application/json")
                || (media.starts_with("application/") && media.ends_with("+json"))
        })
    {
        return attempt.error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "JSON content type required",
            None,
        );
    }
    let bytes = tokio::select! {
        biased;
        _ = shared.stopping.cancelled() => return attempt.error(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Stopping, "admission is stopped", None),
        result = timeout_at(deadline, to_bytes(request.into_body(), shared.config.max_request_bytes)) => match result {
            Err(_) => { shared.metrics.timed_out.fetch_add(1, Ordering::Relaxed); return attempt.error(StatusCode::REQUEST_TIMEOUT, ErrorCode::RequestTimeout, "request deadline exceeded", None); }
            Ok(Err(error)) => {
                use std::error::Error;
                let large = error.source().is_some_and(|source| source.is::<http_body_util::LengthLimitError>());
                return attempt.error(if large { StatusCode::PAYLOAD_TOO_LARGE } else { StatusCode::BAD_REQUEST },
                    if large { ErrorCode::PayloadTooLarge } else { ErrorCode::InvalidJson },
                    if large { "request body limit exceeded" } else { "request body could not be read" }, None);
            }
            Ok(Ok(bytes)) => bytes,
        }
    };
    let values = if is_batch {
        let Ok(batch) = serde_json::from_slice::<BatchInput>(&bytes) else {
            return attempt.error(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidJson,
                "invalid batch JSON",
                None,
            );
        };
        attempt.total = batch.events.len();
        if batch.schema_version != API_SCHEMA_VERSION {
            return attempt.error(
                StatusCode::BAD_REQUEST,
                ErrorCode::UnsupportedVersion,
                "unsupported batch schema version",
                None,
            );
        }
        if attempt.total == 0 {
            return attempt.error(
                StatusCode::BAD_REQUEST,
                ErrorCode::EmptyBatch,
                "batch must contain events",
                None,
            );
        }
        if attempt.total > shared.config.max_batch_events {
            return attempt.error(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::BatchTooLarge,
                "batch event limit exceeded",
                None,
            );
        }
        batch.events
    } else {
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            return attempt.error(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidJson,
                "invalid event JSON",
                None,
            );
        };
        attempt.total = 1;
        vec![value]
    };
    let observed_at = Utc::now();
    let mut events = Vec::with_capacity(values.len());
    for (index, value) in values.into_iter().enumerate() {
        if Instant::now() >= deadline {
            shared.metrics.timed_out.fetch_add(1, Ordering::Relaxed);
            return attempt.error(
                StatusCode::REQUEST_TIMEOUT,
                ErrorCode::RequestTimeout,
                "request deadline exceeded",
                Some(index),
            );
        }
        let Ok(input) = serde_json::from_value::<IngestEvent>(value) else {
            return attempt.error(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidEvent,
                "event fields must follow the version 1 schema",
                Some(index),
            );
        };
        let event = match input.normalize(observed_at) {
            Ok(event) => event,
            Err(error) => {
                return attempt.error(
                    StatusCode::BAD_REQUEST,
                    if error == ValidationError::UnsupportedVersion {
                        ErrorCode::UnsupportedVersion
                    } else {
                        ErrorCode::InvalidEvent
                    },
                    error.to_string(),
                    Some(index),
                );
            }
        };
        events.push(event);
    }
    for (index, event) in events.into_iter().enumerate() {
        if Instant::now() >= deadline {
            shared.metrics.timed_out.fetch_add(1, Ordering::Relaxed);
            return attempt.error(
                StatusCode::REQUEST_TIMEOUT,
                ErrorCode::RequestTimeout,
                "request deadline exceeded",
                Some(index),
            );
        }
        let id = event.id;
        let result = tokio::select! {
            biased;
            _ = shared.stopping.cancelled() => Err((StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Stopping, "admission is stopped")),
            result = timeout_at(deadline, shared.sink.admit(event)) => match result {
                Err(_) => { shared.metrics.timed_out.fetch_add(1, Ordering::Relaxed); Err((StatusCode::REQUEST_TIMEOUT, ErrorCode::RequestTimeout, "request deadline exceeded")) }
                Ok(Err(AdmissionError::Full)) => Err((StatusCode::TOO_MANY_REQUESTS, ErrorCode::Full, "admission capacity is full")),
                Ok(Err(AdmissionError::Closed)) => Err((StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Stopping, "admission is stopped")),
                Ok(Err(AdmissionError::Unavailable)) => Err((StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable, "admission is unavailable")),
                Ok(Ok(())) => Ok(()),
            }
        };
        if let Err((status, code, message)) = result {
            return attempt.error(status, code, message, Some(index));
        }
        attempt.accepted += 1;
        attempt.ids.push(id);
        shared.metrics.accepted.fetch_add(1, Ordering::Relaxed);
    }
    attempt.response(StatusCode::ACCEPTED, None)
}

pub fn authorized(config: &IngestConfig, headers: &axum::http::HeaderMap) -> bool {
    let Some(expected) = &config.api_token else {
        return true;
    };
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return false;
    }
    let Some(provided) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token)
    else {
        return false;
    };
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

async fn ready(State(service): State<IngestService>) -> StatusCode {
    if service.shared.stopping.is_cancelled() || service.shared.sink.metrics().closed {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}
async fn metrics(State(service): State<IngestService>) -> Response {
    let shared = &service.shared;
    let sink = shared.sink.metrics();
    let mut body = format!(
        "signal_ingest_requests_total {}\nsignal_events_accepted_total {}\nsignal_events_rejected_total {}\nsignal_ingest_rejected_requests_total {}\nsignal_ingest_timeouts_total {}\nsignal_queue_depth {}\nsignal_queue_capacity {}\nsignal_queue_bytes {}\nsignal_queue_byte_capacity {}\nsignal_queue_rejections_total {}\nsignal_events_dropped_total {}\nsignal_ingest_in_flight {}\nsignal_ingest_in_flight_capacity {}\nsignal_http_connections {}\nsignal_http_connection_capacity {}\nsignal_http_connection_timeouts_total {}\nsignal_http_connection_errors_total {}\nsignal_wal_bytes {}\nsignal_wal_byte_capacity {}\nsignal_wal_segments {}\nsignal_wal_replayed_total {}\nsignal_wal_corruptions_total {}\nsignal_wal_truncated_records_total {}\nsignal_wal_accepted_total {}\nsignal_wal_command_depth {}\nsignal_wal_command_capacity {}\nsignal_wal_waiters {}\nsignal_wal_waiter_capacity {}\nsignal_wal_timeouts_total {}\nsignal_wal_operations_in_flight {}\nsignal_wal_operation_capacity {}\n",
        shared.metrics.requests.load(Ordering::Relaxed),
        shared.metrics.accepted.load(Ordering::Relaxed),
        shared.metrics.rejected.load(Ordering::Relaxed),
        shared.metrics.rejected_requests.load(Ordering::Relaxed),
        shared.metrics.timed_out.load(Ordering::Relaxed),
        sink.depth,
        sink.capacity,
        sink.bytes,
        sink.byte_capacity,
        sink.rejected,
        sink.dropped,
        shared.config.max_in_flight - shared.permits.available_permits(),
        shared.config.max_in_flight,
        shared.metrics.connections.load(Ordering::Relaxed),
        shared.metrics.connection_capacity.load(Ordering::Relaxed),
        shared.metrics.connection_timeouts.load(Ordering::Relaxed),
        shared.metrics.connection_errors.load(Ordering::Relaxed),
        sink.wal_bytes,
        sink.wal_byte_capacity,
        sink.wal_segments,
        sink.replayed,
        sink.corruptions,
        sink.truncated_records,
        sink.accepted,
        sink.command_depth,
        sink.command_capacity,
        sink.waiters,
        sink.waiter_capacity,
        sink.timeouts,
        sink.operations_in_flight,
        sink.operation_capacity
    );
    if let Some(rules) = sink.rules {
        use std::fmt::Write;
        for (name, value) in [
            ("signal_rules_loaded", rules.loaded as u64),
            ("signal_rules_evaluated_total", rules.evaluated),
            ("signal_rule_matches_total", rules.matches),
            ("signal_rules_failures_total", rules.failures),
        ] {
            let _ = writeln!(body, "{name} {value}");
        }
    }
    if let Some(findings) = sink.findings {
        use std::fmt::Write;
        for (name, value) in [
            ("signal_findings_count", findings.findings as u64),
            ("signal_findings_capacity", findings.finding_capacity as u64),
            ("signal_findings_bytes", findings.bytes),
            ("signal_findings_byte_capacity", findings.byte_capacity),
            ("signal_findings_index_bytes", findings.index_bytes as u64),
            (
                "signal_findings_index_capacity",
                findings.index_capacity as u64,
            ),
            (
                "signal_findings_command_depth",
                findings.command_depth as u64,
            ),
            (
                "signal_findings_command_capacity",
                findings.command_capacity as u64,
            ),
            ("signal_findings_operations", findings.operations as u64),
            (
                "signal_findings_operation_capacity",
                findings.operation_capacity as u64,
            ),
            ("signal_findings_inserted_total", findings.inserted),
            ("signal_findings_duplicates_total", findings.duplicates),
            ("signal_findings_rejections_total", findings.rejections),
            ("signal_findings_failures_total", findings.failures),
            ("signal_findings_timeouts_total", findings.timeouts),
            ("signal_findings_closed", u64::from(findings.closed)),
        ] {
            let _ = writeln!(body, "{name} {value}");
        }
    }
    if let Some(logging) = sink.logging {
        use std::fmt::Write;
        for (name, value) in [
            ("signal_logging_depth", logging.depth as u64),
            ("signal_logging_capacity", logging.capacity as u64),
            ("signal_logging_bytes", logging.bytes as u64),
            ("signal_logging_byte_capacity", logging.byte_capacity as u64),
            ("signal_logging_queued", logging.queued as u64),
            ("signal_logging_dropped_total", logging.dropped),
            ("signal_logging_full_total", logging.full),
            ("signal_logging_oversized_total", logging.oversized),
            (
                "signal_logging_closed_records_total",
                logging.closed_records,
            ),
            ("signal_logging_written_total", logging.written),
            ("signal_logging_errors_total", logging.errors),
            ("signal_logging_closed", u64::from(logging.closed)),
        ] {
            let _ = writeln!(body, "{name} {value}");
        }
    }
    if let Some(query) = sink.query {
        use std::fmt::Write;
        let _ = write!(
            body,
            "signal_query_io_queue_depth {}\nsignal_query_io_queue_capacity {}\nsignal_query_io_running {}\nsignal_query_io_worker_capacity {}\n",
            query.io_queue_depth,
            query.io_queue_capacity,
            query.io_running,
            query.io_worker_capacity
        );
        let _ = write!(
            body,
            "signal_query_depth {}\nsignal_query_capacity {}\nsignal_query_requests_total {}\nsignal_query_completed_total {}\nsignal_query_failures_total {}\nsignal_query_rejections_total {}\nsignal_query_timeouts_total {}\nsignal_query_cancelled_total {}\nsignal_query_scanned_files_total {}\nsignal_query_selected_partitions_total {}\nsignal_query_latency_microseconds_total {}\nsignal_query_memory_bytes {}\nsignal_query_memory_capacity {}\n",
            query.depth,
            query.capacity,
            query.requests,
            query.completed,
            query.failures,
            query.rejected,
            query.timeouts,
            query.cancelled,
            query.scanned_files,
            query.selected_partitions,
            query.latency_micros,
            query.memory_bytes,
            query.memory_capacity
        );
        let _ = write!(
            body,
            "signal_query_io_depth {}\nsignal_query_io_capacity {}\nsignal_query_io_rejections_total {}\nsignal_query_io_bytes {}\nsignal_query_io_byte_capacity {}\nsignal_query_io_waiters {}\nsignal_query_io_waiter_capacity {}\n",
            query.io_depth,
            query.io_capacity,
            query.io_rejected,
            query.io_bytes,
            query.io_byte_capacity,
            query.io_waiters,
            query.io_waiter_capacity
        );
    }
    if let Some(storage) = sink.storage {
        use std::fmt::Write;
        // Writing to String is infallible. No event values or labels enter metrics.
        let _ = write!(
            body,
            "signal_storage_persisted_total {}\nsignal_storage_replayed_total {}\nsignal_storage_bytes {}\nsignal_storage_byte_capacity {}\nsignal_storage_files {}\nsignal_storage_file_capacity {}\nsignal_storage_command_depth {}\nsignal_storage_command_capacity {}\nsignal_storage_operations_in_flight {}\nsignal_storage_operation_capacity {}\nsignal_storage_timeouts_total {}\nsignal_storage_full_total {}\nsignal_storage_failures_total {}\nsignal_storage_high_water {}\nsignal_storage_fail_closed {}\n",
            storage.persisted,
            storage.replayed,
            storage.bytes,
            storage.byte_capacity,
            storage.files,
            storage.file_capacity,
            storage.command_depth,
            storage.command_capacity,
            storage.operations_in_flight,
            storage.operation_capacity,
            storage.timeouts,
            storage.full,
            storage.failures,
            storage.high_water,
            u8::from(storage.fail_closed)
        );
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}
fn simple_error(status: StatusCode, code: ErrorCode, message: &'static str) -> Response {
    (
        status,
        Json(IngestResponse {
            schema_version: API_SCHEMA_VERSION,
            accepted: 0,
            rejected: 0,
            event_ids: Vec::new(),
            error: Some(ApiError {
                code,
                message: message.to_owned(),
                index: None,
            }),
        }),
    )
        .into_response()
}

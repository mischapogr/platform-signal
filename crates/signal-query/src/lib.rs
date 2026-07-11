//! Bounded DataFusion execution over committed Parquet files (ADR-005).

mod access;
mod io;

use arrow::{
    array::{Array, BooleanArray, StringArray},
    datatypes::DataType,
    record_batch::RecordBatch,
};
use chrono::{DateTime, Utc};
use datafusion::{
    error::DataFusionError,
    execution::{
        cache::cache_manager::CacheManagerConfig,
        disk_manager::{DiskManagerBuilder, DiskManagerMode},
        memory_pool::{GreedyMemoryPool, MemoryPool},
        runtime_env::{RuntimeEnv, RuntimeEnvBuilder},
    },
    logical_expr::{ColumnarValue, Expr, Volatility, create_udf},
    prelude::{ParquetReadOptions, SessionConfig, SessionContext, col, lit},
};
use futures_util::StreamExt;
use signal_event::{Severity, lookup_attribute_path};
use signal_protocol::{
    API_SCHEMA_VERSION, EventQuery, EventQueryResponse, QueryMetadata, QueryOrder,
    access::RequestGrant,
};
use signal_storage::{OperationContext, ParquetStore, QueryFileSource, StorageError, codec};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

#[derive(Clone, Debug)]
pub struct QueryConfig {
    pub memory_bytes: usize,
    pub max_concurrent: usize,
    pub max_files: usize,
    pub max_limit: usize,
    pub max_response_bytes: usize,
    pub batch_rows: usize,
    pub target_partitions: usize,
    pub timeout: Duration,
}
impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            memory_bytes: 256 * 1024 * 1024,
            max_concurrent: 4,
            max_files: 1024,
            max_limit: 1000,
            max_response_bytes: 8 * 1024 * 1024,
            batch_rows: 128,
            target_partitions: 1,
            timeout: Duration::from_secs(10),
        }
    }
}
impl QueryConfig {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.memory_bytes == 0
            || self.memory_bytes > u32::MAX as usize
            || self.max_concurrent == 0
            || self.max_concurrent > 1024
            || self.max_files == 0
            || self.max_files > 100_000
            || self.max_limit == 0
            || self.max_limit > 1_000_000
            || self.max_response_bytes < 128
            || self.max_response_bytes > i32::MAX as usize
            || self.batch_rows == 0
            || self.batch_rows > 4096
            || self.target_partitions == 0
            || self.target_partitions > 64
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(3600)
        {
            return Err(QueryError::Config(
                "positive bounded query capacities and deadline",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum QueryError {
    #[error("invalid query configuration: {0}")]
    Config(&'static str),
    #[error("event query access denied")]
    Denied,
    #[error("invalid event query")]
    Invalid,
    #[error("query capacity is full")]
    Busy,
    #[error("query deadline exceeded")]
    Timeout,
    #[error("query cancelled")]
    Cancelled,
    #[error("query resource limit exceeded")]
    Resource,
    #[error("event query is unavailable")]
    Unavailable,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct QueryMetrics {
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
    pub io_depth: usize,
    pub io_capacity: usize,
    pub io_rejected: u64,
    pub io_bytes: usize,
    pub io_byte_capacity: usize,
    pub io_waiters: usize,
    pub io_waiter_capacity: usize,
    pub io_queue_depth: usize,
    pub io_queue_capacity: usize,
    pub io_running: usize,
    pub io_worker_capacity: usize,
}
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    completed: AtomicU64,
    failures: AtomicU64,
    rejected: AtomicU64,
    timeouts: AtomicU64,
    cancelled: AtomicU64,
    scanned_files: AtomicU64,
    selected_partitions: AtomicU64,
    latency_micros: AtomicU64,
}
struct ExecutionObservation<'a> {
    counters: &'a Counters,
    started: Instant,
    finished: bool,
}
impl Drop for ExecutionObservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            self.counters.cancelled.fetch_add(1, Ordering::Relaxed);
            self.counters.latency_micros.fetch_add(
                self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
        }
    }
}
/// Every session uses one shared memory pool; spill is disabled and admission never waits.
pub struct QueryEngine {
    config: QueryConfig,
    store: Arc<dyn QueryFileSource>,
    runtime: Arc<RuntimeEnv>,
    pool: Arc<dyn MemoryPool>,
    io: Arc<io::BoundedLocalStore>,
    permits: Semaphore,
    counters: Counters,
}
impl QueryEngine {
    pub fn new(config: QueryConfig, store: Arc<ParquetStore>) -> Result<Self, QueryError> {
        Self::with_source(config, store)
    }
    pub fn with_source(
        config: QueryConfig,
        store: Arc<dyn QueryFileSource>,
    ) -> Result<Self, QueryError> {
        config.validate()?;
        let pool: Arc<dyn MemoryPool> = Arc::new(GreedyMemoryPool::new(config.memory_bytes));
        let caches = CacheManagerConfig::default()
            .with_file_statistics_cache_limit(0)
            .with_list_files_cache_limit(0)
            .with_metadata_cache_limit(0);
        let runtime = RuntimeEnvBuilder::new()
            .with_cache_manager(caches)
            .with_memory_pool(pool.clone())
            .with_disk_manager_builder(
                DiskManagerBuilder::default().with_mode(DiskManagerMode::Disabled),
            )
            .build_arc()
            .map_err(df_error)?;
        let io_capacity = (config.max_concurrent * config.target_partitions).min(16);
        let io = Arc::new(
            io::BoundedLocalStore::with_source(
                io_capacity,
                config.memory_bytes,
                config.max_files.max(128),
                Some(store.clone()),
            )
            .map_err(|_| QueryError::Config("filesystem query capacities"))?,
        );
        let local_url =
            url::Url::parse("file:///").map_err(|_| QueryError::Config("filesystem registry"))?;
        runtime
            .object_store_registry
            .register_store(&local_url, io.clone());
        Ok(Self {
            io,
            permits: Semaphore::new(config.max_concurrent),
            config,
            store,
            runtime,
            pool,
            counters: Counters::default(),
        })
    }
    pub fn metrics(&self) -> QueryMetrics {
        let c = &self.counters;
        let io = self.io.metrics();
        let load = |n: &AtomicU64| n.load(Ordering::Relaxed);
        QueryMetrics {
            depth: self.config.max_concurrent - self.permits.available_permits(),
            capacity: self.config.max_concurrent,
            requests: load(&c.requests),
            completed: load(&c.completed),
            failures: load(&c.failures),
            rejected: load(&c.rejected),
            timeouts: load(&c.timeouts),
            cancelled: load(&c.cancelled),
            scanned_files: load(&c.scanned_files),
            selected_partitions: load(&c.selected_partitions),
            latency_micros: load(&c.latency_micros),
            memory_bytes: self.pool.reserved(),
            memory_capacity: self.config.memory_bytes,
            io_depth: io.depth,
            io_capacity: io.capacity,
            io_rejected: io.rejected,
            io_bytes: io.read_bytes,
            io_byte_capacity: io.read_byte_capacity,
            io_waiters: io.waiter_depth,
            io_waiter_capacity: io.waiter_capacity,
            io_queue_depth: io.queued,
            io_queue_capacity: io.queue_capacity,
            io_running: io.running,
            io_worker_capacity: io.worker_capacity,
        }
    }
    /// Trusted host entry point for deployments without configured identity.
    /// Authenticated HTTP routes must use `execute_authorized` instead.
    pub async fn execute(
        &self,
        query: EventQuery,
        context: OperationContext,
    ) -> Result<EventQueryResponse, QueryError> {
        self.execute_inner(query, context, None).await
    }
    /// Apply complete QueryEvents grants before sort/limit and verify them again
    /// before returning any response. User filters only narrow that authority.
    pub async fn execute_authorized(
        &self,
        query: EventQuery,
        context: OperationContext,
        grant: &RequestGrant,
    ) -> Result<EventQueryResponse, QueryError> {
        self.execute_inner(query, context, Some(grant)).await
    }
    async fn execute_inner(
        &self,
        query: EventQuery,
        mut context: OperationContext,
        grant: Option<&RequestGrant>,
    ) -> Result<EventQueryResponse, QueryError> {
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let mut observation = ExecutionObservation {
            counters: &self.counters,
            started,
            finished: false,
        };
        context.deadline = context.deadline.min(started + self.config.timeout);
        let result = async {
            access::check(grant)?;
            query
                .validate(self.config.max_limit)
                .map_err(|_| QueryError::Invalid)?;
            if context.cancellation.is_cancelled() {
                return Err(QueryError::Cancelled);
            }
            if started >= context.deadline {
                return Err(QueryError::Timeout);
            }
            if self.permits.is_closed() {
                return Err(QueryError::Unavailable);
            }
            let io = self.io.metrics();
            // Started kernel work still owns these slots after its caller disappears.
            // Reject replacement queries until physical capacity is available.
            if io.depth >= io.capacity {
                return Err(QueryError::Busy);
            }
            let _permit = self.permits.try_acquire().map_err(|_| QueryError::Busy)?;
            tokio::select! {
                biased;
                _ = context.cancellation.cancelled() => Err(QueryError::Cancelled),
                result = timeout_at(context.deadline, self.run(query, context.clone(), started, grant)) =>
                    result.map_err(|_| QueryError::Timeout)?,
            }
        }
        .await
        .and_then(|response| {
            check_context(&context)?;
            access::check(grant)?;
            Ok(response)
        });
        self.counters.latency_micros.fetch_add(
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        match result {
            Ok(_) => {
                self.counters.completed.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.counters.failures.fetch_add(1, Ordering::Relaxed);
                match error {
                    QueryError::Busy => {
                        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    QueryError::Timeout => {
                        self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    QueryError::Cancelled => {
                        self.counters.cancelled.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }
        observation.finished = true;
        result
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), QueryError> {
        self.permits.close();
        check_context(&context)?;
        tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => Err(QueryError::Cancelled),
            result = timeout_at(context.deadline, async {
                // Selection may be remote while local read depth is still zero.
                // Drain the entire admitted execute lifetime before local I/O.
                while self.permits.available_permits() != self.config.max_concurrent {
                    check_context(&context)?;
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                check_context(&context)?;
                let finished = self.io.shutdown(context.deadline).await;
                check_context(&context)?;
                if finished { Ok(()) } else { Err(QueryError::Timeout) }
            }) => {
                result.map_err(|_| QueryError::Timeout)?
            }
        }
    }
    async fn run(
        &self,
        query: EventQuery,
        context: OperationContext,
        started: Instant,
        grant: Option<&RequestGrant>,
    ) -> Result<EventQueryResponse, QueryError> {
        let selection = self
            .store
            .select_query_files(
                query.from,
                query.to,
                self.config.max_files,
                self.config.memory_bytes as u64,
                context.clone(),
            )
            .await
            .map_err(storage_error)?;
        access::check(grant)?;
        if selection.files.len() > self.config.max_files {
            return Err(QueryError::Resource);
        }
        let mut response = EventQueryResponse {
            schema_version: API_SCHEMA_VERSION,
            events: Vec::new(),
            metadata: QueryMetadata {
                duration_ms: 0,
                scanned_files: selection.files.len(),
                candidate_partitions: selection.partitions,
            },
        };
        self.counters
            .scanned_files
            .fetch_add(selection.files.len() as u64, Ordering::Relaxed);
        self.counters
            .selected_partitions
            .fetch_add(selection.partitions as u64, Ordering::Relaxed);
        if selection.files.is_empty() {
            response.metadata.duration_ms = elapsed_ms(started);
            json_bytes(&response, self.config.max_response_bytes)?;
            return Ok(response);
        }
        // Bound external scan input too: Arrow decode buffers and JSON predicates are
        // not charged to DataFusion's operator pool. Footer totals were validated
        // by the storage worker before this check and before any DataFusion read.
        let input_bytes = selection.files.iter().try_fold(0u64, |total, file| {
            total
                .checked_add(file.uncompressed_bytes)
                .ok_or(QueryError::Resource)
        })?;
        if input_bytes > self.config.memory_bytes as u64 {
            return Err(QueryError::Resource);
        }
        let paths = selection
            .files
            .iter()
            .map(|file| {
                // Paths were canonicalized by the storage worker. Passing a URL
                // skips DataFusion's synchronous exists/is_dir probes on Tokio.
                url::Url::from_file_path(&file.path)
                    .map(String::from)
                    .map_err(|_| QueryError::Unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut session_config = SessionConfig::new()
            .with_batch_size(self.config.batch_rows)
            .with_target_partitions(self.config.target_partitions);
        session_config
            .options_mut()
            .execution
            .meta_fetch_concurrency =
            datafusion::common::config::ConfigNonZeroUsize::try_new(1).map_err(df_error)?;
        let session = SessionContext::new_with_config_rt(session_config, self.runtime.clone());
        let schema = codec::schema();
        let mut frame = session
            .read_parquet(
                paths,
                ParquetReadOptions::default()
                    .schema(&schema)
                    .parquet_pruning(true),
            )
            .await
            .map_err(df_error)?;
        if let Some(grant) = grant {
            frame = frame.filter(access::predicate(grant)?).map_err(df_error)?;
        }
        for predicate in predicates(&query) {
            frame = frame.filter(predicate).map_err(df_error)?;
        }
        let ascending = query.order == QueryOrder::Asc;
        frame = frame
            .sort(vec![
                col("timestamp_seconds").sort(ascending, false),
                col("timestamp_nanos").sort(ascending, false),
                col("id").sort(ascending, false),
                col("wal_sequence").sort(ascending, false),
            ])
            .map_err(df_error)?
            .limit(0, Some(query.limit))
            .map_err(df_error)?;
        // No collect(): dropping this stream cancels DataFusion execution and its tracked tasks.
        let mut stream = frame.execute_stream().await.map_err(df_error)?;
        let mut event_bytes = 0usize;
        while let Some(batch) = stream.next().await {
            check_context(&context)?;
            let batch = batch.map_err(df_error)?;
            // Reinstate the exact v1 schema (Parquet may annotate fields as nullable).
            let batch = RecordBatch::try_new(schema.clone(), batch.columns().to_vec())
                .map_err(|_| QueryError::Unavailable)?;
            for index in 0..batch.num_rows() {
                check_context(&context)?;
                if response.events.len() >= query.limit {
                    return Err(QueryError::Unavailable);
                }
                let mut row = codec::decode(&batch.slice(index, 1)).map_err(storage_error)?;
                let event = row.pop().ok_or(QueryError::Unavailable)?.event;
                access::check_event(grant, &event)?;
                let bytes = json_bytes(&event, self.config.max_response_bytes)?;
                response.metadata.duration_ms = elapsed_ms(started);
                let envelope = json_bytes(
                    &EventQueryResponse {
                        schema_version: API_SCHEMA_VERSION,
                        events: Vec::new(),
                        metadata: response.metadata,
                    },
                    self.config.max_response_bytes,
                )?;
                let candidate = envelope
                    .checked_add(event_bytes)
                    .and_then(|n| n.checked_add(bytes))
                    .and_then(|n| n.checked_add(response.events.len()))
                    .ok_or(QueryError::Resource)?;
                if candidate > self.config.max_response_bytes {
                    return Err(QueryError::Resource);
                }
                event_bytes += bytes;
                response.events.push(event);
            }
        }
        response.metadata.duration_ms = elapsed_ms(started);
        json_bytes(&response, self.config.max_response_bytes)?;
        Ok(response)
    }
}
fn check_context(context: &OperationContext) -> Result<(), QueryError> {
    if context.cancellation.is_cancelled() {
        Err(QueryError::Cancelled)
    } else if Instant::now() >= context.deadline {
        Err(QueryError::Timeout)
    } else {
        Ok(())
    }
}
fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}
fn storage_error(error: StorageError) -> QueryError {
    match error {
        StorageError::Timeout => QueryError::Timeout,
        StorageError::Cancelled => QueryError::Cancelled,
        StorageError::Full => QueryError::Resource,
        StorageError::Busy => QueryError::Busy,
        _ => QueryError::Unavailable,
    }
}
fn is_capacity_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if matches!(
            error.downcast_ref::<io::IoLimitError>(),
            Some(io::IoLimitError::Capacity)
        ) {
            return true;
        }
        current = error.source();
    }
    false
}
fn df_error(error: DataFusionError) -> QueryError {
    if is_capacity_error(&error) {
        return QueryError::Busy;
    }
    if io::is_limit_error(&error) {
        return QueryError::Resource;
    }
    match error.find_root() {
        DataFusionError::ResourcesExhausted(_) => QueryError::Resource,
        _ => QueryError::Unavailable,
    }
}
fn predicates(query: &EventQuery) -> Vec<Expr> {
    let mut predicates = Vec::new();
    if let Some(id) = query.event_id {
        predicates.push(col("id").eq(lit(id.to_string())));
    }
    if let Some(from) = query.from {
        predicates.push(time_predicate(from, true));
    }
    if let Some(to) = query.to {
        predicates.push(time_predicate(to, false));
    }
    for (column, value) in [
        ("source_type", query.source_type_filter()),
        ("source_name", query.source_name.as_deref()),
        ("resource_kind", query.resource_kind.as_deref()),
        ("resource_id", query.resource_id_filter()),
        ("resource_account_id", query.account.as_deref()),
    ] {
        if let Some(value) = value {
            predicates.push(col(column).eq(lit(value)));
        }
    }
    if let Some(severity) = query.severity {
        let severity = match severity {
            Severity::Trace => "trace",
            Severity::Debug => "debug",
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
            Severity::Critical => "critical",
        };
        predicates.push(col("severity").eq(lit(severity)));
    }
    if let Some(needle) = &query.contains {
        let needle = needle.clone();
        predicates.push(string_predicate(
            "message_contains",
            "message",
            move |text| Ok(text.contains(&needle)),
        ));
    }
    for (index, attribute) in query.attributes.iter().enumerate() {
        let path = attribute.path.clone();
        let expected = attribute.value.clone();
        predicates.push(string_predicate(
            &format!("attribute_equal_{index}"),
            "attributes_json",
            move |text| {
                let attributes: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(text).map_err(|_| {
                        DataFusionError::Execution("invalid persisted attributes".into())
                    })?;
                Ok(lookup_attribute_path(&attributes, &path)
                    .is_some_and(|actual| actual == &expected))
            },
        ));
    }
    predicates
}
fn time_predicate(timestamp: DateTime<Utc>, lower: bool) -> Expr {
    let seconds = col("timestamp_seconds");
    let nanos = col("timestamp_nanos");
    let second = lit(timestamp.timestamp());
    let nano = lit(timestamp.timestamp_subsec_nanos());
    if lower {
        seconds
            .clone()
            .gt(second.clone())
            .or(seconds.eq(second).and(nanos.gt_eq(nano)))
    } else {
        seconds
            .clone()
            .lt(second.clone())
            .or(seconds.eq(second).and(nanos.lt(nano)))
    }
}
fn string_predicate(
    name: &str,
    column: &str,
    predicate: impl Fn(&str) -> datafusion::error::Result<bool> + Send + Sync + 'static,
) -> Expr {
    let udf = create_udf(
        name,
        vec![DataType::Utf8],
        DataType::Boolean,
        Volatility::Immutable,
        Arc::new(move |arguments| {
            let arrays = ColumnarValue::values_to_arrays(arguments)?;
            let array = arrays
                .first()
                .and_then(|array| array.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| DataFusionError::Execution("invalid predicate input".into()))?;
            let mut matched = Vec::with_capacity(array.len());
            for index in 0..array.len() {
                matched.push(!array.is_null(index) && predicate(array.value(index))?);
            }
            Ok(ColumnarValue::Array(Arc::new(BooleanArray::from(matched))))
        }),
    );
    udf.call(vec![col(column)])
}
struct ByteCounter {
    count: usize,
    limit: usize,
}
impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.count) {
            return Err(std::io::Error::other("query response capacity"));
        }
        self.count += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn json_bytes(value: &impl serde::Serialize, limit: usize) -> Result<usize, QueryError> {
    let mut writer = ByteCounter { count: 0, limit };
    serde_json::to_writer(&mut writer, value).map_err(|_| QueryError::Resource)?;
    Ok(writer.count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::execution::memory_pool::MemoryConsumer;

    #[test]
    fn wrapped_filesystem_admission_errors_stay_distinct_from_byte_and_listing_limits() {
        let wrapped = |limit| {
            DataFusionError::Context(
                "Parquet execution".into(),
                Box::new(DataFusionError::External(Box::new(
                    object_store::Error::Generic {
                        store: "bounded_local",
                        source: Box::new(limit),
                    },
                ))),
            )
        };
        assert_eq!(
            df_error(wrapped(io::IoLimitError::Capacity)),
            QueryError::Busy
        );
        assert_eq!(
            df_error(wrapped(io::IoLimitError::Bytes)),
            QueryError::Resource
        );
        assert_eq!(
            df_error(wrapped(io::IoLimitError::Listing)),
            QueryError::Resource
        );
        assert_eq!(
            df_error(wrapped(io::IoLimitError::Worker)),
            QueryError::Unavailable
        );
    }

    #[tokio::test]
    async fn physical_reads_remain_bounded_after_query_abort_timeout_and_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::TempDir::new()?;
        let store = Arc::new(
            ParquetStore::open(
                signal_storage::StorageConfig {
                    directory: temporary.path().join("events"),
                    ..Default::default()
                },
                uuid::Uuid::new_v4(),
            )
            .await?,
        );
        let event: signal_event::IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"test"},"message":"physical read"}"#,
        )?;
        store
            .append(
                vec![signal_storage::StoredEvent {
                    sequence: 1,
                    event: event.normalize(Utc::now())?,
                }],
                OperationContext::new(Duration::from_secs(2)),
            )
            .await?;
        let engine = Arc::new(QueryEngine::new(
            QueryConfig {
                max_concurrent: 1,
                ..Default::default()
            },
            store.clone(),
        )?);
        for abort in [true, false] {
            let (started, release) = engine.io.pause_read();
            let active = engine.clone();
            let deadline = if abort {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(100)
            };
            let pending = tokio::spawn(async move {
                active
                    .execute(EventQuery::default(), OperationContext::new(deadline))
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), started).await??;
            assert_eq!(engine.io.metrics().running, 1);
            if abort {
                pending.abort();
                assert!(pending.await.is_err());
            } else {
                assert_eq!(pending.await?, Err(QueryError::Timeout));
            }
            assert_eq!(engine.metrics().depth, 0);
            assert_eq!(engine.metrics().io_depth, 1);
            for _ in 0..8 {
                assert_eq!(
                    engine
                        .execute(
                            EventQuery::default(),
                            OperationContext::new(Duration::from_millis(20))
                        )
                        .await,
                    Err(QueryError::Busy)
                );
                assert_eq!(engine.io.metrics().running, 1);
                assert_eq!(engine.io.metrics().worker_capacity, 1);
            }
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(1), async {
                while engine.metrics().io_depth != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            assert_eq!(
                engine
                    .execute(
                        EventQuery::default(),
                        OperationContext::new(Duration::from_secs(2))
                    )
                    .await?
                    .events
                    .len(),
                1
            );
        }
        let (started, release) = engine.io.pause_read();
        let active = engine.clone();
        let pending = tokio::spawn(async move {
            active
                .execute(
                    EventQuery::default(),
                    OperationContext::new(Duration::from_secs(2)),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), started).await??;
        pending.abort();
        let _ = pending.await;
        let began = Instant::now();
        assert_eq!(
            engine
                .shutdown(OperationContext::new(Duration::from_millis(20)))
                .await,
            Err(QueryError::Timeout)
        );
        assert!(began.elapsed() < Duration::from_millis(250));
        release.send(())?;
        engine
            .shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
        assert_eq!(
            engine
                .execute(
                    EventQuery::default(),
                    OperationContext::new(Duration::from_secs(2))
                )
                .await,
            Err(QueryError::Unavailable)
        );
        store
            .shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn physical_reader_retains_object_owner_after_shutdown_timeout_and_engine_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        physical_reader_cache_owner(false).await
    }

    #[tokio::test]
    async fn stopped_cache_prune_waits_for_physical_reader_after_explicit_source_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        physical_reader_cache_owner(true).await
    }

    async fn physical_reader_cache_owner(
        explicit_source_shutdown: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use signal_storage::{
            object_cache::{MaterializationConfig, prune_stopped_materialization},
            object_io::{ObjectIo, ObjectIoError, ObjectIoLimits, SmallOwnerConfig},
            object_publication::{ObjectPublisher, PublicationConfig},
        };
        let temp = tempfile::TempDir::new()?;
        let objects = temp.path().join("remote");
        std::fs::create_dir(&objects)?;
        let owner = SmallOwnerConfig {
            directory: temp.path().join("control"),
            stream_id: uuid::Uuid::new_v4(),
            backend_id: uuid::Uuid::new_v4(),
        };
        let remote = object_store::local::LocalFileSystem::new_with_prefix(&objects)?;
        let io = ObjectIo::open_small_local(
            &owner,
            remote,
            ObjectIoLimits::default(),
            OperationContext::new(Duration::from_secs(2)),
        )
        .await?;
        let cache_config = MaterializationConfig {
            directory: temp.path().join("derived"),
            max_files: 10,
            max_disk_bytes: 1024 * 1024,
        };
        let publisher = Arc::new(ObjectPublisher::new(
            io,
            tokio::runtime::Handle::current(),
            PublicationConfig {
                materialization: Some(cache_config.clone()),
                ..Default::default()
            },
        )?);
        let input: signal_event::IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"physical-owner"},"message":"retained"}"#,
        )?;
        publisher
            .append(
                &[signal_storage::StoredEvent {
                    sequence: 1,
                    event: input.normalize(Utc::now())?,
                }],
                OperationContext::new(Duration::from_secs(2)),
            )
            .await?;
        let engine = Arc::new(QueryEngine::with_source(
            QueryConfig {
                max_concurrent: 1,
                ..Default::default()
            },
            publisher.clone(),
        )?);
        let (started, release) = engine.io.pause_read();
        let active = engine.clone();
        let task = tokio::spawn(async move {
            active
                .execute(
                    EventQuery::default(),
                    OperationContext::new(Duration::from_secs(2)),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), started).await??;
        task.abort();
        let _ = task.await;
        assert_eq!(
            engine
                .shutdown(OperationContext::new(Duration::from_millis(20)))
                .await,
            Err(QueryError::Timeout)
        );
        if explicit_source_shutdown {
            publisher
                .shutdown(OperationContext::new(Duration::from_secs(2)))
                .await?;
        }
        let weak = Arc::downgrade(&publisher);
        drop(engine);
        drop(publisher);
        let retained = weak.upgrade().is_some();
        let cache_locked = matches!(
            std::thread::scope(|scope| scope
                .spawn(|| prune_stopped_materialization(
                    &cache_config,
                    owner.stream_id,
                    owner.backend_id,
                    &OperationContext::new(Duration::from_secs(2))
                ))
                .join()),
            Ok(Err(signal_storage::StorageError::Locked))
        );

        let mut locked = true;
        // Neither no materialization nor a different cache root may bypass
        // source ownership while the old physical read outlives shutdown.
        for materialization in [
            None,
            Some(MaterializationConfig {
                directory: temp.path().join("different-derived"),
                ..cache_config.clone()
            }),
        ] {
            let remote = object_store::local::LocalFileSystem::new_with_prefix(&objects)?;
            let second = ObjectIo::open_small_local(
                &owner,
                remote,
                ObjectIoLimits::default(),
                OperationContext::new(Duration::from_secs(2)),
            )
            .await;
            locked &= matches!(second, Err(ObjectIoError::OwnerLocked));
            if let Ok(io) = second {
                let successor = ObjectPublisher::new(
                    io,
                    tokio::runtime::Handle::current(),
                    PublicationConfig {
                        materialization,
                        ..Default::default()
                    },
                )?;
                successor
                    .shutdown(OperationContext::new(Duration::from_secs(2)))
                    .await?;
            }
        }
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // Owner cleanup is on its original fixed worker, with no replacement.
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let remote = object_store::local::LocalFileSystem::new_with_prefix(&objects)?;
            match ObjectIo::open_small_local(
                &owner,
                remote,
                ObjectIoLimits::default(),
                OperationContext {
                    deadline: until,
                    cancellation: tokio_util::sync::CancellationToken::new(),
                },
            )
            .await
            {
                Ok(io) => {
                    io.shutdown(OperationContext::new(Duration::from_secs(2)))
                        .await?;
                    break;
                }
                Err(ObjectIoError::OwnerLocked) if Instant::now() < until => {
                    tokio::time::sleep(Duration::from_millis(2)).await
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(
            retained,
            "source owner dropped while physical query reader survived"
        );
        assert!(
            locked,
            "source owner released while physical reader survived"
        );
        assert!(cache_locked, "cache pruned while physical reader survived");
        let pruned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    prune_stopped_materialization(
                        &cache_config,
                        owner.stream_id,
                        owner.backend_id,
                        &OperationContext::new(Duration::from_secs(2)),
                    )
                })
                .join()
        })
        .map_err(|_| "maintenance worker panicked")??;
        assert_eq!(pruned.removed_files, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sessions_share_operator_reservations_and_spill_and_caches_are_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::TempDir::new()?;
        let store = Arc::new(
            ParquetStore::open(
                signal_storage::StorageConfig {
                    directory: temporary.path().join("events"),
                    ..Default::default()
                },
                uuid::Uuid::new_v4(),
            )
            .await?,
        );
        let engine = QueryEngine::new(
            QueryConfig {
                memory_bytes: 64 * 1024,
                ..Default::default()
            },
            store.clone(),
        )?;
        let first_session =
            SessionContext::new_with_config_rt(SessionConfig::new(), engine.runtime.clone());
        let second_session =
            SessionContext::new_with_config_rt(SessionConfig::new(), engine.runtime.clone());
        let first_pool = first_session.runtime_env().memory_pool.clone();
        let second_pool = second_session.runtime_env().memory_pool.clone();
        assert!(Arc::ptr_eq(&first_pool, &second_pool));
        let first = MemoryConsumer::new("first-test").register(&first_pool);
        let second = MemoryConsumer::new("second-test").register(&second_pool);
        first.try_grow(40 * 1024)?;
        assert!(matches!(
            second.try_grow(30 * 1024),
            Err(DataFusionError::ResourcesExhausted(_))
        ));
        assert_eq!(engine.metrics().memory_bytes, 40 * 1024);
        drop(first);
        second.try_grow(30 * 1024)?;
        drop(second);
        assert_eq!(engine.metrics().memory_bytes, 0);
        let event: signal_event::IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"test"},"message":"operator memory"}"#,
        )?;
        store
            .append(
                vec![signal_storage::StoredEvent {
                    sequence: 1,
                    event: event.normalize(Utc::now())?,
                }],
                OperationContext::new(Duration::from_secs(2)),
            )
            .await?;
        let competitor = MemoryConsumer::new("active-other-query").register(&first_pool);
        competitor.try_grow(64 * 1024)?;
        assert_eq!(
            engine
                .execute(
                    EventQuery::default(),
                    OperationContext::new(Duration::from_secs(2))
                )
                .await,
            Err(QueryError::Resource)
        );
        drop(competitor);
        assert_eq!(
            engine
                .execute(
                    EventQuery::default(),
                    OperationContext::new(Duration::from_secs(2))
                )
                .await?
                .events
                .len(),
            1
        );
        assert!(!engine.runtime.disk_manager.tmp_files_enabled());
        assert_eq!(engine.runtime.disk_manager.used_disk_space(), 0);
        assert_eq!(
            engine
                .runtime
                .cache_manager
                .get_file_metadata_cache()
                .cache_limit(),
            0
        );
        assert!(
            engine
                .runtime
                .cache_manager
                .get_file_statistic_cache()
                .is_none()
        );
        assert!(
            engine
                .runtime
                .cache_manager
                .get_list_files_cache()
                .is_none()
        );
        store
            .shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
        Ok(())
    }
}

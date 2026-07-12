//! One consumer checkpoints only after event and finding persistence finish.
use signal_buffer::{BufferError, DurableBuffer};
use signal_event::SignalEvent;
use signal_findings::{DerivedFinding, Finding, FindingContext, FindingError, FindingStore};
use signal_protocol::{
    AdmissionFuture, EventSink, FindingSinkMetrics, LoggingSinkMetrics, QuerySinkMetrics,
    RuleSinkMetrics, SinkMetrics, StorageSinkMetrics,
};
use signal_query::QueryEngine;
use signal_rules::{RuleContext, RuleError, RuleSet};
use signal_storage::{OperationContext, StorageError, StoredEvent};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;

pub struct PipelineSink {
    pub audit: Option<Arc<crate::audit::Control>>,
    pub buffer: Arc<DurableBuffer>,
    pub store: Arc<crate::storage::Backend>,
    pub query: Option<Arc<QueryEngine>>,
    pub detection: Option<Arc<DetectionPipeline>>,
    pub logging: Option<crate::logging::LogWriter>,
    pub coverage: Option<Arc<signal_coverage::CoverageStore>>,
}

pub struct DetectionPipeline {
    /// Present only in native identity mode; retained startup WAL is unknown.
    pub authenticated_after: Option<u64>,
    pub rules: RuleSet,
    pub findings: Arc<FindingStore>,
    pub max_rows: usize,
    pub max_bytes: usize,
    pub evaluated: AtomicU64,
    pub matches: AtomicU64,
    pub failures: AtomicU64,
}
impl EventSink for PipelineSink {
    fn admit(&self, event: SignalEvent) -> AdmissionFuture<'_> {
        if self.store.metrics().fail_closed
            || self.store.metrics().closed
            || self
                .detection
                .as_ref()
                .is_some_and(|d| d.findings.metrics().closed)
        {
            self.buffer.close();
        }
        self.buffer.admit(event)
    }
    fn close(&self) {
        self.buffer.close();
    }
    fn metrics(&self) -> SinkMetrics {
        let mut metrics = self.buffer.metrics();
        metrics.audit = self.audit.as_ref().map(|audit| audit.metrics());
        metrics.closed |= metrics.audit.is_some_and(|audit| audit.held);
        metrics.closed |= self
            .coverage
            .as_ref()
            .is_some_and(|store| !store.metrics().available);
        if let Some(detection) = &self.detection {
            let findings = detection.findings.metrics();
            metrics.closed |= findings.closed;
            metrics.rules = Some(RuleSinkMetrics {
                loaded: detection.rules.len(),
                evaluated: detection.evaluated.load(Ordering::Relaxed),
                matches: detection.matches.load(Ordering::Relaxed),
                failures: detection.failures.load(Ordering::Relaxed),
            });
            metrics.findings = Some(FindingSinkMetrics {
                findings: findings.findings,
                finding_capacity: findings.finding_capacity,
                bytes: findings.disk_bytes,
                byte_capacity: findings.disk_capacity,
                index_bytes: findings.index_bytes,
                index_capacity: findings.index_capacity,
                command_depth: findings.command_depth,
                command_capacity: findings.command_capacity,
                operations: findings.operations_in_flight,
                operation_capacity: findings.operation_capacity,
                inserted: findings.inserted,
                duplicates: findings.duplicates,
                rejections: findings.rejections,
                failures: findings.failures,
                timeouts: findings.timeouts,
                closed: findings.closed,
            });
        }
        if let Some(logger) = &self.logging {
            let logs = logger.metrics();
            metrics.logging = Some(LoggingSinkMetrics {
                depth: logs.depth,
                capacity: logs.capacity,
                bytes: logs.bytes,
                byte_capacity: logs.capacity_bytes,
                queued: logs.queued_records,
                dropped: logs.dropped_records,
                full: logs.full_records,
                oversized: logs.oversized_records,
                closed_records: logs.closed_records,
                written: logs.written_records,
                errors: logs.write_errors,
                closed: logs.closed,
            });
        }
        let storage = self.store.metrics();
        metrics.closed |= storage.closed || storage.fail_closed;
        metrics.storage = Some(StorageSinkMetrics {
            persisted: storage.persisted,
            replayed: storage.replayed,
            bytes: storage.disk_bytes,
            byte_capacity: storage.disk_capacity,
            files: storage.files,
            file_capacity: storage.file_capacity,
            command_depth: storage.command_depth,
            command_capacity: storage.command_capacity,
            operations_in_flight: storage.operations_in_flight,
            operation_capacity: storage.operation_capacity,
            timeouts: storage.timeouts,
            full: storage.full,
            failures: storage.failures,
            high_water: storage.high_water,
            fail_closed: storage.fail_closed,
        });
        if let Some(query) = &self.query {
            let query = query.metrics();
            metrics.query = Some(QuerySinkMetrics {
                io_queue_depth: query.io_queue_depth,
                io_queue_capacity: query.io_queue_capacity,
                io_running: query.io_running,
                io_worker_capacity: query.io_worker_capacity,
                io_depth: query.io_depth,
                io_capacity: query.io_capacity,
                io_rejected: query.io_rejected,
                io_bytes: query.io_bytes,
                io_byte_capacity: query.io_byte_capacity,
                io_waiters: query.io_waiters,
                io_waiter_capacity: query.io_waiter_capacity,
                depth: query.depth,
                capacity: query.capacity,
                requests: query.requests,
                completed: query.completed,
                failures: query.failures,
                rejected: query.rejected,
                timeouts: query.timeouts,
                cancelled: query.cancelled,
                scanned_files: query.scanned_files,
                selected_partitions: query.selected_partitions,
                latency_micros: query.latency_micros,
                memory_bytes: query.memory_bytes,
                memory_capacity: query.memory_capacity,
            });
        }
        metrics
    }
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Finding(#[from] FindingError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("detection completion deadline exceeded; unfinished events remain in WAL")]
    Deadline,
    #[error(transparent)]
    Buffer(#[from] BufferError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("storage receipt does not cover the submitted WAL batch")]
    Receipt,
    #[error("consumer cancelled; unfinished events remain in WAL")]
    Cancelled,
}

pub struct ConsumerConfig {
    pub max_events: usize,
    pub max_bytes: usize,
    pub operation_timeout: Duration,
    pub flush_interval: Duration,
}

/// Failure closes admission before the task reports failure. No uncertain append is acked.
pub async fn consume(
    pipeline: Arc<PipelineSink>,
    config: ConsumerConfig,
    drain: CancellationToken,
    cancel: CancellationToken,
    failed: CancellationToken,
) -> Result<(), PipelineError> {
    let result = consume_inner(&pipeline, &config, drain, cancel).await;
    if result.is_err() {
        pipeline.close();
        failed.cancel();
    }
    result
}

async fn consume_inner(
    pipeline: &PipelineSink,
    config: &ConsumerConfig,
    drain: CancellationToken,
    cancel: CancellationToken,
) -> Result<(), PipelineError> {
    let mut pending_since = None;
    loop {
        let depth = pipeline.buffer.snapshot().depth;
        if depth == 0 {
            pending_since = None;
            if drain.is_cancelled() {
                return Ok(());
            }
            pause(&cancel).await?;
            continue;
        } else {
            let since = *pending_since.get_or_insert_with(Instant::now);
            if depth < config.max_events
                && !drain.is_cancelled()
                && Instant::now() < since + config.flush_interval
            {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(PipelineError::Cancelled),
                    _ = drain.cancelled() => {},
                    _ = sleep(Duration::from_millis(10)) => {},
                }
                continue;
            }
        }
        let batch = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(PipelineError::Cancelled),
            result = pipeline.buffer.read_batch(config.max_events, config.max_bytes) => match result {
                Ok(batch) => batch,
                Err(BufferError::Full) => { pause(&cancel).await?; continue; }
                Err(error) => return Err(error.into()),
            },
        };
        if batch.is_empty() {
            if drain.is_cancelled() && pipeline.buffer.snapshot().depth == 0 {
                return Ok(());
            }
            pause(&cancel).await?;
            continue;
        }
        let first = batch.first().ok_or(PipelineError::Receipt)?.sequence;
        let last = batch.last().ok_or(PipelineError::Receipt)?.sequence;
        let deadline = Instant::now() + config.operation_timeout;
        let rows: Vec<_> = batch
            .iter()
            .map(|row| StoredEvent {
                sequence: row.sequence,
                event: row.event.clone(),
            })
            .collect();
        // Only admission contention is retryable. Durable quota/corruption and
        // uncertain effects return without advancing the shared WAL checkpoint.
        let receipt = loop {
            if cancel.is_cancelled() {
                return Err(PipelineError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(PipelineError::Deadline);
            }
            match pipeline
                .store
                .append(
                    &rows,
                    OperationContext {
                        deadline,
                        cancellation: cancel.child_token(),
                    },
                )
                .await
            {
                Ok(receipt) => break receipt,
                Err(StorageError::Busy) => tokio::select! {biased;
                    _=cancel.cancelled()=>return Err(PipelineError::Cancelled),
                    _=tokio::time::sleep_until(deadline)=>return Err(PipelineError::Deadline),
                    _=sleep(Duration::from_millis(2))=>{},
                },
                Err(error) => return Err(error.into()),
            }
        };
        if receipt.first_sequence != first || receipt.last_sequence != last {
            return Err(PipelineError::Receipt);
        }
        if let Some(detection) = &pipeline.detection {
            let result = complete_findings(detection, &batch, deadline, &cancel).await;
            if result.is_err() {
                detection.failures.fetch_add(1, Ordering::Relaxed);
            }
            result?;
        }
        pending_since = None;
        // A bounded WAL command queue may be busy with admissions. Retry the control
        // command without re-persisting the batch; storage has already committed it.
        loop {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(PipelineError::Cancelled),
                result = pipeline.buffer.ack(last) => result,
            };
            match result {
                Ok(()) => break,
                Err(BufferError::Full) => pause(&cancel).await?,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

async fn complete_findings(
    detection: &DetectionPipeline,
    batch: &[signal_buffer::SequencedEvent],
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), PipelineError> {
    let mut pending = Vec::new();
    let mut bytes = 0usize;
    for (index, row) in batch.iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(PipelineError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(PipelineError::Deadline);
        }
        if index % 16 == 0 {
            tokio::task::yield_now().await;
        }
        let findings = detection.rules.evaluate_with_context(
            &row.event,
            &RuleContext {
                deadline,
                cancellation: cancel.child_token(),
            },
        )?;
        detection.evaluated.fetch_add(1, Ordering::Relaxed);
        detection
            .matches
            .fetch_add(findings.len() as u64, Ordering::Relaxed);
        for finding in findings {
            let finding = match detection.authenticated_after {
                Some(floor) => FindingOutput::Derived(DerivedFinding::from_event(
                    finding,
                    &row.event,
                    row.sequence > floor,
                )?),
                None => FindingOutput::Legacy(finding),
            };
            let preview = finding.preview();
            let mut size = SizeCounter {
                bytes: signal_findings::FINDING_FRAME_BYTES,
                limit: detection.max_bytes,
            };
            serde_json::to_writer(&mut size, &preview).map_err(|_| FindingError::Quota)?;
            if pending.len() == detection.max_rows || bytes + size.bytes > detection.max_bytes {
                persist_findings(detection, std::mem::take(&mut pending), deadline, cancel).await?;
                bytes = 0;
            }
            bytes += size.bytes;
            pending.push(finding);
        }
    }
    if !pending.is_empty() {
        persist_findings(detection, pending, deadline, cancel).await?;
    }
    Ok(())
}

enum FindingOutput {
    Legacy(Finding),
    Derived(DerivedFinding),
}
impl FindingOutput {
    fn preview(&self) -> Finding {
        match self {
            Self::Legacy(finding) => finding.clone(),
            Self::Derived(finding) => finding.budget_preview(),
        }
    }
}
async fn persist_findings(
    detection: &DetectionPipeline,
    findings: Vec<FindingOutput>,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), PipelineError> {
    let total = findings.len();
    let context = FindingContext {
        deadline,
        cancellation: cancel.child_token(),
    };
    let receipt = if detection.authenticated_after.is_some() {
        let findings = findings
            .into_iter()
            .map(|finding| match finding {
                FindingOutput::Derived(finding) => Ok(finding),
                FindingOutput::Legacy(_) => Err(FindingError::Invalid("mixed finding modes")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        detection.findings.append_derived(findings, context).await?
    } else {
        let findings = findings
            .into_iter()
            .map(|finding| match finding {
                FindingOutput::Legacy(finding) => Ok(finding),
                FindingOutput::Derived(_) => Err(FindingError::Invalid("mixed finding modes")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        detection.findings.append(findings, context).await?
    };
    if receipt.inserted + receipt.duplicates != total {
        return Err(PipelineError::Receipt);
    }
    Ok(())
}

struct SizeCounter {
    bytes: usize,
    limit: usize,
}
impl Write for SizeCounter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("finding limit"));
        }
        self.bytes += input.len();
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn pause(cancel: &CancellationToken) -> Result<(), PipelineError> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(PipelineError::Cancelled),
        _ = sleep(Duration::from_millis(10)) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_buffer::{BufferConfig, Policy};
    use signal_event::IngestEvent;
    use signal_storage::StorageConfig;
    use tempfile::TempDir;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn event(message: &str) -> Result<SignalEvent> {
        let input: IngestEvent = serde_json::from_value(serde_json::json!({
            "timestamp":"2026-10-06T12:00:00.123456789Z", "source":{"type":"consumer-test"},
            "message":message,"attributes":{"nested":{"values":[1,true,"value"]}}
        }))?;
        let observed = input.timestamp;
        Ok(input.normalize(observed)?)
    }

    fn configs(temp: &TempDir) -> (BufferConfig, StorageConfig) {
        (
            BufferConfig {
                directory: temp.path().join("wal"),
                max_events: 10,
                max_memory_bytes: 8192,
                max_record_bytes: 2048,
                segment_bytes: 8192,
                operation_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            StorageConfig {
                directory: temp.path().join("events"),
                max_batch_events: 10,
                max_batch_bytes: 8192,
                max_event_bytes: 2048,
                ..Default::default()
            },
        )
    }
    fn consumer_config() -> ConsumerConfig {
        ConsumerConfig {
            max_events: 10,
            max_bytes: 8192,
            operation_timeout: Duration::from_secs(5),
            flush_interval: Duration::from_secs(10),
        }
    }
    async fn open(wal: BufferConfig, storage: StorageConfig) -> Result<Arc<PipelineSink>> {
        let buffer = Arc::new(DurableBuffer::open(wal).await?);
        let store = Arc::new(crate::storage::Backend::local(
            signal_storage::ParquetStore::open(storage, buffer.snapshot().stream_id).await?,
        ));
        Ok(Arc::new(PipelineSink {
            audit: None,
            buffer,
            store,
            query: None,
            detection: None,
            logging: None,
            coverage: None,
        }))
    }
    async fn stop(pipeline: &PipelineSink) -> Result {
        pipeline.close();
        if let Some(detection) = &pipeline.detection {
            detection
                .findings
                .shutdown(FindingContext::new(Duration::from_secs(5)))
                .await?;
        }
        pipeline
            .store
            .shutdown(OperationContext::new(Duration::from_secs(5)))
            .await?;
        pipeline.buffer.shutdown().await?;
        Ok(())
    }
    async fn drain(pipeline: Arc<PipelineSink>) -> Result {
        pipeline.close();
        let drain = CancellationToken::new();
        drain.cancel();
        consume(
            pipeline,
            consumer_config(),
            drain,
            CancellationToken::new(),
            CancellationToken::new(),
        )
        .await?;
        Ok(())
    }

    async fn open_detecting(
        wal: BufferConfig,
        storage: StorageConfig,
        finding_config: signal_findings::FindingConfig,
    ) -> Result<Arc<PipelineSink>> {
        let buffer = Arc::new(DurableBuffer::open(wal).await?);
        let stream = buffer.snapshot().stream_id;
        let store = Arc::new(crate::storage::Backend::local(
            signal_storage::ParquetStore::open(storage, stream).await?,
        ));
        let max_rows = finding_config.max_append_rows;
        let max_bytes = finding_config.max_append_bytes;
        let findings = Arc::new(FindingStore::open(finding_config, stream).await?);
        let rules = RuleSet::from_yaml_documents(
            [
                "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: generic.message\n  name: Message example\nspec:\n  severity: medium\n  match:\n    all:\n      - field: message\n        exists: true\n  finding:\n    title: Message detected\n",
            ],
            signal_rules::RuleLimits::default(),
        )?;
        Ok(Arc::new(PipelineSink {
            audit: None,
            buffer,
            store,
            query: None,
            logging: None,
            coverage: None,
            detection: Some(Arc::new(DetectionPipeline {
                authenticated_after: None,
                rules,
                findings,
                max_rows,
                max_bytes,
                evaluated: AtomicU64::new(0),
                matches: AtomicU64::new(0),
                failures: AtomicU64::new(0),
            })),
        }))
    }

    #[tokio::test]
    async fn finding_quota_after_parquet_publish_never_acks_and_replays_both_stores() -> Result {
        let temp = TempDir::new()?;
        let (wal, storage) = configs(&temp);
        let finding_config = signal_findings::FindingConfig {
            directory: temp.path().join("findings"),
            ..Default::default()
        };
        let pipeline = open_detecting(
            wal.clone(),
            storage.clone(),
            signal_findings::FindingConfig {
                max_disk_bytes: 24,
                ..finding_config.clone()
            },
        )
        .await?;
        let expected = vec![event("finding quota a")?, event("finding quota b")?];
        for event in &expected {
            pipeline.admit(event.clone()).await?;
        }
        let drain = CancellationToken::new();
        drain.cancel();
        let failed = CancellationToken::new();
        let result = consume(
            pipeline.clone(),
            consumer_config(),
            drain,
            CancellationToken::new(),
            failed.clone(),
        )
        .await;
        assert!(matches!(
            result,
            Err(PipelineError::Finding(FindingError::Quota))
        ));
        assert!(failed.is_cancelled() && pipeline.metrics().closed);
        assert_eq!(pipeline.store.metrics().high_water, 2);
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
        assert_eq!(pipeline.buffer.snapshot().depth, 2);
        assert_eq!(
            pipeline
                .detection
                .as_ref()
                .ok_or("missing detection")?
                .findings
                .metrics()
                .findings,
            0
        );
        stop(&pipeline).await?;
        let pipeline = open_detecting(wal, storage, finding_config).await?;
        drain_for_test(pipeline.clone()).await?;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 2);
        assert_eq!(pipeline.store.metrics().persisted, 2);
        assert_eq!(pipeline.store.metrics().replayed, 2);
        let detection = pipeline.detection.as_ref().ok_or("missing detection")?;
        let actual = detection
            .findings
            .query(
                signal_findings::FindingQuery {
                    limit: 10,
                    ..Default::default()
                },
                FindingContext::new(Duration::from_secs(5)),
            )
            .await?;
        let mut expected_findings = Vec::new();
        for event in &expected {
            expected_findings.extend(detection.rules.evaluate(event)?);
        }
        expected_findings.sort_by_key(|f| (f.created_at, f.id));
        assert_eq!(actual, expected_findings);
        stop(&pipeline).await?;
        Ok(())
    }

    async fn drain_for_test(pipeline: Arc<PipelineSink>) -> Result {
        drain(pipeline).await
    }

    #[tokio::test]
    async fn both_stores_synced_before_ack_replay_one_finding_and_checkpoint_once() -> Result {
        let temp = TempDir::new()?;
        let (wal, storage) = configs(&temp);
        let finding_config = signal_findings::FindingConfig {
            directory: temp.path().join("findings"),
            ..Default::default()
        };
        let pipeline = open_detecting(wal.clone(), storage.clone(), finding_config.clone()).await?;
        let event = event("finding sync before ack")?;
        pipeline.admit(event.clone()).await?;
        let batch = pipeline.buffer.read_batch(10, 8192).await?;
        pipeline
            .store
            .append(
                &batch
                    .iter()
                    .map(|row| StoredEvent {
                        sequence: row.sequence,
                        event: row.event.clone(),
                    })
                    .collect::<Vec<_>>(),
                OperationContext::new(Duration::from_secs(5)),
            )
            .await?;
        let detection = pipeline.detection.as_ref().ok_or("missing detection")?;
        let expected = detection.rules.evaluate(&event)?;
        detection
            .findings
            .append(
                expected.clone(),
                FindingContext::new(Duration::from_secs(5)),
            )
            .await?;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
        stop(&pipeline).await?;
        let pipeline = open_detecting(wal, storage, finding_config).await?;
        drain(pipeline.clone()).await?;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 1);
        assert_eq!(pipeline.store.metrics().persisted, 1);
        let findings = &pipeline
            .detection
            .as_ref()
            .ok_or("missing detection")?
            .findings;
        assert_eq!(findings.metrics().findings, 1);
        assert_eq!(findings.metrics().duplicates, 1);
        assert_eq!(
            findings
                .query(
                    signal_findings::FindingQuery {
                        limit: 10,
                        ..Default::default()
                    },
                    FindingContext::new(Duration::from_secs(5))
                )
                .await?,
            expected
        );
        stop(&pipeline).await?;
        Ok(())
    }
    #[tokio::test]
    async fn storage_full_never_acknowledges_and_recovery_retains_exact_event() -> Result {
        let temp = TempDir::new()?;
        let (wal, mut storage) = configs(&temp);
        storage.max_disk_bytes = 36;
        let pipeline = open(wal.clone(), storage).await?;
        let event = event("quota backlog")?;
        pipeline.admit(event.clone()).await?;
        let drain = CancellationToken::new();
        drain.cancel();
        let failed = CancellationToken::new();
        let result = consume(
            pipeline.clone(),
            consumer_config(),
            drain,
            CancellationToken::new(),
            failed.clone(),
        )
        .await;
        assert!(matches!(
            result,
            Err(PipelineError::Storage(StorageError::Full))
        ));
        assert!(failed.is_cancelled());
        assert!(pipeline.metrics().closed);
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
        assert_eq!(pipeline.buffer.snapshot().depth, 1);
        assert_eq!(pipeline.store.metrics().high_water, 0);
        stop(&pipeline).await?;
        let replay = DurableBuffer::open(wal).await?;
        assert_eq!(replay.read_batch(1, 8192).await?[0].event, event);
        replay.shutdown().await?;
        Ok(())
    }
    #[tokio::test]
    async fn publication_before_ack_restarts_without_duplicate_rows() -> Result {
        let temp = TempDir::new()?;
        let (wal, storage) = configs(&temp);
        let pipeline = open(wal.clone(), storage.clone()).await?;
        for message in ["before-ack-a", "before-ack-b"] {
            pipeline.admit(event(message)?).await?;
        }
        let batch = pipeline.buffer.read_batch(10, 8192).await?;
        let expected: Vec<_> = batch.iter().map(|row| row.event.clone()).collect();
        pipeline
            .store
            .append(
                &batch
                    .into_iter()
                    .map(|row| StoredEvent {
                        sequence: row.sequence,
                        event: row.event,
                    })
                    .collect::<Vec<_>>(),
                OperationContext::new(Duration::from_secs(5)),
            )
            .await?;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
        stop(&pipeline).await?;
        let pipeline = open(wal, storage).await?;
        assert_eq!(pipeline.buffer.snapshot().depth, 2);
        drain(pipeline.clone()).await?;
        assert_eq!(pipeline.buffer.snapshot().depth, 0);
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 2);
        assert_eq!(pipeline.store.metrics().persisted, 2);
        assert_eq!(pipeline.store.metrics().replayed, 2);
        let rows = pipeline
            .store
            .read_batch(0, 10, 8192, OperationContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(
            rows.into_iter().map(|row| row.event).collect::<Vec<_>>(),
            expected
        );
        stop(&pipeline).await?;
        Ok(())
    }
    #[tokio::test]
    async fn drop_oldest_during_persistence_does_not_ack_later_events() -> Result {
        let temp = TempDir::new()?;
        let (mut wal, storage) = configs(&temp);
        wal.max_events = 2;
        wal.policy = Policy::DropOldest;
        let pipeline = open(wal, storage).await?;
        for message in ["first", "second"] {
            pipeline.admit(event(message)?).await?;
        }
        let batch = pipeline.buffer.read_batch(2, 8192).await?;
        for message in ["third", "fourth"] {
            pipeline.admit(event(message)?).await?;
        }
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 2);
        pipeline
            .store
            .append(
                &batch
                    .into_iter()
                    .map(|row| StoredEvent {
                        sequence: row.sequence,
                        event: row.event,
                    })
                    .collect::<Vec<_>>(),
                OperationContext::new(Duration::from_secs(5)),
            )
            .await?;
        pipeline.buffer.ack(2).await?;
        assert_eq!(pipeline.buffer.snapshot().depth, 2);
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 2);
        let drain = CancellationToken::new();
        drain.cancel();
        let mut config = consumer_config();
        config.max_events = 2;
        consume(
            pipeline.clone(),
            config,
            drain,
            CancellationToken::new(),
            CancellationToken::new(),
        )
        .await?;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 4);
        assert_eq!(pipeline.buffer.snapshot().depth, 0);
        assert_eq!(pipeline.store.metrics().persisted, 4);
        stop(&pipeline).await?;
        Ok(())
    }
    #[tokio::test]
    async fn coalesces_below_row_limit_and_drain_bypasses_interval() -> Result {
        let temp = TempDir::new()?;
        let (wal, storage) = configs(&temp);
        let pipeline = open(wal, storage).await?;
        let drain = CancellationToken::new();
        let worker = tokio::spawn(consume(
            pipeline.clone(),
            consumer_config(),
            drain.clone(),
            CancellationToken::new(),
            CancellationToken::new(),
        ));
        for message in ["coalesce-a", "coalesce-b", "coalesce-c"] {
            pipeline.admit(event(message)?).await?;
        }
        assert_eq!(pipeline.store.metrics().high_water, 0);
        pipeline.close();
        drain.cancel();
        tokio::time::timeout(Duration::from_secs(5), worker).await???;
        assert_eq!(pipeline.buffer.snapshot().depth, 0);
        assert_eq!(pipeline.store.metrics().persisted, 3);
        let manifests = std::fs::read_dir(temp.path().join("events"))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "manifest")
            })
            .count();
        assert_eq!(manifests, 1);
        stop(&pipeline).await?;
        Ok(())
    }
    #[cfg(feature = "s3-query")]
    async fn object_pipeline(
        temp: &TempDir,
        max_disk_bytes: u64,
    ) -> Result<(
        Arc<PipelineSink>,
        Arc<signal_storage::object_publication::ObjectPublisher>,
    )> {
        use signal_storage::{
            object_io::{ObjectIo, ObjectIoLimits, SmallOwnerConfig},
            object_publication::{ObjectPublisher, PublicationConfig},
        };
        let (wal, mut storage) = configs(temp);
        storage.max_disk_bytes = max_disk_bytes;
        let buffer = Arc::new(DurableBuffer::open(wal).await?);
        let objects = temp.path().join("remote");
        std::fs::create_dir(&objects)?;
        let remote = object_store::local::LocalFileSystem::new_with_prefix(&objects)?;
        let io = ObjectIo::open_small_local(
            &SmallOwnerConfig {
                directory: temp.path().join("control"),
                stream_id: buffer.snapshot().stream_id,
                backend_id: uuid::Uuid::new_v4(),
            },
            remote,
            ObjectIoLimits::default(),
            OperationContext::new(Duration::from_secs(5)),
        )
        .await?;
        let publisher = Arc::new(ObjectPublisher::new(
            io,
            tokio::runtime::Handle::current(),
            PublicationConfig {
                storage,
                ..Default::default()
            },
        )?);
        let store = Arc::new(crate::storage::Backend::Object(publisher.clone()));
        Ok((
            Arc::new(PipelineSink {
                audit: None,
                buffer,
                store,
                query: None,
                detection: None,
                logging: None,
                coverage: None,
            }),
            publisher,
        ))
    }
    #[cfg(feature = "s3-query")]
    #[tokio::test]
    async fn object_admission_contention_recovers_without_checkpointing_early() -> Result {
        let temp = TempDir::new()?;
        let (pipeline, publisher) = object_pipeline(&temp, 64 * 1024 * 1024).await?;
        let lease = publisher
            .snapshot(OperationContext::new(Duration::from_secs(5)))
            .await?;
        pipeline.buffer.admit(event("bounded contention")?).await?;
        let drain = CancellationToken::new();
        drain.cancel();
        let handle = tokio::spawn(consume(
            pipeline.clone(),
            consumer_config(),
            drain,
            CancellationToken::new(),
            CancellationToken::new(),
        ));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
        assert_eq!(pipeline.store.metrics().high_water, 0);
        assert_eq!(publisher.metrics().depth, 1);
        drop(lease);
        tokio::time::timeout(Duration::from_secs(5), handle).await???;
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 1);
        assert_eq!(pipeline.store.metrics().persisted, 1);
        assert_eq!(pipeline.store.metrics().files, 2);
        assert!(pipeline.store.metrics().disk_bytes > 0);
        assert_eq!(pipeline.store.metrics().full, 0);
        stop(&pipeline).await?;
        Ok(())
    }
    #[cfg(feature = "s3-query")]
    #[tokio::test]
    async fn object_busy_deadline_and_durable_quota_never_checkpoint() -> Result {
        for quota in [false, true] {
            let temp = TempDir::new()?;
            let (pipeline, publisher) =
                object_pipeline(&temp, if quota { 36 } else { 64 * 1024 * 1024 }).await?;
            let lease = if quota {
                None
            } else {
                Some(
                    publisher
                        .snapshot(OperationContext::new(Duration::from_secs(5)))
                        .await?,
                )
            };
            pipeline.buffer.admit(event("unfinished")?).await?;
            let mut config = consumer_config();
            config.operation_timeout = if quota {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(50)
            };
            let drain = CancellationToken::new();
            drain.cancel();
            let failed = CancellationToken::new();
            let start = Instant::now();
            let result = consume(
                pipeline.clone(),
                config,
                drain,
                CancellationToken::new(),
                failed.clone(),
            )
            .await;
            if quota {
                assert!(matches!(
                    result,
                    Err(PipelineError::Storage(StorageError::Full))
                ));
                assert_eq!(pipeline.store.metrics().full, 1);
            } else {
                assert!(matches!(result, Err(PipelineError::Deadline)));
                assert!(start.elapsed() < Duration::from_millis(300));
            }
            assert!(failed.is_cancelled());
            assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
            assert_eq!(pipeline.store.metrics().high_water, 0);
            drop(lease);
            stop(&pipeline).await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn native_activation_floor_keeps_backlog_unknown_and_replay_preserves_exact_scopes()
    -> Result {
        let temp = TempDir::new()?;
        let (wal, storage) = configs(&temp);
        let finding_config = signal_findings::FindingConfig {
            directory: temp.path().join("findings"),
            ..Default::default()
        };
        let old = event("unverified retained backlog")?;
        let new = event("fresh trusted host admission")?;
        let mut pipeline =
            open_detecting(wal.clone(), storage.clone(), finding_config.clone()).await?;
        pipeline.admit(old.clone()).await?;
        let floor = pipeline.buffer.snapshot().last_sequence;
        {
            let owner = Arc::get_mut(&mut pipeline).ok_or("pipeline ownership")?;
            let detection = Arc::get_mut(owner.detection.as_mut().ok_or("detection")?)
                .ok_or("detection ownership")?;
            detection.authenticated_after = Some(floor);
            detection
                .findings
                .enable_scopes(FindingContext::new(Duration::from_secs(5)))
                .await?;
        }
        // This unit test qualifies the host floor; the HTTP gate proves native
        // credential admission. A sequence number alone is never a credential.
        pipeline.admit(new.clone()).await?;
        let batch = pipeline.buffer.read_batch(10, 8192).await?;
        let detection = pipeline.detection.as_ref().ok_or("detection")?;
        complete_findings(
            detection,
            &batch,
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .await?;
        let query = signal_findings::FindingQuery {
            limit: 10,
            ..Default::default()
        };
        let rows = detection
            .findings
            .query(query.clone(), FindingContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(rows.len(), 2);
        assert!(
            !rows
                .iter()
                .find(|row| row.event_ids == [old.id])
                .ok_or("old row")?
                .attributes
                .contains_key("signal.scope.v1")
        );
        assert!(
            rows.iter()
                .find(|row| row.event_ids == [new.id])
                .ok_or("new row")?
                .attributes
                .contains_key("signal.scope.v1")
        );
        let journal = temp.path().join("findings/findings.journal");
        let bytes = std::fs::read(&journal)?;
        stop(&pipeline).await?;
        let mut pipeline = open_detecting(wal, storage, finding_config).await?;
        let floor = pipeline.buffer.snapshot().last_sequence;
        {
            let owner = Arc::get_mut(&mut pipeline).ok_or("pipeline ownership")?;
            let detection = Arc::get_mut(owner.detection.as_mut().ok_or("detection")?)
                .ok_or("detection ownership")?;
            detection.authenticated_after = Some(floor);
            detection
                .findings
                .enable_scopes(FindingContext::new(Duration::from_secs(5)))
                .await?;
        }
        let batch = pipeline.buffer.read_batch(10, 8192).await?;
        let detection = pipeline.detection.as_ref().ok_or("detection")?;
        complete_findings(
            detection,
            &batch,
            Instant::now() + Duration::from_secs(5),
            &CancellationToken::new(),
        )
        .await?;
        assert_eq!(
            detection
                .findings
                .query(query, FindingContext::new(Duration::from_secs(5)))
                .await?,
            rows
        );
        assert_eq!(std::fs::read(&journal)?, bytes);
        assert_eq!(pipeline.buffer.snapshot().checkpoint, 0);
        assert_eq!(detection.findings.metrics().duplicates, 2);
        stop(&pipeline).await?;
        Ok(())
    }
}

//! Bounded, replay-safe filesystem event persistence. See ADR-004 and ADR-010.
pub mod codec;
mod fs;
mod pages;

use chrono::{DateTime, Utc};
use signal_event::SignalEvent;
use signal_protocol::EventQuery;
use std::{
    future::Future,
    io::Write,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StorageError>> + Send + 'a>>;
pub type EventStream =
    Pin<Box<dyn futures_core::Stream<Item = Result<SignalEvent, StorageError>> + Send>>;
#[derive(Clone, Debug, PartialEq)]
pub struct StoredEvent {
    pub sequence: u64,
    pub event: SignalEvent,
}
/// Immutable committed file validated before exposure to a query engine.
#[derive(Clone, Debug)]
pub struct PublishedFile {
    pub path: PathBuf,
    pub rows: usize,
    pub bytes: u64,
    /// Sum of validated column chunk uncompressed sizes, including page headers.
    pub uncompressed_bytes: u64,
}
/// Caller-bounded snapshot of committed files in intersecting UTC partitions.
#[derive(Clone, Debug, Default)]
pub struct FileSelection {
    pub files: Vec<PublishedFile>,
    pub partitions: usize,
}
#[derive(Clone, Debug)]
pub struct OperationContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
impl OperationContext {
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancellation: CancellationToken::new(),
        }
    }
}
pub(crate) fn check_context(context: Option<&OperationContext>) -> Result<(), StorageError> {
    if let Some(context) = context {
        if Instant::now() >= context.deadline {
            return Err(StorageError::Timeout);
        }
        if context.cancellation.is_cancelled() {
            return Err(StorageError::Cancelled);
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StorageCompression {
    #[default]
    Snappy,
    Zstd,
    Uncompressed,
}
impl std::str::FromStr for StorageCompression {
    type Err = StorageError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "snappy" => Ok(Self::Snappy),
            "zstd" => Ok(Self::Zstd),
            "uncompressed" => Ok(Self::Uncompressed),
            _ => Err(StorageError::Config("compression")),
        }
    }
}
#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub directory: PathBuf,
    pub max_batch_events: usize,
    pub max_batch_bytes: usize,
    pub max_event_bytes: usize,
    pub max_disk_bytes: u64,
    pub max_files: usize,
    pub command_capacity: usize,
    pub operation_timeout: Duration,
    pub compression: StorageCompression,
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            directory: "data/events".into(),
            max_batch_events: 1000,
            max_batch_bytes: 8 * 1024 * 1024,
            max_event_bytes: 2 * 1024 * 1024,
            max_disk_bytes: 1024 * 1024 * 1024,
            max_files: 100_000,
            command_capacity: 8,
            operation_timeout: Duration::from_secs(120),
            compression: StorageCompression::Snappy,
        }
    }
}
impl StorageConfig {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.directory.as_os_str().is_empty()
            || self.max_batch_events == 0
            || self.max_batch_events > 1_000_000
            || self.max_batch_bytes == 0
            || self.max_batch_bytes > i32::MAX as usize / 8
            || self.max_event_bytes == 0
            || self.max_event_bytes > self.max_batch_bytes
            || self.max_disk_bytes < 36
            || self.max_files < 3
            || self.command_capacity == 0
            || self.command_capacity > Semaphore::MAX_PERMITS
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(3600)
        {
            return Err(StorageError::Config(
                "positive bounded storage capacities and deadline",
            ));
        }
        Ok(())
    }
    pub(crate) fn manifest_limit(&self) -> usize {
        4096 + self.max_batch_events * 256
    }
    pub(crate) fn file_limit(&self) -> u64 {
        self.max_batch_bytes as u64 * 4 + 1024 * 1024
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct StoreReceipt {
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub new_count: usize,
    pub replay_count: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct StorageMetrics {
    pub high_water: u64,
    pub persisted: u64,
    pub replayed: u64,
    pub disk_bytes: u64,
    pub disk_capacity: u64,
    pub files: usize,
    pub file_capacity: usize,
    pub command_depth: usize,
    pub command_capacity: usize,
    pub operations_in_flight: usize,
    pub operation_capacity: usize,
    pub timeouts: u64,
    pub full: u64,
    pub failures: u64,
    pub closed: bool,
    pub fail_closed: bool,
}
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid storage configuration: {0}")]
    Config(&'static str),
    #[error("invalid storage batch or conflicting replay content")]
    InvalidBatch,
    #[error("committed storage corruption: {0}")]
    Corrupt(&'static str),
    #[error("storage filesystem operation failed")]
    Io(#[source] std::io::Error),
    #[error("storage capacity is full")]
    Full,
    #[error("storage operation deadline exceeded; an active commit may have completed")]
    Timeout,
    #[error("storage operation cancelled; an active commit may have completed")]
    Cancelled,
    #[error("storage is closed or unavailable")]
    Closed,
    #[error("storage root is already locked")]
    Locked,
    #[error("storage and WAL stream identities differ")]
    StreamMismatch,
    #[error("query execution is deferred until Phase 4")]
    QueryUnavailable,
}
pub trait EventStore: Send + Sync + 'static {
    fn append(
        &self,
        batch: Vec<StoredEvent>,
        context: OperationContext,
    ) -> StoreFuture<'_, StoreReceipt>;
    fn query(&self, query: EventQuery, context: OperationContext) -> StoreFuture<'_, EventStream>;
    fn metrics(&self) -> StorageMetrics;
    fn close(&self);
}
struct Shared {
    closed: AtomicBool,
    failed: AtomicBool,
    stopping: AtomicBool,
    snapshot: Mutex<StorageMetrics>,
    active_deadline: Mutex<Option<(Instant, bool)>>,
    timeouts: AtomicU64,
    full: AtomicU64,
    failures: AtomicU64,
}
impl Shared {
    fn check_deadline(&self) {
        if self
            .active_deadline
            .lock()
            .map(|d| {
                d.is_some_and(|(deadline, read_only)| !read_only && Instant::now() >= deadline)
            })
            .unwrap_or(true)
        {
            self.failed.store(true, Ordering::Release);
            self.closed.store(true, Ordering::Release);
        }
    }
    fn publish(&self, metrics: StorageMetrics) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            *snapshot = metrics;
        } else {
            self.failed.store(true, Ordering::Release);
        }
    }
}
enum Operation {
    Append(Vec<StoredEvent>),
    Read(u64, usize, usize),
    Select(Option<DateTime<Utc>>, Option<DateTime<Utc>>, usize),
    Flush,
    #[cfg(test)]
    Pause(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>),
    #[cfg(test)]
    SelectPause(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>),
}
impl Operation {
    fn read_only_selection(&self) -> bool {
        match self {
            Self::Select(..) => true,
            #[cfg(test)]
            Self::SelectPause(..) => true,
            _ => false,
        }
    }
}
enum Reply {
    Receipt(StoreReceipt),
    Batch(Vec<StoredEvent>),
    Selection(FileSelection),
    Done,
}
struct Command {
    operation: Operation,
    context: OperationContext,
    abandoned: Arc<AtomicBool>,
    reply: oneshot::Sender<Result<Reply, StorageError>>,
    // Worker and caller share ownership. Neither cancellation nor an unpolled
    // reply can release the operation bound before both owners finish.
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}
struct CancelOnDrop(Arc<AtomicBool>, CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        self.1.cancel();
    }
}
struct WorkerExit(Arc<Shared>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        if !self.0.stopping.load(Ordering::Acquire) {
            self.0.failed.store(true, Ordering::Release);
        }
    }
}
/// A single tracked disk worker owns the lock. Dropping handles never blocks Tokio.
pub struct ParquetStore {
    sender: mpsc::Sender<Command>,
    shared: Arc<Shared>,
    config: StorageConfig,
    commands: Arc<Semaphore>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl ParquetStore {
    pub async fn open(config: StorageConfig, stream_id: Uuid) -> Result<Self, StorageError> {
        config.validate()?;
        if stream_id.is_nil() {
            return Err(StorageError::Config("stream identity"));
        }
        let shared = Arc::new(Shared {
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            snapshot: Mutex::new(StorageMetrics::default()),
            active_deadline: Mutex::new(None),
            timeouts: AtomicU64::new(0),
            full: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        });
        let (sender, mut receiver) = mpsc::channel::<Command>(config.command_capacity);
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker_shared = shared.clone();
        let worker_config = config.clone();
        let worker = thread::Builder::new()
            .name("signal-parquet".into())
            .spawn(move || {
                let _exit = WorkerExit(worker_shared.clone());
                let mut engine = match fs::Engine::open(worker_config, stream_id) {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                worker_shared.publish(engine.metrics);
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                while let Some(command) = receiver.blocking_recv() {
                    if worker_shared.stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let result = if worker_shared.failed.load(Ordering::Acquire) {
                        Err(StorageError::Closed)
                    } else if command.context.cancellation.is_cancelled()
                        || command.abandoned.load(Ordering::Acquire)
                        || command.reply.is_closed()
                    {
                        Err(StorageError::Cancelled)
                    } else if Instant::now() >= command.context.deadline {
                        Err(StorageError::Timeout)
                    } else {
                        if let Ok(mut deadline) = worker_shared.active_deadline.lock() {
                            *deadline = Some((
                                command.context.deadline,
                                command.operation.read_only_selection(),
                            ));
                        }
                        match command.operation {
                            Operation::Append(batch)
                                if !worker_shared.closed.load(Ordering::Acquire) =>
                            {
                                engine.append(batch).map(Reply::Receipt)
                            }
                            Operation::Append(_) => Err(StorageError::Closed),
                            Operation::Read(after, events, bytes) => {
                                engine.read(after, events, bytes).map(Reply::Batch)
                            }
                            Operation::Select(from, to, max_files) => engine
                                .select_files(from, to, max_files, &command.context)
                                .map(Reply::Selection),
                            Operation::Flush => engine.flush().map(|()| Reply::Done),
                            #[cfg(test)]
                            Operation::Pause(started, release) => {
                                let _ = started.send(());
                                release
                                    .recv_timeout(Duration::from_secs(2))
                                    .map(|()| Reply::Done)
                                    .map_err(|_| StorageError::Timeout)
                            }
                            #[cfg(test)]
                            Operation::SelectPause(started, release) => {
                                let _ = started.send(());
                                release
                                    .recv_timeout(Duration::from_secs(2))
                                    .map_err(|_| StorageError::Timeout)
                                    .and_then(|()| check_context(Some(&command.context)))
                                    .map(|()| Reply::Selection(FileSelection::default()))
                            }
                        }
                    };
                    worker_shared.check_deadline();
                    if let Ok(mut deadline) = worker_shared.active_deadline.lock() {
                        *deadline = None;
                    }
                    if matches!(&result, Err(StorageError::Io(_) | StorageError::Corrupt(_))) {
                        worker_shared.failed.store(true, Ordering::Release);
                        worker_shared.closed.store(true, Ordering::Release);
                        worker_shared.failures.fetch_add(1, Ordering::Relaxed);
                    }
                    worker_shared.publish(engine.metrics);
                    let _ = command.reply.send(result);
                }
            })
            .map_err(StorageError::Io)?;
        match timeout_at(Instant::now() + config.operation_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                sender,
                shared,
                commands: Arc::new(Semaphore::new(config.command_capacity)),
                config,
                worker: Mutex::new(Some(worker)),
            }),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(StorageError::Closed),
            Err(_) => {
                shared.stopping.store(true, Ordering::Release);
                Err(StorageError::Timeout)
            }
        }
    }
    async fn command(
        &self,
        operation: Operation,
        context: OperationContext,
    ) -> Result<Reply, StorageError> {
        self.shared.check_deadline();
        if self.shared.failed.load(Ordering::Acquire)
            || self.shared.stopping.load(Ordering::Acquire)
        {
            return Err(StorageError::Closed);
        }
        if context.cancellation.is_cancelled() {
            return Err(StorageError::Cancelled);
        }
        if Instant::now() >= context.deadline {
            self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
            return Err(StorageError::Timeout);
        }
        let read_only_selection = operation.read_only_selection();
        let permit = Arc::new(self.commands.clone().try_acquire_owned().map_err(|_| {
            self.shared.full.fetch_add(1, Ordering::Relaxed);
            StorageError::Full
        })?);
        if let Operation::Append(ref batch) = operation {
            validate_batch(batch, &self.config)?;
        }
        let (reply, response) = oneshot::channel();
        let abandoned = Arc::new(AtomicBool::new(false));
        let context = OperationContext {
            deadline: context.deadline,
            cancellation: context.cancellation.child_token(),
        };
        let _guard = CancelOnDrop(abandoned.clone(), context.cancellation.clone());
        self.sender
            .try_send(Command {
                operation,
                context: context.clone(),
                abandoned,
                reply,
                _permit: Some(permit.clone()),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => StorageError::Full,
                mpsc::error::TrySendError::Closed(_) => StorageError::Closed,
            })?;
        let result = tokio::select! { result=timeout_at(context.deadline,response)=>match result{Ok(Ok(value))=>value,Ok(Err(_))=>Err(StorageError::Closed),Err(_)=>{if !read_only_selection { self.shared.failed.store(true,Ordering::Release);self.close(); } Err(StorageError::Timeout)}}, ()=context.cancellation.cancelled()=>Err(StorageError::Cancelled) };
        if matches!(result, Err(StorageError::Timeout)) {
            self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(result, Err(StorageError::Full)) {
            self.shared.full.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    pub async fn append(
        &self,
        batch: Vec<StoredEvent>,
        context: OperationContext,
    ) -> Result<StoreReceipt, StorageError> {
        match self.command(Operation::Append(batch), context).await? {
            Reply::Receipt(r) => Ok(r),
            _ => Err(StorageError::Closed),
        }
    }
    /// Returns a bounded sequence-ordered page; `after_sequence` is exclusive.
    pub async fn read_batch(
        &self,
        after_sequence: u64,
        max_events: usize,
        max_bytes: usize,
        context: OperationContext,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        if max_events == 0
            || max_events > self.config.max_batch_events
            || max_bytes == 0
            || max_bytes > self.config.max_batch_bytes
        {
            return Err(StorageError::InvalidBatch);
        }
        match self
            .command(
                Operation::Read(after_sequence, max_events, max_bytes),
                context,
            )
            .await?
        {
            Reply::Batch(b) => Ok(b),
            _ => Err(StorageError::Closed),
        }
    }
    pub async fn flush(&self, context: OperationContext) -> Result<(), StorageError> {
        match self.command(Operation::Flush, context).await? {
            Reply::Done => Ok(()),
            _ => Err(StorageError::Closed),
        }
    }
    /// Select only committed files; prune UTC hour partitions before opening files.
    /// The upper time bound is exclusive. Exceeding either file bound returns Full.
    pub async fn select_files(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        max_files: usize,
        context: OperationContext,
    ) -> Result<FileSelection, StorageError> {
        if max_files == 0 || from.zip(to).is_some_and(|(from, to)| from >= to) {
            return Err(StorageError::InvalidBatch);
        }
        match self
            .command(
                Operation::Select(from, to, max_files.min(self.config.max_files)),
                context,
            )
            .await?
        {
            Reply::Selection(selection) => Ok(selection),
            _ => Err(StorageError::Closed),
        }
    }
    pub fn metrics(&self) -> StorageMetrics {
        self.shared.check_deadline();
        let mut m = self.shared.snapshot.lock().map(|m| *m).unwrap_or_default();
        m.closed = self.shared.closed.load(Ordering::Acquire);
        m.fail_closed = self.shared.failed.load(Ordering::Acquire);
        m.command_depth = self.config.command_capacity - self.sender.capacity();
        m.command_capacity = self.config.command_capacity;
        m.operations_in_flight = self.config.command_capacity - self.commands.available_permits();
        m.operation_capacity = self.config.command_capacity;
        m.timeouts = self.shared.timeouts.load(Ordering::Relaxed);
        m.full = self.shared.full.load(Ordering::Relaxed);
        m.failures = self.shared.failures.load(Ordering::Relaxed);
        m
    }
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), StorageError> {
        self.close();
        self.shared.stopping.store(true, Ordering::Release);
        let (reply, _) = oneshot::channel();
        let _ = self.sender.try_send(Command {
            operation: Operation::Flush,
            context: context.clone(),
            abandoned: Arc::new(AtomicBool::new(true)),
            reply,
            _permit: None,
        });
        loop {
            let finished = self
                .worker
                .lock()
                .map_err(|_| StorageError::Closed)?
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished);
            if finished {
                break;
            }
            if context.cancellation.is_cancelled() {
                return Err(StorageError::Cancelled);
            }
            if Instant::now() >= context.deadline {
                self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(StorageError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        if let Some(worker) = self.worker.lock().map_err(|_| StorageError::Closed)?.take() {
            worker.join().map_err(|_| StorageError::Closed)?;
        }
        Ok(())
    }
}
impl EventStore for ParquetStore {
    fn append(
        &self,
        batch: Vec<StoredEvent>,
        context: OperationContext,
    ) -> StoreFuture<'_, StoreReceipt> {
        Box::pin(ParquetStore::append(self, batch, context))
    }
    fn query(
        &self,
        _query: EventQuery,
        _context: OperationContext,
    ) -> StoreFuture<'_, EventStream> {
        Box::pin(async { Err(StorageError::QueryUnavailable) })
    }
    fn metrics(&self) -> StorageMetrics {
        ParquetStore::metrics(self)
    }
    fn close(&self) {
        ParquetStore::close(self);
    }
}
struct Counter {
    bytes: usize,
    limit: usize,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("capacity"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn event_bytes(event: &SignalEvent, limit: usize) -> Result<usize, StorageError> {
    let mut count = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut count, event).map_err(|_| StorageError::InvalidBatch)?;
    Ok(count.bytes)
}
pub(crate) fn validate_batch(
    batch: &[StoredEvent],
    config: &StorageConfig,
) -> Result<(), StorageError> {
    if batch.is_empty() || batch.len() > config.max_batch_events {
        return Err(StorageError::InvalidBatch);
    }
    let mut previous = 0;
    let mut bytes = 0;
    for row in batch {
        if row.sequence <= previous {
            return Err(StorageError::InvalidBatch);
        }
        previous = row.sequence;
        row.event
            .validate()
            .map_err(|_| StorageError::InvalidBatch)?;
        bytes += event_bytes(&row.event, config.max_event_bytes)?;
        if bytes > config.max_batch_bytes {
            return Err(StorageError::InvalidBatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    fn context() -> OperationContext {
        OperationContext::new(Duration::from_secs(2))
    }
    fn row() -> TestResult<StoredEvent> {
        let input: signal_event::IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"test"},"message":"queued"}"#,
        )?;
        Ok(StoredEvent {
            sequence: 1,
            event: input.normalize(chrono::Utc::now())?,
        })
    }
    async fn pause(
        store: &ParquetStore,
    ) -> TestResult<(
        std::sync::mpsc::SyncSender<()>,
        oneshot::Receiver<Result<Reply, StorageError>>,
    )> {
        let (started, ready) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let (reply, response) = oneshot::channel();
        store
            .sender
            .try_send(Command {
                operation: Operation::Pause(started, wait),
                context: context(),
                abandoned: Arc::new(AtomicBool::new(false)),
                reply,
                _permit: None,
            })
            .map_err(|_| StorageError::Closed)?;
        tokio::time::timeout(Duration::from_secs(1), ready).await??;
        Ok((release, response))
    }
    async fn queued(store: &ParquetStore) -> TestResult {
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.metrics().command_depth != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
    #[tokio::test]
    async fn bounded_queue_and_cancelled_queued_append_never_mutate() -> TestResult {
        for abort in [false, true] {
            let temp = tempfile::TempDir::new()?;
            let store = Arc::new(
                ParquetStore::open(
                    StorageConfig {
                        directory: temp.path().join("events"),
                        command_capacity: 1,
                        ..Default::default()
                    },
                    Uuid::new_v4(),
                )
                .await?,
            );
            let (release, response) = pause(&store).await?;
            let task_store = store.clone();
            let row = row()?;
            let ctx = context();
            let cancellation = ctx.cancellation.clone();
            let pending = tokio::spawn(async move { task_store.append(vec![row], ctx).await });
            queued(&store).await?;
            assert!(matches!(
                store.read_batch(0, 1, 4096, context()).await,
                Err(StorageError::Full)
            ));
            assert_eq!(store.metrics().operations_in_flight, 1);
            if abort {
                pending.abort();
                assert!(pending.await.is_err());
            } else {
                cancellation.cancel();
                assert!(matches!(pending.await?, Err(StorageError::Cancelled)));
            }
            release.send(())?;
            let _ = response.await?;
            tokio::time::timeout(Duration::from_secs(1), async {
                while store.metrics().command_depth != 0
                    || store.metrics().operations_in_flight != 0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            assert!(store.read_batch(0, 1, 4096, context()).await?.is_empty());
            assert_eq!(store.metrics().high_water, 0);
            store.shutdown(context()).await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn unpolled_read_and_worker_completion_hold_bounded_permits() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store = ParquetStore::open(
            StorageConfig {
                directory: temp.path().join("events"),
                command_capacity: 1,
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await?;
        store.append(vec![row()?], context()).await?;
        let (release, response) = pause(&store).await?;
        let mut read = Box::pin(store.read_batch(0, 1, 4096, context()));
        std::future::poll_fn(|ctx| {
            assert!(Future::poll(read.as_mut(), ctx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        queued(&store).await?;
        release.send(())?;
        let _ = response.await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.metrics().command_depth != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(store.metrics().operations_in_flight, 1);
        assert!(matches!(
            store.read_batch(0, 1, 4096, context()).await,
            Err(StorageError::Full)
        ));
        drop(read);
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.metrics().operations_in_flight != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(store.metrics().operations_in_flight, 0);
        assert_eq!(store.read_batch(0, 1, 4096, context()).await?.len(), 1);
        store.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn queued_timeout_fails_closed_without_late_publication() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store = Arc::new(
            ParquetStore::open(
                StorageConfig {
                    directory: temp.path().join("events"),
                    ..Default::default()
                },
                Uuid::new_v4(),
            )
            .await?,
        );
        let (release, response) = pause(&store).await?;
        let task_store = store.clone();
        let row = row()?;
        let pending = tokio::spawn(async move {
            task_store
                .append(vec![row], OperationContext::new(Duration::from_millis(50)))
                .await
        });
        queued(&store).await?;
        assert!(matches!(pending.await?, Err(StorageError::Timeout)));
        assert!(store.metrics().fail_closed);
        release.send(())?;
        let _ = response.await?;
        let stream = Uuid::parse_str(&std::fs::read_to_string(
            temp.path().join("events/stream-id"),
        )?)?;
        store.shutdown(context()).await?;
        let reopened = ParquetStore::open(
            StorageConfig {
                directory: temp.path().join("events"),
                ..Default::default()
            },
            stream,
        )
        .await?;
        assert_eq!(reopened.metrics().high_water, 0);
        reopened.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn queued_selection_timeout_does_not_close_persistence() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store = Arc::new(
            ParquetStore::open(
                StorageConfig {
                    directory: temp.path().join("events"),
                    command_capacity: 1,
                    ..Default::default()
                },
                Uuid::new_v4(),
            )
            .await?,
        );
        let (release, response) = pause(&store).await?;
        let task_store = store.clone();
        let pending = tokio::spawn(async move {
            task_store
                .select_files(
                    None,
                    None,
                    1,
                    OperationContext::new(Duration::from_millis(200)),
                )
                .await
        });
        queued(&store).await?;
        assert!(matches!(pending.await?, Err(StorageError::Timeout)));
        assert!(!store.metrics().closed && !store.metrics().fail_closed);
        assert_eq!(store.metrics().operations_in_flight, 1);
        release.send(())?;
        let _ = response.await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.metrics().operations_in_flight != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        store.append(vec![row()?], context()).await?;
        assert_eq!(store.metrics().high_water, 1);
        store.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn active_selection_timeout_and_abort_retain_permit_until_worker_finishes() -> TestResult
    {
        for abort in [false, true] {
            let temp = tempfile::TempDir::new()?;
            let store = Arc::new(
                ParquetStore::open(
                    StorageConfig {
                        directory: temp.path().join("events"),
                        command_capacity: 1,
                        ..Default::default()
                    },
                    Uuid::new_v4(),
                )
                .await?,
            );
            let (started, ready) = oneshot::channel();
            let (release, wait) = std::sync::mpsc::sync_channel(1);
            let task_store = store.clone();
            let pending = tokio::spawn(async move {
                task_store
                    .command(
                        Operation::SelectPause(started, wait),
                        OperationContext::new(Duration::from_millis(200)),
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), ready).await??;
            if abort {
                pending.abort();
                assert!(pending.await.is_err());
            } else {
                assert!(matches!(pending.await?, Err(StorageError::Timeout)));
            }
            // The paused read represents a kernel read already in progress. Its
            // query caller is gone, but the single tracked worker still owns it.
            assert_eq!(store.metrics().operations_in_flight, 1);
            assert!(!store.metrics().closed && !store.metrics().fail_closed);
            assert!(matches!(
                store.append(vec![row()?], context()).await,
                Err(StorageError::Full)
            ));
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(1), async {
                while store.metrics().operations_in_flight != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            store.append(vec![row()?], context()).await?;
            assert_eq!(store.metrics().high_water, 1);
            assert!(!store.metrics().closed && !store.metrics().fail_closed);
            store.shutdown(context()).await?;
        }
        Ok(())
    }
}

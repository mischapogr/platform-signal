//! Bounded, single-worker durable WAL. See ADR-006 for commit and replay semantics.
mod wal;

use signal_event::SignalEvent;
use signal_protocol::{AdmissionError, AdmissionFuture, EventSink, SinkMetrics};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{Notify, Semaphore, mpsc, oneshot},
    time::{Instant, timeout_at},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Policy {
    #[default]
    RejectNew,
    DropOldest,
    BlockWithTimeout,
}
impl std::str::FromStr for Policy {
    type Err = BufferError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "reject_new" => Ok(Self::RejectNew),
            "drop_oldest" => Ok(Self::DropOldest),
            "block_with_timeout" => Ok(Self::BlockWithTimeout),
            _ => Err(BufferError::Config("admission policy")),
        }
    }
}
#[derive(Clone, Debug)]
pub struct BufferConfig {
    pub directory: PathBuf,
    pub max_events: usize,
    pub max_memory_bytes: usize,
    pub max_record_bytes: usize,
    pub max_wal_bytes: u64,
    pub segment_bytes: u64,
    pub max_segments: usize,
    pub command_capacity: usize,
    pub max_waiters: usize,
    pub policy: Policy,
    pub operation_timeout: Duration,
    pub block_timeout: Duration,
}
impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("data/wal"),
            max_events: 10_000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_record_bytes: 2 * 1024 * 1024,
            max_wal_bytes: 256 * 1024 * 1024,
            segment_bytes: 8 * 1024 * 1024,
            max_segments: 128,
            command_capacity: 64,
            max_waiters: 64,
            policy: Policy::RejectNew,
            operation_timeout: Duration::from_secs(5),
            block_timeout: Duration::from_secs(1),
        }
    }
}
impl BufferConfig {
    pub fn validate(&self) -> Result<(), BufferError> {
        if self.directory.as_os_str().is_empty()
            || self.max_events == 0
            || self.max_memory_bytes == 0
            || self.max_record_bytes == 0
            || self.max_record_bytes > u32::MAX as usize
            || self.max_record_bytes > self.max_memory_bytes
            || self.max_segments == 0
            || self.command_capacity == 0
            || self.command_capacity > Semaphore::MAX_PERMITS
            || self.max_waiters == 0
            || self.max_waiters > Semaphore::MAX_PERMITS
            || self.segment_bytes < self.max_record_bytes as u64 + 40
            || self
                .segment_bytes
                .checked_add(wal::METADATA_RESERVE)
                .is_none_or(|minimum| self.max_wal_bytes < minimum)
        {
            return Err(BufferError::Config(
                "positive capacities and record/segment/WAL bounds",
            ));
        }
        for duration in [self.operation_timeout, self.block_timeout] {
            if duration.is_zero() || duration > Duration::from_secs(3600) {
                return Err(BufferError::Config("operation deadlines"));
            }
        }
        Ok(())
    }
}
/// In-process snapshot, not a persisted or versioned serialization contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct BufferMetrics {
    pub stream_id: uuid::Uuid,
    pub depth: usize,
    pub capacity: usize,
    pub bytes: usize,
    pub byte_capacity: usize,
    pub wal_bytes: u64,
    pub wal_byte_capacity: u64,
    pub wal_segments: usize,
    pub accepted: u64,
    pub rejected: u64,
    pub dropped: u64,
    pub replayed: u64,
    pub corruptions: u64,
    pub truncated_records: u64,
    pub checkpoint: u64,
    pub last_sequence: u64,
    pub command_depth: usize,
    pub command_capacity: usize,
    pub operations_in_flight: usize,
    pub operation_capacity: usize,
    pub waiters: usize,
    pub waiter_capacity: usize,
    pub timeouts: u64,
    pub closed: bool,
}
#[derive(Debug, Error)]
pub enum BufferError {
    #[error("invalid WAL configuration: {0}")]
    Config(&'static str),
    #[error("WAL directory contains unexpected entries")]
    Directory,
    #[error("WAL directory is already locked or lock acquisition failed")]
    Locked,
    #[error("WAL corruption: {0}")]
    Corrupt(&'static str),
    #[error("WAL filesystem operation failed")]
    Io(#[source] std::io::Error),
    #[error("durable queue capacity is full")]
    Full,
    #[error("WAL admission is stopped")]
    Closed,
    #[error("WAL worker is unavailable")]
    Unavailable,
    #[error("WAL operation deadline exceeded; an in-progress commit may have completed")]
    Timeout,
    #[error("WAL acknowledgment exceeds a delivered sequence")]
    InvalidAck,
    #[error("WAL sequence or counter exhausted")]
    Sequence,
    #[error("event cannot be encoded as a valid canonical record")]
    Event,
}
impl BufferError {
    fn fatal(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Corrupt(_) | Self::Sequence)
    }
}
/// Read batches repeat the unacknowledged prefix until explicitly checkpointed.
#[derive(Clone, Debug)]
pub struct SequencedEvent {
    pub sequence: u64,
    pub event: SignalEvent,
}
struct Shared {
    closed: AtomicBool,
    failed: AtomicBool,
    stopping: AtomicBool,
    snapshot: Mutex<BufferMetrics>,
    rejected: AtomicU64,
    timeouts: AtomicU64,
    space: Notify,
    command_space: Notify,
    active_deadline: Mutex<Option<Instant>>,
}
impl Shared {
    fn wake_waiters(&self) {
        self.space.notify_waiters();
        self.command_space.notify_waiters();
    }
    fn check_deadline(&self) {
        let expired = self
            .active_deadline
            .lock()
            .map(|deadline| deadline.is_some_and(|deadline| Instant::now() >= deadline))
            .unwrap_or(true);
        if expired {
            self.failed.store(true, Ordering::Release);
            self.closed.store(true, Ordering::Release);
            self.wake_waiters();
        }
    }
    fn publish(&self, metrics: BufferMetrics) {
        let mut freed = false;
        if let Ok(mut snapshot) = self.snapshot.lock() {
            freed = metrics.depth < snapshot.depth
                || metrics.bytes < snapshot.bytes
                || metrics.wal_bytes < snapshot.wal_bytes
                || metrics.wal_segments < snapshot.wal_segments;
            *snapshot = metrics;
        } else {
            self.failed.store(true, Ordering::Release);
            self.closed.store(true, Ordering::Release);
        }
        if self.closed.load(Ordering::Acquire) {
            self.wake_waiters();
        } else if freed {
            self.space.notify_waiters();
        }
    }
}
enum Operation {
    Append(Vec<u8>),
    Read(usize, usize),
    Ack(u64),
    #[cfg(test)]
    Pause(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>),
}
enum Reply {
    Done,
    Batch(Vec<SequencedEvent>),
    /// The worker checked durable capacity without starting an append.
    Full,
}
struct Command {
    operation: Operation,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    reply: oneshot::Sender<Result<Reply, BufferError>>,
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct CommandPermit<'a> {
    permit: Option<tokio::sync::SemaphorePermit<'a>>,
    shared: &'a Shared,
    notify_on_release: bool,
}
impl Drop for CommandPermit<'_> {
    fn drop(&mut self) {
        self.permit.take();
        if self.notify_on_release {
            self.shared.command_space.notify_waiters();
        }
    }
}
struct WorkerExit(Arc<Shared>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        if !self.0.stopping.load(Ordering::Acquire) {
            self.0.failed.store(true, Ordering::Release);
        }
        self.0.wake_waiters();
    }
}
struct AdmissionAttempt<'a> {
    shared: &'a Shared,
    accepted: bool,
}
impl Drop for AdmissionAttempt<'_> {
    fn drop(&mut self) {
        if !self.accepted {
            self.shared.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// Dropping the final handle closes the bounded channel. Explicit shutdown provides
/// a deadline and joins the worker; dropping never blocks an async executor.
pub struct DurableBuffer {
    sender: mpsc::Sender<Command>,
    shared: Arc<Shared>,
    config: BufferConfig,
    waiters: Semaphore,
    commands: Semaphore,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl DurableBuffer {
    pub async fn open(config: BufferConfig) -> Result<Self, BufferError> {
        config.validate()?;
        let shared = Arc::new(Shared {
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            snapshot: Mutex::new(BufferMetrics::default()),
            rejected: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            space: Notify::new(),
            command_space: Notify::new(),
            active_deadline: Mutex::new(None),
        });
        let (sender, mut receiver) = mpsc::channel::<Command>(config.command_capacity);
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker_shared = shared.clone();
        let worker_config = config.clone();
        let worker = thread::Builder::new()
            .name("signal-wal".into())
            .spawn(move || {
                let _exit = WorkerExit(worker_shared.clone());
                let mut engine = match wal::Engine::open(worker_config) {
                    Ok(engine) => engine,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                worker_shared.publish(engine.metrics);
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                while let Some(command) = receiver.blocking_recv() {
                    worker_shared.command_space.notify_waiters();
                    if worker_shared.stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let result = if worker_shared.failed.load(Ordering::Acquire) {
                        Err(BufferError::Unavailable)
                    } else if command.cancelled.load(Ordering::Acquire)
                        || command.reply.is_closed()
                        || Instant::now() >= command.deadline
                    {
                        Err(BufferError::Timeout)
                    } else {
                        if let Ok(mut deadline) = worker_shared.active_deadline.lock() {
                            *deadline = Some(command.deadline);
                        }
                        match command.operation {
                            Operation::Append(payload)
                                if !worker_shared.closed.load(Ordering::Acquire) =>
                            {
                                match engine.append(payload) {
                                    Ok(()) => Ok(Reply::Done),
                                    Err(BufferError::Full) => Ok(Reply::Full),
                                    Err(error) => Err(error),
                                }
                            }
                            Operation::Append(_) => Err(BufferError::Closed),
                            Operation::Read(events, bytes) => {
                                engine.read(events, bytes).map(Reply::Batch)
                            }
                            Operation::Ack(seq) => engine.ack(seq).map(|()| Reply::Done),
                            #[cfg(test)]
                            Operation::Pause(started, release) => {
                                let _ = started.send(());
                                release
                                    .recv_timeout(Duration::from_secs(2))
                                    .map(|()| Reply::Done)
                                    .map_err(|_| BufferError::Timeout)
                            }
                        }
                    };
                    worker_shared.check_deadline();
                    if let Ok(mut deadline) = worker_shared.active_deadline.lock() {
                        *deadline = None;
                    }
                    if let Err(error) = &result
                        && error.fatal()
                    {
                        worker_shared.failed.store(true, Ordering::Release);
                        worker_shared.closed.store(true, Ordering::Release);
                        if matches!(error, BufferError::Corrupt(_)) {
                            engine.metrics.corruptions += 1;
                        }
                    }
                    worker_shared.publish(engine.metrics);
                    let _ = command.reply.send(result);
                }
            })
            .map_err(BufferError::Io)?;
        match timeout_at(Instant::now() + config.operation_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                sender,
                shared,
                waiters: Semaphore::new(config.max_waiters),
                commands: Semaphore::new(config.command_capacity),
                config,
                worker: Mutex::new(Some(worker)),
            }),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(BufferError::Unavailable),
            Err(_) => {
                shared.stopping.store(true, Ordering::Release);
                Err(BufferError::Timeout)
            }
        }
    }
    async fn command(&self, operation: Operation, deadline: Instant) -> Result<Reply, BufferError> {
        self.shared.check_deadline();
        if self.shared.stopping.load(Ordering::Acquire)
            || self.shared.failed.load(Ordering::Acquire)
        {
            return Err(BufferError::Unavailable);
        }
        // Bound outstanding replies as well as queued commands. A client that
        // stops polling cannot accumulate an unlimited number of decoded batches.
        let mut permit = CommandPermit {
            permit: Some(self.commands.try_acquire().map_err(|_| BufferError::Full)?),
            shared: &self.shared,
            notify_on_release: true,
        };
        let (reply, response) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let _guard = CancelOnDrop(cancelled.clone());
        let command = Command {
            operation,
            deadline,
            cancelled,
            reply,
        };
        if let Err(error) = self.sender.try_send(command) {
            // A failed enqueue never consumed command capacity. Waking its
            // own waiter here would spin while a canceled command still fills
            // the channel. Actual dequeue or outstanding reply release wakes it.
            permit.notify_on_release = false;
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => BufferError::Full,
                mpsc::error::TrySendError::Closed(_) => BufferError::Unavailable,
            });
        }
        match timeout_at(deadline, response).await {
            Ok(Ok(result)) => {
                if matches!(result, Err(BufferError::Timeout)) {
                    self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                result
            }
            Ok(Err(_)) => Err(BufferError::Unavailable),
            Err(_) => {
                self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                // A stalled worker cannot prove a commit outcome. Fail closed;
                // the one in-progress filesystem operation may still finish.
                self.shared.failed.store(true, Ordering::Release);
                self.close();
                Err(BufferError::Timeout)
            }
        }
    }
    pub fn snapshot(&self) -> BufferMetrics {
        self.shared.check_deadline();
        let mut metrics = self
            .shared
            .snapshot
            .lock()
            .map(|snapshot| *snapshot)
            .unwrap_or_default();
        metrics.closed = self.shared.closed.load(Ordering::Acquire)
            || self.shared.failed.load(Ordering::Acquire);
        metrics.rejected = self.shared.rejected.load(Ordering::Relaxed);
        metrics.timeouts = self.shared.timeouts.load(Ordering::Relaxed);
        metrics.command_depth = self.config.command_capacity - self.sender.capacity();
        metrics.command_capacity = self.config.command_capacity;
        metrics.operations_in_flight =
            self.config.command_capacity - self.commands.available_permits();
        metrics.operation_capacity = self.config.command_capacity;
        metrics.waiters = self.config.max_waiters - self.waiters.available_permits();
        metrics.waiter_capacity = self.config.max_waiters;
        metrics
    }
    /// Bounds include encoded payload bytes; a too-small byte limit can return an empty batch.
    pub async fn read_batch(
        &self,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<Vec<SequencedEvent>, BufferError> {
        match self
            .command(
                Operation::Read(max_events, max_bytes),
                Instant::now() + self.config.operation_timeout,
            )
            .await?
        {
            Reply::Batch(events) => Ok(events),
            Reply::Done | Reply::Full => Err(BufferError::Unavailable),
        }
    }
    /// Call only after persistence of every required consumer through this sequence.
    pub async fn ack(&self, sequence: u64) -> Result<(), BufferError> {
        match self
            .command(
                Operation::Ack(sequence),
                Instant::now() + self.config.operation_timeout,
            )
            .await?
        {
            Reply::Done => Ok(()),
            Reply::Batch(_) | Reply::Full => Err(BufferError::Unavailable),
        }
    }
    pub async fn shutdown(&self) -> Result<(), BufferError> {
        self.close();
        self.shared.stopping.store(true, Ordering::Release);
        // A bounded control wake avoids waiting forever in blocking_recv on an idle worker.
        let (reply, _response) = oneshot::channel();
        let _ = self.sender.try_send(Command {
            operation: Operation::Ack(0),
            deadline: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(true)),
            reply,
        });
        let deadline = Instant::now() + self.config.operation_timeout;
        loop {
            let finished = self
                .worker
                .lock()
                .map_err(|_| BufferError::Unavailable)?
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished);
            if finished {
                break;
            }
            if Instant::now() >= deadline {
                self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(BufferError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let handle = self
            .worker
            .lock()
            .map_err(|_| BufferError::Unavailable)?
            .take();
        if let Some(handle) = handle {
            handle.join().map_err(|_| BufferError::Unavailable)?;
        }
        Ok(())
    }
}
struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("record capacity"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl EventSink for DurableBuffer {
    fn admit(&self, event: SignalEvent) -> AdmissionFuture<'_> {
        Box::pin(async move {
            let mut attempt = AdmissionAttempt {
                shared: &self.shared,
                accepted: false,
            };
            if self.shared.closed.load(Ordering::Acquire) {
                return Err(AdmissionError::Closed);
            }
            let _permit = self
                .waiters
                .try_acquire()
                .map_err(|_| AdmissionError::Full)?;
            event.validate().map_err(|_| AdmissionError::Unavailable)?;
            let mut encoded = LimitedBytes {
                bytes: Vec::new(),
                limit: self.config.max_record_bytes,
            };
            serde_json::to_writer(&mut encoded, &event).map_err(|_| AdmissionError::Full)?;
            let duration = if self.config.policy == Policy::BlockWithTimeout {
                self.config.operation_timeout.min(self.config.block_timeout)
            } else {
                self.config.operation_timeout
            };
            let deadline = Instant::now() + duration;
            loop {
                if self.shared.closed.load(Ordering::Acquire) {
                    return Err(AdmissionError::Closed);
                }
                if self.config.policy == Policy::BlockWithTimeout && Instant::now() >= deadline {
                    self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                    return Err(AdmissionError::Full);
                }
                let notified = self.shared.space.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let command_notified = self.shared.command_space.notified();
                tokio::pin!(command_notified);
                command_notified.as_mut().enable();
                // Command-owned bytes are independently bounded by channel capacity and record size.
                match self
                    .command(Operation::Append(encoded.bytes.clone()), deadline)
                    .await
                {
                    Ok(Reply::Done) => {
                        attempt.accepted = true;
                        return Ok(());
                    }
                    Ok(Reply::Full) if self.config.policy == Policy::BlockWithTimeout => {
                        if timeout_at(deadline, &mut notified).await.is_err() {
                            self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                            return Err(AdmissionError::Full);
                        }
                    }
                    Err(BufferError::Full) if self.config.policy == Policy::BlockWithTimeout => {
                        if timeout_at(deadline, &mut command_notified).await.is_err() {
                            self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
                            return Err(AdmissionError::Full);
                        }
                    }
                    Ok(Reply::Full) | Err(BufferError::Full) => return Err(AdmissionError::Full),
                    Err(BufferError::Closed) => return Err(AdmissionError::Closed),
                    Err(BufferError::Timeout) if self.config.policy == Policy::BlockWithTimeout => {
                        return Err(AdmissionError::Full);
                    }
                    _ => return Err(AdmissionError::Unavailable),
                }
            }
        })
    }
    fn metrics(&self) -> SinkMetrics {
        let metrics = self.snapshot();
        SinkMetrics {
            depth: metrics.depth,
            capacity: metrics.capacity,
            bytes: metrics.bytes,
            byte_capacity: metrics.byte_capacity,
            accepted: metrics.accepted,
            rejected: metrics.rejected,
            dropped: metrics.dropped,
            closed: metrics.closed,
            wal_bytes: metrics.wal_bytes,
            wal_byte_capacity: metrics.wal_byte_capacity,
            wal_segments: metrics.wal_segments,
            replayed: metrics.replayed,
            corruptions: metrics.corruptions,
            truncated_records: metrics.truncated_records,
            command_depth: metrics.command_depth,
            command_capacity: metrics.command_capacity,
            operations_in_flight: metrics.operations_in_flight,
            operation_capacity: metrics.operation_capacity,
            waiters: metrics.waiters,
            waiter_capacity: metrics.waiter_capacity,
            timeouts: metrics.timeouts,
            ..Default::default()
        }
    }
    fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.wake_waiters();
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use std::error::Error;
    type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
    fn event() -> Result<SignalEvent> {
        let input: signal_event::IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"worker-test"},"message":"queued"}"#,
        )?;
        Ok(input.normalize(chrono::Utc::now())?)
    }
    async fn pause(
        buffer: &DurableBuffer,
    ) -> Result<(
        std::sync::mpsc::SyncSender<()>,
        oneshot::Receiver<std::result::Result<Reply, BufferError>>,
    )> {
        let (started, ready) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let (reply, response) = oneshot::channel();
        buffer
            .sender
            .try_send(Command {
                operation: Operation::Pause(started, wait),
                deadline: Instant::now() + buffer.config.operation_timeout,
                cancelled: Arc::new(AtomicBool::new(false)),
                reply,
            })
            .map_err(|_| BufferError::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(1), ready).await??;
        Ok((release, response))
    }
    async fn queued(buffer: &DurableBuffer) -> Result {
        tokio::time::timeout(Duration::from_secs(1), async {
            while buffer.snapshot().command_depth != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
    #[tokio::test]
    async fn full_queue_timeout_never_requeues_its_own_rejection_or_closes_worker() -> Result {
        let temp = tempfile::TempDir::new()?;
        let buffer = DurableBuffer::open(BufferConfig {
            directory: temp.path().join("wal"),
            max_events: 1,
            policy: Policy::BlockWithTimeout,
            block_timeout: Duration::from_millis(500),
            ..Default::default()
        })
        .await?;
        buffer.admit(event()?).await?;
        let mut pending = buffer.admit(event()?);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        // FIFO guarantees the earlier append rejection was published before
        // Pause starts. The worker cannot answer a redundant retry now.
        let (release, response) = pause(&buffer).await?;
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        std::thread::sleep(Duration::from_millis(550));
        assert_eq!(pending.await, Err(AdmissionError::Full));
        let remained_open = !buffer.snapshot().closed;
        let redundant_commands = buffer.snapshot().command_depth;
        release.send(())?;
        let _ = response.await?;
        buffer.shutdown().await?;
        assert_eq!(
            redundant_commands, 0,
            "Full must wait for actual capacity changes"
        );
        assert!(
            remained_open,
            "capacity wait timeout must preserve the healthy worker"
        );
        Ok(())
    }
    #[tokio::test]
    async fn command_capacity_waiter_wakes_on_permit_release_and_close() -> Result {
        for close in [false, true] {
            let temp = tempfile::TempDir::new()?;
            let buffer = DurableBuffer::open(BufferConfig {
                directory: temp.path().join("wal"),
                command_capacity: 1,
                policy: Policy::BlockWithTimeout,
                block_timeout: Duration::from_millis(500),
                ..Default::default()
            })
            .await?;
            let (release, response) = pause(&buffer).await?;
            let mut read = Box::pin(buffer.read_batch(1, 4096));
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(read.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            queued(&buffer).await?;
            release.send(())?;
            let _ = response.await?;
            tokio::time::timeout(Duration::from_secs(1), async {
                while buffer.snapshot().command_depth != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            // The empty read's buffered response owns the only operation
            // permit, while durable event capacity is completely available.
            assert_eq!(buffer.snapshot().operations_in_flight, 1);
            assert_eq!(buffer.snapshot().depth, 0);
            let mut pending = buffer.admit(event()?);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            if close {
                buffer.close();
                assert_eq!(pending.await, Err(AdmissionError::Closed));
                drop(read);
            } else {
                drop(read);
                pending.await?;
                assert_eq!(buffer.snapshot().accepted, 1);
                assert!(!buffer.snapshot().closed);
            }
            buffer.shutdown().await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn canceled_queued_command_waits_for_actual_dequeue_without_self_spin() -> Result {
        let temp = tempfile::TempDir::new()?;
        let buffer = Arc::new(
            DurableBuffer::open(BufferConfig {
                directory: temp.path().join("wal"),
                command_capacity: 1,
                policy: Policy::BlockWithTimeout,
                block_timeout: Duration::from_millis(500),
                ..Default::default()
            })
            .await?,
        );
        let (release, response) = pause(&buffer).await?;
        let caller = buffer.clone();
        let first = event()?;
        let canceled = tokio::spawn(async move { caller.admit(first).await });
        queued(&buffer).await?;
        canceled.abort();
        assert!(canceled.await.is_err());
        assert_eq!(buffer.snapshot().command_depth, 1);
        assert_eq!(buffer.snapshot().operations_in_flight, 0);
        let mut pending = buffer.admit(event()?);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        release.send(())?;
        let _ = response.await?;
        pending.await?;
        assert_eq!(buffer.snapshot().accepted, 1);
        assert_eq!(buffer.read_batch(1, 4096).await?.len(), 1);
        assert!(!buffer.snapshot().closed);
        buffer.shutdown().await?;
        Ok(())
    }
    #[tokio::test]
    async fn queued_client_abort_never_starts_append_and_command_channel_is_bounded() -> Result {
        let temp = tempfile::TempDir::new()?;
        let buffer = Arc::new(
            DurableBuffer::open(BufferConfig {
                directory: temp.path().join("wal"),
                command_capacity: 1,
                ..Default::default()
            })
            .await?,
        );
        let (release, response) = pause(&buffer).await?;
        let task_buffer = buffer.clone();
        let event = event()?;
        let pending = tokio::spawn(async move { task_buffer.admit(event).await });
        queued(&buffer).await?;
        assert_eq!(
            buffer.admit(self::event()?).await,
            Err(AdmissionError::Full)
        );
        assert_eq!(
            buffer.snapshot().command_depth,
            buffer.snapshot().command_capacity
        );
        pending.abort();
        assert!(pending.await.is_err());
        release.send(())?;
        let _ = response.await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while buffer.snapshot().command_depth != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(buffer.read_batch(1, 4096).await?.is_empty());
        assert_eq!(buffer.snapshot().accepted, 0);
        assert_eq!(buffer.snapshot().rejected, 2);
        buffer.shutdown().await?;
        Ok(())
    }
    #[tokio::test]
    async fn queued_deadline_and_close_prevent_late_append() -> Result {
        for expire in [false, true] {
            let temp = tempfile::TempDir::new()?;
            let buffer = Arc::new(
                DurableBuffer::open(BufferConfig {
                    directory: temp.path().join("wal"),
                    operation_timeout: Duration::from_millis(500),
                    ..Default::default()
                })
                .await?,
            );
            let (release, response) = pause(&buffer).await?;
            let task_buffer = buffer.clone();
            let event = event()?;
            let task = tokio::spawn(async move { task_buffer.admit(event).await });
            queued(&buffer).await?;
            if expire {
                assert_eq!(task.await?, Err(AdmissionError::Unavailable));
                assert!(buffer.metrics().closed);
                assert_eq!(buffer.snapshot().timeouts, 1);
                release.send(())?;
                let _ = response.await?;
            } else {
                buffer.close();
                release.send(())?;
                let _ = response.await?;
                assert_eq!(task.await?, Err(AdmissionError::Closed));
            }
            buffer.shutdown().await?;
            let replay = DurableBuffer::open(BufferConfig {
                directory: temp.path().join("wal"),
                ..Default::default()
            })
            .await?;
            assert_eq!(replay.snapshot().depth, 0);
            replay.shutdown().await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn completed_unpolled_read_replies_still_hold_bounded_operation_permits() -> Result {
        let temp = tempfile::TempDir::new()?;
        let buffer = DurableBuffer::open(BufferConfig {
            directory: temp.path().join("wal"),
            command_capacity: 1,
            ..Default::default()
        })
        .await?;
        buffer.admit(event()?).await?;
        let (release, response) = pause(&buffer).await?;
        let mut read = Box::pin(buffer.read_batch(1, 4096));
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(read.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        queued(&buffer).await?;
        release.send(())?;
        let _ = response.await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while buffer.snapshot().command_depth != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(buffer.snapshot().operations_in_flight, 1);
        assert!(matches!(
            buffer.read_batch(1, 4096).await,
            Err(BufferError::Full)
        ));
        drop(read);
        assert_eq!(buffer.snapshot().operations_in_flight, 0);
        assert_eq!(buffer.read_batch(1, 4096).await?.len(), 1);
        buffer.shutdown().await?;
        Ok(())
    }
    #[tokio::test]
    async fn active_deadline_survives_caller_abort_and_shutdown_wait_is_bounded() -> Result {
        let temp = tempfile::TempDir::new()?;
        let buffer = DurableBuffer::open(BufferConfig {
            directory: temp.path().join("wal"),
            operation_timeout: Duration::from_millis(500),
            ..Default::default()
        })
        .await?;
        let (release, response) = pause(&buffer).await?;
        drop(response);
        tokio::time::sleep(Duration::from_millis(550)).await;
        assert!(buffer.metrics().closed);
        assert!(matches!(buffer.shutdown().await, Err(BufferError::Timeout)));
        release.send(())?;
        buffer.shutdown().await?;
        let replay = DurableBuffer::open(BufferConfig {
            directory: temp.path().join("wal"),
            ..Default::default()
        })
        .await?;
        assert_eq!(replay.snapshot().depth, 0);
        replay.shutdown().await?;
        Ok(())
    }
}

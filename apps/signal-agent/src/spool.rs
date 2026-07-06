//! Bounded, single-owner durable agent spool.
//!
//! The directory is exclusively locked. Each `record-<20 digit sequence>` is a
//! 12-byte header (u32 JSON length, payload CRC32, header CRC32) followed by one
//! versioned JSON record. Only an incomplete final record may be discarded on
//! recovery; complete corrupt headers/payloads and sequence gaps fail closed.
//! `state` uses the same framing and is atomically replaced and directory-synced
//! before acknowledged record files are removed. It preserves source cursors
//! after reclamation. A crash may replay events, but their canonical IDs survive.
//!
//! Disk limits charge logical file bytes and a fixed 16 KiB metadata reserve;
//! record/index counts independently bound filesystem and allocator overhead.
//! All disk work runs on one ordinary thread. A timed out or dropped operation
//! closes admission, while its permits remain held through physical completion.
use crate::contracts::SourceCheckpoint;
use serde::{Deserialize, Serialize};
use signal_event::SignalEvent;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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

pub const FRAME_BYTES: usize = 12;
pub const METADATA_RESERVE: u64 = 16 * 1024;
const STATE_LIMIT: usize = METADATA_RESERVE as usize / 2 - FRAME_BYTES;
const INDEX_BYTES: usize = 256;
const CHECKPOINT_BYTES: usize = 512;

#[derive(Clone, Debug)]
pub struct SpoolConfig {
    pub directory: PathBuf,
    pub max_disk_bytes: u64,
    pub max_records: usize,
    pub max_event_bytes: usize,
    pub max_batch_events: usize,
    pub max_batch_bytes: usize,
    pub max_index_bytes: usize,
    pub command_capacity: usize,
    pub operation_capacity: usize,
    pub operation_timeout: Duration,
}
impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            directory: "data/agent-spool".into(),
            max_disk_bytes: 64 * 1024 * 1024,
            max_records: 10_000,
            max_event_bytes: 64 * 1024,
            max_batch_events: 100,
            max_batch_bytes: 1024 * 1024,
            max_index_bytes: 10_000 * INDEX_BYTES,
            command_capacity: 8,
            operation_capacity: 8,
            operation_timeout: Duration::from_secs(5),
        }
    }
}
impl SpoolConfig {
    pub fn validate(&self) -> Result<(), SpoolError> {
        if self.directory.as_os_str().is_empty()
            || self.directory.as_os_str().as_encoded_bytes().len() > 4096
            || self.directory.components().take(129).count() > 128
            || self.max_disk_bytes <= METADATA_RESERVE + FRAME_BYTES as u64
            || self.max_disk_bytes > 64 * 1024 * 1024 * 1024
            || self.max_records == 0
            || self.max_records > 1_000_000
            || self.max_event_bytes == 0
            || self.max_event_bytes > 1024 * 1024
            || self.max_disk_bytes
                < METADATA_RESERVE
                    + self.max_event_bytes as u64
                    + CHECKPOINT_BYTES as u64
                    + FRAME_BYTES as u64
            || self.max_batch_events == 0
            || self.max_batch_events > 10_000
            || self.max_batch_bytes < self.max_event_bytes
            || self.max_batch_bytes > 16 * 1024 * 1024
            || self.max_index_bytes < INDEX_BYTES
            || self.max_index_bytes > 256 * 1024 * 1024
            || self.command_capacity == 0
            || self.command_capacity > 1024
            || self.operation_capacity == 0
            || self.operation_capacity > 1024
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(300)
        {
            return Err(SpoolError::Invalid("spool limits"));
        }
        Ok(())
    }
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpoolError {
    #[error("invalid spool configuration or input: {0}")]
    Invalid(&'static str),
    #[error("spool corruption: {0}")]
    Corrupt(&'static str),
    #[error("spool I/O failed")]
    Io,
    #[error("spool quota exceeded")]
    Quota,
    #[error("spool operation capacity exhausted")]
    Full,
    #[error("spool is closed")]
    Closed,
    #[error("spool operation timed out")]
    Timeout,
    #[error("spool operation cancelled")]
    Cancelled,
    #[error("spool directory is already locked")]
    Locked,
}
fn io(_: std::io::Error) -> SpoolError {
    SpoolError::Io
}
#[derive(Clone, Debug)]
pub struct SpoolRecord {
    pub sequence: u64,
    pub event: SignalEvent,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct SpoolMetrics {
    pub command_depth: usize,
    pub command_capacity: usize,
    pub operations_in_flight: usize,
    pub operation_capacity: usize,
    pub disk_bytes: u64,
    pub disk_capacity: u64,
    pub records: usize,
    pub record_capacity: usize,
    pub index_bytes: usize,
    pub index_capacity: usize,
    pub appended: u64,
    pub acknowledged: u64,
    pub rejections: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub corruptions: u64,
    pub closed: bool,
}
#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    records: AtomicUsize,
    appended: AtomicU64,
    acknowledged: AtomicU64,
    rejections: AtomicU64,
    failures: AtomicU64,
    timeouts: AtomicU64,
    corruptions: AtomicU64,
    closed: AtomicBool,
    stopping: AtomicBool,
}
struct Context {
    deadline: Instant,
    cancellation: CancellationToken,
}
impl Context {
    fn check(&self) -> Result<(), SpoolError> {
        if self.cancellation.is_cancelled() {
            Err(SpoolError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(SpoolError::Timeout)
        } else {
            Ok(())
        }
    }
}
// Cancelling an async waiter never releases a permit held by disk work.
struct WaitGuard {
    cancellation: CancellationToken,
    counters: Arc<Counters>,
    armed: bool,
}
impl Drop for WaitGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
            self.counters.closed.store(true, Ordering::Release);
        }
    }
}
struct Response {
    result: Result<Value, SpoolError>,
    _operation: OwnedSemaphorePermit,
}
enum Value {
    Sequence(u64),
    Batch(Vec<SpoolRecord>),
    Cursors(Vec<SourceCheckpoint>),
    Done,
}
enum Work {
    Append(Box<SignalEvent>, Option<SourceCheckpoint>),
    Read(usize, usize),
    Ack(u64),
    Checkpoint(SourceCheckpoint),
    Cursors,
    #[cfg(test)]
    Hold(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>),
}
struct Request {
    work: Work,
    context: Context,
    response: oneshot::Sender<Response>,
    operation: OwnedSemaphorePermit,
    command: OwnedSemaphorePermit,
}
enum Command {
    Data(Box<Request>),
    Stop(oneshot::Sender<()>),
}
struct Shared {
    sender: mpsc::Sender<Command>,
    operations: Arc<Semaphore>,
    commands: Arc<Semaphore>,
    config: SpoolConfig,
    counters: Arc<Counters>,
}
#[derive(Clone)]
pub struct Spool {
    shared: Arc<Shared>,
}
#[cfg(test)]
pub(crate) struct TestStall {
    release: std::sync::mpsc::Sender<()>,
    completion: tokio::task::JoinHandle<Result<(), SpoolError>>,
}
#[cfg(test)]
impl TestStall {
    pub(crate) async fn release(self) -> Result<(), SpoolError> {
        self.release.send(()).map_err(|_| SpoolError::Io)?;
        self.completion.await.map_err(|_| SpoolError::Closed)?
    }
}
impl Spool {
    fn rejected(&self, error: SpoolError) -> SpoolError {
        count_error(&self.shared.counters, &error);
        error
    }
    #[cfg(test)]
    pub(crate) async fn test_stall(&self) -> Result<TestStall, SpoolError> {
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let spool = self.clone();
        let completion = tokio::spawn(async move {
            spool
                .request(Work::Hold(entered, release_rx), &CancellationToken::new())
                .await
                .map(|_| ())
        });
        entered_rx.await.map_err(|_| SpoolError::Closed)?;
        Ok(TestStall {
            release,
            completion,
        })
    }
    pub async fn open(
        config: SpoolConfig,
        cancellation: &CancellationToken,
    ) -> Result<Self, SpoolError> {
        config.validate()?;
        if cancellation.is_cancelled() {
            return Err(SpoolError::Cancelled);
        }
        let (sender, receiver) = mpsc::channel(config.command_capacity + 1);
        let (ready, ready_rx) = oneshot::channel();
        let counters = Arc::new(Counters::default());
        let spool = Self {
            shared: Arc::new(Shared {
                sender,
                operations: Arc::new(Semaphore::new(config.operation_capacity)),
                commands: Arc::new(Semaphore::new(config.command_capacity)),
                config: config.clone(),
                counters: counters.clone(),
            }),
        };
        let context = Context {
            deadline: Instant::now() + config.operation_timeout,
            cancellation: cancellation.child_token(),
        };
        let deadline = context.deadline;
        let mut guard = WaitGuard {
            cancellation: context.cancellation.clone(),
            counters: counters.clone(),
            armed: true,
        };
        thread::Builder::new()
            .name("signal-agent-spool".into())
            .spawn(move || worker(config, counters, context, receiver, ready))
            .map_err(io)?;
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(SpoolError::Cancelled),
            result = timeout_at(deadline, ready_rx) => match result {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(SpoolError::Closed),
                Err(_) => Err(SpoolError::Timeout),
            },
        };
        if result.is_ok() {
            guard.armed = false;
        }
        result?;
        Ok(spool)
    }
    async fn request(
        &self,
        work: Work,
        cancellation: &CancellationToken,
    ) -> Result<Value, SpoolError> {
        let shared = &self.shared;
        if shared.counters.closed.load(Ordering::Acquire) {
            return Err(self.rejected(SpoolError::Closed));
        }
        if cancellation.is_cancelled() {
            return Err(SpoolError::Cancelled);
        }
        let operation = shared
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| self.rejected(SpoolError::Full))?;
        let command = shared
            .commands
            .clone()
            .try_acquire_owned()
            .map_err(|_| self.rejected(SpoolError::Full))?;
        let context = Context {
            deadline: Instant::now() + shared.config.operation_timeout,
            cancellation: cancellation.child_token(),
        };
        let deadline = context.deadline;
        let mut guard = WaitGuard {
            cancellation: context.cancellation.clone(),
            counters: shared.counters.clone(),
            armed: false,
        };
        let (response, receiver) = oneshot::channel();
        shared
            .sender
            .try_send(Command::Data(Box::new(Request {
                work,
                context,
                response,
                operation,
                command,
            })))
            .map_err(|error| {
                self.rejected(match error {
                    mpsc::error::TrySendError::Full(_) => SpoolError::Full,
                    mpsc::error::TrySendError::Closed(_) => SpoolError::Closed,
                })
            })?;
        guard.armed = true;
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(SpoolError::Cancelled),
            result = timeout_at(deadline, receiver) => match result {
                Ok(Ok(response)) => {
                    guard.armed = false;
                    response.result
                },
                Ok(Err(_)) => Err(SpoolError::Closed),
                Err(_) => {
                    shared.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                    Err(SpoolError::Timeout)
                },
            },
        };
        result
    }
    pub async fn append(
        &self,
        event: SignalEvent,
        checkpoint: Option<SourceCheckpoint>,
        cancellation: &CancellationToken,
    ) -> Result<u64, SpoolError> {
        event
            .validate()
            .map_err(|_| self.rejected(SpoolError::Invalid("event")))?;
        validate_complexity(&event).map_err(|error| self.rejected(error))?;
        encode(&event, self.shared.config.max_event_bytes).map_err(|error| self.rejected(error))?;
        if let Some(checkpoint) = &checkpoint {
            validate_checkpoint(checkpoint).map_err(|error| self.rejected(error))?;
        }
        match self
            .request(Work::Append(Box::new(event), checkpoint), cancellation)
            .await?
        {
            Value::Sequence(sequence) => Ok(sequence),
            _ => Err(SpoolError::Closed),
        }
    }
    /// The byte limit charges canonical event JSON bytes; frame/cursor overhead
    /// remains independently bounded by the configured spool record limits.
    pub async fn read_batch(
        &self,
        max_events: usize,
        max_bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SpoolRecord>, SpoolError> {
        if max_events == 0
            || max_events > self.shared.config.max_batch_events
            || max_bytes < self.shared.config.max_event_bytes
            || max_bytes > self.shared.config.max_batch_bytes
        {
            return Err(self.rejected(SpoolError::Invalid("batch limits")));
        }
        match self
            .request(Work::Read(max_events, max_bytes), cancellation)
            .await?
        {
            Value::Batch(batch) => Ok(batch),
            _ => Err(SpoolError::Closed),
        }
    }
    pub async fn ack(
        &self,
        sequence: u64,
        cancellation: &CancellationToken,
    ) -> Result<(), SpoolError> {
        match self.request(Work::Ack(sequence), cancellation).await? {
            Value::Done => Ok(()),
            _ => Err(SpoolError::Closed),
        }
    }
    pub async fn checkpoint(
        &self,
        checkpoint: SourceCheckpoint,
        cancellation: &CancellationToken,
    ) -> Result<(), SpoolError> {
        validate_checkpoint(&checkpoint).map_err(|error| self.rejected(error))?;
        match self
            .request(Work::Checkpoint(checkpoint), cancellation)
            .await?
        {
            Value::Done => Ok(()),
            _ => Err(SpoolError::Closed),
        }
    }
    pub async fn cursor_snapshot(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SourceCheckpoint>, SpoolError> {
        match self.request(Work::Cursors, cancellation).await? {
            Value::Cursors(cursors) => Ok(cursors),
            _ => Err(SpoolError::Closed),
        }
    }
    /// STOP has a reserved queue slot and uses no data-operation permit. It
    /// closes admission immediately, discards queued work, and waits boundedly
    /// for the physical disk worker to release its lock.
    pub async fn close(&self, cancellation: &CancellationToken) -> Result<(), SpoolError> {
        let shared = &self.shared;
        shared.counters.closed.store(true, Ordering::Release);
        if shared.counters.stopping.swap(true, Ordering::AcqRel) {
            return Err(SpoolError::Closed);
        }
        let (sender, receiver) = oneshot::channel();
        shared
            .sender
            .try_send(Command::Stop(sender))
            .map_err(|_| SpoolError::Closed)?;
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(SpoolError::Cancelled),
            result = tokio::time::timeout(shared.config.operation_timeout, receiver) => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(SpoolError::Closed),
                Err(_) => Err(SpoolError::Timeout),
            },
        }
    }
    pub fn metrics(&self) -> SpoolMetrics {
        let s = &self.shared;
        let c = &s.counters;
        let records = c.records.load(Ordering::Relaxed);
        SpoolMetrics {
            command_depth: s.config.command_capacity - s.commands.available_permits(),
            command_capacity: s.config.command_capacity,
            operations_in_flight: s.config.operation_capacity - s.operations.available_permits(),
            operation_capacity: s.config.operation_capacity,
            disk_bytes: c.bytes.load(Ordering::Relaxed),
            disk_capacity: s.config.max_disk_bytes,
            records,
            record_capacity: s.config.max_records,
            index_bytes: records * INDEX_BYTES,
            index_capacity: s.config.max_index_bytes,
            appended: c.appended.load(Ordering::Relaxed),
            acknowledged: c.acknowledged.load(Ordering::Relaxed),
            rejections: c.rejections.load(Ordering::Relaxed),
            failures: c.failures.load(Ordering::Relaxed),
            timeouts: c.timeouts.load(Ordering::Relaxed),
            corruptions: c.corruptions.load(Ordering::Relaxed),
            closed: c.closed.load(Ordering::Acquire),
        }
    }
}
fn worker(
    config: SpoolConfig,
    counters: Arc<Counters>,
    opening: Context,
    mut receiver: mpsc::Receiver<Command>,
    ready: oneshot::Sender<Result<(), SpoolError>>,
) {
    let mut engine = match Engine::open(config, &opening) {
        Ok(engine) => engine,
        Err(error) => {
            count_error(&counters, &error);
            counters.closed.store(true, Ordering::Release);
            let _ = ready.send(Err(error));
            return;
        }
    };
    engine.update_metrics(&counters);
    if ready.send(Ok(())).is_err() {
        return;
    }
    while let Some(command) = receiver.blocking_recv() {
        let request = match command {
            Command::Stop(response) => {
                drop(engine);
                let _ = response.send(());
                return;
            }
            Command::Data(request) => *request,
        };
        drop(request.command);
        let old_records = engine.entries.len();
        let is_ack = matches!(&request.work, Work::Ack(_));
        let result = if counters.closed.load(Ordering::Acquire) {
            Err(SpoolError::Closed)
        } else {
            request
                .context
                .check()
                .and_then(|()| engine.perform(request.work, &request.context))
        };
        engine.update_metrics(&counters);
        if result.is_ok() && is_ack {
            counters.acknowledged.fetch_add(
                (old_records - engine.entries.len()) as u64,
                Ordering::Relaxed,
            );
        }
        if let Err(error) = &result {
            count_error(&counters, error);
            if matches!(
                error,
                SpoolError::Io
                    | SpoolError::Corrupt(_)
                    | SpoolError::Timeout
                    | SpoolError::Cancelled
            ) {
                counters.closed.store(true, Ordering::Release);
            }
        } else if let Ok(Value::Sequence(_)) = &result {
            counters.appended.fetch_add(1, Ordering::Relaxed);
        }
        let _ = request.response.send(Response {
            result,
            _operation: request.operation,
        });
    }
}
fn count_error(counters: &Counters, error: &SpoolError) {
    match error {
        SpoolError::Full | SpoolError::Quota | SpoolError::Invalid(_) | SpoolError::Closed => {
            counters.rejections.fetch_add(1, Ordering::Relaxed);
        }
        SpoolError::Timeout => {
            counters.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        SpoolError::Corrupt(_) => {
            counters.corruptions.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    counters.failures.fetch_add(1, Ordering::Relaxed);
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskRecord {
    version: u16,
    sequence: u64,
    event: SignalEvent,
    checkpoint: Option<SourceCheckpoint>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u16,
    acknowledged: u64,
    next_sequence: u64,
    cursors: Vec<SourceCheckpoint>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            acknowledged: 0,
            next_sequence: 1,
            cursors: Vec::new(),
        }
    }
}
struct Entry {
    bytes: usize,
    event_bytes: usize,
}
struct Engine {
    config: SpoolConfig,
    _lock: File,
    directory: File,
    entries: BTreeMap<u64, Entry>,
    state: State,
    bytes: u64,
}
fn file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    options
}
fn regular(path: &Path) -> Result<(), SpoolError> {
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_file() {
        return Err(SpoolError::Corrupt("nonregular spool file"));
    }
    Ok(())
}
fn validate_checkpoint(checkpoint: &SourceCheckpoint) -> Result<(), SpoolError> {
    if checkpoint.input >= 16 || checkpoint.anchor.len() > 64 {
        return Err(SpoolError::Invalid("source checkpoint"));
    }
    Ok(())
}
fn validate_complexity(event: &SignalEvent) -> Result<(), SpoolError> {
    fn visit(value: &serde_json::Value, depth: usize, nodes: &mut usize) -> Result<(), SpoolError> {
        *nodes += 1;
        if depth > 32 || *nodes > 4096 {
            return Err(SpoolError::Invalid("event complexity"));
        }
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, depth + 1, nodes)?;
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    visit(value, depth + 1, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut nodes = 0;
    for value in event.attributes.values() {
        visit(value, 1, &mut nodes)?;
    }
    Ok(())
}
fn replace_cursor(state: &mut State, checkpoint: SourceCheckpoint) -> Result<(), SpoolError> {
    validate_checkpoint(&checkpoint)?;
    if let Some(existing) = state
        .cursors
        .iter_mut()
        .find(|c| c.input == checkpoint.input)
    {
        *existing = checkpoint;
    } else {
        if state.cursors.len() >= 16 {
            return Err(SpoolError::Invalid("source count"));
        }
        state.cursors.push(checkpoint);
        state.cursors.sort_by_key(|c| c.input);
    }
    Ok(())
}
/// Publish each new directory name durably in its parent before admitting work
/// beneath it. Syncing only the spool leaf cannot preserve newly made ancestors.
fn ensure_directory(path: &Path, context: &Context) -> Result<(), SpoolError> {
    context.check()?;
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(SpoolError::Invalid("spool directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(error)),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_directory(parent, context)?;
    context.check()?;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path).map_err(io)?.is_dir() {
                return Err(SpoolError::Invalid("spool directory"));
            }
        }
        Err(error) => return Err(io(error)),
    }
    context.check()?;
    File::open(path).map_err(io)?.sync_all().map_err(io)?;
    context.check()?;
    File::open(parent).map_err(io)?.sync_all().map_err(io)?;
    context.check()?;
    Ok(())
}
/// A failed bootstrap may leave existing directory names whose parents were
/// never synced. Before publishing the first state, flush their bounded chain
/// even when mkdir found every directory already present. An existing durable
/// state proves bootstrap finished, so normal recovery skips this extra work.
fn sync_bootstrap_ancestors(path: &Path, context: &Context) -> Result<(), SpoolError> {
    context.check()?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(io)?.join(path)
    };
    if absolute.as_os_str().as_encoded_bytes().len() > 4096
        || absolute.components().take(129).count() > 128
    {
        return Err(SpoolError::Invalid("spool directory depth or size"));
    }
    for ancestor in absolute.ancestors() {
        context.check()?;
        if !fs::symlink_metadata(ancestor).map_err(io)?.is_dir() {
            return Err(SpoolError::Invalid("spool directory"));
        }
        File::open(ancestor).map_err(io)?.sync_all().map_err(io)?;
        context.check()?;
    }
    Ok(())
}
impl Engine {
    fn open(config: SpoolConfig, context: &Context) -> Result<Self, SpoolError> {
        context.check()?;
        ensure_directory(&config.directory, context)?;
        let metadata = fs::symlink_metadata(&config.directory).map_err(io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(SpoolError::Invalid("spool directory"));
        }
        let directory = File::open(&config.directory).map_err(io)?;
        let lock = file_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.directory.join("lock"))
            .map_err(io)?;
        lock.try_lock().map_err(|_| SpoolError::Locked)?;
        context.check()?;
        let state_path = config.directory.join("state");
        let state = if state_path.try_exists().map_err(io)? {
            regular(&state_path)?;
            let bytes = read_frame(&state_path, STATE_LIMIT, false)?
                .ok_or(SpoolError::Corrupt("state incomplete"))?;
            let state: State =
                serde_json::from_slice(&bytes).map_err(|_| SpoolError::Corrupt("state JSON"))?;
            if state.version != 1
                || state.next_sequence <= state.acknowledged
                || state.cursors.len() > 16
            {
                return Err(SpoolError::Corrupt("state contract"));
            }
            let mut seen = [false; 16];
            for checkpoint in &state.cursors {
                validate_checkpoint(checkpoint)
                    .map_err(|_| SpoolError::Corrupt("source checkpoint"))?;
                if std::mem::replace(&mut seen[checkpoint.input as usize], true) {
                    return Err(SpoolError::Corrupt("duplicate source checkpoint"));
                }
            }
            state
        } else {
            State::default()
        };
        let mut engine = Self {
            config,
            _lock: lock,
            directory,
            entries: BTreeMap::new(),
            state,
            bytes: METADATA_RESERVE,
        };
        let mut sequences = Vec::new();
        let mut file_count = 0usize;
        for item in fs::read_dir(&engine.config.directory).map_err(io)? {
            context.check()?;
            let item = item.map_err(io)?;
            file_count += 1;
            if file_count > engine.config.max_records + 3 {
                return Err(SpoolError::Quota);
            }
            let name = item.file_name();
            let name = name.to_str().ok_or(SpoolError::Corrupt("filename"))?;
            regular(&item.path())?;
            match name {
                "lock" | "state" => {}
                "state.tmp" => {
                    if item.metadata().map_err(io)?.len() > (STATE_LIMIT + FRAME_BYTES) as u64 {
                        return Err(SpoolError::Corrupt("state temporary size"));
                    }
                    fs::remove_file(item.path()).map_err(io)?;
                }
                name if name.starts_with("record-") => {
                    let number = &name[7..];
                    let sequence = number
                        .parse::<u64>()
                        .map_err(|_| SpoolError::Corrupt("record filename"))?;
                    if number.len() != 20
                        || sequence == 0
                        || !number.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(SpoolError::Corrupt("record filename"));
                    }
                    if sequence <= engine.state.acknowledged {
                        fs::remove_file(item.path()).map_err(io)?;
                        continue;
                    }
                    if sequences.len() >= engine.config.max_records
                        || (sequences.len() + 1) * INDEX_BYTES > engine.config.max_index_bytes
                    {
                        return Err(SpoolError::Quota);
                    }
                    sequences.push(sequence);
                }
                _ => return Err(SpoolError::Corrupt("unowned directory entry")),
            }
        }
        if !state_path.try_exists().map_err(io)? && !sequences.is_empty() {
            return Err(SpoolError::Corrupt("record directory missing state"));
        }
        sequences.sort_unstable();
        let mut expected = engine
            .state
            .acknowledged
            .checked_add(1)
            .ok_or(SpoolError::Corrupt("sequence overflow"))?;
        let last = sequences.last().copied();
        for sequence in sequences {
            context.check()?;
            let path = engine.record_path(sequence);
            if sequence <= engine.state.acknowledged {
                fs::remove_file(path).map_err(io)?;
                continue;
            }
            if sequence != expected {
                return Err(SpoolError::Corrupt("record sequence gap"));
            }
            let Some(bytes) = read_frame(&path, engine.record_limit(), Some(sequence) == last)?
            else {
                if sequence < engine.state.next_sequence {
                    return Err(SpoolError::Corrupt("checkpointed record incomplete"));
                }
                fs::remove_file(path).map_err(io)?;
                break;
            };
            let record = engine.decode_record(sequence, &bytes)?;
            let event_bytes = encode(&record.event, engine.config.max_event_bytes)?.len();
            if engine.entries.len() >= engine.config.max_records
                || (engine.entries.len() + 1) * INDEX_BYTES > engine.config.max_index_bytes
            {
                return Err(SpoolError::Quota);
            }
            let charged = (bytes.len() + FRAME_BYTES) as u64;
            if engine
                .bytes
                .checked_add(charged)
                .is_none_or(|size| size > engine.config.max_disk_bytes)
            {
                return Err(SpoolError::Quota);
            }
            engine.bytes += charged;
            engine.entries.insert(
                sequence,
                Entry {
                    bytes: charged as usize,
                    event_bytes,
                },
            );
            // A state checkpoint may include a later eventless cursor. Replaying
            // older records must not rewind it. Appends beyond the checkpoint
            // carry the latest cursor for that source.
            if sequence >= engine.state.next_sequence
                && let Some(checkpoint) = record.checkpoint
            {
                replace_cursor(&mut engine.state, checkpoint)?;
            }
            expected = expected
                .checked_add(1)
                .ok_or(SpoolError::Corrupt("sequence overflow"))?;
        }
        if expected < engine.state.next_sequence {
            return Err(SpoolError::Corrupt("checkpointed record missing"));
        }
        engine.state.next_sequence = engine.state.next_sequence.max(expected);
        // Persist an initial identity before admitting records. Existing state is
        // rewritten only by append acknowledgements or cursor-only checkpoints.
        if !state_path.try_exists().map_err(io)? {
            sync_bootstrap_ancestors(&engine.config.directory, context)?;
            engine.persist_state(&engine.state, context)?;
        }
        engine.directory.sync_all().map_err(io)?;
        context.check()?;
        Ok(engine)
    }
    fn record_path(&self, sequence: u64) -> PathBuf {
        self.config.directory.join(format!("record-{sequence:020}"))
    }
    fn record_limit(&self) -> usize {
        self.config.max_event_bytes + CHECKPOINT_BYTES
    }
    fn update_metrics(&self, counters: &Counters) {
        counters.bytes.store(self.bytes, Ordering::Relaxed);
        counters
            .records
            .store(self.entries.len(), Ordering::Relaxed);
    }
    fn decode_record(&self, sequence: u64, bytes: &[u8]) -> Result<DiskRecord, SpoolError> {
        let record: DiskRecord =
            serde_json::from_slice(bytes).map_err(|_| SpoolError::Corrupt("record JSON"))?;
        if record.version != 1 || record.sequence != sequence || record.event.validate().is_err() {
            return Err(SpoolError::Corrupt("record contract"));
        }
        validate_complexity(&record.event).map_err(|_| SpoolError::Corrupt("event complexity"))?;
        if let Some(checkpoint) = &record.checkpoint {
            validate_checkpoint(checkpoint)
                .map_err(|_| SpoolError::Corrupt("source checkpoint"))?;
        }
        Ok(record)
    }
    fn persist_state(&self, state: &State, context: &Context) -> Result<(), SpoolError> {
        context.check()?;
        let data = encode(state, STATE_LIMIT)?;
        let temporary = self.config.directory.join("state.tmp");
        let mut file = file_options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(&header(&data)).map_err(io)?;
        file.write_all(&data).map_err(io)?;
        file.sync_all().map_err(io)?;
        context.check()?;
        fs::rename(temporary, self.config.directory.join("state")).map_err(io)?;
        self.directory.sync_all().map_err(io)?;
        context.check()?;
        Ok(())
    }
    fn perform(&mut self, work: Work, context: &Context) -> Result<Value, SpoolError> {
        match work {
            Work::Append(event, checkpoint) => {
                event.validate().map_err(|_| SpoolError::Invalid("event"))?;
                let event_bytes = encode(&event, self.config.max_event_bytes)?.len();
                if let Some(checkpoint) = &checkpoint {
                    validate_checkpoint(checkpoint)?;
                }
                if self.entries.len() >= self.config.max_records
                    || (self.entries.len() + 1) * INDEX_BYTES > self.config.max_index_bytes
                {
                    return Err(SpoolError::Quota);
                }
                let sequence = self.state.next_sequence;
                let next_sequence = sequence
                    .checked_add(1)
                    .ok_or(SpoolError::Invalid("sequence overflow"))?;
                let record = DiskRecord {
                    version: 1,
                    sequence,
                    event: *event,
                    checkpoint,
                };
                let data = encode(&record, self.record_limit())?;
                let bytes = data.len() + FRAME_BYTES;
                if self
                    .bytes
                    .checked_add(bytes as u64)
                    .is_none_or(|size| size > self.config.max_disk_bytes)
                {
                    return Err(SpoolError::Quota);
                }
                context.check()?;
                let mut file = file_options()
                    .write(true)
                    .create_new(true)
                    .open(self.record_path(sequence))
                    .map_err(io)?;
                file.write_all(&header(&data)).map_err(io)?;
                file.write_all(&data).map_err(io)?;
                file.sync_all().map_err(io)?;
                self.directory.sync_all().map_err(io)?;
                context.check()?;
                self.bytes += bytes as u64;
                self.entries.insert(sequence, Entry { bytes, event_bytes });
                self.state.next_sequence = next_sequence;
                if let Some(checkpoint) = record.checkpoint {
                    replace_cursor(&mut self.state, checkpoint)?;
                }
                Ok(Value::Sequence(sequence))
            }
            Work::Read(max_events, max_bytes) => {
                let mut output = Vec::with_capacity(max_events.min(self.entries.len()));
                let mut bytes = 0;
                for (&sequence, entry) in self.entries.iter().take(max_events) {
                    context.check()?;
                    if bytes + entry.event_bytes > max_bytes {
                        break;
                    }
                    let data = read_frame(&self.record_path(sequence), self.record_limit(), false)?
                        .ok_or(SpoolError::Corrupt("record incomplete"))?;
                    let record = self.decode_record(sequence, &data)?;
                    bytes += entry.event_bytes;
                    output.push(SpoolRecord {
                        sequence,
                        event: record.event,
                    });
                }
                context.check()?;
                Ok(Value::Batch(output))
            }
            Work::Ack(sequence) => {
                if sequence <= self.state.acknowledged {
                    return Ok(Value::Done);
                }
                if !self.entries.contains_key(&sequence) {
                    return Err(SpoolError::Invalid("acknowledged prefix"));
                }
                let mut state = self.state.clone();
                state.acknowledged = sequence;
                self.persist_state(&state, context)?;
                self.state = state;
                while let Some((&first, _)) = self.entries.first_key_value() {
                    if first > sequence {
                        break;
                    }
                    context.check()?;
                    fs::remove_file(self.record_path(first)).map_err(io)?;
                    if let Some(entry) = self.entries.remove(&first) {
                        self.bytes -= entry.bytes as u64;
                    }
                }
                self.directory.sync_all().map_err(io)?;
                context.check()?;
                Ok(Value::Done)
            }
            Work::Checkpoint(checkpoint) => {
                let mut state = self.state.clone();
                replace_cursor(&mut state, checkpoint)?;
                self.persist_state(&state, context)?;
                self.state = state;
                Ok(Value::Done)
            }
            Work::Cursors => Ok(Value::Cursors(self.state.cursors.clone())),
            #[cfg(test)]
            Work::Hold(entered, release) => {
                let _ = entered.send(());
                release.recv().map_err(|_| SpoolError::Io)?;
                context.check()?;
                Ok(Value::Done)
            }
        }
    }
}
fn header(data: &[u8]) -> [u8; FRAME_BYTES] {
    let mut header = [0; FRAME_BYTES];
    header[..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    header[4..8].copy_from_slice(&crc32fast::hash(data).to_le_bytes());
    let crc = crc32fast::hash(&header[..8]);
    header[8..12].copy_from_slice(&crc.to_le_bytes());
    header
}
fn read_frame(
    path: &Path,
    limit: usize,
    allow_incomplete: bool,
) -> Result<Option<Vec<u8>>, SpoolError> {
    let mut file = file_options().read(true).open(path).map_err(io)?;
    let size = file.metadata().map_err(io)?.len();
    if size < FRAME_BYTES as u64 {
        if allow_incomplete {
            return Ok(None);
        }
        return Err(SpoolError::Corrupt("frame header incomplete"));
    }
    if size > (limit + FRAME_BYTES) as u64 {
        return Err(SpoolError::Corrupt("frame size"));
    }
    let mut header = [0; FRAME_BYTES];
    file.read_exact(&mut header).map_err(io)?;
    let number = |range: std::ops::Range<usize>| -> Result<u32, SpoolError> {
        let bytes: [u8; 4] = header[range]
            .try_into()
            .map_err(|_| SpoolError::Corrupt("header shape"))?;
        Ok(u32::from_le_bytes(bytes))
    };
    if crc32fast::hash(&header[..8]) != number(8..12)? {
        return Err(SpoolError::Corrupt("header checksum"));
    }
    let length = number(0..4)? as usize;
    if length == 0 || length > limit {
        return Err(SpoolError::Corrupt("payload length"));
    }
    if size < (length + FRAME_BYTES) as u64 {
        if allow_incomplete {
            return Ok(None);
        }
        return Err(SpoolError::Corrupt("frame payload incomplete"));
    }
    if size != (length + FRAME_BYTES) as u64 {
        return Err(SpoolError::Corrupt("frame trailing bytes"));
    }
    let mut data = vec![0; length];
    file.read_exact(&mut data).map_err(io)?;
    if crc32fast::hash(&data) != number(4..8)? {
        return Err(SpoolError::Corrupt("payload checksum"));
    }
    Ok(Some(data))
}
struct BoundedWriter {
    data: Vec<u8>,
    limit: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .data
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.limit)
        {
            return Err(std::io::Error::other("spool encoding limit"));
        }
        self.data.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, SpoolError> {
    let mut writer = BoundedWriter {
        data: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| SpoolError::Quota)?;
    Ok(writer.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::PermissionsExt;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn config(path: &Path) -> SpoolConfig {
        SpoolConfig {
            directory: path.into(),
            ..Default::default()
        }
    }
    fn event(message: &str) -> Result<SignalEvent, Box<dyn std::error::Error>> {
        Ok(signal_event::IngestEvent {
            schema_version: 1,
            id: None,
            timestamp: chrono::Utc::now(),
            observed_at: None,
            source: signal_event::Source {
                source_type: "file".into(),
                name: Some("synthetic".into()),
            },
            severity: signal_event::Severity::Info,
            message: Some(message.into()),
            attributes: serde_json::Map::new(),
            resource: None,
            trace_id: None,
            span_id: None,
            tags: Vec::new(),
        }
        .normalize(chrono::Utc::now())?)
    }
    fn cursor(input: u16, offset: u64) -> SourceCheckpoint {
        SourceCheckpoint {
            input,
            device: 1,
            inode: 2,
            offset,
            anchor: b"line\n".to_vec(),
        }
    }
    async fn batch(
        spool: &Spool,
        token: &CancellationToken,
    ) -> Result<Vec<SpoolRecord>, SpoolError> {
        spool.read_batch(100, 1024 * 1024, token).await
    }
    #[tokio::test]
    async fn newly_created_nested_spool_has_owned_modes_and_restarts() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let root = directory.path().join("new-data");
        let nested = root.join("nested");
        let spool_path = nested.join("agent-spool");
        let first = event("nested startup")?;
        let spool = Spool::open(config(&spool_path), &token).await?;
        for path in [&root, &nested, &spool_path] {
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
        }
        assert_eq!(
            spool
                .append(first.clone(), Some(cursor(0, 4)), &token)
                .await?,
            1
        );
        spool.close(&token).await?;
        let spool = Spool::open(config(&spool_path), &token).await?;
        assert_eq!(batch(&spool, &token).await?[0].event, first);
        assert_eq!(spool.cursor_snapshot(&token).await?, vec![cursor(0, 4)]);
        spool.ack(1, &token).await?;
        spool.close(&token).await?;
        Ok(())
    }
    #[test]
    fn canceled_directory_initialization_makes_no_new_ancestors() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("new-data/agent-spool");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let context = Context {
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        assert_eq!(
            ensure_directory(&path, &context),
            Err(SpoolError::Cancelled)
        );
        assert!(!directory.path().join("new-data").exists());
        Ok(())
    }
    #[tokio::test]
    async fn bootstrap_recovers_preexisting_empty_nested_directories() -> TestResult {
        let directory = tempfile::tempdir()?;
        let spool_path = directory.path().join("interrupted/data/agent-spool");
        // Model mkdir finishing before initialization was canceled. No state
        // exists yet; the source ordering flushes all ancestors before state.
        fs::create_dir_all(&spool_path)?;
        let token = CancellationToken::new();
        let first = event("after interrupted bootstrap")?;
        let spool = Spool::open(config(&spool_path), &token).await?;
        assert!(spool_path.join("state").exists());
        assert_eq!(
            spool
                .append(first.clone(), Some(cursor(0, 4)), &token)
                .await?,
            1
        );
        spool.close(&token).await?;
        let spool = Spool::open(config(&spool_path), &token).await?;
        assert_eq!(batch(&spool, &token).await?[0].event, first);
        assert_eq!(spool.cursor_snapshot(&token).await?, vec![cursor(0, 4)]);
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn spool_directory_depth_and_bytes_are_bounded_before_disk_work() -> TestResult {
        let token = CancellationToken::new();
        let deep: PathBuf = (0..129).map(|_| "a").collect();
        let huge = PathBuf::from("a".repeat(4097));
        for path in [deep, huge] {
            let cfg = config(&path);
            assert!(matches!(cfg.validate(), Err(SpoolError::Invalid(_))));
            assert!(matches!(
                Spool::open(cfg, &token).await,
                Err(SpoolError::Invalid(_))
            ));
        }
        Ok(())
    }
    #[tokio::test]
    async fn sync_restart_prefix_ack_and_stable_ids() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let first = event("one")?;
        let second = event("two")?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert_eq!(
            spool
                .append(first.clone(), Some(cursor(0, 4)), &token)
                .await?,
            1
        );
        assert_eq!(
            spool
                .append(second.clone(), Some(cursor(0, 8)), &token)
                .await?,
            2
        );
        assert_eq!(spool.metrics().records, 2);
        assert!(spool.metrics().disk_bytes <= spool.metrics().disk_capacity);
        spool.close(&token).await?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        let recovered = batch(&spool, &token).await?;
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].event, first);
        assert_eq!(recovered[1].event, second);
        assert_eq!(spool.cursor_snapshot(&token).await?, vec![cursor(0, 8)]);
        spool.ack(1, &token).await?;
        assert_eq!(spool.metrics().acknowledged, 1);
        assert!(
            !directory
                .path()
                .join("record-00000000000000000001")
                .exists()
        );
        assert_eq!(batch(&spool, &token).await?[0].event.id, second.id);
        spool.ack(2, &token).await?;
        spool.ack(1, &token).await?;
        assert!(batch(&spool, &token).await?.is_empty());
        assert_eq!(spool.metrics().disk_bytes, METADATA_RESERVE);
        spool.close(&token).await?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert!(batch(&spool, &token).await?.is_empty());
        assert_eq!(spool.cursor_snapshot(&token).await?, vec![cursor(0, 8)]);
        assert_eq!(spool.append(event("three")?, None, &token).await?, 3);
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn cursor_only_checkpoint_does_not_rewind_on_pending_replay() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let spool = Spool::open(config(directory.path()), &token).await?;
        spool
            .append(event("one")?, Some(cursor(0, 4)), &token)
            .await?;
        spool.checkpoint(cursor(0, 20), &token).await?;
        spool.checkpoint(cursor(1, 12), &token).await?;
        spool.close(&token).await?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert_eq!(
            spool.cursor_snapshot(&token).await?,
            vec![cursor(0, 20), cursor(1, 12)]
        );
        spool
            .append(event("two")?, Some(cursor(0, 24)), &token)
            .await?;
        spool.close(&token).await?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert_eq!(
            spool.cursor_snapshot(&token).await?,
            vec![cursor(0, 24), cursor(1, 12)]
        );
        spool.ack(2, &token).await?;
        spool.close(&token).await?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert_eq!(
            spool.cursor_snapshot(&token).await?,
            vec![cursor(0, 24), cursor(1, 12)]
        );
        assert!(batch(&spool, &token).await?.is_empty());
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn real_disk_record_index_and_event_quotas() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let mut cfg = config(directory.path());
        cfg.max_records = 1;
        let spool = Spool::open(cfg.clone(), &token).await?;
        spool.append(event("one")?, None, &token).await?;
        assert!(matches!(
            spool.append(event("two")?, None, &token).await,
            Err(SpoolError::Quota)
        ));
        assert!(matches!(
            spool.append(event(&"x".repeat(65536))?, None, &token).await,
            Err(SpoolError::Quota)
        ));
        assert_eq!(spool.metrics().records, 1);
        assert_eq!(spool.metrics().rejections, 2);
        spool.ack(1, &token).await?;
        spool.close(&token).await?;
        cfg.max_records = 10;
        cfg.max_index_bytes = INDEX_BYTES;
        let spool = Spool::open(cfg.clone(), &token).await?;
        spool.append(event("one")?, None, &token).await?;
        assert!(matches!(
            spool.append(event("two")?, None, &token).await,
            Err(SpoolError::Quota)
        ));
        assert_eq!(spool.metrics().index_bytes, INDEX_BYTES);
        spool.ack(2, &token).await?;
        spool.close(&token).await?;
        cfg.max_event_bytes = 1024;
        cfg.max_index_bytes = 10 * INDEX_BYTES;
        cfg.max_disk_bytes = METADATA_RESERVE + 1024 + CHECKPOINT_BYTES as u64 + FRAME_BYTES as u64;
        let spool = Spool::open(cfg, &token).await?;
        spool.append(event(&"x".repeat(512))?, None, &token).await?;
        assert!(matches!(
            spool.append(event(&"x".repeat(512))?, None, &token).await,
            Err(SpoolError::Quota)
        ));
        assert_eq!(batch(&spool, &token).await?.len(), 1);
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn bounded_batches_and_prefix_validation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let cfg = SpoolConfig {
            max_event_bytes: 4096,
            max_batch_bytes: 8192,
            ..config(directory.path())
        };
        let spool = Spool::open(cfg, &token).await?;
        for _ in 0..4 {
            spool
                .append(event(&"a".repeat(2000))?, None, &token)
                .await?;
        }
        assert_eq!(spool.read_batch(2, 8192, &token).await?.len(), 2);
        assert_eq!(spool.read_batch(4, 4096, &token).await?.len(), 1);
        assert!(matches!(
            spool.ack(5, &token).await,
            Err(SpoolError::Invalid(_))
        ));
        assert_eq!(spool.metrics().records, 4);
        assert!(matches!(
            spool.read_batch(101, 8192, &token).await,
            Err(SpoolError::Invalid(_))
        ));
        assert!(matches!(
            spool.checkpoint(cursor(16, 3), &token).await,
            Err(SpoolError::Invalid(_))
        ));
        let mut invalid = cursor(0, 3);
        invalid.anchor = vec![0; 65];
        assert!(matches!(
            spool.append(event("one")?, Some(invalid), &token).await,
            Err(SpoolError::Invalid(_))
        ));
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn incomplete_uncommitted_final_record_recovered_but_interior_refused() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let spool = Spool::open(config(directory.path()), &token).await?;
        let first = event("one")?;
        spool.append(first.clone(), None, &token).await?;
        spool.close(&token).await?;
        let incomplete = directory.path().join("record-00000000000000000002");
        let mut file = File::create(&incomplete)?;
        let data = encode(
            &DiskRecord {
                version: 1,
                sequence: 2,
                event: event("two")?,
                checkpoint: None,
            },
            65536,
        )?;
        file.write_all(&header(&data))?;
        file.write_all(&data[..data.len() - 1])?;
        file.sync_all()?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert_eq!(batch(&spool, &token).await?[0].event, first);
        assert!(!incomplete.exists());
        assert_eq!(spool.append(event("two")?, None, &token).await?, 2);
        spool.close(&token).await?;
        let first_path = directory.path().join("record-00000000000000000001");
        OpenOptions::new()
            .write(true)
            .open(first_path)?
            .set_len(5)?;
        assert!(matches!(
            Spool::open(config(directory.path()), &token).await,
            Err(SpoolError::Corrupt(_))
        ));
        Ok(())
    }
    #[tokio::test]
    async fn corrupt_complete_header_or_payload_fails_closed() -> TestResult {
        for header_corruption in [true, false] {
            let directory = tempfile::tempdir()?;
            let token = CancellationToken::new();
            let spool = Spool::open(config(directory.path()), &token).await?;
            spool.append(event("one")?, None, &token).await?;
            spool.close(&token).await?;
            let path = directory.path().join("record-00000000000000000001");
            let mut file = OpenOptions::new().write(true).open(path)?;
            file.seek(SeekFrom::Start(if header_corruption {
                0
            } else {
                FRAME_BYTES as u64
            }))?;
            file.write_all(&[0xff])?;
            file.sync_all()?;
            assert!(matches!(
                Spool::open(config(directory.path()), &token).await,
                Err(SpoolError::Corrupt(_))
            ));
        }
        Ok(())
    }
    #[tokio::test]
    async fn checkpointed_missing_or_incomplete_record_fails_closed() -> TestResult {
        for missing in [true, false] {
            let directory = tempfile::tempdir()?;
            let token = CancellationToken::new();
            let spool = Spool::open(config(directory.path()), &token).await?;
            spool
                .append(event("one")?, Some(cursor(0, 4)), &token)
                .await?;
            spool.checkpoint(cursor(0, 8), &token).await?;
            spool.close(&token).await?;
            let path = directory.path().join("record-00000000000000000001");
            if missing {
                fs::remove_file(path)?;
            } else {
                OpenOptions::new().write(true).open(path)?.set_len(3)?;
            }
            assert!(matches!(
                Spool::open(config(directory.path()), &token).await,
                Err(SpoolError::Corrupt(_))
            ));
        }
        Ok(())
    }
    #[tokio::test]
    async fn durable_ack_before_reclaim_and_temporary_state_recovery() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let spool = Spool::open(config(directory.path()), &token).await?;
        spool
            .append(event("one")?, Some(cursor(0, 4)), &token)
            .await?;
        let record_path = directory.path().join("record-00000000000000000001");
        let data = fs::read(&record_path)?;
        spool.ack(1, &token).await?;
        spool.close(&token).await?;
        // Reproduce a process crash after durable state but before file unlink.
        fs::write(record_path, data)?;
        fs::write(directory.path().join("state.tmp"), b"partial replacement")?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert!(batch(&spool, &token).await?.is_empty());
        assert_eq!(spool.cursor_snapshot(&token).await?, vec![cursor(0, 4)]);
        assert!(!directory.path().join("state.tmp").exists());
        assert_eq!(spool.append(event("two")?, None, &token).await?, 2);
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn lock_symlink_and_unowned_directory_refused() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert!(matches!(
            Spool::open(config(directory.path()), &token).await,
            Err(SpoolError::Locked)
        ));
        spool.close(&token).await?;
        let spool = Spool::open(config(directory.path()), &token).await?;
        spool.close(&token).await?;
        let external = tempfile::NamedTempFile::new()?;
        std::os::unix::fs::symlink(
            external.path(),
            directory.path().join("record-00000000000000000001"),
        )?;
        assert!(matches!(
            Spool::open(config(directory.path()), &token).await,
            Err(SpoolError::Corrupt(_))
        ));
        fs::remove_file(directory.path().join("record-00000000000000000001"))?;
        fs::write(directory.path().join("foreign"), b"owned elsewhere")?;
        assert!(matches!(
            Spool::open(config(directory.path()), &token).await,
            Err(SpoolError::Corrupt(_))
        ));
        assert_eq!(
            fs::read(directory.path().join("foreign"))?,
            b"owned elsewhere"
        );
        Ok(())
    }
    // Retain an unpolled oneshot response, as a caller stalled after enqueueing
    // would do. Capacity must include its already materialized batch/event.
    fn enqueue(spool: &Spool, work: Work) -> Result<oneshot::Receiver<Response>, SpoolError> {
        let s = &spool.shared;
        let operation = s
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| SpoolError::Full)?;
        let command = s
            .commands
            .clone()
            .try_acquire_owned()
            .map_err(|_| SpoolError::Full)?;
        let (response, receiver) = oneshot::channel();
        s.sender
            .try_send(Command::Data(Box::new(Request {
                work,
                context: Context {
                    deadline: Instant::now() + Duration::from_secs(5),
                    cancellation: CancellationToken::new(),
                },
                response,
                operation,
                command,
            })))
            .map_err(|_| SpoolError::Full)?;
        Ok(receiver)
    }
    #[tokio::test]
    async fn unpolled_responses_retain_capacity_and_stop_has_reserved_admission() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let cfg = SpoolConfig {
            command_capacity: 1,
            operation_capacity: 1,
            ..config(directory.path())
        };
        let spool = Spool::open(cfg, &token).await?;
        let receiver = enqueue(&spool, Work::Append(Box::new(event("one")?), None))?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while spool.metrics().appended == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(spool.metrics().operations_in_flight, 1);
        assert_eq!(spool.metrics().command_depth, 0);
        assert!(matches!(
            spool.append(event("two")?, None, &token).await,
            Err(SpoolError::Full)
        ));
        spool.close(&token).await?;
        assert_eq!(spool.metrics().operations_in_flight, 1);
        drop(receiver);
        assert_eq!(spool.metrics().operations_in_flight, 0);
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert_eq!(batch(&spool, &token).await?.len(), 1);
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn precancelled_operations_never_write() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let spool = Spool::open(config(directory.path()), &token).await?;
        let canceled = CancellationToken::new();
        canceled.cancel();
        assert!(matches!(
            spool.append(event("one")?, None, &canceled).await,
            Err(SpoolError::Cancelled)
        ));
        assert_eq!(spool.metrics().records, 0);
        assert!(!spool.metrics().closed);
        spool.close(&token).await?;
        assert!(matches!(
            Spool::open(config(directory.path()), &canceled).await,
            Err(SpoolError::Cancelled)
        ));
        Ok(())
    }
    #[test]
    fn finite_configuration_limits() {
        let valid = SpoolConfig::default();
        assert!(valid.validate().is_ok());
        for invalid in [
            SpoolConfig {
                max_records: 0,
                ..valid.clone()
            },
            SpoolConfig {
                command_capacity: 0,
                ..valid.clone()
            },
            SpoolConfig {
                operation_capacity: 1025,
                ..valid.clone()
            },
            SpoolConfig {
                operation_timeout: Duration::ZERO,
                ..valid.clone()
            },
            SpoolConfig {
                max_index_bytes: 0,
                ..valid.clone()
            },
            SpoolConfig {
                max_batch_bytes: 1,
                ..valid.clone()
            },
            SpoolConfig {
                max_disk_bytes: METADATA_RESERVE + valid.max_event_bytes as u64,
                ..valid.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }
    #[tokio::test]
    async fn cancellation_keeps_physical_worker_permit_until_completion() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let spool = Spool::open(config(directory.path()), &token).await?;
        let operation_token = CancellationToken::new();
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let caller = spool.clone();
        let cancellation = operation_token.clone();
        let task = tokio::spawn(async move {
            caller
                .request(Work::Hold(entered, release_rx), &cancellation)
                .await
        });
        entered_rx.await?;
        operation_token.cancel();
        assert!(matches!(task.await?, Err(SpoolError::Cancelled)));
        assert!(spool.metrics().closed);
        assert_eq!(spool.metrics().operations_in_flight, 1);
        assert!(matches!(
            spool.append(event("two")?, None, &token).await,
            Err(SpoolError::Closed)
        ));
        release.send(())?;
        spool.close(&token).await?;
        assert_eq!(spool.metrics().operations_in_flight, 0);
        let spool = Spool::open(config(directory.path()), &token).await?;
        assert!(batch(&spool, &token).await?.is_empty());
        spool.close(&token).await?;
        Ok(())
    }
    #[tokio::test]
    async fn deadline_closes_admission_without_releasing_stalled_worker_capacity() -> TestResult {
        let directory = tempfile::tempdir()?;
        let token = CancellationToken::new();
        let cfg = SpoolConfig {
            // Bootstrap and close share this deadline but are not the stalled-worker
            // behavior under test; allow finite headroom for parallel filesystem work.
            operation_timeout: Duration::from_secs(1),
            ..config(directory.path())
        };
        let spool = Spool::open(cfg, &token).await.map_err(|error| {
            std::io::Error::other(format!("deadline-test fixture bootstrap: {error:?}"))
        })?;
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let caller = spool.clone();
        let cancellation = token.clone();
        let task = tokio::spawn(async move {
            caller
                .request(Work::Hold(entered, release_rx), &cancellation)
                .await
        });
        entered_rx.await?;
        assert!(matches!(task.await?, Err(SpoolError::Timeout)));
        assert!(spool.metrics().closed);
        assert_eq!(spool.metrics().operations_in_flight, 1);
        assert_eq!(spool.metrics().timeouts, 1);
        release.send(())?;
        spool.close(&token).await.map_err(|error| {
            std::io::Error::other(format!("deadline-test fixture close: {error:?}"))
        })?;
        assert_eq!(spool.metrics().operations_in_flight, 0);
        Ok(())
    }
    #[test]
    fn runtime_drop_does_not_wait_for_stalled_disk_thread() -> TestResult {
        let directory = tempfile::tempdir()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let token = CancellationToken::new();
        let (release, release_rx) = std::sync::mpsc::channel();
        let spool = runtime.block_on(async {
            let spool = Spool::open(config(directory.path()), &token).await?;
            let (entered, entered_rx) = oneshot::channel();
            let caller = spool.clone();
            let cancellation = token.clone();
            tokio::spawn(async move {
                caller
                    .request(Work::Hold(entered, release_rx), &cancellation)
                    .await
            });
            entered_rx.await.map_err(|_| SpoolError::Closed)?;
            Ok::<_, SpoolError>(spool)
        })?;
        let started = std::time::Instant::now();
        drop(runtime);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(spool.metrics().closed);
        assert_eq!(spool.metrics().operations_in_flight, 1);
        release.send(())?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(spool.close(&token))?;
        assert_eq!(spool.metrics().operations_in_flight, 0);
        Ok(())
    }
}

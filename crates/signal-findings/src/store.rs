use crate::{DetectionSeverity, Finding, encode};
use signal_protocol::findings_feed::{FindingsCursor, FindingsFeedQuery};
#[path = "feed.rs"]
mod feed;
use chrono::{DateTime, Datelike, Utc};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
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

/// Authenticated journal frame header: payload length, payload CRC and header CRC.
pub const FINDING_FRAME_BYTES: usize = 12;
fn frame_header(data: &[u8]) -> [u8; FINDING_FRAME_BYTES] {
    let mut header = [0; FINDING_FRAME_BYTES];
    header[..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    header[4..8].copy_from_slice(&crc32fast::hash(data).to_le_bytes());
    let crc = crc32fast::hash(&header[..8]);
    header[8..].copy_from_slice(&crc.to_le_bytes());
    header
}

#[derive(Debug, Error)]
pub enum FindingError {
    #[error("invalid finding/configuration: {0}")]
    Invalid(&'static str),
    #[error("findings cursor stream mismatch")]
    CursorStreamMismatch,
    #[error("findings cursor position unavailable")]
    CursorPositionUnavailable,
    #[error("findings cursor history mismatch")]
    CursorHistoryMismatch,
    #[error("findings feed page budget exceeded")]
    PageBudgetExceeded,
    #[error("finding journal I/O failed")]
    Io(#[source] std::io::Error),
    #[error("finding journal corrupt: {0}")]
    Corrupt(&'static str),
    #[error("finding identity conflicts with persisted content")]
    Conflict,
    #[error("finding store quota exceeded")]
    Quota,
    #[error("finding store operation capacity exhausted")]
    Full,
    #[error("finding store is closed")]
    Closed,
    #[error("finding store operation timed out")]
    Timeout,
    #[error("finding store operation cancelled")]
    Cancelled,
    #[error("finding root is locked")]
    Locked,
    #[error("finding stream identity mismatch")]
    StreamMismatch,
}
fn io(e: std::io::Error) -> FindingError {
    FindingError::Io(e)
}
#[derive(Clone, Debug)]
pub struct FindingContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
impl FindingContext {
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancellation: CancellationToken::new(),
        }
    }
    fn check(&self) -> Result<(), FindingError> {
        if self.cancellation.is_cancelled() {
            Err(FindingError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(FindingError::Timeout)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug)]
pub struct FindingConfig {
    pub directory: PathBuf,
    pub max_disk_bytes: u64,
    pub max_findings: usize,
    pub max_record_bytes: usize,
    pub max_append_rows: usize,
    pub max_append_bytes: usize,
    pub max_query_rows: usize,
    pub max_query_bytes: usize,
    pub max_index_bytes: usize,
    pub command_capacity: usize,
    pub operation_timeout: Duration,
}
impl Default for FindingConfig {
    fn default() -> Self {
        Self {
            directory: "data/findings".into(),
            max_disk_bytes: 256 * 1024 * 1024,
            max_findings: 100_000,
            max_record_bytes: 65536,
            max_append_rows: 1000,
            max_append_bytes: 1024 * 1024,
            max_query_rows: 1000,
            max_query_bytes: 8 * 1024 * 1024,
            max_index_bytes: 16 * 1024 * 1024,
            command_capacity: 8,
            operation_timeout: Duration::from_secs(5),
        }
    }
}
impl FindingConfig {
    /// Required for deployments enabling the feed. Cursor-free library users may
    /// retain smaller query budgets; those per-call feeds fail without progress.
    pub fn validate_feed(&self) -> Result<(), FindingError> {
        self.validate()?;
        if self.max_query_bytes < 2 * signal_protocol::findings_feed::FINDINGS_FEED_EMPTY_BYTES {
            return Err(FindingError::Invalid(
                "feed requires an empty response budget",
            ));
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.directory.as_os_str().is_empty()
            || self.max_disk_bytes < 24
            || self.max_disk_bytes > 64 * 1024 * 1024 * 1024
            || self.max_findings > 1_000_000
            || self.max_findings == 0
            || self.max_record_bytes == 0
            || self.max_record_bytes > 65536
            || self.max_append_rows == 0
            || self.max_append_rows > 10000
            || self.max_append_bytes < self.max_record_bytes + FINDING_FRAME_BYTES
            || self.max_append_bytes > 16 * 1024 * 1024
            || self.max_query_rows == 0
            || self.max_query_rows > 10000
            || self.max_query_bytes == 0
            || self.max_query_bytes > 64 * 1024 * 1024
            || self.max_index_bytes < INDEX_BYTES
            || self.max_index_bytes > 256 * 1024 * 1024
            || self.command_capacity == 0
            || self.command_capacity > 1024
            || self.operation_timeout > Duration::from_secs(300)
            || self.operation_timeout.is_zero()
        {
            return Err(FindingError::Invalid("store limits"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default)]
pub struct FindingQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub severity: Option<DetectionSeverity>,
    pub rule_id: Option<String>,
    pub limit: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FindingReceipt {
    pub inserted: usize,
    pub duplicates: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct FindingMetrics {
    pub command_depth: usize,
    pub command_capacity: usize,
    pub disk_capacity: u64,
    pub index_capacity: usize,
    pub finding_capacity: usize,
    pub inserted: u64,
    pub duplicates: u64,
    pub findings: usize,
    pub disk_bytes: u64,
    pub index_bytes: usize,
    pub operations_in_flight: usize,
    pub operation_capacity: usize,
    pub rejections: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub closed: bool,
}
/// Upgrade preflight: each unique finding requires this conservative index charge.
/// Covers three map nodes, HashMap spare buckets, UUID/keys, prefix digest and allocator overhead.
pub const FINDING_INDEX_BYTES: usize = 512;
const INDEX_BYTES: usize = FINDING_INDEX_BYTES;
struct AppendEntry {
    id: Uuid,
    cursor: FindingsCursor,
}
struct Entry {
    offset: u64,
    len: usize,
}
struct Engine {
    file: File,
    _lock: File,
    ids: HashMap<Uuid, Entry>,
    order: BTreeMap<(DateTime<Utc>, Uuid), ()>,
    bytes: u64,
    prefix: FindingsCursor,
    append_order: BTreeMap<u64, AppendEntry>,
    config: FindingConfig,
}
fn safe_path(path: &Path, directory: bool) -> Result<(), FindingError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(FindingError::Corrupt("symlink path"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
    }
    if let Ok(m) = fs::symlink_metadata(path)
        && ((directory && !m.is_dir()) || (!directory && !m.is_file()))
    {
        return Err(FindingError::Corrupt("path type"));
    }
    Ok(())
}
impl Engine {
    fn open(
        config: FindingConfig,
        stream: Uuid,
        context: &FindingContext,
    ) -> Result<Self, FindingError> {
        context.check()?;
        safe_path(&config.directory, true)?;
        fs::create_dir_all(&config.directory).map_err(io)?;
        for entry in fs::read_dir(&config.directory).map_err(io)? {
            let entry = entry.map_err(io)?;
            if entry.file_name() != ".lock"
                && entry.file_name() != "findings.journal"
                && entry.file_name() != "findings.journal.tmp"
            {
                return Err(FindingError::Corrupt("unknown root entry"));
            }
            safe_path(&entry.path(), false)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.directory.join(".lock"))
            .map_err(io)?;
        lock.try_lock().map_err(|_| FindingError::Locked)?;
        let path = config.directory.join("findings.journal");
        let temporary = config.directory.join("findings.journal.tmp");
        safe_path(&path, false)?;
        safe_path(&temporary, false)?;
        let exists = path.try_exists().map_err(io)?;
        if temporary.try_exists().map_err(io)? {
            // A temp without a final journal is an owned unfinished initial header.
            // A final plus temp is ambiguous and must not erase either artifact.
            if exists {
                return Err(FindingError::Corrupt("unexpected header temporary"));
            }
            fs::remove_file(&temporary).map_err(io)?;
        }
        if !exists {
            context.check()?;
            let mut initial = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(io)?;
            initial.write_all(b"SIGFND02").map_err(io)?;
            initial.write_all(stream.as_bytes()).map_err(io)?;
            initial.sync_all().map_err(io)?;
            context.check()?;
            fs::rename(&temporary, &path).map_err(io)?;
            File::open(&config.directory)
                .map_err(io)?
                .sync_all()
                .map_err(io)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io)?;
        let bytes = file.metadata().map_err(io)?.len();
        if bytes > config.max_disk_bytes {
            return Err(FindingError::Quota);
        }
        let mut header = [0; 24];
        file.read_exact(&mut header)
            .map_err(|_| FindingError::Corrupt("header"))?;
        if &header[..8] != b"SIGFND02" {
            return Err(FindingError::Corrupt("header magic"));
        }
        if &header[8..] != stream.as_bytes() {
            return Err(FindingError::StreamMismatch);
        }
        let mut engine = Self {
            file,
            _lock: lock,
            ids: HashMap::new(),
            order: BTreeMap::new(),
            bytes: bytes.max(24),
            prefix: FindingsCursor::initial(stream).map_err(|_| FindingError::Invalid("stream"))?,
            append_order: BTreeMap::new(),
            config,
        };
        let mut offset = 24;
        while offset < engine.bytes {
            context.check()?;
            if engine.bytes - offset < FINDING_FRAME_BYTES as u64 {
                engine.truncate(offset)?;
                break;
            }
            engine.file.seek(SeekFrom::Start(offset)).map_err(io)?;
            let mut header = [0; FINDING_FRAME_BYTES];
            engine.file.read_exact(&mut header).map_err(io)?;
            let header_crc = u32::from_le_bytes(
                header[8..]
                    .try_into()
                    .map_err(|_| FindingError::Corrupt("frame header"))?,
            );
            if crc32fast::hash(&header[..8]) != header_crc {
                return Err(FindingError::Corrupt("frame header checksum"));
            }
            let len = u32::from_le_bytes(
                header[..4]
                    .try_into()
                    .map_err(|_| FindingError::Corrupt("frame"))?,
            ) as usize;
            let crc = u32::from_le_bytes(
                header[4..8]
                    .try_into()
                    .map_err(|_| FindingError::Corrupt("frame"))?,
            );
            if len == 0 || len > engine.config.max_record_bytes {
                return Err(FindingError::Corrupt("record length"));
            }
            if engine.bytes - offset - (FINDING_FRAME_BYTES as u64) < len as u64 {
                engine.truncate(offset)?;
                break;
            }
            let mut data = vec![0; len];
            engine.file.read_exact(&mut data).map_err(io)?;
            if crc32fast::hash(&data) != crc {
                return Err(FindingError::Corrupt("record checksum"));
            }
            let finding: Finding =
                serde_json::from_slice(&data).map_err(|_| FindingError::Corrupt("record JSON"))?;
            finding
                .validate()
                .map_err(|_| FindingError::Corrupt("record contract"))?;
            if let Some(entry) = engine.ids.get(&finding.id) {
                let entry = Entry {
                    offset: entry.offset,
                    len: entry.len,
                };
                if engine.read(&entry)? != finding {
                    return Err(FindingError::Conflict);
                }
            } else {
                engine.reserve(1)?;
                engine.insert(&finding, offset + FINDING_FRAME_BYTES as u64, &data)?;
            }
            offset += FINDING_FRAME_BYTES as u64 + len as u64;
        }
        context.check()?;
        // Complete frames surviving a crash are not exposed until the validated
        // retained journal has itself been synced, even if no tail was truncated.
        engine.file.sync_all().map_err(io)?;
        context.check()?;
        Ok(engine)
    }
    fn truncate(&mut self, offset: u64) -> Result<(), FindingError> {
        self.file.set_len(offset).map_err(io)?;
        self.file.sync_all().map_err(io)?;
        self.bytes = offset;
        Ok(())
    }
    fn reserve(&self, count: usize) -> Result<(), FindingError> {
        let rows = self
            .ids
            .len()
            .checked_add(count)
            .ok_or(FindingError::Quota)?;
        self.prefix
            .position()
            .checked_add(u64::try_from(count).map_err(|_| FindingError::Quota)?)
            .ok_or(FindingError::Quota)?;
        if rows > self.config.max_findings
            || rows
                .checked_mul(INDEX_BYTES)
                .is_none_or(|bytes| bytes > self.config.max_index_bytes)
        {
            return Err(FindingError::Quota);
        }
        Ok(())
    }
    fn insert(&mut self, f: &Finding, offset: u64, data: &[u8]) -> Result<(), FindingError> {
        let cursor = self.prefix.advance(data).map_err(|_| FindingError::Quota)?;
        self.ids.insert(
            f.id,
            Entry {
                offset,
                len: data.len(),
            },
        );
        self.order.insert((f.created_at, f.id), ());
        self.append_order
            .insert(cursor.position(), AppendEntry { id: f.id, cursor });
        self.prefix = cursor;
        Ok(())
    }
    fn read(&mut self, e: &Entry) -> Result<Finding, FindingError> {
        self.file.seek(SeekFrom::Start(e.offset)).map_err(io)?;
        let mut data = vec![0; e.len];
        self.file.read_exact(&mut data).map_err(io)?;
        serde_json::from_slice(&data).map_err(|_| FindingError::Corrupt("record JSON"))
    }
    fn append(
        &mut self,
        batch: Vec<Finding>,
        ctx: &FindingContext,
        started: &AtomicBool,
    ) -> Result<FindingReceipt, FindingError> {
        let mut pending: BTreeMap<Uuid, (Finding, Vec<u8>)> = BTreeMap::new();
        let mut receipt = FindingReceipt::default();
        let mut added = 0u64;
        for finding in batch {
            ctx.check()?;
            if let Some(e) = self.ids.get(&finding.id) {
                let e = Entry {
                    offset: e.offset,
                    len: e.len,
                };
                if self.read(&e)? != finding {
                    return Err(FindingError::Conflict);
                }
                receipt.duplicates += 1;
            } else if let Some((existing, _)) = pending.get(&finding.id) {
                if existing != &finding {
                    return Err(FindingError::Conflict);
                }
                receipt.duplicates += 1;
            } else {
                let data = encode(&finding, self.config.max_record_bytes)?;
                added += FINDING_FRAME_BYTES as u64 + data.len() as u64;
                pending.insert(finding.id, (finding, data));
            }
        }
        self.reserve(pending.len())?;
        if self
            .bytes
            .checked_add(added)
            .is_none_or(|n| n > self.config.max_disk_bytes)
        {
            return Err(FindingError::Quota);
        }
        ctx.check()?;
        if pending.is_empty() {
            return Ok(receipt);
        }
        started.store(true, Ordering::Release);
        self.file.seek(SeekFrom::Start(self.bytes)).map_err(io)?;
        for (_, data) in pending.values() {
            ctx.check()?;
            self.file.write_all(&frame_header(data)).map_err(io)?;
            self.file.write_all(data).map_err(io)?;
        }
        self.file.sync_all().map_err(io)?;
        ctx.check()?;
        for (finding, data) in pending.values() {
            self.insert(finding, self.bytes + FINDING_FRAME_BYTES as u64, data)?;
            self.bytes += FINDING_FRAME_BYTES as u64 + data.len() as u64;
            receipt.inserted += 1;
        }
        ctx.check()?;
        Ok(receipt)
    }
    fn query(
        &mut self,
        q: FindingQuery,
        ctx: &FindingContext,
    ) -> Result<Vec<Finding>, FindingError> {
        let mut out = Vec::new();
        let mut bytes = 2usize;
        // Index keys are copied only up to the bounded response size. Iterate by cursor
        // so sparse filters never allocate a vector of all finding IDs.
        let mut cursor = q.from.map(|t| (t, Uuid::nil()));
        let mut inclusive = true;
        loop {
            ctx.check()?;
            use std::ops::Bound::{Excluded, Included, Unbounded};
            let start = match cursor {
                Some(c) if inclusive => Included(c),
                Some(c) => Excluded(c),
                None => Unbounded,
            };
            let next = self
                .order
                .range((start, Unbounded))
                .next()
                .map(|(key, _)| *key);
            let Some(key) = next else {
                break;
            };
            if q.to.is_some_and(|to| key.0 >= to) {
                break;
            }
            cursor = Some(key);
            inclusive = false;
            let e = self.ids.get(&key.1).ok_or(FindingError::Corrupt("index"))?;
            let e = Entry {
                offset: e.offset,
                len: e.len,
            };
            let f = self.read(&e)?;
            if q.severity.is_some_and(|s| s != f.severity)
                || q.rule_id.as_ref().is_some_and(|r| r != &f.rule_id)
            {
                continue;
            }
            // Conservative JSON expansion charge includes map/array nodes, strings,
            // Vec spare capacity and the encoded temporary record. Record/depth/node
            // bounds additionally cap the one transient filtered-out decoded row.
            let charge = e
                .len
                .checked_mul(64)
                .and_then(|n| n.checked_add(std::mem::size_of::<Finding>()))
                .ok_or(FindingError::Quota)?;
            bytes = bytes.checked_add(charge).ok_or(FindingError::Quota)?;
            if bytes > self.config.max_query_bytes {
                return Err(FindingError::Quota);
            }
            out.push(f);
            if out.len() == q.limit {
                break;
            }
        }
        ctx.check()?;
        Ok(out)
    }
}
struct Shared {
    inserted: AtomicU64,
    duplicates: AtomicU64,
    closed: AtomicBool,
    stopping: AtomicBool,
    snapshot: Mutex<FindingMetrics>,
    rejections: AtomicU64,
    failures: AtomicU64,
    timeouts: AtomicU64,
}
impl Shared {
    fn fail(&self) {
        self.closed.store(true, Ordering::Release);
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}
enum Operation {
    Append(Vec<Finding>),
    Query(FindingQuery),
    Feed(FindingsFeedQuery, usize),
    Flush,
    Stop,
    #[cfg(test)]
    Pause(
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
        bool,
    ),
}
impl Operation {
    fn mutation(&self) -> bool {
        match self {
            Self::Append(_) | Self::Flush => true,
            Self::Query(_) | Self::Feed(_, _) | Self::Stop => false,
            #[cfg(test)]
            Self::Pause(_, _, mutation) => *mutation,
        }
    }
}
enum Reply {
    Receipt(FindingReceipt),
    Findings(Vec<Finding>),
    Feed(Vec<u8>),
    Done,
}
struct Command {
    operation: Operation,
    context: FindingContext,
    started: Arc<AtomicBool>,
    reply: oneshot::Sender<Result<Reply, FindingError>>,
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}
struct Guard {
    token: CancellationToken,
    shared: Arc<Shared>,
    started: Arc<AtomicBool>,
    mutation: bool,
    completed: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.token.cancel();
        if !self.completed && self.mutation && self.started.load(Ordering::Acquire) {
            self.shared.fail();
        }
    }
}
struct Exit(Arc<Shared>);
impl Drop for Exit {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
    }
}
/// A fixed ordinary disk worker owns the journal and root lock. All queued,
/// active and completed-but-unpolled operations retain a capacity permit.
/// Disk syscalls cannot be forcibly cancelled: an uncertain append fails closed,
/// its worker keeps ownership until the syscall returns, and reopen replays WAL.
pub struct FindingStore {
    sender: mpsc::Sender<Command>,
    shared: Arc<Shared>,
    config: FindingConfig,
    permits: Arc<Semaphore>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl FindingStore {
    pub async fn open(config: FindingConfig, stream_id: Uuid) -> Result<Self, FindingError> {
        config.validate()?;
        if stream_id.is_nil() {
            return Err(FindingError::Invalid("stream identity"));
        }
        let shared = Arc::new(Shared {
            inserted: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            snapshot: Mutex::new(FindingMetrics::default()),
            rejections: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
        });
        let (sender, mut receiver) = mpsc::channel::<Command>(config.command_capacity + 1);
        let (ready, response) = oneshot::channel();
        let worker_shared = shared.clone();
        let worker_config = config.clone();
        let context = FindingContext::new(config.operation_timeout);
        let worker_context = context.clone();
        let worker = thread::Builder::new()
            .name("signal-findings".into())
            .spawn(move || {
                let _exit = Exit(worker_shared.clone());
                let mut engine = match Engine::open(worker_config, stream_id, &worker_context) {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                publish(&worker_shared, &engine);
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Some(command) = receiver.blocking_recv() {
                    if worker_shared.stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let mutation =
                        matches!(command.operation, Operation::Append(_) | Operation::Flush);
                    let result = if worker_shared.closed.load(Ordering::Acquire) {
                        Err(FindingError::Closed)
                    } else if command.reply.is_closed() {
                        Err(FindingError::Cancelled)
                    } else {
                        command
                            .context
                            .check()
                            .and_then(|()| match command.operation {
                                Operation::Stop => Err(FindingError::Closed),
                                Operation::Append(batch) => engine
                                    .append(batch, &command.context, &command.started)
                                    .map(Reply::Receipt),
                                Operation::Query(q) => {
                                    engine.query(q, &command.context).map(Reply::Findings)
                                }
                                Operation::Feed(q, max_bytes) => {
                                    engine.feed(q, max_bytes, &command.context).map(Reply::Feed)
                                }
                                Operation::Flush => {
                                    command.started.store(true, Ordering::Release);
                                    engine
                                        .file
                                        .sync_all()
                                        .map_err(io)
                                        .and_then(|()| command.context.check())
                                        .map(|()| Reply::Done)
                                }
                                #[cfg(test)]
                                Operation::Pause(started, release, mutation) => {
                                    if mutation {
                                        command.started.store(true, Ordering::Release);
                                    }
                                    let _ = started.send(());
                                    release
                                        .recv_timeout(Duration::from_secs(2))
                                        .map_err(|_| FindingError::Timeout)
                                        .and_then(|()| command.context.check())
                                        .map(|()| Reply::Done)
                                }
                            })
                    };
                    if matches!(result, Err(FindingError::Io(_) | FindingError::Corrupt(_)))
                        || (mutation && command.started.load(Ordering::Acquire) && result.is_err())
                    {
                        worker_shared.fail();
                    }
                    if matches!(
                        result,
                        Err(FindingError::Quota
                            | FindingError::Conflict
                            | FindingError::PageBudgetExceeded
                            | FindingError::CursorStreamMismatch
                            | FindingError::CursorPositionUnavailable
                            | FindingError::CursorHistoryMismatch)
                    ) {
                        worker_shared.rejections.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Ok(Reply::Receipt(receipt)) = &result {
                        worker_shared
                            .inserted
                            .fetch_add(receipt.inserted as u64, Ordering::Relaxed);
                        worker_shared
                            .duplicates
                            .fetch_add(receipt.duplicates as u64, Ordering::Relaxed);
                    }
                    publish(&worker_shared, &engine);
                    // Shared permit in the reply retains resource admission until caller polls.
                    let _ = command.reply.send(result);
                }
            })
            .map_err(io)?;
        let result = timeout_at(context.deadline, response).await;
        match result {
            Ok(Ok(Ok(()))) => Ok(Self {
                sender,
                shared,
                permits: Arc::new(Semaphore::new(config.command_capacity)),
                config,
                worker: Mutex::new(Some(worker)),
            }),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(FindingError::Closed),
            Err(_) => {
                context.cancellation.cancel();
                shared.stopping.store(true, Ordering::Release);
                Err(FindingError::Timeout)
            }
        }
    }
    async fn command(
        &self,
        operation: Operation,
        mut context: FindingContext,
    ) -> Result<Reply, FindingError> {
        if self.shared.closed.load(Ordering::Acquire)
            || self.shared.stopping.load(Ordering::Acquire)
        {
            return Err(FindingError::Closed);
        }
        context.deadline = context
            .deadline
            .min(Instant::now() + self.config.operation_timeout);
        context.check()?;
        let permit = Arc::new(self.permits.clone().try_acquire_owned().map_err(|_| {
            self.shared.rejections.fetch_add(1, Ordering::Relaxed);
            FindingError::Full
        })?);
        let mutation = operation.mutation();
        context.cancellation = context.cancellation.child_token();
        let started = Arc::new(AtomicBool::new(false));
        let mut guard = Guard {
            token: context.cancellation.clone(),
            shared: self.shared.clone(),
            started: started.clone(),
            mutation,
            completed: false,
        };
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Command {
                operation,
                context: context.clone(),
                started,
                reply,
                _permit: Some(permit.clone()),
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => FindingError::Full,
                mpsc::error::TrySendError::Closed(_) => FindingError::Closed,
            })?;
        let result = tokio::select! { result = timeout_at(context.deadline, response) => match result { Ok(Ok(r)) => r, Ok(Err(_)) => Err(FindingError::Closed), Err(_) => Err(FindingError::Timeout) }, () = context.cancellation.cancelled() => Err(FindingError::Cancelled) };
        if matches!(result, Err(FindingError::Timeout)) {
            self.shared.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        guard.completed = !matches!(result, Err(FindingError::Timeout | FindingError::Cancelled));
        result
    }
    /// Syncs the entire batch once before returning. Identical replay is a no-op;
    /// conflicting content for an existing identity is rejected before mutation.
    pub async fn append(
        &self,
        batch: Vec<Finding>,
        context: FindingContext,
    ) -> Result<FindingReceipt, FindingError> {
        let validation = (|| {
            if batch.len() > self.config.max_append_rows {
                return Err(FindingError::Quota);
            }
            let mut bytes = 0usize;
            for finding in &batch {
                finding.validate()?;
                let size = encode(finding, self.config.max_record_bytes)?.len();
                bytes = bytes
                    .checked_add(size + FINDING_FRAME_BYTES)
                    .ok_or(FindingError::Quota)?;
                if bytes > self.config.max_append_bytes {
                    return Err(FindingError::Quota);
                }
            }
            Ok(())
        })();
        if let Err(error) = validation {
            self.shared.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        match self.command(Operation::Append(batch), context).await? {
            Reply::Receipt(r) => Ok(r),
            _ => Err(FindingError::Closed),
        }
    }
    /// Lists findings in ascending `(created_at, id)` order, with `[from,to)`.
    /// Limit is mandatory and may not exceed the configured server bound.
    pub async fn query(
        &self,
        query: FindingQuery,
        context: FindingContext,
    ) -> Result<Vec<Finding>, FindingError> {
        if query.from.is_some_and(|t| !(0..=9999).contains(&t.year()))
            || query.to.is_some_and(|t| !(0..=9999).contains(&t.year()))
            || query.limit == 0
            || query.limit > self.config.max_query_rows
            || query
                .from
                .zip(query.to)
                .is_some_and(|(from, to)| from >= to)
            || query
                .rule_id
                .as_ref()
                .is_some_and(|r| r.trim().is_empty() || r.len() > 256)
        {
            return Err(FindingError::Invalid("query"));
        }
        match self.command(Operation::Query(query), context).await? {
            Reply::Findings(f) => Ok(f),
            _ => Err(FindingError::Closed),
        }
    }
    /// A serialized version-1 append feed, bounded before decoding and output allocation.
    /// The existing query budget covers decoded page and encoded output together.
    /// Returned caller-owned buffers additionally require a caller concurrency budget;
    /// the server uses its bounded transport connection count/lifetime.
    pub async fn feed(
        &self,
        query: FindingsFeedQuery,
        max_response_bytes: usize,
        context: FindingContext,
    ) -> Result<Vec<u8>, FindingError> {
        if query.limit == 0 || query.limit > self.config.max_query_rows || max_response_bytes == 0 {
            self.shared.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(FindingError::Invalid("feed query"));
        }
        match self
            .command(
                Operation::Feed(query, max_response_bytes.min(self.config.max_query_bytes)),
                context,
            )
            .await?
        {
            Reply::Feed(bytes) => Ok(bytes),
            _ => Err(FindingError::Closed),
        }
    }
    pub async fn flush(&self, context: FindingContext) -> Result<(), FindingError> {
        match self.command(Operation::Flush, context).await? {
            Reply::Done => Ok(()),
            _ => Err(FindingError::Closed),
        }
    }
    pub fn metrics(&self) -> FindingMetrics {
        let mut m = self.shared.snapshot.lock().map(|m| *m).unwrap_or_default();
        m.command_depth = self.sender.max_capacity() - self.sender.capacity();
        m.command_capacity = self.sender.max_capacity();
        m.disk_capacity = self.config.max_disk_bytes;
        m.index_capacity = self.config.max_index_bytes;
        m.finding_capacity = self.config.max_findings;
        m.inserted = self.shared.inserted.load(Ordering::Relaxed);
        m.duplicates = self.shared.duplicates.load(Ordering::Relaxed);
        m.operations_in_flight = self.config.command_capacity - self.permits.available_permits();
        m.operation_capacity = self.config.command_capacity;
        m.rejections = self.shared.rejections.load(Ordering::Relaxed);
        m.failures = self.shared.failures.load(Ordering::Relaxed);
        m.timeouts = self.shared.timeouts.load(Ordering::Relaxed);
        m.closed = self.shared.closed.load(Ordering::Acquire)
            || self.shared.stopping.load(Ordering::Acquire);
        m
    }
    /// Stop dispatch and await physical worker completion within a deadline.
    /// On deadline expiry the thread retains the root lock until I/O returns.
    pub async fn shutdown(&self, context: FindingContext) -> Result<(), FindingError> {
        self.shared.stopping.store(true, Ordering::Release);
        loop {
            context.check()?;
            let finished = self
                .worker
                .lock()
                .map_err(|_| FindingError::Closed)?
                .as_ref()
                .is_none_or(|h| h.is_finished());
            if finished {
                if let Some(worker) = self.worker.lock().map_err(|_| FindingError::Closed)?.take() {
                    worker.join().map_err(|_| FindingError::Closed)?;
                }
                return Ok(());
            }
            // The queue has one reserved control slot beyond data-operation permits.
            // Completed but unpolled replies may hold every data permit while the
            // worker is idle, so shutdown must not need another data permit.
            let (reply, _) = oneshot::channel();
            let _ = self.sender.try_send(Command {
                operation: Operation::Stop,
                context: context.clone(),
                started: Arc::new(AtomicBool::new(false)),
                reply,
                _permit: None,
            });
            tokio::select! { () = tokio::time::sleep(Duration::from_millis(2)) => {}, () = context.cancellation.cancelled() => return Err(FindingError::Cancelled) }
        }
    }
}
impl Drop for FindingStore {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
    }
}
fn publish(shared: &Shared, engine: &Engine) {
    if let Ok(mut m) = shared.snapshot.lock() {
        m.findings = engine.ids.len();
        m.disk_bytes = engine.bytes;
        m.index_bytes = engine.ids.len() * INDEX_BYTES;
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn ctx() -> FindingContext {
        FindingContext::new(Duration::from_secs(2))
    }
    fn query() -> FindingQuery {
        FindingQuery {
            limit: 1,
            ..Default::default()
        }
    }
    async fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> bool {
        let mut future = future;
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_ready())).await
    }
    async fn settle(store: &FindingStore, count: usize) -> Result<(), FindingError> {
        let deadline = Instant::now() + Duration::from_secs(1);
        while store.metrics().operations_in_flight != count {
            if Instant::now() >= deadline {
                return Err(FindingError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok(())
    }
    #[tokio::test]
    async fn active_and_queued_abort_retain_permits_until_worker_finishes() -> TestResult {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(
            FindingStore::open(
                FindingConfig {
                    directory: temp.path().into(),
                    command_capacity: 2,
                    ..Default::default()
                },
                Uuid::new_v4(),
            )
            .await?,
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let active_store = store.clone();
        let active = tokio::spawn(async move {
            active_store
                .command(Operation::Pause(started_tx, release_rx, false), ctx())
                .await
        });
        tokio::task::yield_now().await;
        started_rx.recv_timeout(Duration::from_secs(1))?;
        let mut queued = Box::pin(store.query(query(), ctx()));
        assert!(!poll_once(queued.as_mut()).await);
        drop(queued);
        active.abort();
        let _ = active.await;
        assert_eq!(store.metrics().operations_in_flight, 2);
        assert!(matches!(
            store.query(query(), ctx()).await,
            Err(FindingError::Full)
        ));
        release_tx.send(())?;
        settle(&store, 0).await?;
        assert!(!store.metrics().closed);
        store.query(query(), ctx()).await?;
        store.shutdown(ctx()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn active_mutation_abort_fails_closed_and_keeps_worker_lock() -> TestResult {
        let temp = tempfile::tempdir()?;
        let cfg = FindingConfig {
            directory: temp.path().into(),
            command_capacity: 2,
            ..Default::default()
        };
        let stream = Uuid::new_v4();
        let store = Arc::new(FindingStore::open(cfg.clone(), stream).await?);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let active_store = store.clone();
        let active = tokio::spawn(async move {
            active_store
                .command(Operation::Pause(started_tx, release_rx, true), ctx())
                .await
        });
        tokio::task::yield_now().await;
        started_rx.recv_timeout(Duration::from_secs(1))?;
        active.abort();
        let _ = active.await;
        assert!(store.metrics().closed);
        assert_eq!(store.metrics().operations_in_flight, 1);
        assert!(matches!(
            FindingStore::open(cfg.clone(), stream).await,
            Err(FindingError::Locked)
        ));
        assert!(matches!(
            store.append(Vec::new(), ctx()).await,
            Err(FindingError::Closed)
        ));
        release_tx.send(())?;
        store.shutdown(ctx()).await?;
        let reopened = FindingStore::open(cfg, stream).await?;
        reopened.shutdown(ctx()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn completed_unpolled_reply_retains_operation_capacity() -> TestResult {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(
            FindingStore::open(
                FindingConfig {
                    directory: temp.path().into(),
                    command_capacity: 2,
                    ..Default::default()
                },
                Uuid::new_v4(),
            )
            .await?,
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let paused_store = store.clone();
        let paused = tokio::spawn(async move {
            paused_store
                .command(Operation::Pause(started_tx, release_rx, false), ctx())
                .await
        });
        tokio::task::yield_now().await;
        started_rx.recv_timeout(Duration::from_secs(1))?;
        let mut first = Box::pin(store.query(query(), ctx()));
        assert!(!poll_once(first.as_mut()).await);
        release_tx.send(())?;
        paused.await??;
        // Awaiting the pause drains its permit; the unpolled reply retains one.
        settle(&store, 1).await?;
        let spare = store.permits.clone().try_acquire_owned()?;
        assert!(matches!(
            store.query(query(), ctx()).await,
            Err(FindingError::Full)
        ));
        first.await?;
        drop(spare);
        settle(&store, 0).await?;
        store.shutdown(ctx()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn shutdown_wakes_idle_worker_while_unpolled_reply_holds_all_permits() -> TestResult {
        let temp = tempfile::tempdir()?;
        let store = FindingStore::open(
            FindingConfig {
                directory: temp.path().into(),
                command_capacity: 3,
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await?;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut paused =
            Box::pin(store.command(Operation::Pause(started_tx, release_rx, false), ctx()));
        assert!(!poll_once(paused.as_mut()).await);
        started_rx.recv_timeout(Duration::from_secs(1))?;
        let mut first = Box::pin(store.query(query(), ctx()));
        let mut second = Box::pin(store.query(query(), ctx()));
        assert!(!poll_once(first.as_mut()).await);
        assert!(!poll_once(second.as_mut()).await);
        release_tx.send(())?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while store.metrics().command_depth != 0 {
            if Instant::now() >= deadline {
                return Err(FindingError::Timeout.into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(store.metrics().operations_in_flight, 3);
        assert_eq!(store.metrics().command_depth, 0);
        store
            .shutdown(FindingContext::new(Duration::from_millis(100)))
            .await?;
        paused.await?;
        first.await?;
        second.await?;
        Ok(())
    }
    #[tokio::test]
    async fn read_timeout_does_not_close_store_and_shutdown_deadline_is_bounded() -> TestResult {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(
            FindingStore::open(
                FindingConfig {
                    directory: temp.path().into(),
                    command_capacity: 2,
                    ..Default::default()
                },
                Uuid::new_v4(),
            )
            .await?,
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let active_store = store.clone();
        let active = tokio::spawn(async move {
            active_store
                .command(
                    Operation::Pause(started_tx, release_rx, false),
                    FindingContext::new(Duration::from_millis(50)),
                )
                .await
        });
        tokio::task::yield_now().await;
        started_rx.recv_timeout(Duration::from_secs(1))?;
        assert!(matches!(active.await?, Err(FindingError::Timeout)));
        assert!(!store.metrics().closed);
        assert_eq!(store.metrics().operations_in_flight, 1);
        assert!(matches!(
            store
                .shutdown(FindingContext::new(Duration::from_millis(10)))
                .await,
            Err(FindingError::Timeout)
        ));
        release_tx.send(())?;
        store.shutdown(ctx()).await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "feed_tests.rs"]
mod feed_tests;

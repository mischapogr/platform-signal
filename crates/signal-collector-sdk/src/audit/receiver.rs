//! Restricted, finite Linux receipt journal. Authentication and independently
//! current restore witnesses belong to the host, not record contents or hashes.
use crate::{
    ExtensionContext,
    transport::worker::{Worker, WorkerError},
};
use sha2::{Digest, Sha256};
use signal_protocol::audit::{AuditAcknowledgement, PreparedAudit, RECORD_BYTES};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

static DISK: Worker = Worker::new();
const HEADER: usize = 72;
const CONTROL: usize = 32;
const MAGIC: &[u8; 8] = b"SIGAUD01";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceiverError {
    #[error("invalid audit receiver configuration or document")]
    Invalid,
    #[error("audit receiver capacity is occupied")]
    Busy,
    #[error("audit receiver capacity is exhausted")]
    Full,
    #[error("audit publisher is not permitted")]
    Denied,
    #[error("audit receipt conflicts with retained history")]
    Conflict,
    #[error("audit receiver history requires reconciliation")]
    History,
    #[error("audit receiver operation is uncertain")]
    Uncertain,
}

#[derive(Clone, Copy, Debug)]
pub struct ReceiverLimits {
    pub max_bytes: u64,
    pub max_records: usize,
    pub max_producers: usize,
}
impl ReceiverLimits {
    fn validate(self) -> Result<Self, ReceiverError> {
        if self.max_bytes < (HEADER + RECORD_BYTES) as u64
            || self.max_bytes > 64 * 1024 * 1024
            || !(1..=16_384).contains(&self.max_records)
            || !(1..=256).contains(&self.max_producers)
        {
            return Err(ReceiverError::Invalid);
        }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug)]
pub enum OpenMode {
    Initialize,
    Existing,
}

/// Construct only after the host authenticates and selects a configured producer
/// namespace. Neither this constructor nor a parsed producer UUID authenticates
/// an HTTP request. Never construct it from unverified body/header claims.
pub struct TrustedProducer(Uuid);
impl TrustedProducer {
    pub fn from_authenticated_namespace(id: Uuid) -> Result<Self, ReceiverError> {
        if id.is_nil() {
            return Err(ReceiverError::Denied);
        }
        Ok(Self(id))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReceiverHealth {
    pub records: usize,
    pub bytes: u64,
    pub record_capacity: usize,
    pub byte_capacity: u64,
    pub physical_depth: usize,
    pub physical_capacity: usize,
    pub physical_rejected: u64,
    pub rejected: u64,
    pub uncertain: u64,
    pub held: bool,
}
#[derive(Default)]
struct State {
    records: AtomicUsize,
    bytes: AtomicU64,
    rejected: AtomicU64,
    uncertain: AtomicU64,
    held: AtomicBool,
}
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
struct Entry {
    producer: Uuid,
    sequence: u64,
    id: Uuid,
    offset: u64,
    len: usize,
}
struct Engine {
    path: PathBuf,
    directory: File,
    lock: Lock,
    control: File,
    identity: [u8; CONTROL],
    journal: File,
    limits: ReceiverLimits,
    entries: Vec<Entry>,
    producers: Vec<Uuid>,
    bytes: u64,
    state: Arc<State>,
    #[cfg(test)]
    pause: Option<Pause>,
    #[cfg(test)]
    pause_before_arm: Option<Pause>,
}
#[cfg(test)]
struct Pause {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
fn history(_: std::io::Error) -> ReceiverError {
    ReceiverError::History
}
fn live(ctx: &ExtensionContext) -> Result<(), ReceiverError> {
    ctx.check().map_err(|_| ReceiverError::Uncertain)
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn private(file: &File, cap: u64) -> Result<(), ReceiverError> {
    let m = file.metadata().map_err(history)?;
    let uid = fs::metadata("/proc/self").map_err(history)?.uid();
    if !m.is_file()
        || m.uid() != uid
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > cap
    {
        return Err(ReceiverError::History);
    }
    Ok(())
}
fn anchored(directory: &File, name: &'static str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{name}", directory.as_raw_fd()))
}
fn open_file(
    directory: &File,
    name: &'static str,
    create: bool,
    cap: u64,
) -> Result<File, ReceiverError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(anchored(directory, name))
        .map_err(history)?;
    private(&file, cap)?;
    Ok(file)
}
impl Engine {
    fn open(
        path: PathBuf,
        mode: OpenMode,
        limits: ReceiverLimits,
        state: Arc<State>,
        ctx: &ExtensionContext,
    ) -> Result<Self, ReceiverError> {
        live(ctx)?;
        let original = fs::symlink_metadata(&path).map_err(history)?;
        let uid = fs::metadata("/proc/self").map_err(history)?.uid();
        if !original.is_dir()
            || original.file_type().is_symlink()
            || original.uid() != uid
            || original.mode() & 0o777 != 0o700
        {
            return Err(ReceiverError::Invalid);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(history)?;
        if !same(&original, &directory.metadata().map_err(history)?) {
            return Err(ReceiverError::History);
        }
        let initialize = matches!(mode, OpenMode::Initialize);
        if initialize
            && fs::read_dir(anchored(&directory, "."))
                .map_err(history)?
                .next()
                .is_some()
        {
            return Err(ReceiverError::History);
        }
        let file = open_file(&directory, "lock", initialize, 0)?;
        file.try_lock().map_err(|_| ReceiverError::Busy)?;
        let lock = Lock(file);
        let mut control = open_file(&directory, "control", initialize, CONTROL as u64)?;
        let journal = open_file(&directory, "journal", initialize, limits.max_bytes)?;
        let mut control_body = [0u8; CONTROL];
        if initialize {
            control_body[..8].copy_from_slice(MAGIC);
            control_body[8..24].copy_from_slice(Uuid::new_v4().as_bytes());
            control.write_all(&control_body).map_err(history)?;
            control.sync_all().map_err(history)?;
            journal.sync_all().map_err(history)?;
            directory.sync_all().map_err(history)?;
        } else {
            control.read_exact(&mut control_body).map_err(history)?;
            if control_body[..8] != MAGIC[..]
                || control_body[24..] != [0u8; 8]
                || Uuid::from_slice(&control_body[8..24])
                    .map_err(|_| ReceiverError::History)?
                    .is_nil()
            {
                return Err(ReceiverError::History);
            }
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.max_records)
            .map_err(|_| ReceiverError::Full)?;
        let mut producers = Vec::new();
        producers
            .try_reserve_exact(limits.max_producers)
            .map_err(|_| ReceiverError::Full)?;
        let mut engine = Self {
            path,
            directory,
            lock,
            control,
            identity: control_body,
            journal,
            limits,
            entries,
            producers,
            bytes: 0,
            state,
            #[cfg(test)]
            pause: None,
            #[cfg(test)]
            pause_before_arm: None,
        };
        engine.stable(ctx, false)?;
        engine.recover(ctx)?;
        engine.stable(ctx, true)?;
        Ok(engine)
    }
    fn stable(&self, ctx: &ExtensionContext, size: bool) -> Result<(), ReceiverError> {
        live(ctx)?;
        if self.state.held.load(Ordering::Acquire) {
            return Err(ReceiverError::Uncertain);
        }
        let current = fs::symlink_metadata(&self.path).map_err(history)?;
        let root = self.directory.metadata().map_err(history)?;
        if current.file_type().is_symlink()
            || current.uid() != root.uid()
            || current.mode() & 0o777 != 0o700
            || !same(&current, &root)
        {
            return Err(ReceiverError::History);
        }
        // A hostile directory cannot add unchecked auxiliary files or aliases.
        let mut count = 0;
        for entry in fs::read_dir(anchored(&self.directory, ".")).map_err(history)? {
            live(ctx)?;
            count += 1;
            let name = entry.map_err(history)?.file_name();
            if count > 3 || !["lock", "control", "journal"].iter().any(|n| name == *n) {
                return Err(ReceiverError::History);
            }
        }
        if count != 3 {
            return Err(ReceiverError::History);
        }
        for (name, retained, cap) in [
            ("lock", &self.lock.0, 0),
            ("control", &self.control, CONTROL as u64),
            ("journal", &self.journal, self.limits.max_bytes),
        ] {
            let file = open_file(&self.directory, name, false, cap)?;
            if !same(
                &file.metadata().map_err(history)?,
                &retained.metadata().map_err(history)?,
            ) {
                return Err(ReceiverError::History);
            }
            private(retained, cap)?;
        }
        if self.control.metadata().map_err(history)?.len() != CONTROL as u64
            || size && self.journal.metadata().map_err(history)?.len() != self.bytes
        {
            return Err(ReceiverError::History);
        }
        let mut control = &self.control;
        control.seek(SeekFrom::Start(0)).map_err(history)?;
        let mut identity = [0u8; CONTROL];
        control.read_exact(&mut identity).map_err(history)?;
        if identity != self.identity {
            return Err(ReceiverError::History);
        }
        Ok(())
    }
    fn validate_next(&self, record: &PreparedAudit) -> Result<(), ReceiverError> {
        let r = record.record();
        if self.entries.iter().any(|e| e.id == r.record_id) {
            return Err(ReceiverError::Conflict);
        }
        let previous = self
            .entries
            .iter()
            .rev()
            .find(|e| e.producer == r.producer_id)
            .map_or(0, |e| e.sequence);
        if previous.checked_add(1) != Some(r.sequence) {
            return Err(ReceiverError::Conflict);
        }
        if self.entries.len() == self.limits.max_records
            || !self.producers.contains(&r.producer_id)
                && self.producers.len() == self.limits.max_producers
        {
            return Err(ReceiverError::Full);
        }
        Ok(())
    }
    fn index(&mut self, record: &PreparedAudit, offset: u64) {
        let r = record.record();
        if !self.producers.contains(&r.producer_id) {
            self.producers.push(r.producer_id);
        }
        self.entries.push(Entry {
            producer: r.producer_id,
            sequence: r.sequence,
            id: r.record_id,
            offset,
            len: record.body().len(),
        });
    }
    fn recover(&mut self, ctx: &ExtensionContext) -> Result<(), ReceiverError> {
        let total = self.journal.metadata().map_err(history)?.len();
        let mut offset = 0u64;
        while offset < total {
            live(ctx)?;
            if total - offset < HEADER as u64 {
                return Err(ReceiverError::History);
            }
            self.journal
                .seek(SeekFrom::Start(offset))
                .map_err(history)?;
            let mut header = [0u8; HEADER];
            self.journal.read_exact(&mut header).map_err(history)?;
            let len = frame_length(&header, &self.identity)?;
            let end = offset
                .checked_add((HEADER + len) as u64)
                .ok_or(ReceiverError::History)?;
            if end > total {
                // Only a complete valid header followed by an incomplete final
                // body is recoverable. Partial/unknown headers remain evidence.
                self.journal.set_len(offset).map_err(history)?;
                break;
            }
            let record = read_body(&mut self.journal, &header, len, &self.identity)?;
            self.validate_next(&record)
                .map_err(|_| ReceiverError::History)?;
            self.index(&record, offset);
            offset = end;
        }
        live(ctx)?;
        self.journal.sync_all().map_err(history)?;
        self.directory.sync_all().map_err(history)?;
        self.bytes = offset;
        self.state.bytes.store(offset, Ordering::Release);
        self.state
            .records
            .store(self.entries.len(), Ordering::Release);
        live(ctx)
    }
    fn read(
        &mut self,
        offset: u64,
        len: usize,
        ctx: &ExtensionContext,
    ) -> Result<PreparedAudit, ReceiverError> {
        self.stable(ctx, true)?;
        self.journal
            .seek(SeekFrom::Start(offset))
            .map_err(history)?;
        let mut header = [0u8; HEADER];
        self.journal.read_exact(&mut header).map_err(history)?;
        if frame_length(&header, &self.identity)? != len {
            return Err(ReceiverError::History);
        }
        let record = read_body(&mut self.journal, &header, len, &self.identity)?;
        live(ctx)?;
        Ok(record)
    }
    fn append(
        &mut self,
        record: PreparedAudit,
        ctx: &ExtensionContext,
        started: &AtomicBool,
    ) -> Result<Vec<u8>, ReceiverError> {
        self.stable(ctx, true)?;
        let r = record.record();
        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.producer == r.producer_id && e.sequence == r.sequence)
        {
            let (offset, len, id) = (entry.offset, entry.len, entry.id);
            let original = self.read(offset, len, ctx)?;
            if id != r.record_id || original.body() != record.body() {
                return Err(ReceiverError::Conflict);
            }
            // Reverify bytes and persistence for exact retry, never hash-only ACK.
            self.journal.sync_all().map_err(history)?;
            live(ctx)?;
            return AuditAcknowledgement::for_prepared(&original)
                .to_json()
                .map_err(|_| ReceiverError::History);
        }
        self.validate_next(&record)?;
        let end = self
            .bytes
            .checked_add((HEADER + record.body().len()) as u64)
            .ok_or(ReceiverError::Full)?;
        if end > self.limits.max_bytes {
            return Err(ReceiverError::Full);
        }
        let mut header = [0u8; HEADER];
        header[..4].copy_from_slice(b"AUD1");
        header[4..8].copy_from_slice(&(record.body().len() as u32).to_le_bytes());
        header[8..40].copy_from_slice(&frame_digest(&self.identity, record.body()));
        let check = header_digest(&self.identity, &header[..40]);
        header[40..].copy_from_slice(&check);
        live(ctx)?;
        #[cfg(test)]
        if let Some(pause) = self.pause_before_arm.take() {
            let _ = pause.entered.send(());
            pause
                .release
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| ReceiverError::Uncertain)?;
        }
        started.store(true, Ordering::Release);
        live(ctx)?;
        hit("before-write");
        self.journal
            .seek(SeekFrom::Start(self.bytes))
            .map_err(history)?;
        self.journal.write_all(&header).map_err(history)?;
        hit("header-written");
        self.journal.write_all(record.body()).map_err(history)?;
        hit("body-written");
        self.journal.sync_all().map_err(history)?;
        self.directory.sync_all().map_err(history)?;
        hit("journal-synced");
        #[cfg(test)]
        if let Some(pause) = self.pause.take() {
            let _ = pause.entered.send(());
            pause
                .release
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| ReceiverError::Uncertain)?;
        }
        live(ctx)?;
        let offset = self.bytes;
        self.index(&record, offset);
        self.bytes = end;
        self.state
            .records
            .store(self.entries.len(), Ordering::Release);
        self.state.bytes.store(end, Ordering::Release);
        let original = self.read(offset, record.body().len(), ctx)?;
        if original.body() != record.body() {
            return Err(ReceiverError::History);
        }
        hit("readback-confirmed");
        live(ctx)?;
        AuditAcknowledgement::for_prepared(&original)
            .to_json()
            .map_err(|_| ReceiverError::History)
    }
}
fn frame_length(header: &[u8; HEADER], identity: &[u8; CONTROL]) -> Result<usize, ReceiverError> {
    if header_digest(identity, &header[..40]).as_slice() != &header[40..] {
        return Err(ReceiverError::History);
    }
    if &header[..4] != b"AUD1" {
        return Err(ReceiverError::History);
    }
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(1..=RECORD_BYTES).contains(&len) {
        return Err(ReceiverError::History);
    }
    Ok(len)
}
fn header_digest(identity: &[u8; CONTROL], header: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"platform-signal/audit-receiver-header/v1\0");
    hash.update(identity);
    hash.update(header);
    hash.finalize().into()
}
fn frame_digest(identity: &[u8; CONTROL], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"platform-signal/audit-receiver-frame/v1\0");
    hash.update(identity);
    hash.update(body);
    hash.finalize().into()
}
fn read_body(
    file: &mut File,
    header: &[u8; HEADER],
    len: usize,
    identity: &[u8; CONTROL],
) -> Result<PreparedAudit, ReceiverError> {
    let mut body = [0u8; RECORD_BYTES];
    file.read_exact(&mut body[..len]).map_err(history)?;
    if frame_digest(identity, &body[..len]).as_slice() != &header[8..40] {
        return Err(ReceiverError::History);
    }
    PreparedAudit::from_original(&body[..len]).map_err(|_| ReceiverError::History)
}
fn worker(error: WorkerError) -> ReceiverError {
    if matches!(error, WorkerError::Busy) {
        ReceiverError::Busy
    } else {
        ReceiverError::Uncertain
    }
}
fn hit(_stage: &str) {
    #[cfg(test)]
    if std::env::var("SIGNAL_TEST_AUDIT_RECEIVER_CRASH").is_ok_and(|stage| stage == _stage) {
        std::process::exit(76);
    }
}
struct Attempt {
    started: Arc<AtomicBool>,
    state: Arc<State>,
    cancel: tokio_util::sync::CancellationToken,
    confirmed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.cancel.cancel();
        if !self.confirmed && self.started.load(Ordering::Acquire) {
            self.state.held.store(true, Ordering::Release);
            self.state.uncertain.fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// Finite local receipt mechanism. Run the host under independent credentials,
/// filesystem ownership and lifetime; a store object alone establishes none of
/// those deployment properties. Existing history never implicitly initializes.
pub struct AuditReceiver {
    engine: Arc<Mutex<Engine>>,
    allowed: Vec<Uuid>,
    limits: ReceiverLimits,
    state: Arc<State>,
}
impl AuditReceiver {
    pub async fn open(
        root: &Path,
        mode: OpenMode,
        limits: ReceiverLimits,
        allowed: &[Uuid],
        ctx: ExtensionContext,
    ) -> Result<Self, ReceiverError> {
        let limits = limits.validate()?;
        if root.as_os_str().is_empty()
            || root.as_os_str().len() > 4096
            || allowed.is_empty()
            || allowed.len() > limits.max_producers
            || allowed
                .iter()
                .enumerate()
                .any(|(n, id)| id.is_nil() || allowed[..n].contains(id))
        {
            return Err(ReceiverError::Invalid);
        }
        live(&ctx)?;
        let state = Arc::new(State::default());
        let cancel = ctx.cancellation().child_token();
        let _guard = super::CancelOnDrop(cancel.clone());
        let work = ExtensionContext::from_deadline(cancel.clone(), ctx.deadline())
            .map_err(|_| ReceiverError::Uncertain)?;
        let (engine, allowed) = DISK
            .run_with_factory("signal-audit-receiver-open", ctx.deadline(), cancel, || {
                let path = root.to_owned();
                let state = state.clone();
                let allowed = allowed.to_vec();
                move || {
                    Ok(Engine::open(path, mode, limits, state, &work)
                        .map(|engine| (engine, allowed)))
                }
            })
            .await
            .map_err(worker)??;
        live(&ctx)?;
        Ok(Self {
            engine: Arc::new(Mutex::new(engine)),
            allowed,
            limits,
            state,
        })
    }
    pub async fn append(
        &self,
        producer: &TrustedProducer,
        record: &PreparedAudit,
        ctx: ExtensionContext,
    ) -> Result<Vec<u8>, ReceiverError> {
        live(&ctx)?;
        if producer.0 != record.record().producer_id || !self.allowed.contains(&producer.0) {
            self.state.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(ReceiverError::Denied);
        }
        if self.state.held.load(Ordering::Acquire) {
            return Err(ReceiverError::Uncertain);
        }
        let cancel = ctx.cancellation().child_token();
        let work = ExtensionContext::from_deadline(cancel.clone(), ctx.deadline())
            .map_err(|_| ReceiverError::Uncertain)?;
        let started = Arc::new(AtomicBool::new(false));
        let mut attempt = Attempt {
            started: started.clone(),
            state: self.state.clone(),
            cancel: cancel.clone(),
            confirmed: false,
        };
        let result = DISK
            .run_with_factory(
                "signal-audit-receiver-append",
                ctx.deadline(),
                cancel,
                || {
                    let engine = self.engine.clone();
                    let body = record.body().to_vec();
                    move || {
                        let mut engine = engine.lock().map_err(|_| WorkerError::Unavailable)?;
                        let result = PreparedAudit::from_original(&body)
                            .map_err(|_| ReceiverError::Invalid)
                            .and_then(|record| engine.append(record, &work, &started));
                        if matches!(result, Err(ReceiverError::History)) {
                            engine.state.held.store(true, Ordering::Release);
                        }
                        Ok(result)
                    }
                },
            )
            .await
            .map_err(worker)
            .and_then(|r| r);
        if matches!(
            result,
            Err(ReceiverError::Busy | ReceiverError::Full | ReceiverError::Conflict)
        ) {
            self.state.rejected.fetch_add(1, Ordering::Relaxed);
        }
        live(&ctx)?;
        if result.is_ok() {
            attempt.confirmed = true;
        }
        result
    }
    /// Aggregate snapshot does not acquire the disk mutex or expose identities.
    /// It is not an authenticated external probe or proof of producer completeness.
    pub fn health(&self) -> ReceiverHealth {
        ReceiverHealth {
            records: self.state.records.load(Ordering::Acquire),
            bytes: self.state.bytes.load(Ordering::Acquire),
            record_capacity: self.limits.max_records,
            byte_capacity: self.limits.max_bytes,
            physical_depth: DISK.depth(),
            physical_capacity: 1,
            physical_rejected: DISK.rejections(),
            rejected: self.state.rejected.load(Ordering::Relaxed),
            uncertain: self.state.uncertain.load(Ordering::Relaxed),
            held: self.state.held.load(Ordering::Acquire),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

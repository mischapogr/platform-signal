//! One-record durable control outbox. Local crash recovery is not proof that a
//! restored old directory represents independently current destination history.
use crate::{
    ExtensionContext,
    transport::worker::{Worker, WorkerError},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use signal_protocol::audit::{
    Action, Actor, AppendError, AuditAcknowledgement, AuditRecord, AuditSink, PreparedAudit,
    RECORD_BYTES,
};
use std::{
    ffi::CStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use uuid::Uuid;

static DISK: Worker = Worker::new();
const STATE_BYTES: usize = 1024;
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum OutboxError {
    #[error("audit outbox capacity is occupied")]
    Busy,
    #[error("invalid audit outbox configuration or record")]
    Invalid,
    #[error("audit outbox history requires reconciliation")]
    History,
    #[error("audit outbox operation is uncertain")]
    Uncertain,
}
#[derive(Clone, Copy, Debug)]
pub struct OutboxMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub physical_depth: usize,
    pub physical_capacity: usize,
    pub physical_rejected: u64,
    pub rejected: u64,
    pub uncertain: u64,
    pub held: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u16,
    producer_id: Uuid,
    acknowledged: Option<AuditAcknowledgement>,
}
impl State {
    fn decode(body: &[u8]) -> Result<Self, OutboxError> {
        if body.len() > STATE_BYTES || body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
        {
            return Err(OutboxError::History);
        }
        let state: Self = serde_json::from_slice(body).map_err(|_| OutboxError::History)?;
        let shape: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| OutboxError::History)?;
        if shape
            .get("acknowledged")
            .is_none_or(|a| !a.is_null() && !a.is_object())
        {
            return Err(OutboxError::History);
        }
        if state.schema_version != 1
            || state.producer_id.is_nil()
            || state.acknowledged.as_ref().is_some_and(|a| {
                a.schema_version != 1
                    || a.producer_id != state.producer_id
                    || a.record_id.is_nil()
                    || a.sequence == 0
                    || a.body_sha256.len() != 64
                    || !a
                        .body_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(OutboxError::History);
        }
        Ok(state)
    }
    fn sequence(&self) -> u64 {
        self.acknowledged.as_ref().map_or(0, |a| a.sequence)
    }
    fn matches(&self, record: &PreparedAudit) -> bool {
        self.acknowledged.as_ref().is_some_and(|a| {
            a.sequence == record.record().sequence
                && a.record_id == record.record().record_id
                && a.producer_id == record.record().producer_id
                && a.body_sha256 == record.sha256()
        })
    }
    fn bytes(&self) -> Result<Vec<u8>, OutboxError> {
        let body = serde_json::to_vec(self).map_err(|_| OutboxError::History)?;
        if body.len() > STATE_BYTES {
            return Err(OutboxError::History);
        }
        Ok(body)
    }
}
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
struct Engine {
    path: PathBuf,
    directory: File,
    lock: Lock,
    held: Arc<AtomicBool>,
    pending: Arc<AtomicBool>,
    may_initialize: bool,
    #[cfg(test)]
    input_capacity: usize,
}
fn io_error(_: std::io::Error) -> OutboxError {
    OutboxError::History
}
fn live(ctx: &ExtensionContext) -> Result<(), OutboxError> {
    ctx.check().map_err(|_| OutboxError::Uncertain)
}
fn identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn private(file: &File, cap: usize) -> Result<(), OutboxError> {
    let m = file.metadata().map_err(io_error)?;
    let uid = fs::metadata("/proc/self").map_err(io_error)?.uid();
    if !m.is_file()
        || m.uid() != uid
        || m.mode() & 0o777 != 0o600
        || (m.nlink() != 1 && (cap == 0 || m.nlink() != 2))
        || m.len() > cap as u64
    {
        return Err(OutboxError::History);
    }
    Ok(())
}
impl Engine {
    fn open(
        path: PathBuf,
        ctx: &ExtensionContext,
        held: Arc<AtomicBool>,
        pending: Arc<AtomicBool>,
    ) -> Result<Self, OutboxError> {
        live(ctx)?;
        let original = fs::symlink_metadata(&path).map_err(io_error)?;
        let uid = fs::metadata("/proc/self").map_err(io_error)?.uid();
        if !original.is_dir()
            || original.file_type().is_symlink()
            || original.mode() & 0o777 != 0o700
            || original.uid() != uid
        {
            return Err(OutboxError::Invalid);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(io_error)?;
        if !identity(&original, &directory.metadata().map_err(io_error)?) {
            return Err(OutboxError::History);
        }
        let lock_path = format!("/proc/self/fd/{}/lock", directory.as_raw_fd());
        let created = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&lock_path);
        let (file, may_initialize) = match created {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(lock_path)
                    .map_err(io_error)?,
                false,
            ),
            Err(_) => return Err(OutboxError::History),
        };
        private(&file, 0)?;
        file.try_lock().map_err(|_| OutboxError::Busy)?;
        let mut engine = Self {
            path,
            directory,
            lock: Lock(file),
            held,
            pending,
            may_initialize,
            #[cfg(test)]
            input_capacity: 0,
        };
        engine.directory.sync_all().map_err(io_error)?;
        engine.recover(ctx)?;
        live(ctx)?;
        Ok(engine)
    }
    fn stable(&self, ctx: &ExtensionContext) -> Result<(), OutboxError> {
        live(ctx)?;
        if self.held.load(Ordering::Acquire) {
            return Err(OutboxError::Uncertain);
        }
        let path = fs::symlink_metadata(&self.path).map_err(io_error)?;
        let root = self.directory.metadata().map_err(io_error)?;
        if path.file_type().is_symlink()
            || path.mode() & 0o777 != 0o700
            || !identity(&path, &root)
            || path.uid() != root.uid()
        {
            return Err(OutboxError::History);
        }
        let lock = self.file(c"lock", 0)?.ok_or(OutboxError::History)?;
        if !identity(
            &lock.metadata().map_err(io_error)?,
            &self.lock.0.metadata().map_err(io_error)?,
        ) {
            return Err(OutboxError::History);
        }
        Ok(())
    }
    fn anchored(&self, name: &CStr) -> Result<PathBuf, OutboxError> {
        let name = name.to_str().map_err(|_| OutboxError::History)?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.directory.as_raw_fd(),
            name
        )))
    }
    fn file(&self, name: &CStr, cap: usize) -> Result<Option<File>, OutboxError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.anchored(name)?)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(OutboxError::History),
        };
        private(&file, cap)?;
        if file.metadata().map_err(io_error)?.nlink() == 2 {
            let peer = match name.to_bytes() {
                b"state" => c"state.next",
                b"state.next" => c"state",
                b"pending" => c"pending.next",
                b"pending.next" => c"pending",
                _ => return Err(OutboxError::History),
            };
            let companion = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(self.anchored(peer)?)
                .map_err(io_error)?;
            private(&companion, cap)?;
            if !identity(
                &file.metadata().map_err(io_error)?,
                &companion.metadata().map_err(io_error)?,
            ) {
                return Err(OutboxError::History);
            }
        }
        Ok(Some(file))
    }
    fn read(&self, name: &CStr, cap: usize) -> Result<Option<Vec<u8>>, OutboxError> {
        let Some(mut file) = self.file(name, cap)? else {
            return Ok(None);
        };
        let mut body = Vec::with_capacity(cap);
        (&mut file)
            .take((cap + 1) as u64)
            .read_to_end(&mut body)
            .map_err(io_error)?;
        private(&file, cap)?;
        if body.len() > cap {
            return Err(OutboxError::History);
        }
        Ok(Some(body))
    }
    fn inventory(&self, ctx: &ExtensionContext) -> Result<(), OutboxError> {
        self.stable(ctx)?;
        // /proc exposes the already owned directory, not a new path resolution.
        for (i, item) in fs::read_dir(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
            .map_err(io_error)?
            .enumerate()
        {
            self.stable(ctx)?;
            if i >= 5 {
                return Err(OutboxError::History);
            }
            let item = item.map_err(io_error)?;
            let (name, cap) = match item.file_name().to_str() {
                Some("lock") => (c"lock", 0),
                Some("state") => (c"state", STATE_BYTES),
                Some("state.next") => (c"state.next", STATE_BYTES),
                Some("pending") => (c"pending", RECORD_BYTES),
                Some("pending.next") => (c"pending.next", RECORD_BYTES),
                _ => return Err(OutboxError::History),
            };
            self.file(name, cap)?.ok_or(OutboxError::History)?;
        }
        self.stable(ctx)
    }
    fn clean_live(&self, ctx: &ExtensionContext) -> Result<(), OutboxError> {
        self.inventory(ctx)?;
        // A healthy live owner has no temporary controls. Interrupted mutations
        // are held and must reopen through complete recovery preflight.
        if self.file(c"state.next", STATE_BYTES)?.is_some()
            || self.file(c"pending.next", RECORD_BYTES)?.is_some()
        {
            return Err(OutboxError::History);
        }
        Ok(())
    }
    fn write(&self, name: &CStr, bytes: &[u8], ctx: &ExtensionContext) -> Result<(), OutboxError> {
        self.stable(ctx)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.anchored(name)?)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        self.stable(ctx)?;
        file.sync_all().map_err(io_error)?;
        self.stable(ctx)
    }
    fn publish(
        &self,
        from: &CStr,
        to: &CStr,
        replace: bool,
        ctx: &ExtensionContext,
    ) -> Result<(), OutboxError> {
        self.stable(ctx)?;
        if replace {
            fs::rename(self.anchored(from)?, self.anchored(to)?).map_err(io_error)?;
        } else {
            // Exclusive publication; recovery permits only these exact two-name
            // aliases, never a link to external evidence.
            fs::hard_link(self.anchored(from)?, self.anchored(to)?).map_err(io_error)?;
            hit(if to.to_bytes() == b"pending" {
                "pending-linked"
            } else {
                "identity-linked"
            });
            fs::remove_file(self.anchored(from)?).map_err(io_error)?;
        }
        self.stable(ctx)
    }
    fn remove_pending(&self, ctx: &ExtensionContext) -> Result<(), OutboxError> {
        self.stable(ctx)?;
        fs::remove_file(self.anchored(c"pending")?).map_err(io_error)?;
        hit("pending-removed");
        self.directory.sync_all().map_err(io_error)?;
        self.stable(ctx)
    }
    fn state(&self) -> Result<State, OutboxError> {
        State::decode(
            &self
                .read(c"state", STATE_BYTES)?
                .ok_or(OutboxError::History)?,
        )
    }
    fn record(&self) -> Result<Option<PreparedAudit>, OutboxError> {
        self.read(c"pending", RECORD_BYTES)?
            .map(|b| PreparedAudit::from_original(&b).map_err(|_| OutboxError::History))
            .transpose()
    }
    fn recover(&mut self, ctx: &ExtensionContext) -> Result<(), OutboxError> {
        self.inventory(ctx)?;
        // Decode and validate the entire finite graph before any unlink, adoption
        // or initialization. A locally valid alias may belong to foreign history.
        let state = self
            .read(c"state", STATE_BYTES)?
            .map(|b| State::decode(&b))
            .transpose()?;
        let mut next = self
            .read(c"state.next", STATE_BYTES)?
            .map(|b| State::decode(&b))
            .transpose()?;
        let record = self.record()?;
        let mut staged = self
            .read(c"pending.next", RECORD_BYTES)?
            .map(|b| PreparedAudit::from_original(&b).map_err(|_| OutboxError::History))
            .transpose()?;
        let mut aliases = Vec::with_capacity(2);
        for (published, temporary, cap) in [
            (c"state", c"state.next", STATE_BYTES),
            (c"pending", c"pending.next", RECORD_BYTES),
        ] {
            if let (Some(a), Some(b)) = (self.file(published, cap)?, self.file(temporary, cap)?)
                && identity(
                    &a.metadata().map_err(io_error)?,
                    &b.metadata().map_err(io_error)?,
                )
            {
                aliases.push(temporary);
                if cap == STATE_BYTES {
                    next = None;
                } else {
                    staged = None;
                }
            }
        }
        match state.as_ref() {
            None => {
                if record.is_some()
                    || staged.is_some()
                    || next.as_ref().is_some_and(|s| s.acknowledged.is_some())
                    || (next.is_none() && !self.may_initialize)
                {
                    return Err(OutboxError::History);
                }
            }
            Some(current) => {
                if let Some(next) = next.as_ref()
                    && (staged.is_some()
                        || next.producer_id != current.producer_id
                        || current.sequence().checked_add(1) != Some(next.sequence())
                        || record.as_ref().is_none_or(|r| !next.matches(r)))
                {
                    return Err(OutboxError::History);
                }
                let effective = next.as_ref().unwrap_or(current);
                if record.as_ref().is_some_and(|r| {
                    r.record().producer_id != effective.producer_id
                        || (!effective.matches(r)
                            && effective.sequence().checked_add(1) != Some(r.record().sequence))
                }) {
                    return Err(OutboxError::History);
                }
                if staged.as_ref().is_some_and(|r| {
                    record.is_some()
                        || r.record().producer_id != effective.producer_id
                        || effective.sequence().checked_add(1) != Some(r.record().sequence)
                }) {
                    return Err(OutboxError::History);
                }
            }
        }
        self.stable(ctx)?;
        for temporary in aliases {
            fs::remove_file(self.anchored(temporary)?).map_err(io_error)?;
            self.directory.sync_all().map_err(io_error)?;
            self.stable(ctx)?;
        }
        if state.is_none() {
            if next.is_none() {
                let initial = State {
                    schema_version: 1,
                    producer_id: Uuid::new_v4(),
                    acknowledged: None,
                };
                self.write(c"state.next", &initial.bytes()?, ctx)?;
                hit("identity-temp");
            }
            self.file(c"state.next", STATE_BYTES)?
                .ok_or(OutboxError::History)?
                .sync_all()
                .map_err(io_error)?;
            self.publish(c"state.next", c"state", false, ctx)?;
            self.directory.sync_all().map_err(io_error)?;
            hit("identity-synced");
        } else if next.is_some() {
            self.file(c"state.next", STATE_BYTES)?
                .ok_or(OutboxError::History)?
                .sync_all()
                .map_err(io_error)?;
            self.publish(c"state.next", c"state", true, ctx)?;
            self.directory.sync_all().map_err(io_error)?;
        }
        if staged.is_some() {
            self.file(c"pending.next", RECORD_BYTES)?
                .ok_or(OutboxError::History)?
                .sync_all()
                .map_err(io_error)?;
            self.publish(c"pending.next", c"pending", false, ctx)?;
            self.directory.sync_all().map_err(io_error)?;
        }
        let state = self.state()?;
        if self.record()?.as_ref().is_some_and(|r| state.matches(r)) {
            self.remove_pending(ctx)?;
        }
        self.pending
            .store(self.record()?.is_some(), Ordering::Release);
        self.inventory(ctx)
    }
    fn stage(
        &mut self,
        actor: Actor,
        action: Action,
        timestamp: DateTime<Utc>,
        ctx: &ExtensionContext,
        started: &AtomicBool,
    ) -> Result<PreparedAudit, OutboxError> {
        #[cfg(test)]
        {
            let actor_capacity = match &actor {
                Actor::VerifiedSubject { key } => key.capacity(),
                _ => 0,
            };
            let action_capacity = match &action {
                Action::ConfigurationActivation {
                    revision_sha256, ..
                } => revision_sha256.capacity(),
                _ => 0,
            };
            self.input_capacity = actor_capacity.max(action_capacity);
        }
        self.clean_live(ctx)?;
        if self.record()?.is_some() {
            return Err(OutboxError::Busy);
        }
        if self.read(c"pending.next", RECORD_BYTES)?.is_some()
            || self.read(c"state.next", STATE_BYTES)?.is_some()
        {
            return Err(OutboxError::History);
        }
        let state = self.state()?;
        let record = AuditRecord {
            schema_version: 1,
            record_id: Uuid::new_v4(),
            producer_id: state.producer_id,
            sequence: state
                .sequence()
                .checked_add(1)
                .ok_or(OutboxError::History)?,
            timestamp,
            actor,
            action,
        }
        .prepare()
        .map_err(|_| OutboxError::Invalid)?;
        self.stable(ctx)?;
        started.store(true, Ordering::Release);
        self.write(c"pending.next", record.body(), ctx)?;
        hit("pending-temp");
        self.publish(c"pending.next", c"pending", false, ctx)?;
        hit("pending-published");
        self.directory.sync_all().map_err(io_error)?;
        hit("pending-synced");
        self.stable(ctx)?;
        self.pending.store(true, Ordering::Release);
        Ok(record)
    }
    fn confirm(
        &mut self,
        original: &[u8],
        ctx: &ExtensionContext,
        started: &AtomicBool,
    ) -> Result<(), OutboxError> {
        self.clean_live(ctx)?;
        let record = PreparedAudit::from_original(original).map_err(|_| OutboxError::Invalid)?;
        let mut state = self.state()?;
        let pending = self.record()?;
        if state.matches(&record) {
            if let Some(pending) = pending
                && pending.body() == record.body()
            {
                started.store(true, Ordering::Release);
                self.remove_pending(ctx)?;
                self.pending.store(false, Ordering::Release);
            }
            return Ok(());
        }
        if pending.as_ref().is_none_or(|p| p.body() != record.body())
            || record.record().producer_id != state.producer_id
            || state.sequence().checked_add(1) != Some(record.record().sequence)
        {
            return Err(OutboxError::History);
        }
        if self.read(c"state.next", STATE_BYTES)?.is_some() {
            return Err(OutboxError::History);
        }
        state.acknowledged = Some(AuditAcknowledgement::for_prepared(&record));
        self.stable(ctx)?;
        started.store(true, Ordering::Release);
        self.write(c"state.next", &state.bytes()?, ctx)?;
        hit("checkpoint-temp");
        self.publish(c"state.next", c"state", true, ctx)?;
        hit("checkpoint-published");
        self.directory.sync_all().map_err(io_error)?;
        hit("checkpoint-synced");
        self.remove_pending(ctx)?;
        self.pending.store(false, Ordering::Release);
        self.stable(ctx)
    }
}

fn hit(_stage: &str) {
    #[cfg(test)]
    if std::env::var("SIGNAL_TEST_AUDIT_CRASH").is_ok_and(|s| s == _stage) {
        std::process::exit(75);
    }
}
struct Attempt {
    started: Arc<AtomicBool>,
    held: Arc<AtomicBool>,
    uncertain: Arc<AtomicU64>,
    cancellation: tokio_util::sync::CancellationToken,
    confirmed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if !self.confirmed && self.started.load(Ordering::Acquire) {
            self.held.store(true, Ordering::Release);
            self.uncertain.fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// Linux descriptor-relative single-record outbox. Selected root must already
/// be an empty current-user0700 directory separate from telemetry/query roots.
/// Pending and checkpoint data never appear in Debug or ordinary diagnostics.
pub struct AuditOutbox {
    engine: Arc<Mutex<Engine>>,
    held: Arc<AtomicBool>,
    pending: Arc<AtomicBool>,
    uncertain: Arc<AtomicU64>,
    rejected: AtomicU64,
}
impl AuditOutbox {
    pub async fn open(root: &Path, ctx: ExtensionContext) -> Result<Self, OutboxError> {
        if root.as_os_str().len() > 4096 || root.as_os_str().is_empty() {
            return Err(OutboxError::Invalid);
        }
        live(&ctx)?;
        let held = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicBool::new(false));
        let cancellation = ctx.cancellation().child_token();
        let _cancel_on_drop = super::CancelOnDrop(cancellation.clone());
        let work = ExtensionContext::from_deadline(cancellation.clone(), ctx.deadline())
            .map_err(|_| OutboxError::Uncertain)?;
        let result = DISK
            .run_with_factory("signal-audit-open", ctx.deadline(), cancellation, || {
                let path = root.to_owned();
                let held = held.clone();
                let pending = pending.clone();
                move || Ok(Engine::open(path, &work, held, pending))
            })
            .await
            .map_err(worker_error)??;
        live(&ctx)?;
        Ok(Self {
            engine: Arc::new(Mutex::new(result)),
            held,
            pending,
            uncertain: Arc::new(AtomicU64::new(0)),
            rejected: AtomicU64::new(0),
        })
    }
    async fn run<T: Send + 'static>(
        &self,
        ctx: ExtensionContext,
        mutation: bool,
        operation: impl FnOnce(&mut Engine, &ExtensionContext, &AtomicBool) -> Result<T, OutboxError>
        + Send
        + 'static,
    ) -> Result<T, OutboxError> {
        live(&ctx)?;
        let cancellation = ctx.cancellation().child_token();
        let work = ExtensionContext::from_deadline(cancellation.clone(), ctx.deadline())
            .map_err(|_| OutboxError::Uncertain)?;
        let started = Arc::new(AtomicBool::new(false));
        let mut attempt = Attempt {
            started: started.clone(),
            held: self.held.clone(),
            uncertain: self.uncertain.clone(),
            cancellation: cancellation.clone(),
            confirmed: !mutation,
        };
        let result = DISK
            .run_with_factory("signal-audit-disk", ctx.deadline(), cancellation, || {
                let engine = self.engine.clone();
                move || {
                    let mut engine = engine.lock().map_err(|_| WorkerError::Unavailable)?;
                    Ok(operation(&mut engine, &work, &started))
                }
            })
            .await
            .map_err(worker_error)
            .and_then(|r| r);
        if matches!(result, Err(OutboxError::Busy)) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
        live(&ctx)?;
        if result.is_ok() {
            attempt.confirmed = true;
        }
        result
    }
    /// Assign identity/sequence once and sync immutable bytes before delivery.
    /// An occupied outbox must be flushed/reconciled before staging another act.
    pub async fn stage(
        &self,
        actor: Actor,
        action: Action,
        timestamp: DateTime<Utc>,
        ctx: ExtensionContext,
    ) -> Result<PreparedAudit, OutboxError> {
        // Validate caller-owned metadata before moving it into physical work.
        let mut input = AuditRecord {
            schema_version: 1,
            record_id: Uuid::from_u128(1),
            producer_id: Uuid::from_u128(1),
            sequence: 1,
            timestamp,
            actor,
            action,
        };
        input.validate().map_err(|_| OutboxError::Invalid)?;
        // Caller-owned spare capacity is not carried into physical work.
        if let Actor::VerifiedSubject { key } = &mut input.actor {
            *key = std::mem::take(key).into_boxed_str().into_string();
        }
        if let Action::ConfigurationActivation {
            revision_sha256, ..
        } = &mut input.action
        {
            *revision_sha256 = std::mem::take(revision_sha256)
                .into_boxed_str()
                .into_string();
        }
        self.run(ctx, true, move |engine, ctx, started| {
            engine.stage(input.actor, input.action, input.timestamp, ctx, started)
        })
        .await
    }
    pub async fn pending(
        &self,
        ctx: ExtensionContext,
    ) -> Result<Option<PreparedAudit>, OutboxError> {
        self.run(ctx, false, |engine, ctx, _| {
            engine.clean_live(ctx)?;
            let record = engine.record()?;
            let state = engine.state()?;
            if record.as_ref().is_some_and(|r| {
                r.record().producer_id != state.producer_id
                    || state.sequence().checked_add(1) != Some(r.record().sequence)
            }) {
                return Err(OutboxError::History);
            }
            Ok(record)
        })
        .await
    }
    /// Confirm only the exact pending record after the configured AuditSink's
    /// complete acknowledgement. An uncertain network reply keeps the original
    /// pending record replayable. Success does not authorize a new operation.
    pub async fn flush(
        &self,
        sink: &dyn AuditSink,
        ctx: ExtensionContext,
    ) -> Result<Option<Uuid>, OutboxError> {
        let Some(record) = self.pending(ctx.clone()).await? else {
            return Ok(None);
        };
        live(&ctx)?;
        let append = sink.append(&record, ctx.deadline().into_std());
        tokio::select! { biased;
            _ = ctx.cancellation().cancelled() => return Err(OutboxError::Uncertain),
            r = tokio::time::timeout_at(ctx.deadline(), append) => r.map_err(|_| OutboxError::Uncertain)?.map_err(|e| match e { AppendError::Busy => OutboxError::Busy, AppendError::Uncertain => OutboxError::Uncertain })?,
        }
        live(&ctx)?;
        let id = record.record().record_id;
        let original = record.body().to_vec();
        self.run(ctx, true, move |engine, ctx, started| {
            engine.confirm(&original, ctx, started)
        })
        .await?;
        Ok(Some(id))
    }
    pub fn metrics(&self) -> OutboxMetrics {
        OutboxMetrics {
            depth: usize::from(
                self.pending.load(Ordering::Acquire) || self.held.load(Ordering::Acquire),
            ),
            capacity: 1,
            physical_depth: DISK.depth(),
            physical_capacity: 1,
            physical_rejected: DISK.rejections(),
            rejected: self.rejected.load(Ordering::Relaxed),
            uncertain: self.uncertain.load(Ordering::Relaxed),
            held: self.held.load(Ordering::Acquire),
        }
    }
}
fn worker_error(error: WorkerError) -> OutboxError {
    if error == WorkerError::Busy {
        OutboxError::Busy
    } else {
        OutboxError::Uncertain
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

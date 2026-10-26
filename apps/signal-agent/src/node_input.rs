//! Dedicated retained physical node-log worker; no filesystem work on Tokio.
mod state;
use crate::{
    contracts::SourceCheckpoint,
    input::{InputRecord, ReadOutcome},
    node_root,
    spool::CursorProfile,
};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tokio::{
    sync::{Semaphore, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

static WORKER_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
#[derive(Clone, Debug)]
pub struct Config {
    pub root: PathBuf,
    pub cluster: String,
    pub node: String,
    pub namespace: Option<String>,
    pub max_line_bytes: usize,
    pub follow: bool,
    pub limits: node_root::Limits,
    pub scan_interval: Duration,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.root.is_absolute()
            || self.root.as_os_str().as_encoded_bytes().len() > 4096
            || self.root.components().take(129).count() > 128
            || self
                .root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            || self
                .namespace
                .as_deref()
                .is_some_and(|n| !node_root::valid_namespace(n))
            || self.max_line_bytes == 0
            || self.max_line_bytes > signal_collector_sdk::kubernetes_log::MAX_RECORD_BYTES
            || self.scan_interval.is_zero()
            || self.scan_interval > Duration::from_secs(60)
        {
            return Err(Error::Configuration);
        }
        self.limits.validate().map_err(|_| Error::Configuration)?;
        signal_collector_sdk::kubernetes_log::Profile::new(&self.cluster, &self.node)
            .map_err(|_| Error::Configuration)?;
        Ok(())
    }
    fn binding(&self, root: &node_root::Root) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"platform-signal/node-cri/v1\0");
        for bytes in [
            self.root.as_os_str().as_encoded_bytes(),
            self.cluster.as_bytes(),
            self.node.as_bytes(),
            self.namespace.as_deref().unwrap_or("").as_bytes(),
        ] {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        for n in [
            root.identity().0,
            root.identity().1,
            self.max_line_bytes as u64,
            self.limits.max_entries as u64,
            self.limits.max_active as u64,
            self.limits.max_rotated as u64,
        ] {
            h.update(n.to_le_bytes());
        }
        h.finalize().into()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid node input configuration or source profile")]
    Configuration,
    #[error("node source cursor cannot be restored safely")]
    Cursor,
    #[error("node input worker is busy")]
    Busy,
    #[error("node input operation cancelled")]
    Cancelled,
    #[error("node input original deadline expired")]
    Timeout,
    #[error("node input worker closed")]
    Closed,
    #[error("node source filesystem refused")]
    Root(#[from] node_root::Error),
    #[error("node log read failed")]
    Io(#[from] std::io::Error),
}
#[derive(Default)]
struct Counters {
    queued: AtomicUsize,
    active: AtomicUsize,
    slots: AtomicUsize,
    fds: AtomicUsize,
    buffered: AtomicUsize,
    pending: AtomicUsize,
    scans: AtomicU64,
    scan_refusals: AtomicU64,
    admission_refusals: AtomicU64,
    gaps: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicBool,
    retired: AtomicBool,
    failures: AtomicU64,
    rejections: AtomicU64,
    timeouts: AtomicU64,
    scan_entries: AtomicUsize,
    scan_active: AtomicUsize,
    scan_rotated: AtomicUsize,
}
#[derive(Clone)]
pub struct Metrics {
    shared: Arc<Counters>,
    buffer_capacity: usize,
    limits: node_root::Limits,
}
impl Metrics {
    pub fn text(&self) -> String {
        let c = &self.shared;
        let mut s = String::new();
        for (name, n) in [
            ("command_depth", c.queued.load(Ordering::Relaxed) as u64),
            ("command_capacity", 1),
            ("failures_total", c.failures.load(Ordering::Relaxed)),
            ("rejections_total", c.rejections.load(Ordering::Relaxed)),
            ("timeouts_total", c.timeouts.load(Ordering::Relaxed)),
            (
                "worker_rejections_total",
                WORKER_REJECTIONS.load(Ordering::Relaxed),
            ),
            (
                "scan_entries",
                c.scan_entries.load(Ordering::Relaxed) as u64,
            ),
            ("scan_entry_capacity", self.limits.max_entries as u64),
            ("scan_active", c.scan_active.load(Ordering::Relaxed) as u64),
            ("scan_active_capacity", self.limits.max_active as u64),
            (
                "scan_rotated",
                c.scan_rotated.load(Ordering::Relaxed) as u64,
            ),
            ("scan_rotated_capacity", self.limits.max_rotated as u64),
            ("retired", u64::from(c.retired.load(Ordering::Acquire))),
            ("operations", c.active.load(Ordering::Relaxed) as u64),
            ("operation_capacity", 1),
            ("sources", c.slots.load(Ordering::Relaxed) as u64),
            ("source_capacity", 16),
            ("files", c.fds.load(Ordering::Relaxed) as u64),
            ("file_capacity", 16),
            ("buffer_bytes", c.buffered.load(Ordering::Relaxed) as u64),
            ("buffer_capacity_bytes", self.buffer_capacity as u64),
            ("pending", c.pending.load(Ordering::Relaxed) as u64),
            ("pending_capacity", 1),
            ("scans_total", c.scans.load(Ordering::Relaxed)),
            (
                "scan_refusals_total",
                c.scan_refusals.load(Ordering::Relaxed),
            ),
            (
                "admission_refusals_total",
                c.admission_refusals.load(Ordering::Relaxed),
            ),
            ("gaps_total", c.gaps.load(Ordering::Relaxed)),
            ("rejected_records_total", c.rejected.load(Ordering::Relaxed)),
            ("closed", u64::from(c.closed.load(Ordering::Acquire))),
        ] {
            s.push_str(&format!("signal_agent_node_{name} {n}\n"));
        }
        s
    }
}
struct Context {
    deadline: Instant,
    cancel: CancellationToken,
    lifetime: CancellationToken,
}
impl Context {
    fn check(&self) -> Result<(), Error> {
        if self.cancel.is_cancelled() || self.lifetime.is_cancelled() {
            Err(Error::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
}
enum Action {
    Restore(Vec<SourceCheckpoint>),
    Read,
    Commit,
    #[cfg(test)]
    Hold(oneshot::Sender<()>, mpsc::Receiver<()>),
}
enum Reply {
    Done,
    Read(ReadOutcome),
}
struct Command {
    action: Action,
    context: Context,
    reply: oneshot::Sender<Result<Reply, Error>>,
}
/// Drop/cancel closes logical admission; physical ownership ends only at exit.
struct CallGuard {
    lifetime: CancellationToken,
    closed: Arc<Counters>,
    success: bool,
}
impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.success {
            self.closed.failures.fetch_add(1, Ordering::Relaxed);
            self.closed.closed.store(true, Ordering::Release);
            self.lifetime.cancel();
        }
    }
}
pub struct Reader {
    commands: Option<mpsc::SyncSender<Command>>,
    lifetime: CancellationToken,
    exited: Option<oneshot::Receiver<()>>,
    retired: bool,
    metrics: Metrics,
    profile: CursorProfile,
}
impl Reader {
    pub async fn prepare(
        mut config: Config,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Self, Error> {
        config.validate()?;
        config.root = config.root.components().collect();
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let permit = WORKERS.clone().try_acquire_owned().map_err(|_| {
            WORKER_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            Error::Busy
        })?;
        let counters = Arc::new(Counters::default());
        let shared = counters.clone();
        let lifetime = CancellationToken::new();
        let owned_lifetime = lifetime.clone();
        let context = Context {
            deadline,
            cancel: cancel.child_token(),
            lifetime: lifetime.clone(),
        };
        let (ready, wait) = oneshot::channel();
        let (exit, exited) = oneshot::channel();
        let (commands, receive) = mpsc::sync_channel::<Command>(1);
        let capacity = config.max_line_bytes * 16;
        let limits = config.limits;
        std::thread::Builder::new()
            .name("signal-node-input".into())
            .spawn(move || {
                let result = (|| {
                    context.check()?;
                    let root = node_root::Root::open(&config.root, config.limits)?;
                    context.check()?;
                    let profile = CursorProfile::KubernetesNode {
                        source_binding: config.binding(&root),
                    };
                    let state = state::State::new(config, root, profile, shared.clone())?;
                    Ok((state, profile))
                })();
                if let Ok((mut state, profile)) = result {
                    if ready.send(Ok(profile)).is_ok() {
                        while !owned_lifetime.is_cancelled() {
                            let command = match receive.recv_timeout(Duration::from_millis(10)) {
                                Ok(c) => c,
                                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(_) => break,
                            };
                            shared.queued.fetch_sub(1, Ordering::Relaxed);
                            shared.active.store(1, Ordering::Relaxed);
                            let result =
                                command.context.check().and_then(|_| match command.action {
                                    Action::Restore(c) => state.restore(c).map(|_| Reply::Done),
                                    Action::Read => state.read(&command.context).map(Reply::Read),
                                    Action::Commit => state.commit().map(|_| Reply::Done),
                                    #[cfg(test)]
                                    Action::Hold(entered, release) => {
                                        let _ = entered.send(());
                                        release
                                            .recv_timeout(Duration::from_secs(3))
                                            .map_err(|_| Error::Closed)?;
                                        Ok(Reply::Done)
                                    }
                                });
                            state.metrics();
                            shared.active.store(0, Ordering::Relaxed);
                            let result = result.and_then(|value| {
                                command.context.check()?;
                                Ok(value)
                            });
                            let failed = result.is_err();
                            let _ = command.reply.send(result);
                            if failed {
                                break;
                            }
                        }
                    }
                    drop(state);
                } else if let Err(error) = result {
                    let _ = ready.send(Err(error));
                }
                // Physical resources and worker permit retire before confirmation.
                drop(receive);
                shared.queued.store(0, Ordering::Relaxed);
                shared.closed.store(true, Ordering::Release);
                drop(permit);
                shared.active.store(0, Ordering::Relaxed);
                shared.slots.store(0, Ordering::Relaxed);
                shared.fds.store(0, Ordering::Relaxed);
                shared.buffered.store(0, Ordering::Relaxed);
                shared.pending.store(0, Ordering::Relaxed);
                shared.retired.store(true, Ordering::Release);
                let _ = exit.send(());
            })
            .map_err(|_| Error::Closed)?;
        let mut guard = CallGuard {
            lifetime: lifetime.clone(),
            closed: counters.clone(),
            success: false,
        };
        let profile = tokio::select! {biased;_=cancel.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout_at(deadline,wait)=>r.map_err(|_|Error::Timeout)?.map_err(|_|Error::Closed)?}?;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        guard.success = true;
        Ok(Self {
            commands: Some(commands),
            lifetime,
            exited: Some(exited),
            retired: false,
            metrics: Metrics {
                shared: counters,
                buffer_capacity: capacity,
                limits,
            },
            profile,
        })
    }
    pub fn profile(&self) -> CursorProfile {
        self.profile
    }
    pub fn metrics(&self) -> Metrics {
        self.metrics.clone()
    }
    fn rejected(&self, error: Error) -> Error {
        self.metrics
            .shared
            .rejections
            .fetch_add(1, Ordering::Relaxed);
        if matches!(error, Error::Timeout) {
            self.metrics.shared.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        error
    }
    async fn call(
        &mut self,
        action: Action,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Reply, Error> {
        if self.metrics.shared.closed.load(Ordering::Acquire) || self.lifetime.is_cancelled() {
            return Err(Error::Closed);
        }
        let context = Context {
            deadline,
            cancel: cancel.child_token(),
            lifetime: self.lifetime.clone(),
        };
        context.check().map_err(|e| self.rejected(e))?;
        let (reply, wait) = oneshot::channel();
        self.metrics.shared.queued.fetch_add(1, Ordering::Relaxed);
        if let Err(error) = self
            .commands
            .as_ref()
            .ok_or(Error::Closed)?
            .try_send(Command {
                action,
                context,
                reply,
            })
        {
            self.metrics.shared.queued.fetch_sub(1, Ordering::Relaxed);
            return Err(self.rejected(match error {
                mpsc::TrySendError::Full(_) => Error::Busy,
                mpsc::TrySendError::Disconnected(_) => Error::Closed,
            }));
        }
        let mut guard = CallGuard {
            lifetime: self.lifetime.clone(),
            closed: self.metrics.shared.clone(),
            success: false,
        };
        let result = tokio::select! {biased;_=cancel.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout_at(deadline,wait)=>r.map_err(|_|{self.metrics.shared.timeouts.fetch_add(1,Ordering::Relaxed);Error::Timeout})?.map_err(|_|Error::Closed)?};
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        guard.success = result.is_ok();
        result
    }
    pub async fn restore(
        &mut self,
        cursors: Vec<SourceCheckpoint>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
        if cursors.len() > 16 {
            return Err(self.rejected(Error::Cursor));
        }
        for c in &cursors {
            self.profile
                .checkpoint(c)
                .map_err(|_| self.rejected(Error::Cursor))?;
        }
        match self
            .call(Action::Restore(cursors), deadline, cancel)
            .await?
        {
            Reply::Done => Ok(()),
            _ => Err(Error::Closed),
        }
    }
    pub async fn read(
        &mut self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<ReadOutcome, Error> {
        match self.call(Action::Read, deadline, cancel).await? {
            Reply::Read(r) => Ok(r),
            _ => Err(Error::Closed),
        }
    }
    pub async fn commit(
        &mut self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), Error> {
        match self.call(Action::Commit, deadline, cancel).await? {
            Reply::Done => Ok(()),
            _ => Err(Error::Closed),
        }
    }
    pub async fn close(&mut self, deadline: Instant) -> Result<(), Error> {
        self.lifetime.cancel();
        self.commands.take();
        if self.retired {
            return Ok(());
        }
        let receiver = self.exited.as_mut().ok_or(Error::Closed)?;
        match tokio::time::timeout_at(deadline, receiver).await {
            Err(_) => Err(Error::Timeout),
            Ok(result) => {
                self.exited.take();
                result.map_err(|_| Error::Closed)?;
                self.retired = true;
                Ok(())
            }
        }
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.metrics.shared.closed.store(true, Ordering::Release);
        self.lifetime.cancel();
        self.commands.take();
    }
}

#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(test)]
#[path = "node_input/worker_tests.rs"]
mod tests;

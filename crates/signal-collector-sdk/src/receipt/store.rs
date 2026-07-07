use super::*;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    sync::atomic::Ordering,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

enum Operation {
    Publish(Vec<u8>, ReceiptBinding),
    Inspect(ReceiptBinding),
}
enum Answer {
    Published(ReceiptInfo),
    Inspected(Option<StoredReceipt>),
}
struct Command {
    op: Operation,
    ctx: ExtensionContext,
    reply: oneshot::Sender<Result<Answer, ReceiptError>>,
}
/// One physical blocking worker owns the advisory file lock. Dropping or timing
/// out a caller never releases a lock held by an in-flight disk operation.
pub struct ReceiptStore {
    sender: Option<mpsc::Sender<Command>>,
    worker: Option<JoinHandle<()>>,
    metrics: Arc<Metrics>,
}
impl ReceiptStore {
    pub async fn open(
        config: ReceiptConfig,
        owner: Uuid,
        generation: u64,
        ctx: ExtensionContext,
    ) -> Result<Self, ReceiptError> {
        check(&ctx)?;
        if owner.is_nil() || generation == 0 {
            return Err(ReceiptError::Configuration);
        }
        let (sender, mut receiver) = mpsc::channel::<Command>(QUEUE_CAPACITY);
        let (ready, boot) = oneshot::channel();
        let metrics = Arc::new(Metrics::default());
        let wm = metrics.clone();
        let wc = ctx.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let opened = Engine::open(config, owner, generation, &wc);
            let mut engine = match opened {
                Ok(e) => {
                    if ready.send(Ok(())).is_err() {
                        wm.stopped.store(true, Ordering::Release);
                        return;
                    }
                    e
                }
                Err(e) => {
                    let _ = ready.send(Err(e));
                    wm.stopped.store(true, Ordering::Release);
                    return;
                }
            };
            while let Some(command) = receiver.blocking_recv() {
                wm.depth.fetch_sub(1, Ordering::AcqRel);
                wm.active.store(true, Ordering::Release);
                let result = if command.reply.is_closed() {
                    Err(ReceiptError::Cancelled)
                } else {
                    match command.op {
                        Operation::Publish(bytes, binding) => engine
                            .publish(bytes, &binding, &command.ctx, &wm)
                            .map(Answer::Published),
                        Operation::Inspect(binding) => engine.read(&command.ctx).and_then(|r| {
                            if r.as_ref()
                                .is_some_and(|r| r.metadata["binding"] != binding.0)
                            {
                                Err(ReceiptError::Scope)
                            } else {
                                Ok(Answer::Inspected(r))
                            }
                        }),
                    }
                };
                if result.is_err() {
                    wm.rejected.fetch_add(1, Ordering::AcqRel);
                }
                wm.active.store(false, Ordering::Release);
                if command.reply.send(result).is_err() {
                    wm.unobserved_results.fetch_add(1, Ordering::AcqRel);
                }
            }
            drop(engine);
            wm.stopped.store(true, Ordering::Release);
        });
        let result = tokio::select! {biased; _=ctx.cancellation().cancelled()=>Err(ReceiptError::Cancelled),_=tokio::time::sleep_until(ctx.deadline())=>Err(ReceiptError::Timeout),r=boot=>r.map_err(|_|ReceiptError::Closed)?};
        result?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            metrics,
        })
    }
    async fn request(&self, op: Operation, ctx: ExtensionContext) -> Result<Answer, ReceiptError> {
        if let Err(e) = check(&ctx) {
            self.metrics.rejected.fetch_add(1, Ordering::AcqRel);
            return Err(e);
        }
        let sender = self.sender.as_ref().ok_or(ReceiptError::Closed)?;
        let permit = match sender.try_reserve() {
            Ok(p) => p,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.rejected.fetch_add(1, Ordering::AcqRel);
                return Err(ReceiptError::Busy);
            }
            Err(_) => {
                self.metrics.rejected.fetch_add(1, Ordering::AcqRel);
                return Err(ReceiptError::Closed);
            }
        };
        let (reply, result) = oneshot::channel();
        self.metrics.depth.fetch_add(1, Ordering::AcqRel);
        permit.send(Command {
            op,
            ctx: ctx.clone(),
            reply,
        });
        let answer = tokio::select! {biased;_=ctx.cancellation().cancelled()=>Err(ReceiptError::Cancelled),_=tokio::time::sleep_until(ctx.deadline())=>Err(ReceiptError::Timeout),r=result=>r.map_err(|_|ReceiptError::Closed)?};
        if matches!(answer, Err(ReceiptError::Cancelled | ReceiptError::Timeout)) {
            self.metrics.caller_uncertain.fetch_add(1, Ordering::AcqRel);
        }
        answer
    }
    /// An error/caller cancellation does not prove that publication did not commit.
    pub async fn publish(
        &self,
        bytes: Vec<u8>,
        binding: ReceiptBinding,
        ctx: ExtensionContext,
    ) -> Result<ReceiptInfo, ReceiptError> {
        if bytes.len() > MAX_RECEIPT_BYTES {
            self.metrics.rejected.fetch_add(1, Ordering::AcqRel);
            return Err(ReceiptError::Invalid("receipt bytes"));
        }
        match self
            .request(Operation::Publish(bytes, binding), ctx)
            .await?
        {
            Answer::Published(i) => Ok(i),
            _ => Err(ReceiptError::Closed),
        }
    }
    pub async fn inspect(
        &self,
        binding: ReceiptBinding,
        ctx: ExtensionContext,
    ) -> Result<Option<StoredReceipt>, ReceiptError> {
        match self.request(Operation::Inspect(binding), ctx).await? {
            Answer::Inspected(r) => Ok(r),
            _ => Err(ReceiptError::Closed),
        }
    }
    pub fn metrics(&self) -> ReceiptMetrics {
        self.metrics.snapshot()
    }
    /// Stop admission, drain cancelled/accepted commands and await physical exit.
    /// Deadline/cancellation can return while the worker still owns its lock.
    pub async fn close(mut self, ctx: ExtensionContext) -> Result<(), ReceiptError> {
        self.sender.take();
        let worker = self.worker.take().ok_or(ReceiptError::Closed)?;
        tokio::select! {biased;_=ctx.cancellation().cancelled()=>Err(ReceiptError::Cancelled),_=tokio::time::sleep_until(ctx.deadline())=>Err(ReceiptError::Timeout),r=worker=>r.map_err(|_|ReceiptError::Closed)}
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    ReceiptTempSynced,
    ReceiptLinked,
    ReceiptRenamed,
    ReceiptDirectorySynced,
    ControlTempSynced,
    ControlLinked,
    ControlRenamed,
    ControlDirectorySynced,
}
struct Engine {
    config: ReceiptConfig,
    root: File,
    lock: File,
    owner: Uuid,
    generation: u64,
    poisoned: bool,
}
fn options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600);
    o
}
#[cfg(unix)]
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    false
}
fn private_file(f: &File) -> Result<(), ReceiptError> {
    let m = f.metadata().map_err(io_error)?;
    if !m.is_file() {
        return Err(ReceiptError::Root);
    }
    #[cfg(unix)]
    if m.nlink() != 1 || m.mode() & 0o077 != 0 {
        return Err(ReceiptError::Root);
    }
    Ok(())
}
impl Engine {
    fn open(
        mut config: ReceiptConfig,
        owner: Uuid,
        generation: u64,
        ctx: &ExtensionContext,
    ) -> Result<Self, ReceiptError> {
        check(ctx)?;
        let m = fs::symlink_metadata(&config.root).map_err(io_error)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(ReceiptError::Root);
        }
        #[cfg(unix)]
        if m.mode() & 0o777 != 0o700 {
            return Err(ReceiptError::Root);
        }
        #[cfg(not(unix))]
        return Err(ReceiptError::Root);
        config.root = fs::canonicalize(&config.root).map_err(io_error)?;
        let mut directory_options = options();
        #[cfg(unix)]
        directory_options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY);
        let root = directory_options.open(&config.root).map_err(io_error)?;
        if !same(&m, &root.metadata().map_err(io_error)?) {
            return Err(ReceiptError::Root);
        }
        check(ctx)?;
        let lock = options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.root.join("lock"))
            .map_err(io_error)?;
        private_file(&lock)?;
        #[cfg(unix)]
        if lock.metadata().map_err(io_error)?.uid() != m.uid() {
            return Err(ReceiptError::Root);
        }
        if lock.metadata().map_err(io_error)?.len() != 0 {
            return Err(ReceiptError::Root);
        }
        lock.try_lock().map_err(|_| ReceiptError::Locked)?;
        root.sync_all().map_err(io_error)?;
        check(ctx)?;
        let mut engine = Self {
            config,
            root,
            lock,
            owner,
            generation,
            poisoned: false,
        };
        engine.read(ctx)?;
        Ok(engine)
    }
    fn stable(&self, ctx: &ExtensionContext) -> Result<(), ReceiptError> {
        check(ctx)?;
        if self.poisoned {
            return Err(ReceiptError::Uncertain);
        }
        let root = fs::symlink_metadata(&self.config.root).map_err(io_error)?;
        let lock = fs::symlink_metadata(self.config.root.join("lock")).map_err(io_error)?;
        #[cfg(unix)]
        if root.mode() & 0o777 != 0o700
            || root.uid() != self.lock.metadata().map_err(io_error)?.uid()
        {
            return Err(ReceiptError::Root);
        }
        private_file(&self.lock)?;
        if !same(&root, &self.root.metadata().map_err(io_error)?)
            || !same(&lock, &self.lock.metadata().map_err(io_error)?)
            || root.file_type().is_symlink()
            || lock.file_type().is_symlink()
        {
            return Err(ReceiptError::Root);
        }
        Ok(())
    }
    fn scan(&self, ctx: &ExtensionContext) -> Result<(Option<Uuid>, bool), ReceiptError> {
        self.stable(ctx)?;
        let mut id = None;
        let mut control = false;
        let mut temp = false;
        let mut used = 4 * 1024 * 1024u64;
        let mut count = 0;
        for entry in fs::read_dir(&self.config.root).map_err(io_error)? {
            self.stable(ctx)?;
            count += 1;
            if count > 6 {
                return Err(ReceiptError::Root);
            }
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ReceiptError::Root)?;
            let cap = match name.as_str() {
                "lock" => 0,
                "control" => {
                    control = true;
                    8 * 1024 * 1024
                }
                "control.next" => {
                    temp = true;
                    8 * 1024 * 1024
                }
                "receipt.next" => {
                    temp = true;
                    MAX_RECEIPT_BYTES as u64
                }
                "capture.next" => {
                    temp = true;
                    8 * 1024 * 1024
                }
                s => {
                    let Some(s) = s.strip_suffix(".src") else {
                        return Err(ReceiptError::Root);
                    };
                    let parsed = Uuid::parse_str(s).map_err(|_| ReceiptError::Root)?;
                    if parsed.is_nil() || parsed.to_string() != s || id.replace(parsed).is_some() {
                        return Err(ReceiptError::Root);
                    }
                    MAX_RECEIPT_BYTES as u64
                }
            };
            let f = options().open(entry.path()).map_err(io_error)?;
            private_file(&f)?;
            #[cfg(unix)]
            if f.metadata().map_err(io_error)?.uid()
                != self.root.metadata().map_err(io_error)?.uid()
            {
                return Err(ReceiptError::Root);
            }
            let size = f.metadata().map_err(io_error)?.len();
            if size > cap {
                return Err(ReceiptError::Quota);
            }
            used = used.checked_add(size).ok_or(ReceiptError::Quota)?;
        }
        if used > self.config.quota {
            return Err(ReceiptError::Quota);
        }
        self.stable(ctx)?;
        if temp || control != id.is_some() {
            return Err(ReceiptError::Uncertain);
        }
        Ok((id, control))
    }
    fn load(
        &self,
        name: &str,
        cap: usize,
        ctx: &ExtensionContext,
    ) -> Result<Vec<u8>, ReceiptError> {
        self.stable(ctx)?;
        let mut file = options()
            .open(self.config.root.join(name))
            .map_err(io_error)?;
        private_file(&file)?;
        let len = file.metadata().map_err(io_error)?.len();
        if len > cap as u64 {
            return Err(ReceiptError::Quota);
        }
        let len = usize::try_from(len).map_err(|_| ReceiptError::Quota)?;
        let mut out = Vec::with_capacity(len);
        let mut chunk = [0; 65536];
        loop {
            self.stable(ctx)?;
            let n = file.read(&mut chunk).map_err(io_error)?;
            if n == 0 {
                break;
            }
            if out.len().checked_add(n).is_none_or(|l| l > len) {
                return Err(ReceiptError::Uncertain);
            }
            out.extend_from_slice(&chunk[..n]);
        }
        if out.len() != len || file.metadata().map_err(io_error)?.len() != len as u64 {
            return Err(ReceiptError::Uncertain);
        }
        self.stable(ctx)?;
        Ok(out)
    }
    fn read_inner(&self, ctx: &ExtensionContext) -> Result<Option<StoredReceipt>, ReceiptError> {
        let (id, _) = self.scan(ctx)?;
        let Some(id) = id else {
            return Ok(None);
        };
        let r = format::decode(
            self.load(&format!("{id}.src"), MAX_RECEIPT_BYTES, ctx)?,
            ctx,
        )?;
        if r.info.id != id {
            return Err(ReceiptError::Invalid("filename identity"));
        }
        let control = self.load("control", 8 * 1024 * 1024, ctx)?;
        format::verify_initial(&control, &r, self.owner, self.generation)?;
        Ok(Some(r))
    }
    fn read(&mut self, ctx: &ExtensionContext) -> Result<Option<StoredReceipt>, ReceiptError> {
        let result = self.read_inner(ctx);
        if matches!(&result,Err(e) if !matches!(e,ReceiptError::Cancelled|ReceiptError::Timeout)) {
            self.poisoned = true;
        }
        result
    }
    fn hit(&self, stage: Stage, ctx: &ExtensionContext) -> Result<(), ReceiptError> {
        self.stable(ctx)?;
        #[cfg(test)]
        if let Some(h) = &self.config.hook {
            h(stage)?;
        }
        #[cfg(not(test))]
        let _ = stage;
        self.stable(ctx)
    }
    fn write(&self, name: &str, data: &[u8], ctx: &ExtensionContext) -> Result<(), ReceiptError> {
        self.stable(ctx)?;
        let mut f = options()
            .write(true)
            .create_new(true)
            .open(self.config.root.join(name))
            .map_err(io_error)?;
        for b in data.chunks(65536) {
            self.stable(ctx)?;
            f.write_all(b).map_err(io_error)?;
        }
        self.stable(ctx)?;
        f.sync_all().map_err(io_error)?;
        self.stable(ctx)
    }
    fn publish(
        &mut self,
        bytes: Vec<u8>,
        binding: &ReceiptBinding,
        ctx: &ExtensionContext,
        metrics: &Metrics,
    ) -> Result<ReceiptInfo, ReceiptError> {
        self.stable(ctx)?;
        let r = format::decode(bytes, ctx)?;
        if r.metadata["binding"] != binding.0 {
            return Err(ReceiptError::Scope);
        }
        if let Some(old) = self.read(ctx)? {
            if old.info.id != r.info.id {
                return Err(ReceiptError::Occupied);
            }
            if old.bytes != r.bytes {
                return Err(ReceiptError::IdentityConflict);
            }
            metrics.replays.fetch_add(1, Ordering::AcqRel);
            return Ok(old.info);
        }
        let control = format::initial(&r, self.owner, self.generation)?;
        // Reserve the complete laboratory work budget, not just short fixture sizes.
        if self.config.quota < 60 * 1024 * 1024 {
            return Err(ReceiptError::Quota);
        }
        check(ctx)?;
        let result = (|| {
            self.write("receipt.next", &r.bytes, ctx)?;
            self.hit(Stage::ReceiptTempSynced, ctx)?;
            // Exclusive namespace creation never clobbers an injected destination.
            // Both names temporarily refer to one inode: no second payload copy.
            fs::hard_link(
                self.config.root.join("receipt.next"),
                self.config.root.join(format!("{}.src", r.info.id)),
            )
            .map_err(io_error)?;
            self.hit(Stage::ReceiptLinked, ctx)?;
            fs::remove_file(self.config.root.join("receipt.next")).map_err(io_error)?;
            self.hit(Stage::ReceiptRenamed, ctx)?;
            self.root.sync_all().map_err(io_error)?;
            self.hit(Stage::ReceiptDirectorySynced, ctx)?;
            self.write("control.next", &control, ctx)?;
            self.hit(Stage::ControlTempSynced, ctx)?;
            fs::hard_link(
                self.config.root.join("control.next"),
                self.config.root.join("control"),
            )
            .map_err(io_error)?;
            self.hit(Stage::ControlLinked, ctx)?;
            fs::remove_file(self.config.root.join("control.next")).map_err(io_error)?;
            self.hit(Stage::ControlRenamed, ctx)?;
            self.root.sync_all().map_err(io_error)?;
            self.hit(Stage::ControlDirectorySynced, ctx)?;
            Ok(r.info)
        })();
        if result.is_err() {
            self.poisoned = true;
        } else {
            metrics.admitted.fetch_add(1, Ordering::AcqRel);
        }
        result
    }
}

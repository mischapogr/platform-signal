//! One bounded CPU worker for object Parquet preparation/inspection. It performs
//! no network or disk I/O and grants no publication, checkpoint or source custody.
//! Outstanding results retain admission until they are dropped or consumed.
mod intake;
mod parquet;
use crate::object_manifest::{ManifestLimits, QueryFile};
use crate::{OperationContext, StorageConfig, StorageError, StoredEvent, check_context};
use bytes::Bytes;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::{Instant, timeout_at},
};

pub struct PreparedQueryFile {
    pub(crate) date: String,
    pub(crate) hour: u8,
    pub(crate) body: Bytes,
    pub(crate) rows: usize,
    pub(crate) decoded_bytes: u64,
    pub(crate) sha256: [u8; 32],
}
impl PreparedQueryFile {
    pub fn date(&self) -> &str {
        &self.date
    }
    pub fn hour(&self) -> u8 {
        self.hour
    }
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }
    pub fn rows(&self) -> usize {
        self.rows
    }
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}
pub struct PreparedQueryBatch {
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) events: usize,
    pub(crate) files: Vec<PreparedQueryFile>,
    _permit: Arc<OwnedSemaphorePermit>,
}
impl PreparedQueryBatch {
    pub fn first_sequence(&self) -> u64 {
        self.first
    }
    pub fn last_sequence(&self) -> u64 {
        self.last
    }
    pub fn event_count(&self) -> usize {
        self.events
    }
    pub fn files(&self) -> &[PreparedQueryFile] {
        &self.files
    }
}
pub struct InspectedQueryFile {
    rows: Vec<StoredEvent>,
    _permit: Arc<OwnedSemaphorePermit>,
}
impl InspectedQueryFile {
    pub fn rows(&self) -> &[StoredEvent] {
        &self.rows
    }
}
#[derive(Clone, Copy, Debug)]
pub struct CodecMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub running: usize,
    pub worker_capacity: usize,
    pub rejected: u64,
    pub processed: u64,
    pub closed: bool,
}
struct Shared {
    permits: Arc<Semaphore>,
    closed: AtomicBool,
    running: AtomicUsize,
    rejected: AtomicU64,
    processed: AtomicU64,
}
struct WorkerExit(Arc<Shared>);
struct RejectionObservation {
    shared: Arc<Shared>,
    armed: bool,
}
impl RejectionObservation {
    fn finish<T>(&mut self, result: &Result<T, StorageError>) {
        self.armed = result.is_err();
    }
}
impl Drop for RejectionObservation {
    fn drop(&mut self) {
        if self.armed {
            self.shared.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.running.store(0, Ordering::Release);
        self.0.closed.store(true, Ordering::Release);
        self.0.permits.close();
    }
}
struct CancelOnDrop {
    context: OperationContext,
    armed: bool,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.context.cancellation.cancel();
        }
    }
}
enum Work {
    Encode(Vec<u8>),
    Inspect(QueryFile, Vec<u8>, u64, u64),
    #[cfg(test)]
    Pause(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>),
}
enum Reply {
    Prepared(PreparedQueryBatch),
    Inspected(InspectedQueryFile),
    #[cfg(test)]
    Done,
}
struct Command {
    work: Work,
    context: OperationContext,
    permit: Arc<OwnedSemaphorePermit>,
    reply: oneshot::Sender<Completion>,
}
struct Completion {
    result: Result<Reply, StorageError>,
    _permit: Arc<OwnedSemaphorePermit>,
}
/// One worker, one queued/outstanding request/result. Input logical sizes and all
/// codec allocations are bounded by config. Intake borrows typed caller memory,
/// walks bounded nesting/nodes, and transfers only finite wire copies to work.
/// Rejected deep caller values remain caller-owned and are never dropped here.
pub struct ObjectCodec {
    sender: Mutex<Option<mpsc::Sender<Command>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    shared: Arc<Shared>,
    config: StorageConfig,
    limits: ManifestLimits,
}
impl ObjectCodec {
    pub fn new(config: StorageConfig, limits: ManifestLimits) -> Result<Self, StorageError> {
        config.validate()?;
        limits
            .validate()
            .map_err(|_| StorageError::Config("object codec limits"))?;
        let shared = Arc::new(Shared {
            permits: Arc::new(Semaphore::new(1)),
            closed: AtomicBool::new(false),
            running: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
            processed: AtomicU64::new(0),
        });
        let (sender, mut receiver) = mpsc::channel::<Command>(1);
        let state = shared.clone();
        let policy = config.clone();
        let worker = thread::Builder::new()
            .name("signal-object-codec".into())
            .spawn(move || {
                let _exit = WorkerExit(state.clone());
                while let Some(command) = receiver.blocking_recv() {
                    state.processed.fetch_add(1, Ordering::Relaxed);
                    state.running.store(1, Ordering::Release);
                    let result = (|| {
                        check_context(Some(&command.context))?;
                        let result = match command.work {
                            Work::Encode(wire) => {
                                let rows = intake::decode(&wire, &command.context)?;
                                let (first, last, events, files) =
                                    parquet::encode(rows, &policy, limits, &command.context)?;
                                Reply::Prepared(PreparedQueryBatch {
                                    first,
                                    last,
                                    events,
                                    files,
                                    _permit: command.permit.clone(),
                                })
                            }
                            Work::Inspect(file, bytes, first, last) => {
                                let rows = parquet::inspect(
                                    &file,
                                    bytes,
                                    first,
                                    last,
                                    &policy,
                                    limits,
                                    &command.context,
                                )?;
                                Reply::Inspected(InspectedQueryFile {
                                    rows,
                                    _permit: command.permit.clone(),
                                })
                            }
                            #[cfg(test)]
                            Work::Pause(entered, release) => {
                                let _ = entered.send(());
                                let _ = release.recv();
                                Reply::Done
                            }
                        };
                        check_context(Some(&command.context))?;
                        Ok(result)
                    })();
                    state.running.store(0, Ordering::Release);
                    // Move the physical lease into the reply before waking the
                    // caller. Errors/unpolled replies also retain admission.
                    let _ = command.reply.send(Completion {
                        result,
                        _permit: command.permit,
                    });
                }
            })
            .map_err(StorageError::Io)?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            shared,
            config,
            limits,
        })
    }
    pub fn metrics(&self) -> CodecMetrics {
        CodecMetrics {
            depth: 1 - self.shared.permits.available_permits(),
            capacity: 1,
            running: self.shared.running.load(Ordering::Acquire),
            worker_capacity: 1,
            rejected: self.shared.rejected.load(Ordering::Relaxed),
            processed: self.shared.processed.load(Ordering::Relaxed),
            closed: self.shared.closed.load(Ordering::Acquire),
        }
    }
    fn admit(
        &self,
        context: &mut OperationContext,
    ) -> Result<Arc<OwnedSemaphorePermit>, StorageError> {
        context.deadline = context
            .deadline
            .min(Instant::now() + self.config.operation_timeout);
        check_context(Some(context))?;
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(StorageError::Closed);
        }
        let permit = self
            .shared
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                if self.shared.closed.load(Ordering::Acquire) {
                    StorageError::Closed
                } else {
                    StorageError::Full
                }
            })?;
        Ok(Arc::new(permit))
    }

    async fn request(
        &self,
        work: Work,
        context: OperationContext,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<Reply, StorageError> {
        check_context(Some(&context))?;
        let (reply, receive) = oneshot::channel();
        self.sender
            .lock()
            .map_err(|_| StorageError::Closed)?
            .as_ref()
            .ok_or(StorageError::Closed)?
            .try_send(Command {
                work,
                context: context.clone(),
                permit: permit.clone(),
                reply,
            })
            .map_err(|_| StorageError::Closed)?;
        let mut guard = CancelOnDrop {
            context: context.clone(),
            armed: true,
        };
        let result = tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => return Err(StorageError::Cancelled),
            result = timeout_at(context.deadline, receive) => match result {
                Err(_) => return Err(StorageError::Timeout),
                Ok(Err(_)) => return Err(StorageError::Closed),
                Ok(Ok(reply)) => reply.result,
            }
        };
        guard.armed = false;
        result
    }
    pub async fn prepare(
        &self,
        rows: &[StoredEvent],
        context: OperationContext,
    ) -> Result<PreparedQueryBatch, StorageError> {
        let mut observation = RejectionObservation {
            shared: self.shared.clone(),
            armed: true,
        };
        let result = self.prepare_inner(rows, context).await;
        observation.finish(&result);
        result
    }
    async fn prepare_inner(
        &self,
        rows: &[StoredEvent],
        mut context: OperationContext,
    ) -> Result<PreparedQueryBatch, StorageError> {
        if rows.is_empty() || rows.len() > self.config.max_batch_events.min(self.limits.events) {
            return Err(StorageError::InvalidBatch);
        }
        // Admission precedes every internal traversal/copy/serialization allocation.
        let permit = self.admit(&mut context)?;
        let wire = intake::encode(rows, &self.config, &context)?;
        match self.request(Work::Encode(wire), context, permit).await? {
            Reply::Prepared(result) => Ok(result),
            _ => Err(StorageError::Closed),
        }
    }
    pub async fn inspect(
        &self,
        file: &QueryFile,
        bytes: &[u8],
        first: u64,
        last: u64,
        context: OperationContext,
    ) -> Result<InspectedQueryFile, StorageError> {
        let mut observation = RejectionObservation {
            shared: self.shared.clone(),
            armed: true,
        };
        let result = self.inspect_inner(file, bytes, first, last, context).await;
        observation.finish(&result);
        result
    }
    async fn inspect_inner(
        &self,
        file: &QueryFile,
        bytes: &[u8],
        first: u64,
        last: u64,
        mut context: OperationContext,
    ) -> Result<InspectedQueryFile, StorageError> {
        check_context(Some(&context))?;
        let object_limit = self.limits.object_bytes.min(self.config.file_limit());
        if bytes.len() as u64 > object_limit
            || file.rows > self.config.max_batch_events.min(self.limits.events)
        {
            return Err(StorageError::Full);
        }
        let permit = self.admit(&mut context)?;
        file.object
            .verify_bytes(bytes, object_limit)
            .map_err(|_| StorageError::Corrupt("object reference"))?;
        file.intersects(None, None)
            .map_err(|_| StorageError::Corrupt("object partition"))?;
        let file = file.clone(); // Clone logical bounded metadata, never caller spare capacity.
        let bytes = intake::copy(bytes, object_limit as usize)?;
        check_context(Some(&context))?;
        match self
            .request(Work::Inspect(file, bytes, first, last), context, permit)
            .await?
        {
            Reply::Inspected(result) => Ok(result),
            _ => Err(StorageError::Closed),
        }
    }
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.permits.close();
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), StorageError> {
        self.close();
        loop {
            check_context(Some(&context))?;
            let finished = self
                .worker
                .lock()
                .map_err(|_| StorageError::Closed)?
                .as_ref()
                .is_none_or(|w| w.is_finished());
            if finished {
                if let Some(worker) = self.worker.lock().map_err(|_| StorageError::Closed)?.take() {
                    worker.join().map_err(|_| StorageError::Closed)?;
                }
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }
}
impl Drop for ObjectCodec {
    fn drop(&mut self) {
        self.close();
    }
}
#[cfg(test)]
mod tests;

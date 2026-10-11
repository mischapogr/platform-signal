//! Exact-object reader for trusted committed catalog bytes. It does not discover
//! commitment, grant tenant authority, publish objects or enable remote deletion.
use crate::object_cache::{Cache, MaterializationConfig};
use crate::object_codec::ObjectCodec;
use crate::object_io::{ObjectIo, ObjectIoError};
use crate::object_manifest::{ManifestLimits, QueryManifest, sha256};
use crate::{FileSelection, OperationContext, StorageConfig, StorageError, check_context};
use chrono::{DateTime, Utc};
use std::{
    collections::BTreeSet,
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
use uuid::Uuid;

const CATALOG_BYTES: usize = 1024 * 1024;
const CATALOG_ITEMS: usize = 128;

#[derive(Clone, Debug)]
pub struct SelectionConfig {
    pub stream: Uuid,
    /// Trusted host's backend mapping, checked against database catalog authority.
    pub backend: Uuid,
    pub storage: StorageConfig,
    pub manifests: ManifestLimits,
    pub cache: MaterializationConfig,
}
impl SelectionConfig {
    fn validate(&self) -> Result<(), StorageError> {
        self.storage.validate()?;
        self.cache.validate()?;
        self.manifests
            .validate()
            .map_err(|_| StorageError::Config("selection manifest bounds"))?;
        if self.stream.is_nil() || self.backend.is_nil() {
            return Err(StorageError::Config("selection stream/backend"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct SelectionMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub running: usize,
    pub worker_capacity: usize,
    pub processed: u64,
    pub rejected: u64,
    pub closed: bool,
}
struct State {
    slots: Arc<Semaphore>,
    closed: AtomicBool,
    running: AtomicUsize,
    processed: AtomicU64,
    rejected: AtomicU64,
    cleanup_failed: AtomicBool,
    cache_owner: Mutex<Option<Arc<crate::object_owner::SmallOwner>>>,
}
struct Exit(Arc<State>);
impl Drop for Exit {
    fn drop(&mut self) {
        self.0.running.store(0, Ordering::Release);
        self.0.closed.store(true, Ordering::Release);
        self.0.slots.close();
    }
}
struct Guard {
    state: Arc<State>,
    context: OperationContext,
    failed: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.failed {
            self.state.rejected.fetch_add(1, Ordering::Relaxed);
            self.context.cancellation.cancel();
        }
    }
}
/// Selection policy is bounded independently of caller query limits.
#[derive(Clone, Copy)]
pub struct SelectionBounds {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub max_files: usize,
    pub max_decoded_bytes: u64,
}
struct Command {
    manifests: Vec<Vec<u8>>,
    bounds: SelectionBounds,
    context: OperationContext,
    slot: Arc<OwnedSemaphorePermit>,
    reply: oneshot::Sender<Completion>,
}
struct Completion {
    result: Result<FileSelection, StorageError>,
    _slot: Arc<OwnedSemaphorePermit>,
}
/// One ordinary controller, one exact I/O worker and one codec worker. A cancelled
/// caller does not release admission until all physical child operations drain.
pub struct ObjectSelection {
    io: Arc<ObjectIo>,
    codec: Arc<ObjectCodec>,
    config: SelectionConfig,
    state: Arc<State>,
    sender: Mutex<Option<mpsc::Sender<Command>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl ObjectSelection {
    pub fn new(
        io: ObjectIo,
        runtime: tokio::runtime::Handle,
        config: SelectionConfig,
    ) -> Result<Self, StorageError> {
        config.validate()?;
        if io.small_owner_binding().is_some() {
            return Err(StorageError::Config(
                "shared selection requires unowned read I/O",
            ));
        }
        let codec = Arc::new(ObjectCodec::new(config.storage.clone(), config.manifests)?);
        Self::with_workers(Arc::new(io), codec, runtime, config)
    }
    /// Retain child-worker ownership in the host even if controller creation
    /// fails. Immutable codec bounds must match the selection configuration.
    pub fn with_workers(
        io: Arc<ObjectIo>,
        codec: Arc<ObjectCodec>,
        runtime: tokio::runtime::Handle,
        config: SelectionConfig,
    ) -> Result<Self, StorageError> {
        config.validate()?;
        if io.small_owner_binding().is_some()
            || !codec.matches_configuration(&config.storage, config.manifests)
            || io.metrics().closed
            || codec.metrics().closed
        {
            return Err(StorageError::Config("selection retained worker binding"));
        }
        let observed_io = io.clone();
        let observed_codec = codec.clone();
        let state = Arc::new(State {
            slots: Arc::new(Semaphore::new(1)),
            closed: AtomicBool::new(false),
            running: AtomicUsize::new(0),
            processed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            cleanup_failed: AtomicBool::new(false),
            cache_owner: Mutex::new(None),
        });
        let shared = state.clone();
        let policy = config.clone();
        let (sender, mut receive) = mpsc::channel::<Command>(1);
        let worker = thread::Builder::new()
            .name("signal-object-select".into())
            .spawn(move || {
                let _exit = Exit(shared.clone());
                let mut cache = None;
                while let Some(command) = receive.blocking_recv() {
                    shared.running.store(1, Ordering::Release);
                    shared.processed.fetch_add(1, Ordering::Relaxed);
                    let result = runtime
                        .block_on(select(&io, &codec, &mut cache, &shared, &policy, &command));
                    runtime.block_on(async {
                        while io.metrics().depth != 0 || codec.metrics().depth != 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                        }
                    });
                    shared.running.store(0, Ordering::Release);
                    let _ = command.reply.send(Completion {
                        result,
                        _slot: command.slot,
                    });
                }
                let context = OperationContext::new(policy.storage.operation_timeout);
                let (cpu, disk) = runtime.block_on(async {
                    let cpu = codec.shutdown(context.clone()).await;
                    let disk = io.shutdown(context).await;
                    (cpu, disk)
                });
                shared
                    .cleanup_failed
                    .store(cpu.is_err() || disk.is_err(), Ordering::Release);
            })
            .map_err(StorageError::Io)?;
        Ok(Self {
            io: observed_io,
            codec: observed_codec,
            config,
            state,
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
        })
    }
    pub fn binding(&self) -> (Uuid, Uuid) {
        (self.config.stream, self.config.backend)
    }
    pub fn validate_bounds(&self, bounds: SelectionBounds) -> Result<(), StorageError> {
        if bounds.max_files == 0
            || bounds.max_files > self.config.storage.max_files
            || bounds.max_decoded_bytes == 0
            || bounds.max_decoded_bytes > self.config.manifests.decoded_bytes
            || matches!((bounds.from,bounds.to),(Some(from),Some(to)) if from>to)
        {
            return Err(StorageError::InvalidBatch);
        }
        Ok(())
    }
    pub fn metrics(&self) -> SelectionMetrics {
        SelectionMetrics {
            depth: 1 - self.state.slots.available_permits(),
            capacity: 1,
            running: self.state.running.load(Ordering::Acquire),
            worker_capacity: 1,
            processed: self.state.processed.load(Ordering::Relaxed),
            rejected: self.state.rejected.load(Ordering::Relaxed),
            closed: self.state.closed.load(Ordering::Acquire),
        }
    }
    /// Read-only physical child metrics; retaining them never grants admission.
    pub fn io_metrics(&self) -> crate::object_io::ObjectIoMetrics {
        self.io.metrics()
    }
    pub fn codec_metrics(&self) -> crate::object_codec::CodecMetrics {
        self.codec.metrics()
    }
    /// The host must establish committed catalog authority before calling this.
    /// Borrowed bytes are copied only after admission and aggregate size checks.
    /// Context must already be restricted to the original non-renewable pin.
    pub async fn materialize(
        &self,
        manifests: &[&[u8]],
        bounds: SelectionBounds,
        mut context: OperationContext,
    ) -> Result<FileSelection, StorageError> {
        context.deadline = context
            .deadline
            .min(Instant::now() + self.config.storage.operation_timeout);
        context.cancellation = context.cancellation.child_token();
        let mut guard = Guard {
            state: self.state.clone(),
            context: context.clone(),
            failed: true,
        };
        check_context(Some(&context))?;
        if self.state.closed.load(Ordering::Acquire) {
            return Err(StorageError::Closed);
        }
        let slot = self
            .state
            .slots
            .clone()
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| {
                if self.state.closed.load(Ordering::Acquire) {
                    StorageError::Closed
                } else {
                    StorageError::Busy
                }
            })?;
        self.validate_bounds(bounds)?;
        if manifests.len() > CATALOG_ITEMS {
            return Err(StorageError::InvalidBatch);
        }
        let mut bytes = 0_usize;
        for manifest in manifests {
            check_context(Some(&context))?;
            bytes = bytes
                .checked_add(manifest.len())
                .ok_or(StorageError::Full)?;
            if manifest.is_empty()
                || manifest.len() > self.config.manifests.manifest_bytes
                || bytes > CATALOG_BYTES
            {
                return Err(StorageError::Full);
            }
        }
        let (reply, receive) = oneshot::channel();
        self.sender
            .lock()
            .map_err(|_| StorageError::Closed)?
            .as_ref()
            .ok_or(StorageError::Closed)?
            .try_send(Command {
                manifests: manifests.iter().map(|bytes| bytes.to_vec()).collect(),
                bounds,
                context: context.clone(),
                slot,
                reply,
            })
            .map_err(|_| StorageError::Closed)?;
        let completion = tokio::select! { biased;
            _ = context.cancellation.cancelled() => return Err(StorageError::Cancelled),
            result = timeout_at(context.deadline,receive) => match result { Err(_)=>return Err(StorageError::Timeout), Ok(Err(_))=>return Err(StorageError::Closed), Ok(Ok(value))=>value },
        };
        check_context(Some(&context))?;
        let mut selection = completion.result?;
        selection.check_lifetime()?;
        selection.selection_slot = Some(completion._slot);
        guard.failed = false;
        Ok(selection)
    }
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
        self.state.slots.close();
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
                .is_none_or(|worker| worker.is_finished());
            if finished {
                if let Some(worker) = self.worker.lock().map_err(|_| StorageError::Closed)?.take() {
                    worker.join().map_err(|_| StorageError::Closed)?;
                }
                return if self.state.cleanup_failed.load(Ordering::Acquire) {
                    Err(StorageError::Closed)
                } else {
                    Ok(())
                };
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }
}
impl Drop for ObjectSelection {
    fn drop(&mut self) {
        self.close();
    }
}

async fn select(
    io: &ObjectIo,
    codec: &ObjectCodec,
    cache: &mut Option<Cache>,
    state: &State,
    config: &SelectionConfig,
    command: &Command,
) -> Result<FileSelection, StorageError> {
    let context = &command.context;
    check_context(Some(context))?;
    let mut selected = Vec::new();
    let mut decoded = 0_u64;
    let mut objects = 0_usize;
    let mut partitions = BTreeSet::new();
    let mut last = 0_u64;
    let mut previous: Option<(&[u8], QueryManifest)> = None;
    // Validate the complete catalog before touching objects or cache state.
    for bytes in &command.manifests {
        check_context(Some(context))?;
        let manifest: QueryManifest = serde_json::from_slice(bytes)
            .map_err(|_| StorageError::Corrupt("selected manifest"))?;
        manifest
            .validate(config.manifests, config.stream)
            .map_err(|_| StorageError::Corrupt("selected manifest binding"))?;
        if Some(manifest.first_sequence) != last.checked_add(1) {
            return Err(StorageError::Corrupt("selected chain"));
        }
        match (&previous, &manifest.previous) {
            (None, None) => {}
            (Some((raw, prior)), Some(reference))
                if reference.first_sequence == prior.first_sequence
                    && reference.last_sequence == prior.last_sequence
                    && reference.object.bytes == raw.len() as u64
                    && reference.object.sha256 == sha256(raw) => {}
            _ => return Err(StorageError::Corrupt("selected predecessor")),
        }
        objects = objects
            .checked_add(manifest.files.len() + usize::from(manifest.previous.is_some()))
            .ok_or(StorageError::Full)?;
        if objects > CATALOG_ITEMS {
            return Err(StorageError::Full);
        }
        for file in &manifest.files {
            check_context(Some(context))?;
            if !file
                .intersects(command.bounds.from, command.bounds.to)
                .map_err(|_| StorageError::Corrupt("selected partition"))?
            {
                continue;
            }
            if selected.len() >= command.bounds.max_files {
                return Err(StorageError::Full);
            }
            decoded = decoded
                .checked_add(file.decoded_bytes)
                .ok_or(StorageError::Full)?;
            if decoded > command.bounds.max_decoded_bytes {
                return Err(StorageError::Full);
            }
            partitions.insert((file.date.clone(), file.hour));
            selected.push((
                file.clone(),
                manifest.first_sequence,
                manifest.last_sequence,
            ));
        }
        last = manifest.last_sequence;
        previous = Some((bytes, manifest));
    }
    let mut selection = FileSelection {
        partitions: partitions.len(),
        ..Default::default()
    };
    selection.restrict_deadline(context.deadline);
    if !selected.is_empty() && cache.is_none() {
        let opened = Cache::open(&config.cache, config.stream, config.backend, context)?;
        *state.cache_owner.lock().map_err(|_| StorageError::Closed)? = Some(opened.owner());
        *cache = Some(opened);
    }
    for (file, first, last) in selected {
        check_context(Some(context))?;
        let read = io
            .read_exact(&file.object, context.clone())
            .await
            .map_err(io_error)?;
        let inspected = codec
            .inspect(&file, read.bytes(), first, last, context.clone())
            .await?;
        let cache = cache.as_ref().ok_or(StorageError::Closed)?;
        selection
            .files
            .push(cache.materialize(&file, read.bytes(), context)?);
        selection.retain_materialization(cache.owner());
        drop(inspected);
        drop(read);
    }
    check_context(Some(context))?;
    Ok(selection)
}
fn io_error(error: ObjectIoError) -> StorageError {
    match error {
        ObjectIoError::Timeout => StorageError::Timeout,
        ObjectIoError::Cancelled => StorageError::Cancelled,
        ObjectIoError::Full => StorageError::Full,
        ObjectIoError::Closed => StorageError::Closed,
        other => StorageError::ObjectIo(other),
    }
}
#[cfg(test)]
mod tests;

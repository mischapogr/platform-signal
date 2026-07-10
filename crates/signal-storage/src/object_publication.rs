//! Small single-owner query publication. Immutable objects and manifests are
//! validated before the local head advances. This is not original custody,
//! distributed fencing, source completeness, or backend durability qualification.
use crate::object_cache::{Cache, MaterializationConfig};
use crate::object_codec::{ObjectCodec, intake};
use crate::object_io::{ObjectIo, ObjectIoError};
use crate::object_manifest::{
    MANIFEST_SCHEMA_VERSION, ManifestLimits, PreviousManifest, QueryFile, QueryManifest,
    QueryObjectRef, data_key, manifest_key,
};
use crate::{
    FileSelection, OperationContext, QueryFileSource, StorageConfig, StorageError, StoreFuture,
    StoreReceipt, StoredEvent, check_context,
};
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

#[derive(Clone, Debug)]
pub struct PublicationConfig {
    pub storage: StorageConfig,
    pub manifests: ManifestLimits,
    /// Includes committed references and unreferenced query objects, never raw
    /// evidence. Exhaustion holds progress; this module does not delete objects.
    pub inventory_objects: usize,
    pub catalog_bytes: usize,
    pub normalizer_revision: String,
    pub materialization: Option<MaterializationConfig>,
}
impl Default for PublicationConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            manifests: ManifestLimits::default(),
            inventory_objects: 10_000,
            catalog_bytes: 16 * 1024 * 1024,
            normalizer_revision: "signal-event-v1".into(),
            materialization: None,
        }
    }
}
impl PublicationConfig {
    fn validate(&self) -> Result<(), StorageError> {
        self.storage.validate()?;
        if let Some(config) = &self.materialization {
            config.validate()?;
        }
        self.manifests
            .validate()
            .map_err(|_| StorageError::Config("publication manifest bounds"))?;
        if self.inventory_objects == 0
            || self.inventory_objects > 100_000
            || !(4096..=64 * 1024 * 1024).contains(&self.catalog_bytes)
            || self.normalizer_revision.is_empty()
            || self.normalizer_revision.len() > 128
            || self.normalizer_revision.chars().any(char::is_control)
            || self.storage.directory.as_os_str().len() > 4096
            || self.storage.directory.components().count() > 64
        {
            return Err(StorageError::Config("publication bounds"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct CommittedManifest {
    pub reference: PreviousManifest,
    pub manifest: QueryManifest,
}
/// Owned finite metadata; holding a snapshot retains publisher admission. Query
/// consumers still must authenticate exact object bytes before exposing rows.
pub struct CommittedSnapshot {
    manifests: Vec<CommittedManifest>,
    orphans: Vec<QueryObjectRef>,
    _slot: Arc<OwnedSemaphorePermit>,
}
impl CommittedSnapshot {
    pub fn manifests(&self) -> &[CommittedManifest] {
        &self.manifests
    }
    pub fn orphans(&self) -> &[QueryObjectRef] {
        &self.orphans
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PublicationMetrics {
    pub high_water: u64,
    pub depth: usize,
    pub capacity: usize,
    pub running: usize,
    pub worker_capacity: usize,
    pub processed: u64,
    pub rejected: u64,
    pub closed: bool,
}
struct Shared {
    slots: Arc<Semaphore>,
    closed: AtomicBool,
    running: AtomicUsize,
    processed: AtomicU64,
    rejected: AtomicU64,
    high_water: AtomicU64,
    cleanup_failed: AtomicBool,
}
struct WorkerExit(Arc<Shared>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.running.store(0, Ordering::Release);
        self.0.closed.store(true, Ordering::Release);
        self.0.slots.close();
    }
}
struct Reject(Arc<Shared>, bool);
impl Drop for Reject {
    fn drop(&mut self) {
        if self.1 {
            self.0.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
struct Cancel(OperationContext, bool);
impl Drop for Cancel {
    fn drop(&mut self) {
        if self.1 {
            self.0.cancellation.cancel();
        }
    }
}
enum Work {
    Append(Vec<u8>),
    Snapshot,
    Select(Option<DateTime<Utc>>, Option<DateTime<Utc>>, usize, u64),
}
enum Reply {
    Receipt(StoreReceipt),
    Snapshot(CommittedSnapshot),
    Selection(FileSelection),
}
struct Completion {
    result: Result<Reply, StorageError>,
    _slot: Arc<OwnedSemaphorePermit>,
}
struct Command {
    work: Work,
    context: OperationContext,
    slot: Arc<OwnedSemaphorePermit>,
    reply: oneshot::Sender<Completion>,
}

/// One ordinary controller worker, one admission lease, one I/O worker and one
/// codec worker. No unbounded task/channel or Tokio blocking-pool submission.
pub struct ObjectPublisher {
    sender: Mutex<Option<mpsc::Sender<Command>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    shared: Arc<Shared>,
    config: PublicationConfig,
}
impl ObjectPublisher {
    pub fn new(
        io: ObjectIo,
        runtime: tokio::runtime::Handle,
        config: PublicationConfig,
    ) -> Result<Self, StorageError> {
        config.validate()?;
        let (stream, backend) = io
            .small_owner_binding()
            .ok_or(StorageError::Config("Small publication owner required"))?;
        let codec = ObjectCodec::new(config.storage.clone(), config.manifests)?;
        let shared = Arc::new(Shared {
            slots: Arc::new(Semaphore::new(1)),
            closed: AtomicBool::new(false),
            running: AtomicUsize::new(0),
            processed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            high_water: AtomicU64::new(0),
            cleanup_failed: AtomicBool::new(false),
        });
        let state = shared.clone();
        let policy = config.clone();
        let (sender, mut receiver) = mpsc::channel::<Command>(1);
        let worker = thread::Builder::new()
            .name("signal-object-publish".into())
            .spawn(move || {
                let _exit = WorkerExit(state.clone());
                let mut controller = Controller {
                    io,
                    codec,
                    config: policy,
                    stream,
                    backend,
                    cache: None,
                };
                while let Some(command) = receiver.blocking_recv() {
                    state.processed.fetch_add(1, Ordering::Relaxed);
                    state.running.store(1, Ordering::Release);
                    let result = runtime.block_on(async {
                        check_context(Some(&command.context))?;
                        match command.work {
                            Work::Append(wire) => {
                                let rows = intake::decode(&wire, &command.context)?;
                                let (receipt, high_water) =
                                    controller.append(&rows, &command.context).await?;
                                state.high_water.store(high_water, Ordering::Release);
                                Ok(Reply::Receipt(receipt))
                            }
                            Work::Snapshot => {
                                let catalog = controller.recover(None, &command.context).await?;
                                state
                                    .high_water
                                    .store(catalog.high_water(), Ordering::Release);
                                Ok(Reply::Snapshot(CommittedSnapshot {
                                    manifests: catalog.manifests,
                                    orphans: catalog.orphans,
                                    _slot: command.slot.clone(),
                                }))
                            }
                            Work::Select(from, to, max_files, max_decoded_bytes) => {
                                let (selection, high_water) = controller
                                    .select(
                                        from,
                                        to,
                                        max_files,
                                        max_decoded_bytes,
                                        &command.context,
                                    )
                                    .await?;
                                state.high_water.store(high_water, Ordering::Release);
                                Ok(Reply::Selection(selection))
                            }
                        }
                    });
                    // A cancelled child future can finish before its physical
                    // worker drops a retained reply or exits a kernel call.
                    // Keep this command's parent admission until every child
                    // lease has actually drained; caller cancellation/deadline
                    // still returns independently through the front receiver.
                    runtime.block_on(async {
                        while controller.io.metrics().depth != 0
                            || controller.codec.metrics().depth != 0
                        {
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                        }
                    });
                    state.running.store(0, Ordering::Release);
                    let _ = command.reply.send(Completion {
                        result,
                        _slot: command.slot,
                    });
                }
                let cleanup = OperationContext::new(controller.config.storage.operation_timeout);
                let clean = runtime.block_on(async {
                    controller.codec.shutdown(cleanup.clone()).await?;
                    controller.io.shutdown(cleanup).await.map_err(io_error)
                });
                state
                    .cleanup_failed
                    .store(clean.is_err(), Ordering::Release);
            })
            .map_err(StorageError::Io)?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            shared,
            config,
        })
    }
    pub fn metrics(&self) -> PublicationMetrics {
        PublicationMetrics {
            high_water: self.shared.high_water.load(Ordering::Acquire),
            depth: 1 - self.shared.slots.available_permits(),
            capacity: 1,
            running: self.shared.running.load(Ordering::Acquire),
            worker_capacity: 1,
            processed: self.shared.processed.load(Ordering::Relaxed),
            rejected: self.shared.rejected.load(Ordering::Relaxed),
            closed: self.shared.closed.load(Ordering::Acquire),
        }
    }
    fn admit(
        &self,
        context: &mut OperationContext,
    ) -> Result<Arc<OwnedSemaphorePermit>, StorageError> {
        context.deadline = context
            .deadline
            .min(Instant::now() + self.config.storage.operation_timeout);
        check_context(Some(context))?;
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(StorageError::Closed);
        }
        self.shared
            .slots
            .clone()
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| {
                if self.shared.closed.load(Ordering::Acquire) {
                    StorageError::Closed
                } else {
                    StorageError::Full
                }
            })
    }
    async fn request(
        &self,
        work: Work,
        context: OperationContext,
        slot: Arc<OwnedSemaphorePermit>,
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
                slot,
                reply,
            })
            .map_err(|_| StorageError::Closed)?;
        let mut guard = Cancel(context.clone(), true);
        let completion = tokio::select! { biased;
            _ = context.cancellation.cancelled() => return Err(StorageError::Cancelled),
            result = timeout_at(context.deadline, receive) => match result {
                Err(_) => return Err(StorageError::Timeout), Ok(Err(_)) => return Err(StorageError::Closed), Ok(Ok(c)) => c,
            }
        };
        check_context(Some(&context))?;
        guard.1 = false;
        completion.result
    }
    pub async fn append(
        &self,
        rows: &[StoredEvent],
        mut context: OperationContext,
    ) -> Result<StoreReceipt, StorageError> {
        let mut reject = Reject(self.shared.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            if rows.is_empty() || rows.len() > self.config.manifests.events {
                return Err(StorageError::InvalidBatch);
            }
            let wire = intake::encode(rows, &self.config.storage, &context)?;
            match self.request(Work::Append(wire), context, slot).await? {
                Reply::Receipt(receipt) => Ok(receipt),
                _ => Err(StorageError::Closed),
            }
        }
        .await;
        reject.1 = result.is_err();
        result
    }
    pub async fn snapshot(
        &self,
        mut context: OperationContext,
    ) -> Result<CommittedSnapshot, StorageError> {
        let mut reject = Reject(self.shared.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            match self.request(Work::Snapshot, context, slot).await? {
                Reply::Snapshot(snapshot) => Ok(snapshot),
                _ => Err(StorageError::Closed),
            }
        }
        .await;
        reject.1 = result.is_err();
        result
    }
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.slots.close();
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), StorageError> {
        self.close();
        loop {
            check_context(Some(&context))?;
            if self
                .worker
                .lock()
                .map_err(|_| StorageError::Closed)?
                .as_ref()
                .is_none_or(|w| w.is_finished())
            {
                if let Some(worker) = self.worker.lock().map_err(|_| StorageError::Closed)?.take() {
                    worker.join().map_err(|_| StorageError::Closed)?;
                }
                return if self.shared.cleanup_failed.load(Ordering::Acquire) {
                    Err(StorageError::Closed)
                } else {
                    Ok(())
                };
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }
}
impl QueryFileSource for ObjectPublisher {
    fn select_query_files(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        max_files: usize,
        max_decoded_bytes: u64,
        mut context: OperationContext,
    ) -> StoreFuture<'_, FileSelection> {
        Box::pin(async move {
            let mut reject = Reject(self.shared.clone(), true);
            let result = async {
                let slot = self.admit(&mut context)?;
                if max_files == 0
                    || max_files > 100_000
                    || max_decoded_bytes == 0
                    || max_decoded_bytes > 4 * 1024 * 1024 * 1024
                    || from.zip(to).is_some_and(|(from, to)| from >= to)
                {
                    return Err(StorageError::InvalidBatch);
                }
                if self.config.materialization.is_none() {
                    return Err(StorageError::Config("query materialization required"));
                }
                match self
                    .request(
                        Work::Select(from, to, max_files, max_decoded_bytes),
                        context,
                        slot,
                    )
                    .await?
                {
                    Reply::Selection(selection) => Ok(selection),
                    _ => Err(StorageError::Closed),
                }
            }
            .await;
            reject.1 = result.is_err();
            result
        })
    }
}
impl Drop for ObjectPublisher {
    fn drop(&mut self) {
        self.close();
    }
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
struct Catalog {
    manifests: Vec<CommittedManifest>,
    orphans: Vec<QueryObjectRef>,
    objects: usize,
    bytes: u64,
    metadata: usize,
    inventory: Vec<QueryObjectRef>,
}
impl Catalog {
    fn head(&self) -> Option<&PreviousManifest> {
        self.manifests.last().map(|m| &m.reference)
    }
    fn high_water(&self) -> u64 {
        self.head().map_or(0, |h| h.last_sequence)
    }
}
struct Controller {
    io: ObjectIo,
    codec: ObjectCodec,
    config: PublicationConfig,
    stream: Uuid,
    backend: Uuid,
    cache: Option<Cache>,
}
impl Controller {
    async fn select(
        &mut self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        max_files: usize,
        max_decoded_bytes: u64,
        context: &OperationContext,
    ) -> Result<(FileSelection, u64), StorageError> {
        let catalog = self.recover(None, context).await?;
        let high_water = catalog.high_water();
        let mut selected = Vec::new();
        let mut partitions = BTreeSet::new();
        let mut decoded = 0u64;
        for committed in &catalog.manifests {
            for file in &committed.manifest.files {
                check_context(Some(context))?;
                if !file
                    .intersects(from, to)
                    .map_err(|_| StorageError::Corrupt("selected partition"))?
                {
                    continue;
                }
                if selected.len() >= max_files {
                    return Err(StorageError::Full);
                }
                decoded = decoded
                    .checked_add(file.decoded_bytes)
                    .ok_or(StorageError::Full)?;
                if decoded > max_decoded_bytes {
                    return Err(StorageError::Full);
                }
                selected.push((
                    file,
                    committed.reference.first_sequence,
                    committed.reference.last_sequence,
                ));
                partitions.insert((file.date.clone(), file.hour));
            }
        }
        if selected.is_empty() {
            return Ok((FileSelection::default(), high_water));
        }
        if self.cache.is_none() {
            let config = self
                .config
                .materialization
                .as_ref()
                .ok_or(StorageError::Config("query materialization required"))?;
            self.cache = Some(Cache::open(config, self.stream, self.backend, context)?);
        }
        let mut files = Vec::with_capacity(selected.len());
        for (file, first, last) in selected {
            check_context(Some(context))?;
            let read = self
                .io
                .read_exact(&file.object, context.clone())
                .await
                .map_err(io_error)?;
            let inspected = self
                .codec
                .inspect(file, read.bytes(), first, last, context.clone())
                .await?;
            // Actual byte/schema/row checks precede local publication. Materialized
            // copies are immutable until query shutdown, with no eviction here.
            files.push(
                self.cache
                    .as_ref()
                    .ok_or(StorageError::Closed)?
                    .materialize(file, read.bytes(), context)?,
            );
            drop(inspected);
            drop(read);
        }
        check_context(Some(context))?;
        Ok((
            FileSelection {
                files,
                partitions: partitions.len(),
            },
            high_water,
        ))
    }
    async fn manifest(
        &self,
        reference: &PreviousManifest,
        context: &OperationContext,
    ) -> Result<QueryManifest, StorageError> {
        crate::object_head::validate_reference(reference, self.stream)?;
        reference
            .object
            .validate(self.config.manifests.manifest_bytes as u64)
            .map_err(|_| StorageError::Corrupt("query head manifest budget"))?;
        let read = self
            .io
            .read_exact(&reference.object, context.clone())
            .await
            .map_err(io_error)?;
        let manifest = QueryManifest::decode_at(
            read.bytes(),
            &reference.object,
            self.config.manifests,
            self.stream,
        )
        .map_err(|_| StorageError::Corrupt("pinned query manifest"))?;
        if manifest.first_sequence != reference.first_sequence
            || manifest.last_sequence != reference.last_sequence
        {
            return Err(StorageError::Corrupt("query head range"));
        }
        check_context(Some(context))?;
        Ok(manifest)
    }
    async fn discover_manifest(
        &self,
        key: &str,
        context: &OperationContext,
    ) -> Result<CommittedManifest, StorageError> {
        let read = self
            .io
            .discover_bounded(key, self.config.manifests.manifest_bytes, context.clone())
            .await
            .map_err(io_error)?;
        let manifest = QueryManifest::decode_at(
            read.bytes(),
            read.reference(),
            self.config.manifests,
            self.stream,
        )
        .map_err(|_| StorageError::Corrupt("discovered query manifest"))?;
        let reference = PreviousManifest {
            object: read.reference().clone(),
            first_sequence: manifest.first_sequence,
            last_sequence: manifest.last_sequence,
        };
        Ok(CommittedManifest {
            reference,
            manifest,
        })
    }
    /// Listing grants no commit. A missing head with commits requires explicit
    /// WAL-content reconciliation; a known head may adopt a unique validated tail.
    async fn recover(
        &self,
        replay: Option<&[StoredEvent]>,
        context: &OperationContext,
    ) -> Result<Catalog, StorageError> {
        check_context(Some(context))?;
        let head = self
            .io
            .read_small_head(context.clone())
            .await
            .map_err(io_error)?;
        let mut initialized = self
            .io
            .small_query_initialized(context.clone())
            .await
            .map_err(io_error)?;
        let prefix = format!("query/{}", self.stream);
        let inventory = self
            .io
            .inventory(&prefix, context.clone())
            .await
            .map_err(io_error)?;
        if inventory.entries().len()
            > self
                .config
                .inventory_objects
                .min(self.config.storage.max_files)
        {
            return Err(StorageError::Full);
        }
        let mut metadata = 0usize;
        let mut bytes = 0u64;
        for reference in inventory.entries() {
            metadata = metadata
                .checked_add(reference_weight(reference))
                .ok_or(StorageError::Full)?;
            bytes = bytes
                .checked_add(reference.bytes)
                .ok_or(StorageError::Full)?;
            if metadata > self.config.catalog_bytes || bytes > self.config.storage.max_disk_bytes {
                return Err(StorageError::Full);
            }
        }
        let entries = inventory.entries().to_vec();
        drop(inventory);
        if head.is_none() && !initialized && entries.is_empty() {
            self.io
                .initialize_small_query(context.clone())
                .await
                .map_err(io_error)?;
            initialized = true;
        }
        let commit_prefix = format!("{prefix}/commits/");
        let data_prefix = format!("{prefix}/data/");
        if entries
            .iter()
            .any(|r| !r.key.starts_with(&commit_prefix) && !r.key.starts_with(&data_prefix))
        {
            return Err(StorageError::Corrupt("unknown query object namespace"));
        }
        let mut manifests = Vec::<CommittedManifest>::new();
        let mut cursor = head.clone();
        while let Some(reference) = cursor {
            check_context(Some(context))?;
            if manifests.len() >= self.config.inventory_objects
                || !entries.iter().any(|r| r.key == reference.object.key)
            {
                return Err(StorageError::Corrupt("query head missing from inventory"));
            }
            let manifest = self.manifest(&reference, context).await?;
            cursor = manifest.previous.clone();
            metadata = metadata
                .checked_add(manifest_weight(&manifest) + reference_weight(&reference.object))
                .ok_or(StorageError::Full)?;
            if metadata > self.config.catalog_bytes {
                return Err(StorageError::Full);
            }
            manifests.push(CommittedManifest {
                reference,
                manifest,
            });
        }
        manifests.reverse();
        // Immutable pinned history is checked against current inventory before
        // advancing any recovered tail. Selected query reads still verify bytes.
        for committed in &manifests {
            check_inventory_identity(&entries, &committed.reference.object)?;
            for file in &committed.manifest.files {
                check_inventory_identity(&entries, &file.object)?;
            }
        }
        let extra: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.key.starts_with(&commit_prefix)
                    && !manifests.iter().any(|m| m.reference.object.key == e.key)
            })
            .collect();
        // More than one uncertain candidate is a branch/unknown history. Never
        // pick whichever happens to appear first in listing order.
        if extra.len() > 1 {
            return Err(StorageError::Corrupt("multiple uncommitted query slots"));
        }
        if let Some(extra) = extra.first() {
            let candidate = self.discover_manifest(&extra.key, context).await?;
            check_inventory_identity(&entries, &candidate.reference.object)?;
            for file in &candidate.manifest.files {
                check_inventory_identity(&entries, &file.object)?;
            }
            if candidate.manifest.previous.as_ref() != head.as_ref() {
                return Err(StorageError::Corrupt("query candidate predecessor"));
            }
            metadata = metadata
                .checked_add(
                    manifest_weight(&candidate.manifest)
                        + reference_weight(&candidate.reference.object),
                )
                .ok_or(StorageError::Full)?;
            if metadata > self.config.catalog_bytes {
                return Err(StorageError::Full);
            }
            if head.is_none() && !initialized {
                let expected =
                    replay.ok_or(StorageError::Corrupt("missing query head authority"))?;
                // The entire initial committed range must be in the replay;
                // truncated/split input cannot establish unknown prior content.
                self.inspect_manifest(&candidate.manifest, Some(expected), true, context)
                    .await?;
            } else {
                self.inspect_manifest(&candidate.manifest, None, false, context)
                    .await?;
            }
            self.io
                .advance_small_head(head.as_ref(), &candidate.reference, context.clone())
                .await
                .map_err(io_error)?;
            manifests.push(candidate);
        }
        let mut referenced = BTreeSet::<&str>::new();
        for committed in &manifests {
            referenced.insert(&committed.reference.object.key);
            for file in &committed.manifest.files {
                if !entries.iter().any(|e| e.key == file.object.key) {
                    return Err(StorageError::Corrupt("committed query data missing"));
                }
                if !referenced.insert(&file.object.key) {
                    return Err(StorageError::Corrupt("duplicate query data reference"));
                }
            }
        }
        let orphans = entries
            .iter()
            .filter(|r| !referenced.contains(r.key.as_str()))
            .cloned()
            .collect();
        check_context(Some(context))?;
        Ok(Catalog {
            manifests,
            orphans,
            objects: entries.len(),
            bytes,
            metadata,
            inventory: entries,
        })
    }
    /// Authenticate every actual row and cross-partition sequence before a
    /// recovered candidate is committed. Optional expected rows bind replay.
    async fn inspect_manifest(
        &self,
        manifest: &QueryManifest,
        expected: Option<&[StoredEvent]>,
        require_all: bool,
        context: &OperationContext,
    ) -> Result<(), StorageError> {
        let mut seen = BTreeSet::new();
        for file in &manifest.files {
            let read = self
                .io
                .read_exact(&file.object, context.clone())
                .await
                .map_err(io_error)?;
            let inspected = self
                .codec
                .inspect(
                    file,
                    read.bytes(),
                    manifest.first_sequence,
                    manifest.last_sequence,
                    context.clone(),
                )
                .await?;
            for row in inspected.rows() {
                check_context(Some(context))?;
                if !seen.insert(row.sequence) {
                    return Err(StorageError::Corrupt("duplicate manifest sequence"));
                }
                if let Some(expected) = expected {
                    match expected.binary_search_by_key(&row.sequence, |r| r.sequence) {
                        Ok(index) if expected[index] == *row => {}
                        Ok(_) => return Err(StorageError::InvalidBatch),
                        Err(_) if require_all => return Err(StorageError::InvalidBatch),
                        Err(_) => {}
                    }
                }
            }
        }
        if seen.len() != manifest.events
            || seen.first() != Some(&manifest.first_sequence)
            || seen.last() != Some(&manifest.last_sequence)
        {
            return Err(StorageError::Corrupt("actual manifest sequence range"));
        }
        if let Some(expected) = expected {
            for row in expected.iter().filter(|r| {
                (manifest.first_sequence..=manifest.last_sequence).contains(&r.sequence)
            }) {
                if !seen.contains(&row.sequence) {
                    return Err(StorageError::InvalidBatch);
                }
            }
        }
        Ok(())
    }
    async fn create_exact(
        &self,
        key: &str,
        bytes: &[u8],
        context: &OperationContext,
    ) -> Result<QueryObjectRef, StorageError> {
        let created = self.io.create(key, bytes, context.clone()).await;
        let read = match created {
            Ok(reference) => self
                .io
                .read_exact(&reference, context.clone())
                .await
                .map_err(io_error)?,
            Err(ObjectIoError::Exists | ObjectIoError::Backend) => {
                check_context(Some(context))?;
                self.io
                    .discover_bounded(key, bytes.len(), context.clone())
                    .await
                    .map_err(io_error)?
            }
            Err(error) => return Err(io_error(error)),
        };
        if read.bytes() != bytes {
            return Err(StorageError::InvalidBatch);
        }
        Ok(read.reference().clone())
    }
    async fn append(
        &self,
        rows: &[StoredEvent],
        context: &OperationContext,
    ) -> Result<(StoreReceipt, u64), StorageError> {
        crate::validate_batch(rows, &self.config.storage)?;
        let catalog = self.recover(Some(rows), context).await?;
        let high_water = catalog.high_water();
        let replayed = rows.partition_point(|r| r.sequence <= high_water);
        let replay = &rows[..replayed];
        let mut matched = 0usize;
        for committed in &catalog.manifests {
            let manifest = &committed.manifest;
            let part: Vec<_> = replay
                .iter()
                .filter(|r| {
                    (manifest.first_sequence..=manifest.last_sequence).contains(&r.sequence)
                })
                .collect();
            if !part.is_empty() {
                self.inspect_manifest(manifest, Some(replay), false, context)
                    .await?;
                matched += part.len();
            }
        }
        if matched != replayed {
            return Err(StorageError::InvalidBatch);
        }
        let new = &rows[replayed..];
        if new.is_empty() {
            return Ok((
                StoreReceipt {
                    first_sequence: rows[0].sequence,
                    last_sequence: rows[rows.len() - 1].sequence,
                    new_count: 0,
                    replay_count: replayed,
                },
                high_water,
            ));
        }
        let prepared = self.codec.prepare(new, context.clone()).await?;
        let mut files = Vec::with_capacity(prepared.files().len());
        let mut existing = Vec::with_capacity(prepared.files().len());
        let mut missing_objects = 1usize; // the new immutable manifest
        let mut missing_bytes = 0u64;
        for file in prepared.files() {
            let key = data_key(self.stream, file.date(), file.hour(), file.sha256());
            if catalog.inventory.iter().any(|r| r.key == key) {
                // Reconcile counted orphans before reserving a new write. A
                // conflicting object cannot become quota-free reuse.
                let read = self
                    .io
                    .discover_bounded(&key, file.bytes().len(), context.clone())
                    .await
                    .map_err(io_error)?;
                if read.bytes() != file.bytes() {
                    return Err(StorageError::InvalidBatch);
                }
                check_inventory_identity(&catalog.inventory, read.reference())?;
                existing.push(Some(read.reference().clone()));
            } else {
                missing_objects += 1;
                missing_bytes = missing_bytes
                    .checked_add(file.bytes().len() as u64)
                    .ok_or(StorageError::Full)?;
                existing.push(None);
            }
        }
        let prospective_objects = catalog
            .objects
            .checked_add(missing_objects)
            .ok_or(StorageError::Full)?;
        let prospective_bytes = catalog
            .bytes
            .checked_add(missing_bytes)
            .ok_or(StorageError::Full)?;
        // Reserve logical metadata at the maximum allowed returned version and
        // ETag lengths before a write can create an orphan. This is deliberately
        // conservative; listing/readback cannot exceed the configured catalog.
        let manifest_ref = std::mem::size_of::<QueryObjectRef>()
            + 512
            + manifest_key(self.stream, prepared.first_sequence()).len();
        let future_metadata = prepared.files().iter().zip(&existing).try_fold(
            catalog
                .metadata
                .checked_add(
                    2 * manifest_ref
                        + std::mem::size_of::<CommittedManifest>()
                        + self.config.normalizer_revision.len()
                        + catalog.head().map_or(0, |h| {
                            std::mem::size_of::<PreviousManifest>() + reference_weight(&h.object)
                        }),
                )
                .ok_or(StorageError::Full)?,
            |total, (file, existing)| {
                let reference = std::mem::size_of::<QueryObjectRef>()
                    + 512
                    + data_key(self.stream, file.date(), file.hour(), file.sha256()).len();
                total
                    .checked_add(
                        (if existing.is_some() { 1 } else { 2 }) * reference
                            + std::mem::size_of::<QueryFile>()
                            + file.date().len(),
                    )
                    .ok_or(StorageError::Full)
            },
        )?;
        if prospective_objects
            > self
                .config
                .inventory_objects
                .min(self.config.storage.max_files)
            || prospective_bytes
                .checked_add(self.config.manifests.manifest_bytes as u64)
                .is_none_or(|n| n > self.config.storage.max_disk_bytes)
            || future_metadata > self.config.catalog_bytes
        {
            return Err(StorageError::Full);
        }
        for (file, existing) in prepared.files().iter().zip(existing) {
            let key = data_key(self.stream, file.date(), file.hour(), file.sha256());
            let object = match existing {
                Some(reference) => reference,
                None => self.create_exact(&key, file.bytes(), context).await?,
            };
            files.push(QueryFile {
                date: file.date().into(),
                hour: file.hour(),
                object,
                rows: file.rows(),
                decoded_bytes: file.decoded_bytes(),
            });
        }
        let manifest = QueryManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            storage_schema_version: crate::codec::STORAGE_SCHEMA_VERSION,
            stream_id: self.stream,
            normalizer_revision: self.config.normalizer_revision.clone(),
            first_sequence: prepared.first_sequence(),
            last_sequence: prepared.last_sequence(),
            events: prepared.event_count(),
            previous: catalog.head().cloned(),
            files,
        };
        let body = manifest
            .encode(self.config.manifests, self.stream)
            .map_err(|_| StorageError::Corrupt("prepared query manifest"))?;
        let reference = self
            .create_exact(
                &manifest_key(self.stream, manifest.first_sequence),
                &body,
                context,
            )
            .await?;
        QueryManifest::decode_at(&body, &reference, self.config.manifests, self.stream)
            .map_err(|_| StorageError::Corrupt("published query manifest"))?;
        let head = PreviousManifest {
            object: reference,
            first_sequence: manifest.first_sequence,
            last_sequence: manifest.last_sequence,
        };
        self.io
            .advance_small_head(catalog.head(), &head, context.clone())
            .await
            .map_err(io_error)?;
        check_context(Some(context))?;
        Ok((
            StoreReceipt {
                first_sequence: rows[0].sequence,
                last_sequence: manifest.last_sequence,
                new_count: new.len(),
                replay_count: replayed,
            },
            manifest.last_sequence,
        ))
    }
}
fn check_inventory_identity(
    entries: &[QueryObjectRef],
    expected: &QueryObjectRef,
) -> Result<(), StorageError> {
    let actual = entries
        .iter()
        .find(|r| r.key == expected.key)
        .ok_or(StorageError::Corrupt("committed query object missing"))?;
    if actual.bytes != expected.bytes
        || actual.etag != expected.etag
        || match &actual.version {
            Some(version) => expected.version.as_ref() != Some(version),
            // S3 ListObjectsV2 omits versions. Matching ETag/length detect
            // current-object drift, but never replace the pinned read version.
            None => expected.etag.as_ref().is_none_or(String::is_empty),
        }
    {
        return Err(StorageError::Corrupt(
            "committed query object identity drift",
        ));
    }
    Ok(())
}
fn reference_weight(reference: &QueryObjectRef) -> usize {
    std::mem::size_of::<QueryObjectRef>()
        + reference.key.len()
        + reference.etag.as_ref().map_or(0, String::len)
        + reference.version.as_ref().map_or(0, String::len)
}
fn manifest_weight(manifest: &QueryManifest) -> usize {
    std::mem::size_of::<CommittedManifest>()
        + manifest.normalizer_revision.len()
        + manifest.previous.as_ref().map_or(0, |h| {
            std::mem::size_of::<PreviousManifest>() + reference_weight(&h.object)
        })
        + manifest
            .files
            .iter()
            .map(|f| std::mem::size_of::<QueryFile>() + f.date.len() + reference_weight(&f.object))
            .sum::<usize>()
}
#[cfg(test)]
mod tests;

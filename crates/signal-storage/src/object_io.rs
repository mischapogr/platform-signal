//! Bounded query-object I/O. No delete/overwrite/multipart, source ACK or custody.
use crate::object_manifest::{QueryObjectRef, sha256};
pub use crate::object_owner::SmallOwnerConfig;
use crate::{OperationContext, check_context};
use bytes::Bytes;
use futures_util::StreamExt;
use object_store::{
    GetOptions, GetResultPayload, ObjectMeta, ObjectStore, PutMode, PutOptions, path::Path,
};
use std::{
    sync::{
        Arc, Mutex,
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

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum ObjectIoError {
    #[error("invalid query object I/O bounds")]
    Config,
    #[error("query object I/O is full")]
    Full,
    #[error("query object I/O is closed")]
    Closed,
    #[error("query object I/O deadline exceeded; write may have completed")]
    Timeout,
    #[error("query object I/O cancelled; write may have completed")]
    Cancelled,
    #[error("query object was not found")]
    NotFound,
    #[error("query object already exists; explicit reconciliation required")]
    Exists,
    #[error("query object condition did not match")]
    Condition,
    #[error("query object backend rejected or failed request")]
    Backend,
    #[error("query object response violates its exact bounded reference")]
    Corrupt,
    #[error("Small object owner root is already locked")]
    OwnerLocked,
    #[error("Small object owner stream/backend binding differs")]
    OwnerBinding,
}
#[derive(Clone, Copy, Debug)]
pub struct ObjectIoLimits {
    pub bytes: usize,
    pub entries: usize,
    pub timeout: Duration,
}
impl Default for ObjectIoLimits {
    fn default() -> Self {
        Self {
            bytes: 64 * 1024 * 1024,
            entries: 10000,
            timeout: Duration::from_secs(120),
        }
    }
}
impl ObjectIoLimits {
    fn validate(self) -> Result<(), ObjectIoError> {
        if self.bytes == 0
            || self.bytes > 1024 * 1024 * 1024
            || self.entries == 0
            || self.entries > 100000
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(3600)
        {
            return Err(ObjectIoError::Config);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ObjectIoMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub running: usize,
    pub worker_capacity: usize,
    pub rejected: u64,
    pub processed: u64,
    pub closed: bool,
}
struct State {
    slots: Arc<Semaphore>,
    closed: AtomicBool,
    running: AtomicUsize,
    rejected: AtomicU64,
    processed: AtomicU64,
}
pub struct ObjectRead {
    reference: QueryObjectRef,
    body: Vec<u8>,
    _slot: Arc<OwnedSemaphorePermit>,
}
impl ObjectRead {
    pub fn reference(&self) -> &QueryObjectRef {
        &self.reference
    }
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }
}
/// Finite inventory only. Listing is not commitment or source completeness.
pub struct ObjectInventory {
    entries: Vec<QueryObjectRef>,
    _slot: Arc<OwnedSemaphorePermit>,
}
impl ObjectInventory {
    pub fn entries(&self) -> &[QueryObjectRef] {
        &self.entries
    }
}
enum Work {
    Create(String, Vec<u8>),
    Read(String, Option<QueryObjectRef>, usize),
    List(String),
    ReadHead,
    ReadGenesis,
    InitializeGenesis,
    AdvanceHead(crate::object_head::HeadRecord),
    #[cfg(test)]
    Pause(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>),
}
enum ResultData {
    Created(QueryObjectRef),
    Read(ObjectRead),
    Inventory(ObjectInventory),
    Head(Option<crate::object_manifest::PreviousManifest>),
    Genesis(bool),
    #[cfg(test)]
    Done,
}
type OwnerStartup = (
    SmallOwnerConfig,
    OperationContext,
    oneshot::Sender<Result<(), ObjectIoError>>,
);
struct Completion {
    result: Result<ResultData, ObjectIoError>,
    _slot: Arc<OwnedSemaphorePermit>,
}
struct Command {
    work: Work,
    context: OperationContext,
    slot: Arc<OwnedSemaphorePermit>,
    reply: oneshot::Sender<Completion>,
}
struct CancelGuard(OperationContext, bool);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.1 {
            self.0.cancellation.cancel()
        }
    }
}
struct RejectGuard(Arc<State>, bool);
impl Drop for RejectGuard {
    fn drop(&mut self) {
        if self.1 {
            self.0.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
struct WorkerExit(Arc<State>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.running.store(0, Ordering::Release);
        self.0.closed.store(true, Ordering::Release);
        self.0.slots.close();
    }
}
/// Audited remote backend futures run on an owned physical worker through this
/// runtime. Local filesystem backends execute outside Tokio on the same fixed
/// ordinary thread. Backends must bound their internal metadata/body parsing;
/// this wrapper bounds admission, copies, listing and retained returned data.
pub struct ObjectIo {
    sender: Mutex<Option<mpsc::Sender<Command>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    state: Arc<State>,
    limits: ObjectIoLimits,
    owner_binding: Option<(uuid::Uuid, uuid::Uuid)>,
}
impl ObjectIo {
    pub fn remote(
        store: Arc<dyn ObjectStore>,
        runtime: tokio::runtime::Handle,
        limits: ObjectIoLimits,
    ) -> Result<Self, ObjectIoError> {
        Self::start(store, Some(runtime), limits, None)
    }
    pub fn local(
        store: object_store::local::LocalFileSystem,
        limits: ObjectIoLimits,
    ) -> Result<Self, ObjectIoError> {
        Self::start(Arc::new(store), None, limits, None)
    }
    pub async fn open_small_remote(
        owner: &SmallOwnerConfig,
        store: Arc<dyn ObjectStore>,
        runtime: tokio::runtime::Handle,
        limits: ObjectIoLimits,
        context: OperationContext,
    ) -> Result<Self, ObjectIoError> {
        Self::open_owned(owner, store, Some(runtime), limits, context).await
    }
    pub async fn open_small_local(
        owner: &SmallOwnerConfig,
        store: object_store::local::LocalFileSystem,
        limits: ObjectIoLimits,
        context: OperationContext,
    ) -> Result<Self, ObjectIoError> {
        Self::open_owned(owner, Arc::new(store), None, limits, context).await
    }
    async fn open_owned(
        owner: &SmallOwnerConfig,
        store: Arc<dyn ObjectStore>,
        runtime: Option<tokio::runtime::Handle>,
        limits: ObjectIoLimits,
        mut context: OperationContext,
    ) -> Result<Self, ObjectIoError> {
        limits.validate()?;
        context.deadline = context.deadline.min(Instant::now() + limits.timeout);
        check(&context)?;
        let owner = owner.bounded_copy().map_err(owner_error)?;
        let (reply, receive) = oneshot::channel();
        let io = Self::start(
            store,
            runtime,
            limits,
            Some((owner, context.clone(), reply)),
        )?;
        let mut guard = CancelGuard(context.clone(), true);
        receive_owner_ready(receive, &context).await?;
        guard.1 = false;
        Ok(io)
    }
    fn start(
        store: Arc<dyn ObjectStore>,
        runtime: Option<tokio::runtime::Handle>,
        limits: ObjectIoLimits,
        owner: Option<OwnerStartup>,
    ) -> Result<Self, ObjectIoError> {
        limits.validate()?;
        let owner_binding = owner
            .as_ref()
            .map(|(config, _, _)| (config.stream_id, config.backend_id));
        let state = Arc::new(State {
            slots: Arc::new(Semaphore::new(1)),
            closed: AtomicBool::new(false),
            running: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
            processed: AtomicU64::new(0),
        });
        let (sender, mut receiver) = mpsc::channel::<Command>(1);
        let shared = state.clone();
        let worker = thread::Builder::new()
            .name("signal-object-io".into())
            .spawn(move || {
                let _exit = WorkerExit(shared.clone());
                // The physical worker retains the root lock even if the caller
                // drops the frontend during non-cancellable filesystem work.
                let owner = match owner {
                    None => None,
                    Some((config, context, reply)) => {
                        match crate::object_owner::SmallOwner::open(&config, &context) {
                            Ok(owner) => {
                                if reply.send(Ok(())).is_err() { return; }
                                Some(owner)
                            }
                            Err(error) => { let _ = reply.send(Err(owner_error(error))); return; }
                        }
                    }
                };
                while let Some(command) = receiver.blocking_recv() {
                    shared.processed.fetch_add(1, Ordering::Relaxed);
                    shared.running.store(1, Ordering::Release);
                    let future = execute(
                        &*store, command.work, limits, &command.context,
                        command.slot.clone(), runtime.is_some(), owner.as_ref(),
                    );
                    let result = match &runtime {
                        Some(handle) => handle.block_on(async {
                            tokio::select! {
                                biased;
                                _ = command.context.cancellation.cancelled() => Err(ObjectIoError::Cancelled),
                                result = timeout_at(command.context.deadline, future) => match result {
                                    Ok(result) => result,
                                    Err(_) => Err(ObjectIoError::Timeout),
                                }
                            }
                        }),
                        None => futures::executor::block_on(future),
                    };
                    shared.running.store(0, Ordering::Release);
                    let _ = command.reply.send(Completion {
                        result, _slot: command.slot,
                    });
                }
            })
            .map_err(|_| ObjectIoError::Backend)?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            state,
            limits,
            owner_binding,
        })
    }
    pub fn small_owner_binding(&self) -> Option<(uuid::Uuid, uuid::Uuid)> {
        self.owner_binding
    }
    pub async fn small_query_initialized(
        &self,
        context: OperationContext,
    ) -> Result<bool, ObjectIoError> {
        self.genesis(false, context).await
    }
    /// Trusted publisher must first verify bounded empty query inventory.
    pub async fn initialize_small_query(
        &self,
        context: OperationContext,
    ) -> Result<(), ObjectIoError> {
        self.genesis(true, context).await.map(|_| ())
    }
    async fn genesis(
        &self,
        initialize: bool,
        mut context: OperationContext,
    ) -> Result<bool, ObjectIoError> {
        let mut rejected = RejectGuard(self.state.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            if self.owner_binding.is_none() {
                return Err(ObjectIoError::Config);
            }
            let work = if initialize {
                Work::InitializeGenesis
            } else {
                Work::ReadGenesis
            };
            match self.submit(work, context, slot).await? {
                ResultData::Genesis(value) => Ok(value),
                _ => Err(ObjectIoError::Closed),
            }
        }
        .await;
        rejected.1 = result.is_err();
        result
    }
    /// None is uninitialized control, not proof of an empty backend.
    pub async fn read_small_head(
        &self,
        mut context: OperationContext,
    ) -> Result<Option<crate::object_manifest::PreviousManifest>, ObjectIoError> {
        let mut rejected = RejectGuard(self.state.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            if self.owner_binding.is_none() {
                return Err(ObjectIoError::Config);
            }
            match self.submit(Work::ReadHead, context, slot).await? {
                ResultData::Head(head) => Ok(head),
                _ => Err(ObjectIoError::Closed),
            }
        }
        .await;
        rejected.1 = result.is_err();
        result
    }
    /// Trusted publisher calls only after manifest/data validation. This CASes
    /// a local witness and grants no remote durability, source ACK or custody.
    pub async fn advance_small_head(
        &self,
        expected: Option<&crate::object_manifest::PreviousManifest>,
        next: &crate::object_manifest::PreviousManifest,
        mut context: OperationContext,
    ) -> Result<(), ObjectIoError> {
        let mut rejected = RejectGuard(self.state.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            let (stream, backend) = self.owner_binding.ok_or(ObjectIoError::Config)?;
            let record = crate::object_head::HeadRecord::new(stream, backend, expected, next)
                .map_err(owner_error)?;
            match self
                .submit(Work::AdvanceHead(record), context, slot)
                .await?
            {
                ResultData::Head(_) => Ok(()),
                _ => Err(ObjectIoError::Closed),
            }
        }
        .await;
        rejected.1 = result.is_err();
        result
    }
    pub fn metrics(&self) -> ObjectIoMetrics {
        ObjectIoMetrics {
            depth: 1 - self.state.slots.available_permits(),
            capacity: 1,
            running: self.state.running.load(Ordering::Acquire),
            worker_capacity: 1,
            rejected: self.state.rejected.load(Ordering::Relaxed),
            processed: self.state.processed.load(Ordering::Relaxed),
            closed: self.state.closed.load(Ordering::Acquire),
        }
    }
    fn admit(
        &self,
        ctx: &mut OperationContext,
    ) -> Result<Arc<OwnedSemaphorePermit>, ObjectIoError> {
        ctx.deadline = ctx.deadline.min(Instant::now() + self.limits.timeout);
        check(ctx)?;
        if self.state.closed.load(Ordering::Acquire) {
            return Err(ObjectIoError::Closed);
        }
        self.state
            .slots
            .clone()
            .try_acquire_owned()
            .map(Arc::new)
            .map_err(|_| {
                if self.state.closed.load(Ordering::Acquire) {
                    ObjectIoError::Closed
                } else {
                    ObjectIoError::Full
                }
            })
    }
    async fn submit(
        &self,
        work: Work,
        context: OperationContext,
        slot: Arc<OwnedSemaphorePermit>,
    ) -> Result<ResultData, ObjectIoError> {
        check(&context)?;
        let (reply, receive) = oneshot::channel();
        self.sender
            .lock()
            .map_err(|_| ObjectIoError::Closed)?
            .as_ref()
            .ok_or(ObjectIoError::Closed)?
            .try_send(Command {
                work,
                context: context.clone(),
                slot,
                reply,
            })
            .map_err(|_| ObjectIoError::Closed)?;
        let mut guard = CancelGuard(context.clone(), true);
        let completed = tokio::select! {biased;_=context.cancellation.cancelled()=>return Err(ObjectIoError::Cancelled),result=timeout_at(context.deadline,receive)=>match result{Err(_)=>return Err(ObjectIoError::Timeout),Ok(Err(_))=>return Err(ObjectIoError::Closed),Ok(Ok(reply))=>reply}};
        check(&context)?;
        guard.1 = false;
        completed.result
    }
    pub async fn create(
        &self,
        key: &str,
        body: &[u8],
        mut context: OperationContext,
    ) -> Result<QueryObjectRef, ObjectIoError> {
        let mut rejected = RejectGuard(self.state.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            valid_key(key)?;
            if body.is_empty() || body.len() > self.limits.bytes {
                return Err(ObjectIoError::Full);
            }
            let body = copy(body, self.limits.bytes)?;
            match self
                .submit(Work::Create(key.to_owned(), body), context, slot)
                .await?
            {
                ResultData::Created(reference) => Ok(reference),
                _ => Err(ObjectIoError::Closed),
            }
        }
        .await;
        rejected.1 = result.is_err();
        result
    }
    /// Only reconciliation/discovery may inspect current state. Normal reads use
    /// read_exact; absence or changed versions never fall back to current.
    pub async fn discover(
        &self,
        key: &str,
        context: OperationContext,
    ) -> Result<ObjectRead, ObjectIoError> {
        self.read(key, None, self.limits.bytes, context).await
    }
    pub async fn discover_bounded(
        &self,
        key: &str,
        max_bytes: usize,
        context: OperationContext,
    ) -> Result<ObjectRead, ObjectIoError> {
        self.read(key, None, max_bytes, context).await
    }
    pub async fn read_exact(
        &self,
        reference: &QueryObjectRef,
        context: OperationContext,
    ) -> Result<ObjectRead, ObjectIoError> {
        self.read(&reference.key, Some(reference), self.limits.bytes, context)
            .await
    }
    async fn read(
        &self,
        key: &str,
        reference: Option<&QueryObjectRef>,
        max_bytes: usize,
        mut context: OperationContext,
    ) -> Result<ObjectRead, ObjectIoError> {
        let mut rejected = RejectGuard(self.state.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            valid_key(key)?;
            if max_bytes == 0 || max_bytes > self.limits.bytes {
                return Err(ObjectIoError::Full);
            }
            if let Some(reference) = reference {
                reference
                    .validate(self.limits.bytes as u64)
                    .map_err(|_| ObjectIoError::Corrupt)?;
            }
            match self
                .submit(
                    Work::Read(key.to_owned(), reference.cloned(), max_bytes),
                    context,
                    slot,
                )
                .await?
            {
                ResultData::Read(read) => Ok(read),
                _ => Err(ObjectIoError::Closed),
            }
        }
        .await;
        rejected.1 = result.is_err();
        result
    }
    pub async fn inventory(
        &self,
        prefix: &str,
        mut context: OperationContext,
    ) -> Result<ObjectInventory, ObjectIoError> {
        let mut rejected = RejectGuard(self.state.clone(), true);
        let result = async {
            let slot = self.admit(&mut context)?;
            valid_key(prefix)?;
            match self
                .submit(Work::List(prefix.to_owned()), context, slot)
                .await?
            {
                ResultData::Inventory(inventory) => Ok(inventory),
                _ => Err(ObjectIoError::Closed),
            }
        }
        .await;
        rejected.1 = result.is_err();
        result
    }
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
        self.state.slots.close();
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), ObjectIoError> {
        self.close();
        loop {
            check(&context)?;
            let finished = self
                .worker
                .lock()
                .map_err(|_| ObjectIoError::Closed)?
                .as_ref()
                .is_none_or(|w| w.is_finished());
            if finished {
                if let Some(worker) = self
                    .worker
                    .lock()
                    .map_err(|_| ObjectIoError::Closed)?
                    .take()
                {
                    worker.join().map_err(|_| ObjectIoError::Closed)?;
                }
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}
async fn receive_owner_ready(
    receive: oneshot::Receiver<Result<(), ObjectIoError>>,
    context: &OperationContext,
) -> Result<(), ObjectIoError> {
    tokio::select! {
        biased;
        _ = context.cancellation.cancelled() => return Err(ObjectIoError::Cancelled),
        result = timeout_at(context.deadline, receive) => match result {
            Err(_) => return Err(ObjectIoError::Timeout),
            Ok(Err(_)) => return Err(ObjectIoError::Closed),
            Ok(Ok(result)) => result?,
        }
    }
    // timeout_at may poll an already-ready reply before its expired timer.
    check(context)
}
fn owner_error(error: crate::StorageError) -> ObjectIoError {
    match error {
        crate::StorageError::Locked => ObjectIoError::OwnerLocked,
        crate::StorageError::StreamMismatch => ObjectIoError::OwnerBinding,
        crate::StorageError::Timeout => ObjectIoError::Timeout,
        crate::StorageError::Cancelled => ObjectIoError::Cancelled,
        crate::StorageError::Config(_) => ObjectIoError::Config,
        crate::StorageError::Corrupt(_) => ObjectIoError::Corrupt,
        crate::StorageError::InvalidBatch => ObjectIoError::Condition,
        _ => ObjectIoError::Backend,
    }
}
impl Drop for ObjectIo {
    fn drop(&mut self) {
        self.close();
    }
}
fn check(ctx: &OperationContext) -> Result<(), ObjectIoError> {
    check_context(Some(ctx)).map_err(|e| match e {
        crate::StorageError::Timeout => ObjectIoError::Timeout,
        crate::StorageError::Cancelled => ObjectIoError::Cancelled,
        _ => ObjectIoError::Closed,
    })
}
fn valid_key(key: &str) -> Result<(), ObjectIoError> {
    if key.is_empty()
        || key.len() > 512
        || key.starts_with('/')
        || key.contains(['\\', '%', '?', '#'])
        || key.chars().any(char::is_control)
        || key
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(ObjectIoError::Corrupt);
    }
    Ok(())
}
fn copy(body: &[u8], limit: usize) -> Result<Vec<u8>, ObjectIoError> {
    let mut out = Vec::new();
    if body.len() > limit {
        return Err(ObjectIoError::Full);
    }
    out.try_reserve_exact(body.len())
        .map_err(|_| ObjectIoError::Full)?;
    out.extend_from_slice(body);
    if out.capacity() > limit {
        return Err(ObjectIoError::Full);
    }
    Ok(out)
}
fn backend(error: object_store::Error) -> ObjectIoError {
    match error {
        object_store::Error::NotFound { .. } => ObjectIoError::NotFound,
        object_store::Error::AlreadyExists { .. } => ObjectIoError::Exists,
        object_store::Error::Precondition { .. } | object_store::Error::NotModified { .. } => {
            ObjectIoError::Condition
        }
        _ => ObjectIoError::Backend,
    }
}
fn reference(
    meta: &ObjectMeta,
    sha: [u8; 32],
    limit: usize,
) -> Result<QueryObjectRef, ObjectIoError> {
    if meta.location.as_ref().len() > 512
        || meta.version.as_ref().is_some_and(|v| v.len() > 256)
        || meta.e_tag.as_ref().is_some_and(|v| v.len() > 256)
    {
        return Err(ObjectIoError::Corrupt);
    }
    let result = QueryObjectRef {
        key: meta.location.to_string(),
        version: meta.version.clone(),
        etag: meta.e_tag.clone(),
        bytes: meta.size,
        sha256: sha,
    };
    result
        .validate(limit as u64)
        .map_err(|_| ObjectIoError::Corrupt)?;
    Ok(result)
}
async fn execute(
    store: &dyn ObjectStore,
    work: Work,
    limits: ObjectIoLimits,
    ctx: &OperationContext,
    slot: Arc<OwnedSemaphorePermit>,
    remote: bool,
    owner: Option<&crate::object_owner::SmallOwner>,
) -> Result<ResultData, ObjectIoError> {
    check(ctx)?;
    #[cfg(feature = "s3")]
    let _request_scope = crate::object_s3::RequestScope::enter(ctx)?;
    match work {
        Work::ReadGenesis => {
            let owner = owner.ok_or(ObjectIoError::Config)?;
            Ok(ResultData::Genesis(
                owner.query_initialized(ctx).map_err(owner_error)?,
            ))
        }
        Work::InitializeGenesis => {
            let owner = owner.ok_or(ObjectIoError::Config)?;
            owner.initialize_query(ctx).map_err(owner_error)?;
            Ok(ResultData::Genesis(true))
        }
        Work::ReadHead => {
            let owner = owner.ok_or(ObjectIoError::Config)?;
            let head = owner.read_head(ctx).map_err(owner_error)?;
            Ok(ResultData::Head(head.map(|h| h.current)))
        }
        Work::AdvanceHead(next) => {
            let owner = owner.ok_or(ObjectIoError::Config)?;
            owner.advance_head(&next, ctx).map_err(owner_error)?;
            Ok(ResultData::Head(Some(next.current)))
        }
        #[cfg(test)]
        Work::Pause(entered, release) => {
            let _ = entered.send(());
            let _ = release.recv();
            check(ctx)?;
            Ok(ResultData::Done)
        }
        Work::Create(key, body) => {
            let len = body.len() as u64;
            let hash = sha256(&body);
            let path = Path::parse(&key).map_err(|_| ObjectIoError::Corrupt)?;
            let result = store
                .put_opts(
                    &path,
                    Bytes::from(body).into(),
                    PutOptions {
                        mode: PutMode::Create,
                        ..Default::default()
                    },
                )
                .await
                .map_err(backend)?;
            check(ctx)?;
            let reference = QueryObjectRef {
                key,
                version: result.version,
                etag: result.e_tag,
                bytes: len,
                sha256: hash,
            };
            reference
                .validate(limits.bytes as u64)
                .map_err(|_| ObjectIoError::Corrupt)?;
            Ok(ResultData::Created(reference))
        }
        Work::Read(key, expected, max_bytes) => {
            let path = Path::parse(&key).map_err(|_| ObjectIoError::Corrupt)?;
            let options = match &expected {
                None => GetOptions::default(),
                Some(reference) => GetOptions::new()
                    .with_version(reference.version.clone())
                    .with_if_match(reference.etag.clone()),
            };
            let result = store.get_opts(&path, options).await.map_err(backend)?;
            check(ctx)?;
            if result.meta.location != path
                || result.range.start != 0
                || result.range.end != result.meta.size
            {
                return Err(ObjectIoError::Corrupt);
            }
            // Metadata is checked before any owned copy/body read. Versions and
            // conditions must be honored even if a backend ignores options.
            let meta = reference(&result.meta, [0; 32], max_bytes)?;
            if let Some(expected) = &expected
                && (meta.bytes != expected.bytes
                    || expected
                        .version
                        .as_ref()
                        .is_some_and(|v| meta.version.as_ref() != Some(v))
                    || expected
                        .etag
                        .as_ref()
                        .is_some_and(|v| meta.etag.as_ref() != Some(v)))
            {
                return Err(ObjectIoError::Condition);
            }
            let body_limit = meta.bytes as usize;
            let mut body = Vec::new();
            match result.payload {
                GetResultPayload::File(mut file, _) => {
                    if remote {
                        return Err(ObjectIoError::Corrupt);
                    }
                    use std::io::Read;
                    let mut chunk = [0; 8192];
                    loop {
                        check(ctx)?;
                        let n = file.read(&mut chunk).map_err(|_| ObjectIoError::Backend)?;
                        if n == 0 {
                            break;
                        }
                        append(&mut body, &chunk[..n], body_limit)?;
                    }
                }
                GetResultPayload::Stream(mut stream) => {
                    while let Some(chunk) = stream.next().await {
                        check(ctx)?;
                        append(&mut body, &chunk.map_err(backend)?, body_limit)?;
                    }
                }
            }
            let mut actual = meta;
            actual.sha256 = sha256(&body);
            actual
                .verify_bytes(&body, limits.bytes as u64)
                .map_err(|_| ObjectIoError::Corrupt)?;
            if let Some(expected) = expected {
                expected
                    .verify_bytes(&body, limits.bytes as u64)
                    .map_err(|_| ObjectIoError::Corrupt)?;
                actual = expected;
            }
            check(ctx)?;
            Ok(ResultData::Read(ObjectRead {
                reference: actual,
                body,
                _slot: slot,
            }))
        }
        Work::List(prefix) => {
            let path = Path::parse(&prefix).map_err(|_| ObjectIoError::Corrupt)?;
            let mut listing = store.list(Some(&path));
            let mut entries = Vec::new();
            while let Some(meta) = listing.next().await {
                check(ctx)?;
                if entries.len() >= limits.entries {
                    return Err(ObjectIoError::Full);
                }
                let meta = meta.map_err(backend)?;
                let key = meta.location.as_ref();
                if !(key == prefix
                    || key
                        .strip_prefix(&prefix)
                        .is_some_and(|s| s.starts_with('/')))
                {
                    return Err(ObjectIoError::Corrupt);
                }
                entries.push(reference(&meta, [0; 32], limits.bytes)?);
            }
            check(ctx)?;
            Ok(ResultData::Inventory(ObjectInventory {
                entries,
                _slot: slot,
            }))
        }
    }
}
#[cfg(test)]
mod tests;
fn append(out: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<(), ObjectIoError> {
    if chunk.len() > limit.saturating_sub(out.len()) {
        return Err(ObjectIoError::Full);
    }
    out.try_reserve_exact(chunk.len())
        .map_err(|_| ObjectIoError::Full)?;
    out.extend_from_slice(chunk);
    if out.capacity() > limit {
        return Err(ObjectIoError::Full);
    }
    Ok(())
}

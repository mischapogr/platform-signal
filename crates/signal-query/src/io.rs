//! Read-only filesystem access with bounded physical work and retained read buffers.
//!
//! Cancellation stops admission or waiting for a reply. Admitted disk work finishes
//! on a fixed set of ordinary threads; it never occupies Tokio's blocking pool.
//! Read buffers retain a separate byte lease through every `Bytes` clone/slice.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, stream::BoxStream};
use object_store::{
    CopyOptions, GetOptions, GetResult, GetResultPayload, ListResult, MultipartUpload, ObjectMeta,
    ObjectStore, PutMultipartOptions, PutOptions, PutPayload, PutResult, local::LocalFileSystem,
    path::Path,
};
use std::{
    fmt,
    io::{Read, Seek, SeekFrom},
    ops::Range,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
};
use thiserror::Error;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot},
    time::{Instant, timeout_at},
};

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum IoLimitError {
    #[error("invalid filesystem I/O limits")]
    Config,
    #[error("filesystem I/O admission capacity is full")]
    Capacity,
    #[error("filesystem read byte capacity exceeded")]
    Bytes,
    #[error("filesystem listing capacity exceeded")]
    Listing,
    #[error("invalid filesystem read range")]
    Range,
    #[error("filesystem I/O worker unavailable")]
    Worker,
}

pub fn is_limit_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(limit) = error.downcast_ref::<IoLimitError>() {
            return matches!(
                limit,
                IoLimitError::Capacity | IoLimitError::Bytes | IoLimitError::Listing
            );
        }
        current = error.source();
    }
    false
}

#[derive(Debug, Clone, Copy)]
pub struct IoMetrics {
    /// Queued work, running work and replies not yet consumed.
    pub depth: usize,
    pub capacity: usize,
    pub waiter_depth: usize,
    pub waiter_capacity: usize,
    pub queued: usize,
    pub queue_capacity: usize,
    pub running: usize,
    pub worker_capacity: usize,
    pub read_bytes: usize,
    pub read_byte_capacity: usize,
    pub rejected: u64,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

#[derive(Debug, Default)]
struct WorkCounts {
    queued: AtomicUsize,
    running: AtomicUsize,
    physical: AtomicUsize,
    completed: Notify,
}

struct State {
    local: LocalFileSystem,
    owner: Option<Arc<dyn signal_storage::QueryFileSource>>,
    sender: Mutex<Option<SyncSender<Job>>>,
    // Handles are retained for the lifetime of the fixed pool. Dropping a handle
    // detaches an ordinary thread; runtime shutdown never waits on kernel I/O.
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    work: Arc<WorkCounts>,
    io: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    capacity: usize,
    worker_capacity: usize,
    waiter_capacity: usize,
    byte_capacity: usize,
    max_entries: usize,
    closed: AtomicBool,
    rejected: AtomicU64,
    #[cfg(test)]
    pause: Mutex<Option<TestPause>>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilesystemPool")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct BoundedLocalStore {
    state: Arc<State>,
}

impl BoundedLocalStore {
    #[cfg(test)]
    pub fn new(
        capacity: usize,
        max_read_bytes: usize,
        max_list_entries: usize,
    ) -> Result<Self, IoLimitError> {
        Self::with_source(capacity, max_read_bytes, max_list_entries, None)
    }
    pub(crate) fn with_source(
        capacity: usize,
        max_read_bytes: usize,
        max_list_entries: usize,
        owner: Option<Arc<dyn signal_storage::QueryFileSource>>,
    ) -> Result<Self, IoLimitError> {
        let waiter_capacity = capacity
            .checked_mul(max_list_entries)
            .ok_or(IoLimitError::Config)?;
        if capacity == 0
            || capacity > 65_536
            || max_read_bytes == 0
            || max_read_bytes > u32::MAX as usize
            || max_read_bytes > Semaphore::MAX_PERMITS
            || max_list_entries == 0
            || max_list_entries > 100_000
            || waiter_capacity > Semaphore::MAX_PERMITS
        {
            return Err(IoLimitError::Config);
        }
        // Admission slots may exceed worker threads. Both the pending job queue
        // and the actual thread count have independent fixed upper bounds.
        let worker_capacity = capacity.min(32);
        let (sender, receiver) = sync_channel::<Job>(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let work = Arc::new(WorkCounts::default());
        let mut workers = Vec::with_capacity(worker_capacity);
        for index in 0..worker_capacity {
            let receiver = receiver.clone();
            let work = work.clone();
            let worker = std::thread::Builder::new()
                .name(format!("signal-query-io-{index}"))
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => break,
                        };
                        let Ok(job) = job else { break };
                        work.queued.fetch_sub(1, Ordering::AcqRel);
                        work.running.fetch_add(1, Ordering::AcqRel);
                        // No Tokio runtime is entered here. LocalFileSystem's
                        // maybe_spawn_blocking executes directly on this worker.
                        let _ = catch_unwind(AssertUnwindSafe(job));
                        work.running.fetch_sub(1, Ordering::AcqRel);
                        work.physical.fetch_sub(1, Ordering::AcqRel);
                        work.completed.notify_waiters();
                    }
                })
                .map_err(|_| IoLimitError::Worker)?;
            workers.push(worker);
        }
        Ok(Self {
            state: Arc::new(State {
                local: LocalFileSystem::new(),
                owner,
                sender: Mutex::new(Some(sender)),
                workers: Mutex::new(workers),
                work,
                io: Arc::new(Semaphore::new(capacity)),
                waiters: Arc::new(Semaphore::new(waiter_capacity)),
                bytes: Arc::new(Semaphore::new(max_read_bytes)),
                capacity,
                worker_capacity,
                waiter_capacity,
                byte_capacity: max_read_bytes,
                max_entries: max_list_entries,
                closed: AtomicBool::new(false),
                rejected: AtomicU64::new(0),
                #[cfg(test)]
                pause: Mutex::new(None),
            }),
        })
    }

    pub fn metrics(&self) -> IoMetrics {
        IoMetrics {
            depth: self.state.capacity - self.state.io.available_permits(),
            capacity: self.state.capacity,
            waiter_depth: self.state.waiter_capacity - self.state.waiters.available_permits(),
            waiter_capacity: self.state.waiter_capacity,
            queued: self.state.work.queued.load(Ordering::Acquire),
            queue_capacity: self.state.capacity,
            running: self.state.work.running.load(Ordering::Acquire),
            worker_capacity: self.state.worker_capacity,
            read_bytes: self.state.byte_capacity - self.state.bytes.available_permits(),
            read_byte_capacity: self.state.byte_capacity,
            rejected: self.state.rejected.load(Ordering::Relaxed),
        }
    }

    /// Stop new admission, drain queued physical work by the shared deadline.
    /// False leaves the fixed ordinary threads to complete their kernel calls.
    pub async fn shutdown(&self, deadline: Instant) -> bool {
        self.state.closed.store(true, Ordering::Release);
        self.state.io.close();
        self.state.waiters.close();
        if let Ok(mut sender) = self.state.sender.lock() {
            sender.take();
        }
        loop {
            let completed = self.state.work.completed.notified();
            tokio::pin!(completed);
            completed.as_mut().enable();
            if self.state.work.physical.load(Ordering::Acquire) == 0 {
                break;
            }
            if timeout_at(deadline, completed).await.is_err() {
                return false;
            }
        }
        // Never join a thread still finishing its receive loop. Finished handles
        // may be joined without any filesystem or scheduling wait.
        if let Ok(mut workers) = self.state.workers.lock() {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    let _ = workers.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn pause_read(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (started, observed) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        if let Ok(mut pause) = self.state.pause.lock() {
            *pause = Some(TestPause { started, wait });
        }
        (observed, release)
    }
}

impl fmt::Display for BoundedLocalStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundedLocalStore")
    }
}

fn store_error(source: impl std::error::Error + Send + Sync + 'static) -> object_store::Error {
    object_store::Error::Generic {
        store: "bounded_local",
        source: Box::new(source),
    }
}
fn unsupported(operation: &'static str) -> object_store::Error {
    object_store::Error::NotSupported {
        source: format!("read-only filesystem: {operation}").into(),
    }
}

impl State {
    fn reject(&self, limit: IoLimitError) -> object_store::Error {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        store_error(limit)
    }
    fn reserve_bytes(&self, size: usize) -> object_store::Result<OwnedSemaphorePermit> {
        let size = u32::try_from(size).map_err(|_| self.reject(IoLimitError::Bytes))?;
        self.bytes
            .clone()
            .try_acquire_many_owned(size)
            .map_err(|_| self.reject(IoLimitError::Bytes))
    }

    async fn tracked<T: Send + 'static>(
        self: &Arc<Self>,
        work: impl FnOnce() -> object_store::Result<T> + Send + 'static,
    ) -> object_store::Result<T> {
        if self.closed.load(Ordering::Acquire) {
            return Err(self.reject(IoLimitError::Worker));
        }
        // Waiting callers are bounded and cancellable; no worker job exists yet.
        let waiter = self
            .waiters
            .clone()
            .try_acquire_owned()
            .map_err(|_| self.reject(IoLimitError::Capacity))?;
        let permit = self
            .io
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| store_error(IoLimitError::Worker))?;
        drop(waiter);
        let (send, receive) = oneshot::channel();
        let state = self.clone();
        let owner = self.owner.clone();
        let job = Box::new(move || {
            // Discard cancelled queued work before starting any filesystem call.
            if send.is_closed() {
                state.rejected.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let result = work();
            // Unconsumed replies also own an admission slot. If their receiver
            // was cancelled, dropping the failed send releases it after disk I/O.
            let _ = send.send(Reply {
                result,
                _permit: permit,
            });
            // Retain source/cache ownership even after caller or engine drop.
            // No explicit source shutdown is permitted before this physical job drains.
            drop(owner);
        });
        {
            let sender = self
                .sender
                .lock()
                .map_err(|_| store_error(IoLimitError::Worker))?;
            let sender = sender
                .as_ref()
                .ok_or_else(|| store_error(IoLimitError::Worker))?;
            self.work.queued.fetch_add(1, Ordering::AcqRel);
            self.work.physical.fetch_add(1, Ordering::AcqRel);
            if sender.try_send(job).is_err() {
                self.work.queued.fetch_sub(1, Ordering::AcqRel);
                self.work.physical.fetch_sub(1, Ordering::AcqRel);
                return Err(self.reject(IoLimitError::Capacity));
            }
        }
        let reply = receive
            .await
            .map_err(|_| store_error(IoLimitError::Worker))?;
        reply.result
    }

    #[cfg(test)]
    fn read_boundary(&self) {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let pause = self.pause.lock().ok().and_then(|mut pause| pause.take());
        if let Some(TestPause { started, wait }) = pause {
            let _ = started.send(());
            let _ = wait.recv();
        }
    }
}
struct Reply<T> {
    result: object_store::Result<T>,
    _permit: OwnedSemaphorePermit,
}
struct LeasedBytes {
    bytes: Bytes,
    _permit: Arc<OwnedSemaphorePermit>,
}
impl AsRef<[u8]> for LeasedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
fn leased(bytes: Bytes, permit: Arc<OwnedSemaphorePermit>) -> Bytes {
    Bytes::from_owner(LeasedBytes {
        bytes,
        _permit: permit,
    })
}

#[async_trait]
impl ObjectStore for BoundedLocalStore {
    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        let state = self.state.clone();
        let location = location.clone();
        self.state
            .tracked(move || {
                let head = options.head;
                let result = futures::executor::block_on(state.local.get_opts(&location, options))?;
                if head {
                    return Ok(GetResult {
                        payload: GetResultPayload::Stream(futures_util::stream::empty().boxed()),
                        ..result
                    });
                }
                let size = usize::try_from(result.range.end - result.range.start)
                    .map_err(|_| state.reject(IoLimitError::Bytes))?;
                let permit = Arc::new(state.reserve_bytes(size)?);
                let GetResult {
                    payload,
                    meta,
                    range,
                    attributes,
                } = result;
                // No File payload escapes: downstream reads are entirely in memory.
                let bytes = match payload {
                    GetResultPayload::File(mut file, _) => {
                        #[cfg(test)]
                        state.read_boundary();
                        file.seek(SeekFrom::Start(range.start))
                            .map_err(store_error)?;
                        let mut bytes = vec![0; size];
                        file.read_exact(&mut bytes).map_err(store_error)?;
                        Bytes::from(bytes)
                    }
                    GetResultPayload::Stream(_) => {
                        return Err(unsupported("non-local read payload"));
                    }
                };
                let bytes = leased(bytes, permit);
                Ok(GetResult {
                    payload: GetResultPayload::Stream(
                        futures_util::stream::once(async move { Ok(bytes) }).boxed(),
                    ),
                    meta,
                    range,
                    attributes,
                })
            })
            .await
    }

    async fn get_ranges(
        &self,
        location: &Path,
        ranges: &[Range<u64>],
    ) -> object_store::Result<Vec<Bytes>> {
        if ranges.len() > self.state.max_entries {
            return Err(self.state.reject(IoLimitError::Listing));
        }
        let mut size = 0usize;
        for range in ranges {
            let length = range
                .end
                .checked_sub(range.start)
                .ok_or_else(|| store_error(IoLimitError::Range))?;
            size = size
                .checked_add(
                    usize::try_from(length).map_err(|_| self.state.reject(IoLimitError::Bytes))?,
                )
                .ok_or_else(|| self.state.reject(IoLimitError::Bytes))?;
        }
        let state = self.state.clone();
        let location = location.clone();
        let ranges = ranges.to_vec();
        self.state
            .tracked(move || {
                let permit = Arc::new(state.reserve_bytes(size)?);
                #[cfg(test)]
                state.read_boundary();
                let bytes =
                    futures::executor::block_on(state.local.get_ranges(&location, &ranges))?;
                Ok(bytes
                    .into_iter()
                    .map(|bytes| leased(bytes, permit.clone()))
                    .collect())
            })
            .await
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        let store = self.clone();
        let prefix = prefix.cloned();
        futures_util::stream::once(async move { store.bounded_list(prefix).await })
            .map(|result| match result {
                Ok(list) => futures_util::stream::unfold(
                    (list.result.objects.into_iter(), list._permit),
                    |(mut objects, permit)| async move {
                        objects.next().map(|object| (Ok(object), (objects, permit)))
                    },
                )
                .boxed(),
                Err(error) => futures_util::stream::once(async move { Err(error) }).boxed(),
            })
            .flatten()
            .boxed()
    }

    async fn list_with_delimiter(&self, _: Option<&Path>) -> object_store::Result<ListResult> {
        // ListResult cannot retain a byte lease. Exact manifest paths do not
        // require delimiter enumeration.
        Err(unsupported("delimiter listing"))
    }
    async fn put_opts(
        &self,
        _: &Path,
        _: PutPayload,
        _: PutOptions,
    ) -> object_store::Result<PutResult> {
        Err(unsupported("put"))
    }
    async fn put_multipart_opts(
        &self,
        _: &Path,
        _: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        Err(unsupported("multipart upload"))
    }
    fn delete_stream(
        &self,
        _: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        futures_util::stream::once(async { Err(unsupported("delete")) }).boxed()
    }
    async fn copy_opts(&self, _: &Path, _: &Path, _: CopyOptions) -> object_store::Result<()> {
        Err(unsupported("copy"))
    }
}

struct Listed {
    result: ListResult,
    _permit: OwnedSemaphorePermit,
}
impl BoundedLocalStore {
    async fn bounded_list(&self, prefix: Option<Path>) -> object_store::Result<Listed> {
        let state = self.state.clone();
        self.state
            .tracked(move || {
                // The full listing has one byte lease, including while awaiting a
                // caller or stream polling. Directory traversal has no read-ahead.
                let permit = state.reserve_bytes(state.byte_capacity)?;
                let root = state
                    .local
                    .path_to_filesystem(&prefix.unwrap_or_default())?;
                let mut directories = vec![root];
                let mut objects = Vec::new();
                let mut visited = 0usize;
                let mut retained = 0usize;
                while let Some(directory) = directories.pop() {
                    let entries = match std::fs::read_dir(&directory) {
                        Ok(entries) => entries,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(store_error(error)),
                    };
                    for entry in entries {
                        let entry = entry.map_err(store_error)?;
                        visited += 1;
                        if visited > state.max_entries {
                            return Err(state.reject(IoLimitError::Listing));
                        }
                        let kind = entry.file_type().map_err(store_error)?;
                        if kind.is_symlink() {
                            return Err(unsupported("symlink listing"));
                        }
                        let path = entry.path();
                        let location = Path::from_filesystem_path(&path).map_err(store_error)?;
                        // Account for both paths and collection allocations, including
                        // the capacity growth of the bounded vectors.
                        retained = retained
                            .checked_add(
                                2 * (std::mem::size_of::<ObjectMeta>()
                                    + location.as_ref().len()
                                    + 128),
                            )
                            .ok_or_else(|| state.reject(IoLimitError::Bytes))?;
                        if retained > state.byte_capacity {
                            return Err(state.reject(IoLimitError::Bytes));
                        }
                        if kind.is_dir() {
                            directories.push(path);
                        } else if kind.is_file() && !location.as_ref().contains('#') {
                            let metadata = entry.metadata().map_err(store_error)?;
                            objects.push(ObjectMeta {
                                location,
                                last_modified: metadata.modified().map_err(store_error)?.into(),
                                size: metadata.len(),
                                e_tag: None,
                                version: None,
                            });
                        }
                    }
                }
                Ok(Listed {
                    result: ListResult {
                        common_prefixes: Vec::new(),
                        objects,
                    },
                    _permit: permit,
                })
            })
            .await
    }
}

#[cfg(test)]
struct TestPause {
    started: oneshot::Sender<()>,
    wait: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use futures_util::TryStreamExt;
    use object_store::{GetRange, ObjectStoreExt};
    use std::time::Duration;

    fn file(bytes: &[u8]) -> (tempfile::TempDir, Path) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        std::fs::write(&path, bytes).unwrap();
        let location = Path::from_filesystem_path(&path).unwrap();
        (directory, location)
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn invalid_limits_fail_before_workers_start() {
        for limits in [
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0),
            (65_537, 1, 1),
            (1, usize::MAX, 1),
            (1, 1, 100_001),
        ] {
            assert!(matches!(
                BoundedLocalStore::new(limits.0, limits.1, limits.2),
                Err(IoLimitError::Config)
            ));
        }
    }

    #[tokio::test]
    async fn reads_ranges_and_preconditions_preserve_local_semantics() {
        let (_directory, location) = file(b"0123456789");
        let store = BoundedLocalStore::new(2, 64, 16).unwrap();
        let head = store.head(&location).await.unwrap();
        assert_eq!(head.size, 10);
        assert_eq!(store.metrics().read_bytes, 0);
        let result = store.get(&location).await.unwrap();
        assert!(matches!(result.payload, GetResultPayload::Stream(_)));
        assert_eq!(result.range, 0..10);
        assert_eq!(result.bytes().await.unwrap(), b"0123456789"[..]);
        assert_eq!(store.get_range(&location, 3..7).await.unwrap(), b"3456"[..]);
        for (range, expected) in [
            (GetRange::Offset(8), &b"89"[..]),
            (GetRange::Suffix(3), &b"789"[..]),
            (GetRange::Bounded(8..100), &b"89"[..]),
        ] {
            let result = store
                .get_opts(
                    &location,
                    GetOptions {
                        range: Some(range),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(result.bytes().await.unwrap(), expected);
        }
        let result = store
            .get_opts(
                &location,
                GetOptions {
                    if_match: Some("wrong-tag".to_owned()),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(object_store::Error::Precondition { .. })
        ));
        let missing = Path::from(format!("{location}.missing"));
        assert!(matches!(
            store.head(&missing).await,
            Err(object_store::Error::NotFound { .. })
        ));
        assert_eq!(store.metrics().read_bytes, 0);
        assert!(
            store
                .shutdown(Instant::now() + Duration::from_secs(1))
                .await
        );
    }

    #[tokio::test]
    async fn buffers_and_slices_retain_global_byte_budget() {
        let (_directory, location) = file(b"0123456789");
        let store = BoundedLocalStore::new(2, 10, 16).unwrap();
        let bytes = store.get(&location).await.unwrap().bytes().await.unwrap();
        let slice = bytes.slice(1..3);
        drop(bytes);
        assert_eq!(store.metrics().read_bytes, 10);
        assert!(is_limit_error(
            &store.get_range(&location, 0..1).await.unwrap_err()
        ));
        assert_eq!(store.metrics().rejected, 1);
        drop(slice);
        assert_eq!(store.metrics().read_bytes, 0);
        assert_eq!(store.get_range(&location, 0..1).await.unwrap(), b"0"[..]);
    }

    #[tokio::test]
    async fn whole_files_and_multi_ranges_are_capped_before_reading() {
        let (_directory, location) = file(b"0123456789");
        let store = BoundedLocalStore::new(1, 8, 4).unwrap();
        assert!(is_limit_error(&store.get(&location).await.unwrap_err()));
        assert!(is_limit_error(
            &store
                .get_ranges(&location, &[0..5, 5..10])
                .await
                .unwrap_err()
        ));
        assert!(is_limit_error(
            &store
                .get_ranges(&location, &vec![0..1; 5])
                .await
                .unwrap_err()
        ));
        assert_eq!(store.metrics().read_bytes, 0);
        let ranges = store.get_ranges(&location, &[0..3, 6..10]).await.unwrap();
        assert_eq!(
            ranges,
            vec![Bytes::from_static(b"012"), Bytes::from_static(b"6789")]
        );
        assert_eq!(store.metrics().read_bytes, 7);
        let retained = ranges[0].clone();
        drop(ranges);
        assert_eq!(store.metrics().read_bytes, 7);
        drop(retained);
        assert_eq!(store.metrics().read_bytes, 0);
        let backwards = Range { start: 5, end: 3 };
        assert!(store.get_ranges(&location, &[backwards]).await.is_err());
        assert!(
            store
                .get_ranges(&location, std::slice::from_ref(&(10..11)))
                .await
                .is_err()
        );
        assert_eq!(store.metrics().read_bytes, 0);
    }

    #[tokio::test]
    async fn cancelled_reads_keep_the_actual_worker_slot_until_completion() {
        let (_directory, location) = file(b"0123456789");
        let store = Arc::new(BoundedLocalStore::new(1, 32, 2).unwrap());
        let (started, release) = store.pause_read();
        let caller = tokio::spawn({
            let store = store.clone();
            let location = location.clone();
            async move { store.get(&location).await }
        });
        started.await.unwrap();
        assert_eq!(store.metrics().running, 1);
        assert_eq!(store.metrics().depth, 1);
        assert_eq!(store.metrics().read_bytes, 10);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        for _ in 0..8 {
            assert!(
                tokio::time::timeout(Duration::from_millis(5), store.get(&location))
                    .await
                    .is_err()
            );
            assert_eq!(store.metrics().running, 1);
            assert_eq!(store.metrics().depth, 1);
            assert_eq!(store.metrics().queued, 0);
            assert_eq!(store.metrics().waiter_depth, 0);
            assert_eq!(store.metrics().worker_capacity, 1);
        }
        release.send(()).unwrap();
        until(|| store.metrics().depth == 0 && store.metrics().running == 0).await;
        assert_eq!(store.metrics().read_bytes, 0);
        assert_eq!(
            store.get(&location).await.unwrap().bytes().await.unwrap(),
            b"0123456789"[..]
        );
    }

    #[tokio::test]
    async fn admitted_waiters_are_bounded_and_cancel_without_creating_jobs() {
        let (_directory, location) = file(b"0123456789");
        let store = Arc::new(BoundedLocalStore::new(1, 32, 1).unwrap());
        let (started, release) = store.pause_read();
        let first = tokio::spawn({
            let store = store.clone();
            let location = location.clone();
            async move { store.get(&location).await }
        });
        started.await.unwrap();
        let waiter = tokio::spawn({
            let store = store.clone();
            let location = location.clone();
            async move { store.head(&location).await }
        });
        until(|| store.metrics().waiter_depth == 1).await;
        assert!(is_limit_error(&store.head(&location).await.unwrap_err()));
        assert_eq!(store.metrics().rejected, 1);
        assert_eq!(store.metrics().queued, 0);
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(store.metrics().waiter_depth, 0);
        release.send(()).unwrap();
        drop(first.await.unwrap().unwrap());
        until(|| store.metrics().depth == 0).await;
    }

    #[tokio::test]
    async fn completed_unpolled_replies_remain_bounded() {
        let (_directory, location) = file(b"0123456789");
        let store = BoundedLocalStore::new(1, 10, 2).unwrap();
        let mut caller = Box::pin(store.get(&location));
        assert!(futures::poll!(&mut caller).is_pending());
        until(|| store.state.work.physical.load(Ordering::Acquire) == 0).await;
        assert_eq!(store.metrics().depth, 1);
        assert_eq!(store.metrics().read_bytes, 10);
        assert_eq!(store.metrics().queued, 0);
        drop(caller);
        assert_eq!(store.metrics().depth, 0);
        assert_eq!(store.metrics().read_bytes, 0);
    }

    #[tokio::test]
    async fn shutdown_deadline_does_not_wait_for_kernel_work_or_admit_replacements() {
        let (_directory, location) = file(b"0123456789");
        let store = Arc::new(BoundedLocalStore::new(1, 32, 2).unwrap());
        let (started, release) = store.pause_read();
        let caller = tokio::spawn({
            let store = store.clone();
            let location = location.clone();
            async move { store.get(&location).await }
        });
        started.await.unwrap();
        caller.abort();
        let _ = caller.await;
        assert!(
            !store
                .shutdown(Instant::now() + Duration::from_millis(5))
                .await
        );
        assert_eq!(store.metrics().running, 1);
        assert!(store.head(&location).await.is_err());
        release.send(()).unwrap();
        assert!(
            store
                .shutdown(Instant::now() + Duration::from_secs(1))
                .await
        );
        assert_eq!(store.metrics().running, 0);
        assert_eq!(store.metrics().depth, 0);
    }

    #[tokio::test]
    async fn listing_bounds_and_stream_byte_leases_cover_all_results() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join("a.parquet"), b"abc").unwrap();
        std::fs::write(directory.path().join("nested/b.parquet"), b"def").unwrap();
        let prefix = Path::from_filesystem_path(directory.path()).unwrap();
        let store = BoundedLocalStore::new(2, 4096, 3).unwrap();
        let mut stream = store.list(Some(&prefix));
        assert!(stream.next().await.unwrap().is_ok());
        assert_eq!(store.metrics().read_bytes, 4096);
        assert_eq!(stream.try_collect::<Vec<_>>().await.unwrap().len(), 1);
        assert_eq!(store.metrics().read_bytes, 0);
        assert!(matches!(
            store.list_with_delimiter(Some(&prefix)).await,
            Err(object_store::Error::NotSupported { .. })
        ));
        let bounded = BoundedLocalStore::new(1, 4096, 2).unwrap();
        let error = bounded
            .list(Some(&prefix))
            .try_collect::<Vec<_>>()
            .await
            .unwrap_err();
        assert!(is_limit_error(&error));
        assert_eq!(bounded.metrics().rejected, 1);
        let byte_limited = BoundedLocalStore::new(1, 8, 3).unwrap();
        assert!(is_limit_error(
            &byte_limited
                .list(Some(&prefix))
                .try_collect::<Vec<_>>()
                .await
                .unwrap_err()
        ));
        assert_eq!(byte_limited.metrics().read_bytes, 0);
    }

    #[test]
    fn paused_filesystem_work_does_not_delay_tokio_runtime_drop() {
        let (_directory, location) = file(b"0123456789");
        let store = Arc::new(BoundedLocalStore::new(1, 32, 2).unwrap());
        let (started, release) = store.pause_read();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (caller,) = runtime.block_on(async {
            let caller = tokio::spawn({
                let store = store.clone();
                async move { store.get(&location).await }
            });
            started.await.unwrap();
            (caller,)
        });
        assert_eq!(store.metrics().running, 1);
        let (done, observed) = std::sync::mpsc::channel();
        let dropper = std::thread::spawn(move || {
            drop(runtime);
            done.send(()).unwrap();
        });
        let dropped_before_release = observed.recv_timeout(Duration::from_secs(1)).is_ok();
        // Release even on failure so a regression cannot leave a hanging thread.
        release.send(()).unwrap();
        dropper.join().unwrap();
        drop(caller);
        assert!(dropped_before_release);
    }

    #[tokio::test]
    async fn cancelled_queued_jobs_do_not_start_disk_work() {
        let store = Arc::new(BoundedLocalStore::new(33, 64, 2).unwrap());
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let mut callers = Vec::new();
        for _ in 0..32 {
            let store = store.clone();
            let gate = gate.clone();
            callers.push(tokio::spawn(async move {
                store
                    .state
                    .tracked(move || {
                        let mut released = gate.0.lock().unwrap();
                        while !*released {
                            released = gate.1.wait(released).unwrap();
                        }
                        Ok(())
                    })
                    .await
            }));
        }
        until(|| store.metrics().running == 32).await;
        let ran = Arc::new(AtomicBool::new(false));
        let queued = tokio::spawn({
            let store = store.clone();
            let ran = ran.clone();
            async move {
                store
                    .state
                    .tracked(move || {
                        ran.store(true, Ordering::Release);
                        Ok(())
                    })
                    .await
            }
        });
        until(|| store.metrics().queued == 1).await;
        queued.abort();
        let _ = queued.await;
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        for caller in callers {
            caller.await.unwrap().unwrap();
        }
        until(|| store.metrics().depth == 0 && store.metrics().running == 0).await;
        assert!(!ran.load(Ordering::Acquire));
        assert_eq!(store.metrics().rejected, 1);
        assert!(
            store
                .shutdown(Instant::now() + Duration::from_secs(1))
                .await
        );
    }

    #[tokio::test]
    async fn read_only_operations_return_typed_not_supported() {
        let (_directory, location) = file(b"abc");
        let store = BoundedLocalStore::new(1, 32, 2).unwrap();
        assert!(matches!(
            store.put(&location, "new".into()).await,
            Err(object_store::Error::NotSupported { .. })
        ));
        assert!(matches!(
            store.copy(&location, &location).await,
            Err(object_store::Error::NotSupported { .. })
        ));
        assert!(matches!(
            store.delete(&location).await,
            Err(object_store::Error::NotSupported { .. })
        ));
    }
}

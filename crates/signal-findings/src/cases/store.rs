use super::*;
use sha2::Sha256;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout_at},
};

const HEADER: u64 = 28;
#[derive(Clone, Debug)]
pub struct CaseConfig {
    pub directory: PathBuf,
    pub max_cases: usize,
    pub max_operations: usize,
    pub max_disk_bytes: u64,
    pub max_record_bytes: usize,
    pub max_state_bytes: usize,
    pub max_page_records: usize,
    pub max_page_bytes: usize,
    pub operation_capacity: usize,
    pub operation_timeout: Duration,
}
impl Default for CaseConfig {
    fn default() -> Self {
        Self {
            directory: "data/cases".into(),
            max_cases: 1024,
            max_operations: 4096,
            max_disk_bytes: 32 * 1024 * 1024,
            max_record_bytes: MAX_CASE_RECORD_BYTES,
            max_state_bytes: 64 * 1024 * 1024,
            max_page_records: 100,
            max_page_bytes: 1024 * 1024,
            operation_capacity: 4,
            operation_timeout: Duration::from_secs(5),
        }
    }
}
impl CaseConfig {
    fn validate(&self) -> Result<(), CaseError> {
        if self.directory.as_os_str().is_empty()
            || !(1..=100_000).contains(&self.max_cases)
            || !(1..=100_000).contains(&self.max_operations)
            || self.max_cases > self.max_operations
            || !(HEADER..=1024 * 1024 * 1024).contains(&self.max_disk_bytes)
            || !(128..=MAX_CASE_RECORD_BYTES).contains(&self.max_record_bytes)
            || !(4096..=512 * 1024 * 1024).contains(&self.max_state_bytes)
            || !(1..=100).contains(&self.max_page_records)
            || !(128..=4 * 1024 * 1024).contains(&self.max_page_bytes)
            || !(1..=16).contains(&self.operation_capacity)
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(30)
        {
            return Err(CaseError::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct CaseMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub rejections: u64,
    pub closed: bool,
}
struct Shared {
    closed: AtomicBool,
    rejections: AtomicU64,
}
struct CallGuard {
    context: FindingContext,
    shared: Arc<Shared>,
    finished: bool,
}
impl Drop for CallGuard {
    fn drop(&mut self) {
        self.context.cancellation.cancel();
        if !self.finished {
            self.shared.rejections.fetch_add(1, Ordering::Relaxed);
        }
    }
}
trait RuntimeAuthority: Clone + Send + Sync + 'static {
    fn lease(&self) -> &FindingContext;
    fn check(&self) -> Result<(), CaseError>;
}
impl RuntimeAuthority for CaseAuthority {
    fn lease(&self) -> &FindingContext {
        &self.context
    }
    fn check(&self) -> Result<(), CaseError> {
        CaseAuthority::check(self)
    }
}
impl RuntimeAuthority for CaseInventoryAuthority {
    fn lease(&self) -> &FindingContext {
        &self.context
    }
    fn check(&self) -> Result<(), CaseError> {
        CaseInventoryAuthority::check(self)
    }
}
struct Reply<R> {
    result: Result<R, CaseError>,
    _permit: Arc<OwnedSemaphorePermit>,
}
pub struct CaseStore {
    config: CaseConfig,
    engine: Arc<Mutex<Engine>>,
    permits: Arc<Semaphore>,
    shared: Arc<Shared>,
}
impl CaseStore {
    pub async fn open(
        config: CaseConfig,
        namespace: Uuid,
        mut context: FindingContext,
    ) -> Result<Self, CaseError> {
        config.validate()?;
        if namespace.is_nil() {
            return Err(CaseError::Invalid);
        }
        context.deadline = context
            .deadline
            .min(Instant::now() + config.operation_timeout);
        context.cancellation = context.cancellation.child_token();
        check(&context)?;
        let shared = Arc::new(Shared {
            closed: AtomicBool::new(false),
            rejections: AtomicU64::new(0),
        });
        let mut guard = CallGuard {
            context: context.clone(),
            shared: shared.clone(),
            finished: false,
        };
        let worker_config = config.clone();
        let worker_context = context.clone();
        let task = tokio::task::spawn_blocking(move || {
            Engine::open(worker_config, namespace, &worker_context)
        });
        let engine = tokio::select! {
            r = timeout_at(context.deadline, task) => r.map_err(|_| CaseError::Timeout)?.map_err(|_| CaseError::Unavailable)??,
            () = context.cancellation.cancelled() => return Err(CaseError::Cancelled),
        };
        check(&context)?;
        guard.finished = true;
        Ok(Self {
            permits: Arc::new(Semaphore::new(config.operation_capacity)),
            config,
            engine: Arc::new(Mutex::new(engine)),
            shared,
        })
    }
    pub fn metrics(&self) -> CaseMetrics {
        CaseMetrics {
            depth: self.config.operation_capacity - self.permits.available_permits(),
            capacity: self.config.operation_capacity,
            rejections: self.shared.rejections.load(Ordering::Relaxed),
            closed: self.shared.closed.load(Ordering::Acquire),
        }
    }
    async fn execute<R, A, F>(
        &self,
        authority: A,
        mut context: FindingContext,
        work: F,
    ) -> Result<R, CaseError>
    where
        R: Send + 'static,
        A: RuntimeAuthority,
        F: FnOnce(&mut Engine, &A, &FindingContext) -> Result<R, CaseError> + Send + 'static,
    {
        // Guard also counts aborted callers. Physical permit belongs to the task/reply.
        context.deadline = context
            .deadline
            .min(authority.lease().deadline)
            .min(Instant::now() + self.config.operation_timeout);
        context.cancellation = context.cancellation.child_token();
        let mut guard = CallGuard {
            context: context.clone(),
            shared: self.shared.clone(),
            finished: false,
        };
        let result = async {
            if self.shared.closed.load(Ordering::Acquire) { return Err(CaseError::Unavailable); }
            check(&context)?; authority.check()?;
            let permit = Arc::new(self.permits.clone().try_acquire_owned().map_err(|_| CaseError::Capacity)?);
            let engine = self.engine.clone(); let current = context.clone(); let proof = authority.clone(); let shared = self.shared.clone();
            let task = tokio::task::spawn_blocking(move || {
                let result = (|| {
                    let mut engine = engine.lock().map_err(|_| CaseError::Unavailable)?;
                    check(&current)?; proof.check()?;
                    if engine.failed { return Err(CaseError::Unavailable); }
                    let result = work(&mut engine, &proof, &current);
                    if matches!(result, Err(CaseError::Corrupt | CaseError::Unavailable)) { engine.failed = true; }
                    if engine.failed { shared.closed.store(true, Ordering::Release); }
                    result
                })();
                Reply { result, _permit: permit }
            });
            let reply = tokio::select! {
                r = timeout_at(context.deadline, task) => r.map_err(|_| CaseError::Timeout)?.map_err(|_| CaseError::Unavailable)?,
                () = context.cancellation.cancelled() => return Err(CaseError::Cancelled),
                () = authority.lease().cancellation.cancelled() => return Err(CaseError::Cancelled),
            };
            check(&context)?; authority.check()?; reply.result
        }.await;
        guard.finished = true;
        if result.is_err() {
            self.shared.rejections.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    pub async fn record(
        &self,
        authority: CaseAuthority,
        request: CaseRequest,
        context: FindingContext,
    ) -> Result<CaseReceipt, CaseError> {
        // Validation is repeated on the worker; reject huge typed allocations before queueing.
        if let Err(e) = request.validate() {
            self.shared.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        self.execute(authority, context, move |engine, authority, context| {
            engine.record(authority, request, context)
        })
        .await
    }
    pub async fn head(
        &self,
        authority: CaseAuthority,
        context: FindingContext,
    ) -> Result<CaseHead, CaseError> {
        self.execute(authority, context, |engine, authority, context| {
            engine.paths(context)?;
            let head = engine
                .heads
                .get(&authority.case_id)
                .ok_or(CaseError::NotFound)?;
            authority.authorize(engine.namespace, head.case_id, &head.references, None)?;
            check(context)?;
            Ok(head.clone())
        })
        .await
    }
    pub async fn history(
        &self,
        authority: CaseAuthority,
        after_revision: u64,
        limit: usize,
        context: FindingContext,
    ) -> Result<CaseHistory, CaseError> {
        self.execute(authority, context, move |engine, authority, context| {
            engine.paths(context)?;
            if limit == 0 || limit > engine.config.max_page_records {
                return Err(CaseError::Invalid);
            }
            let head = engine
                .heads
                .get(&authority.case_id)
                .ok_or(CaseError::NotFound)?;
            authority.authorize(engine.namespace, head.case_id, &head.references, None)?;
            if after_revision > head.revision {
                return Err(CaseError::Invalid);
            }
            let mut page = CaseHistory {
                schema_version: CASE_SCHEMA_VERSION,
                records: Vec::new(),
                has_more: false,
                next_revision: after_revision,
            };
            for (record, _) in &engine.records {
                check(context)?;
                authority.check()?;
                if record.head.case_id == head.case_id && record.head.revision > after_revision {
                    if page.records.len() == limit {
                        page.has_more = true;
                        break;
                    }
                    page.records.push(record.clone());
                    page.next_revision = record.head.revision;
                }
            }
            let bytes = serde_json::to_vec(&page).map_err(|_| CaseError::Corrupt)?;
            if bytes.len() > engine.config.max_page_bytes {
                return Err(CaseError::Capacity);
            }
            check(context)?;
            authority.check()?;
            Ok(page)
        })
        .await
    }
    /// Internal reference discovery only. This result cannot authorize clients.
    pub async fn reference_inventory(
        &self,
        authority: CaseInventoryAuthority,
        case_id: Uuid,
        context: FindingContext,
    ) -> Result<CaseInventoryEntry, CaseError> {
        self.execute(authority, context, move |engine, authority, context| {
            authority.authorize(engine.namespace)?;
            engine.paths(context)?;
            if case_id.is_nil() {
                return Err(CaseError::Invalid);
            }
            let head = engine.heads.get(&case_id).ok_or(CaseError::NotFound)?;
            let entry = CaseInventoryEntry {
                namespace: engine.namespace,
                case_id: head.case_id,
                revision: head.revision,
                references: head.references.clone(),
            };
            entry.check_bytes(engine.config.max_page_bytes)?;
            check(context)?;
            authority.check()?;
            Ok(entry)
        })
        .await
    }
    /// Internal deterministic UUID traversal bound to the exact committed prefix.
    /// The raw cursor is not a client API or an authorization decision.
    pub async fn inventory_page(
        &self,
        authority: CaseInventoryAuthority,
        after_case_id: Option<Uuid>,
        expected_commit: Option<[u8; 32]>,
        limit: usize,
        context: FindingContext,
    ) -> Result<CaseInventoryPage, CaseError> {
        self.execute(authority, context, move |engine, authority, context| {
            authority.authorize(engine.namespace)?;
            engine.paths(context)?;
            if limit == 0
                || limit > engine.config.max_page_records
                || after_case_id.is_some_and(|id| id.is_nil())
                || (after_case_id.is_some() && expected_commit.is_none())
            {
                return Err(CaseError::Invalid);
            }
            let binding: [u8; 32] = engine.prefix.clone().finalize().into();
            if expected_commit.is_some_and(|old| old != binding) {
                return Err(CaseError::Conflict);
            }
            let start = after_case_id.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
            let mut page = CaseInventoryPage {
                namespace: engine.namespace,
                entries: Vec::new(),
                next_case_id: None,
                has_more: false,
                commit_binding: binding,
            };
            for (_, head) in engine.heads.range((start, std::ops::Bound::Unbounded)) {
                check(context)?;
                authority.check()?;
                if page.entries.len() == limit {
                    page.has_more = true;
                    break;
                }
                page.entries.push(CaseInventoryEntry {
                    namespace: engine.namespace,
                    case_id: head.case_id,
                    revision: head.revision,
                    references: head.references.clone(),
                });
            }
            if page.has_more {
                page.next_case_id = page.entries.last().map(|entry| entry.case_id);
            }
            page.check_bytes(engine.config.max_page_bytes)?;
            check(context)?;
            authority.check()?;
            Ok(page)
        })
        .await
    }
    /// Stop admission and bound waiting; detached physical owners retain the root lock.
    pub async fn shutdown(self, context: FindingContext) -> Result<(), CaseError> {
        self.shared.closed.store(true, Ordering::Release);
        check(&context)?;
        let permits = self
            .permits
            .clone()
            .acquire_many_owned(self.config.operation_capacity as u32);
        tokio::select! {
            r = timeout_at(context.deadline, permits) => { let _all = r.map_err(|_| CaseError::Timeout)?.map_err(|_| CaseError::Unavailable)?; check(&context) },
            () = context.cancellation.cancelled() => Err(CaseError::Cancelled),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    schema_version: u16,
    namespace: Uuid,
    end: u64,
    records: usize,
    prefix: [u8; 32],
}
struct Engine {
    config: CaseConfig,
    namespace: Uuid,
    _lock: File,
    file: File,
    root_identity: (u64, u64),
    heads: BTreeMap<Uuid, CaseHead>,
    operations: BTreeMap<Uuid, usize>,
    records: Vec<(CaseRecord, Vec<u8>)>,
    bytes: u64,
    charge: usize,
    prefix: Sha256,
    failed: bool,
}
fn io<T>(result: std::io::Result<T>) -> Result<T, CaseError> {
    result.map_err(|_| CaseError::Unavailable)
}
fn private(path: &Path, directory: bool) -> Result<std::fs::Metadata, CaseError> {
    for ancestor in path.ancestors() {
        if let Ok(m) = fs::symlink_metadata(ancestor)
            && m.file_type().is_symlink()
        {
            return Err(CaseError::Corrupt);
        }
    }
    let m = io(fs::symlink_metadata(path))?;
    if (directory && (!m.is_dir() || m.mode() & 0o777 != 0o700))
        || (!directory && (!m.is_file() || m.nlink() != 1 || m.mode() & 0o777 != 0o600))
    {
        return Err(CaseError::Corrupt);
    }
    Ok(m)
}
fn optional_private(path: &Path) -> Result<bool, CaseError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            private(path, false)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CaseError::Unavailable),
    }
}
fn header(namespace: Uuid) -> Vec<u8> {
    let mut bytes = b"SIGCASE1".to_vec();
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&crc32fast::hash(&bytes).to_le_bytes());
    bytes
}
fn frame(data: &[u8]) -> Vec<u8> {
    let mut bytes = (data.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    bytes.extend_from_slice(&crc32fast::hash(&bytes).to_le_bytes());
    bytes.extend_from_slice(data);
    bytes
}
impl Engine {
    fn open(
        config: CaseConfig,
        namespace: Uuid,
        context: &FindingContext,
    ) -> Result<Self, CaseError> {
        check(context)?;
        if !config.directory.exists() {
            io(fs::DirBuilder::new().mode(0o700).create(&config.directory))?;
            let parent = config
                .directory
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            io(io(File::open(parent))?.sync_all())?;
        }
        let root = private(&config.directory, true)?;
        for entry in io(fs::read_dir(&config.directory))? {
            let entry = io(entry)?;
            if ![
                ".lock",
                "cases.journal",
                "cases.initial",
                "cases.commit",
                "cases.commit.tmp",
            ]
            .iter()
            .any(|n| entry.file_name() == *n)
            {
                return Err(CaseError::Corrupt);
            }
            private(&entry.path(), false)?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(config.directory.join(".lock")))?;
        private(&config.directory.join(".lock"), false)?;
        lock.try_lock().map_err(|_| CaseError::Locked)?;
        let held = io(lock.metadata())?;
        let named = private(&config.directory.join(".lock"), false)?;
        if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            return Err(CaseError::Corrupt);
        }
        let path = config.directory.join("cases.journal");
        let initial = config.directory.join("cases.initial");
        let commit = config.directory.join("cases.commit");
        let exists = optional_private(&path)?;
        if !exists {
            if optional_private(&commit)? {
                return Err(CaseError::Corrupt);
            }
            if optional_private(&initial)? {
                io(fs::remove_file(&initial))?;
            }
            let mut f = io(OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&initial))?;
            io(f.write_all(&header(namespace)))?;
            io(f.sync_all())?;
            check(context)?;
            io(fs::rename(&initial, &path))?;
            io(io(File::open(&config.directory))?.sync_all())?;
        } else if optional_private(&initial)? {
            return Err(CaseError::Corrupt);
        }
        private(&path, false)?;
        let mut file = io(OpenOptions::new().read(true).write(true).open(&path))?;
        let physical = io(file.metadata())?.len();
        if physical < HEADER {
            return Err(CaseError::Corrupt);
        }
        if physical > config.max_disk_bytes {
            return Err(CaseError::Capacity);
        }
        let mut actual = [0u8; 28];
        io(file.read_exact(&mut actual))?;
        if actual.as_slice() != header(namespace) {
            return Err(CaseError::Corrupt);
        }
        let mut prefix = Sha256::new();
        prefix.update(actual);
        let witness = if optional_private(&commit)? {
            let mut f = io(File::open(&commit))?;
            if io(f.metadata())?.len() > 1024 {
                return Err(CaseError::Corrupt);
            }
            let mut bytes = Vec::new();
            io(f.read_to_end(&mut bytes))?;
            serde_json::from_slice::<Witness>(&bytes).map_err(|_| CaseError::Corrupt)?
        } else {
            if physical != HEADER {
                return Err(CaseError::Corrupt);
            }
            Witness {
                schema_version: CASE_SCHEMA_VERSION,
                namespace,
                end: HEADER,
                records: 0,
                prefix: prefix.clone().finalize().into(),
            }
        };
        if witness.schema_version != CASE_SCHEMA_VERSION
            || witness.namespace != namespace
            || witness.end < HEADER
            || physical < witness.end
        {
            return Err(CaseError::Corrupt);
        }
        if witness.records > config.max_operations {
            return Err(CaseError::Capacity);
        }
        let mut e = Self {
            config,
            namespace,
            _lock: lock,
            file,
            root_identity: (root.dev(), root.ino()),
            heads: BTreeMap::new(),
            operations: BTreeMap::new(),
            records: Vec::new(),
            bytes: HEADER,
            charge: 0,
            prefix,
            failed: false,
        };
        while e.bytes < witness.end {
            check(context)?;
            if witness.end - e.bytes < 12 {
                return Err(CaseError::Corrupt);
            }
            let mut h = [0u8; 12];
            io(e.file.read_exact(&mut h))?;
            let len =
                u32::from_le_bytes(h[..4].try_into().map_err(|_| CaseError::Corrupt)?) as usize;
            if crc32fast::hash(&h[..8]).to_le_bytes() != h[8..]
                || len == 0
                || len > e.config.max_record_bytes
                || len as u64 + 12 > witness.end - e.bytes
            {
                return Err(CaseError::Corrupt);
            }
            let mut data = vec![0; len];
            io(e.file.read_exact(&mut data))?;
            if crc32fast::hash(&data).to_le_bytes() != h[4..8] {
                return Err(CaseError::Corrupt);
            }
            let record: CaseRecord =
                serde_json::from_slice(&data).map_err(|_| CaseError::Corrupt)?;
            e.preflight(&record, data.len()).map_err(|error| {
                if error == CaseError::Capacity {
                    error
                } else {
                    CaseError::Corrupt
                }
            })?;
            e.prefix.update(h);
            e.prefix.update(&data);
            e.bytes += 12 + len as u64;
            e.apply(record, data);
        }
        if e.records.len() != witness.records
            || <[u8; 32]>::from(e.prefix.clone().finalize()) != witness.prefix
        {
            return Err(CaseError::Corrupt);
        }
        check(context)?;
        if physical > witness.end {
            io(e.file.set_len(witness.end))?;
            io(e.file.sync_all())?;
        }
        // Never promote a temporary witness after uncertain replacement.
        let temp = e.config.directory.join("cases.commit.tmp");
        if optional_private(&temp)? {
            io(fs::remove_file(temp))?;
        }
        if !commit.exists() {
            e.witness(&witness, context, None)?;
        }
        e.paths(context)?;
        check(context)?;
        Ok(e)
    }
    fn paths(&self, context: &FindingContext) -> Result<(), CaseError> {
        let root = private(&self.config.directory, true)?;
        let m = private(&self.config.directory.join("cases.journal"), false)?;
        let fd = io(self.file.metadata())?;
        let lock = private(&self.config.directory.join(".lock"), false)?;
        let owned_lock = io(self._lock.metadata())?;
        if (root.dev(), root.ino()) != self.root_identity
            || (m.dev(), m.ino()) != (fd.dev(), fd.ino())
            || (lock.dev(), lock.ino()) != (owned_lock.dev(), owned_lock.ino())
            || fd.len() != self.bytes
        {
            return Err(CaseError::Corrupt);
        }
        let commit = self.config.directory.join("cases.commit");
        let meta = private(&commit, false)?;
        if meta.len() > 1024 {
            return Err(CaseError::Corrupt);
        }
        let bytes = io(fs::read(commit))?;
        let witness: Witness = serde_json::from_slice(&bytes).map_err(|_| CaseError::Corrupt)?;
        let expected: [u8; 32] = self.prefix.clone().finalize().into();
        if witness.schema_version != CASE_SCHEMA_VERSION
            || witness.namespace != self.namespace
            || witness.end != self.bytes
            || witness.records != self.records.len()
            || witness.prefix != expected
        {
            return Err(CaseError::Corrupt);
        }
        let mut file = io(self.file.try_clone())?;
        io(file.seek(SeekFrom::Start(0)))?;
        let mut remaining = self.bytes;
        let mut hash = Sha256::new();
        let mut chunk = [0u8; 8192];
        while remaining > 0 {
            check(context)?;
            let length = remaining.min(chunk.len() as u64) as usize;
            io(file.read_exact(&mut chunk[..length]))?;
            hash.update(&chunk[..length]);
            remaining -= length as u64;
        }
        if <[u8; 32]>::from(hash.finalize()) != expected {
            return Err(CaseError::Corrupt);
        }
        check(context)
    }
    fn preflight(&self, record: &CaseRecord, len: usize) -> Result<(), CaseError> {
        record.validate_after(self.heads.get(&record.head.case_id))?;
        if self.operations.contains_key(&record.request.operation_id) {
            return Err(CaseError::Corrupt);
        }
        if self.records.len() >= self.config.max_operations
            || (!self.heads.contains_key(&record.head.case_id)
                && self.heads.len() >= self.config.max_cases)
            || len > self.config.max_record_bytes
            || self.bytes + len as u64 + 12 > self.config.max_disk_bytes
            || self.charge + len * 8 + 4096 > self.config.max_state_bytes
        {
            return Err(CaseError::Capacity);
        }
        Ok(())
    }
    fn apply(&mut self, record: CaseRecord, data: Vec<u8>) {
        self.charge += data.len() * 8 + 4096;
        self.heads.insert(record.head.case_id, record.head.clone());
        self.operations
            .insert(record.request.operation_id, self.records.len());
        self.records.push((record, data));
    }
    fn witness(
        &self,
        witness: &Witness,
        context: &FindingContext,
        authority: Option<&CaseAuthority>,
    ) -> Result<(), CaseError> {
        let temp = self.config.directory.join("cases.commit.tmp");
        let data = serde_json::to_vec(witness).map_err(|_| CaseError::Corrupt)?;
        let mut f = io(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp))?;
        io(f.write_all(&data))?;
        io(f.sync_all())?;
        check(context)?;
        if let Some(authority) = authority {
            authority.check()?;
        }
        io(fs::rename(temp, self.config.directory.join("cases.commit")))?;
        io(io(File::open(&self.config.directory))?.sync_all())?;
        Ok(())
    }
    fn record(
        &mut self,
        authority: &CaseAuthority,
        request: CaseRequest,
        context: &FindingContext,
    ) -> Result<CaseReceipt, CaseError> {
        self.paths(context)?;
        request.validate()?;
        if let Some(index) = self.operations.get(&request.operation_id) {
            let (record, _) = &self.records[*index];
            authority.authorize(
                self.namespace,
                record.head.case_id,
                &record.head.references,
                Some(&request),
            )?;
            if record.request != request || record.actor != authority.actor {
                return Err(CaseError::Conflict);
            }
            check(context)?;
            return Ok(CaseReceipt {
                schema_version: CASE_SCHEMA_VERSION,
                record: record.clone(),
                replayed: true,
            });
        }
        let previous = self.heads.get(&request.case_id);
        let references = match (&request.change, previous) {
            (CaseChange::Create { references, .. }, _) => references,
            (_, Some(head)) => &head.references,
            _ => return Err(CaseError::NotFound),
        };
        authority.authorize(self.namespace, request.case_id, references, Some(&request))?;
        let record = CaseRecord::prepare(request, authority.actor.clone(), previous)?;
        let data = serde_json::to_vec(&record).map_err(|_| CaseError::Invalid)?;
        self.preflight(&record, data.len())?;
        let frame = frame(&data);
        let mut prefix = self.prefix.clone();
        prefix.update(&frame);
        let witness = Witness {
            schema_version: CASE_SCHEMA_VERSION,
            namespace: self.namespace,
            end: self.bytes + frame.len() as u64,
            records: self.records.len() + 1,
            prefix: prefix.clone().finalize().into(),
        };
        check(context)?;
        authority.check()?;
        self.paths(context)?;
        #[cfg(test)]
        test_hook("prepared", &record)?;
        // From here any failure is uncertain and closes this engine until reopen.
        self.failed = true;
        io(self.file.seek(SeekFrom::Start(self.bytes)))?;
        io(self.file.write_all(&frame))?;
        io(self.file.sync_all())?;
        #[cfg(test)]
        test_hook("journaled", &record)?;
        check(context)?;
        authority.check()?;
        self.witness(&witness, context, Some(authority))?;
        #[cfg(test)]
        test_hook("committed", &record)?;
        check(context)?;
        authority.check()?;
        self.bytes = witness.end;
        self.prefix = prefix;
        self.apply(record.clone(), data);
        self.paths(context)?;
        authority.check()?;
        self.failed = false;
        Ok(CaseReceipt {
            schema_version: CASE_SCHEMA_VERSION,
            record,
            replayed: false,
        })
    }
}

#[cfg(test)]
fn test_hook(phase: &str, record: &CaseRecord) -> Result<(), CaseError> {
    if std::env::var("SIGNAL_CASE_CHILD").as_deref() != Ok("1")
        || std::env::var("SIGNAL_CASE_CUT").as_deref() != Ok(phase)
        || record.request.operation_id.as_u128() != 11
    {
        return Ok(());
    }
    let path = PathBuf::from(std::env::var_os("SIGNAL_CASE_OUTPUT").ok_or(CaseError::Invalid)?);
    let mut ready = io(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("intent.tmp")))?;
    io(ready.write_all(&serde_json::to_vec(record).map_err(|_| CaseError::Invalid)?))?;
    io(ready.sync_all())?;
    io(fs::rename(path.join("intent.tmp"), path.join("ready.json")))?;
    io(io(File::open(&path))?.sync_all())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(CaseError::Timeout)
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

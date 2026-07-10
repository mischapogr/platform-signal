//! Real Parquet/DataFusion over bounded committed object copies. In-process only.
use chrono::{DateTime, Utc};
use object_store::{
    GetOptions, GetResult, GetResultPayload, ObjectMeta, ObjectStore, PutOptions, PutPayload,
    PutResult, memory::InMemory, path::Path,
};
use signal_event::IngestEvent;
use signal_protocol::{AttributeFilter, EventQuery};
use signal_query::{QueryConfig, QueryEngine, QueryError};
use signal_storage::{
    OperationContext, StoredEvent,
    object_cache::{MaterializationConfig, prune_stopped_materialization},
    object_io::{ObjectIo, ObjectIoLimits, SmallOwnerConfig},
    object_publication::{ObjectPublisher, PublicationConfig},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
fn time(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}
#[derive(Debug)]
struct Backend {
    inner: InMemory,
    mode: AtomicUsize,
    reads: Mutex<BTreeMap<String, usize>>,
    entered: tokio::sync::Notify,
    gate: tokio::sync::Semaphore,
    physical_gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            inner: InMemory::new(),
            mode: AtomicUsize::new(0),
            reads: Mutex::new(BTreeMap::new()),
            entered: tokio::sync::Notify::new(),
            gate: tokio::sync::Semaphore::new(0),
            physical_gate: Mutex::new(None),
        }
    }
}
impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("finite object query fixture")
    }
}
fn fault() -> object_store::Error {
    object_store::Error::Generic {
        store: "query fixture",
        source: std::io::Error::other("synthetic denial").into(),
    }
}
#[async_trait::async_trait]
impl ObjectStore for Backend {
    async fn put_opts(
        &self,
        path: &Path,
        payload: PutPayload,
        options: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.inner.put_opts(path, payload, options).await
    }
    async fn get_opts(&self, path: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        let data = path.as_ref().ends_with(".parquet");
        if data {
            let mut reads = self.reads.lock().map_err(|_| fault())?;
            if reads.len() >= 128 && !reads.contains_key(path.as_ref()) {
                return Err(fault());
            }
            *reads.entry(path.to_string()).or_default() += 1;
        }
        let mode = self.mode.load(Ordering::Acquire);
        if data && mode == 1 {
            return Err(fault());
        }
        if data && mode == 3 {
            self.entered.notify_one();
            let _permit = self.gate.acquire().await.map_err(|_| fault())?;
        }
        if data && mode == 4 {
            let gate = self
                .physical_gate
                .lock()
                .map_err(|_| fault())?
                .take()
                .ok_or_else(fault)?;
            self.entered.notify_one();
            // Test-only non-cancellable native-call stand-in on physical worker.
            gate.recv_timeout(Duration::from_secs(5))
                .map_err(|_| fault())?;
        }
        let mut result = self.inner.get_opts(path, options).await?;
        if data && mode == 2 {
            if result.meta.size > 1024 * 1024 {
                return Err(fault());
            }
            let bytes = bytes::Bytes::from(vec![b'X'; result.meta.size as usize]);
            // Preserve identity metadata, deliberately violate content immutability.
            result.payload = GetResultPayload::Stream(Box::pin(futures_util::stream::once(
                async move { Ok(bytes) },
            )));
        }
        Ok(result)
    }
    fn list(
        &self,
        prefix: Option<&Path>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }
    async fn put_multipart_opts(
        &self,
        _: &Path,
        _: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        Err(fault())
    }
    fn delete_stream(
        &self,
        _: futures_util::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<Path>> {
        Box::pin(futures_util::stream::once(async { Err(fault()) }))
    }
    async fn list_with_delimiter(
        &self,
        _: Option<&Path>,
    ) -> object_store::Result<object_store::ListResult> {
        Err(fault())
    }
    async fn copy_opts(
        &self,
        _: &Path,
        _: &Path,
        _: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        Err(fault())
    }
}
impl Backend {
    fn clear(&self) -> Result {
        self.reads.lock().map_err(|_| "fixture mutex")?.clear();
        Ok(())
    }
    fn reads(&self) -> Result<BTreeMap<String, usize>> {
        Ok(self.reads.lock().map_err(|_| "fixture mutex")?.clone())
    }
}
struct Fixture {
    root: TempDir,
    owner: SmallOwnerConfig,
    backend: Arc<Backend>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = TempDir::new()?;
        let owner = SmallOwnerConfig {
            directory: root.path().join("publication"),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        Ok(Self {
            root,
            owner,
            backend: Arc::new(Backend {
                gate: tokio::sync::Semaphore::new(0),
                ..Default::default()
            }),
        })
    }
    fn cache(&self) -> std::path::PathBuf {
        self.root.path().join("derived")
    }
    async fn open(&self, files: usize, bytes: u64) -> Result<Arc<ObjectPublisher>> {
        let io = ObjectIo::open_small_remote(
            &self.owner,
            self.backend.clone(),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
            context(),
        )
        .await?;
        Ok(Arc::new(ObjectPublisher::new(
            io,
            tokio::runtime::Handle::current(),
            PublicationConfig {
                materialization: Some(MaterializationConfig {
                    directory: self.cache(),
                    max_files: files,
                    max_disk_bytes: bytes,
                }),
                ..Default::default()
            },
        )?))
    }
}
fn rows() -> Result<Vec<StoredEvent>> {
    ["2026-07-10T19:30:00.000000001Z","2026-07-10T20:30:00Z"].into_iter().enumerate().map(|(i,timestamp)| {
        let input:IngestEvent=serde_json::from_value(serde_json::json!({"id":Uuid::from_u128(i as u128+1),"timestamp":timestamp,"source":{"type":"application","name":"fixture"},"severity":"error","message":"exact object query","attributes":{"user":{"active":true},"nested":[{"x":1},null]},"resource":{"kind":"host","id":"synthetic-node","account_id":"synthetic-account"}}))?;
        Ok(StoredEvent {sequence:7+i as u64*2,event:input.normalize(time("2026-07-10T21:00:00Z")?)?})
    }).collect()
}
fn first_hour() -> Result<EventQuery> {
    Ok(EventQuery {
        from: Some(time("2026-07-10T19:00:00Z")?),
        to: Some(time("2026-07-10T20:00:00Z")?),
        ..Default::default()
    })
}
#[tokio::test]
async fn object_queries_prune_before_data_get_and_rebuild_after_derived_root_deletion() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    let rows = rows()?;
    writer.append(&rows, context()).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), writer.clone())?;
    fixture.backend.clear()?;
    let mut query = first_hour()?;
    query.account = Some("synthetic-account".into());
    query.source_name = Some("fixture".into());
    query.attributes = vec![AttributeFilter {
        path: "user.active".into(),
        value: serde_json::json!(true),
    }];
    let response = engine.execute(query.clone(), context()).await?;
    assert_eq!(response.events, vec![rows[0].event.clone()]);
    assert_eq!(
        (
            response.metadata.scanned_files,
            response.metadata.candidate_partitions
        ),
        (1, 1)
    );
    let reads = fixture.backend.reads()?;
    assert_eq!(reads.len(), 1);
    assert!(reads.keys().all(|key| key.contains("hour=19/")));
    assert_eq!(
        std::fs::read_dir(fixture.cache().join("objects"))?.count(),
        1
    );
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    drop(engine);
    drop(writer);
    std::fs::remove_dir_all(fixture.cache())?;
    let reopened = fixture.open(16, 8 * 1024 * 1024).await?;
    let query_engine = QueryEngine::with_source(QueryConfig::default(), reopened.clone())?;
    assert_eq!(
        query_engine.execute(query, context()).await?.events,
        vec![rows[0].event.clone()]
    );
    assert_eq!(
        reopened.append(&rows[..1], context()).await?.replay_count,
        1
    );
    query_engine.shutdown(context()).await?;
    reopened.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn selected_file_and_decoded_limits_reject_before_data_get() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    writer.append(&rows()?, context()).await?;
    for config in [
        QueryConfig {
            max_files: 1,
            ..Default::default()
        },
        QueryConfig {
            memory_bytes: 1,
            ..Default::default()
        },
    ] {
        fixture.backend.clear()?;
        let engine = QueryEngine::with_source(config, writer.clone())?;
        assert_eq!(
            engine.execute(EventQuery::default(), context()).await.err(),
            Some(QueryError::Resource)
        );
        assert!(fixture.backend.reads()?.is_empty());
        assert!(!fixture.cache().exists());
        engine.shutdown(context()).await?;
    }
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn data_denial_or_same_identity_corruption_never_returns_empty_success() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    let rows = rows()?;
    writer.append(&rows, context()).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), writer.clone())?;
    for mode in [1, 2] {
        fixture.backend.mode.store(mode, Ordering::Release);
        assert_eq!(
            engine.execute(first_hour()?, context()).await.err(),
            Some(QueryError::Unavailable)
        );
        assert_eq!(writer.metrics().high_water, 9);
    }
    fixture.backend.mode.store(0, Ordering::Release);
    assert_eq!(
        engine.execute(first_hour()?, context()).await?.events,
        vec![rows[0].event.clone()]
    );
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn corrupted_derived_copy_is_preserved_and_stopped_rebuild_restores_query() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    let rows = rows()?;
    writer.append(&rows, context()).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), writer.clone())?;
    engine.execute(first_hour()?, context()).await?;
    let path = std::fs::read_dir(fixture.cache().join("objects"))?
        .next()
        .ok_or("derived file")??
        .path();
    let mut bytes = std::fs::read(&path)?;
    bytes[0] ^= 1;
    std::fs::write(&path, &bytes)?;
    assert_eq!(
        engine.execute(first_hour()?, context()).await.err(),
        Some(QueryError::Unavailable)
    );
    assert_eq!(std::fs::read(&path)?, bytes);
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    drop(engine);
    drop(writer);
    assert_eq!(prune_fixture(&fixture, 16)?.removed_files, 1);
    let reopened = fixture.open(16, 8 * 1024 * 1024).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), reopened.clone())?;
    assert_eq!(
        engine.execute(first_hour()?, context()).await?.events,
        vec![rows[0].event.clone()]
    );
    engine.shutdown(context()).await?;
    reopened.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn cache_file_quota_is_finite_and_does_not_evict_previous_reader_files() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(1, 8 * 1024 * 1024).await?;
    let rows = rows()?;
    writer.append(&rows, context()).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), writer.clone())?;
    engine.execute(first_hour()?, context()).await?;
    assert_eq!(
        engine.execute(EventQuery::default(), context()).await.err(),
        Some(QueryError::Resource)
    );
    assert_eq!(
        std::fs::read_dir(fixture.cache().join("objects"))?.count(),
        1
    );
    assert_eq!(
        engine.execute(first_hour()?, context()).await?.events,
        vec![rows[0].event.clone()]
    );
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn cancelled_object_get_drains_physical_admission_and_next_query_recovers() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    writer.append(&rows()?, context()).await?;
    let engine = Arc::new(QueryEngine::with_source(
        QueryConfig::default(),
        writer.clone(),
    )?);
    fixture.backend.mode.store(3, Ordering::Release);
    let ctx = context();
    let cancel = ctx.cancellation.clone();
    let front = engine.clone();
    let query = first_hour()?;
    let pending = tokio::spawn(async move { front.execute(query, ctx).await });
    tokio::time::timeout(Duration::from_secs(3), fixture.backend.entered.notified()).await?;
    assert_eq!(writer.metrics().depth, 1);
    cancel.cancel();
    assert_eq!(pending.await?.err(), Some(QueryError::Cancelled));
    tokio::time::timeout(Duration::from_secs(3), async {
        while writer.metrics().depth != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    fixture.backend.mode.store(0, Ordering::Release);
    assert_eq!(
        engine.execute(first_hour()?, context()).await?.events.len(),
        1
    );
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn noncancellable_child_keeps_parent_admission_and_owner_after_front_timeout() -> Result {
    struct Release(Option<std::sync::mpsc::SyncSender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.try_send(());
            }
        }
    }
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    writer.append(&rows()?, context()).await?;
    let engine = Arc::new(QueryEngine::with_source(
        QueryConfig::default(),
        writer.clone(),
    )?);
    let (release, gate) = std::sync::mpsc::sync_channel(1);
    let release = Release(Some(release));
    *fixture
        .backend
        .physical_gate
        .lock()
        .map_err(|_| "fixture mutex")? = Some(gate);
    fixture.backend.mode.store(4, Ordering::Release);
    let ctx = context();
    let cancel = ctx.cancellation.clone();
    let front = engine.clone();
    let query = first_hour()?;
    let pending = tokio::spawn(async move { front.execute(query, ctx).await });
    tokio::time::timeout(Duration::from_secs(3), fixture.backend.entered.notified()).await?;
    cancel.cancel();
    assert_eq!(pending.await?.err(), Some(QueryError::Cancelled));
    assert_eq!(writer.metrics().depth, 1);
    assert_eq!(
        engine.execute(first_hour()?, context()).await.err(),
        Some(QueryError::Busy)
    );
    engine.shutdown(context()).await?;
    assert!(matches!(
        writer
            .shutdown(OperationContext::new(Duration::from_millis(20)))
            .await,
        Err(signal_storage::StorageError::Timeout)
    ));
    assert_eq!(writer.metrics().depth, 1);
    assert!(matches!(
        fixture
            .open(16, 8 * 1024 * 1024)
            .await
            .err()
            .and_then(|e| e
                .downcast::<signal_storage::object_io::ObjectIoError>()
                .ok())
            .as_deref(),
        Some(signal_storage::object_io::ObjectIoError::OwnerLocked)
    ));
    drop(release);
    writer.shutdown(context()).await?;
    fixture.backend.mode.store(0, Ordering::Release);
    drop(engine);
    drop(writer);
    let reopened = fixture.open(16, 8 * 1024 * 1024).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), reopened.clone())?;
    assert_eq!(
        engine.execute(first_hour()?, context()).await?.events.len(),
        1
    );
    engine.shutdown(context()).await?;
    reopened.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn shutdown_waits_for_remote_selection_under_original_deadline() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(16, 8 * 1024 * 1024).await?;
    writer.append(&rows()?, context()).await?;
    let engine = Arc::new(QueryEngine::with_source(
        QueryConfig::default(),
        writer.clone(),
    )?);
    fixture.backend.mode.store(3, Ordering::Release);
    let ctx = context();
    let cancel = ctx.cancellation.clone();
    let front = engine.clone();
    let query = first_hour()?;
    let pending = tokio::spawn(async move { front.execute(query, ctx).await });
    tokio::time::timeout(Duration::from_secs(3), fixture.backend.entered.notified()).await?;
    assert_eq!(engine.metrics().depth, 1);
    assert_eq!(engine.metrics().io_depth, 0);
    let result = engine
        .shutdown(OperationContext::new(Duration::from_millis(20)))
        .await;
    // Clean up even on the red reproduction: no fixture/request is detached.
    cancel.cancel();
    assert_eq!(pending.await?.err(), Some(QueryError::Cancelled));
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    assert_eq!(result.err(), Some(QueryError::Timeout));
    Ok(())
}

// Maintenance uses one ordinary scoped worker, outside the query I/O pool.
fn prune_fixture(
    fixture: &Fixture,
    files: usize,
) -> Result<signal_storage::object_cache::MaterializationPrune> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                prune_stopped_materialization(
                    &MaterializationConfig {
                        directory: fixture.cache(),
                        max_files: files,
                        max_disk_bytes: 8 * 1024 * 1024,
                    },
                    fixture.owner.stream_id,
                    fixture.owner.backend_id,
                    &context(),
                )
            })
            .join()
            .map_err(|_| "maintenance worker panicked")?
            .map_err(Into::into)
    })
}
#[tokio::test]
async fn stopped_cache_prune_recovers_quota_without_changing_committed_events() -> Result {
    let fixture = Fixture::new()?;
    let writer = fixture.open(1, 8 * 1024 * 1024).await?;
    let rows = rows()?;
    writer.append(&rows, context()).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), writer.clone())?;
    assert_eq!(
        engine.execute(first_hour()?, context()).await?.events,
        vec![rows[0].event.clone()]
    );
    let mut second_hour = first_hour()?;
    second_hour.from = Some(time("2026-07-10T20:00:00Z")?);
    second_hour.to = Some(time("2026-07-10T21:00:00Z")?);
    assert_eq!(
        engine.execute(second_hour.clone(), context()).await.err(),
        Some(QueryError::Resource)
    );
    assert!(matches!(
        prune_fixture(&fixture, 1)
            .err()
            .and_then(|e| e.downcast::<signal_storage::StorageError>().ok())
            .as_deref(),
        Some(signal_storage::StorageError::Locked)
    ));
    let binding = std::fs::read(fixture.cache().join("control/binding.json"))?;
    engine.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    // Explicit shutdown leaves the immutable source lifetime protected.
    assert!(prune_fixture(&fixture, 1).is_err());
    drop(engine);
    drop(writer);
    let pruned = prune_fixture(&fixture, 1)?;
    assert_eq!(pruned.removed_files, 1);
    assert!(pruned.removed_bytes > 0);
    assert_eq!(
        std::fs::read(fixture.cache().join("control/binding.json"))?,
        binding
    );
    let reopened = fixture.open(1, 8 * 1024 * 1024).await?;
    let engine = QueryEngine::with_source(QueryConfig::default(), reopened.clone())?;
    assert_eq!(
        engine.execute(second_hour, context()).await?.events,
        vec![rows[1].event.clone()]
    );
    assert_eq!(reopened.metrics().high_water, 9);
    assert_eq!(
        reopened.append(&rows[..1], context()).await?.replay_count,
        1
    );
    assert_eq!(
        std::fs::read_dir(fixture.cache().join("objects"))?.count(),
        1
    );
    engine.shutdown(context()).await?;
    reopened.shutdown(context()).await?;
    Ok(())
}

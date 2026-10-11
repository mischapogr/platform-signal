use super::*;
use crate::StoredEvent;
use crate::object_io::ObjectIoLimits;
use crate::object_manifest::{PreviousManifest, QueryFile, QueryObjectRef, data_key, manifest_key};
use object_store::local::LocalFileSystem;
use signal_event::IngestEvent;
use tempfile::TempDir;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(std::time::Duration::from_secs(5))
}
fn bounds() -> SelectionBounds {
    SelectionBounds {
        from: None,
        to: None,
        max_files: 128,
        max_decoded_bytes: 256 * 1024 * 1024,
    }
}
fn config(cache: &TempDir) -> SelectionConfig {
    SelectionConfig {
        stream: Uuid::from_u128(1),
        backend: Uuid::from_u128(2),
        storage: StorageConfig::default(),
        manifests: ManifestLimits::default(),
        cache: MaterializationConfig {
            directory: cache.path().join("derived"),
            max_files: 128,
            max_disk_bytes: 64 * 1024 * 1024,
        },
    }
}
async fn fixture(root: &TempDir, cache: &TempDir) -> Result<(ObjectSelection, Vec<u8>)> {
    let config = config(cache);
    let io = ObjectIo::local(
        LocalFileSystem::new_with_prefix(root.path())?,
        ObjectIoLimits::default(),
    )?;
    let codec = ObjectCodec::new(config.storage.clone(), config.manifests)?;
    let mut rows = Vec::new();
    for (i, time) in ["2026-10-10T10:00:00Z", "2026-10-10T11:00:00Z"]
        .iter()
        .enumerate()
    {
        let event: IngestEvent = serde_json::from_value(
            serde_json::json!({"timestamp":time,"source":{"type":"synthetic"},"message":format!("selected-{i}"),"attributes":{"nested":{"array":[true,null,42]}}}),
        )?;
        rows.push(StoredEvent {
            sequence: i as u64 + 1,
            event: event.normalize(Utc::now())?,
        });
    }
    let batch = codec.prepare(&rows, context()).await?;
    let mut files = Vec::new();
    for prepared in batch.files() {
        let reference = io
            .create(
                &data_key(
                    config.stream,
                    prepared.date(),
                    prepared.hour(),
                    prepared.sha256(),
                ),
                prepared.bytes(),
                context(),
            )
            .await?;
        files.push(QueryFile {
            date: prepared.date().into(),
            hour: prepared.hour(),
            object: reference,
            rows: prepared.rows(),
            decoded_bytes: prepared.decoded_bytes(),
        });
    }
    drop(batch);
    codec.shutdown(context()).await?;
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: config.stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: 1,
        last_sequence: 2,
        events: 2,
        previous: None,
        files,
    };
    let bytes = manifest.encode(config.manifests, config.stream)?;
    Ok((
        ObjectSelection::new(io, tokio::runtime::Handle::current(), config)?,
        bytes,
    ))
}
#[tokio::test]
async fn actual_parquet_pruning_and_returned_selection_retain_capacity_and_cache_owner() -> Result {
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let (reader, bytes) = fixture(&root, &cache).await?;
    let b = SelectionBounds {
        from: Some("2026-10-10T10:00:00Z".parse()?),
        to: Some("2026-10-10T10:59:59Z".parse()?),
        ..bounds()
    };
    let selected = reader.materialize(&[&bytes], b, context()).await?;
    assert_eq!((selected.files.len(), selected.partitions), (1, 1));
    assert_eq!(selected.files[0].rows, 1);
    assert!(selected.files[0].path.is_file());
    assert_eq!(reader.metrics().depth, 1);
    assert!(matches!(
        reader.materialize(&[&bytes], bounds(), context()).await,
        Err(StorageError::Busy)
    ));
    let copy = selected.clone();
    reader.shutdown(context()).await?;
    drop(reader);
    // Actual exclusive cache lock remains after source shutdown and first clone drop.
    drop(selected);
    assert!(matches!(
        Cache::open(
            &config(&cache).cache,
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            &context()
        ),
        Err(StorageError::Locked)
    ));
    drop(copy);
    drop(Cache::open(
        &config(&cache).cache,
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        &context(),
    )?);
    Ok(())
}
#[tokio::test]
async fn corrupt_or_missing_exact_objects_and_finite_budgets_never_return_partial_files() -> Result
{
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let (reader, bytes) = fixture(&root, &cache).await?;
    assert!(matches!(
        reader
            .materialize(
                &[&bytes],
                SelectionBounds {
                    max_files: 1,
                    ..bounds()
                },
                context()
            )
            .await,
        Err(StorageError::Full)
    ));
    assert!(matches!(
        reader
            .materialize(
                &[&bytes],
                SelectionBounds {
                    max_decoded_bytes: 1,
                    ..bounds()
                },
                context()
            )
            .await,
        Err(StorageError::Full)
    ));
    let mut manifest: QueryManifest = serde_json::from_slice(&bytes)?;
    manifest.files[1].object.sha256 = [7; 32];
    manifest.files[1].object.key = data_key(
        manifest.stream_id,
        &manifest.files[1].date,
        manifest.files[1].hour,
        [7; 32],
    );
    let missing = manifest.encode(ManifestLimits::default(), manifest.stream_id)?;
    assert!(matches!(
        reader.materialize(&[&missing], bounds(), context()).await,
        Err(StorageError::ObjectIo(ObjectIoError::NotFound))
    ));
    // A prior successful file may be cached, but a failed aggregate never escapes.
    let mut changed: QueryManifest = serde_json::from_slice(&bytes)?;
    changed.files[0].rows += 1;
    changed.events += 1;
    // Keep structural span valid while actual decoded Parquet rows disagree.
    changed.last_sequence = 3;
    let changed = changed.encode(ManifestLimits::default(), changed.stream_id)?;
    assert!(matches!(
        reader.materialize(&[&changed], bounds(), context()).await,
        Err(StorageError::Corrupt(_))
    ));
    let selected = reader.materialize(&[&bytes], bounds(), context()).await?;
    assert_eq!(selected.files.len(), 2);
    drop(selected);
    assert_eq!(reader.metrics().depth, 0);
    assert_eq!(reader.metrics().rejected, 4);
    reader.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn empty_and_populated_snapshots_keep_original_finite_deadline() -> Result {
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let (reader, bytes) = fixture(&root, &cache).await?;
    let original = Instant::now() + std::time::Duration::from_millis(1000);
    let mut ctx = context();
    ctx.deadline = original;
    let selected = reader.materialize(&[&bytes], bounds(), ctx).await?;
    assert_eq!(selected.deadline(), Some(original));
    tokio::time::sleep_until(original).await;
    assert!(matches!(
        selected.check_lifetime(),
        Err(StorageError::Timeout)
    ));
    drop(selected);
    let mut ctx = context();
    ctx.deadline = Instant::now() + std::time::Duration::from_millis(1000);
    let empty = reader.materialize(&[], bounds(), ctx.clone()).await?;
    assert!(empty.files.is_empty());
    assert_eq!(empty.deadline(), Some(ctx.deadline));
    tokio::time::sleep_until(ctx.deadline).await;
    assert!(matches!(empty.check_lifetime(), Err(StorageError::Timeout)));
    drop(empty);
    let mut expired = context();
    expired.deadline = Instant::now();
    assert!(matches!(
        reader.materialize(&[], bounds(), expired).await,
        Err(StorageError::Timeout)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        reader.materialize(&[&bytes], bounds(), cancelled).await,
        Err(StorageError::Cancelled)
    ));
    reader.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn complete_chain_and_stream_are_checked_before_object_reads() -> Result {
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let (reader, bytes) = fixture(&root, &cache).await?;
    let mut second: QueryManifest = serde_json::from_slice(&bytes)?;
    second.first_sequence = 3;
    second.last_sequence = 4;
    second.previous = Some(PreviousManifest {
        first_sequence: 1,
        last_sequence: 2,
        object: QueryObjectRef {
            key: manifest_key(second.stream_id, 1),
            version: Some("synthetic-v1".into()),
            etag: None,
            bytes: bytes.len() as u64,
            sha256: [9; 32],
        },
    });
    let second = second.encode(ManifestLimits::default(), second.stream_id)?;
    assert!(matches!(
        reader
            .materialize(&[&bytes, &second], bounds(), context())
            .await,
        Err(StorageError::Corrupt("selected predecessor"))
    ));
    assert!(!config(&cache).cache.directory.exists());
    let mut foreign: QueryManifest = serde_json::from_slice(&bytes)?;
    foreign.stream_id = Uuid::new_v4();
    let foreign = serde_json::to_vec(&foreign)?;
    assert!(matches!(
        reader.materialize(&[&foreign], bounds(), context()).await,
        Err(StorageError::Corrupt("selected manifest binding"))
    ));
    assert!(!config(&cache).cache.directory.exists());
    reader.shutdown(context()).await?;
    Ok(())
}

#[derive(Debug)]
struct StalledStore {
    inner: LocalFileSystem,
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl std::fmt::Display for StalledStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned stalled read fixture")
    }
}
fn fault() -> object_store::Error {
    object_store::Error::Generic {
        store: "selection fixture",
        source: std::io::Error::other("fixture channel").into(),
    }
}
#[async_trait::async_trait]
impl object_store::ObjectStore for StalledStore {
    async fn get_opts(
        &self,
        path: &object_store::path::Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        let entered = self.entered.lock().map_err(|_| fault())?.take();
        if let Some(entered) = entered {
            let _ = entered.send(());
            // Deliberately non-cancellable physical syscall stand-in on the
            // dedicated I/O worker, never on a Tokio runtime worker.
            self.release
                .lock()
                .map_err(|_| fault())?
                .recv()
                .map_err(|_| fault())?;
        }
        let result = self.inner.get_opts(path, options).await?;
        let meta = result.meta.clone();
        let range = result.range.clone();
        let attributes = result.attributes.clone();
        let extensions = result.extensions.clone();
        let bytes = result.bytes().await?;
        Ok(object_store::GetResult {
            payload: object_store::GetResultPayload::Stream(Box::pin(futures_util::stream::once(
                async { Ok(bytes) },
            ))),
            meta,
            range,
            attributes,
            extensions,
        })
    }
    async fn put_opts(
        &self,
        p: &object_store::path::Path,
        b: object_store::PutPayload,
        o: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.inner.put_opts(p, b, o).await
    }
    async fn put_multipart_opts(
        &self,
        p: &object_store::path::Path,
        o: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(p, o).await
    }
    fn list(
        &self,
        p: Option<&object_store::path::Path>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
    {
        self.inner.list(p)
    }
    fn delete_stream(
        &self,
        s: futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>
    {
        self.inner.delete_stream(s)
    }
    async fn list_with_delimiter(
        &self,
        p: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        self.inner.list_with_delimiter(p).await
    }
    async fn copy_opts(
        &self,
        a: &object_store::path::Path,
        b: &object_store::path::Path,
        o: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(a, b, o).await
    }
}
#[tokio::test]
async fn caller_timeout_holds_parent_capacity_until_physical_read_drains() -> Result {
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let (initial, bytes) = fixture(&root, &cache).await?;
    initial.shutdown(context()).await?;
    drop(initial);
    let (entered, receive) = oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let backend = Arc::new(StalledStore {
        inner: LocalFileSystem::new_with_prefix(root.path())?,
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(wait),
    });
    let io = ObjectIo::remote(
        backend,
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?;
    let reader = Arc::new(ObjectSelection::new(
        io,
        tokio::runtime::Handle::current(),
        config(&cache),
    )?);
    let child = reader.clone();
    let input = bytes.clone();
    let request = tokio::spawn(async move {
        let mut ctx = context();
        ctx.deadline = Instant::now() + std::time::Duration::from_millis(500);
        child.materialize(&[&input], bounds(), ctx).await
    });
    timeout_at(Instant::now() + std::time::Duration::from_secs(2), receive).await??;
    assert!(matches!(request.await?, Err(StorageError::Timeout)));
    assert_eq!((reader.metrics().depth, reader.metrics().running), (1, 1));
    assert!(matches!(
        reader.materialize(&[&bytes], bounds(), context()).await,
        Err(StorageError::Busy)
    ));
    // Owned release guard ensures a failed assertion cannot strand the fixture.
    release.send(())?;
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    while reader.metrics().depth != 0 {
        if Instant::now() >= deadline {
            return Err("physical child did not drain".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let selected = reader.materialize(&[&bytes], bounds(), context()).await?;
    assert_eq!(selected.files.len(), 2);
    drop(selected);
    reader.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn derived_disk_quota_holds_whole_selection_and_stopped_reopen_reuses_only_verified_copies()
-> Result {
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let (initial, bytes) = fixture(&root, &cache).await?;
    initial.shutdown(context()).await?;
    drop(initial);
    let mut limited = config(&cache);
    limited.cache.max_files = 1;
    let reader = ObjectSelection::new(
        ObjectIo::local(
            LocalFileSystem::new_with_prefix(root.path())?,
            ObjectIoLimits::default(),
        )?,
        tokio::runtime::Handle::current(),
        limited,
    )?;
    assert!(matches!(
        reader.materialize(&[&bytes], bounds(), context()).await,
        Err(StorageError::Full)
    ));
    assert_eq!(
        std::fs::read_dir(config(&cache).cache.directory.join("objects"))?.count(),
        1
    );
    reader.shutdown(context()).await?;
    drop(reader);
    let reader = ObjectSelection::new(
        ObjectIo::local(
            LocalFileSystem::new_with_prefix(root.path())?,
            ObjectIoLimits::default(),
        )?,
        tokio::runtime::Handle::current(),
        config(&cache),
    )?;
    let selected = reader.materialize(&[&bytes], bounds(), context()).await?;
    assert_eq!(selected.files.len(), 2);
    drop(selected);
    reader.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn failed_retained_selection_keeps_physical_children_for_host_cleanup() -> Result {
    let root = TempDir::new()?;
    let cache = TempDir::new()?;
    let cfg = config(&cache);
    let io = Arc::new(ObjectIo::local(
        LocalFileSystem::new_with_prefix(root.path())?,
        ObjectIoLimits::default(),
    )?);
    let codec = Arc::new(ObjectCodec::new(cfg.storage.clone(), cfg.manifests)?);
    let mut invalid = cfg.clone();
    invalid.cache.max_files = 0;
    assert!(
        ObjectSelection::with_workers(
            io.clone(),
            codec.clone(),
            tokio::runtime::Handle::current(),
            invalid
        )
        .is_err()
    );
    let mut mismatched = cfg.clone();
    mismatched.storage.max_files += 1;
    assert!(matches!(
        ObjectSelection::with_workers(
            io.clone(),
            codec.clone(),
            tokio::runtime::Handle::current(),
            mismatched
        ),
        Err(StorageError::Config("selection retained worker binding"))
    ));
    assert!(!io.metrics().closed);
    assert!(!codec.metrics().closed);
    assert_eq!(Arc::strong_count(&io), 1);
    assert_eq!(Arc::strong_count(&codec), 1);
    let selection = ObjectSelection::with_workers(
        io.clone(),
        codec.clone(),
        tokio::runtime::Handle::current(),
        cfg,
    )?;
    selection.shutdown(context()).await?;
    // Child handles remain usable for explicit idempotent host shutdown.
    codec.shutdown(context()).await?;
    io.shutdown(context()).await?;
    assert!(codec.metrics().closed);
    assert!(io.metrics().closed);
    Ok(())
}

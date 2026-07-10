use super::*;
use crate::object_io::{ObjectIoLimits, SmallOwnerConfig};
use object_store::{ObjectStore, ObjectStoreExt, memory::InMemory};
use signal_event::IngestEvent;
use tempfile::TempDir;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn versionless_inventory_requires_matching_nonempty_etag_and_retains_pin() -> Result {
    let pinned = QueryObjectRef {
        key: "query/test/data/pin.parquet".into(),
        version: Some("pinned-v1".into()),
        etag: Some("nonempty-etag".into()),
        bytes: 9,
        sha256: [1; 32],
    };
    let mut listed = pinned.clone();
    listed.version = None;
    check_inventory_identity(&[listed.clone()], &pinned)?;
    assert_eq!(pinned.version.as_deref(), Some("pinned-v1"));
    for drift in [
        QueryObjectRef {
            etag: None,
            ..listed.clone()
        },
        QueryObjectRef {
            etag: Some("changed".into()),
            ..listed.clone()
        },
        QueryObjectRef {
            bytes: 10,
            ..listed.clone()
        },
        QueryObjectRef {
            version: Some("wrong-version".into()),
            ..listed.clone()
        },
    ] {
        assert!(check_inventory_identity(&[drift], &pinned).is_err());
    }
    let no_etag = QueryObjectRef {
        etag: None,
        ..pinned
    };
    let no_version_or_etag = QueryObjectRef {
        version: None,
        ..no_etag.clone()
    };
    assert!(check_inventory_identity(&[no_version_or_etag], &no_etag).is_err());
    Ok(())
}
fn context() -> OperationContext {
    OperationContext::new(std::time::Duration::from_secs(5))
}
fn rows() -> Result<Vec<StoredEvent>> {
    ["2026-07-10T19:30:00Z", "2026-07-10T20:30:00Z", "2026-07-10T20:31:00Z"].into_iter().enumerate().map(|(i, timestamp)| {
        let input: IngestEvent = serde_json::from_value(serde_json::json!({"timestamp": timestamp, "source":{"type":"synthetic"}, "message":"query copy", "attributes":{"native":{"nested":[1, true, null]}}}))?;
        Ok(StoredEvent { sequence: 7 + i as u64 * 2, event: input.normalize(chrono::Utc::now())? })
    }).collect()
}
fn owner(control: &TempDir) -> SmallOwnerConfig {
    SmallOwnerConfig {
        directory: control.path().to_path_buf(),
        stream_id: Uuid::new_v4(),
        backend_id: Uuid::new_v4(),
    }
}
async fn publisher(
    owner: &SmallOwnerConfig,
    backend: Arc<dyn ObjectStore>,
    config: PublicationConfig,
) -> Result<ObjectPublisher> {
    let io = ObjectIo::open_small_remote(
        owner,
        backend,
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    Ok(ObjectPublisher::new(
        io,
        tokio::runtime::Handle::current(),
        config,
    )?)
}
#[tokio::test]
async fn actual_publication_replay_split_restart_and_snapshot_lease() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let rows = rows()?;
    let first = writer.append(&rows[..2], context()).await?;
    assert_eq!(
        (
            first.first_sequence,
            first.last_sequence,
            first.new_count,
            first.replay_count
        ),
        (7, 9, 2, 0)
    );
    let second = writer.append(&rows[1..], context()).await?;
    assert_eq!(
        (second.last_sequence, second.new_count, second.replay_count),
        (11, 1, 1)
    );
    let snapshot = writer.snapshot(context()).await?;
    assert_eq!(snapshot.manifests().len(), 2);
    assert!(snapshot.orphans().is_empty());
    assert_eq!(
        snapshot.manifests()[1].manifest.previous.as_ref(),
        Some(&snapshot.manifests()[0].reference)
    );
    assert_eq!(writer.metrics().depth, 1);
    assert!(matches!(
        writer.append(&rows, context()).await,
        Err(StorageError::Busy)
    ));
    drop(snapshot);
    writer.shutdown(context()).await?;
    let reopened = publisher(&owner, backend, PublicationConfig::default()).await?;
    let replay = reopened.append(&rows, context()).await?;
    assert_eq!(
        (replay.last_sequence, replay.new_count, replay.replay_count),
        (11, 0, 3)
    );
    let mut conflict = rows.clone();
    conflict[0].event.message = Some("different admitted event".into());
    assert!(matches!(
        reopened.append(&conflict, context()).await,
        Err(StorageError::InvalidBatch)
    ));
    assert_eq!(reopened.metrics().high_water, 11);
    reopened.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn missing_head_requires_exact_initial_wal_reconciliation() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let rows = rows()?;
    writer.append(&rows[..2], context()).await?;
    writer.shutdown(context()).await?;
    // Simulate process interruption after manifest creation but before any local
    // head witness, by removing only this test's owned witness.
    std::fs::remove_file(control.path().join("head.json"))?;
    std::fs::remove_file(control.path().join("genesis.json"))?;
    let recovered = publisher(&owner, backend, PublicationConfig::default()).await?;
    assert!(matches!(
        recovered.snapshot(context()).await,
        Err(StorageError::Corrupt("missing query head authority"))
    ));
    assert!(matches!(
        recovered.append(&rows[1..], context()).await,
        Err(StorageError::InvalidBatch)
    ));
    assert!(!control.path().join("head.json").exists());
    let result = recovered.append(&rows, context()).await?;
    assert_eq!(
        (result.new_count, result.replay_count, result.last_sequence),
        (1, 2, 11)
    );
    recovered.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn synced_genesis_recovers_first_commit_with_smaller_replay_batches() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let rows = rows()?;
    writer.append(&rows, context()).await?;
    writer.shutdown(context()).await?;
    assert!(control.path().join("genesis.json").exists());
    std::fs::remove_file(control.path().join("head.json"))?;
    let recovered = publisher(&owner, backend, PublicationConfig::default()).await?;
    for part in &rows {
        let receipt = recovered
            .append(std::slice::from_ref(part), context())
            .await?;
        assert_eq!(
            (
                receipt.new_count,
                receipt.replay_count,
                receipt.last_sequence
            ),
            (0, 1, part.sequence)
        );
        assert_eq!(recovered.metrics().high_water, 11);
    }
    let snapshot = recovered.snapshot(context()).await?;
    assert_eq!(snapshot.manifests().len(), 1);
    drop(snapshot);
    recovered.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn unique_valid_tail_recovers_but_missing_data_holds() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let rows = rows()?;
    writer.append(&rows[..2], context()).await?;
    let original_head = std::fs::read(control.path().join("head.json"))?;
    writer.append(&rows[2..], context()).await?;
    let snapshot = writer.snapshot(context()).await?;
    let last = snapshot.manifests()[1].clone();
    drop(snapshot);
    writer.shutdown(context()).await?;
    std::fs::write(control.path().join("head.json"), &original_head)?;
    let tail = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let snapshot = tail.snapshot(context()).await?;
    assert_eq!(snapshot.manifests().len(), 2);
    drop(snapshot);
    tail.shutdown(context()).await?;
    std::fs::write(control.path().join("head.json"), &original_head)?;
    backend
        .delete(&object_store::path::Path::from(
            last.manifest.files[0].object.key.clone(),
        ))
        .await?;
    let missing = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    assert!(missing.snapshot(context()).await.is_err());
    assert_eq!(
        std::fs::read(control.path().join("head.json"))?,
        original_head
    );
    missing.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn multiple_unknown_commit_slots_cannot_advance_the_head() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let rows = rows()?;
    writer.append(&rows[..2], context()).await?;
    let original_head = std::fs::read(control.path().join("head.json"))?;
    writer.append(&rows[2..], context()).await?;
    writer.shutdown(context()).await?;
    std::fs::write(control.path().join("head.json"), &original_head)?;
    backend
        .put(
            &object_store::path::Path::from(manifest_key(owner.stream_id, 100)),
            bytes::Bytes::from_static(b"{unknown manifest}").into(),
        )
        .await?;
    let recovered = publisher(&owner, backend, PublicationConfig::default()).await?;
    assert!(matches!(
        recovered.snapshot(context()).await,
        Err(StorageError::Corrupt("multiple uncommitted query slots"))
    ));
    assert_eq!(
        std::fs::read(control.path().join("head.json"))?,
        original_head
    );
    recovered.shutdown(context()).await?;
    Ok(())
}

/// Finite in-process fault fixture. It does not qualify S3 or process durability.
#[derive(Debug)]
struct FaultStore {
    inner: InMemory,
    mode: AtomicUsize,
    entered: tokio::sync::Notify,
    release: Semaphore,
}
impl std::fmt::Display for FaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bounded publication fault fixture")
    }
}
fn fault_error() -> object_store::Error {
    object_store::Error::Generic {
        store: "publication test",
        source: std::io::Error::other("injected response loss or denial").into(),
    }
}
#[async_trait::async_trait]
impl ObjectStore for FaultStore {
    async fn put_opts(
        &self,
        location: &object_store::path::Path,
        payload: object_store::PutPayload,
        options: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        let response = self.inner.put_opts(location, payload, options).await?;
        let mode = self.mode.load(Ordering::Acquire);
        let manifest = location.as_ref().contains("/commits/");
        if (mode == 1 && !manifest) || (mode == 2 && manifest) {
            self.mode.store(0, Ordering::Release);
            return Err(fault_error());
        }
        if mode == 3 && manifest {
            self.entered.notify_one();
            let permit = self.release.acquire().await.map_err(|_| fault_error())?;
            permit.forget();
        }
        Ok(response)
    }
    async fn get_opts(
        &self,
        location: &object_store::path::Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        if self.mode.load(Ordering::Acquire) == 4 {
            return Err(fault_error());
        }
        self.inner.get_opts(location, options).await
    }
    fn list(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
    {
        self.inner.list(prefix)
    }
    async fn put_multipart_opts(
        &self,
        _: &object_store::path::Path,
        _: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        Err(object_store::Error::NotImplemented {
            operation: "unused fixture operation".into(),
            implementer: "FaultStore".into(),
        })
    }
    fn delete_stream(
        &self,
        _: futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>
    {
        Box::pin(futures_util::stream::once(async {
            Err(object_store::Error::NotImplemented {
                operation: "unused fixture operation".into(),
                implementer: "FaultStore".into(),
            })
        }))
    }
    async fn list_with_delimiter(
        &self,
        _: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        Err(object_store::Error::NotImplemented {
            operation: "unused fixture operation".into(),
            implementer: "FaultStore".into(),
        })
    }
    async fn copy_opts(
        &self,
        _: &object_store::path::Path,
        _: &object_store::path::Path,
        _: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        Err(object_store::Error::NotImplemented {
            operation: "unused fixture operation".into(),
            implementer: "FaultStore".into(),
        })
    }
}
fn fault_store(mode: usize) -> Arc<FaultStore> {
    Arc::new(FaultStore {
        inner: InMemory::new(),
        mode: AtomicUsize::new(mode),
        entered: tokio::sync::Notify::new(),
        release: Semaphore::new(0),
    })
}
#[tokio::test]
async fn completed_publication_reply_cannot_bypass_original_deadline() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let writer = publisher(&owner, backend, PublicationConfig::default()).await?;
    let original = rows()?;
    let ctx = OperationContext::new(std::time::Duration::from_secs(2));
    let deadline = ctx.deadline;
    let mut request = Box::pin(writer.append(&original, ctx));
    assert!(futures_util::poll!(request.as_mut()).is_pending());
    while writer.metrics().processed == 0 || writer.metrics().running != 0 {
        assert!(
            Instant::now() < deadline,
            "physical publication must finish before deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    tokio::time::sleep_until(deadline + std::time::Duration::from_millis(2)).await;
    assert!(matches!(request.await, Err(StorageError::Timeout)));
    assert_eq!(writer.metrics().depth, 0);
    assert_eq!(writer.metrics().rejected, 1);
    let replay = writer.append(&original[..1], context()).await?;
    assert_eq!(
        (replay.new_count, replay.replay_count, replay.last_sequence),
        (0, 1, 7)
    );
    assert_eq!(writer.metrics().high_water, 11);
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn lost_data_and_manifest_create_replies_reconcile_exact_bytes() -> Result {
    for mode in [1, 2] {
        let control = TempDir::new()?;
        let owner = owner(&control);
        let backend = fault_store(mode);
        let writer = publisher(&owner, backend, PublicationConfig::default()).await?;
        let rows = rows()?;
        let receipt = writer.append(&rows, context()).await?;
        assert_eq!((receipt.last_sequence, receipt.new_count), (11, 3));
        let snapshot = writer.snapshot(context()).await?;
        assert_eq!(snapshot.manifests().len(), 1);
        assert!(snapshot.orphans().is_empty());
        drop(snapshot);
        let replay = writer.append(&rows, context()).await?;
        assert_eq!(replay.new_count, 0);
        writer.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn cancelled_manifest_response_keeps_lease_until_exit_and_recovers_from_genesis() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = fault_store(3);
    let writer = Arc::new(publisher(&owner, backend.clone(), PublicationConfig::default()).await?);
    let original = rows()?;
    let queued = original.clone();
    let handle = writer.clone();
    let operation = tokio::spawn(async move { handle.append(&queued, context()).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        backend.entered.notified(),
    )
    .await?;
    assert!(matches!(
        writer.append(&original, context()).await,
        Err(StorageError::Busy)
    ));
    assert!(control.path().join("genesis.json").exists());
    assert!(!control.path().join("head.json").exists());
    operation.abort();
    assert!(operation.await.is_err());
    let until = Instant::now() + std::time::Duration::from_secs(5);
    while writer.metrics().depth != 0 || writer.metrics().running != 0 {
        assert!(Instant::now() < until, "cancelled physical work must exit");
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    writer.shutdown(context()).await?;
    backend.mode.store(0, Ordering::Release);
    let recovered = publisher(&owner, backend, PublicationConfig::default()).await?;
    let replay = recovered.append(&original[..1], context()).await?;
    assert_eq!(
        (replay.new_count, replay.replay_count, replay.last_sequence),
        (0, 1, 7)
    );
    assert_eq!(recovered.metrics().high_water, 11);
    recovered.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn readback_denial_leaves_only_orphans_and_no_completed_head() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = fault_store(4);
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    let original = rows()?;
    assert!(writer.append(&original, context()).await.is_err());
    assert!(!control.path().join("head.json").exists());
    assert_eq!(writer.metrics().high_water, 0);
    backend.mode.store(0, Ordering::Release);
    let snapshot = writer.snapshot(context()).await?;
    assert!(snapshot.manifests().is_empty());
    assert_eq!(snapshot.orphans().len(), 1);
    drop(snapshot);
    let receipt = writer.append(&original, context()).await?;
    assert_eq!(receipt.new_count, 3);
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn conflicting_existing_object_and_missing_replay_sequence_hold() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let original = rows()?;
    let codec = ObjectCodec::new(StorageConfig::default(), ManifestLimits::default())?;
    let prepared = codec.prepare(&original[..1], context()).await?;
    let file = &prepared.files()[0];
    let key = data_key(owner.stream_id, file.date(), file.hour(), file.sha256());
    drop(prepared);
    codec.shutdown(context()).await?;
    let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
    // Initialize from genuinely empty inventory first. The next injected bytes
    // impersonate a content-keyed query object but cannot satisfy exact readback.
    drop(writer.snapshot(context()).await?);
    backend
        .put(
            &object_store::path::Path::from(key.clone()),
            bytes::Bytes::from_static(b"conflicting bytes").into(),
        )
        .await?;
    assert!(matches!(
        writer.append(&original[..1], context()).await,
        Err(StorageError::InvalidBatch)
    ));
    assert_eq!(writer.metrics().high_water, 0);
    assert!(!control.path().join("head.json").exists());
    assert!(
        backend
            .head(&object_store::path::Path::from(key.clone()))
            .await
            .is_ok()
    );
    // Explicit fixture cleanup, never a production publisher deletion path.
    backend.delete(&object_store::path::Path::from(key)).await?;
    writer.append(&original, context()).await?;
    let mut gap = original[0].clone();
    gap.sequence = 8;
    assert!(matches!(
        writer.append(&[gap], context()).await,
        Err(StorageError::InvalidBatch)
    ));
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn exact_capacity_retry_reuses_counted_orphan_without_permanent_full() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = fault_store(4);
    let config = PublicationConfig {
        inventory_objects: 3,
        ..PublicationConfig::default()
    };
    let writer = publisher(&owner, backend.clone(), config).await?;
    let original = rows()?;
    assert!(writer.append(&original, context()).await.is_err());
    assert!(!control.path().join("head.json").exists());
    backend.mode.store(0, Ordering::Release);
    let before = writer.snapshot(context()).await?;
    assert_eq!(before.orphans().len(), 1);
    drop(before);
    let receipt = writer.append(&original, context()).await?;
    assert_eq!(
        (
            receipt.first_sequence,
            receipt.last_sequence,
            receipt.new_count
        ),
        (7, 11, 3)
    );
    let after = writer.snapshot(context()).await?;
    assert_eq!(after.manifests().len(), 1);
    assert_eq!(after.manifests()[0].manifest.files.len(), 2);
    assert!(after.orphans().is_empty());
    drop(after);
    writer.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn changed_historical_object_identity_holds_new_append_and_recovery_head() -> Result {
    for recover_tail in [false, true] {
        let control = TempDir::new()?;
        let owner = owner(&control);
        let backend = Arc::new(InMemory::new());
        let writer = publisher(&owner, backend.clone(), PublicationConfig::default()).await?;
        let original = rows()?;
        writer.append(&original[..2], context()).await?;
        let previous_head = std::fs::read(control.path().join("head.json"))?;
        let snapshot = writer.snapshot(context()).await?;
        let key = snapshot.manifests()[0].manifest.files[0].object.key.clone();
        drop(snapshot);
        if recover_tail {
            writer.append(&original[2..], context()).await?;
        }
        writer.shutdown(context()).await?;
        if recover_tail {
            std::fs::write(control.path().join("head.json"), &previous_head)?;
        }
        backend
            .put(
                &object_store::path::Path::from(key),
                bytes::Bytes::from_static(b"corrupt historical bytes").into(),
            )
            .await?;
        let reopened = publisher(&owner, backend, PublicationConfig::default()).await?;
        assert!(matches!(
            reopened.append(&original[2..], context()).await,
            Err(StorageError::Corrupt(
                "committed query object identity drift"
            ))
        ));
        assert!(matches!(
            reopened.snapshot(context()).await,
            Err(StorageError::Corrupt(
                "committed query object identity drift"
            ))
        ));
        assert_eq!(
            std::fs::read(control.path().join("head.json"))?,
            previous_head
        );
        reopened.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn metadata_and_orphan_quota_hold_without_deleting_any_object() -> Result {
    let control = TempDir::new()?;
    let owner = owner(&control);
    let backend = Arc::new(InMemory::new());
    let config = PublicationConfig {
        inventory_objects: 3,
        ..PublicationConfig::default()
    };
    let writer = publisher(&owner, backend.clone(), config).await?;
    let rows = rows()?;
    writer.append(&rows[..1], context()).await?;
    let key = format!("query/{}/data/unreferenced", owner.stream_id);
    backend
        .put(
            &object_store::path::Path::from(key.clone()),
            bytes::Bytes::from_static(b"uncommitted query copy").into(),
        )
        .await?;
    let snapshot = writer.snapshot(context()).await?;
    assert_eq!(snapshot.manifests().len(), 1);
    assert_eq!(snapshot.orphans().len(), 1);
    assert_eq!(snapshot.orphans()[0].sha256, [0; 32]);
    drop(snapshot);
    assert!(matches!(
        writer.append(&rows[1..], context()).await,
        Err(StorageError::Full)
    ));
    assert!(
        backend
            .head(&object_store::path::Path::from(key))
            .await
            .is_ok()
    );
    assert_eq!(writer.metrics().high_water, 7);
    writer.shutdown(context()).await?;
    Ok(())
}

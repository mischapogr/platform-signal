use super::*;
use crate::{
    QueryFileSource, StoredEvent,
    object_cache::MaterializationConfig,
    object_io::{ObjectIo, ObjectIoLimits, SmallOwnerConfig},
    object_manifest::{QueryObjectRef, manifest_key},
    object_publication::{ObjectPublisher, PublicationConfig},
};
use object_store::{ObjectStore, ObjectStoreExt, memory::InMemory};
use std::{sync::Arc, time::Duration};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(5))
}
fn time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}
fn policy() -> RetentionPolicy {
    RetentionPolicy {
        schema_version: 1,
        raw_seconds: None,
        query_seconds: 3600,
        index_seconds: None,
        replay_seconds: 1800,
        evidence_reference_seconds: 7200,
        reader_seconds: 600,
        orphan_grace_seconds: 1800,
    }
}
fn anchor(stream: Uuid, first: u64, last: u64) -> PreviousManifest {
    PreviousManifest {
        first_sequence: first,
        last_sequence: last,
        object: QueryObjectRef {
            key: manifest_key(stream, first),
            version: Some("immutable-v1".into()),
            etag: Some("opaque-etag".into()),
            bytes: 300,
            sha256: [1; 32],
        },
    }
}
#[test]
fn retirement_control_codec_binds_checkpoint_cutoff_identity_and_predecessor() -> Result {
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    let now = time("2026-07-10T21:00:00Z")?;
    let first = anchor(stream, 1, 3);
    let record = RetirementRecord::new(stream, backend, None, &first, 3, now, &policy())?;
    let bytes = record.encode(&context())?;
    assert_eq!(
        RetirementRecord::decode(&bytes, stream, backend, &context())?,
        record
    );
    assert!(RetirementRecord::new(stream, backend, None, &first, 2, now, &policy()).is_err());
    assert!(
        RetirementRecord::new(stream, backend, Some(&first), &first, 3, now, &policy()).is_err()
    );
    let next = anchor(stream, 4, 6);
    RetirementRecord::new(stream, backend, Some(&first), &next, 6, now, &policy())?;
    for mode in 0..5 {
        let mut modified = record.clone();
        match mode {
            0 => modified.query_before = now,
            1 => modified.schema_version = 2,
            2 => modified.anchor.object.version = Some("v".repeat(257)),
            3 => modified.anchor.object.sha256 = [0; 32],
            _ => modified.backend_id = Uuid::new_v4(),
        }
        assert!(modified.validate(stream, backend).is_err());
    }
    assert!(
        RetirementRecord::decode(&vec![b' '; RECORD_BYTES + 1], stream, backend, &context())
            .is_err()
    );
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        record.encode(&cancelled),
        Err(StorageError::Cancelled)
    ));
    assert!(
        RetirementRecord::new(
            stream,
            backend,
            None,
            &first,
            3,
            DateTime::<Utc>::MIN_UTC,
            &policy()
        )
        .is_err()
    );
    Ok(())
}
struct Fixture {
    root: tempfile::TempDir,
    owner: SmallOwnerConfig,
    remote: Arc<InMemory>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::TempDir::new()?;
        let owner = SmallOwnerConfig {
            directory: root.path().join("control"),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        Ok(Self {
            root,
            owner,
            remote: Arc::new(InMemory::new()),
        })
    }
    async fn open(&self) -> Result<Arc<ObjectPublisher>> {
        let io = ObjectIo::open_small_remote(
            &self.owner,
            self.remote.clone(),
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
                    directory: self.root.path().join("derived"),
                    max_files: 16,
                    max_disk_bytes: 8 * 1024 * 1024,
                }),
                ..Default::default()
            },
        )?))
    }
}
fn row(sequence: u64, timestamp: &str) -> Result<StoredEvent> {
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":timestamp,"source":{"type":"retirement-fixture"},"message":"held query object"}),
    )?;
    Ok(StoredEvent {
        sequence,
        event: input.normalize(Utc::now())?,
    })
}
#[tokio::test]
async fn retired_prefix_is_synced_recovered_and_distinct_from_missing_live_data() -> Result {
    let fixture = Fixture::new()?;
    let publisher = fixture.open().await?;
    let rows = [
        row(1, "2026-07-10T19:15:00Z")?,
        row(2, "2026-07-10T19:20:00Z")?,
        row(3, "2026-07-10T20:20:00Z")?,
        row(4, "2026-07-10T18:20:00Z")?,
    ];
    publisher.append(&rows[..1], context()).await?;
    publisher.append(&rows[1..3], context()).await?;
    publisher.append(&rows[3..], context()).await?;
    let before = publisher.snapshot(context()).await?;
    let data: Vec<_> = before
        .manifests()
        .iter()
        .flat_map(|m| m.manifest.files.iter().map(|f| f.object.clone()))
        .collect();
    assert_eq!(data.len(), 4);
    assert!(matches!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 4
                },
                time("2026-07-10T21:00:00Z")?,
                context()
            )
            .await,
        Err(StorageError::Busy)
    ));
    drop(before);
    let now = time("2026-07-10T21:00:00Z")?;
    assert_eq!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 0
                },
                now,
                context()
            )
            .await?,
        0
    );
    assert_eq!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 1
                },
                now,
                context()
            )
            .await?,
        1
    );
    assert_eq!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 4
                },
                now,
                context()
            )
            .await?,
        1
    );
    assert_eq!(publisher.metrics().high_water, 4);
    assert_eq!(publisher.retired_through(), 1);
    assert!(matches!(
        publisher.append(&rows[..1], context()).await,
        Err(StorageError::InvalidBatch)
    ));
    assert!(matches!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 0
                },
                now,
                context()
            )
            .await,
        Err(StorageError::InvalidBatch)
    ));
    for reference in &data {
        assert!(
            fixture
                .remote
                .head(&object_store::path::Path::from(reference.key.clone()))
                .await
                .is_ok()
        );
    }
    let selected = publisher
        .select_query_files(None, None, 16, 8 * 1024 * 1024, context())
        .await?;
    assert_eq!(selected.files.iter().map(|f| f.rows).sum::<usize>(), 3);
    assert!(matches!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 4
                },
                time("2026-07-10T23:00:00Z")?,
                context()
            )
            .await,
        Err(StorageError::Busy)
    ));
    drop(selected);
    publisher.shutdown(context()).await?;
    drop(publisher);
    let reopened = fixture.open().await?;
    let snapshot = reopened.snapshot(context()).await?;
    assert_eq!(snapshot.retired_through(), 1);
    drop(snapshot);
    assert_eq!(
        reopened
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 4
                },
                time("2026-07-10T23:00:00Z")?,
                context()
            )
            .await?,
        4
    );
    reopened.shutdown(context()).await?;
    drop(reopened);
    // Fault/recovery only: directly remove a known retired query object. This
    // exercises reachability recovery, not an implemented deletion capability.
    fixture
        .remote
        .delete(&object_store::path::Path::from(data[0].key.clone()))
        .await?;
    let recovered = fixture.open().await?;
    let snapshot = recovered.snapshot(context()).await?;
    assert_eq!(snapshot.retired_through(), 4);
    drop(snapshot);
    assert!(
        recovered
            .select_query_files(None, None, 16, 8 * 1024 * 1024, context())
            .await?
            .files
            .is_empty()
    );
    assert!(matches!(
        recovered.append(&rows[3..], context()).await,
        Err(StorageError::InvalidBatch)
    ));
    recovered.shutdown(context()).await?;
    drop(recovered);
    Ok(())
}

#[tokio::test]
async fn retained_snapshot_blocks_successor_after_publisher_shutdown_and_drop() -> Result {
    let fixture = Fixture::new()?;
    let publisher = fixture.open().await?;
    publisher
        .append(&[row(1, "2026-07-10T19:15:00Z")?], context())
        .await?;
    let snapshot = publisher.snapshot(context()).await?;
    publisher.shutdown(context()).await?;
    drop(publisher);
    assert!(matches!(
        fixture
            .open()
            .await
            .err()
            .and_then(|e| e.downcast::<crate::object_io::ObjectIoError>().ok())
            .as_deref(),
        Some(crate::object_io::ObjectIoError::OwnerLocked)
    ));
    assert_eq!(snapshot.manifests()[0].reference.last_sequence, 1);
    drop(snapshot);
    let successor = fixture.open().await?;
    assert_eq!(
        successor
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 1
                },
                time("2026-07-10T21:00:00Z")?,
                context()
            )
            .await?,
        1
    );
    successor.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn missing_retired_data_is_allowed_but_missing_live_data_holds_recovery() -> Result {
    let fixture = Fixture::new()?;
    let publisher = fixture.open().await?;
    for r in [
        row(1, "2026-07-10T19:15:00Z")?,
        row(2, "2026-07-10T20:15:00Z")?,
    ] {
        publisher.append(&[r], context()).await?;
    }
    let original = object_store::path::Path::from("protected/native/original");
    fixture
        .remote
        .put_opts(
            &original,
            b"retain native bytes".to_vec().into(),
            Default::default(),
        )
        .await?;
    let snapshot = publisher.snapshot(context()).await?;
    let old = snapshot.manifests()[0].manifest.files[0].object.key.clone();
    let live = snapshot.manifests()[1].manifest.files[0].object.key.clone();
    drop(snapshot);
    publisher
        .retire_query_prefix(
            &policy(),
            RetirementCheckpoint {
                stream_id: fixture.owner.stream_id,
                checkpoint: 2,
            },
            time("2026-07-10T21:00:00Z")?,
            context(),
        )
        .await?;
    let witness = std::fs::read(fixture.owner.directory.join("retirement.json"))?;
    fixture
        .remote
        .delete(&object_store::path::Path::from(old))
        .await?;
    let snapshot = publisher.snapshot(context()).await?;
    assert_eq!(snapshot.retired_through(), 1);
    drop(snapshot);
    fixture
        .remote
        .delete(&object_store::path::Path::from(live))
        .await?;
    assert!(matches!(
        publisher.snapshot(context()).await,
        Err(StorageError::Corrupt(_))
    ));
    assert_eq!(
        std::fs::read(fixture.owner.directory.join("retirement.json"))?,
        witness
    );
    assert_eq!(
        fixture.remote.get(&original).await?.bytes().await?.as_ref(),
        b"retain native bytes"
    );
    publisher.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn unauthenticated_pending_retirement_preserves_current_and_candidate_bytes() -> Result {
    let fixture = Fixture::new()?;
    let publisher = fixture.open().await?;
    for sequence in 1..=2 {
        publisher
            .append(&[row(sequence, "2026-07-10T19:15:00Z")?], context())
            .await?;
    }
    let snapshot = publisher.snapshot(context()).await?;
    let first = snapshot.manifests()[0].reference.clone();
    let second = snapshot.manifests()[1].reference.clone();
    drop(snapshot);
    publisher
        .retire_query_prefix(
            &policy(),
            RetirementCheckpoint {
                stream_id: fixture.owner.stream_id,
                checkpoint: 1,
            },
            time("2026-07-10T21:00:00Z")?,
            context(),
        )
        .await?;
    publisher.shutdown(context()).await?;
    drop(publisher);
    let current_path = fixture.owner.directory.join("retirement.json");
    let pending_path = fixture.owner.directory.join("retirement.tmp");
    let current = std::fs::read(&current_path)?;
    // Correct predecessor, binding and bounds; only the pinned committed identity
    // is forged. General owner opening must not replace the valid witness.
    let mut forged = second.clone();
    forged.object.sha256 = [77; 32];
    let bad = RetirementRecord::new(
        fixture.owner.stream_id,
        fixture.owner.backend_id,
        Some(&first),
        &forged,
        2,
        time("2026-07-10T21:00:00Z")?,
        &policy(),
    )?
    .encode(&context())?;
    std::fs::write(&pending_path, &bad)?;
    let recovered = fixture.open().await?;
    assert_eq!(std::fs::read(&current_path)?, current);
    assert_eq!(std::fs::read(&pending_path)?, bad);
    assert!(matches!(
        recovered.snapshot(context()).await,
        Err(StorageError::Corrupt(_))
    ));
    assert_eq!(std::fs::read(&current_path)?, current);
    assert_eq!(std::fs::read(&pending_path)?, bad);
    recovered.shutdown(context()).await?;
    drop(recovered);
    // Emulate a completely synced, valid interrupted candidate in this test's
    // owned control. Recovery authenticates and publishes it, then is idempotent.
    let valid = RetirementRecord::new(
        fixture.owner.stream_id,
        fixture.owner.backend_id,
        Some(&first),
        &second,
        2,
        time("2026-07-10T21:00:00Z")?,
        &policy(),
    )?
    .encode(&context())?;
    std::fs::write(&pending_path, &valid)?;
    let recovered = fixture.open().await?;
    assert_eq!(std::fs::read(&current_path)?, current);
    let snapshot = recovered.snapshot(context()).await?;
    assert_eq!(snapshot.retired_through(), 2);
    drop(snapshot);
    assert_eq!(std::fs::read(&current_path)?, valid);
    assert!(!pending_path.exists());
    // Same interrupted bytes may only be removed after reauthentication.
    std::fs::write(&pending_path, &valid)?;
    drop(recovered.snapshot(context()).await?);
    assert!(!pending_path.exists());
    recovered.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn retirement_accepts_checkpoint_beyond_store_and_rejects_foreign_stream() -> Result {
    let fixture = Fixture::new()?;
    let publisher = fixture.open().await?;
    publisher
        .append(&[row(6, "2026-07-10T19:15:00Z")?], context())
        .await?;
    let now = time("2026-07-10T21:00:00Z")?;
    assert!(matches!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: Uuid::new_v4(),
                    checkpoint: 7,
                },
                now,
                context()
            )
            .await,
        Err(StorageError::StreamMismatch)
    ));
    assert!(!fixture.owner.directory.join("retirement.json").exists());
    // drop_oldest can ACK a dropped row 7 after committed store frontier 6.
    // The actual committed anchor remains <= the supplied fresh WAL checkpoint.
    assert_eq!(
        publisher
            .retire_query_prefix(
                &policy(),
                RetirementCheckpoint {
                    stream_id: fixture.owner.stream_id,
                    checkpoint: 7,
                },
                now,
                context()
            )
            .await?,
        6
    );
    let record = RetirementRecord::decode(
        &std::fs::read(fixture.owner.directory.join("retirement.json"))?,
        fixture.owner.stream_id,
        fixture.owner.backend_id,
        &context(),
    )?;
    assert_eq!(record.wal_checkpoint, 7);
    assert_eq!(record.anchor.last_sequence, 6);
    publisher.shutdown(context()).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "parent-invoked actual retirement control crash helper"]
async fn retirement_control_crash_helper() -> Result {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var("SIGNAL_TEST_RETIREMENT_ROOT")?);
    let owner = SmallOwnerConfig {
        directory: root.join("control"),
        stream_id: Uuid::parse_str(&std::env::var("SIGNAL_TEST_RETIREMENT_STREAM")?)?,
        backend_id: Uuid::parse_str(&std::env::var("SIGNAL_TEST_RETIREMENT_BACKEND")?)?,
    };
    let stage = std::env::var("SIGNAL_TEST_RETIREMENT_STAGE")?;
    if !["temp_synced", "renamed", "directory_synced"].contains(&stage.as_str()) {
        return Err("unknown retirement crash stage".into());
    }
    let io = ObjectIo::open_small_local(
        &owner,
        object_store::local::LocalFileSystem::new_with_prefix(root.join("objects"))?,
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    let lease = io.small_owner_lease()?;
    let publisher = ObjectPublisher::new(
        io,
        tokio::runtime::Handle::current(),
        PublicationConfig::default(),
    )?;
    let record = RetirementRecord::decode(
        &std::fs::read(root.join("plan"))?,
        owner.stream_id,
        owner.backend_id,
        &context(),
    )?;
    let snapshot = publisher.snapshot(context()).await?;
    assert_eq!(snapshot.manifests()[0].reference, record.anchor);
    assert_eq!(
        snapshot
            .manifests()
            .last()
            .map(|m| m.reference.last_sequence),
        Some(2)
    );
    drop(snapshot);
    lease.advance_retirement_with(&record, &context(), |point| {
        if point == stage {
            let mut witness =
                std::fs::File::create(root.join("witness")).map_err(StorageError::Io)?;
            witness
                .write_all(point.as_bytes())
                .map_err(StorageError::Io)?;
            witness.sync_all().map_err(StorageError::Io)?;
            crate::fs::sync_dir(&root)?;
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    })?;
    publisher.shutdown(context()).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn actual_process_loss_at_retirement_control_milestones_recovers_exact_prefix() -> Result {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
        time::Instant,
    };
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for stage in ["temp_synced", "renamed", "directory_synced"] {
        let root = tempfile::TempDir::new()?;
        std::fs::create_dir(root.path().join("objects"))?;
        let owner = SmallOwnerConfig {
            directory: root.path().join("control"),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        let open = || async {
            let io = ObjectIo::open_small_local(
                &owner,
                object_store::local::LocalFileSystem::new_with_prefix(root.path().join("objects"))?,
                ObjectIoLimits::default(),
                context(),
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error>>(ObjectPublisher::new(
                io,
                tokio::runtime::Handle::current(),
                PublicationConfig::default(),
            )?)
        };
        let publisher = open().await?;
        for event in [
            row(1, "2026-07-10T19:15:00Z")?,
            row(2, "2026-07-10T20:15:00Z")?,
        ] {
            publisher.append(&[event], context()).await?;
        }
        let snapshot = publisher.snapshot(context()).await?;
        let references: Vec<_> = snapshot
            .manifests()
            .iter()
            .map(|m| m.reference.clone())
            .collect();
        let data: Vec<_> = snapshot
            .manifests()
            .iter()
            .flat_map(|m| m.manifest.files.iter().map(|f| f.object.clone()))
            .collect();
        let record = RetirementRecord::new(
            owner.stream_id,
            owner.backend_id,
            None,
            &references[0],
            2,
            time("2026-07-10T21:00:00Z")?,
            &policy(),
        )?;
        let expected = record.encode(&context())?;
        std::fs::write(root.path().join("plan"), &expected)?;
        std::fs::write(
            root.path().join("protected-original"),
            b"native immutable evidence",
        )?;
        drop(snapshot);
        publisher.shutdown(context()).await?;
        drop(publisher);
        let binding = std::fs::read(owner.directory.join("binding.json"))?;
        let head = std::fs::read(owner.directory.join("head.json"))?;
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "object_retirement::tests::retirement_control_crash_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SIGNAL_TEST_RETIREMENT_ROOT", root.path())
                .env("SIGNAL_TEST_RETIREMENT_STREAM", owner.stream_id.to_string())
                .env(
                    "SIGNAL_TEST_RETIREMENT_BACKEND",
                    owner.backend_id.to_string(),
                )
                .env("SIGNAL_TEST_RETIREMENT_STAGE", stage)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let until = Instant::now() + Duration::from_secs(3);
        while !root.path().join("witness").exists() {
            if child.0.try_wait()?.is_some() || Instant::now() >= until {
                return Err(format!("retirement witness unavailable at {stage}").into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            std::fs::read(root.path().join("witness"))?,
            stage.as_bytes()
        );
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let recovered = open().await?;
        let snapshot = recovered.snapshot(context()).await?;
        assert_eq!(snapshot.retired_through(), 1);
        assert_eq!(
            snapshot
                .manifests()
                .iter()
                .map(|m| m.reference.clone())
                .collect::<Vec<_>>(),
            references
        );
        drop(snapshot);
        assert_eq!(
            std::fs::read(owner.directory.join("retirement.json"))?,
            expected
        );
        assert!(!owner.directory.join("retirement.tmp").exists());
        assert_eq!(
            std::fs::read(owner.directory.join("binding.json"))?,
            binding
        );
        assert_eq!(std::fs::read(owner.directory.join("head.json"))?, head);
        assert_eq!(
            std::fs::read(root.path().join("protected-original"))?,
            b"native immutable evidence"
        );
        let remote =
            object_store::local::LocalFileSystem::new_with_prefix(root.path().join("objects"))?;
        for file in data {
            assert_eq!(
                remote
                    .head(&object_store::path::Path::from(file.key))
                    .await?
                    .size,
                file.bytes
            );
        }
        assert!(matches!(
            recovered
                .append(&[row(1, "2026-07-10T19:15:00Z")?], context())
                .await,
            Err(StorageError::InvalidBatch)
        ));
        recovered.shutdown(context()).await?;
    }
    Ok(())
}

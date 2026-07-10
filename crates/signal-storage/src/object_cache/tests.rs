use super::*;
use crate::object_manifest::{QueryObjectRef, sha256};
use tempfile::TempDir;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(std::time::Duration::from_secs(3))
}
fn config(root: &TempDir) -> MaterializationConfig {
    MaterializationConfig {
        directory: root.path().join("derived"),
        max_files: 1,
        max_disk_bytes: 4,
    }
}
fn file(body: &[u8]) -> QueryFile {
    QueryFile {
        date: "2026-07-10".into(),
        hour: 19,
        rows: 1,
        decoded_bytes: 64,
        object: QueryObjectRef {
            key: "query/synthetic/data/fixture.parquet".into(),
            version: Some("v1".into()),
            etag: Some("etag1".into()),
            bytes: body.len() as u64,
            sha256: sha256(body),
        },
    }
}
fn stem(body: &[u8]) -> String {
    sha256(body).iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn exclusive_derived_owner_and_backend_mismatch_preserve_bound_control() -> Result {
    let root = TempDir::new()?;
    let config = config(&root);
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    let first = Cache::open(&config, stream, backend, &context())?;
    assert!(matches!(
        Cache::open(&config, stream, backend, &context()),
        Err(StorageError::Locked)
    ));
    let binding = fs::read(config.directory.join("control/binding.json"))?;
    drop(first);
    assert!(matches!(
        Cache::open(&config, stream, Uuid::new_v4(), &context()),
        Err(StorageError::StreamMismatch)
    ));
    assert_eq!(
        fs::read(config.directory.join("control/binding.json"))?,
        binding
    );
    Cache::open(&config, stream, backend, &context())?;
    Ok(())
}
#[test]
fn foreign_and_symlink_cache_layout_fail_before_new_binding() -> Result {
    let root = TempDir::new()?;
    let config = config(&root);
    let objects = config.directory.join("objects");
    fs::create_dir_all(&objects)?;
    fs::write(objects.join("foreign"), b"keep")?;
    assert!(matches!(
        Cache::open(&config, Uuid::new_v4(), Uuid::new_v4(), &context()),
        Err(StorageError::Corrupt(_))
    ));
    assert!(!config.directory.join("control/binding.json").exists());
    assert_eq!(fs::read(objects.join("foreign"))?, b"keep");
    fs::remove_file(objects.join("foreign"))?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            root.path(),
            objects.join(format!("{}.parquet", stem(b"copy"))),
        )?;
        assert!(matches!(
            Cache::open(&config, Uuid::new_v4(), Uuid::new_v4(), &context()),
            Err(StorageError::Corrupt(_))
        ));
        assert!(!config.directory.join("control/binding.json").exists());
    }
    Ok(())
}
#[test]
fn exact_capacity_temp_reconciliation_and_partial_temp_hold_are_bounded() -> Result {
    let root = TempDir::new()?;
    let config = config(&root);
    let cache = Cache::open(&config, Uuid::new_v4(), Uuid::new_v4(), &context())?;
    let body = b"copy";
    let temp = cache.objects.join(format!("{}.tmp", stem(body)));
    fs::write(&temp, b"part")?;
    assert!(matches!(
        cache.materialize(&file(body), body, &context()),
        Err(StorageError::Corrupt(_))
    ));
    assert_eq!(fs::read(&temp)?, b"part");
    fs::write(&temp, body)?;
    let result = cache.materialize(&file(body), body, &context())?;
    assert_eq!(fs::read(result.path)?, body);
    assert!(!temp.exists());
    let other = b"next";
    assert!(matches!(
        cache.materialize(&file(other), other, &context()),
        Err(StorageError::Full)
    ));
    assert_eq!(fs::read_dir(&cache.objects)?.count(), 1);
    cache.materialize(&file(body), body, &context())?;
    Ok(())
}

#[test]
fn stopped_prune_requires_existing_binding_and_preserves_control_and_originals() -> Result {
    let root = TempDir::new()?;
    let config = config(&root);
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    assert!(prune_stopped_materialization(&config, stream, backend, &context()).is_err());
    assert!(!config.directory.exists());
    let original = root.path().join("protected-original");
    fs::write(&original, b"retain native original")?;
    let cache = Cache::open(&config, stream, backend, &context())?;
    cache.materialize(&file(b"copy"), b"copy", &context())?;
    let binding = fs::read(config.directory.join("control/binding.json"))?;
    assert!(matches!(
        prune_stopped_materialization(&config, stream, backend, &context()),
        Err(StorageError::Locked)
    ));
    drop(cache);
    assert!(matches!(
        prune_stopped_materialization(&config, stream, Uuid::new_v4(), &context()),
        Err(StorageError::StreamMismatch)
    ));
    let result = prune_stopped_materialization(&config, stream, backend, &context())?;
    assert_eq!((result.removed_files, result.removed_bytes), (1, 4));
    assert_eq!(
        fs::read(config.directory.join("control/binding.json"))?,
        binding
    );
    assert_eq!(fs::read(original)?, b"retain native original");
    let cache = Cache::open(&config, stream, backend, &context())?;
    let rebuilt = cache.materialize(&file(b"next"), b"next", &context())?;
    assert_eq!(fs::read(rebuilt.path)?, b"next");
    Ok(())
}

#[test]
fn stopped_prune_preflights_foreign_links_and_cancelled_partial_work() -> Result {
    let root = TempDir::new()?;
    let mut config = config(&root);
    config.max_files = 3;
    config.max_disk_bytes = 12;
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    let cache = Cache::open(&config, stream, backend, &context())?;
    cache.materialize(&file(b"copy"), b"copy", &context())?;
    cache.materialize(&file(b"next"), b"next", &context())?;
    let objects = cache.objects.clone();
    drop(cache);
    let foreign = objects.join("foreign");
    fs::write(&foreign, b"keep")?;
    assert!(matches!(
        prune_stopped_materialization(&config, stream, backend, &context()),
        Err(StorageError::Corrupt(_))
    ));
    assert_eq!(fs::read_dir(&objects)?.count(), 3);
    fs::remove_file(&foreign)?;
    #[cfg(unix)]
    {
        let link = objects.join(format!("{}.parquet", "c".repeat(64)));
        let source = objects.join(format!("{}.parquet", stem(b"copy")));
        std::os::unix::fs::symlink(&source, &link)?;
        assert!(prune_stopped_materialization(&config, stream, backend, &context()).is_err());
        assert_eq!(fs::read_dir(&objects)?.count(), 3);
        fs::remove_file(&link)?;
        fs::hard_link(&source, &link)?;
        assert!(prune_stopped_materialization(&config, stream, backend, &context()).is_err());
        assert_eq!(fs::read_dir(&objects)?.count(), 3);
        fs::remove_file(&link)?;
    }
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        prune_stopped_materialization(&config, stream, backend, &cancelled),
        Err(StorageError::Cancelled)
    ));
    assert_eq!(fs::read_dir(&objects)?.count(), 2);
    let interrupted = context();
    assert!(matches!(
        prune(&config, stream, backend, &interrupted, |_| {
            interrupted.cancellation.cancel();
            Ok(())
        }),
        Err(StorageError::Cancelled)
    ));
    assert_eq!(fs::read_dir(&objects)?.count(), 1);
    assert_eq!(
        prune_stopped_materialization(&config, stream, backend, &context())?.removed_files,
        1
    );
    assert_eq!(
        prune_stopped_materialization(&config, stream, backend, &context())?.removed_files,
        0
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn stopped_prune_permission_failure_preserves_cache_and_binding() -> Result {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Root bypasses this DAC check. Native non-root CI/host execution is required.
    if fs::metadata("/proc/self")?.uid() == 0 {
        eprintln!("unlink DAC check unavailable for root");
        return Ok(());
    }
    let root = TempDir::new()?;
    let config = config(&root);
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    let cache = Cache::open(&config, stream, backend, &context())?;
    cache.materialize(&file(b"copy"), b"copy", &context())?;
    let objects = cache.objects.clone();
    drop(cache);
    let binding = fs::read(config.directory.join("control/binding.json"))?;
    fs::set_permissions(&objects, fs::Permissions::from_mode(0o500))?;
    let result = prune_stopped_materialization(&config, stream, backend, &context());
    fs::set_permissions(&objects, fs::Permissions::from_mode(0o700))?;
    assert!(
        matches!(result, Err(StorageError::Io(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(fs::read_dir(&objects)?.count(), 1);
    assert_eq!(
        fs::read(config.directory.join("control/binding.json"))?,
        binding
    );
    assert_eq!(
        prune_stopped_materialization(&config, stream, backend, &context())?.removed_files,
        1
    );
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "parent-invoked stopped-cache crash helper"]
fn stopped_prune_crash_helper() -> Result {
    let root = PathBuf::from(std::env::var("SIGNAL_TEST_CACHE_ROOT")?);
    let stream = Uuid::parse_str(&std::env::var("SIGNAL_TEST_CACHE_STREAM")?)?;
    let backend = Uuid::parse_str(&std::env::var("SIGNAL_TEST_CACHE_BACKEND")?)?;
    let config = MaterializationConfig {
        directory: root.join("derived"),
        max_files: 2,
        max_disk_bytes: 8,
    };
    prune(&config, stream, backend, &context(), |count| {
        if count == 1 {
            let mut witness =
                File::create(root.join("first-unlink-synced")).map_err(StorageError::Io)?;
            witness.write_all(b"1").map_err(StorageError::Io)?;
            witness.sync_all().map_err(StorageError::Io)?;
            crate::fs::sync_dir(&root)?;
            // Test-only bounded pause for the parent to kill this exact child.
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
        Ok(())
    })?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn actual_process_loss_after_synced_cache_unlink_reopens_and_rebuilds() -> Result {
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
    let root = TempDir::new()?;
    let mut config = config(&root);
    config.max_files = 2;
    config.max_disk_bytes = 8;
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    let original = root.path().join("protected-original");
    fs::write(&original, b"retain native original")?;
    let cache = Cache::open(&config, stream, backend, &context())?;
    for body in [b"copy", b"next"] {
        cache.materialize(&file(body), body, &context())?;
    }
    drop(cache);
    let binding = fs::read(config.directory.join("control/binding.json"))?;
    let mut child = OwnedChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "object_cache::tests::stopped_prune_crash_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("SIGNAL_TEST_CACHE_ROOT", root.path())
            .env("SIGNAL_TEST_CACHE_STREAM", stream.to_string())
            .env("SIGNAL_TEST_CACHE_BACKEND", backend.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + std::time::Duration::from_secs(3);
    while !root.path().join("first-unlink-synced").exists() {
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("crash witness unavailable".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(fs::read(root.path().join("first-unlink-synced"))?, b"1");
    child.0.kill()?;
    assert_eq!(child.0.wait()?.signal(), Some(9));
    assert_eq!(fs::read_dir(config.directory.join("objects"))?.count(), 1);
    assert_eq!(
        prune_stopped_materialization(&config, stream, backend, &context())?.removed_files,
        1
    );
    let cache = Cache::open(&config, stream, backend, &context())?;
    for body in [b"copy", b"next"] {
        let rebuilt = cache.materialize(&file(body), body, &context())?;
        assert_eq!(fs::read(rebuilt.path)?, body);
    }
    assert_eq!(
        fs::read(config.directory.join("control/binding.json"))?,
        binding
    );
    assert_eq!(fs::read(original)?, b"retain native original");
    Ok(())
}

#[test]
fn stopped_prune_preserves_temporary_and_unrelated_control_records() -> Result {
    let root = TempDir::new()?;
    let config = config(&root);
    let stream = Uuid::new_v4();
    let backend = Uuid::new_v4();
    let cache = Cache::open(&config, stream, backend, &context())?;
    cache.materialize(&file(b"copy"), b"copy", &context())?;
    drop(cache);
    let binding = fs::read(config.directory.join("control/binding.json"))?;
    for name in [
        "binding.tmp",
        "genesis.tmp",
        "genesis.json",
        "head.tmp",
        "head.json",
    ] {
        let unexpected = config.directory.join("control").join(name);
        fs::write(&unexpected, &binding)?;
        let result = prune_stopped_materialization(&config, stream, backend, &context());
        assert!(unexpected.exists(), "maintenance removed a control record");
        assert_eq!(fs::read(&unexpected)?, binding);
        assert!(matches!(result, Err(StorageError::Corrupt(_))));
        assert_eq!(fs::read_dir(config.directory.join("objects"))?.count(), 1);
        fs::remove_file(unexpected)?;
    }
    Ok(())
}

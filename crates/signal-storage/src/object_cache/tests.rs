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

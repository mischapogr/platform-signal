use signal_event::{IngestEvent, SignalEvent};
use signal_storage::{
    OperationContext, ParquetStore, StorageCompression, StorageConfig, StorageError, StoredEvent,
};
use std::{fs, time::Duration};
use tempfile::TempDir;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
fn config(temp: &TempDir) -> StorageConfig {
    StorageConfig {
        directory: temp.path().join("events"),
        max_batch_events: 10,
        max_batch_bytes: 64 * 1024,
        max_event_bytes: 16 * 1024,
        ..Default::default()
    }
}
fn event(timestamp: &str) -> Result<SignalEvent> {
    let input: IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":timestamp,"source":{"type":"test"},"message":"durable","attributes":{"nested":{"array":[1,true,null,{"name":"preserved"}]}}}),
    )?;
    Ok(input.normalize(chrono::Utc::now())?)
}
fn row(sequence: u64, timestamp: &str) -> Result<StoredEvent> {
    Ok(StoredEvent {
        sequence,
        event: event(timestamp)?,
    })
}
#[tokio::test]
async fn partition_roundtrip_all_compression_and_restart() -> Result {
    for compression in [
        StorageCompression::Snappy,
        StorageCompression::Zstd,
        StorageCompression::Uncompressed,
    ] {
        let temp = TempDir::new()?;
        let mut config = config(&temp);
        config.compression = compression;
        let stream = Uuid::new_v4();
        let store = ParquetStore::open(config.clone(), stream).await?;
        let rows = vec![
            row(1, "2026-10-06T23:59:59.123456789Z")?,
            row(2, "2026-10-07T02:00:00+02:00")?,
        ];
        let receipt = store.append(rows.clone(), context()).await?;
        assert_eq!(receipt.new_count, 2);
        assert!(config.directory.join("date=2026-10-06/hour=23").is_dir());
        assert!(config.directory.join("date=2026-10-07/hour=00").is_dir());
        assert_eq!(store.read_batch(0, 10, 64 * 1024, context()).await?, rows);
        store.shutdown(context()).await?;
        drop(store);
        let store = ParquetStore::open(config, stream).await?;
        assert_eq!(store.read_batch(0, 10, 64 * 1024, context()).await?, rows);
        assert_eq!(store.metrics().high_water, 2);
        store.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn changed_batch_boundaries_replay_prefix_and_append_suffix() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let rows = (1..=5)
        .map(|s| row(s, "2026-10-06T12:00:00Z"))
        .collect::<Result<Vec<_>>>()?;
    let store = ParquetStore::open(config.clone(), stream).await?;
    store.append(rows[..2].to_vec(), context()).await?;
    store.append(rows[2..4].to_vec(), context()).await?;
    store.shutdown(context()).await?;
    let store = ParquetStore::open(config, stream).await?;
    let r = store.append(rows[..1].to_vec(), context()).await?;
    assert_eq!((r.new_count, r.replay_count), (0, 1));
    let r = store.append(rows[1..].to_vec(), context()).await?;
    assert_eq!((r.new_count, r.replay_count), (1, 3));
    assert_eq!(store.read_batch(0, 10, 64 * 1024, context()).await?, rows);
    assert_eq!(store.metrics().persisted, 5);
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn replay_checks_content_and_does_not_deduplicate_independent_ids() -> Result {
    let temp = TempDir::new()?;
    let store = ParquetStore::open(config(&temp), Uuid::new_v4()).await?;
    let first = row(1, "2026-10-06T12:00:00Z")?;
    store.append(vec![first.clone()], context()).await?;
    let mut conflict = first.clone();
    conflict.event.message = Some("changed".into());
    assert!(matches!(
        store.append(vec![conflict], context()).await,
        Err(StorageError::InvalidBatch)
    ));
    let second = StoredEvent {
        sequence: 2,
        event: first.event,
    };
    let r = store.append(vec![second], context()).await?;
    assert_eq!(r.new_count, 1);
    assert_eq!(
        store.read_batch(0, 10, 64 * 1024, context()).await?.len(),
        2
    );
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn gaps_are_allowed_but_missing_replay_sequence_is_not_assumed_persisted() -> Result {
    let temp = TempDir::new()?;
    let store = ParquetStore::open(config(&temp), Uuid::new_v4()).await?;
    let rows = vec![
        row(2, "2026-10-06T12:00:00Z")?,
        row(7, "2026-10-06T12:00:00Z")?,
    ];
    store.append(rows.clone(), context()).await?;
    assert_eq!(store.append(rows, context()).await?.replay_count, 2);
    assert!(matches!(
        store
            .append(vec![row(5, "2026-10-06T12:00:00Z")?], context())
            .await,
        Err(StorageError::InvalidBatch)
    ));
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn dedicated_root_lock_and_stream_binding() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    assert!(matches!(
        ParquetStore::open(config.clone(), stream).await,
        Err(StorageError::Locked)
    ));
    store.shutdown(context()).await?;
    assert!(matches!(
        ParquetStore::open(config, Uuid::new_v4()).await,
        Err(StorageError::StreamMismatch)
    ));
    Ok(())
}
#[tokio::test]
async fn incomplete_owned_files_never_become_visible() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    let rows = vec![row(1, "2026-10-06T12:00:00Z")?];
    store.append(rows.clone(), context()).await?;
    store.shutdown(context()).await?;
    let part = config.directory.join("date=2026-10-06/hour=12");
    let orphan = part.join("batch-00000000000000000002-00000000000000000003.parquet");
    fs::write(&orphan, b"partial")?;
    let temp = part.join("batch-00000000000000000004-00000000000000000004.parquet.tmp");
    fs::write(&temp, b"partial")?;
    let manifest = config
        .directory
        .join("batch-00000000000000000002-00000000000000000003.manifest.tmp");
    fs::write(&manifest, b"partial")?;
    let store = ParquetStore::open(config, stream).await?;
    assert!(!orphan.exists() && !temp.exists() && !manifest.exists());
    assert_eq!(store.read_batch(0, 10, 64 * 1024, context()).await?, rows);
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn corrupt_committed_file_fails_startup() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    store
        .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
        .await?;
    store.shutdown(context()).await?;
    let file = config
        .directory
        .join("date=2026-10-06/hour=12/batch-00000000000000000001-00000000000000000001.parquet");
    let mut bytes = fs::read(&file)?;
    bytes[8] ^= 1;
    fs::write(file, bytes)?;
    assert!(matches!(
        ParquetStore::open(config, stream).await,
        Err(StorageError::Corrupt(_))
    ));
    Ok(())
}
#[tokio::test]
async fn corrupt_committed_manifest_is_not_treated_as_fresh_store() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    store
        .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
        .await?;
    store.shutdown(context()).await?;
    fs::write(
        config
            .directory
            .join("batch-00000000000000000001-00000000000000000001.manifest"),
        b"broken",
    )?;
    assert!(matches!(
        ParquetStore::open(config, stream).await,
        Err(StorageError::Corrupt(_))
    ));
    Ok(())
}
#[tokio::test]
async fn byte_and_file_quotas_keep_store_and_input_bounded() -> Result {
    for files in [false, true] {
        let temp = TempDir::new()?;
        let mut config = config(&temp);
        if files {
            config.max_files = 3;
        } else {
            config.max_disk_bytes = 100;
        }
        let store = ParquetStore::open(config.clone(), Uuid::new_v4()).await?;
        assert!(matches!(
            store
                .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
                .await,
            Err(StorageError::Full)
        ));
        assert_eq!(store.metrics().high_water, 0);
        assert_eq!(store.metrics().full, 1);
        assert!(store.metrics().disk_bytes <= config.max_disk_bytes);
        store.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn bounded_output_writer_removes_partial_publication_after_quota_error() -> Result {
    let temp = TempDir::new()?;
    let mut config = config(&temp);
    config.max_disk_bytes = config.max_batch_events as u64 * 256 + 4096 + 100;
    let store = ParquetStore::open(config.clone(), Uuid::new_v4()).await?;
    assert!(matches!(
        store
            .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
            .await,
        Err(StorageError::Full)
    ));
    assert_eq!(store.metrics().high_water, 0);
    assert!(store.metrics().disk_bytes <= config.max_disk_bytes);
    assert!(
        store
            .read_batch(0, 10, 64 * 1024, context())
            .await?
            .is_empty()
    );
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn validation_cancellation_and_paged_reads() -> Result {
    let temp = TempDir::new()?;
    let store = ParquetStore::open(config(&temp), Uuid::new_v4()).await?;
    let rows = (1..=3)
        .map(|s| row(s, "2026-10-06T12:00:00Z"))
        .collect::<Result<Vec<_>>>()?;
    assert!(matches!(
        store.append(Vec::new(), context()).await,
        Err(StorageError::InvalidBatch)
    ));
    assert!(matches!(
        store
            .append(vec![rows[1].clone(), rows[0].clone()], context())
            .await,
        Err(StorageError::InvalidBatch)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        store.append(rows.clone(), cancelled).await,
        Err(StorageError::Cancelled)
    ));
    let expired = OperationContext::new(Duration::ZERO);
    assert!(matches!(
        store.append(rows.clone(), expired).await,
        Err(StorageError::Timeout)
    ));
    assert_eq!(store.metrics().high_water, 0);
    store.append(rows.clone(), context()).await?;
    assert_eq!(
        store.read_batch(0, 1, 64 * 1024, context()).await?,
        rows[..1]
    );
    assert_eq!(
        store.read_batch(1, 10, 64 * 1024, context()).await?,
        rows[1..]
    );
    assert!(matches!(
        store.read_batch(0, 1, 1, context()).await,
        Err(StorageError::InvalidBatch)
    ));
    store.close();
    assert!(matches!(
        store
            .append(vec![row(4, "2026-10-06T12:00:00Z")?], context())
            .await,
        Err(StorageError::Closed)
    ));
    store.shutdown(context()).await?;
    Ok(())
}
#[cfg(unix)]
#[tokio::test]
async fn unknown_entries_and_symlinks_are_rejected_without_removal() -> Result {
    use std::os::unix::fs::symlink;
    for link in [false, true] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        fs::create_dir(&config.directory)?;
        let unexpected = config.directory.join("unknown");
        if link {
            symlink(temp.path(), &unexpected)?;
        } else {
            fs::write(&unexpected, b"user-owned")?;
        }
        assert!(matches!(
            ParquetStore::open(config, Uuid::new_v4()).await,
            Err(StorageError::Corrupt(_))
        ));
        assert!(unexpected.symlink_metadata().is_ok());
    }
    Ok(())
}

fn replace_manifest_checksum(config: &StorageConfig, parquet: &std::path::Path) -> Result {
    let manifest = config
        .directory
        .join("batch-00000000000000000001-00000000000000000001.manifest");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    let bytes = fs::read(parquet)?;
    value["files"][0]["bytes"] = serde_json::json!(bytes.len());
    value["files"][0]["crc32"] = serde_json::json!(crc32fast::hash(&bytes));
    fs::write(manifest, serde_json::to_vec(&value)?)?;
    Ok(())
}
#[tokio::test]
async fn oversized_compressed_columns_rejected_before_arrow_decode() -> Result {
    use parquet::{
        arrow::ArrowWriter,
        basic::{Compression, ZstdLevel},
        file::properties::WriterProperties,
    };
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    let mut row = row(1, "2026-10-06T12:00:00Z")?;
    store.append(vec![row.clone()], context()).await?;
    store.shutdown(context()).await?;
    row.event.message = Some("x".repeat(1024 * 1024));
    let batch = signal_storage::codec::encode(&[row])?;
    let path = config
        .directory
        .join("date=2026-10-06/hour=12/batch-00000000000000000001-00000000000000000001.parquet");
    let properties = WriterProperties::builder()
        .set_dictionary_enabled(false)
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
        .build();
    let mut writer = ArrowWriter::try_new(
        fs::File::create(&path)?,
        signal_storage::codec::schema(),
        Some(properties),
    )?;
    writer.write(&batch)?;
    writer.close()?;
    assert!(fs::metadata(&path)?.len() < config.max_batch_bytes as u64);
    replace_manifest_checksum(&config, &path)?;
    assert!(matches!(
        ParquetStore::open(config, stream).await,
        Err(StorageError::Corrupt("Parquet allocation bounds"))
    ));
    Ok(())
}
#[tokio::test]
async fn oversized_page_header_rejected_even_when_footer_claims_bounded_column() -> Result {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    let mut row = row(1, "2026-10-06T12:00:00Z")?;
    row.event.message = Some("x".repeat(10_000));
    store.append(vec![row], context()).await?;
    store.shutdown(context()).await?;
    let path = config
        .directory
        .join("date=2026-10-06/hour=12/batch-00000000000000000001-00000000000000000001.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(fs::File::open(&path)?)?;
    let column = builder.metadata().row_group(0).column(2);
    assert!(column.uncompressed_size() < 20_000);
    let mut bytes = fs::read(&path)?;
    let mut at = column.data_page_offset() as usize;
    assert_eq!(bytes[at], 0x15);
    at += 1;
    while bytes[at] & 128 != 0 {
        at += 1;
    }
    at += 1;
    assert_eq!(bytes[at], 0x15);
    at += 1;
    let start = at;
    while bytes[at] & 128 != 0 {
        at += 1;
    }
    assert_eq!(at - start + 1, 3);
    bytes[start..start + 3].copy_from_slice(&[0xfe, 0xff, 0x7f]);
    fs::write(&path, bytes)?;
    replace_manifest_checksum(&config, &path)?;
    assert!(matches!(
        ParquetStore::open(config, stream).await,
        Err(StorageError::Corrupt("Parquet allocation bounds"))
    ));
    Ok(())
}

#[tokio::test]
async fn oversized_footer_list_count_rejected_before_parquet_metadata_allocation() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    store
        .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
        .await?;
    store.shutdown(context()).await?;
    let path = config
        .directory
        .join("date=2026-10-06/hour=12/batch-00000000000000000001-00000000000000000001.parquet");
    let bytes = fs::read(&path)?;
    let footer_len =
        u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into()?) as usize;
    let start = bytes.len() - 8 - footer_len;
    let footer = &bytes[start..bytes.len() - 8];
    // Root row_groups is one struct; its first field is the 20-column list.
    let signature = [0x19, 0x1c, 0x19, 0xfc, 20];
    let positions = footer
        .windows(signature.len())
        .enumerate()
        .filter_map(|(i, w)| (w == signature).then_some(i))
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let at = positions[0] + 1;
    let mut changed = bytes[..start].to_vec();
    changed.extend_from_slice(&footer[..at]);
    changed.extend_from_slice(&[0xfc, 0xff, 0xff, 0xff, 0xff, 0x07]);
    changed.extend_from_slice(&footer[at + 1..]);
    changed.extend_from_slice(&((footer_len + 5) as u32).to_le_bytes());
    changed.extend_from_slice(b"PAR1");
    fs::write(&path, changed)?;
    replace_manifest_checksum(&config, &path)?;
    assert!(matches!(
        ParquetStore::open(config, stream).await,
        Err(StorageError::Corrupt("Parquet allocation bounds"))
    ));
    Ok(())
}

#[tokio::test]
async fn oversized_schema_children_scalar_rejected_before_parquet_schema_allocation() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let stream = Uuid::new_v4();
    let store = ParquetStore::open(config.clone(), stream).await?;
    store
        .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
        .await?;
    store.shutdown(context()).await?;
    let path = config
        .directory
        .join("date=2026-10-06/hour=12/batch-00000000000000000001-00000000000000000001.parquet");
    let bytes = fs::read(&path)?;
    let footer_len =
        u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into()?) as usize;
    let start = bytes.len() - 8 - footer_len;
    let footer = &bytes[start..bytes.len() - 8];
    // Root SchemaElement has 20 children; the next element starts with its type.
    let signature = [0x15, 40, 0, 0x15];
    let positions = footer
        .windows(signature.len())
        .enumerate()
        .filter_map(|(i, w)| (w == signature).then_some(i))
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let at = positions[0] + 1;
    let mut changed = bytes[..start].to_vec();
    changed.extend_from_slice(&footer[..at]);
    changed.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff, 0x0f]);
    changed.extend_from_slice(&footer[at + 1..]);
    changed.extend_from_slice(&((footer_len + 4) as u32).to_le_bytes());
    changed.extend_from_slice(b"PAR1");
    fs::write(&path, changed)?;
    replace_manifest_checksum(&config, &path)?;
    assert!(matches!(
        ParquetStore::open(config, stream).await,
        Err(StorageError::Corrupt("Parquet allocation bounds"))
    ));
    Ok(())
}

fn utc(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(value)?.with_timezone(&chrono::Utc))
}
#[tokio::test]
async fn committed_file_selection_prunes_half_open_utc_hours_and_preserves_year_bounds() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let store = ParquetStore::open(config, Uuid::new_v4()).await?;
    store
        .append(
            vec![
                row(1, "0000-01-01T00:00:00Z")?,
                row(2, "2026-10-06T11:59:59.999999999Z")?,
                row(3, "2026-10-06T12:00:00Z")?,
                row(4, "2026-10-06T12:00:00.000000001Z")?,
                row(5, "2026-10-06T13:00:00Z")?,
                row(6, "9999-12-31T23:59:59.999999999Z")?,
            ],
            context(),
        )
        .await?;
    let selected = store
        .select_files(
            Some(utc("2026-10-06T14:00:00+02:00")?),
            Some(utc("2026-10-06T13:00:00Z")?),
            10,
            context(),
        )
        .await?;
    assert_eq!((selected.files.len(), selected.partitions), (1, 1));
    assert_eq!(selected.files[0].rows, 2);
    assert!(selected.files[0].path.is_absolute());
    assert!(
        selected.files[0]
            .path
            .to_string_lossy()
            .contains("date=2026-10-06/hour=12/")
    );
    assert_eq!(
        fs::metadata(&selected.files[0].path)?.len(),
        selected.files[0].bytes
    );
    let selected = store
        .select_files(
            Some(utc("2026-10-06T11:59:59.999999999Z")?),
            Some(utc("2026-10-06T12:00:00Z")?),
            10,
            context(),
        )
        .await?;
    assert_eq!(selected.files.len(), 1);
    assert!(
        selected.files[0]
            .path
            .to_string_lossy()
            .contains("/hour=11/")
    );
    let selected = store
        .select_files(
            Some(utc("2026-10-06T12:00:00Z")?),
            Some(utc("2026-10-06T12:00:00.000000001Z")?),
            10,
            context(),
        )
        .await?;
    assert_eq!(selected.files.len(), 1);
    assert!(
        selected.files[0]
            .path
            .to_string_lossy()
            .contains("/hour=12/")
    );
    let selected = store
        .select_files(None, Some(utc("0000-01-01T01:00:00Z")?), 10, context())
        .await?;
    assert_eq!(selected.files.len(), 1);
    assert!(
        selected.files[0]
            .path
            .to_string_lossy()
            .contains("date=0000-01-01/")
    );
    let selected = store
        .select_files(Some(utc("9999-01-01T00:00:00Z")?), None, 10, context())
        .await?;
    assert_eq!(selected.files.len(), 1);
    assert!(
        selected.files[0]
            .path
            .to_string_lossy()
            .contains("date=9999-12-31/")
    );
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn file_selection_is_bounded_and_excludes_uncommitted_publications() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let store = ParquetStore::open(config.clone(), Uuid::new_v4()).await?;
    store
        .append(vec![row(1, "2026-10-06T12:00:00Z")?], context())
        .await?;
    store
        .append(vec![row(2, "2026-10-06T12:10:00Z")?], context())
        .await?;
    fs::write(
        config.directory.join(
            "date=2026-10-06/hour=12/batch-00000000000000000003-00000000000000000003.parquet",
        ),
        b"unfinished",
    )?;
    assert!(matches!(
        store.select_files(None, None, 1, context()).await,
        Err(StorageError::Full)
    ));
    assert_eq!(store.metrics().full, 1);
    assert!(!store.metrics().fail_closed);
    let selected = store.select_files(None, None, 2, context()).await?;
    assert_eq!((selected.files.len(), selected.partitions), (2, 1));
    assert_eq!(
        selected.files.iter().map(|file| file.rows).sum::<usize>(),
        2
    );
    let selected = store
        .select_files(Some(utc("2027-01-01T00:00:00Z")?), None, 1, context())
        .await?;
    assert!(selected.files.is_empty());
    assert_eq!(selected.partitions, 0);
    assert!(matches!(
        store.select_files(None, None, 0, context()).await,
        Err(StorageError::InvalidBatch)
    ));
    assert!(matches!(
        store
            .select_files(
                Some(utc("2026-10-06T13:00:00Z")?),
                Some(utc("2026-10-06T12:00:00Z")?),
                10,
                context()
            )
            .await,
        Err(StorageError::InvalidBatch)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        store.select_files(None, None, 10, cancelled).await,
        Err(StorageError::Cancelled)
    ));
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn unrelated_partition_is_not_opened_or_validated_during_selection() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let store = ParquetStore::open(config.clone(), Uuid::new_v4()).await?;
    store
        .append(
            vec![
                row(1, "2026-10-06T12:00:00Z")?,
                row(2, "2026-10-07T00:00:00Z")?,
            ],
            context(),
        )
        .await?;
    // Modify a previously startup-validated committed file while the store runs.
    // A successful bounded selection proves excluded files are not even CRC read.
    let unrelated = config
        .directory
        .join("date=2026-10-07/hour=00/batch-00000000000000000001-00000000000000000002.parquet");
    fs::write(&unrelated, b"corrupt unrelated partition")?;
    let changed_mtime = fs::metadata(&unrelated)?.modified()?;
    let selected = store
        .select_files(
            Some(utc("2026-10-06T12:00:00Z")?),
            Some(utc("2026-10-06T13:00:00Z")?),
            10,
            context(),
        )
        .await?;
    assert_eq!((selected.files.len(), selected.partitions), (1, 1));
    assert_eq!(fs::metadata(&unrelated)?.modified()?, changed_mtime);
    assert!(!store.metrics().fail_closed);
    assert!(matches!(
        store
            .select_files(
                Some(utc("2026-10-07T00:00:00Z")?),
                Some(utc("2026-10-07T01:00:00Z")?),
                10,
                context()
            )
            .await,
        Err(StorageError::Corrupt("committed file contents"))
    ));
    assert!(store.metrics().fail_closed);
    store.shutdown(context()).await?;
    Ok(())
}

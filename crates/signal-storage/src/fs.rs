//! Synchronous engine: every filesystem operation runs on the one storage worker.
use crate::{
    StorageCompression, StorageConfig, StorageError, StorageMetrics, StoreReceipt, StoredEvent,
    codec, event_bytes, validate_batch,
};
use chrono::{DateTime, NaiveDate, Timelike, Utc};
use parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    basic::{Compression, ZstdLevel},
    file::properties::WriterProperties,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    stream_id: Uuid,
    first: u64,
    last: u64,
    rows: usize,
    files: Vec<PublishedFile>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublishedFile {
    path: String,
    bytes: u64,
    crc32: u32,
    rows: usize,
}
pub(crate) struct Engine {
    config: StorageConfig,
    stream_id: Uuid,
    pub metrics: StorageMetrics,
    manifests: BTreeMap<u64, Manifest>,
    _lock: File,
}
fn io(e: std::io::Error) -> StorageError {
    StorageError::Io(e)
}
pub(crate) fn create(path: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io)
}
pub(crate) fn directory(path: &Path) -> Result<(), StorageError> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => return Err(StorageError::Corrupt("directory ownership")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(e)),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    directory(parent)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path).map_err(io)?.is_dir() {
                return Err(StorageError::Corrupt("directory ownership"));
            }
        }
        Err(e) => return Err(io(e)),
    }
    sync_dir(path)?;
    sync_dir(parent)
}
pub(crate) fn sync_dir(path: &Path) -> Result<(), StorageError> {
    File::open(path).map_err(io)?.sync_all().map_err(io)
}
fn range_name(first: u64, last: u64, suffix: &str) -> String {
    format!("batch-{first:020}-{last:020}.{suffix}")
}
fn owned_batch(name: &str, suffix: &str) -> bool {
    let Some(stem) = name.strip_suffix(suffix) else {
        return false;
    };
    let Some(stem) = stem.strip_prefix("batch-") else {
        return false;
    };
    let Some((a, b)) = stem.split_once('-') else {
        return false;
    };
    a.len() == 20
        && b.len() == 20
        && a.bytes().all(|x| x.is_ascii_digit())
        && b.bytes().all(|x| x.is_ascii_digit())
}
fn partition(event: &signal_event::SignalEvent) -> String {
    format!(
        "date={}/hour={:02}",
        event.timestamp.format("%Y-%m-%d"),
        event.timestamp.hour()
    )
}
fn valid_partition(date: &str, hour: &str) -> bool {
    let Some(date) = date.strip_prefix("date=") else {
        return false;
    };
    let Some(hour) = hour.strip_prefix("hour=") else {
        return false;
    };
    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok()
        && hour.len() == 2
        && hour.parse::<u8>().is_ok_and(|h| h < 24)
}
fn relative_file(path: &str) -> bool {
    let parts: Vec<_> = Path::new(path).components().collect();
    if parts.len() != 3 {
        return false;
    }
    let mut text = Vec::with_capacity(3);
    for part in parts {
        let Component::Normal(p) = part else {
            return false;
        };
        let Some(p) = p.to_str() else {
            return false;
        };
        text.push(p);
    }
    valid_partition(text[0], text[1]) && owned_batch(text[2], ".parquet")
}
/// Iteration and every returned metadata map are bounded by max_files, including directories.
fn inventory(
    root: &Path,
    max_files: usize,
) -> Result<(BTreeMap<String, u64>, usize), StorageError> {
    let mut files = BTreeMap::new();
    let mut entries = 0;
    for entry in fs::read_dir(root).map_err(io)? {
        let entry = entry.map_err(io)?;
        entries += 1;
        if entries > max_files {
            return Err(StorageError::Full);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| StorageError::Corrupt("entry name"))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(io)?;
        if metadata.is_file() {
            if name != ".lock"
                && name != "stream-id"
                && name != "stream-id.tmp"
                && !owned_batch(&name, ".manifest")
                && !owned_batch(&name, ".manifest.tmp")
            {
                return Err(StorageError::Corrupt("unknown storage entry"));
            }
            files.insert(name, metadata.len());
            continue;
        }
        if !metadata.is_dir() || !name.starts_with("date=") {
            return Err(StorageError::Corrupt("unknown storage entry"));
        }
        // Validate even empty date directories; parse supports canonical extended years.
        if chrono::NaiveDate::parse_from_str(&name[5..], "%Y-%m-%d").is_err() {
            return Err(StorageError::Corrupt("partition date"));
        }
        for hour in fs::read_dir(entry.path()).map_err(io)? {
            let hour = hour.map_err(io)?;
            entries += 1;
            if entries > max_files {
                return Err(StorageError::Full);
            }
            let h = hour
                .file_name()
                .into_string()
                .map_err(|_| StorageError::Corrupt("partition hour"))?;
            if !valid_partition(&name, &h)
                || !fs::symlink_metadata(hour.path()).map_err(io)?.is_dir()
            {
                return Err(StorageError::Corrupt("partition hour"));
            }
            for file in fs::read_dir(hour.path()).map_err(io)? {
                let file = file.map_err(io)?;
                entries += 1;
                if entries > max_files {
                    return Err(StorageError::Full);
                }
                let f = file
                    .file_name()
                    .into_string()
                    .map_err(|_| StorageError::Corrupt("file name"))?;
                let metadata = fs::symlink_metadata(file.path()).map_err(io)?;
                if !metadata.is_file()
                    || (!owned_batch(&f, ".parquet") && !owned_batch(&f, ".parquet.tmp"))
                {
                    return Err(StorageError::Corrupt("unknown partition entry"));
                }
                files.insert(format!("{name}/{h}/{f}"), metadata.len());
            }
        }
    }
    Ok((files, entries))
}
fn crc_file(path: &Path) -> Result<u32, StorageError> {
    crc_file_context(path, None)
}
fn crc_file_context(
    path: &Path,
    context: Option<&crate::OperationContext>,
) -> Result<u32, StorageError> {
    crate::check_context(context)?;
    let mut file = File::open(path).map_err(io)?;
    let mut hash = crc32fast::Hasher::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        crate::check_context(context)?;
        let n = file.read(&mut buffer).map_err(io)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finalize())
}
fn bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    limit: usize,
) -> Result<T, StorageError> {
    if fs::symlink_metadata(path).map_err(io)?.len() > limit as u64 {
        return Err(StorageError::Corrupt("manifest capacity"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() > limit {
        return Err(StorageError::Corrupt("manifest capacity"));
    }
    serde_json::from_slice(&bytes).map_err(|_| StorageError::Corrupt("manifest encoding"))
}
impl Engine {
    pub fn open(mut config: StorageConfig, stream_id: Uuid) -> Result<Self, StorageError> {
        directory(&config.directory)?;
        config.directory = fs::canonicalize(&config.directory).map_err(io)?;
        let lock_path = config.directory.join(".lock");
        let lock = match fs::symlink_metadata(&lock_path) {
            Ok(m) if m.is_file() => OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(io)?,
            Ok(_) => return Err(StorageError::Corrupt("lock entry")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create(&lock_path)?,
            Err(e) => return Err(io(e)),
        };
        lock.try_lock().map_err(|_| StorageError::Locked)?;
        let (mut files, initial_entries) = inventory(&config.directory, config.max_files)?;
        let initial_bytes = files
            .values()
            .try_fold(0u64, |a, b| a.checked_add(*b))
            .ok_or(StorageError::Full)?;
        if initial_bytes > config.max_disk_bytes {
            return Err(StorageError::Full);
        }
        let identity_path = config.directory.join("stream-id");
        if let Some(bytes) = files.get("stream-id") {
            if *bytes != 36 {
                return Err(StorageError::Corrupt("stream identity"));
            }
            let mut identity = String::new();
            File::open(&identity_path)
                .map_err(io)?
                .take(37)
                .read_to_string(&mut identity)
                .map_err(io)?;
            if Uuid::parse_str(&identity).map_err(|_| StorageError::Corrupt("stream identity"))?
                != stream_id
            {
                return Err(StorageError::StreamMismatch);
            }
        } else {
            if !files.contains_key("stream-id.tmp") && initial_entries >= config.max_files {
                return Err(StorageError::Full);
            }
            if files.keys().any(|p| p.ends_with(".manifest")) {
                return Err(StorageError::Corrupt("missing stream identity"));
            }
            if initial_bytes + 36 > config.max_disk_bytes {
                return Err(StorageError::Full);
            }
            if files.contains_key("stream-id.tmp") {
                fs::remove_file(config.directory.join("stream-id.tmp")).map_err(io)?;
                files.remove("stream-id.tmp");
            }
            let mut file = create(&config.directory.join("stream-id.tmp"))?;
            file.write_all(stream_id.to_string().as_bytes())
                .map_err(io)?;
            file.sync_all().map_err(io)?;
            fs::rename(config.directory.join("stream-id.tmp"), &identity_path).map_err(io)?;
            sync_dir(&config.directory)?;
            files.insert("stream-id".into(), 36);
        }
        let mut engine = Self {
            metrics: StorageMetrics {
                disk_capacity: config.max_disk_bytes,
                file_capacity: config.max_files,
                ..Default::default()
            },
            config,
            stream_id,
            manifests: BTreeMap::new(),
            _lock: lock,
        };
        let mut referenced = BTreeSet::new();
        for (name, _) in files.iter().filter(|(name, _)| name.ends_with(".manifest")) {
            let manifest: Manifest = bounded_json(
                &engine.config.directory.join(name),
                engine.config.manifest_limit(),
            )?;
            if manifest.schema_version != 1
                || manifest.stream_id != stream_id
                || manifest.first == 0
                || manifest.last < manifest.first
                || manifest.rows == 0
                || manifest.rows > engine.config.max_batch_events
                || manifest.files.is_empty()
                || manifest.files.len() > manifest.rows
                || *name != range_name(manifest.first, manifest.last, "manifest")
            {
                return Err(StorageError::Corrupt("manifest contract"));
            }
            for file in &manifest.files {
                if !relative_file(&file.path)
                    || file.bytes > engine.config.file_limit()
                    || file.rows == 0
                    || file.rows > manifest.rows
                    || files.get(&file.path) != Some(&file.bytes)
                    || !referenced.insert(file.path.clone())
                    || crc_file(&engine.config.directory.join(&file.path))? != file.crc32
                {
                    return Err(StorageError::Corrupt("committed file"));
                }
            }
            if engine.manifests.insert(manifest.first, manifest).is_some() {
                return Err(StorageError::Corrupt("duplicate manifest"));
            }
        }
        let mut high_water = 0;
        let mut persisted = 0u64;
        for manifest in engine.manifests.values() {
            if manifest.first <= high_water {
                return Err(StorageError::Corrupt("manifest sequence order"));
            }
            let rows = engine.read_manifest(manifest)?;
            if rows.len() != manifest.rows
                || rows.first().map(|r| r.sequence) != Some(manifest.first)
                || rows.last().map(|r| r.sequence) != Some(manifest.last)
            {
                return Err(StorageError::Corrupt("manifest sequence coverage"));
            }
            high_water = manifest.last;
            persisted += manifest.rows as u64;
        }
        // Only strictly recognized owned unfinished publications are removed, while holding the lock.
        for name in files.keys() {
            if name == "stream-id.tmp"
                || name.ends_with(".tmp")
                || (name.ends_with(".parquet") && !referenced.contains(name))
            {
                let path = engine.config.directory.join(name);
                fs::remove_file(&path).map_err(io)?;
                if let Some(parent) = path.parent() {
                    sync_dir(parent)?;
                }
            }
        }
        sync_dir(&engine.config.directory)?;
        engine.metrics.high_water = high_water;
        engine.metrics.persisted = persisted;
        engine.refresh()?;
        Ok(engine)
    }
    fn refresh(&mut self) -> Result<(), StorageError> {
        let (files, entries) = inventory(&self.config.directory, self.config.max_files)?;
        self.metrics.disk_bytes = files
            .values()
            .try_fold(0u64, |a, b| a.checked_add(*b))
            .ok_or(StorageError::Full)?;
        self.metrics.files = entries;
        if self.metrics.disk_bytes > self.config.max_disk_bytes {
            return Err(StorageError::Full);
        }
        Ok(())
    }
    fn inspect_file(
        &self,
        file: &PublishedFile,
        context: Option<&crate::OperationContext>,
    ) -> Result<ParquetRecordBatchReaderBuilder<File>, StorageError> {
        crate::check_context(context)?;
        let path = self.config.directory.join(&file.path);
        let metadata = fs::symlink_metadata(&path).map_err(io)?;
        if !metadata.is_file()
            || metadata.len() != file.bytes
            || crc_file_context(&path, context)? != file.crc32
        {
            return Err(StorageError::Corrupt("committed file contents"));
        }
        let mut input = File::open(path).map_err(io)?;
        let footer_start = crate::pages::footer(&mut input, file.bytes, &self.config, context)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(input.try_clone().map_err(io)?)
            .map_err(|_| StorageError::Corrupt("Parquet footer"))?;
        if builder.schema() != &codec::schema()
            || builder.metadata().file_metadata().num_rows() != file.rows as i64
        {
            return Err(StorageError::Corrupt("Parquet schema or rows"));
        }
        crate::pages::check(
            &mut input,
            footer_start,
            builder.metadata(),
            &self.config,
            context,
        )?;
        Ok(builder)
    }
    fn read_manifest(&self, manifest: &Manifest) -> Result<Vec<StoredEvent>, StorageError> {
        let mut rows = Vec::with_capacity(manifest.rows);
        let mut bytes = 0usize;
        for file in &manifest.files {
            let builder = self.inspect_file(file, None)?;
            let mut reader = builder
                .with_batch_size(self.config.max_batch_events.min(128))
                .build()
                .map_err(|_| StorageError::Corrupt("Parquet reader"))?;
            let start = rows.len();
            for batch in &mut reader {
                let batch = batch.map_err(|_| StorageError::Corrupt("Parquet data"))?;
                for row in codec::decode(&batch)? {
                    bytes = bytes
                        .checked_add(
                            event_bytes(&row.event, self.config.max_event_bytes)
                                .map_err(|_| StorageError::Corrupt("event capacity"))?,
                        )
                        .ok_or(StorageError::Corrupt("batch capacity"))?;
                    if rows.len() >= manifest.rows
                        || bytes > self.config.max_batch_bytes
                        || partition(&row.event)
                            != file.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
                    {
                        return Err(StorageError::Corrupt("partition or batch capacity"));
                    }
                    rows.push(row);
                }
            }
            if rows.len() - start != file.rows {
                return Err(StorageError::Corrupt("file row count"));
            }
        }
        rows.sort_unstable_by_key(|r| r.sequence);
        validate_batch(&rows, &self.config)
            .map_err(|_| StorageError::Corrupt("stored sequence order"))?;
        Ok(rows)
    }
    pub fn read(
        &self,
        after: u64,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        let mut output = Vec::new();
        let mut bytes = 0;
        for manifest in self.manifests.values().filter(|m| m.last > after) {
            for row in self.read_manifest(manifest)? {
                if row.sequence <= after {
                    continue;
                }
                let size = event_bytes(&row.event, self.config.max_event_bytes)?;
                if size > max_bytes.saturating_sub(bytes) {
                    if output.is_empty() {
                        return Err(StorageError::InvalidBatch);
                    }
                    return Ok(output);
                }
                bytes += size;
                output.push(row);
                if output.len() == max_events {
                    return Ok(output);
                }
            }
        }
        Ok(output)
    }
    pub fn select_files(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        max_files: usize,
        context: &crate::OperationContext,
    ) -> Result<crate::FileSelection, StorageError> {
        let mut files = Vec::new();
        let mut partitions = BTreeSet::new();
        for manifest in self.manifests.values() {
            for file in &manifest.files {
                if context.cancellation.is_cancelled() {
                    return Err(StorageError::Cancelled);
                }
                if tokio::time::Instant::now() >= context.deadline {
                    return Err(StorageError::Timeout);
                }
                let (partition, _) = file
                    .path
                    .rsplit_once('/')
                    .ok_or(StorageError::Corrupt("partition path"))?;
                let (date, hour) = partition
                    .split_once('/')
                    .ok_or(StorageError::Corrupt("partition path"))?;
                let date = NaiveDate::parse_from_str(
                    date.strip_prefix("date=")
                        .ok_or(StorageError::Corrupt("partition date"))?,
                    "%Y-%m-%d",
                )
                .map_err(|_| StorageError::Corrupt("partition date"))?;
                let hour = hour
                    .strip_prefix("hour=")
                    .and_then(|hour| hour.parse::<u32>().ok())
                    .ok_or(StorageError::Corrupt("partition hour"))?;
                let start = date
                    .and_hms_opt(hour, 0, 0)
                    .ok_or(StorageError::Corrupt("partition hour"))?
                    .and_utc();
                let end = start.checked_add_signed(chrono::Duration::hours(1));
                if from.is_some_and(|from| end.is_some_and(|end| end <= from))
                    || to.is_some_and(|to| start >= to)
                {
                    continue;
                }
                if files.len() >= max_files || files.len() >= self.config.max_files {
                    return Err(StorageError::Full);
                }
                // Only selected files undergo filesystem checks. Unrelated partitions
                // remain unopened; startup already validated the canonical rows.
                let inspected = self.inspect_file(file, Some(context))?;
                let uncompressed_bytes = inspected
                    .metadata()
                    .row_groups()
                    .iter()
                    .flat_map(|group| group.columns())
                    .try_fold(0u64, |sum, column| {
                        let bytes = u64::try_from(column.uncompressed_size())
                            .map_err(|_| StorageError::Corrupt("Parquet allocation bounds"))?;
                        sum.checked_add(bytes)
                            .ok_or(StorageError::Corrupt("Parquet allocation bounds"))
                    })?;
                partitions.insert(partition.to_owned());
                files.push(crate::PublishedFile {
                    path: self.config.directory.join(&file.path),
                    rows: file.rows,
                    bytes: file.bytes,
                    uncompressed_bytes,
                });
            }
        }
        Ok(crate::FileSelection {
            files,
            partitions: partitions.len(),
        })
    }
    pub fn append(&mut self, batch: Vec<StoredEvent>) -> Result<StoreReceipt, StorageError> {
        validate_batch(&batch, &self.config)?;
        let first = batch[0].sequence;
        let last = batch[batch.len() - 1].sequence;
        let replay_count = batch
            .iter()
            .take_while(|r| r.sequence <= self.metrics.high_water)
            .count();
        if replay_count > 0 {
            let replay = &batch[..replay_count];
            let mut checked = 0;
            for manifest in self
                .manifests
                .values()
                .filter(|m| m.last >= first && m.first <= replay[replay.len() - 1].sequence)
            {
                for stored in self.read_manifest(manifest)? {
                    if checked < replay.len() && stored.sequence == replay[checked].sequence {
                        if stored.event != replay[checked].event {
                            return Err(StorageError::InvalidBatch);
                        }
                        checked += 1;
                    }
                }
            }
            if checked != replay.len() {
                return Err(StorageError::InvalidBatch);
            }
        }
        let new_count = batch.len() - replay_count;
        if new_count == 0 {
            self.metrics.replayed += replay_count as u64;
            return Ok(StoreReceipt {
                first_sequence: first,
                last_sequence: last,
                new_count,
                replay_count,
            });
        }
        let suffix = &batch[replay_count..];
        let mut partitions: BTreeMap<String, Vec<StoredEvent>> = BTreeMap::new();
        for row in suffix {
            partitions
                .entry(partition(&row.event))
                .or_default()
                .push(row.clone());
        }
        self.refresh()?;
        let required_entries = partitions
            .len()
            .checked_mul(3)
            .and_then(|n| n.checked_add(1))
            .ok_or(StorageError::Full)?;
        if required_entries > self.config.max_files.saturating_sub(self.metrics.files) {
            return Err(StorageError::Full);
        }
        let manifest_reserve = self.config.manifest_limit() as u64;
        if manifest_reserve
            >= self
                .config
                .max_disk_bytes
                .saturating_sub(self.metrics.disk_bytes)
        {
            return Err(StorageError::Full);
        }
        let mut manifest = Manifest {
            schema_version: 1,
            stream_id: self.stream_id,
            first: suffix[0].sequence,
            last,
            rows: new_count,
            files: Vec::with_capacity(partitions.len()),
        };
        let mut available = self.config.max_disk_bytes - self.metrics.disk_bytes - manifest_reserve;
        let outcome = (|| {
            for (part, rows) in partitions {
                let parent = self.config.directory.join(&part);
                directory(&parent)?;
                let name = range_name(manifest.first, last, "parquet");
                let relative = format!("{part}/{name}");
                let temp = parent.join(format!("{name}.tmp"));
                let final_path = parent.join(&name);
                let file = create(&temp)?;
                let compression = match self.config.compression {
                    StorageCompression::Snappy => Compression::SNAPPY,
                    StorageCompression::Zstd => Compression::ZSTD(ZstdLevel::default()),
                    StorageCompression::Uncompressed => Compression::UNCOMPRESSED,
                };
                let properties = WriterProperties::builder()
                    .set_compression(compression)
                    .set_dictionary_enabled(false)
                    .set_max_row_group_row_count(Some(self.config.max_batch_events.min(128)))
                    .set_write_batch_size(128)
                    .set_data_page_size_limit(64 * 1024)
                    .build();
                let mut writer = ArrowWriter::try_new(
                    QuotaWriter {
                        file,
                        bytes: 0,
                        limit: available.min(self.config.file_limit()),
                        full: false,
                    },
                    codec::schema(),
                    Some(properties),
                )
                .map_err(|_| StorageError::Corrupt("writer creation"))?;
                for chunk in rows.chunks(128) {
                    let batch = codec::encode(chunk)?;
                    let result = writer.write(&batch);
                    if result.is_err() {
                        return Err(if writer.inner().full {
                            StorageError::Full
                        } else {
                            StorageError::Io(std::io::Error::other("Parquet write"))
                        });
                    }
                    if writer.memory_size() > self.config.max_batch_bytes
                        || writer.in_progress_size() > self.config.max_batch_bytes
                    {
                        writer.flush().map_err(|_| {
                            StorageError::Io(std::io::Error::other("Parquet flush"))
                        })?;
                    }
                }
                let result = writer.finish();
                if result.is_err() {
                    return Err(if writer.inner().full {
                        StorageError::Full
                    } else {
                        StorageError::Io(std::io::Error::other("Parquet footer"))
                    });
                }
                let bytes = writer.inner().bytes;
                writer.inner().file.sync_all().map_err(io)?;
                drop(writer);
                fs::rename(&temp, &final_path).map_err(io)?;
                sync_dir(&parent)?;
                available = available.checked_sub(bytes).ok_or(StorageError::Full)?;
                manifest.files.push(PublishedFile {
                    path: relative,
                    bytes,
                    crc32: crc_file(&final_path)?,
                    rows: rows.len(),
                });
            }
            let encoded = serde_json::to_vec(&manifest).map_err(|_| StorageError::InvalidBatch)?;
            if encoded.len() > self.config.manifest_limit() {
                return Err(StorageError::Full);
            }
            let name = range_name(manifest.first, last, "manifest");
            let temp = self.config.directory.join(format!("{name}.tmp"));
            let mut file = create(&temp)?;
            file.write_all(&encoded).map_err(io)?;
            file.sync_all().map_err(io)?;
            fs::rename(&temp, self.config.directory.join(name)).map_err(io)?;
            sync_dir(&self.config.directory)?;
            Ok(())
        })();
        if let Err(error) = outcome {
            if matches!(error, StorageError::Full) {
                self.clean_unpublished(&manifest)?;
                self.refresh()?;
            }
            return Err(error);
        }
        self.metrics.high_water = last;
        self.metrics.persisted += new_count as u64;
        self.metrics.replayed += replay_count as u64;
        self.manifests.insert(manifest.first, manifest);
        self.refresh()?;
        Ok(StoreReceipt {
            first_sequence: first,
            last_sequence: last,
            new_count,
            replay_count,
        })
    }
    fn clean_unpublished(&self, manifest: &Manifest) -> Result<(), StorageError> {
        let name = range_name(manifest.first, manifest.last, "parquet");
        for date in fs::read_dir(&self.config.directory).map_err(io)? {
            let date = date.map_err(io)?;
            if !date.file_type().map_err(io)?.is_dir() {
                continue;
            }
            for hour in fs::read_dir(date.path()).map_err(io)? {
                let hour = hour.map_err(io)?;
                if !hour.file_type().map_err(io)?.is_dir() {
                    continue;
                }
                for suffix in [name.clone(), format!("{name}.tmp")] {
                    let path = hour.path().join(suffix);
                    match fs::remove_file(path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(io(e)),
                    }
                }
                sync_dir(&hour.path())?;
            }
        }
        Ok(())
    }
    pub fn flush(&self) -> Result<(), StorageError> {
        sync_dir(&self.config.directory)
    }
}
struct QuotaWriter {
    file: File,
    bytes: u64,
    limit: u64,
    full: bool,
}
impl Write for QuotaWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() as u64 > self.limit.saturating_sub(self.bytes) {
            self.full = true;
            return Err(std::io::Error::other("storage capacity"));
        }
        let count = self.file.write(buffer)?;
        self.bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

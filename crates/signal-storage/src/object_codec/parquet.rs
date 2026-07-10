use super::*;
use crate::{StorageCompression, codec, event_bytes, object_manifest::sha256, validate_batch};
use ::parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    basic::{Compression, ZstdLevel},
    file::properties::WriterProperties,
};
use chrono::Timelike;
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
};
struct Quota {
    bytes: Vec<u8>,
    limit: usize,
    full: bool,
}
impl Write for Quota {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.full = true;
            return Err(std::io::Error::other("object capacity"));
        }
        if self.bytes.capacity() - self.bytes.len() < bytes.len() {
            self.bytes
                .try_reserve_exact(bytes.len())
                .map_err(|_| std::io::Error::other("object allocation"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn failure(full: bool) -> StorageError {
    if full {
        StorageError::Full
    } else {
        StorageError::Corrupt("object Parquet encoding")
    }
}
type Prepared = (u64, u64, usize, Vec<PreparedQueryFile>);
pub(super) fn encode(
    rows: Vec<StoredEvent>,
    config: &StorageConfig,
    limits: ManifestLimits,
    context: &OperationContext,
) -> Result<Prepared, StorageError> {
    check_context(Some(context))?;
    validate_batch(&rows, config)?;
    let first = rows.first().ok_or(StorageError::InvalidBatch)?.sequence;
    let last = rows.last().ok_or(StorageError::InvalidBatch)?.sequence;
    let events = rows.len();
    let mut partitions = BTreeMap::<(String, u8), Vec<StoredEvent>>::new();
    for row in rows {
        check_context(Some(context))?;
        let key = (
            row.event.timestamp.format("%Y-%m-%d").to_string(),
            row.event.timestamp.hour() as u8,
        );
        if !partitions.contains_key(&key) && partitions.len() >= limits.files {
            return Err(StorageError::Full);
        }
        partitions.entry(key).or_default().push(row);
    }
    let mut files = Vec::with_capacity(partitions.len());
    let mut available = limits.batch_object_bytes;
    let mut decoded_available = limits.decoded_bytes;
    for ((date, hour), rows) in partitions {
        check_context(Some(context))?;
        let compression = match config.compression {
            StorageCompression::Snappy => Compression::SNAPPY,
            StorageCompression::Zstd => Compression::ZSTD(ZstdLevel::default()),
            StorageCompression::Uncompressed => Compression::UNCOMPRESSED,
        };
        let properties = WriterProperties::builder()
            .set_compression(compression)
            .set_dictionary_enabled(false)
            .set_max_row_group_row_count(Some(config.max_batch_events.min(128)))
            .set_write_batch_size(128)
            .set_data_page_size_limit(64 * 1024)
            .build();
        let mut quota = Quota {
            bytes: Vec::new(),
            limit: available.min(limits.object_bytes).min(config.file_limit()) as usize,
            full: false,
        };
        let mut writer = ArrowWriter::try_new(&mut quota, codec::schema(), Some(properties))
            .map_err(|_| StorageError::Corrupt("object writer"))?;
        for chunk in rows.chunks(128) {
            check_context(Some(context))?;
            if writer.write(&codec::encode(chunk)?).is_err() {
                return Err(failure(writer.inner().full));
            }
            if (writer.memory_size() > config.max_batch_bytes
                || writer.in_progress_size() > config.max_batch_bytes)
                && writer.flush().is_err()
            {
                return Err(failure(writer.inner().full));
            }
        }
        if writer.finish().is_err() {
            return Err(failure(writer.inner().full));
        }
        // finish writes the footer once; into_inner would attempt a second one.
        // The quota remains owned here and is exposed only after writer drop.
        drop(writer);
        if quota.bytes.capacity() > quota.limit {
            return Err(StorageError::Full);
        }
        available = available
            .checked_sub(quota.bytes.capacity() as u64)
            .ok_or(StorageError::Full)?;
        let body = Bytes::from(quota.bytes);
        let (restored, decoded_bytes) = read(
            body.clone(),
            &date,
            hour,
            first,
            last,
            rows.len(),
            config,
            context,
            decoded_available,
            None,
        )?;
        if restored != rows || decoded_bytes > decoded_available {
            return Err(StorageError::Corrupt(
                "object roundtrip or decoded capacity",
            ));
        }
        decoded_available -= decoded_bytes;
        files.push(PreparedQueryFile {
            date,
            hour,
            sha256: sha256(&body),
            body,
            rows: rows.len(),
            decoded_bytes,
        });
    }
    Ok((first, last, events, files))
}
pub(super) fn inspect(
    file: &QueryFile,
    bytes: Vec<u8>,
    first: u64,
    last: u64,
    config: &StorageConfig,
    limits: ManifestLimits,
    context: &OperationContext,
) -> Result<Vec<StoredEvent>, StorageError> {
    check_context(Some(context))?;
    file.object
        .verify_bytes(&bytes, limits.object_bytes)
        .map_err(|_| StorageError::Corrupt("object reference"))?;
    if file.rows == 0
        || file.rows > config.max_batch_events.min(limits.events)
        || file.decoded_bytes == 0
        || file.decoded_bytes > limits.decoded_bytes
    {
        return Err(StorageError::Corrupt("object rows or decoded capacity"));
    }
    let (rows, decoded) = read(
        Bytes::from(bytes),
        &file.date,
        file.hour,
        first,
        last,
        file.rows,
        config,
        context,
        limits.decoded_bytes,
        Some(file.decoded_bytes),
    )?;
    if decoded != file.decoded_bytes {
        return Err(StorageError::Corrupt("object decoded size"));
    }
    Ok(rows)
}
#[allow(clippy::too_many_arguments)] // Exact selected reference bounds stay explicit.
fn read(
    body: Bytes,
    date: &str,
    hour: u8,
    first: u64,
    last: u64,
    count: usize,
    config: &StorageConfig,
    context: &OperationContext,
    decoded_cap: u64,
    expected_decoded: Option<u64>,
) -> Result<(Vec<StoredEvent>, u64), StorageError> {
    check_context(Some(context))?;
    if first == 0
        || last < first
        || count == 0
        || count > config.max_batch_events
        || body.len() as u64 > config.file_limit()
    {
        return Err(StorageError::Corrupt("object bounds"));
    }
    let mut input = Cursor::new(body.clone());
    let footer = crate::pages::footer(&mut input, body.len() as u64, config, Some(context))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(body)
        .map_err(|_| StorageError::Corrupt("object footer"))?;
    if builder.schema() != &codec::schema()
        || builder.metadata().file_metadata().num_rows() != count as i64
    {
        return Err(StorageError::Corrupt("object schema or rows"));
    }
    let decoded = builder
        .metadata()
        .row_groups()
        .iter()
        .try_fold(0u64, |total, group| {
            group.columns().iter().try_fold(total, |sum, col| {
                let bytes = u64::try_from(col.uncompressed_size())
                    .map_err(|_| StorageError::Corrupt("object decoded size"))?;
                sum.checked_add(bytes)
                    .ok_or(StorageError::Corrupt("object decoded size"))
            })
        })?;
    // Reject the real decoded budget before page decompression/Arrow allocation.
    if decoded > decoded_cap || expected_decoded.is_some_and(|expected| expected != decoded) {
        return Err(StorageError::Corrupt("object decoded size"));
    }
    crate::pages::check(
        &mut input,
        footer,
        builder.metadata(),
        config,
        Some(context),
    )?;
    let mut reader = builder
        .with_batch_size(config.max_batch_events.min(128))
        .build()
        .map_err(|_| StorageError::Corrupt("object reader"))?;
    let mut rows = Vec::with_capacity(count);
    let mut bytes = 0usize;
    let mut nodes = 0usize;
    let node_limit = super::intake::wire_node_limit(count)?;
    for batch in &mut reader {
        check_context(Some(context))?;
        let batch = batch.map_err(|_| StorageError::Corrupt("object pages"))?;
        let json = batch
            .column(2)
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .ok_or(StorageError::Corrupt("object JSON column"))?;
        for index in 0..batch.num_rows() {
            let raw = json.value(index).as_bytes();
            bytes = bytes.checked_add(raw.len()).ok_or(StorageError::Full)?;
            if bytes > config.max_batch_bytes {
                return Err(StorageError::Corrupt("object JSON bounds"));
            }
            let used = super::intake::json_preflight(
                raw,
                config.max_event_bytes,
                node_limit.saturating_sub(nodes),
                context,
            )
            .map_err(|error| match error {
                StorageError::Timeout | StorageError::Cancelled => error,
                _ => StorageError::Corrupt("object JSON bounds"),
            })?;
            nodes += used;
        }
        for row in codec::decode(&batch)? {
            check_context(Some(context))?;
            event_bytes(&row.event, config.max_event_bytes)?;
            if rows.len() >= count
                || bytes > config.max_batch_bytes
                || row.sequence < first
                || row.sequence > last
                || row.event.timestamp.format("%Y-%m-%d").to_string() != date
                || row.event.timestamp.hour() != hour as u32
            {
                return Err(StorageError::Corrupt("object sequence/partition/bytes"));
            }
            rows.push(row);
        }
    }
    if rows.len() != count {
        return Err(StorageError::Corrupt("object row count"));
    }
    validate_batch(&rows, config).map_err(|_| StorageError::Corrupt("object sequence ordering"))?;
    Ok((rows, decoded))
}

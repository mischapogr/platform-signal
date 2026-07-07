//! Preflight owned Parquet data before any page decompression or Arrow allocation.
//! Compact Thrift page headers use bounded read-ahead, never payload-sized allocation.
use crate::{OperationContext, StorageConfig, StorageError, check_context};
use parquet::file::metadata::ParquetMetaData;
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
};
// One fixed buffer per active footer/page header; logical parser budgets below
// remain independent of read-ahead. Absolute seeks position each subsequent page.
const HEADER_BUFFER_BYTES: usize = 1024;

fn corrupt() -> StorageError {
    StorageError::Corrupt("Parquet allocation bounds")
}
pub(crate) fn footer(
    file: &mut File,
    length: u64,
    config: &StorageConfig,
    context: Option<&OperationContext>,
) -> Result<u64, StorageError> {
    check_context(context)?;
    if length < 12 {
        return Err(corrupt());
    }
    file.seek(SeekFrom::End(-8)).map_err(StorageError::Io)?;
    let mut tail = [0; 8];
    file.read_exact(&mut tail).map_err(StorageError::Io)?;
    let bytes = u32::from_le_bytes(tail[..4].try_into().map_err(|_| corrupt())?) as u64;
    if &tail[4..] != b"PAR1"
        || bytes > 64 * 1024 + config.max_batch_events as u64 * 128
        || bytes > length - 12
    {
        return Err(corrupt());
    }
    let start = length - 8 - bytes;
    file.seek(SeekFrom::Start(start))
        .map_err(StorageError::Io)?;
    let mut preflight = Header {
        file: BufReader::with_capacity(HEADER_BUFFER_BYTES, file),
        bytes: 0,
        limit: bytes as usize,
        container_limit: config.max_batch_events.max(128),
        context,
    };
    preflight.metadata(crate::codec::schema().fields().len())?;
    if preflight.bytes != bytes as usize {
        return Err(corrupt());
    }
    Ok(start)
}
pub(crate) fn check(
    file: &mut File,
    footer_start: u64,
    metadata: &ParquetMetaData,
    config: &StorageConfig,
    context: Option<&OperationContext>,
) -> Result<(), StorageError> {
    check_context(context)?;
    let columns = crate::codec::schema().fields().len();
    let rows = metadata.file_metadata().num_rows();
    if rows <= 0
        || rows > config.max_batch_events as i64
        || metadata.num_row_groups() > config.max_batch_events
    {
        return Err(corrupt());
    }
    let budget = config.max_batch_bytes as u64 * 4 + rows as u64 * 1024 + 64 * 1024;
    let page_budget = config.max_batch_bytes as u64 * 4 + 128 * 1024 + 64 * 1024;
    let mut uncompressed = 0u64;
    for group in metadata.row_groups() {
        check_context(context)?;
        if group.num_rows() <= 0
            || group.num_rows() > config.max_batch_events.min(128) as i64
            || group.num_columns() != columns
            || group.total_byte_size() < 0
        {
            return Err(corrupt());
        }
        for column in group.columns() {
            check_context(context)?;
            if column.num_values() != group.num_rows()
                || column.uncompressed_size() < 0
                || column.compressed_size() < 0
                || column.dictionary_page_offset().is_some()
                || column.data_page_offset() < 4
            {
                return Err(corrupt());
            }
            let start = column.data_page_offset() as u64;
            let length = column.compressed_size() as u64;
            let end = start.checked_add(length).ok_or_else(corrupt)?;
            if end > footer_start {
                return Err(corrupt());
            }
            uncompressed = uncompressed
                .checked_add(column.uncompressed_size() as u64)
                .ok_or_else(corrupt)?;
            if uncompressed > budget {
                return Err(corrupt());
            }
            let mut at = start;
            let mut page_total = 0u64;
            let mut pages = 0usize;
            while at < end {
                check_context(context)?;
                pages += 1;
                if pages > config.max_batch_events + 1 {
                    return Err(corrupt());
                }
                file.seek(SeekFrom::Start(at)).map_err(StorageError::Io)?;
                let mut header = Header {
                    file: BufReader::with_capacity(HEADER_BUFFER_BYTES, &mut *file),
                    bytes: 0,
                    limit: 64 * 1024,
                    container_limit: 1024,
                    context,
                };
                let (page_type, raw, compressed) = header.page()?;
                if !matches!(page_type, 0 | 3)
                    || raw <= 0
                    || compressed < 0
                    || raw as u64 > page_budget
                {
                    return Err(corrupt());
                }
                let header_bytes = header.bytes as u64;
                page_total = page_total
                    .checked_add(raw as u64 + header_bytes)
                    .ok_or_else(corrupt)?;
                if page_total > column.uncompressed_size() as u64 {
                    return Err(corrupt());
                }
                at = at
                    .checked_add(header_bytes)
                    .and_then(|n| n.checked_add(compressed as u64))
                    .ok_or_else(corrupt)?;
                if at > end {
                    return Err(corrupt());
                }
            }
            if at != end || page_total != column.uncompressed_size() as u64 {
                return Err(corrupt());
            }
        }
    }
    Ok(())
}
struct Header<'a> {
    file: BufReader<&'a mut File>,
    bytes: usize,
    limit: usize,
    container_limit: usize,
    context: Option<&'a OperationContext>,
}
impl Header<'_> {
    // The storage contract is a flat schema. Check num_children before the
    // Parquet parser uses that scalar to allocate a children Vec.
    fn schema_element(&mut self, root: bool, columns: usize) -> Result<(), StorageError> {
        let mut id = 0;
        let mut children = None;
        for _ in 0..128 {
            let field = self.byte()?;
            if field == 0 {
                if (root && children != Some(columns as i64))
                    || (!root && children.is_some_and(|n| n != 0))
                {
                    return Err(corrupt());
                }
                return Ok(());
            }
            id = self.field_id(id, field)?;
            if id == 5 {
                if field & 15 != 5 || children.is_some() {
                    return Err(corrupt());
                }
                children = Some(self.signed()?);
            } else {
                self.skip(field & 15, 1, true)?;
            }
        }
        Err(corrupt())
    }
    fn metadata(&mut self, columns: usize) -> Result<(), StorageError> {
        let mut id = 0;
        let mut schema = false;
        for _ in 0..128 {
            let field = self.byte()?;
            if field == 0 {
                return if schema { Ok(()) } else { Err(corrupt()) };
            }
            id = self.field_id(id, field)?;
            if id == 2 {
                if field & 15 != 9 || schema {
                    return Err(corrupt());
                }
                let header = self.byte()?;
                let count = if header >> 4 == 15 {
                    self.unsigned()?
                } else {
                    (header >> 4) as u64
                };
                if header & 15 != 12 || count != columns as u64 + 1 {
                    return Err(corrupt());
                }
                for element in 0..count {
                    self.schema_element(element == 0, columns)?;
                }
                schema = true;
            } else {
                self.skip(field & 15, 1, true)?;
            }
        }
        Err(corrupt())
    }
    fn byte(&mut self) -> Result<u8, StorageError> {
        if self.bytes.is_multiple_of(1024) {
            check_context(self.context)?;
        }
        if self.bytes >= self.limit {
            return Err(corrupt());
        }
        let mut b = [0];
        self.file.read_exact(&mut b).map_err(StorageError::Io)?;
        self.bytes += 1;
        Ok(b[0])
    }
    fn unsigned(&mut self) -> Result<u64, StorageError> {
        let mut n = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.byte()?;
            if shift == 63 && b > 1 {
                return Err(corrupt());
            }
            n |= ((b & 127) as u64) << shift;
            if b & 128 == 0 {
                return Ok(n);
            }
        }
        Err(corrupt())
    }
    fn signed(&mut self) -> Result<i64, StorageError> {
        let n = self.unsigned()?;
        Ok((n >> 1) as i64 ^ -((n & 1) as i64))
    }
    fn advance(&mut self, count: u64) -> Result<(), StorageError> {
        check_context(self.context)?;
        if count > self.limit.saturating_sub(self.bytes) as u64 {
            return Err(corrupt());
        }
        self.file
            .seek_relative(count as i64)
            .map_err(StorageError::Io)?;
        self.bytes += count as usize;
        Ok(())
    }
    fn skip(&mut self, kind: u8, depth: usize, field: bool) -> Result<(), StorageError> {
        if depth > 16 {
            return Err(corrupt());
        }
        match kind {
            1 | 2 => {
                if !field {
                    let _ = self.byte()?;
                }
            }
            3 => {
                let _ = self.byte()?;
            }
            4..=6 => {
                let _ = self.unsigned()?;
            }
            7 => self.advance(8)?,
            8 => {
                let len = self.unsigned()?;
                self.advance(len)?;
            }
            9 | 10 => {
                let header = self.byte()?;
                let mut count = (header >> 4) as u64;
                if count == 15 {
                    count = self.unsigned()?;
                }
                if count > self.container_limit as u64
                    || count > self.limit.saturating_sub(self.bytes) as u64
                {
                    return Err(corrupt());
                }
                for _ in 0..count {
                    self.skip(header & 15, depth + 1, false)?;
                }
            }
            11 => {
                let count = self.unsigned()?;
                if count > self.container_limit as u64
                    || count > self.limit.saturating_sub(self.bytes) as u64
                {
                    return Err(corrupt());
                }
                if count > 0 {
                    let kinds = self.byte()?;
                    for _ in 0..count {
                        self.skip(kinds >> 4, depth + 1, false)?;
                        self.skip(kinds & 15, depth + 1, false)?;
                    }
                }
            }
            12 => {
                let mut id = 0;
                for _ in 0..128 {
                    let header = self.byte()?;
                    if header == 0 {
                        return Ok(());
                    }
                    id = self.field_id(id, header)?;
                    self.skip(header & 15, depth + 1, true)?;
                }
                return Err(corrupt());
            }
            _ => return Err(corrupt()),
        }
        Ok(())
    }
    fn field_id(&mut self, previous: i64, header: u8) -> Result<i64, StorageError> {
        let delta = header >> 4;
        let id = if delta == 0 {
            self.signed()?
        } else {
            previous.checked_add(delta as i64).ok_or_else(corrupt)?
        };
        if !(1..=i16::MAX as i64).contains(&id) {
            return Err(corrupt());
        }
        Ok(id)
    }
    fn page(&mut self) -> Result<(i64, i64, i64), StorageError> {
        let mut id = 0i64;
        let mut values = [None; 3];
        for _ in 0..128 {
            let field = self.byte()?;
            if field == 0 {
                return match values {
                    [Some(kind), Some(raw), Some(compressed)] => Ok((kind, raw, compressed)),
                    _ => Err(corrupt()),
                };
            }
            id = self.field_id(id, field)?;
            if (1..=3).contains(&id) {
                if field & 15 != 5 {
                    return Err(corrupt());
                }
                let value = self.signed()?;
                if i32::try_from(value).is_err() || values[id as usize - 1].replace(value).is_some()
                {
                    return Err(corrupt());
                }
            } else {
                self.skip(field & 15, 1, true)?;
            }
        }
        Err(corrupt())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn input() -> Result<File, Box<dyn std::error::Error>> {
        let mut file = tempfile::tempfile()?;
        let data: Vec<_> = (0..4096).map(|index| (index % 256) as u8).collect();
        file.write_all(&data)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    #[test]
    fn header_skips_use_logical_cursor_inside_and_beyond_read_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut file = input()?;
        let mut header = Header {
            file: BufReader::with_capacity(HEADER_BUFFER_BYTES, &mut file),
            bytes: 0,
            limit: 4096,
            container_limit: 1024,
            context: None,
        };
        assert_eq!(header.byte()?, 0);
        header.advance(17)?;
        assert_eq!(header.byte()?, 18);
        // Cross the fixed buffer boundary after an in-buffer relative skip.
        header.advance(HEADER_BUFFER_BYTES as u64 + 5)?;
        assert_eq!(header.byte()?, ((19 + HEADER_BUFFER_BYTES + 5) % 256) as u8);
        assert_eq!(header.bytes, 20 + HEADER_BUFFER_BYTES + 5);
        Ok(())
    }

    #[test]
    fn buffered_bytes_do_not_bypass_logical_header_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut file = input()?;
        let mut header = Header {
            file: BufReader::with_capacity(HEADER_BUFFER_BYTES, &mut file),
            bytes: 0,
            limit: 7,
            container_limit: 1024,
            context: None,
        };
        assert_eq!(header.byte()?, 0);
        assert!(matches!(header.advance(7), Err(StorageError::Corrupt(_))));
        assert_eq!(header.bytes, 1);
        header.advance(5)?;
        assert_eq!(header.byte()?, 6);
        assert!(matches!(header.byte(), Err(StorageError::Corrupt(_))));
        assert_eq!(header.bytes, 7);
        Ok(())
    }

    #[test]
    fn cancellation_is_checked_at_logical_buffer_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut file = input()?;
        let context = OperationContext::new(std::time::Duration::from_secs(30));
        let mut header = Header {
            file: BufReader::with_capacity(HEADER_BUFFER_BYTES, &mut file),
            bytes: 0,
            limit: 4096,
            container_limit: 1024,
            context: Some(&context),
        };
        assert_eq!(header.byte()?, 0);
        header.advance(HEADER_BUFFER_BYTES as u64 - 1)?;
        context.cancellation.cancel();
        assert!(matches!(header.byte(), Err(StorageError::Cancelled)));
        assert!(matches!(header.advance(1), Err(StorageError::Cancelled)));
        assert_eq!(header.bytes, HEADER_BUFFER_BYTES);
        Ok(())
    }
}

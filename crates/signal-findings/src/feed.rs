use super::*;
use signal_protocol::findings_feed::{FindingsAfter, FindingsFeedResponse};

/// Count or build output, rejecting each write before any growth beyond the cap.
struct Output {
    length: usize,
    limit: usize,
    data: Option<Vec<u8>>,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.length) {
            return Err(std::io::Error::other("feed output limit"));
        }
        self.length += bytes.len();
        if let Some(data) = &mut self.data {
            data.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Engine {
    pub(super) fn read_feed_record(
        &mut self,
        entry: &Entry,
        previous: FindingsCursor,
        next: FindingsCursor,
        id: Uuid,
    ) -> Result<Finding, FindingError> {
        let header_offset = entry
            .offset
            .checked_sub(FINDING_FRAME_BYTES as u64)
            .ok_or(FindingError::Corrupt("frame offset"))?;
        self.file.seek(SeekFrom::Start(header_offset)).map_err(io)?;
        let mut header = [0; FINDING_FRAME_BYTES];
        self.file.read_exact(&mut header).map_err(io)?;
        let mut data = vec![0; entry.len];
        self.file.read_exact(&mut data).map_err(io)?;
        if frame_header(&data) != header
            || previous
                .advance(&data)
                .map_err(|_| FindingError::Corrupt("position"))?
                != next
        {
            return Err(FindingError::Corrupt("feed record history"));
        }
        let finding: Finding =
            serde_json::from_slice(&data).map_err(|_| FindingError::Corrupt("record JSON"))?;
        finding
            .validate()
            .map_err(|_| FindingError::Corrupt("record contract"))?;
        if finding.id != id {
            return Err(FindingError::Corrupt("feed record identity"));
        }
        Ok(finding)
    }
    pub(super) fn feed(
        &mut self,
        q: FindingsFeedQuery,
        max_bytes: usize,
        ctx: &FindingContext,
    ) -> Result<Vec<u8>, FindingError> {
        ctx.check()?;
        // Physical worker is serial: this tail remains stable throughout this operation.
        let tail = self.prefix.position();
        let mut cursor = match q.after {
            FindingsAfter::Begin => FindingsCursor::initial(self.prefix.stream())
                .map_err(|_| FindingError::Corrupt("stream"))?,
            FindingsAfter::Cursor(c) => c,
        };
        if cursor.stream() != self.prefix.stream() {
            return Err(FindingError::CursorStreamMismatch);
        }
        if cursor.position() > tail {
            return Err(FindingError::CursorPositionUnavailable);
        }
        let expected = if cursor.position() == 0 {
            FindingsCursor::initial(self.prefix.stream())
                .map_err(|_| FindingError::Corrupt("stream"))?
        } else {
            self.append_order
                .get(&cursor.position())
                .ok_or(FindingError::Corrupt("append index"))?
                .cursor
        };
        if cursor != expected {
            return Err(FindingError::CursorHistoryMismatch);
        }
        let mut page = FindingsFeedResponse::<Finding> {
            schema_version: 1,
            findings: Vec::new(),
            next_cursor: cursor.encode(),
            has_more: false,
        };
        let mut count = Output {
            length: 0,
            limit: max_bytes,
            data: None,
        };
        serde_json::to_writer(&mut count, &page).map_err(|_| FindingError::PageBudgetExceeded)?;
        // The false flag is one byte larger than true, giving an output upper bound.
        let mut output_bytes = count.length;
        let mut live_bytes = output_bytes
            .checked_mul(2)
            .ok_or(FindingError::PageBudgetExceeded)?;
        if live_bytes > self.config.max_query_bytes {
            return Err(FindingError::PageBudgetExceeded);
        }
        while cursor.position() < tail && page.findings.len() < q.limit {
            ctx.check()?;
            let next_position = cursor
                .position()
                .checked_add(1)
                .ok_or(FindingError::Corrupt("position"))?;
            let next = self
                .append_order
                .get(&next_position)
                .ok_or(FindingError::Corrupt("append index"))?;
            let next_cursor = next.cursor;
            let next_id = next.id;
            let entry = self
                .ids
                .get(&next.id)
                .ok_or(FindingError::Corrupt("index"))?;
            let entry = Entry {
                offset: entry.offset,
                len: entry.len,
                position: entry.position,
            };
            // Charge JSON string/container expansion, record buffer, Vec spare capacity,
            // encoded output including allocator growth, and the decoded Finding before read.
            let charge = entry
                .len
                .checked_mul(64)
                .and_then(|v| v.checked_add(std::mem::size_of::<Finding>()))
                .ok_or(FindingError::PageBudgetExceeded)?;
            let next_live = live_bytes
                .checked_add(charge)
                .ok_or(FindingError::PageBudgetExceeded)?;
            if next_live > self.config.max_query_bytes {
                if page.findings.is_empty() {
                    return Err(FindingError::PageBudgetExceeded);
                }
                break;
            }
            let finding = self.read_feed_record(&entry, cursor, next_cursor, next_id)?;
            let mut size = Output {
                length: 0,
                limit: max_bytes,
                data: None,
            };
            let fits = serde_json::to_writer(&mut size, &finding).is_ok();
            let next_output = output_bytes
                .checked_add(size.length)
                .and_then(|v| v.checked_add(usize::from(!page.findings.is_empty())));
            if !fits || next_output.is_none_or(|n| n > max_bytes) {
                if page.findings.is_empty() {
                    return Err(FindingError::PageBudgetExceeded);
                }
                break;
            }
            output_bytes = next_output.ok_or(FindingError::PageBudgetExceeded)?;
            live_bytes = next_live;
            page.findings.push(finding);
            cursor = next_cursor;
        }
        page.next_cursor = cursor.encode();
        page.has_more = cursor.position() < tail;
        let mut output = Output {
            length: 0,
            limit: max_bytes,
            data: Some(Vec::with_capacity(output_bytes)),
        };
        serde_json::to_writer(&mut output, &page).map_err(|_| FindingError::PageBudgetExceeded)?;
        ctx.check()?;
        output.data.ok_or(FindingError::Corrupt("feed output"))
    }
}

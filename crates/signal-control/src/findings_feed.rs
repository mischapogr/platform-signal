//! Integrity verification, not read authorization. Anchors must come from one
//! authenticated, generation-checked database snapshot, never request fields.
use crate::{ControlContext, ControlError, ITEM_BYTES, ITEMS, REPLY_BYTES};
use sha2::{Digest, Sha256};
use signal_findings::Finding;
use signal_protocol::findings_feed::{FindingsAfter, FindingsCursor, FindingsFeedQuery};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Original first-occurrence record. Debug deliberately excludes private bytes.
pub struct RetainedFinding {
    pub id: Uuid,
    pub cursor: FindingsCursor,
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
}
impl std::fmt::Debug for RetainedFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedFinding")
            .field("bytes", &"redacted")
            .finish_non_exhaustive()
    }
}

/// A checked contiguous page, tied to its original operation budget. Possession
/// proves integrity only: the host must separately enforce current global read
/// authority before querying the database and before emitting a response.
pub struct RetainedFindingsPage {
    generation: Uuid,
    records: Vec<RetainedFinding>,
    next: FindingsCursor,
    has_more: bool,
    context: ControlContext,
}
impl RetainedFindingsPage {
    /// `anchor` is the retained digest at the requested position, and `head` is
    /// the global head from that SAME database snapshot. No pruning/bootstrap is
    /// supported. Charge framing and retained allocation as well as body bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        store: Uuid,
        generation: Uuid,
        query: FindingsFeedQuery,
        anchor: FindingsCursor,
        head: FindingsCursor,
        records: Vec<RetainedFinding>,
        context: ControlContext,
    ) -> Result<Self, ControlError> {
        context.check()?;
        if store.is_nil() || generation.is_nil() || !(1..=ITEMS).contains(&query.limit) {
            return Err(ControlError::Invalid);
        }
        let initial = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        let after = match query.after {
            FindingsAfter::Begin => initial,
            FindingsAfter::Cursor(cursor) => cursor,
        };
        // A divergent/foreign client prefix is a conflict, not a replacement cursor.
        if after.stream() != store || after != anchor || after.position() > head.position() {
            return Err(ControlError::Conflict);
        }
        if anchor.stream() != store
            || head.stream() != store
            || head.position() > i64::MAX as u64
            || (anchor.position() == 0 && anchor != initial)
            || (head.position() == 0 && head != initial)
            || (anchor.position() == head.position() && anchor != head)
        {
            return Err(ControlError::Corrupt);
        }
        if records.len() > query.limit || records.capacity() > ITEMS {
            return Err(ControlError::Full);
        }
        let mut charge = records
            .capacity()
            .checked_mul(std::mem::size_of::<RetainedFinding>())
            .and_then(|n| n.checked_add(256))
            .ok_or(ControlError::Full)?;
        // Preflight every allocation before JSON parsing or hash-set growth.
        for record in &records {
            if record.bytes.is_empty()
                || record.bytes.len() > ITEM_BYTES
                || record.bytes.capacity() > ITEM_BYTES
            {
                return Err(ControlError::Full);
            }
            charge = charge
                .checked_add(record.bytes.capacity())
                .and_then(|n| n.checked_add(128))
                .filter(|n| *n <= REPLY_BYTES)
                .ok_or(ControlError::Full)?;
        }
        let mut next = anchor;
        let mut ids = BTreeSet::new();
        for record in &records {
            context.check()?;
            if record.id.is_nil()
                || !ids.insert(record.id)
                || record.cursor.position() > head.position()
                || Sha256::digest(&record.bytes).as_slice() != record.sha256
            {
                return Err(ControlError::Corrupt);
            }
            next = next
                .advance(&record.bytes)
                .map_err(|_| ControlError::Corrupt)?;
            if next != record.cursor {
                return Err(ControlError::Corrupt);
            }
            let finding: Finding =
                serde_json::from_slice(&record.bytes).map_err(|_| ControlError::Corrupt)?;
            finding.validate().map_err(|_| ControlError::Corrupt)?;
            if finding.id != record.id {
                return Err(ControlError::Corrupt);
            }
        }
        // Empty nonterminal pages cannot silently move or stall a consumer.
        if (records.is_empty() && next.position() < head.position())
            || (next.position() == head.position() && next != head)
        {
            return Err(ControlError::Corrupt);
        }
        context.check()?;
        Ok(Self {
            generation,
            records,
            next,
            has_more: next.position() < head.position(),
            context,
        })
    }
    pub fn generation(&self) -> Result<Uuid, ControlError> {
        self.context.check()?;
        Ok(self.generation)
    }
    pub fn records(&self) -> Result<&[RetainedFinding], ControlError> {
        self.context.check()?;
        Ok(&self.records)
    }
    pub fn next_cursor(&self) -> Result<FindingsCursor, ControlError> {
        self.context.check()?;
        Ok(self.next)
    }
    pub fn has_more(&self) -> Result<bool, ControlError> {
        self.context.check()?;
        Ok(self.has_more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn context() -> Result<ControlContext, ControlError> {
        ControlContext::new(Duration::from_secs(5))
    }
    fn row(cursor: FindingsCursor, id: Uuid) -> Result<RetainedFinding, ControlError> {
        // Deliberate original whitespace: reserialization MUST change the digest.
        let bytes = format!(
            "{{ \"schema_version\":1,\"id\":\"{id}\",\"rule_id\":\"synthetic\",\"created_at\":\"2026-10-11T00:00:00Z\",\"severity\":\"high\",\"title\":\"synthetic\",\"event_ids\":[\"{}\"],\"attributes\":{{}} }}",
            Uuid::new_v4()
        ).into_bytes();
        Ok(RetainedFinding {
            id,
            cursor: cursor.advance(&bytes).map_err(|_| ControlError::Invalid)?,
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        })
    }
    fn query(after: FindingsAfter) -> FindingsFeedQuery {
        FindingsFeedQuery { after, limit: 2 }
    }
    #[test]
    fn original_bytes_nonterminal_page_and_exact_empty_tail() -> Result<(), ControlError> {
        let store = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let begin = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        let first = row(begin, Uuid::new_v4())?;
        let next = first.cursor;
        let original = first.bytes.clone();
        let second = row(next, Uuid::new_v4())?;
        let head = second.cursor;
        let page = RetainedFindingsPage::verify(
            store,
            generation,
            query(FindingsAfter::Begin),
            begin,
            head,
            vec![first],
            context()?,
        )?;
        assert_eq!(page.records()?[0].bytes, original);
        assert_eq!(page.next_cursor()?, next);
        assert!(page.has_more()?);
        assert_eq!(page.generation()?, generation);
        let page = RetainedFindingsPage::verify(
            store,
            generation,
            query(FindingsAfter::Cursor(next)),
            next,
            head,
            vec![second],
            context()?,
        )?;
        assert!(!page.has_more()?);
        assert_eq!(page.next_cursor()?, head);
        let empty = RetainedFindingsPage::verify(
            store,
            generation,
            query(FindingsAfter::Cursor(head)),
            head,
            head,
            vec![],
            context()?,
        )?;
        assert_eq!(empty.next_cursor()?, head);
        assert!(empty.records()?.is_empty());
        Ok(())
    }
    #[test]
    fn divergent_history_and_foreign_cursor_never_reset() -> Result<(), ControlError> {
        let store = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let begin = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        let foreign = FindingsCursor::initial(Uuid::new_v4()).map_err(|_| ControlError::Invalid)?;
        for after in [
            foreign,
            begin
                .advance(b"wrong history")
                .map_err(|_| ControlError::Invalid)?,
        ] {
            assert!(matches!(
                RetainedFindingsPage::verify(
                    store,
                    generation,
                    query(FindingsAfter::Cursor(after)),
                    begin,
                    begin,
                    vec![],
                    context()?
                ),
                Err(ControlError::Conflict)
            ));
        }
        let wrong_head = begin
            .advance(b"wrong head")
            .map_err(|_| ControlError::Invalid)?;
        assert!(matches!(
            RetainedFindingsPage::verify(
                store,
                generation,
                query(FindingsAfter::Begin),
                begin,
                wrong_head,
                vec![],
                context()?
            ),
            Err(ControlError::Corrupt)
        ));
        Ok(())
    }
    #[test]
    fn missing_tampered_duplicate_and_misidentified_rows_fail() -> Result<(), ControlError> {
        let store = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let begin = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        for mode in 0..5 {
            let first = row(begin, Uuid::new_v4())?;
            let mut second = row(first.cursor, Uuid::new_v4())?;
            let head = second.cursor;
            match mode {
                0 => second.bytes[0] = b'!',
                1 => second.sha256[0] ^= 1,
                2 => second.id = first.id,
                3 => second.cursor = first.cursor,
                _ => second.id = Uuid::new_v4(),
            }
            assert!(matches!(
                RetainedFindingsPage::verify(
                    store,
                    generation,
                    query(FindingsAfter::Begin),
                    begin,
                    head,
                    vec![first, second],
                    context()?
                ),
                Err(ControlError::Corrupt)
            ));
        }
        let first = row(begin, Uuid::new_v4())?;
        let second = row(first.cursor, Uuid::new_v4())?;
        assert!(matches!(
            RetainedFindingsPage::verify(
                store,
                generation,
                query(FindingsAfter::Begin),
                begin,
                second.cursor,
                vec![second],
                context()?
            ),
            Err(ControlError::Corrupt)
        ));
        Ok(())
    }
    #[test]
    fn allocation_count_and_payload_limits_precede_materialization() -> Result<(), ControlError> {
        let store = Uuid::new_v4();
        let begin = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        let generation = Uuid::new_v4();
        let mut first = row(begin, Uuid::new_v4())?;
        first.bytes.reserve_exact(ITEM_BYTES + 1);
        assert!(matches!(
            RetainedFindingsPage::verify(
                store,
                generation,
                query(FindingsAfter::Begin),
                begin,
                first.cursor,
                vec![first],
                context()?
            ),
            Err(ControlError::Full)
        ));
        let rows = Vec::with_capacity(ITEMS + 1);
        assert!(matches!(
            RetainedFindingsPage::verify(
                store,
                generation,
                query(FindingsAfter::Begin),
                begin,
                begin,
                rows,
                context()?
            ),
            Err(ControlError::Full)
        ));
        let invalid = FindingsFeedQuery {
            after: FindingsAfter::Begin,
            limit: ITEMS + 1,
        };
        assert!(matches!(
            RetainedFindingsPage::verify(
                store,
                generation,
                invalid,
                begin,
                begin,
                vec![],
                context()?
            ),
            Err(ControlError::Invalid)
        ));
        Ok(())
    }
    #[test]
    fn total_allocation_and_invalid_finding_fail_without_partial_page() -> Result<(), ControlError>
    {
        let store = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let begin = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        let mut head = begin;
        let mut records = Vec::with_capacity(17);
        for _ in 0..17 {
            let mut record = row(head, Uuid::new_v4())?;
            let mut retained = Vec::with_capacity(ITEM_BYTES);
            retained.extend_from_slice(&record.bytes);
            record.bytes = retained;
            head = record.cursor;
            records.push(record);
        }
        let q = FindingsFeedQuery {
            after: FindingsAfter::Begin,
            limit: ITEMS,
        };
        assert!(matches!(
            RetainedFindingsPage::verify(store, generation, q, begin, head, records, context()?),
            Err(ControlError::Full)
        ));
        let mut invalid = row(begin, Uuid::new_v4())?;
        invalid.bytes = b"{\"schema_version\":99}".to_vec();
        invalid.sha256 = Sha256::digest(&invalid.bytes).into();
        invalid.cursor = begin
            .advance(&invalid.bytes)
            .map_err(|_| ControlError::Invalid)?;
        assert!(matches!(
            RetainedFindingsPage::verify(
                store,
                generation,
                q,
                begin,
                invalid.cursor,
                vec![invalid],
                context()?
            ),
            Err(ControlError::Corrupt)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn original_budget_cannot_be_renewed_by_borrowing() -> Result<(), ControlError> {
        let store = Uuid::new_v4();
        let begin = FindingsCursor::initial(store).map_err(|_| ControlError::Invalid)?;
        let ctx = context()?;
        let page = RetainedFindingsPage::verify(
            store,
            Uuid::new_v4(),
            query(FindingsAfter::Begin),
            begin,
            begin,
            vec![],
            ctx.clone(),
        )?;
        ctx.cancel();
        assert!(matches!(page.records(), Err(ControlError::Cancelled)));
        assert!(matches!(page.next_cursor(), Err(ControlError::Cancelled)));
        assert!(matches!(page.generation(), Err(ControlError::Cancelled)));
        assert!(matches!(page.has_more(), Err(ControlError::Cancelled)));
        let ctx = ControlContext::new(Duration::from_millis(10))?;
        let page = RetainedFindingsPage::verify(
            store,
            Uuid::new_v4(),
            query(FindingsAfter::Begin),
            begin,
            begin,
            vec![],
            ctx,
        )?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(page.records(), Err(ControlError::Timeout)));
        assert!(matches!(page.next_cursor(), Err(ControlError::Timeout)));
        Ok(())
    }
}

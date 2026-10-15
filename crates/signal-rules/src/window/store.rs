//! Blocking transaction engine; the retained bounded worker is its sole owner.
use super::{Error, Policy, State};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use signal_findings::Finding;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(skip)]
    pub history: HistoryUsage,
    pub schema_version: u16,
    pub revision: u64,
    pub checkpoint: u64,
    pub source_stream: uuid::Uuid,
    pub source_binding: [u8; 32],
    pub state: State,
    pub findings: Vec<Finding>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct HistoryUsage {
    pub assessments: usize,
    pub bytes: usize,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveEvidence {
    pub schema_version: u16,
    pub source_stream: uuid::Uuid,
    pub source_binding: [u8; 32],
    pub policy: Policy,
    pub assessment: super::Assessment,
}
#[derive(serde::Serialize)]
pub struct HistoryRecord {
    pub schema_version: u16,
    pub id: [u8; 32],
    pub checkpoint: u64,
    pub recorded_at_ms: i64,
    pub expires_at_ms: i64,
    /// Expired metadata remains explicit; expired canonical inputs are withheld.
    pub evidence: Option<ArchiveEvidence>,
}
#[derive(serde::Serialize)]
pub struct HistoryPage {
    pub schema_version: u16,
    pub source_stream: Option<uuid::Uuid>,
    pub checkpoint: u64,
    pub retained_count: usize,
    pub records: Vec<HistoryRecord>,
    pub truncated: bool,
    /// Empty/expired history never establishes a clean detector result.
    pub missing_evidence: bool,
    pub next: Option<HistoryCursor>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCursor {
    pub schema_version: u16,
    pub source_stream: uuid::Uuid,
    pub source_binding: [u8; 32],
    pub revision: u64,
    pub checkpoint: u64,
    pub id: [u8; 32],
}
impl HistoryPage {
    pub(super) fn withhold_expired(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();
        for record in &mut self.records {
            if record.expires_at_ms <= now {
                record.evidence = None;
                self.missing_evidence = true;
            }
        }
    }
}
pub struct Engine {
    connection: Connection,
    policy: Policy,
    _lock: File,
}
impl Engine {
    /// Local owner read/export primitive, not an HTTP authority boundary. Exact
    /// retained contents are validated before response assembly on the worker.
    pub fn history(
        &self,
        after: Option<HistoryCursor>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<HistoryPage, Error> {
        if !(1..=128).contains(&limit) || !(256..=33_554_432).contains(&max_bytes) {
            return Err(Error::Configuration);
        }
        self.validate_history()?;
        let snapshot = self.load()?;
        if let Some(cursor) = &after {
            let current = snapshot.as_ref().ok_or(Error::Conflict)?;
            if cursor.schema_version != 1
                || cursor.source_stream != current.source_stream
                || cursor.source_binding != current.source_binding
                || cursor.revision != current.revision
                || cursor.checkpoint > current.checkpoint
            {
                return Err(Error::Conflict);
            }
            let exists: bool = self
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM window_assessments WHERE checkpoint=?1 AND id=?2)",
                    params![cursor.checkpoint as i64, cursor.id.as_slice()],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Journal)?;
            if !exists {
                return Err(Error::Conflict);
            }
        }
        let checkpoint = after.as_ref().map_or(0, |c| c.checkpoint as i64);
        let id = after.as_ref().map_or([0; 32], |c| c.id);
        let present = i64::from(after.is_some());
        let remaining:i64=self.connection.query_row("SELECT count(*) FROM window_assessments WHERE ?3=0 OR checkpoint<?1 OR (checkpoint=?1 AND id<?2)",
            params![checkpoint,id.as_slice(),present],|r|r.get(0)).map_err(|_|Error::Journal)?;
        let mut page = HistoryPage {
            schema_version: 1,
            source_stream: snapshot.as_ref().map(|s| s.source_stream),
            checkpoint: snapshot.as_ref().map_or(0, |s| s.checkpoint),
            retained_count: snapshot.as_ref().map_or(0, |s| s.history.assessments),
            records: Vec::new(),
            truncated: false,
            missing_evidence: false,
            next: None,
        };
        let mut statement=self.connection.prepare("SELECT id,checkpoint,recorded_at,expires_at,CASE WHEN expires_at>?5 THEN substr(payload,1,?1) ELSE NULL END FROM window_assessments WHERE ?6=0 OR checkpoint<?3 OR (checkpoint=?3 AND id<?4) ORDER BY checkpoint DESC,id DESC LIMIT ?2").map_err(|_|Error::Journal)?;
        let now = chrono::Utc::now().timestamp_millis();
        let mut rows = statement
            .query(params![
                (max_bytes + 1) as i64,
                limit as i64,
                checkpoint,
                id.as_slice(),
                now,
                present
            ])
            .map_err(|_| Error::Journal)?;
        let mut used = serde_json::to_vec(&page)
            .map_err(|_| Error::Configuration)?
            .len();
        while let Some(row) = rows.next().map_err(|_| Error::Journal)? {
            let id: Vec<u8> = row.get(0).map_err(|_| Error::Journal)?;
            let checkpoint: i64 = row.get(1).map_err(|_| Error::Journal)?;
            let recorded_at_ms: i64 = row.get(2).map_err(|_| Error::Journal)?;
            let expires_at_ms: i64 = row.get(3).map_err(|_| Error::Journal)?;
            let payload: Option<Vec<u8>> = row.get(4).map_err(|_| Error::Journal)?;
            let expired = expires_at_ms <= now;
            let evidence = if expired {
                None
            } else {
                let payload = payload.ok_or(Error::Conflict)?;
                if payload.len() > max_bytes {
                    if page.records.is_empty() {
                        return Err(Error::Capacity);
                    }
                    break;
                }
                Some(serde_json::from_slice(&payload).map_err(|_| Error::Configuration)?)
            };
            let record = HistoryRecord {
                schema_version: 1,
                id: id.as_slice().try_into().map_err(|_| Error::Conflict)?,
                checkpoint: checkpoint as u64,
                recorded_at_ms,
                expires_at_ms,
                evidence,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| Error::Configuration)?
                .len();
            let cursor = if page.records.len() + 1 < remaining as usize {
                let current = snapshot.as_ref().ok_or(Error::Conflict)?;
                Some(HistoryCursor {
                    schema_version: 1,
                    source_stream: current.source_stream,
                    source_binding: current.source_binding,
                    revision: current.revision,
                    checkpoint: record.checkpoint,
                    id: record.id,
                })
            } else {
                None
            };
            let cursor_bytes = cursor
                .as_ref()
                .map(|c| serde_json::to_vec(c).map(|b| b.len().saturating_sub(4)))
                .transpose()
                .map_err(|_| Error::Configuration)?
                .unwrap_or(0);
            if used + bytes + 1 + cursor_bytes > max_bytes {
                if page.records.is_empty() {
                    return Err(Error::Capacity);
                }
                break;
            }
            used += bytes + 1;
            page.missing_evidence |= expired;
            page.records.push(record);
            page.next = cursor;
        }
        page.truncated = page.records.len() < remaining as usize;
        page.missing_evidence |= page.records.is_empty() || page.truncated;
        page.withhold_expired();
        if serde_json::to_vec(&page)
            .map_err(|_| Error::Configuration)?
            .len()
            > max_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(page)
    }
    pub fn open(path: &Path, policy: Policy) -> Result<Self, Error> {
        policy.validate()?;
        if path.as_os_str().is_empty() || path.as_os_str().len() > 4096 {
            return Err(Error::Configuration);
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(Error::Configuration)?;
        for ancestor in path.ancestors() {
            if let Ok(metadata) = fs::symlink_metadata(ancestor)
                && metadata.file_type().is_symlink()
            {
                return Err(Error::Configuration);
            }
        }
        let directory = fs::metadata(parent).map_err(|_| Error::Journal)?;
        if !directory.is_dir() || directory.permissions().mode() & 0o777 != 0o700 {
            return Err(Error::Configuration);
        }
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_name)
            .map_err(|_| Error::Journal)?;
        let metadata = lock.metadata().map_err(|_| Error::Journal)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() != 0
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(Error::Configuration);
        }
        lock.try_lock().map_err(|_| Error::Busy)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::Journal)?;
        let metadata = file.metadata().map_err(|_| Error::Journal)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() > 67_108_864
        {
            return Err(Error::Configuration);
        }
        file.sync_all().map_err(|_| Error::Journal)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::Journal)?;
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| Error::Journal)?;
        connection
            .busy_timeout(Duration::from_millis(100))
            .map_err(|_| Error::Journal)?;
        #[cfg(test)]
        if path
            .file_name()
            .is_some_and(|name| name == "retained-lock-test.sqlite")
        {
            connection
                .busy_handler(Some(super::recovery_tests::sqlite_busy_probe))
                .map_err(|_| Error::Journal)?;
        }
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA max_page_count=16384; CREATE TABLE IF NOT EXISTS window_snapshot(singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL, checkpoint INTEGER NOT NULL, payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS window_assessments(id BLOB PRIMARY KEY CHECK(length(id)=32), checkpoint INTEGER NOT NULL, recorded_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, pending INTEGER NOT NULL CHECK(pending IN(0,1)), payload BLOB NOT NULL); CREATE INDEX IF NOT EXISTS window_assessment_expiry ON window_assessments(expires_at);").map_err(|_|Error::Journal)?;
        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|_| Error::Journal)?;
        if page_size != 4096 {
            return Err(Error::Configuration);
        }
        let engine = Self {
            connection,
            policy,
            _lock: lock,
        };
        engine.load()?;
        engine.validate_history()?;
        Ok(engine)
    }
    fn validate_history(&self) -> Result<(), Error> {
        let (count, bytes): (i64, i64) = self
            .connection
            .query_row(
                "SELECT count(*),coalesce(sum(length(payload)),0) FROM window_assessments",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Error::Journal)?;
        if count < 0
            || bytes < 0
            || count as usize > self.policy.max_history_assessments
            || bytes as usize > self.policy.max_history_bytes
        {
            return Err(Error::Capacity);
        }
        let current = self.load()?;
        let mut expected_pending = std::collections::BTreeSet::new();
        if let Some(snapshot) = &current {
            for assessment in snapshot.state.assessments() {
                let payload = serde_json::to_vec(&serde_json::json!({"schema_version":1,
                    "source_stream":snapshot.source_stream,"source_binding":snapshot.source_binding,
                    "policy":self.policy,"assessment":assessment}))
                .map_err(|_| Error::Configuration)?;
                expected_pending.insert(<[u8; 32]>::from(Sha256::digest(payload)));
            }
        }
        let mut statement = self.connection.prepare("SELECT id,checkpoint,recorded_at,expires_at,pending,substr(payload,1,?1) FROM window_assessments").map_err(|_|Error::Journal)?;
        let mut rows = statement
            .query([(self.policy.max_history_bytes + 1) as i64])
            .map_err(|_| Error::Journal)?;
        while let Some(row) = rows.next().map_err(|_| Error::Journal)? {
            let id: Vec<u8> = row.get(0).map_err(|_| Error::Journal)?;
            let checkpoint: i64 = row.get(1).map_err(|_| Error::Journal)?;
            let recorded: i64 = row.get(2).map_err(|_| Error::Journal)?;
            let expires: i64 = row.get(3).map_err(|_| Error::Journal)?;
            let pending: i64 = row.get(4).map_err(|_| Error::Journal)?;
            let payload: Vec<u8> = row.get(5).map_err(|_| Error::Journal)?;
            if payload.len() > self.policy.max_history_bytes
                || id.as_slice() != Sha256::digest(&payload).as_slice()
                || !matches!(pending, 0 | 1)
                || recorded.checked_add(self.policy.history_retention_ms) != Some(expires)
                || checkpoint <= 0
            {
                return Err(Error::Conflict);
            }
            let evidence: ArchiveEvidence =
                serde_json::from_slice(&payload).map_err(|_| Error::Configuration)?;
            if pending == 1 {
                let key: [u8; 32] = id.as_slice().try_into().map_err(|_| Error::Conflict)?;
                if !expected_pending.remove(&key) {
                    return Err(Error::Conflict);
                }
            }
            let snapshot = current.as_ref().ok_or(Error::Conflict)?;
            if evidence.schema_version != 1
                || evidence.policy != self.policy
                || evidence.source_stream != snapshot.source_stream
                || evidence.source_binding != snapshot.source_binding
                || checkpoint as u64 > snapshot.checkpoint
            {
                return Err(Error::Conflict);
            }
            let mut validation = State::new(self.policy.clone())?;
            validation.watermark = Some(evidence.assessment.anchor);
            validation.outputs.push(evidence.assessment);
            validation.validate(&self.policy)?;
        }
        if !expected_pending.is_empty() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn load(&self) -> Result<Option<Snapshot>, Error> {
        let row: Option<(i64, i64, Vec<u8>)> = self
            .connection
            .query_row(
                // Bound allocation even when an externally corrupted database
                // contains an oversized blob. One extra byte detects overflow.
                "SELECT revision,checkpoint,substr(payload,1,?1) FROM window_snapshot WHERE singleton=1",
                [(self.policy.max_state_bytes * 2 + 1) as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| Error::Journal)?;
        let Some((revision, checkpoint, bytes)) = row else {
            return Ok(None);
        };
        if bytes.len() > self.policy.max_state_bytes * 2 {
            return Err(Error::Capacity);
        }
        let mut snapshot: Snapshot =
            serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
        let (count, history_bytes): (i64, i64) = self
            .connection
            .query_row(
                "SELECT count(*),coalesce(sum(length(payload)),0) FROM window_assessments",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Error::Journal)?;
        if count < 0
            || history_bytes < 0
            || count as usize > self.policy.max_history_assessments
            || history_bytes as usize > self.policy.max_history_bytes
        {
            return Err(Error::Capacity);
        }
        snapshot.history = HistoryUsage {
            assessments: count as usize,
            bytes: history_bytes as usize,
        };
        if revision < 0
            || checkpoint < 0
            || revision as u64 != snapshot.revision
            || checkpoint as u64 != snapshot.checkpoint
        {
            return Err(Error::Conflict);
        }
        self.validate(&snapshot)?;
        Ok(Some(snapshot))
    }
    fn validate(&self, snapshot: &Snapshot) -> Result<(), Error> {
        if snapshot.schema_version != 1
            || snapshot.revision == 0
            || snapshot.revision > i64::MAX as u64
            || snapshot.checkpoint > i64::MAX as u64
            || snapshot.source_stream.is_nil()
            || snapshot.findings.len() > self.policy.max_outputs
        {
            return Err(Error::Configuration);
        }
        snapshot.state.validate(&self.policy)?;
        let expected: Vec<_> = snapshot
            .state
            .assessments()
            .iter()
            .map(|a| a.finding(&self.policy))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        if expected != snapshot.findings {
            return Err(Error::Conflict);
        }
        if serde_json::to_vec(snapshot)
            .map_err(|_| Error::Configuration)?
            .len()
            > self.policy.max_state_bytes * 2
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// State, deterministic finding outbox and checkpoint are one synced SQLite
    /// transaction; caller must reload after uncertain completion.
    pub fn commit(
        &mut self,
        expected_revision: u64,
        mut next: Snapshot,
    ) -> Result<Snapshot, Error> {
        self.validate(&next)?;
        self.validate_history()?;
        if self.load()?.is_some_and(|current| {
            current.source_stream != next.source_stream
                || current.source_binding != next.source_binding
        }) {
            return Err(Error::Conflict);
        }
        if expected_revision.checked_add(1) != Some(next.revision) {
            return Err(Error::Conflict);
        }
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::Configuration)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Journal)?;
        let current: Option<(i64, i64)> = transaction
            .query_row(
                "SELECT revision,checkpoint FROM window_snapshot WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| Error::Journal)?;
        let (revision, checkpoint) = current.unwrap_or((0, 0));
        if revision < 0
            || checkpoint < 0
            || revision as u64 != expected_revision
            || next.checkpoint <= checkpoint as u64
        {
            return Err(Error::Conflict);
        }
        let recorded_at = chrono::Utc::now().timestamp_millis();
        let expires_at = recorded_at
            .checked_add(self.policy.history_retention_ms)
            .ok_or(Error::Configuration)?;
        transaction
            .execute(
                "DELETE FROM window_assessments WHERE expires_at <= ?1 AND pending=0",
                [recorded_at],
            )
            .map_err(|_| Error::Journal)?;
        for assessment in next.state.assessments() {
            // The stable identity excludes receipt time and checkpoint. Replay
            // retains the first custody/expiry boundary instead of extending it.
            let payload = serde_json::to_vec(&serde_json::json!({"schema_version":1,
                "source_stream":next.source_stream,"source_binding":next.source_binding,
                "policy":self.policy,"assessment":assessment}))
            .map_err(|_| Error::Configuration)?;
            if payload.len() > self.policy.max_history_bytes {
                return Err(Error::Capacity);
            }
            let id: [u8; 32] = Sha256::digest(&payload).into();
            transaction.execute("INSERT INTO window_assessments(id,checkpoint,recorded_at,expires_at,pending,payload) VALUES(?1,?2,?3,?4,1,?5) ON CONFLICT(id) DO UPDATE SET pending=1",
                params![id.as_slice(), next.checkpoint as i64, recorded_at, expires_at, payload]).map_err(|_|Error::Journal)?;
        }
        let (count, history_bytes): (i64, i64) = transaction
            .query_row(
                "SELECT count(*),coalesce(sum(length(payload)),0) FROM window_assessments",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Error::Journal)?;
        if count < 0
            || history_bytes < 0
            || count as usize > self.policy.max_history_assessments
            || history_bytes as usize > self.policy.max_history_bytes
        {
            return Err(Error::Capacity);
        }
        next.history = HistoryUsage {
            assessments: count as usize,
            bytes: history_bytes as usize,
        };
        transaction.execute("INSERT INTO window_snapshot(singleton,revision,checkpoint,payload) VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,checkpoint=excluded.checkpoint,payload=excluded.payload",params![next.revision as i64,next.checkpoint as i64,bytes]).map_err(|_|Error::Journal)?;
        transaction.commit().map_err(|_| Error::Journal)?;
        Ok(next)
    }
    /// Host calls this only after durable publication of the complete prefix.
    /// Archive custody and source progress remain intact at the same checkpoint.
    pub fn retire(&mut self, expected_revision: u64, published: usize) -> Result<Snapshot, Error> {
        self.validate_history()?;
        let mut next = self.load()?.ok_or(Error::Conflict)?;
        if next.revision != expected_revision {
            return Err(Error::Conflict);
        }
        if published > next.state.assessments().len() {
            return Err(Error::Conflict);
        }
        let mut archived_ids = Vec::with_capacity(published);
        for assessment in &next.state.assessments()[..published] {
            let payload = serde_json::to_vec(&serde_json::json!({"schema_version":1,
                "source_stream":next.source_stream,"source_binding":next.source_binding,
                "policy":self.policy,"assessment":assessment}))
            .map_err(|_| Error::Configuration)?;
            archived_ids.push(<[u8; 32]>::from(Sha256::digest(payload)));
        }
        next.state.retire_assessments(published)?;
        let mut still_pending = std::collections::BTreeSet::new();
        for assessment in next.state.assessments() {
            let payload = serde_json::to_vec(&serde_json::json!({"schema_version":1,
                "source_stream":next.source_stream,"source_binding":next.source_binding,
                "policy":self.policy,"assessment":assessment}))
            .map_err(|_| Error::Configuration)?;
            still_pending.insert(<[u8; 32]>::from(Sha256::digest(payload)));
        }
        next.findings = next
            .state
            .assessments()
            .iter()
            .map(|a| a.finding(&self.policy))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        next.revision = next.revision.checked_add(1).ok_or(Error::Capacity)?;
        self.validate(&next)?;
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::Configuration)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Journal)?;
        let changed = transaction.execute("UPDATE window_snapshot SET revision=?1,payload=?2 WHERE singleton=1 AND revision=?3",
            params![next.revision as i64,bytes,expected_revision as i64]).map_err(|_|Error::Journal)?;
        if changed != 1 {
            return Err(Error::Conflict);
        }
        for id in archived_ids {
            if still_pending.contains(&id) {
                continue;
            }
            let changed = transaction
                .execute(
                    "UPDATE window_assessments SET pending=0 WHERE id=?1",
                    [id.as_slice()],
                )
                .map_err(|_| Error::Journal)?;
            if changed != 1 {
                return Err(Error::Conflict);
            }
        }
        transaction.commit().map_err(|_| Error::Journal)?;
        Ok(next)
    }
}

use crate::format::{self, CommitMetadata, HistoryBinding, ProfileDefinition, State, Timestamp};
use crate::intake::{AuthorizedBinding, CoverageSubmission, IntakeContext, IntakeOutcome};
use crate::worker::WorkContext;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior, limits::Limit, params,
};
use serde::{Deserialize, Serialize};
use signal_collector_sdk::coverage::ValidatedCoverage;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("invalid coverage configuration: {0}")]
    Config(&'static str),
    #[error("invalid prepared coverage input: {0}")]
    Invalid(&'static str),
    #[error("coverage history corruption: {0}")]
    Corrupt(&'static str),
    #[error("coverage filesystem operation failed")]
    Io(#[source] std::io::Error),
    #[error("coverage SQLite operation failed")]
    Sqlite(#[source] rusqlite::Error),
    #[error("coverage assertion validation failed")]
    Coverage(#[source] signal_collector_sdk::coverage::CoverageError),
    #[error("coverage capacity exhausted")]
    Quota,
    #[error("coverage root is already owned")]
    Locked,
    #[error("coverage root is unavailable")]
    Unavailable,
    #[error("coverage operation slots exhausted")]
    Capacity,
    #[error("coverage store is closed")]
    Closed,
    #[error("coverage operation cancelled before mutation")]
    Cancelled,
    #[error("coverage operation timed out before mutation")]
    Timeout,
    #[error("coverage mutation outcome unknown; reconcile durable history after recovery")]
    OutcomeUnknown,
    #[error("coverage record identity is already retained")]
    IdentityExists,
    #[error("coverage caller is not authorized for the original full binding")]
    NotAuthorized,
    #[error("coverage retained identity has different original content or correction link")]
    IdContentConflict,
    #[error("coverage original receipt replay window expired")]
    ReplayWindowExpired,
    #[error("coverage current trusted profile is unavailable for new admission")]
    ProfileUnavailable,
    #[error("coverage report exceeds its maximum admission age")]
    ReportTooOld,
    #[error("coverage referenced history or position is unavailable")]
    HistoryUnavailable,
    #[error("coverage referenced identity has been pruned")]
    IdentityPruned,
    #[error("invalid coverage scan cursor")]
    InvalidCursor,
    #[error("coverage scan history has been pruned")]
    HistoryPruned(crate::ScanAvailability),
    #[error("coverage scan response limit prevents progress")]
    ResponseLimit,
    #[error("coverage scan work limit prevents progress")]
    ScanWorkLimit,
    #[error("coverage supplied receipt differs from the committed receipt")]
    ReceiptMismatch,
    #[error("coverage correction target original evidence is unavailable")]
    CorrectionTargetUnavailable,
    #[error("coverage correction target has a different full binding")]
    CorrectionBindingMismatch,
    #[error("invalid coverage correction link: {0}")]
    InvalidCorrection(&'static str),
    #[error("coverage profile revision conflicts with retained definition")]
    ProfileRevisionConflict,
    #[error("coverage receiver clock regressed")]
    ClockRegression,
    #[error("coverage sequence or accounting exhausted")]
    Exhausted,
}
impl From<std::io::Error> for CoverageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rusqlite::Error> for CoverageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

/// Local laboratory limits, not a deployment retention policy or serialized configuration.
#[derive(Clone, Debug)]
pub struct CoverageConfig {
    pub directory: PathBuf,
    pub max_payloads: u64,
    pub max_identities: u64,
    pub max_bindings: u64,
    pub max_ledger_bytes: u64,
    pub max_database_pages: u32,
    pub max_journal_bytes: u64,
    pub operation_capacity: usize,
    pub transient_memory_bytes: u64,
    pub worker_memory_bytes: u64,
    pub max_vm_steps: u64,
    pub operation_timeout: Duration,
}
impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            directory: "data/coverage".into(),
            max_payloads: 128,
            max_identities: 128,
            max_bindings: 32,
            max_ledger_bytes: 4 * 1024 * 1024,
            max_database_pages: 1024,
            max_journal_bytes: 140 * 1024 * 1024,
            operation_capacity: 4,
            transient_memory_bytes: 16 * 1024 * 1024,
            worker_memory_bytes: 8 * 1024 * 1024,
            max_vm_steps: 10_000_000,
            operation_timeout: Duration::from_secs(10),
        }
    }
}
impl CoverageConfig {
    pub fn journal_reserve(&self) -> Result<u64, CoverageError> {
        // SQLite's pinned pager caps sectors at 65,536. No savepoints/attached DB/maintenance SQL.
        let p = u64::from(self.max_database_pages);
        p.checked_mul(4104)
            .and_then(|n| {
                (p + 1)
                    .checked_mul(2 * 65536)
                    .and_then(|padding| n.checked_add(padding))
            })
            .ok_or(CoverageError::Config("journal reserve overflow"))
    }
    pub fn validate(&self) -> Result<(), CoverageError> {
        if self.directory.as_os_str().is_empty()
            || self
                .directory
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || self.max_payloads == 0
            || self.max_payloads > self.max_identities
            || self.max_identities > 1_000_000
            || self.max_bindings == 0
            || self.max_bindings > self.max_identities
            || self.max_ledger_bytes < format::ROOT_CHARGE
            || self.max_ledger_bytes > i64::MAX as u64
            || !(16..=1_048_576).contains(&self.max_database_pages)
            || self.max_journal_bytes < self.journal_reserve()?
            || self.max_journal_bytes > i64::MAX as u64
            || self.operation_capacity == 0
            || self.operation_capacity > 1024
            || self.max_vm_steps < 1000
            || self.max_vm_steps > 1_000_000_000
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(300)
        {
            return Err(CoverageError::Config("finite local store limits"));
        }
        let db = u64::from(self.max_database_pages) * 4096;
        let worker_min = db
            .checked_add(2 * format::MAX_ENTRY_BYTES as u64 + 1024 * 1024)
            .ok_or(CoverageError::Config("worker reserve"))?;
        let transient_min = (self.operation_capacity as u64)
            .checked_mul(2 * format::MAX_ENTRY_BYTES as u64)
            .and_then(|v| v.checked_add(self.worker_memory_bytes))
            .ok_or(CoverageError::Config("transient reserve"))?;
        if self.worker_memory_bytes < worker_min
            || self.transient_memory_bytes < transient_min
            || self.transient_memory_bytes > i64::MAX as u64
        {
            return Err(CoverageError::Config("memory reserves"));
        }
        Ok(())
    }
}
/// Runtime counters; no wire serialization or observer-health inference.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoverageMetrics {
    pub history_id: Uuid,
    pub committed_sequence: u64,
    pub payload_pruned_through: u64,
    pub identity_pruned_through: u64,
    pub payloads: u64,
    pub payload_capacity: u64,
    pub identities: u64,
    pub identity_capacity: u64,
    pub bindings: u64,
    pub binding_capacity: u64,
    pub ledger_bytes: u64,
    pub ledger_capacity: u64,
    pub database_bytes: u64,
    pub database_capacity: u64,
    pub journal_capacity: u64,
    pub operation_capacity: usize,
    pub operations_in_flight: usize,
    pub command_depth: usize,
    pub command_capacity: usize,
    pub accepted: u64,
    pub replayed: u64,
    pub payload_prune_operations: u64,
    pub payloads_pruned: u64,
    pub payload_bytes_pruned: u64,
    pub identity_prune_operations: u64,
    pub identities_pruned: u64,
    pub identity_metadata_bytes_pruned: u64,
    pub rejected: u64,
    pub timeouts: u64,
    pub failures: u64,
    pub available: bool,
}

/// Per-call prefix work limits. Raw bytes exclude the fixed logical payload charge.
/// This trusted local mechanism has no serialized configuration or wire contract.
#[derive(Clone, Copy, Debug)]
pub struct PayloadPruneBudget {
    pub max_records: u64,
    pub max_raw_bytes: u64,
}
impl PayloadPruneBudget {
    pub(crate) fn validate(&self, config: &CoverageConfig) -> Result<(), CoverageError> {
        let raw_cap = config
            .max_payloads
            .checked_mul(format::MAX_RAW_BYTES as u64)
            .ok_or(CoverageError::Invalid("payload pruning budget overflow"))?
            .min(config.max_ledger_bytes);
        if self.max_records == 0
            || self.max_records > config.max_payloads
            || self.max_raw_bytes == 0
            || self.max_raw_bytes > raw_cap
        {
            return Err(CoverageError::Invalid("finite payload pruning budget"));
        }
        Ok(())
    }
}

/// Successful global prefix reclamation; zero records means no durable mutation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PayloadPruneOutcome {
    pub pruned_records: u64,
    pub pruned_raw_bytes: u64,
    pub reclaimed_ledger_bytes: u64,
    pub payload_pruned_through: u64,
}

/// Per-call identity prefix limits. Metadata bytes count selected immutable commit encodings.
/// Each selected record can reclaim at most one bounded binding and one bounded profile pin.
#[derive(Clone, Copy, Debug)]
pub struct IdentityPruneBudget {
    pub max_records: u64,
    pub max_metadata_bytes: u64,
}
impl IdentityPruneBudget {
    pub(crate) fn validate(&self, config: &CoverageConfig) -> Result<(), CoverageError> {
        let metadata_cap = config
            .max_identities
            .checked_mul(format::MAX_METADATA_BYTES as u64)
            .ok_or(CoverageError::Invalid("identity pruning budget overflow"))?
            .min(config.max_ledger_bytes);
        if self.max_records == 0
            || self.max_records > config.max_identities
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > metadata_cap
        {
            return Err(CoverageError::Invalid("finite identity pruning budget"));
        }
        Ok(())
    }
}

/// Successful identity prefix reclamation, including any newly unreferenced pins.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityPruneOutcome {
    pub pruned_records: u64,
    pub pruned_metadata_bytes: u64,
    pub reclaimed_ledger_bytes: u64,
    pub identity_pruned_through: u64,
}

/// Immutable receiver metadata supplied by a trusted local caller; no credentials or policy.
#[derive(Clone, Debug)]
pub struct AdmissionMetadata {
    pub authority_revision: String,
    pub accepted_at: Timestamp,
    pub replay_until: Timestamp,
    pub identity_until: Timestamp,
}
/// Prepared report: SDK semantic validation and full-key equality precede store dispatch.
#[derive(Clone, Debug)]
pub struct PreparedObservation {
    pub(crate) raw: Vec<u8>,
    pub(crate) profile: ProfileDefinition,
    pub(crate) binding: HistoryBinding,
    pub(crate) record_id: Uuid,
    pub(crate) admission: AdmissionMetadata,
}
impl PreparedObservation {
    pub fn prepare(
        raw: &[u8],
        profile: ProfileDefinition,
        binding: HistoryBinding,
        admission: AdmissionMetadata,
    ) -> Result<Self, CoverageError> {
        validate_raw(raw, &profile, &binding, admission.accepted_at)?;
        if admission.authority_revision.is_empty()
            || admission.authority_revision.len() > 1024
            || admission.accepted_at >= admission.replay_until
            || admission.replay_until > admission.identity_until
            || admission.identity_until.datetime()? - admission.accepted_at.datetime()?
                > chrono::TimeDelta::seconds(u32::MAX.into())
        {
            return Err(CoverageError::Invalid("admission metadata"));
        }
        let (_, times) = HistoryBinding::from_record(raw)?;
        Ok(Self {
            raw: raw.to_vec(),
            profile,
            binding,
            record_id: times.id,
            admission,
        })
    }
    pub fn record_id(&self) -> Uuid {
        self.record_id
    }
}
fn validate_raw(
    raw: &[u8],
    profile: &ProfileDefinition,
    binding: &HistoryBinding,
    at: Timestamp,
) -> Result<(), CoverageError> {
    ValidatedCoverage::parse(raw, Some(&profile.sdk)).map_err(CoverageError::Coverage)?;
    let (actual, times) = HistoryBinding::from_record(raw)?;
    if actual.encoded() != binding.encoded() || !binding.profile_matches(profile) {
        return Err(CoverageError::Invalid("full binding/profile mismatch"));
    }
    format::non_nil(times.id)?;
    let maximum = at
        .datetime()?
        .checked_add_signed(chrono::TimeDelta::seconds(i64::from(profile.skew())))
        .ok_or(CoverageError::Invalid("admission time overflow"))?;
    if times.verified.datetime()? > maximum || times.observed.datetime()? > maximum {
        return Err(CoverageError::Invalid("report verification in future"));
    }
    Ok(())
}

/// Versioned durable receipt. External exposure requires a separate authorized intake layer.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub history_id: Uuid,
    pub sequence: String,
    pub record_id: Uuid,
    pub content_sha256: String,
    pub prefix_digest: String,
    pub accepted_at: String,
    pub replay_until: String,
    pub identity_until: String,
    pub profile_fingerprint: String,
    pub authority_revision: String,
    pub correction_of: Option<Uuid>,
}
impl Receipt {
    pub(crate) fn validate_reference(&self) -> Result<u64, CoverageError> {
        if self.sequence.is_empty() || self.sequence.len() > 20 {
            return Err(CoverageError::Invalid("receipt sequence bound"));
        }
        let sequence = self
            .sequence
            .parse::<u64>()
            .map_err(|_| CoverageError::Invalid("receipt sequence"))?;
        let hashes = [
            &self.content_sha256,
            &self.prefix_digest,
            &self.profile_fingerprint,
        ];
        if self.schema_version != 1
            || self.history_id.is_nil()
            || self.record_id.is_nil()
            || sequence == 0
            || self.sequence != sequence.to_string()
            || hashes.iter().any(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || self.authority_revision.is_empty()
            || self.authority_revision.len() > 1024
        {
            return Err(CoverageError::Invalid("receipt reference"));
        }
        for time in [&self.accepted_at, &self.replay_until, &self.identity_until] {
            if Timestamp::parse(time)?.to_string() != *time {
                return Err(CoverageError::Invalid("receipt canonical time"));
            }
        }
        if self.accepted_at >= self.replay_until || self.replay_until > self.identity_until {
            return Err(CoverageError::Invalid("receipt retention ordering"));
        }
        if let Some(id) = self.correction_of {
            format::non_nil(id)?;
        }
        Ok(sequence)
    }
    fn from_metadata(m: &CommitMetadata, prefix: [u8; 32]) -> Result<Self, CoverageError> {
        let r = Self {
            schema_version: 1,
            history_id: m.history_id,
            sequence: m.sequence.to_string(),
            record_id: m.record_id,
            content_sha256: format::hex(&m.content_sha256),
            prefix_digest: format::hex(&prefix),
            accepted_at: m.accepted_at.to_string(),
            replay_until: m.replay_until.to_string(),
            identity_until: m.identity_until.to_string(),
            profile_fingerprint: format::hex(&m.profile_fingerprint),
            authority_revision: m.authority_revision.clone(),
            correction_of: m.correction_of,
        };
        if serde_json::to_vec(&r)
            .map_err(|_| CoverageError::Invalid("receipt JSON"))?
            .len()
            > 4096
        {
            return Err(CoverageError::Invalid("receipt encoded bound"));
        }
        Ok(r)
    }
}
/// One bounded read for trusted library callers. No retry-success or current-health policy.
#[derive(Clone, Debug)]
pub struct StoredObservation {
    pub receipt: Receipt,
    pub raw: Option<Vec<u8>>,
    pub profile: ProfileDefinition,
    pub binding: HistoryBinding,
}

const SCHEMA: &[(&str, &str)] = &[
    (
        "state",
        "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL CHECK(length(data)<=512), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT",
    ),
    (
        "profiles",
        "CREATE TABLE profiles (id TEXT NOT NULL, revision TEXT NOT NULL, definition BLOB NOT NULL CHECK(length(definition)<=8192), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), PRIMARY KEY(id,revision)) STRICT, WITHOUT ROWID",
    ),
    (
        "bindings",
        "CREATE TABLE bindings (key BLOB PRIMARY KEY CHECK(length(key)<=65536), profile_id TEXT NOT NULL, profile_revision TEXT NOT NULL, FOREIGN KEY(profile_id,profile_revision) REFERENCES profiles(id,revision)) STRICT, WITHOUT ROWID",
    ),
    (
        "entries",
        "CREATE TABLE entries (sequence BLOB PRIMARY KEY CHECK(length(sequence)=8), record_id BLOB NOT NULL UNIQUE CHECK(length(record_id)=16), metadata BLOB NOT NULL CHECK(length(metadata)<=73728), prefix BLOB NOT NULL CHECK(length(prefix)=32), raw BLOB CHECK(length(raw)<=65536), binding BLOB NOT NULL, profile_id TEXT NOT NULL, profile_revision TEXT NOT NULL, FOREIGN KEY(binding) REFERENCES bindings(key), FOREIGN KEY(profile_id,profile_revision) REFERENCES profiles(id,revision)) STRICT, WITHOUT ROWID",
    ),
];

pub(crate) struct Engine {
    // Connection closes before the root lock (field drop order) and exit notification.
    connection: Connection,
    _lock: File,
    root: File,
    config: CoverageConfig,
    state: State,
    database_bytes: u64,
}
struct LoadedRow {
    sequence: Vec<u8>,
    metadata: Vec<u8>,
    prefix: Vec<u8>,
    raw: Option<Vec<u8>>,
    binding: Vec<u8>,
    profile_id: String,
    profile_revision: String,
}
struct IdentityRow {
    record_id: Vec<u8>,
    metadata: Vec<u8>,
    prefix: Vec<u8>,
    raw_unavailable: bool,
    binding: Vec<u8>,
    profile_id: String,
    profile_revision: String,
}
fn safe_path(path: &Path, directory: bool) -> Result<(), CoverageError> {
    for p in path.ancestors() {
        match fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(CoverageError::Corrupt("symlink path"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let m = fs::symlink_metadata(path)?;
    if (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1))
        || m.permissions().mode() & 0o777 != if directory { 0o700 } else { 0o600 }
    {
        return Err(CoverageError::Corrupt("private root/file type or mode"));
    }
    Ok(())
}
fn new_file(path: &Path) -> Result<File, CoverageError> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn check_root(config: &CoverageConfig) -> Result<(), CoverageError> {
    safe_path(&config.directory, true)?;
    for e in fs::read_dir(&config.directory)? {
        let e = e?;
        let name = e.file_name();
        if ![
            ".lock",
            "identity",
            "coverage.sqlite3",
            "coverage.sqlite3-journal",
        ]
        .iter()
        .any(|n| name == *n)
        {
            return Err(CoverageError::Corrupt(
                "unexpected or interrupted root entry",
            ));
        }
        safe_path(&e.path(), false)?;
        let len = e.metadata()?.len();
        let cap = match name.to_str() {
            Some(".lock") => 0,
            Some("identity") => 56,
            Some("coverage.sqlite3") => u64::from(config.max_database_pages) * 4096,
            _ => config.max_journal_bytes,
        };
        if len > cap {
            return Err(CoverageError::Quota);
        }
    }
    Ok(())
}
fn bounded_blob(row: &rusqlite::Row<'_>, column: usize, cap: usize) -> rusqlite::Result<Vec<u8>> {
    let data = row.get_ref(column)?.as_blob()?;
    if data.len() > cap {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::other("coverage blob bound")),
        ));
    }
    Ok(data.to_vec())
}
fn bounded_text(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<String> {
    let s = row.get_ref(column)?.as_str()?;
    if s.is_empty() || s.len() > 1024 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other("coverage text bound")),
        ));
    }
    Ok(s.to_owned())
}
fn count(connection: &Connection, table: &str) -> Result<u64, CoverageError> {
    // Only fixed internal table names call this helper.
    let sql = match table {
        "entries" => "SELECT count(*) FROM entries",
        "bindings" => "SELECT count(*) FROM bindings",
        "profiles" => "SELECT count(*) FROM profiles",
        _ => return Err(CoverageError::Corrupt("table inventory")),
    };
    let n: i64 = connection.query_row(sql, [], |r| r.get(0))?;
    u64::try_from(n).map_err(|_| CoverageError::Corrupt("negative count"))
}
impl Engine {
    pub fn open(
        config: CoverageConfig,
        initial: Option<(Uuid, Timestamp)>,
        ctx: &WorkContext,
    ) -> Result<Self, CoverageError> {
        config.validate()?;
        ctx.check()?;
        let directory = &config.directory;
        if let Some((id, _)) = initial {
            format::non_nil(id)?;
            for p in directory.ancestors().skip(1) {
                if let Ok(m) = fs::symlink_metadata(p)
                    && m.file_type().is_symlink()
                {
                    return Err(CoverageError::Corrupt("symlink ancestor"));
                }
            }
            ctx.start()?;
            fs::DirBuilder::new().mode(0o700).create(directory)?;
            File::open(
                directory
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
        }
        check_root(&config)?;
        let root = File::open(directory)?;
        let lock = if initial.is_some() {
            new_file(&directory.join(".lock"))?
        } else {
            safe_path(&directory.join(".lock"), false)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(directory.join(".lock"))?
        };
        lock.try_lock().map_err(|_| CoverageError::Locked)?;
        if lock.metadata()?.len() != 0 {
            return Err(CoverageError::Corrupt("lock file"));
        }
        let history = if let Some((id, _)) = initial {
            let mut f = new_file(&directory.join("identity.tmp"))?;
            f.write_all(&format::identity(id)?)?;
            f.sync_all()?;
            fs::rename(directory.join("identity.tmp"), directory.join("identity"))?;
            root.sync_all()?;
            let f = new_file(&directory.join("coverage.sqlite3"))?;
            f.sync_all()?;
            root.sync_all()?;
            id
        } else {
            safe_path(&directory.join("identity"), false)?;
            let mut f = File::open(directory.join("identity"))?;
            let mut bytes = [0; 56];
            if f.metadata()?.len() != 56 {
                return Err(CoverageError::Corrupt("identity size"));
            }
            f.read_exact(&mut bytes)?;
            safe_path(&directory.join("coverage.sqlite3"), false)?;
            if fs::metadata(directory.join("coverage.sqlite3"))?.len() < 4096 {
                return Err(CoverageError::Corrupt("database header unavailable"));
            }
            format::read_identity(&bytes)?
        };
        ctx.start()?;
        let connection = Connection::open_with_flags_and_vfs(
            directory.join("coverage.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            "unix",
        )?;
        set_progress(&connection, ctx, &config)?;
        if initial.is_none() {
            let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if version != 1 {
                return Err(CoverageError::Corrupt("database schema version"));
            }
        }
        configure(&connection, &config)?;
        if let Some((_, clock)) = initial {
            let state = State::empty(history, clock)?;
            connection.execute_batch("BEGIN IMMEDIATE")?;
            for (_, sql) in SCHEMA {
                connection.execute_batch(sql)?;
            }
            connection.execute_batch("PRAGMA user_version=1")?;
            let data = state.encode()?;
            connection.execute(
                "INSERT INTO state VALUES(1,?1,?2)",
                params![&data, &format::sha256(&data)[..]],
            )?;
            connection.execute_batch("COMMIT")?;
            root.sync_all()?;
        }
        let state = load_state(&connection)?;
        if state.history_id != history {
            return Err(CoverageError::Corrupt("sidecar/state history mismatch"));
        }
        let database_bytes = fs::metadata(directory.join("coverage.sqlite3"))?.len();
        let engine = Self {
            connection,
            _lock: lock,
            root,
            config,
            state,
            database_bytes,
        };
        engine.recover(ctx)?;
        ctx.check()?;
        Ok(engine)
    }
    pub fn metrics(&self) -> CoverageMetrics {
        CoverageMetrics {
            history_id: self.state.history_id,
            committed_sequence: self.state.committed_sequence,
            payload_pruned_through: self.state.payload_pruned_through,
            identity_pruned_through: self.state.identity_pruned_through,
            payloads: self.state.payload_count,
            payload_capacity: self.config.max_payloads,
            identities: self.state.identity_count,
            identity_capacity: self.config.max_identities,
            bindings: self.state.binding_count,
            binding_capacity: self.config.max_bindings,
            ledger_bytes: self.state.ledger_charge,
            ledger_capacity: self.config.max_ledger_bytes,
            database_bytes: self.database_bytes,
            database_capacity: u64::from(self.config.max_database_pages) * 4096,
            journal_capacity: self.config.max_journal_bytes,
            operation_capacity: self.config.operation_capacity,
            available: true,
            ..CoverageMetrics::default()
        }
    }
    pub fn begin(&self, ctx: &WorkContext) -> Result<(), CoverageError> {
        set_progress(&self.connection, ctx, &self.config)
    }
    pub fn scan(
        &self,
        authority: AuthorizedBinding,
        cursor: Option<crate::ScanCursor>,
        budget: crate::ScanBudget,
        ctx: &WorkContext,
    ) -> Result<crate::ScanPage, CoverageError> {
        use crate::scan::{CursorState, ScanPage, ScanRecord, page_header_bytes};
        budget.validate(&self.config)?;
        ctx.check()?;
        let availability = crate::ScanAvailability {
            history_id: self.state.history_id,
            committed_sequence: self.state.committed_sequence,
            payload_pruned_through: self.state.payload_pruned_through,
            identity_pruned_through: self.state.identity_pruned_through,
        };
        let mut position = if let Some(cursor) = cursor {
            let position = cursor.state()?;
            // Cursor knowledge never grants access, including retention classification.
            if position.binding != authority.binding.encoded() {
                return Err(CoverageError::NotAuthorized);
            }
            if position.history_id != self.state.history_id
                || position.frontier > self.state.committed_sequence
                || position.payload_marker > self.state.payload_pruned_through
                || position.identity_marker > self.state.identity_pruned_through
            {
                return Err(CoverageError::HistoryUnavailable);
            }
            if position.payload_marker != self.state.payload_pruned_through
                || position.identity_marker != self.state.identity_pruned_through
            {
                return Err(CoverageError::HistoryPruned(availability));
            }
            if self.scan_prefix(position.frontier)? != position.frontier_prefix
                || self.scan_prefix(position.last)? != position.last_prefix
            {
                return Err(CoverageError::HistoryUnavailable);
            }
            position
        } else {
            CursorState {
                history_id: self.state.history_id,
                binding: authority.binding.encoded().to_vec(),
                frontier: self.state.committed_sequence,
                frontier_prefix: self.state.committed_prefix,
                last: self.state.identity_pruned_through,
                last_prefix: self.state.identity_anchor,
                payload_marker: self.state.payload_pruned_through,
                identity_marker: self.state.identity_pruned_through,
            }
        };
        let mut page = ScanPage {
            records: Vec::new(),
            continuation: None,
            availability,
            frontier: position.frontier,
            scanned_records: 0,
            scanned_bytes: 0,
            response_bytes: page_header_bytes(&authority),
            permit: None,
        };
        if page.response_bytes > budget.max_response_bytes {
            return Err(CoverageError::ResponseLimit);
        }
        while position.last < position.frontier
            && page.scanned_records < budget.max_scanned_records
            && (page.records.len() as u64) < budget.max_records
        {
            ctx.check()?;
            let sequence = position
                .last
                .checked_add(1)
                .ok_or(CoverageError::Exhausted)?;
            // Probe fixed-size lengths before allocating any row, payload, binding or pin.
            let (record_id, row_bytes) = self.scan_row_size(sequence)?;
            let scanned_bytes = add(page.scanned_bytes, row_bytes)?;
            if scanned_bytes > budget.max_scanned_bytes {
                if page.scanned_records == 0 {
                    return Err(CoverageError::ScanWorkLimit);
                }
                break;
            }
            let stored = self
                .load(record_id, ctx)
                .map_err(|error| match error {
                    CoverageError::Invalid(_) | CoverageError::Coverage(_) => {
                        CoverageError::Corrupt("scan row metadata")
                    }
                    other => other,
                })?
                .ok_or(CoverageError::Corrupt("scan missing row"))?;
            if stored.receipt.sequence != sequence.to_string() {
                return Err(CoverageError::Corrupt("scan row sequence"));
            }
            page.scanned_records = add(page.scanned_records, 1)?;
            page.scanned_bytes = scanned_bytes;
            if stored.binding.encoded() == authority.binding.encoded() {
                let response_bytes = add(
                    page.response_bytes,
                    stored.raw.as_ref().map_or(0, |raw| raw.len() as u64)
                        + crate::SCAN_RECORD_ALLOWANCE_BYTES,
                )?;
                if response_bytes > budget.max_response_bytes {
                    if page.records.is_empty() {
                        return Err(CoverageError::ResponseLimit);
                    }
                    // This row was examined but not consumed. The next page must retry it.
                    break;
                }
                page.records
                    .try_reserve_exact(1)
                    .map_err(|_| CoverageError::Quota)?;
                page.response_bytes = response_bytes;
                let prefix = receipt_prefix(&stored.receipt)?;
                page.records.push(ScanRecord {
                    receipt: stored.receipt,
                    raw: stored.raw,
                });
                position.last_prefix = prefix;
            } else {
                position.last_prefix = receipt_prefix(&stored.receipt)?;
            }
            position.last = sequence;
        }
        if position.last < position.frontier {
            page.continuation = Some(position.encode()?);
        }
        ctx.check()?;
        Ok(page)
    }
    fn scan_prefix(&self, sequence: u64) -> Result<[u8; 32], CoverageError> {
        if sequence == self.state.identity_pruned_through {
            return Ok(self.state.identity_anchor);
        }
        if sequence == self.state.payload_pruned_through {
            return Ok(self.state.payload_anchor);
        }
        if sequence == self.state.committed_sequence {
            return Ok(self.state.committed_prefix);
        }
        let prefix = self
            .connection
            .query_row(
                "SELECT prefix FROM entries WHERE sequence=?1",
                params![&sequence.to_be_bytes()[..]],
                |r| bounded_blob(r, 0, 32),
            )
            .optional()?
            .ok_or(CoverageError::HistoryUnavailable)?;
        prefix
            .try_into()
            .map_err(|_| CoverageError::Corrupt("scan witness width"))
    }
    fn scan_row_size(&self, sequence: u64) -> Result<(Uuid, u64), CoverageError> {
        let row = self.connection.query_row(
            "SELECT e.record_id,length(e.metadata),coalesce(length(e.raw),0),length(e.binding),length(p.definition),b.profile_id=e.profile_id AND b.profile_revision=e.profile_revision FROM entries e LEFT JOIN profiles p ON p.id=e.profile_id AND p.revision=e.profile_revision LEFT JOIN bindings b ON b.key=e.binding WHERE e.sequence=?1",
            params![&sequence.to_be_bytes()[..]],
            |r| Ok((bounded_blob(r, 0, 16)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, Option<bool>>(5)?)),
        ).optional()?.ok_or(CoverageError::Corrupt("scan missing prefix"))?;
        let record_id =
            Uuid::from_slice(&row.0).map_err(|_| CoverageError::Corrupt("scan record UUID"))?;
        if record_id.is_nil() {
            return Err(CoverageError::Corrupt("scan nil record UUID"));
        }
        if row.5 != Some(true) {
            return Err(CoverageError::Corrupt("scan binding pin references"));
        }
        let profile_len = row
            .4
            .ok_or(CoverageError::Corrupt("scan missing profile pin"))?;
        let mut charge = crate::SCAN_WORK_ALLOWANCE_BYTES;
        for (length, cap) in [
            (row.1, format::MAX_METADATA_BYTES),
            (row.2, format::MAX_RAW_BYTES),
            (row.3, format::MAX_BINDING_BYTES),
            (profile_len, format::MAX_PROFILE_BYTES),
        ] {
            let n = u64::try_from(length)
                .map_err(|_| CoverageError::Corrupt("scan negative length"))?;
            if n > cap as u64 {
                return Err(CoverageError::Corrupt("scan row bound"));
            }
            charge = add(charge, n)?;
        }
        Ok((record_id, charge))
    }
    pub fn prune_payloads(
        &mut self,
        now: Timestamp,
        budget: PayloadPruneBudget,
        ctx: &WorkContext,
    ) -> Result<PayloadPruneOutcome, CoverageError> {
        budget.validate(&self.config)?;
        ctx.check()?;
        if now < self.state.clock_floor {
            return Err(CoverageError::ClockRegression);
        }
        let mut outcome = PayloadPruneOutcome {
            payload_pruned_through: self.state.payload_pruned_through,
            ..PayloadPruneOutcome::default()
        };
        let mut anchor = self.state.payload_anchor;
        let mut blocked = false;
        // One owned worker holds the store throughout selection and commit. Stream metadata,
        // then read only a byte-budget-eligible payload; never retain a history-sized vector.
        {
            let mut stmt = self.connection.prepare(
                "SELECT sequence,metadata,prefix,length(raw) FROM entries WHERE sequence>?1 ORDER BY sequence LIMIT ?2",
            )?;
            let mut rows = stmt.query(params![
                &self.state.payload_pruned_through.to_be_bytes()[..],
                budget.max_records as i64
            ])?;
            while let Some(row) = rows.next()? {
                ctx.check()?;
                let sequence = outcome
                    .payload_pruned_through
                    .checked_add(1)
                    .ok_or(CoverageError::Exhausted)?;
                let data = bounded_blob(row, 1, format::MAX_METADATA_BYTES)?;
                let metadata = CommitMetadata::decode(&data)
                    .map_err(|_| CoverageError::Corrupt("payload pruning metadata"))?;
                let prefix = format::prefix(anchor, &data);
                let raw_length: Option<i64> = row.get(3)?;
                if bounded_blob(row, 0, 8)? != sequence.to_be_bytes()
                    || metadata.sequence != sequence
                    || metadata.history_id != self.state.history_id
                    || sequence > self.state.committed_sequence
                    || bounded_blob(row, 2, 32)? != prefix
                    || raw_length != Some(i64::from(metadata.raw_length))
                {
                    return Err(CoverageError::Corrupt("payload pruning prefix"));
                }
                if metadata.replay_until > now {
                    blocked = true;
                    break;
                }
                let total_raw = add(outcome.pruned_raw_bytes, u64::from(metadata.raw_length))?;
                if total_raw > budget.max_raw_bytes {
                    blocked = true;
                    break;
                }
                let raw = self.connection.query_row(
                    "SELECT raw FROM entries WHERE sequence=?1",
                    params![&sequence.to_be_bytes()[..]],
                    |r| bounded_blob(r, 0, format::MAX_RAW_BYTES),
                )?;
                if raw.len() != metadata.raw_length as usize
                    || format::sha256(&raw) != metadata.content_sha256
                {
                    return Err(CoverageError::Corrupt("payload pruning original bytes"));
                }
                outcome.pruned_records = add(outcome.pruned_records, 1)?;
                outcome.pruned_raw_bytes = total_raw;
                outcome.reclaimed_ledger_bytes = add(
                    outcome.reclaimed_ledger_bytes,
                    u64::from(metadata.raw_length) + 256,
                )?;
                outcome.payload_pruned_through = sequence;
                anchor = prefix;
            }
        }
        ctx.check()?;
        if !blocked
            && outcome.pruned_records < budget.max_records
            && outcome.payload_pruned_through < self.state.committed_sequence
        {
            return Err(CoverageError::Corrupt("payload pruning missing prefix"));
        }
        if outcome.pruned_records == 0 {
            return Ok(outcome);
        }
        let mut state = self.state.clone();
        state.payload_pruned_through = outcome.payload_pruned_through;
        state.payload_anchor = anchor;
        state.clock_floor = now;
        state.payload_count = state
            .payload_count
            .checked_sub(outcome.pruned_records)
            .ok_or(CoverageError::Corrupt("payload pruning count"))?;
        state.ledger_charge = state
            .ledger_charge
            .checked_sub(outcome.reclaimed_ledger_bytes)
            .ok_or(CoverageError::Corrupt("payload pruning charge"))?;
        let state_data = state.encode()?;
        ctx.start()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pruned = tx.execute(
            "UPDATE entries SET raw=NULL WHERE sequence>?1 AND sequence<=?2 AND raw IS NOT NULL",
            params![
                &self.state.payload_pruned_through.to_be_bytes()[..],
                &state.payload_pruned_through.to_be_bytes()[..]
            ],
        )?;
        if pruned as u64 != outcome.pruned_records {
            return Err(CoverageError::Corrupt("payload pruning cardinality"));
        }
        let updated = tx.execute(
            "UPDATE state SET data=?1,checksum=?2 WHERE id=1",
            params![&state_data, &format::sha256(&state_data)[..]],
        )?;
        if updated != 1 {
            return Err(CoverageError::Corrupt("state update cardinality"));
        }
        #[cfg(test)]
        test_checkpoint("prune_before_commit", state.payload_pruned_through)?;
        tx.commit()?;
        #[cfg(test)]
        test_checkpoint("prune_after_commit", state.payload_pruned_through)?;
        self.state = state;
        self.database_bytes = fs::metadata(self.config.directory.join("coverage.sqlite3"))?.len();
        ctx.check()?;
        Ok(outcome)
    }
    pub fn prune_identities(
        &mut self,
        now: Timestamp,
        budget: IdentityPruneBudget,
        ctx: &WorkContext,
    ) -> Result<IdentityPruneOutcome, CoverageError> {
        budget.validate(&self.config)?;
        ctx.check()?;
        if now < self.state.clock_floor {
            return Err(CoverageError::ClockRegression);
        }
        let mut outcome = IdentityPruneOutcome {
            identity_pruned_through: self.state.identity_pruned_through,
            ..IdentityPruneOutcome::default()
        };
        let mut anchor = self.state.identity_anchor;
        while outcome.pruned_records < budget.max_records
            && outcome.identity_pruned_through < self.state.payload_pruned_through
        {
            ctx.check()?;
            let sequence = outcome
                .identity_pruned_through
                .checked_add(1)
                .ok_or(CoverageError::Exhausted)?;
            let row = identity_row(&self.connection, sequence)?;
            let metadata =
                validate_identity_row(&self.connection, &row, sequence, anchor, &self.state)?;
            if metadata.identity_until > now {
                break;
            }
            let total_metadata = add(outcome.pruned_metadata_bytes, row.metadata.len() as u64)?;
            if total_metadata > budget.max_metadata_bytes {
                break;
            }
            anchor = format::prefix(anchor, &row.metadata);
            outcome.pruned_records = add(outcome.pruned_records, 1)?;
            outcome.pruned_metadata_bytes = total_metadata;
            outcome.reclaimed_ledger_bytes = add(
                outcome.reclaimed_ledger_bytes,
                row.metadata.len() as u64 + 8192,
            )?;
            outcome.identity_pruned_through = sequence;
        }
        ctx.check()?;
        if outcome.pruned_records == 0 {
            return Ok(outcome);
        }
        let mut state = self.state.clone();
        state.identity_pruned_through = outcome.identity_pruned_through;
        state.identity_anchor = anchor;
        state.identity_count = state
            .identity_count
            .checked_sub(outcome.pruned_records)
            .ok_or(CoverageError::Corrupt("identity pruning count"))?;
        state.clock_floor = now;
        ctx.start()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Point-load one selected row at a time. Pin reclamation is bounded by those rows,
        // with no global orphan scan, accumulated registry list or history-sized allocation.
        let mut current_anchor = self.state.identity_anchor;
        for offset in 1..=outcome.pruned_records {
            ctx.check()?;
            let sequence = self
                .state
                .identity_pruned_through
                .checked_add(offset)
                .ok_or(CoverageError::Exhausted)?;
            let row = identity_row(&tx, sequence)?;
            let metadata = validate_identity_row(&tx, &row, sequence, current_anchor, &self.state)?;
            if metadata.identity_until > now {
                return Err(CoverageError::Corrupt("identity pruning changed deadline"));
            }
            current_anchor = format::prefix(current_anchor, &row.metadata);
            if tx.execute(
                "DELETE FROM entries WHERE sequence=?1 AND raw IS NULL",
                params![&sequence.to_be_bytes()[..]],
            )? != 1
            {
                return Err(CoverageError::Corrupt("identity pruning cardinality"));
            }
            let binding_referenced = tx
                .query_row(
                    "SELECT 1 FROM entries WHERE binding=?1 LIMIT 1",
                    params![&row.binding],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .is_some();
            if !binding_referenced {
                if tx.execute("DELETE FROM bindings WHERE key=?1", params![&row.binding])? != 1 {
                    return Err(CoverageError::Corrupt(
                        "identity pruning binding cardinality",
                    ));
                }
                state.binding_count = state
                    .binding_count
                    .checked_sub(1)
                    .ok_or(CoverageError::Corrupt("identity pruning binding count"))?;
                outcome.reclaimed_ledger_bytes = add(
                    outcome.reclaimed_ledger_bytes,
                    row.binding.len() as u64 + 4096,
                )?;
                let profile_referenced = tx
                    .query_row(
                        "SELECT 1 FROM entries WHERE profile_id=?1 AND profile_revision=?2 LIMIT 1",
                        params![&row.profile_id, &row.profile_revision],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()?
                    .is_some()
                    || tx
                        .query_row(
                            "SELECT 1 FROM bindings WHERE profile_id=?1 AND profile_revision=?2 LIMIT 1",
                            params![&row.profile_id, &row.profile_revision],
                            |r| r.get::<_, i64>(0),
                        )
                        .optional()?
                        .is_some();
                if !profile_referenced {
                    let profile = load_profile(&tx, &row.profile_id, &row.profile_revision)?;
                    if tx.execute(
                        "DELETE FROM profiles WHERE id=?1 AND revision=?2",
                        params![&row.profile_id, &row.profile_revision],
                    )? != 1
                    {
                        return Err(CoverageError::Corrupt(
                            "identity pruning profile cardinality",
                        ));
                    }
                    state.profile_count = state
                        .profile_count
                        .checked_sub(1)
                        .ok_or(CoverageError::Corrupt("identity pruning profile count"))?;
                    outcome.reclaimed_ledger_bytes = add(
                        outcome.reclaimed_ledger_bytes,
                        profile.encoded().len() as u64 + 4096,
                    )?;
                }
            }
        }
        if current_anchor != state.identity_anchor {
            return Err(CoverageError::Corrupt("identity pruning changed prefix"));
        }
        state.ledger_charge = state
            .ledger_charge
            .checked_sub(outcome.reclaimed_ledger_bytes)
            .ok_or(CoverageError::Corrupt("identity pruning charge"))?;
        let state_data = state.encode()?;
        if tx.execute(
            "UPDATE state SET data=?1,checksum=?2 WHERE id=1",
            params![&state_data, &format::sha256(&state_data)[..]],
        )? != 1
        {
            return Err(CoverageError::Corrupt("state update cardinality"));
        }
        #[cfg(test)]
        test_checkpoint(
            "identity_prune_before_commit",
            state.identity_pruned_through,
        )?;
        tx.commit()?;
        #[cfg(test)]
        test_checkpoint("identity_prune_after_commit", state.identity_pruned_through)?;
        self.state = state;
        self.database_bytes = fs::metadata(self.config.directory.join("coverage.sqlite3"))?.len();
        ctx.check()?;
        Ok(outcome)
    }
    fn recover(&self, ctx: &WorkContext) -> Result<(), CoverageError> {
        let mut schema = self
            .connection
            .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name")?;
        let mut rows = schema.query([])?;
        let mut tables = 0;
        let mut indexes = 0;
        while let Some(row) = rows.next()? {
            ctx.check()?;
            let kind: String = row.get(0)?;
            let name: String = row.get(1)?;
            let table: String = row.get(2)?;
            let sql: Option<String> = row.get(3)?;
            if kind == "table"
                && let Some((_, expected)) = SCHEMA.iter().find(|(n, _)| *n == name)
            {
                if sql.as_deref() != Some(*expected) {
                    return Err(CoverageError::Corrupt("schema definition"));
                }
                tables += 1;
            } else if kind == "index"
                && table == "entries"
                && name.starts_with("sqlite_autoindex_entries_")
                && sql.is_none()
            {
                indexes += 1;
            } else {
                return Err(CoverageError::Corrupt("schema inventory"));
            }
        }
        if tables != 4 || indexes != 1 {
            return Err(CoverageError::Corrupt("schema inventory count"));
        }
        let integrity: String =
            self.connection
                .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(CoverageError::Corrupt("SQLite integrity"));
        }
        if self
            .connection
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_some()
        {
            return Err(CoverageError::Corrupt("foreign key integrity"));
        }
        for (table, cap) in [
            ("entries", self.config.max_identities),
            ("profiles", self.config.max_bindings),
            ("bindings", self.config.max_bindings),
        ] {
            if count(&self.connection, table)? > cap {
                return Err(CoverageError::Quota);
            }
        }
        if self.state.payload_count > self.config.max_payloads
            || self.state.ledger_charge > self.config.max_ledger_bytes
        {
            return Err(CoverageError::Quota);
        }
        let mut charge = format::ROOT_CHARGE;
        let mut profiles = 0_u64;
        let mut bindings = 0_u64;
        let mut stmt = self
            .connection
            .prepare("SELECT id,revision,definition,fingerprint FROM profiles")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            ctx.check()?;
            let id = bounded_text(row, 0)?;
            let rev = bounded_text(row, 1)?;
            let data = bounded_blob(row, 2, format::MAX_PROFILE_BYTES)?;
            let p = ProfileDefinition::decode(&data)?;
            if p.id() != id
                || p.revision() != rev
                || p.fingerprint() != bounded_blob(row, 3, 32)?.as_slice()
            {
                return Err(CoverageError::Corrupt("profile pin"));
            }
            let refs: i64 = self.connection.query_row(
                "SELECT count(*) FROM entries WHERE profile_id=?1 AND profile_revision=?2",
                params![id, rev],
                |r| r.get(0),
            )?;
            if refs == 0 {
                return Err(CoverageError::Corrupt("orphan profile"));
            }
            charge = add(charge, data.len() as u64 + 4096)?;
            profiles += 1;
        }
        let mut stmt = self
            .connection
            .prepare("SELECT key,profile_id,profile_revision FROM bindings")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            ctx.check()?;
            let key = bounded_blob(row, 0, format::MAX_BINDING_BYTES)?;
            let binding = HistoryBinding::decode(&key)?;
            let id = bounded_text(row, 1)?;
            let rev = bounded_text(row, 2)?;
            let p = load_profile(&self.connection, &id, &rev)?;
            if !binding.profile_matches(&p) {
                return Err(CoverageError::Corrupt("binding profile reference"));
            }
            let refs: i64 = self.connection.query_row(
                "SELECT count(*) FROM entries WHERE binding=?1",
                params![&key],
                |r| r.get(0),
            )?;
            if refs == 0 {
                return Err(CoverageError::Corrupt("orphan binding"));
            }
            charge = add(charge, key.len() as u64 + 4096)?;
            bindings += 1;
        }
        let mut previous = self.state.identity_anchor;
        let mut sequence = self.state.identity_pruned_through;
        let mut identities = 0_u64;
        let mut payloads = 0_u64;
        let mut previous_time = None;
        let mut stmt=self.connection.prepare("SELECT sequence,record_id,metadata,prefix,raw,binding,profile_id,profile_revision FROM entries ORDER BY sequence")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            ctx.check()?;
            sequence = sequence.checked_add(1).ok_or(CoverageError::Exhausted)?;
            let stored_sequence = bounded_blob(row, 0, 8)?;
            let record_id = bounded_blob(row, 1, 16)?;
            let data = bounded_blob(row, 2, format::MAX_METADATA_BYTES)?;
            let m = CommitMetadata::decode(&data)?;
            let h = bounded_blob(row, 3, 32)?;
            let p = load_profile(
                &self.connection,
                &bounded_text(row, 6)?,
                &bounded_text(row, 7)?,
            )?;
            if stored_sequence != sequence.to_be_bytes()
                || m.sequence != sequence
                || m.history_id != self.state.history_id
                || record_id != m.record_id.as_bytes()
                || bounded_blob(row, 5, format::MAX_BINDING_BYTES)? != m.binding.encoded()
                || !m.binding.profile_matches(&p)
                || m.profile_fingerprint != p.fingerprint()
                || m.accepted_at > self.state.clock_floor
                || previous_time.is_some_and(|t| t > m.accepted_at)
            {
                return Err(CoverageError::Corrupt("entry identity/references/order"));
            }
            previous_time = Some(m.accepted_at);
            previous = format::prefix(previous, &data);
            if h != previous
                || (sequence == self.state.payload_pruned_through
                    && previous != self.state.payload_anchor)
            {
                return Err(CoverageError::Corrupt("entry prefix"));
            }
            if sequence > self.state.payload_pruned_through {
                let raw = bounded_blob(row, 4, format::MAX_RAW_BYTES)?;
                if raw.len() != m.raw_length as usize || format::sha256(&raw) != m.content_sha256 {
                    return Err(CoverageError::Corrupt("original bytes"));
                }
                validate_raw(&raw, &p, &m.binding, m.accepted_at)?;
                if HistoryBinding::from_record(&raw)?.1.id != m.record_id {
                    return Err(CoverageError::Corrupt("original record ID"));
                }
                charge = add(charge, raw.len() as u64 + 256)?;
                payloads += 1;
            } else if !matches!(row.get_ref(4)?, rusqlite::types::ValueRef::Null) {
                return Err(CoverageError::Corrupt("pruned payload"));
            }
            Receipt::from_metadata(&m, previous)?;
            charge = add(charge, data.len() as u64 + 8192)?;
            identities += 1;
        }
        if sequence != self.state.committed_sequence
            || previous != self.state.committed_prefix
            || identities != self.state.identity_count
            || payloads != self.state.payload_count
            || bindings != self.state.binding_count
            || profiles != self.state.profile_count
            || charge != self.state.ledger_charge
        {
            return Err(CoverageError::Corrupt("recovered state accounting/prefix"));
        }
        check_root(&self.config)?;
        Ok(())
    }
    pub fn append(
        &mut self,
        p: PreparedObservation,
        ctx: &WorkContext,
    ) -> Result<Receipt, CoverageError> {
        self.append_with_correction(p, None, ctx)
    }
    // Only trusted intake supplies a link, after one-hop validation on this worker.
    fn append_with_correction(
        &mut self,
        p: PreparedObservation,
        correction_of: Option<Uuid>,
        ctx: &WorkContext,
    ) -> Result<Receipt, CoverageError> {
        ctx.check()?;
        if p.admission.accepted_at < self.state.clock_floor {
            return Err(CoverageError::ClockRegression);
        }
        if self
            .connection
            .query_row(
                "SELECT 1 FROM entries WHERE record_id=?1",
                params![p.record_id.as_bytes()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Err(CoverageError::IdentityExists);
        }
        let retained: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT definition FROM profiles WHERE id=?1 AND revision=?2",
                params![p.profile.id(), p.profile.revision()],
                |r| bounded_blob(r, 0, format::MAX_PROFILE_BYTES),
            )
            .optional()?;
        if retained
            .as_deref()
            .is_some_and(|bytes| bytes != p.profile.encoded())
        {
            return Err(CoverageError::ProfileRevisionConflict);
        }
        let new_profile = retained.is_none();
        let new_binding = self
            .connection
            .query_row(
                "SELECT 1 FROM bindings WHERE key=?1",
                params![p.binding.encoded()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_none();
        let sequence = self
            .state
            .committed_sequence
            .checked_add(1)
            .ok_or(CoverageError::Exhausted)?;
        let m = CommitMetadata {
            history_id: self.state.history_id,
            sequence,
            record_id: p.record_id,
            raw_length: p.raw.len() as u32,
            content_sha256: format::sha256(&p.raw),
            binding: p.binding,
            profile_fingerprint: p.profile.fingerprint(),
            authority_revision: p.admission.authority_revision,
            accepted_at: p.admission.accepted_at,
            replay_until: p.admission.replay_until,
            identity_until: p.admission.identity_until,
            correction_of,
        };
        let data = m.encode()?;
        let h = format::prefix(self.state.committed_prefix, &data);
        let receipt = Receipt::from_metadata(&m, h)?;
        let mut state = self.state.clone();
        state.committed_sequence = sequence;
        state.committed_prefix = h;
        state.clock_floor = m.accepted_at;
        state.payload_count = add(state.payload_count, 1)?;
        state.identity_count = add(state.identity_count, 1)?;
        state.binding_count = add(state.binding_count, u64::from(new_binding))?;
        state.profile_count = add(state.profile_count, u64::from(new_profile))?;
        let added = data.len() as u64
            + 8192
            + p.raw.len() as u64
            + 256
            + if new_binding {
                m.binding.encoded().len() as u64 + 4096
            } else {
                0
            }
            + if new_profile {
                p.profile.encoded().len() as u64 + 4096
            } else {
                0
            };
        state.ledger_charge = add(state.ledger_charge, added)?;
        if state.payload_count > self.config.max_payloads
            || state.identity_count > self.config.max_identities
            || state.binding_count > self.config.max_bindings
            || state.profile_count > self.config.max_bindings
            || state.ledger_charge > self.config.max_ledger_bytes
        {
            return Err(CoverageError::Quota);
        }
        let state_data = state.encode()?;
        ctx.start()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if new_profile {
            tx.execute(
                "INSERT INTO profiles VALUES(?1,?2,?3,?4)",
                params![
                    p.profile.id(),
                    p.profile.revision(),
                    p.profile.encoded(),
                    &p.profile.fingerprint()[..]
                ],
            )?;
        }
        if new_binding {
            tx.execute(
                "INSERT INTO bindings VALUES(?1,?2,?3)",
                params![m.binding.encoded(), p.profile.id(), p.profile.revision()],
            )?;
        }
        tx.execute(
            "INSERT INTO entries VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                &sequence.to_be_bytes()[..],
                m.record_id.as_bytes(),
                &data,
                &h[..],
                &p.raw,
                m.binding.encoded(),
                p.profile.id(),
                p.profile.revision()
            ],
        )?;
        #[cfg(test)]
        test_checkpoint("after_entry", sequence)?;
        let updated = tx.execute(
            "UPDATE state SET data=?1,checksum=?2 WHERE id=1",
            params![&state_data, &format::sha256(&state_data)[..]],
        )?;
        if updated != 1 {
            return Err(CoverageError::Corrupt("state update cardinality"));
        }
        #[cfg(test)]
        test_checkpoint("before_commit", sequence)?;
        tx.commit()?;
        #[cfg(test)]
        test_checkpoint("after_commit", sequence)?;
        self.state = state;
        self.database_bytes = fs::metadata(self.config.directory.join("coverage.sqlite3"))?.len();
        ctx.check()?;
        Ok(receipt)
    }
    pub fn submit(
        &mut self,
        submission: CoverageSubmission,
        intake: IntakeContext,
        reference: Option<Receipt>,
        ctx: &WorkContext,
    ) -> Result<IntakeOutcome, CoverageError> {
        // The single worker serializes authorization, identity lookup and admission.
        // Check the stored binding before disclosing any original receipt or payload.
        let retained = self.get_authorized(submission.record_id, &intake.authority, ctx)?;
        if let Some(reference) = &reference {
            let sequence = reference.validate_reference()?;
            if retained.is_none() {
                // Deleted originals cannot establish their historical binding or receipt
                // authenticity. Authorize the supplied report's full binding before giving
                // only a retention classification, never an original-receipt success.
                let (binding, times) = HistoryBinding::from_record(&submission.raw)?;
                if binding.encoded() != intake.authority.binding.encoded() {
                    return Err(CoverageError::NotAuthorized);
                }
                if times.id != submission.record_id {
                    return Err(CoverageError::Invalid("producer record identity mismatch"));
                }
                if reference.record_id != submission.record_id {
                    return Err(CoverageError::ReceiptMismatch);
                }
            }
            if reference.history_id != self.state.history_id
                || sequence > self.state.committed_sequence
            {
                return Err(CoverageError::HistoryUnavailable);
            }
            if sequence <= self.state.identity_pruned_through {
                if sequence == self.state.identity_pruned_through
                    && reference.prefix_digest != format::hex(&self.state.identity_anchor)
                {
                    return Err(CoverageError::ReceiptMismatch);
                }
                return Err(CoverageError::IdentityPruned);
            }
            if retained.is_none() {
                return Err(CoverageError::HistoryUnavailable);
            }
        }
        if intake.received_at < self.state.clock_floor {
            return Err(CoverageError::ClockRegression);
        }
        if let Some(stored) = retained {
            if reference.as_ref().is_some_and(|r| r != &stored.receipt) {
                return Err(CoverageError::ReceiptMismatch);
            }
            if intake.received_at >= Timestamp::parse(&stored.receipt.replay_until)? {
                return Err(CoverageError::ReplayWindowExpired);
            }
            let raw = stored.raw.ok_or(CoverageError::ReplayWindowExpired)?;
            if raw != submission.raw || stored.receipt.correction_of != submission.correction_of {
                return Err(CoverageError::IdContentConflict);
            }
            ctx.check()?;
            return Ok(IntakeOutcome::Replayed(stored.receipt));
        }
        let profile = intake.profile.ok_or(CoverageError::ProfileUnavailable)?;
        if profile.skew() > intake.policy.max_clock_skew_seconds {
            return Err(CoverageError::Invalid(
                "profile exceeds configured clock skew",
            ));
        }
        let (binding, times) = HistoryBinding::from_record(&submission.raw)?;
        if binding.encoded() != intake.authority.binding.encoded() {
            return Err(CoverageError::NotAuthorized);
        }
        if times.id != submission.record_id {
            return Err(CoverageError::Invalid("producer record identity mismatch"));
        }
        let admission = intake
            .policy
            .admission(intake.received_at, intake.authority.revision)?;
        let prepared = PreparedObservation::prepare(
            &submission.raw,
            profile,
            intake.authority.binding,
            admission,
        )?;
        if intake.received_at.datetime()? - times.observed.datetime()?
            > chrono::TimeDelta::seconds(i64::from(intake.policy.max_report_age_seconds))
        {
            return Err(CoverageError::ReportTooOld);
        }
        if let Some(target_id) = submission.correction_of {
            self.validate_correction(&prepared, target_id, ctx)?;
        }
        ctx.check()?;
        self.append_with_correction(prepared, submission.correction_of, ctx)
            .map(IntakeOutcome::Accepted)
    }
    fn validate_correction(
        &self,
        correction: &PreparedObservation,
        target_id: Uuid,
        ctx: &WorkContext,
    ) -> Result<(), CoverageError> {
        if target_id == correction.record_id {
            return Err(CoverageError::InvalidCorrection("self reference"));
        }
        let target = self
            .load_for_binding(target_id, &correction.binding, ctx)
            .map_err(|error| match error {
                CoverageError::NotAuthorized => CoverageError::CorrectionBindingMismatch,
                other => other,
            })?
            .ok_or(CoverageError::CorrectionTargetUnavailable)?;
        let raw = target
            .raw
            .ok_or(CoverageError::CorrectionTargetUnavailable)?;
        let sequence = target
            .receipt
            .sequence
            .parse::<u64>()
            .map_err(|_| CoverageError::Corrupt("target sequence"))?;
        // The next commit is strictly after every currently committed target.
        if sequence == 0 || sequence > self.state.committed_sequence {
            return Err(CoverageError::InvalidCorrection("target commit order"));
        }
        let (_, old) = HistoryBinding::from_record(&raw)?;
        let (_, new) = HistoryBinding::from_record(&correction.raw)?;
        if new.start >= old.end || old.start >= new.end {
            return Err(CoverageError::InvalidCorrection("nonoverlapping interval"));
        }
        if new.verified <= old.verified {
            return Err(CoverageError::InvalidCorrection(
                "verification is not later",
            ));
        }
        ctx.check()
    }
    pub fn get_authorized(
        &self,
        id: Uuid,
        authority: &AuthorizedBinding,
        ctx: &WorkContext,
    ) -> Result<Option<StoredObservation>, CoverageError> {
        self.load_for_binding(id, &authority.binding, ctx)
    }
    fn load_for_binding(
        &self,
        id: Uuid,
        binding: &HistoryBinding,
        ctx: &WorkContext,
    ) -> Result<Option<StoredObservation>, CoverageError> {
        ctx.check()?;
        format::non_nil(id)?;
        let stored_binding = self
            .connection
            .query_row(
                "SELECT binding FROM entries WHERE record_id=?1",
                params![id.as_bytes()],
                |r| bounded_blob(r, 0, format::MAX_BINDING_BYTES),
            )
            .optional()?;
        match stored_binding {
            None => Ok(None),
            Some(stored) if stored != binding.encoded() => Err(CoverageError::NotAuthorized),
            Some(_) => self.load(id, ctx),
        }
    }
    pub fn load(
        &self,
        id: Uuid,
        ctx: &WorkContext,
    ) -> Result<Option<StoredObservation>, CoverageError> {
        ctx.check()?;
        format::non_nil(id)?;
        let data: Option<LoadedRow> = self.connection.query_row(
            "SELECT sequence,metadata,prefix,raw,binding,profile_id,profile_revision FROM entries WHERE record_id=?1",
            params![id.as_bytes()], |r| {
                let raw = if matches!(r.get_ref(3)?, rusqlite::types::ValueRef::Null) {
                    None
                } else {
                    Some(bounded_blob(r, 3, format::MAX_RAW_BYTES)?)
                };
                Ok(LoadedRow {
                    sequence: bounded_blob(r, 0, 8)?,
                    metadata: bounded_blob(r, 1, format::MAX_METADATA_BYTES)?,
                    prefix: bounded_blob(r, 2, 32)?,
                    raw,
                    binding: bounded_blob(r, 4, format::MAX_BINDING_BYTES)?,
                    profile_id: bounded_text(r, 5)?,
                    profile_revision: bounded_text(r, 6)?,
                })
            }).optional()?;
        let Some(row) = data else {
            return Ok(None);
        };
        let m = CommitMetadata::decode(&row.metadata)
            .map_err(|_| CoverageError::Corrupt("loaded metadata"))?;
        let h: [u8; 32] = row
            .prefix
            .try_into()
            .map_err(|_| CoverageError::Corrupt("prefix width"))?;
        let profile = load_profile(&self.connection, &row.profile_id, &row.profile_revision)?;
        if m.record_id != id
            || m.history_id != self.state.history_id
            || row.sequence != m.sequence.to_be_bytes()
            || m.sequence <= self.state.identity_pruned_through
            || m.sequence > self.state.committed_sequence
            || m.accepted_at > self.state.clock_floor
            || row.binding != m.binding.encoded()
            || !m.binding.profile_matches(&profile)
            || m.profile_fingerprint != profile.fingerprint()
            || row.raw.is_some() != (m.sequence > self.state.payload_pruned_through)
        {
            return Err(CoverageError::Corrupt("loaded references"));
        }
        let previous: [u8; 32] = if m.sequence - 1 == self.state.identity_pruned_through {
            self.state.identity_anchor
        } else {
            self.connection
                .query_row(
                    "SELECT prefix FROM entries WHERE sequence=?1",
                    params![(m.sequence - 1).to_be_bytes()],
                    |r| bounded_blob(r, 0, 32),
                )?
                .try_into()
                .map_err(|_| CoverageError::Corrupt("previous prefix width"))?
        };
        if format::prefix(previous, &row.metadata) != h
            || (m.sequence == self.state.committed_sequence && h != self.state.committed_prefix)
        {
            return Err(CoverageError::Corrupt("loaded prefix"));
        }
        if let Some(raw) = &row.raw {
            if raw.len() != m.raw_length as usize || format::sha256(raw) != m.content_sha256 {
                return Err(CoverageError::Corrupt("loaded original bytes"));
            }
            validate_raw(raw, &profile, &m.binding, m.accepted_at)
                .map_err(|_| CoverageError::Corrupt("loaded report semantics"))?;
            if HistoryBinding::from_record(raw)?.1.id != m.record_id {
                return Err(CoverageError::Corrupt("loaded report identity"));
            }
        }
        ctx.check()?;
        Ok(Some(StoredObservation {
            receipt: Receipt::from_metadata(&m, h)?,
            raw: row.raw,
            profile,
            binding: m.binding,
        }))
    }
    pub fn close(self) -> Result<(), CoverageError> {
        self.connection
            .close()
            .map_err(|(_, e)| CoverageError::Sqlite(e))?;
        self.root.sync_all()?;
        Ok(())
    }
}
fn add(a: u64, b: u64) -> Result<u64, CoverageError> {
    a.checked_add(b)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(CoverageError::Exhausted)
}
fn receipt_prefix(receipt: &Receipt) -> Result<[u8; 32], CoverageError> {
    let bytes = receipt.prefix_digest.as_bytes();
    if bytes.len() != 64 {
        return Err(CoverageError::Corrupt("scan receipt prefix"));
    }
    let mut prefix = [0; 32];
    for (output, pair) in prefix.iter_mut().zip(bytes.chunks_exact(2)) {
        fn nibble(b: u8) -> Result<u8, CoverageError> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(CoverageError::Corrupt("scan receipt prefix")),
            }
        }
        *output = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(prefix)
}
fn identity_row(c: &Connection, sequence: u64) -> Result<IdentityRow, CoverageError> {
    c.query_row(
        "SELECT record_id,metadata,prefix,raw IS NULL,binding,profile_id,profile_revision FROM entries WHERE sequence=?1",
        params![&sequence.to_be_bytes()[..]],
        |r| Ok(IdentityRow {
            record_id: bounded_blob(r, 0, 16)?,
            metadata: bounded_blob(r, 1, format::MAX_METADATA_BYTES)?,
            prefix: bounded_blob(r, 2, 32)?,
            raw_unavailable: r.get(3)?,
            binding: bounded_blob(r, 4, format::MAX_BINDING_BYTES)?,
            profile_id: bounded_text(r, 5)?,
            profile_revision: bounded_text(r, 6)?,
        }),
    )
    .optional()?
    .ok_or(CoverageError::Corrupt("identity pruning missing prefix"))
}
fn validate_identity_row(
    c: &Connection,
    row: &IdentityRow,
    sequence: u64,
    previous: [u8; 32],
    state: &State,
) -> Result<CommitMetadata, CoverageError> {
    let metadata = CommitMetadata::decode(&row.metadata)
        .map_err(|_| CoverageError::Corrupt("identity pruning metadata"))?;
    let prefix = format::prefix(previous, &row.metadata);
    let profile = load_profile(c, &row.profile_id, &row.profile_revision)?;
    let binding_profile = c.query_row(
        "SELECT profile_id,profile_revision FROM bindings WHERE key=?1",
        params![&row.binding],
        |r| Ok((bounded_text(r, 0)?, bounded_text(r, 1)?)),
    )?;
    if metadata.sequence != sequence
        || metadata.history_id != state.history_id
        || metadata.record_id.as_bytes() != row.record_id.as_slice()
        || metadata.accepted_at > state.clock_floor
        || row.binding != metadata.binding.encoded()
        || binding_profile.0 != row.profile_id
        || binding_profile.1 != row.profile_revision
        || !metadata.binding.profile_matches(&profile)
        || metadata.profile_fingerprint != profile.fingerprint()
        || row.prefix != prefix
        || !row.raw_unavailable
        || sequence > state.payload_pruned_through
        || (sequence == state.payload_pruned_through && prefix != state.payload_anchor)
        || (sequence == state.committed_sequence && prefix != state.committed_prefix)
    {
        return Err(CoverageError::Corrupt("identity pruning references/prefix"));
    }
    Receipt::from_metadata(&metadata, prefix)
        .map_err(|_| CoverageError::Corrupt("identity pruning receipt"))?;
    Ok(metadata)
}
fn load_state(c: &Connection) -> Result<State, CoverageError> {
    let n: i64 = c.query_row("SELECT count(*) FROM state", [], |r| r.get(0))?;
    if n != 1 {
        return Err(CoverageError::Corrupt("state cardinality"));
    }
    let (data, checksum) = c.query_row("SELECT data,checksum FROM state WHERE id=1", [], |r| {
        Ok((bounded_blob(r, 0, 512)?, bounded_blob(r, 1, 32)?))
    })?;
    if format::sha256(&data) != checksum.as_slice() {
        return Err(CoverageError::Corrupt("state checksum"));
    }
    State::decode(&data)
}
fn load_profile(c: &Connection, id: &str, rev: &str) -> Result<ProfileDefinition, CoverageError> {
    let (data, fingerprint) = c.query_row(
        "SELECT definition,fingerprint FROM profiles WHERE id=?1 AND revision=?2",
        params![id, rev],
        |r| {
            Ok((
                bounded_blob(r, 0, format::MAX_PROFILE_BYTES)?,
                bounded_blob(r, 1, 32)?,
            ))
        },
    )?;
    let p =
        ProfileDefinition::decode(&data).map_err(|_| CoverageError::Corrupt("profile encoding"))?;
    if p.id() != id || p.revision() != rev || p.fingerprint() != fingerprint.as_slice() {
        return Err(CoverageError::Corrupt("profile reference"));
    }
    Ok(p)
}
fn set_progress(
    c: &Connection,
    ctx: &WorkContext,
    config: &CoverageConfig,
) -> Result<(), CoverageError> {
    let ctx = ctx.clone();
    let mut remaining = config.max_vm_steps;
    c.progress_handler(
        1000,
        Some(move || {
            remaining = remaining.saturating_sub(1000);
            remaining == 0 || ctx.check().is_err()
        }),
    )?;
    Ok(())
}
fn configure(c: &Connection, config: &CoverageConfig) -> Result<(), CoverageError> {
    c.busy_timeout(Duration::ZERO)?;
    c.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA foreign_keys=ON; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA auto_vacuum=NONE; PRAGMA cache_size=-1024; PRAGMA cache_spill=OFF; PRAGMA trusted_schema=OFF;")?;
    let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if mode != "delete" {
        return Err(CoverageError::Config("SQLite journal mode"));
    }
    for (sql, expected) in [
        ("PRAGMA page_size", 4096),
        ("PRAGMA synchronous", 3),
        ("PRAGMA foreign_keys", 1),
        ("PRAGMA mmap_size", 0),
        ("PRAGMA temp_store", 2),
        ("PRAGMA auto_vacuum", 0),
        ("PRAGMA cache_size", -1024),
        ("PRAGMA cache_spill", 0),
        ("PRAGMA trusted_schema", 0),
        ("PRAGMA busy_timeout", 0),
    ] {
        let actual: i64 = c.query_row(sql, [], |r| r.get(0))?;
        if actual != expected {
            return Err(CoverageError::Config("SQLite settings"));
        }
    }
    c.pragma_update(None, "max_page_count", config.max_database_pages)?;
    let pages: i64 = c.query_row("PRAGMA max_page_count", [], |r| r.get(0))?;
    if pages != i64::from(config.max_database_pages) {
        return Err(CoverageError::Config("SQLite page cap"));
    }
    for (limit, n) in [
        (Limit::SQLITE_LIMIT_LENGTH, format::MAX_ENTRY_BYTES as i32),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 16_384),
        (Limit::SQLITE_LIMIT_COLUMN, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 32),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        c.set_limit(limit, n)?;
        if c.limit(limit)? != n {
            return Err(CoverageError::Config("SQLite VM limits"));
        }
    }
    Ok(())
}

#[cfg(test)]
fn test_checkpoint(stage: &str, sequence: u64) -> Result<(), CoverageError> {
    if sequence == 2
        && std::env::var("SIGNAL_COVERAGE_TEST_CHECKPOINT")
            .ok()
            .as_deref()
            == Some(stage)
    {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(b"COVERAGE-CHECKPOINT\n")?;
        stdout.flush()?;
        drop(stdout);
        std::io::stdin().read_exact(&mut [0; 1])?;
    }
    Ok(())
}

//! Bounded opaque detector state/outbox/checkpoint transaction. The host validates
//! domain state, original evidence and authorization before proposing a commit.
mod worker;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use thiserror::Error;
use uuid::Uuid;
pub use worker::{Journal, Ready};

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid detector journal configuration or record")]
    Configuration,
    #[error("detector journal capacity exhausted")]
    Capacity,
    #[error("detector journal binding or revision conflicts")]
    Conflict,
    #[error("detector journal I/O failed; reload durable state")]
    Journal,
    #[error("detector journal worker busy")]
    Busy,
    #[error("detector journal caller cancelled; reload durable state")]
    Cancelled,
    #[error("detector journal original deadline expired; reload durable state")]
    Timeout,
    #[error("detector journal worker closed")]
    Closed,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u16,
    pub source_stream: Uuid,
    /// Complete host-owned scope/generation binding, not a caller-supplied grant.
    pub source_binding: [u8; 32],
    /// Includes all observer keys as well as the exact detector policy.
    pub enrollment_binding: [u8; 32],
    pub max_record_bytes: usize,
    pub max_state_bytes: usize,
    pub max_outputs: usize,
    pub max_output_bytes: usize,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.source_stream.is_nil()
            || self.source_binding == [0; 32]
            || self.enrollment_binding == [0; 32]
            || !(1024..=32 * 1024 * 1024).contains(&self.max_record_bytes)
            || !(1..=16 * 1024 * 1024).contains(&self.max_state_bytes)
            || self.max_state_bytes > self.max_record_bytes
            || !(1..=4096).contains(&self.max_outputs)
            || !(1..=65536).contains(&self.max_output_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub schema_version: u16,
    pub id: Uuid,
    /// Original delivery bytes; decoding/rebuilding them is not reconciliation.
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u16,
    pub revision: u64,
    pub checkpoint: u64,
    /// Versioned host snapshot including monitor and original evidence custody.
    pub state: Vec<u8>,
    pub outbox: Vec<Output>,
}
struct Limit(usize);
impl Write for Limit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("detector journal capacity"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Record {
    fn encode(&self, config: &Config) -> Result<Vec<u8>, Error> {
        if self.schema_version != 1
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.checkpoint > i64::MAX as u64
            || self.state.is_empty()
        {
            return Err(Error::Configuration);
        }
        if self.state.len() > config.max_state_bytes || self.outbox.len() > config.max_outputs {
            return Err(Error::Capacity);
        }
        let mut ids = BTreeSet::new();
        for o in &self.outbox {
            if o.schema_version != 1 || o.id.is_nil() || o.bytes.is_empty() || !ids.insert(o.id) {
                return Err(Error::Configuration);
            }
            if o.bytes.len() > config.max_output_bytes {
                return Err(Error::Capacity);
            }
        }
        serde_json::to_writer(Limit(config.max_record_bytes), self).map_err(|_| Error::Capacity)?;
        serde_json::to_vec(self).map_err(|_| Error::Configuration)
    }
}
const META: &str = "CREATE TABLE state_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),config BLOB NOT NULL)";
const DATA: &str = "CREATE TABLE state_snapshot(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,checkpoint INTEGER NOT NULL,payload BLOB NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32))";
const APP_ID: i64 = 0x53474A31;

struct Engine {
    connection: Connection,
    config: Config,
    // Declared last so SQLite closes before the filesystem writer lease drops.
    _lock: crate::journal_lease::WriterLease,
}
fn secure_file(path: &Path, maximum: u64) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Journal)?;
    let m = file.metadata().map_err(|_| Error::Journal)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.permissions().mode() & 0o777 != 0o600
        || m.len() > maximum
    {
        return Err(Error::Configuration);
    }
    Ok(file)
}
fn schema(connection: &Connection) -> Result<Vec<(String, String)>, Error> {
    let mut q = connection.prepare("SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name LIMIT 3").map_err(|_| Error::Journal)?;
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|_| Error::Journal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Journal)
}
impl Engine {
    fn open(path: &Path, config: Config) -> Result<Self, Error> {
        config.validate()?;
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(Error::Configuration);
        }
        for ancestor in path.ancestors() {
            if let Ok(m) = fs::symlink_metadata(ancestor)
                && m.file_type().is_symlink()
            {
                return Err(Error::Configuration);
            }
        }
        let parent = path.parent().ok_or(Error::Configuration)?;
        let directory = fs::metadata(parent).map_err(|_| Error::Journal)?;
        if !directory.is_dir() || directory.permissions().mode() & 0o777 != 0o700 {
            return Err(Error::Configuration);
        }
        let lock_path = path.with_added_extension("lock");
        let lock = secure_file(&lock_path, 0)?;
        let lock =
            crate::journal_lease::WriterLease::acquire(lock).map_err(|error| match error {
                std::fs::TryLockError::WouldBlock => Error::Busy,
                std::fs::TryLockError::Error(_) => Error::Journal,
            })?;
        let file = secure_file(path, 64 * 1024 * 1024)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut side = path.as_os_str().to_os_string();
            side.push(suffix);
            let side = Path::new(&side);
            if fs::symlink_metadata(side).is_ok() {
                secure_file(side, 64 * 1024 * 1024)?;
            }
        }
        file.sync_all()
            .and_then(|_| File::open(parent)?.sync_all())
            .map_err(|_| Error::Journal)?;
        let mut connection = Connection::open_with_flags(
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
            .is_some_and(|name| name == "physical.sqlite")
        {
            connection
                .busy_handler(Some(tests::busy_probe))
                .map_err(|_| Error::Journal)?;
        }
        let objects = schema(&connection)?;
        let app: i64 = connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(|_| Error::Journal)?;
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|_| Error::Journal)?;
        let fresh = objects.is_empty() && app == 0 && version == 0;
        if !fresh
            && (objects
                != vec![
                    ("state_metadata".into(), META.into()),
                    ("state_snapshot".into(), DATA.into()),
                ]
                || app != APP_ID
                || version != 1)
        {
            return Err(Error::Configuration);
        }
        if !fresh {
            check_binding(&connection, &config)?;
        }
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=16384;",
            )
            .map_err(|_| Error::Journal)?;
        let page: i64 = connection
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|_| Error::Journal)?;
        if page != 4096 {
            return Err(Error::Configuration);
        }
        if fresh {
            let tx = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| Error::Journal)?;
            tx.execute_batch(META)
                .and_then(|_| tx.execute_batch(DATA))
                .map_err(|_| Error::Journal)?;
            let bytes = serde_json::to_vec(&config).map_err(|_| Error::Configuration)?;
            tx.execute("INSERT INTO state_metadata VALUES(1,?1)", [bytes])
                .map_err(|_| Error::Journal)?;
            tx.pragma_update(None, "application_id", APP_ID)
                .and_then(|_| tx.pragma_update(None, "user_version", 1))
                .map_err(|_| Error::Journal)?;
            tx.commit().map_err(|_| Error::Journal)?;
        }
        let engine = Self {
            connection,
            config,
            _lock: lock,
        };
        engine.load()?;
        Ok(engine)
    }
    fn load(&self) -> Result<Option<Record>, Error> {
        read(&self.connection, &self.config)
    }
    fn commit(&mut self, expected: u64, next: Record) -> Result<Record, Error> {
        let bytes = next.encode(&self.config)?;
        if expected.checked_add(1) != Some(next.revision) {
            return Err(Error::Conflict);
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Journal)?;
        let current = read(&tx, &self.config)?;
        if current.as_ref() == Some(&next) {
            return Ok(next);
        }
        if current.as_ref().map_or(0, |r| r.revision) != expected
            || current.as_ref().is_some_and(|r| {
                next.checkpoint < r.checkpoint || !next.outbox.starts_with(&r.outbox)
            })
        {
            return Err(Error::Conflict);
        }
        write(&tx, &next, &bytes)?;
        tx.commit().map_err(|_| Error::Journal)?;
        Ok(next)
    }
    fn retire(&mut self, expected: u64, published: usize) -> Result<Record, Error> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| Error::Journal)?;
        let mut next = read(&tx, &self.config)?.ok_or(Error::Conflict)?;
        if next.revision != expected || published == 0 || published > next.outbox.len() {
            return Err(Error::Conflict);
        }
        next.revision = next.revision.checked_add(1).ok_or(Error::Conflict)?;
        next.outbox.drain(..published);
        let bytes = next.encode(&self.config)?;
        write(&tx, &next, &bytes)?;
        tx.commit().map_err(|_| Error::Journal)?;
        Ok(next)
    }
}
fn check_binding(c: &Connection, config: &Config) -> Result<(), Error> {
    let bytes: Vec<u8> = c
        .query_row(
            "SELECT substr(config,1,2049) FROM state_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| Error::Journal)?;
    if bytes.len() > 2048
        || bytes != serde_json::to_vec(config).map_err(|_| Error::Configuration)?
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn read(c: &Connection, config: &Config) -> Result<Option<Record>, Error> {
    check_binding(c, config)?;
    let row: Option<(i64,i64,Vec<u8>,Vec<u8>)> = c.query_row("SELECT revision,checkpoint,substr(payload,1,?1),substr(digest,1,33) FROM state_snapshot WHERE singleton=1",[(config.max_record_bytes+1) as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|_|Error::Journal)?;
    let Some((revision, checkpoint, bytes, digest)) = row else {
        return Ok(None);
    };
    if bytes.len() > config.max_record_bytes {
        return Err(Error::Capacity);
    }
    if digest.as_slice() != Sha256::digest(&bytes).as_slice() {
        return Err(Error::Conflict);
    }
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
    record.encode(config)?;
    if revision < 0
        || checkpoint < 0
        || record.revision != revision as u64
        || record.checkpoint != checkpoint as u64
    {
        return Err(Error::Conflict);
    }
    Ok(Some(record))
}
fn write(c: &Connection, record: &Record, bytes: &[u8]) -> Result<(), Error> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    c.execute("INSERT INTO state_snapshot VALUES(1,?1,?2,?3,?4) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,checkpoint=excluded.checkpoint,payload=excluded.payload,digest=excluded.digest",params![record.revision as i64,record.checkpoint as i64,bytes,digest.as_slice()]).map_err(|_|Error::Journal)?;
    Ok(())
}

#[cfg(test)]
mod tests;

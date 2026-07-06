//! Synchronous disk engine, called only by the single dedicated WAL worker.
use crate::{BufferConfig, BufferError, BufferMetrics, Policy};
use signal_event::SignalEvent;
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const SEGMENT_HEADER: u64 = 20;
const RECORD_HEADER: u64 = 20;
// Two checkpoint slots (28 bytes each), plus final/temporary stream UUID slots.
pub(crate) const METADATA_RESERVE: u64 = 128;
const SEGMENT_MAGIC: &[u8; 8] = b"SIGWAL01";
const CHECKPOINT_MAGIC: &[u8; 8] = b"SIGACK01";

pub(crate) struct Record {
    pub seq: u64,
    pub payload: Vec<u8>,
}
struct Segment {
    first: u64,
    last: Option<u64>,
    bytes: u64,
    path: PathBuf,
}
pub(crate) struct Engine {
    pub config: BufferConfig,
    pub metrics: BufferMetrics,
    queue: VecDeque<Record>,
    segments: VecDeque<Segment>,
    active: Option<File>,
    directory: File,
    _lock: File,
    checkpoint: u64,
    last: u64,
    delivered: u64,
}

fn io(error: std::io::Error) -> BufferError {
    BufferError::Io(error)
}
fn regular(path: &Path) -> Result<(), BufferError> {
    if !fs::symlink_metadata(path).map_err(io)?.is_file() {
        return Err(BufferError::Directory);
    }
    Ok(())
}
fn create(path: &Path) -> Result<File, BufferError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io)
}
fn ensure_directory(path: &Path) -> Result<(), BufferError> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(BufferError::Directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(error)),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_directory(parent)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path).map_err(io)?.is_dir() {
                return Err(BufferError::Directory);
            }
        }
        Err(error) => return Err(io(error)),
    }
    File::open(path).map_err(io)?.sync_all().map_err(io)?;
    File::open(parent).map_err(io)?.sync_all().map_err(io)
}
fn crc(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, BufferError> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or(BufferError::Corrupt("integer"))?;
    Ok(u64::from_le_bytes(
        slice
            .try_into()
            .map_err(|_| BufferError::Corrupt("integer"))?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, BufferError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(BufferError::Corrupt("integer"))?;
    Ok(u32::from_le_bytes(
        slice
            .try_into()
            .map_err(|_| BufferError::Corrupt("integer"))?,
    ))
}

impl Engine {
    pub fn open(config: BufferConfig) -> Result<Self, BufferError> {
        ensure_directory(&config.directory)?;
        if !fs::symlink_metadata(&config.directory)
            .map_err(io)?
            .is_dir()
        {
            return Err(BufferError::Directory);
        }
        let directory = File::open(&config.directory).map_err(io)?;
        let lock_path = config.directory.join("lock");
        let lock = match create(&lock_path) {
            Ok(file) => file,
            Err(BufferError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                regular(&lock_path)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lock_path)
                    .map_err(io)?
            }
            Err(error) => return Err(error),
        };
        lock.try_lock().map_err(|_| BufferError::Locked)?;
        if lock.metadata().map_err(io)?.len() != 0 {
            return Err(BufferError::Directory);
        }
        directory.sync_all().map_err(io)?;
        let mut paths = Vec::new();
        let mut total_bytes = METADATA_RESERVE;
        for entry in fs::read_dir(&config.directory).map_err(io)? {
            let entry = entry.map_err(io)?;
            regular(&entry.path())?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(BufferError::Directory)?;
            if name == "identity.tmp" {
                if entry.metadata().map_err(io)?.len() > 36 {
                    return Err(BufferError::Corrupt("temporary stream identity length"));
                }
                continue;
            }
            if name == "identity" {
                if entry.metadata().map_err(io)?.len() != 36 {
                    return Err(BufferError::Corrupt("stream identity length"));
                }
                continue;
            }
            if matches!(name, "lock" | "checkpoint" | "checkpoint.tmp") {
                if name != "lock" && entry.metadata().map_err(io)?.len() > 28 {
                    return Err(BufferError::Corrupt("checkpoint length"));
                }
                continue;
            }
            let prefix = name.strip_suffix(".wal").ok_or(BufferError::Directory)?;
            if prefix.len() != 20 || !prefix.bytes().all(|c| c.is_ascii_digit()) {
                return Err(BufferError::Directory);
            }
            let first: u64 = prefix.parse().map_err(|_| BufferError::Directory)?;
            if first == 0 || paths.len() >= config.max_segments {
                return Err(BufferError::Config("segment count"));
            }
            let bytes = entry.metadata().map_err(io)?.len();
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or(BufferError::Config("WAL quota"))?;
            if total_bytes > config.max_wal_bytes || bytes > config.segment_bytes {
                return Err(BufferError::Config("WAL or segment quota"));
            }
            paths.push((first, entry.path()));
        }
        paths.sort_by_key(|(first, _)| *first);
        let checkpoint_path = config.directory.join("checkpoint");
        let (checkpoint, dropped) = match File::open(&checkpoint_path) {
            Ok(mut file) => {
                if file.metadata().map_err(io)?.len() != 28 {
                    return Err(BufferError::Corrupt("checkpoint length"));
                }
                let mut bytes = [0; 28];
                file.read_exact(&mut bytes).map_err(io)?;
                if &bytes[..8] != CHECKPOINT_MAGIC || crc(&bytes[..24]) != u32_at(&bytes, 24)? {
                    return Err(BufferError::Corrupt("checkpoint CRC or version"));
                }
                (u64_at(&bytes, 8)?, u64_at(&bytes, 16)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && paths.is_empty() => {
                (0, 0)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BufferError::Corrupt("missing checkpoint"));
            }
            Err(error) => return Err(io(error)),
        };
        // A crash before publication leaves only a recognized temporary identity.
        let identity_temp = config.directory.join("identity.tmp");
        match fs::remove_file(&identity_temp) {
            Ok(()) => directory.sync_all().map_err(io)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(error)),
        }
        let identity_path = config.directory.join("identity");
        let stream_id = match File::open(&identity_path) {
            Ok(mut file) => {
                let mut bytes = [0; 36];
                if file.metadata().map_err(io)?.len() != bytes.len() as u64 {
                    return Err(BufferError::Corrupt("stream identity length"));
                }
                file.read_exact(&mut bytes).map_err(io)?;
                std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .filter(|value| !value.is_nil())
                    .ok_or(BufferError::Corrupt("stream identity"))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Upgrade an existing Phase 2 WAL once. The storage binding makes a
                // later replacement/reset fail rather than reusing old sequences.
                let value = uuid::Uuid::new_v4();
                let mut file = create(&identity_temp)?;
                file.write_all(value.to_string().as_bytes()).map_err(io)?;
                file.sync_all().map_err(io)?;
                fs::rename(&identity_temp, &identity_path).map_err(io)?;
                directory.sync_all().map_err(io)?;
                value
            }
            Err(error) => return Err(io(error)),
        };
        let mut engine = Self {
            metrics: BufferMetrics {
                stream_id,
                capacity: config.max_events,
                byte_capacity: config.max_memory_bytes,
                wal_byte_capacity: config.max_wal_bytes,
                wal_bytes: METADATA_RESERVE,
                dropped,
                command_capacity: config.command_capacity,
                waiter_capacity: config.max_waiters,
                ..Default::default()
            },
            config,
            queue: VecDeque::new(),
            segments: VecDeque::new(),
            active: None,
            directory,
            _lock: lock,
            checkpoint,
            last: checkpoint,
            delivered: checkpoint,
        };
        // A temporary checkpoint never supersedes the atomically published checkpoint.
        if engine
            .config
            .directory
            .join("checkpoint.tmp")
            .try_exists()
            .map_err(io)?
        {
            fs::remove_file(engine.config.directory.join("checkpoint.tmp")).map_err(io)?;
            engine.directory.sync_all().map_err(io)?;
        }
        if !checkpoint_path.try_exists().map_err(io)? {
            engine.save_checkpoint(0, 0)?;
        }
        let mut previous = None;
        for (index, (first, path)) in paths.iter().enumerate() {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(io)?;
            let mut length = file.metadata().map_err(io)?.len();
            let final_segment = index + 1 == paths.len();
            let expected = previous.map_or(checkpoint.saturating_add(1), |seq: u64| {
                seq.saturating_add(1)
            });
            if previous.is_some() && *first != expected || previous.is_none() && *first > expected {
                return Err(BufferError::Corrupt("segment sequence"));
            }
            if length < SEGMENT_HEADER {
                if !final_segment || *first != expected {
                    return Err(BufferError::Corrupt("segment header truncation"));
                }
                drop(file);
                fs::remove_file(path).map_err(io)?;
                engine.directory.sync_all().map_err(io)?;
                engine.metrics.truncated_records += 1;
                continue;
            }
            let mut header = [0; 20];
            file.read_exact(&mut header).map_err(io)?;
            if &header[..8] != SEGMENT_MAGIC
                || u64_at(&header, 8)? != *first
                || crc(&header[..16]) != u32_at(&header, 16)?
            {
                return Err(BufferError::Corrupt("segment header"));
            }
            let mut offset = SEGMENT_HEADER;
            let mut segment_last = None;
            while offset < length {
                let remaining = length - offset;
                if remaining < RECORD_HEADER {
                    if !final_segment {
                        return Err(BufferError::Corrupt("interior record header truncation"));
                    }
                    file.set_len(offset).map_err(io)?;
                    file.sync_all().map_err(io)?;
                    length = offset;
                    engine.metrics.truncated_records += 1;
                    break;
                }
                let mut header = [0; 20];
                file.read_exact(&mut header).map_err(io)?;
                if crc(&header[..12]) != u32_at(&header, 12)? {
                    return Err(BufferError::Corrupt("record header CRC"));
                }
                let size = u32_at(&header, 0)? as usize;
                if size == 0 || size > engine.config.max_record_bytes {
                    return Err(BufferError::Config("record size"));
                }
                let seq = u64_at(&header, 4)?;
                let expected_seq = segment_last.map_or(*first, |seq: u64| seq.saturating_add(1));
                if seq != expected_seq {
                    return Err(BufferError::Corrupt("record sequence"));
                }
                if remaining < RECORD_HEADER + size as u64 {
                    if !final_segment {
                        return Err(BufferError::Corrupt("interior payload truncation"));
                    }
                    file.set_len(offset).map_err(io)?;
                    file.sync_all().map_err(io)?;
                    length = offset;
                    engine.metrics.truncated_records += 1;
                    break;
                }
                let mut payload = vec![0; size];
                file.read_exact(&mut payload).map_err(io)?;
                if crc(&payload) != u32_at(&header, 16)? {
                    return Err(BufferError::Corrupt("payload CRC"));
                }
                let event: SignalEvent = serde_json::from_slice(&payload)
                    .map_err(|_| BufferError::Corrupt("event JSON"))?;
                event
                    .validate()
                    .map_err(|_| BufferError::Corrupt("event contract"))?;
                if seq > checkpoint {
                    if seq != engine.last.checked_add(1).ok_or(BufferError::Sequence)? {
                        return Err(BufferError::Corrupt("replay sequence"));
                    }
                    if engine.queue.len() >= engine.config.max_events
                        || engine.metrics.bytes.saturating_add(size)
                            > engine.config.max_memory_bytes
                    {
                        return Err(BufferError::Config("replay memory capacity"));
                    }
                    engine.metrics.bytes += size;
                    engine.queue.push_back(Record { seq, payload });
                    engine.metrics.replayed += 1;
                    engine.last = seq;
                }
                segment_last = Some(seq);
                offset += RECORD_HEADER + size as u64;
            }
            if segment_last.is_none() && !final_segment {
                return Err(BufferError::Corrupt("empty interior segment"));
            }
            if segment_last.is_none()
                && *first != engine.last.checked_add(1).ok_or(BufferError::Sequence)?
            {
                return Err(BufferError::Corrupt("empty final segment sequence"));
            }
            previous = segment_last.or(previous);
            engine.metrics.wal_bytes = engine
                .metrics
                .wal_bytes
                .checked_add(length)
                .ok_or(BufferError::Config("WAL bytes"))?;
            if engine.metrics.wal_bytes > engine.config.max_wal_bytes {
                return Err(BufferError::Config("WAL quota"));
            }
            engine.segments.push_back(Segment {
                first: *first,
                last: segment_last,
                bytes: length,
                path: path.clone(),
            });
            if final_segment {
                file.seek(SeekFrom::End(0)).map_err(io)?;
                engine.active = Some(file);
            }
        }
        engine.reclaim()?;
        engine.refresh();
        Ok(engine)
    }

    fn refresh(&mut self) {
        self.metrics.depth = self.queue.len();
        self.metrics.wal_segments = self.segments.len();
        self.metrics.checkpoint = self.checkpoint;
        self.metrics.last_sequence = self.last;
    }
    fn save_checkpoint(&self, seq: u64, dropped: u64) -> Result<(), BufferError> {
        let path = self.config.directory.join("checkpoint.tmp");
        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&seq.to_le_bytes());
        bytes.extend_from_slice(&dropped.to_le_bytes());
        bytes.extend_from_slice(&crc(&bytes).to_le_bytes());
        let mut file = create(&path)?;
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fs::rename(path, self.config.directory.join("checkpoint")).map_err(io)?;
        self.directory.sync_all().map_err(io)
    }
    fn reclaim(&mut self) -> Result<(), BufferError> {
        while self
            .segments
            .front()
            .is_some_and(|segment| segment.last.is_some_and(|last| last <= self.checkpoint))
        {
            if self.segments.len() == 1 {
                self.active = None;
            }
            let segment = self
                .segments
                .pop_front()
                .ok_or(BufferError::Corrupt("segment state"))?;
            fs::remove_file(segment.path).map_err(io)?;
            self.directory.sync_all().map_err(io)?;
            self.metrics.wal_bytes -= segment.bytes;
        }
        self.refresh();
        Ok(())
    }
    fn advance(&mut self, seq: u64, dropped: u64) -> Result<(), BufferError> {
        self.save_checkpoint(seq, dropped)?;
        self.checkpoint = seq;
        self.metrics.dropped = dropped;
        while self.queue.front().is_some_and(|record| record.seq <= seq) {
            if let Some(record) = self.queue.pop_front() {
                self.metrics.bytes -= record.payload.len();
            }
        }
        self.reclaim()
    }
    fn fits(&self, size: usize) -> bool {
        let record_bytes = RECORD_HEADER + size as u64;
        let rotate = self
            .segments
            .back()
            .is_none_or(|segment| segment.bytes + record_bytes > self.config.segment_bytes);
        self.queue.len() < self.config.max_events
            && self.metrics.bytes.saturating_add(size) <= self.config.max_memory_bytes
            && self
                .metrics
                .wal_bytes
                .saturating_add(record_bytes + if rotate { SEGMENT_HEADER } else { 0 })
                <= self.config.max_wal_bytes
            && (!rotate || self.segments.len() < self.config.max_segments)
    }
    pub fn append(&mut self, payload: Vec<u8>) -> Result<(), BufferError> {
        let size = payload.len();
        if size == 0
            || size > self.config.max_record_bytes
            || size > self.config.max_memory_bytes
            || RECORD_HEADER + size as u64 + SEGMENT_HEADER > self.config.segment_bytes
            || RECORD_HEADER + size as u64 + SEGMENT_HEADER + METADATA_RESERVE
                > self.config.max_wal_bytes
        {
            return Err(BufferError::Full);
        }
        // Check overflow before an intentional drop changes the checkpoint.
        let seq = self.last.checked_add(1).ok_or(BufferError::Sequence)?;
        while !self.fits(size) {
            if self.config.policy != Policy::DropOldest {
                return Err(BufferError::Full);
            }
            let oldest = self.queue.front().ok_or(BufferError::Full)?.seq;
            let dropped = self
                .metrics
                .dropped
                .checked_add(1)
                .ok_or(BufferError::Sequence)?;
            self.advance(oldest, dropped)?;
        }
        let record_bytes = RECORD_HEADER + size as u64;
        if self
            .segments
            .back()
            .is_none_or(|segment| segment.bytes + record_bytes > self.config.segment_bytes)
        {
            let path = self.config.directory.join(format!("{seq:020}.wal"));
            let mut file = create(&path)?;
            let mut header = Vec::with_capacity(20);
            header.extend_from_slice(SEGMENT_MAGIC);
            header.extend_from_slice(&seq.to_le_bytes());
            header.extend_from_slice(&crc(&header).to_le_bytes());
            file.write_all(&header).map_err(io)?;
            file.sync_all().map_err(io)?;
            self.directory.sync_all().map_err(io)?;
            self.active = Some(file);
            self.segments.push_back(Segment {
                first: seq,
                last: None,
                bytes: SEGMENT_HEADER,
                path,
            });
            self.metrics.wal_bytes += SEGMENT_HEADER;
        }
        let mut header = Vec::with_capacity(20);
        header.extend_from_slice(&(size as u32).to_le_bytes());
        header.extend_from_slice(&seq.to_le_bytes());
        header.extend_from_slice(&crc(&header).to_le_bytes());
        header.extend_from_slice(&crc(&payload).to_le_bytes());
        let file = self
            .active
            .as_mut()
            .ok_or(BufferError::Corrupt("active segment"))?;
        file.write_all(&header).map_err(io)?;
        file.write_all(&payload).map_err(io)?;
        file.sync_all().map_err(io)?;
        let segment = self
            .segments
            .back_mut()
            .ok_or(BufferError::Corrupt("active segment metadata"))?;
        // Segment starting sequence is tracked independently for format validation.
        if seq < segment.first {
            return Err(BufferError::Corrupt("append sequence"));
        }
        segment.last = Some(seq);
        segment.bytes += record_bytes;
        self.last = seq;
        self.metrics.wal_bytes += record_bytes;
        self.metrics.bytes += size;
        self.queue.push_back(Record { seq, payload });
        self.metrics.accepted += 1;
        self.refresh();
        Ok(())
    }
    pub fn read(
        &mut self,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<Vec<crate::SequencedEvent>, BufferError> {
        if max_events == 0
            || max_bytes == 0
            || max_events > self.config.max_events
            || max_bytes > self.config.max_memory_bytes
        {
            return Err(BufferError::Config("read batch bounds"));
        }
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for record in self.queue.iter().take(max_events) {
            if record.payload.len() > max_bytes - bytes {
                break;
            }
            bytes += record.payload.len();
            let event = serde_json::from_slice(&record.payload)
                .map_err(|_| BufferError::Corrupt("queued event"))?;
            result.push(crate::SequencedEvent {
                sequence: record.seq,
                event,
            });
        }
        if let Some(last) = result.last() {
            self.delivered = self.delivered.max(last.sequence);
        }
        Ok(result)
    }
    pub fn ack(&mut self, seq: u64) -> Result<(), BufferError> {
        if seq <= self.checkpoint {
            return Ok(());
        }
        if seq > self.delivered || seq > self.last {
            return Err(BufferError::InvalidAck);
        }
        self.advance(seq, self.metrics.dropped)
    }
}

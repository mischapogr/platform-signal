//! Bounded input workers. A record remains pending until durable spool admission.
use crate::contracts::SourceCheckpoint;
use chrono::Utc;
use serde_json::{Map, Value};
use signal_event::{SCHEMA_VERSION, Severity, SignalEvent, Source};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_FILES: usize = 16;
#[derive(Clone, Copy, Debug)]
pub enum ParseMode {
    Plain,
    Json,
    Auto,
}
#[derive(Clone, Debug)]
pub enum InputKind {
    Stdin,
    File(PathBuf),
}
#[derive(Clone, Debug)]
pub struct InputSpec {
    pub id: u16,
    pub kind: InputKind,
    pub source: Source,
    pub mode: ParseMode,
    pub max_line_bytes: usize,
    pub follow: bool,
}
#[derive(Clone, Debug)]
pub struct InputRecord {
    pub event: Option<SignalEvent>,
    pub checkpoint: Option<SourceCheckpoint>,
    pub rejected: u64,
}
#[derive(Clone, Debug)]
pub enum ReadOutcome {
    Record(Box<InputRecord>),
    Idle,
    End,
}
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("line limit must be between one byte and 64 KiB")]
    InvalidLimit,
    #[error("input I/O operation failed")]
    Io(#[source] io::Error),
    #[error("input path must be a regular file without a symlink")]
    NotRegular,
    #[error("input worker is busy")]
    Busy,
    #[error("input operation timed out")]
    Timeout,
    #[error("input operation cancelled")]
    Cancelled,
    #[error("input worker stopped")]
    Stopped,
}
impl From<io::Error> for InputError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
enum Command {
    Read(oneshot::Sender<Result<ReadOutcome, InputError>>),
    Commit(oneshot::Sender<()>),
    Stop,
}
/// Each worker owns all physical I/O, including an operation whose caller timed out.
/// The finite command slot prevents replacement work from growing without bound.
#[derive(Default)]
struct Counters {
    queued: AtomicUsize,
    active: AtomicUsize,
    rejected: AtomicU64,
    buffered: AtomicUsize,
}
#[derive(Clone, Copy, Debug)]
pub struct InputMetrics {
    pub command_depth: usize,
    pub command_capacity: usize,
    pub active_operations: usize,
    pub operation_capacity: usize,
    pub rejected_lines: u64,
    pub buffered_bytes: usize,
    pub buffer_capacity_bytes: usize,
}
pub struct InputReader {
    commands: mpsc::SyncSender<Command>,
    counters: Arc<Counters>,
    line_limit: usize,
}
impl InputReader {
    pub fn start(
        spec: InputSpec,
        checkpoint: Option<SourceCheckpoint>,
    ) -> Result<Self, InputError> {
        if spec.max_line_bytes == 0 || spec.max_line_bytes > MAX_LINE_BYTES {
            return Err(InputError::InvalidLimit);
        }
        let line_limit = spec.max_line_bytes;
        let counters = Arc::new(Counters::default());
        let worker_counters = counters.clone();
        let (commands, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("signal-input".into())
            .spawn(move || {
                let mut state = State::open(spec, checkpoint);
                let mut pending: Option<InputRecord> = None;
                while let Ok(command) = receiver.recv() {
                    if !matches!(command, Command::Stop) {
                        worker_counters.queued.fetch_sub(1, Ordering::Relaxed);
                    }
                    worker_counters.active.store(1, Ordering::Relaxed);
                    match command {
                        Command::Stop => break,
                        Command::Commit(reply) => {
                            pending = None;
                            let _ = reply.send(());
                        }
                        Command::Read(reply) => {
                            let result = if let Some(record) = &pending {
                                Ok(ReadOutcome::Record(Box::new(record.clone())))
                            } else {
                                match &mut state {
                                    Ok(state) => state.next(),
                                    Err(error) => {
                                        Err(std::mem::replace(error, InputError::Stopped))
                                    }
                                }
                            };
                            if let Ok(ReadOutcome::Record(record)) = &result {
                                if pending.is_none() {
                                    worker_counters
                                        .rejected
                                        .fetch_add(record.rejected, Ordering::Relaxed);
                                }
                                pending = Some((**record).clone());
                            }
                            if let Ok(state) = &state {
                                worker_counters.buffered.store(
                                    state.partial.len() + state.stdin_buffer.len(),
                                    Ordering::Relaxed,
                                );
                            }
                            let _ = reply.send(result);
                        }
                    }
                    worker_counters.active.store(0, Ordering::Relaxed);
                }
            })?;
        Ok(Self {
            commands,
            counters,
            line_limit,
        })
    }
    pub async fn read(
        &self,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<ReadOutcome, InputError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Read(tx))?;
        tokio::select! { biased; _ = cancel.cancelled() => Err(InputError::Cancelled), result = tokio::time::timeout(deadline, rx) => match result { Ok(Ok(result)) => result, Ok(Err(_)) => Err(InputError::Stopped), Err(_) => Err(InputError::Timeout) } }
    }
    pub async fn commit(
        &self,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), InputError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Commit(tx))?;
        tokio::select! { biased; _ = cancel.cancelled() => Err(InputError::Cancelled), result = tokio::time::timeout(deadline, rx) => match result { Ok(Ok(())) => Ok(()), Ok(Err(_)) => Err(InputError::Stopped), Err(_) => Err(InputError::Timeout) } }
    }
    pub fn metrics(&self) -> InputMetrics {
        InputMetrics {
            command_depth: self.counters.queued.load(Ordering::Relaxed),
            command_capacity: 1,
            active_operations: self.counters.active.load(Ordering::Relaxed),
            operation_capacity: 1,
            rejected_lines: self.counters.rejected.load(Ordering::Relaxed),
            buffered_bytes: self.counters.buffered.load(Ordering::Relaxed),
            buffer_capacity_bytes: self.line_limit + 4096,
        }
    }
    fn send(&self, command: Command) -> Result<(), InputError> {
        self.counters.queued.fetch_add(1, Ordering::Relaxed);
        self.commands.try_send(command).map_err(|e| {
            self.counters.queued.fetch_sub(1, Ordering::Relaxed);
            match e {
                mpsc::TrySendError::Full(_) => InputError::Busy,
                mpsc::TrySendError::Disconnected(_) => InputError::Stopped,
            }
        })
    }
}
impl Drop for InputReader {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Stop);
    }
}

struct State {
    spec: InputSpec,
    file: File,
    offset: u64,
    anchor: Vec<u8>,
    partial: Vec<u8>,
    oversized: bool,
    ended: bool,
    stdin_buffer: VecDeque<u8>,
}
impl State {
    fn open(spec: InputSpec, checkpoint: Option<SourceCheckpoint>) -> Result<Self, InputError> {
        let file = match &spec.kind {
            InputKind::Stdin => OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open("/proc/self/fd/0")?,
            InputKind::File(path) => open_regular(path)?,
        };
        let line_limit = spec.max_line_bytes;
        let mut state = Self {
            spec,
            file,
            offset: 0,
            anchor: Vec::new(),
            partial: Vec::with_capacity(line_limit),
            oversized: false,
            ended: false,
            stdin_buffer: VecDeque::with_capacity(4096),
        };
        if let (InputKind::File(_), Some(cursor)) = (&state.spec.kind, checkpoint) {
            let metadata = state.file.metadata()?;
            if cursor.input == state.spec.id
                && cursor.device == metadata.dev()
                && cursor.inode == metadata.ino()
                && cursor.offset <= metadata.len()
                && cursor.anchor.len() <= 64
                && read_anchor(&state.file, cursor.offset)? == cursor.anchor
            {
                state.offset = cursor.offset;
                state.anchor = cursor.anchor;
            }
        }
        Ok(state)
    }
    fn next(&mut self) -> Result<ReadOutcome, InputError> {
        if self.ended {
            return Ok(ReadOutcome::End);
        }
        let is_file = matches!(self.spec.kind, InputKind::File(_));
        if is_file
            && (self.file.metadata()?.len() < self.offset
                || read_anchor(&self.file, self.offset)? != self.anchor)
        {
            self.offset = 0;
            self.anchor.clear();
            self.partial.clear();
            self.oversized = false;
        }
        // Read-ahead stays in this worker, bounded to one 4 KiB chunk.
        let mut buffer = [0u8; 4096];
        let n = if is_file {
            self.file.read_at(&mut buffer, self.offset)?
        } else if !self.stdin_buffer.is_empty() {
            self.stdin_buffer.len()
        } else {
            match self.file.read(&mut buffer) {
                Ok(n) => {
                    self.stdin_buffer.extend(&buffer[..n]);
                    n
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(ReadOutcome::Idle),
                Err(e) => return Err(e.into()),
            }
        };
        if n == 0 {
            if !is_file || !self.spec.follow {
                self.ended = true;
                if !self.partial.is_empty() || self.oversized {
                    return self.finish();
                }
                return Ok(ReadOutcome::End);
            }
            if let InputKind::File(path) = &self.spec.kind {
                match open_regular(path) {
                    Ok(replacement) => {
                        let old = self.file.metadata()?;
                        let new = replacement.metadata()?;
                        if old.dev() != new.dev() || old.ino() != new.ino() {
                            if !self.partial.is_empty() || self.oversized {
                                return self.finish();
                            }
                            self.file = replacement;
                            self.offset = 0;
                            self.anchor.clear();
                        }
                    }
                    Err(InputError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            return Ok(ReadOutcome::Idle);
        }
        for file_byte in buffer.iter().take(n) {
            let byte = if is_file {
                *file_byte
            } else {
                match self.stdin_buffer.pop_front() {
                    Some(byte) => byte,
                    None => break,
                }
            };
            self.offset += 1;
            if byte == b'\n' {
                if is_file {
                    self.anchor = read_anchor(&self.file, self.offset)?;
                }
                return self.finish();
            }
            if self.partial.len() < self.spec.max_line_bytes {
                self.partial.push(byte);
            } else {
                self.oversized = true;
            }
        }
        if is_file {
            self.anchor = read_anchor(&self.file, self.offset)?;
        }
        Ok(ReadOutcome::Idle)
    }
    fn finish(&mut self) -> Result<ReadOutcome, InputError> {
        let checkpoint = if matches!(self.spec.kind, InputKind::File(_)) {
            let metadata = self.file.metadata()?;
            Some(SourceCheckpoint {
                input: self.spec.id,
                device: metadata.dev(),
                inode: metadata.ino(),
                offset: self.offset,
                anchor: read_anchor(&self.file, self.offset)?,
            })
        } else {
            None
        };
        let event = if self.oversized {
            None
        } else {
            parse_line(&self.partial, self.spec.mode, &self.spec.source)
        };
        self.partial.clear();
        self.oversized = false;
        let rejected = u64::from(event.is_none());
        Ok(ReadOutcome::Record(Box::new(InputRecord {
            event,
            checkpoint,
            rejected,
        })))
    }
}
fn open_regular(path: &PathBuf) -> Result<File, InputError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(InputError::NotRegular);
    }
    Ok(file)
}
fn read_anchor(file: &File, offset: u64) -> Result<Vec<u8>, InputError> {
    let count = offset.min(64) as usize;
    let mut anchor = vec![0; count];
    let mut done = 0;
    while done < count {
        let n = file.read_at(&mut anchor[done..], offset - count as u64 + done as u64)?;
        if n == 0 {
            anchor.truncate(done);
            break;
        }
        done += n;
    }
    Ok(anchor)
}
fn parse_line(bytes: &[u8], mode: ParseMode, source: &Source) -> Option<SignalEvent> {
    let text = std::str::from_utf8(bytes).ok()?.trim_end_matches('\r');
    if text.trim().is_empty() {
        return None;
    }
    let attributes = match mode {
        ParseMode::Plain => Map::new(),
        ParseMode::Json => match serde_json::from_str::<Value>(text).ok()? {
            Value::Object(map) => map,
            _ => return None,
        },
        ParseMode::Auto if text.trim_start().starts_with('{') => {
            match serde_json::from_str::<Value>(text).ok()? {
                Value::Object(map) => map,
                _ => return None,
            }
        }
        ParseMode::Auto => Map::new(),
    };
    let message = attributes
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or(text)
        .to_owned();
    let now = Utc::now();
    Some(SignalEvent {
        schema_version: SCHEMA_VERSION,
        id: Uuid::new_v4(),
        timestamp: now,
        observed_at: now,
        source: source.clone(),
        severity: Severity::Info,
        message: Some(message),
        attributes,
        resource: None,
        trace_id: None,
        span_id: None,
        tags: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;
    fn spec(path: PathBuf) -> InputSpec {
        InputSpec {
            id: 1,
            kind: InputKind::File(path),
            source: Source {
                source_type: "file".into(),
                name: None,
            },
            mode: ParseMode::Auto,
            max_line_bytes: MAX_LINE_BYTES,
            follow: true,
        }
    }
    fn record(state: &mut State) -> InputRecord {
        for _ in 0..100 {
            if let ReadOutcome::Record(record) = state.next().expect("read") {
                return *record;
            }
        }
        panic!("record expected")
    }
    #[test]
    fn partial_lines_restart_and_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        std::fs::write(&path, b"first\npar").expect("write");
        let mut state = State::open(spec(path.clone()), None).expect("open");
        let first = record(&mut state);
        assert_eq!(
            first.event.expect("event").message.as_deref(),
            Some("first")
        );
        let cursor = first.checkpoint;
        assert!(matches!(state.next().expect("read"), ReadOutcome::Idle));
        let mut state = State::open(spec(path.clone()), cursor).expect("restart");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append")
            .write_all(b"tial\n")
            .expect("write");
        assert_eq!(
            record(&mut state).event.expect("event").message.as_deref(),
            Some("partial")
        );
        std::fs::rename(&path, dir.path().join("old")).expect("rename");
        std::fs::write(&path, b"new\n").expect("new");
        OpenOptions::new()
            .append(true)
            .open(dir.path().join("old"))
            .expect("old handle")
            .write_all(b"late\n")
            .expect("late write");
        assert_eq!(
            record(&mut state)
                .event
                .expect("old event")
                .message
                .as_deref(),
            Some("late")
        );
        assert!(matches!(state.next().expect("rotate"), ReadOutcome::Idle));
        assert_eq!(
            record(&mut state).event.expect("event").message.as_deref(),
            Some("new")
        );
    }
    #[test]
    fn copytruncate_regrow_and_oversize_are_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        std::fs::write(&path, b"previous\n").expect("write");
        let mut state = State::open(spec(path.clone()), None).expect("open");
        record(&mut state);
        std::fs::write(&path, b"replacement longer\n").expect("truncate-regrow");
        assert_eq!(
            record(&mut state).event.expect("event").message.as_deref(),
            Some("replacement longer")
        );
        let mut bytes = vec![b'x'; MAX_LINE_BYTES + 20];
        bytes.extend_from_slice(b"\nok\n");
        std::fs::write(&path, bytes).expect("write");
        let rejected = record(&mut state);
        assert_eq!(rejected.rejected, 1);
        assert!(rejected.event.is_none());
        assert!(state.partial.len() <= MAX_LINE_BYTES);
        assert_eq!(
            record(&mut state).event.expect("event").message.as_deref(),
            Some("ok")
        );
    }
    #[test]
    fn json_preserves_nested_keys_and_rejects_malformed() {
        let source = Source {
            source_type: "stdin".into(),
            name: None,
        };
        let event = parse_line(
            br#"{"message":"hello","user":{"name":"abc"}}"#,
            ParseMode::Auto,
            &source,
        )
        .expect("json");
        assert_eq!(event.attributes["user"]["name"], "abc");
        assert_eq!(event.message.as_deref(), Some("hello"));
        event.validate().expect("valid");
        assert!(parse_line(b"{secretbroken", ParseMode::Auto, &source).is_none());
    }
    #[tokio::test]
    async fn pending_record_identity_and_cancel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        std::fs::write(&path, b"first\nsecond\n").expect("write");
        let reader = InputReader::start(spec(path), None).expect("start");
        let cancel = CancellationToken::new();
        let first = reader
            .read(Duration::from_secs(1), &cancel)
            .await
            .expect("read");
        let again = reader
            .read(Duration::from_secs(1), &cancel)
            .await
            .expect("read");
        match (first, again) {
            (ReadOutcome::Record(a), ReadOutcome::Record(b)) => assert_eq!(a.event, b.event),
            _ => panic!("records"),
        }
        reader
            .commit(Duration::from_secs(1), &cancel)
            .await
            .expect("commit");
        match reader
            .read(Duration::from_secs(1), &cancel)
            .await
            .expect("next")
        {
            ReadOutcome::Record(r) => {
                assert_eq!(r.event.expect("event").message.as_deref(), Some("second"))
            }
            _ => panic!("record"),
        }
        cancel.cancel();
        assert!(matches!(
            reader.read(Duration::from_secs(1), &cancel).await,
            Err(InputError::Cancelled)
        ));
    }
    #[test]
    fn symlink_and_nonregular_rejected_without_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        std::fs::write(&path, b"x").expect("write");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(path, &link).expect("symlink");
        assert!(open_regular(&link).is_err());
        assert!(open_regular(&dir.path().to_path_buf()).is_err());
    }
    #[test]
    fn idle_stream_is_nonblocking_and_eof_flushes() {
        use std::os::{fd::OwnedFd, unix::net::UnixStream};
        let (reader, mut writer) = UnixStream::pair().expect("pair");
        reader.set_nonblocking(true).expect("nonblock");
        let fd: OwnedFd = reader.into();
        let mut config = spec(PathBuf::new());
        config.kind = InputKind::Stdin;
        let mut state = State {
            spec: config,
            file: File::from(fd),
            offset: 0,
            anchor: Vec::new(),
            partial: Vec::new(),
            oversized: false,
            ended: false,
            stdin_buffer: VecDeque::new(),
        };
        assert!(matches!(state.next().expect("idle"), ReadOutcome::Idle));
        writer.write_all(b"partial").expect("write");
        assert!(matches!(state.next().expect("partial"), ReadOutcome::Idle));
        drop(writer);
        assert_eq!(
            record(&mut state).event.expect("event").message.as_deref(),
            Some("partial")
        );
        assert!(matches!(state.next().expect("end"), ReadOutcome::End));
    }
    #[test]
    fn snapshot_flushes_partial_and_ends() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        std::fs::write(&path, b"partial").expect("write");
        let mut config = spec(path);
        config.follow = false;
        let mut state = State::open(config, None).expect("open");
        assert_eq!(
            record(&mut state).event.expect("event").message.as_deref(),
            Some("partial")
        );
        assert!(matches!(state.next().expect("end"), ReadOutcome::End));
    }
}

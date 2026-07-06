//! Bounded, lossy diagnostics with one dedicated synchronous sink worker.
//!
//! Formatting reservations, queued records and the active sink write all share
//! the same record/byte budget. Shutdown never joins a stalled kernel writer;
//! the single worker may finish later, without retaining a Tokio runtime task.
//! `fmt::Layer` first formats into an unbounded String, so installation uses our
//! streaming JSON layer rather than feeding this writer through `fmt()`.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fmt,
    io::{self, Write},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{sync::Notify, time::Instant};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, filter::LevelFilter, fmt::MakeWriter, layer::SubscriberExt};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub queue_records: usize,
    pub queue_bytes: usize,
    pub max_record_bytes: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            queue_records: 1024,
            queue_bytes: 1_048_576,
            max_record_bytes: 8192,
        }
    }
}

impl LoggingConfig {
    pub fn validate(&self) -> Result<(), LoggingError> {
        if !(1..=65_536).contains(&self.queue_records)
            || !(64..=67_108_864).contains(&self.queue_bytes)
            || !(64..=1_048_576).contains(&self.max_record_bytes)
            || self.max_record_bytes > self.queue_bytes
        {
            return Err(LoggingError::Config);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error(
        "invalid logging capacity: records 1..65536, bytes 64..67108864, record bytes 64..1048576 and <= queue bytes"
    )]
    Config,
    #[error("logging worker startup failed")]
    Worker(#[source] io::Error),
    #[error("structured logging subscriber installation failed")]
    Install,
    #[error("logging shutdown deadline exceeded; diagnostic records may be lost")]
    Deadline,
    #[error("logging sink write or flush failed; diagnostic records may be lost")]
    Sink,
}

#[derive(Clone, Copy, Debug)]
pub struct LoggingMetrics {
    /// Includes formatting reservations, queued records and the active write.
    pub depth: usize,
    pub capacity: usize,
    pub bytes: usize,
    pub capacity_bytes: usize,
    pub queued_records: usize,
    pub dropped_records: u64,
    pub full_records: u64,
    pub oversized_records: u64,
    pub closed_records: u64,
    pub written_records: u64,
    pub write_errors: u64,
    pub closed: bool,
}

struct State {
    records: VecDeque<Vec<u8>>,
    metrics: LoggingMetrics,
    finished: bool,
}

struct Shared {
    config: LoggingConfig,
    state: Mutex<State>,
    wake: Condvar,
    finished: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // No application code or I/O runs under this lock. Recovering a poisoned
        // lock avoids recursive logging or panicking in diagnostic Drop paths.
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn close(&self) {
        self.lock().metrics.closed = true;
        self.wake.notify_one();
    }
}

#[derive(Clone)]
pub struct LogWriter(Arc<Shared>);

pub struct LoggerGuard {
    writer: LogWriter,
}

impl LoggerGuard {
    pub fn stderr(config: LoggingConfig) -> Result<Self, LoggingError> {
        Self::with_sink(config, io::stderr())
    }

    fn with_sink<W: Write + Send + 'static>(
        config: LoggingConfig,
        sink: W,
    ) -> Result<Self, LoggingError> {
        config.validate()?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                records: VecDeque::new(),
                metrics: LoggingMetrics {
                    depth: 0,
                    capacity: config.queue_records,
                    bytes: 0,
                    capacity_bytes: config.queue_bytes,
                    queued_records: 0,
                    dropped_records: 0,
                    full_records: 0,
                    oversized_records: 0,
                    closed_records: 0,
                    written_records: 0,
                    write_errors: 0,
                    closed: false,
                },
                finished: false,
            }),
            config,
            wake: Condvar::new(),
            finished: Notify::new(),
        });
        let worker_shared = shared.clone();
        // Dropping std's JoinHandle detaches; unlike spawn_blocking, this worker
        // does not make Tokio runtime destruction wait for a stalled stderr.
        std::thread::Builder::new()
            .name("signal-diagnostics".into())
            .spawn(move || worker(worker_shared, sink))
            .map_err(LoggingError::Worker)?;
        Ok(Self {
            writer: LogWriter(shared),
        })
    }

    pub fn writer(&self) -> LogWriter {
        self.writer.clone()
    }

    #[cfg(test)]
    pub fn metrics(&self) -> LoggingMetrics {
        self.writer.metrics()
    }

    pub fn install(&self) -> Result<(), LoggingError> {
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry()
                .with(JsonLayer(self.writer()).with_filter(LevelFilter::INFO)),
        )
        .map_err(|_| LoggingError::Install)
    }

    pub async fn shutdown(&self, deadline: Instant) -> Result<(), LoggingError> {
        self.writer.0.close();
        loop {
            let finished = self.writer.0.finished.notified();
            // Register before inspecting state: notify_waiters need not retain
            // a permit, and multiple callers may wait for the same completion.
            tokio::pin!(finished);
            finished.as_mut().enable();
            {
                let state = self.writer.0.lock();
                if state.finished {
                    return if state.metrics.write_errors == 0 {
                        Ok(())
                    } else {
                        Err(LoggingError::Sink)
                    };
                }
            }
            tokio::time::timeout_at(deadline, finished)
                .await
                .map_err(|_| LoggingError::Deadline)?;
        }
    }
}

impl Drop for LoggerGuard {
    fn drop(&mut self) {
        self.writer.0.close();
    }
}

impl LogWriter {
    pub fn metrics(&self) -> LoggingMetrics {
        self.0.lock().metrics
    }

    /// Only pass errors whose Display contains static, sanitized context.
    /// Formatting is streamed through the same reservation and byte bound.
    pub fn report_error(&self, error: &dyn fmt::Display) {
        let mut record = self.make_writer();
        if record.discarded {
            return;
        }
        let result = (|| {
            record.write_all(b"{\"level\":\"ERROR\",\"fields\":{\"message\":\"")?;
            fmt::write(&mut Escaped(&mut record), format_args!("{error}"))
                .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
            record.write_all(b"\"}}\n")
        })();
        if result.is_err() {
            record.discarded = true;
        }
    }
}

/// A one-shot startup/fatal diagnostic path, including before global install.
/// The deadline covers sink draining; no formatting String or blocking join.
pub async fn report_startup_error(
    error: &dyn fmt::Display,
    deadline: Instant,
) -> Result<(), LoggingError> {
    let logger = LoggerGuard::stderr(LoggingConfig::default())?;
    logger.writer.report_error(error);
    logger.shutdown(deadline).await
}

pub struct RecordWriter {
    shared: Arc<Shared>,
    bytes: Vec<u8>,
    reserved: bool,
    discarded: bool,
    oversized: bool,
}

impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        let mut state = self.0.lock();
        let available = !state.metrics.closed
            && state.metrics.depth < self.0.config.queue_records
            && self.0.config.max_record_bytes <= self.0.config.queue_bytes - state.metrics.bytes;
        if available {
            state.metrics.depth += 1;
            state.metrics.bytes += self.0.config.max_record_bytes;
        } else {
            state.metrics.dropped_records += 1;
            if state.metrics.closed {
                state.metrics.closed_records += 1;
            } else {
                state.metrics.full_records += 1;
            }
        }
        drop(state);
        RecordWriter {
            shared: self.0.clone(),
            bytes: if available {
                Vec::with_capacity(self.0.config.max_record_bytes)
            } else {
                Vec::new()
            },
            reserved: available,
            discarded: !available,
            oversized: false,
        }
    }
}

impl Write for RecordWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.discarded {
            return Err(io::ErrorKind::Other.into());
        }
        if bytes.len() > self.shared.config.max_record_bytes - self.bytes.len() {
            self.discarded = true;
            self.oversized = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Only whole records are enqueued by Drop, never formatting fragments.
        Ok(())
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        if !self.reserved {
            return;
        }
        let mut state = self.shared.lock();
        if self.discarded || self.bytes.is_empty() || state.metrics.closed {
            // Free the formatting allocation before releasing its reservation.
            drop(std::mem::take(&mut self.bytes));
        }
        state.metrics.bytes -= self.shared.config.max_record_bytes;
        if self.discarded || self.bytes.is_empty() || state.metrics.closed {
            state.metrics.depth -= 1;
            state.metrics.dropped_records += 1;
            if self.oversized {
                state.metrics.oversized_records += 1;
            } else if state.metrics.closed {
                state.metrics.closed_records += 1;
            }
        } else {
            // Capacity remains max_record_bytes while queued or actively being
            // written, so reserve allocation capacity rather than logical len.
            state.metrics.bytes += self.shared.config.max_record_bytes;
            state.records.push_back(std::mem::take(&mut self.bytes));
            state.metrics.queued_records += 1;
        }
        drop(state);
        self.shared.wake.notify_one();
    }
}

fn worker<W: Write>(shared: Arc<Shared>, mut sink: W) {
    loop {
        let record = {
            let mut state = shared.lock();
            loop {
                if let Some(record) = state.records.pop_front() {
                    state.metrics.queued_records -= 1;
                    break Some(record);
                }
                if state.metrics.closed {
                    break None;
                }
                state = shared
                    .wake
                    .wait(state)
                    .unwrap_or_else(|error| error.into_inner());
            }
        };
        let Some(record) = record else { break };
        let result = sink.write_all(&record);
        drop(record);
        let mut state = shared.lock();
        state.metrics.depth -= 1;
        state.metrics.bytes -= shared.config.max_record_bytes;
        if result.is_ok() {
            state.metrics.written_records += 1;
        } else {
            state.metrics.write_errors += 1;
            state.metrics.dropped_records += 1;
        }
    }
    let result = sink.flush();
    {
        let mut state = shared.lock();
        if result.is_err() {
            state.metrics.write_errors += 1;
        }
        state.finished = true;
    }
    shared.finished.notify_waiters();
}

struct JsonLayer(LogWriter);

impl<S: Subscriber> Layer<S> for JsonLayer {
    fn on_event(&self, event: &Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut record = self.0.make_writer();
        if record.discarded {
            return;
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let result = (|| {
            record.write_all(b"{\"timestamp_unix_ms\":")?;
            serde_json::to_writer(&mut record, &timestamp).map_err(io::Error::other)?;
            record.write_all(b",\"level\":")?;
            serde_json::to_writer(&mut record, event.metadata().level().as_str())
                .map_err(io::Error::other)?;
            record.write_all(b",\"target\":")?;
            serde_json::to_writer(&mut record, event.metadata().target())
                .map_err(io::Error::other)?;
            record.write_all(b",\"fields\":{")?;
            event.record(&mut JsonVisitor {
                record: &mut record,
                first: true,
            });
            record.write_all(b"}}\n")
        })();
        if result.is_err() {
            record.discarded = true;
        }
    }
}

struct JsonVisitor<'a> {
    record: &'a mut RecordWriter,
    first: bool,
}

impl JsonVisitor<'_> {
    fn prefix(&mut self, field: &tracing::field::Field) -> io::Result<()> {
        if !self.first {
            self.record.write_all(b",")?;
        }
        self.first = false;
        serde_json::to_writer(&mut *self.record, field.name()).map_err(io::Error::other)?;
        self.record.write_all(b":")
    }

    fn value<T: Serialize>(&mut self, field: &tracing::field::Field, value: T) {
        if self.record.discarded {
            return;
        }
        if self.prefix(field).is_err() || serde_json::to_writer(&mut *self.record, &value).is_err()
        {
            self.record.discarded = true;
        }
    }
}

impl Visit for JsonVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if self.record.discarded {
            return;
        }
        let result = (|| {
            self.prefix(field)?;
            self.record.write_all(b"\"")?;
            fmt::write(&mut Escaped(self.record), format_args!("{value:?}"))
                .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
            self.record.write_all(b"\"")
        })();
        if result.is_err() {
            self.record.discarded = true;
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.value(field, value);
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.value(field, value);
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.value(field, value);
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.value(field, value);
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.value(field, value);
    }
    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.value(field, value);
    }
    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.value(field, value);
    }
}

/// Debug/Display output is escaped incrementally, with no intermediate String.
struct Escaped<'a>(&'a mut RecordWriter);

impl fmt::Write for Escaped<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for character in text.chars() {
            let result = match character {
                '"' => self.0.write_all(b"\\\""),
                '\\' => self.0.write_all(b"\\\\"),
                '\n' => self.0.write_all(b"\\n"),
                '\r' => self.0.write_all(b"\\r"),
                '\t' => self.0.write_all(b"\\t"),
                control if control <= '\u{1f}' => {
                    let value = control as usize;
                    self.0
                        .write_all(&[b'\\', b'u', b'0', b'0', HEX[value >> 4], HEX[value & 15]])
                }
                other => {
                    let mut bytes = [0; 4];
                    self.0.write_all(other.encode_utf8(&mut bytes).as_bytes())
                }
            };
            result.map_err(|_| fmt::Error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::from(io::ErrorKind::Other))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn small_config() -> LoggingConfig {
        LoggingConfig {
            queue_records: 3,
            queue_bytes: 1536,
            max_record_bytes: 512,
        }
    }

    #[test]
    fn configuration_rejects_zero_and_excessive_bounds() -> TestResult {
        let config: LoggingConfig = serde_json::from_str("{}")?;
        config.validate()?;
        for config in [
            LoggingConfig {
                queue_records: 0,
                ..Default::default()
            },
            LoggingConfig {
                queue_records: 65_537,
                ..Default::default()
            },
            LoggingConfig {
                queue_bytes: 67_108_865,
                ..Default::default()
            },
            LoggingConfig {
                max_record_bytes: 1_048_577,
                ..Default::default()
            },
            LoggingConfig {
                queue_bytes: 64,
                max_record_bytes: 65,
                ..Default::default()
            },
        ] {
            assert!(matches!(config.validate(), Err(LoggingError::Config)));
        }
        Ok(())
    }

    #[tokio::test]
    async fn fragments_form_one_record_and_format_reservations_are_bounded() -> TestResult {
        let capture = Capture::default();
        let guard = LoggerGuard::with_sink(small_config(), capture.clone())?;
        let writer = guard.writer();
        let mut record = writer.make_writer();
        record.write_all(b"first ")?;
        record.write_all(b"second\n")?;
        let second = writer.make_writer();
        let third = writer.make_writer();
        let rejected = writer.make_writer();
        assert!(rejected.discarded);
        assert_eq!(rejected.bytes.capacity(), 0);
        assert_eq!(writer.metrics().depth, 3);
        assert_eq!(writer.metrics().bytes, 1536);
        assert_eq!(writer.metrics().full_records, 1);
        // Empty reserved writers release capacity without publishing fragments.
        drop(second);
        drop(third);
        drop(record);
        guard
            .shutdown(Instant::now() + Duration::from_secs(2))
            .await?;
        assert_eq!(
            *capture.0.lock().map_err(|_| "capture poisoned")?,
            b"first second\n"
        );
        assert_eq!(writer.metrics().written_records, 1);
        assert_eq!(writer.metrics().bytes, 0);
        assert_eq!(writer.metrics().depth, 0);
        assert!(writer.make_writer().discarded);
        assert_eq!(writer.metrics().closed_records, 1);
        Ok(())
    }

    struct LongDebug(Arc<AtomicUsize>);

    impl fmt::Debug for LongDebug {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for _ in 0..1_000_000 {
                self.0.fetch_add(1, Ordering::Relaxed);
                formatter.write_str("oversized diagnostic ")?;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn streaming_json_preserves_fields_and_stops_oversized_debug_early() -> TestResult {
        let capture = Capture::default();
        let guard = LoggerGuard::with_sink(small_config(), capture.clone())?;
        let visits = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(JsonLayer(guard.writer()).with_filter(LevelFilter::INFO));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(detail = "debug-only detail", "excluded by default level");
            tracing::info!(
                count = 7u64,
                ready = true,
                detail = "a\"b\n雪",
                "quoted {}",
                "line\n"
            );
            tracing::info!(large = ?LongDebug(visits.clone()), "too long");
        });
        guard.writer().report_error(&"static fatal \"context\"\n");
        guard
            .shutdown(Instant::now() + Duration::from_secs(2))
            .await?;
        assert!(visits.load(Ordering::Relaxed) < 100);
        assert_eq!(guard.metrics().oversized_records, 1);
        assert_eq!(guard.metrics().dropped_records, 1);
        let bytes = capture.0.lock().map_err(|_| "capture poisoned")?;
        let text = std::str::from_utf8(&bytes)?;
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["level"], "INFO");
        assert_eq!(rows[0]["fields"]["count"], 7);
        assert_eq!(rows[0]["fields"]["ready"], true);
        assert_eq!(rows[0]["fields"]["detail"], "a\"b\n雪");
        assert_eq!(rows[0]["fields"]["message"], "quoted line\n");
        assert_eq!(rows[1]["fields"]["message"], "static fatal \"context\"\n");
        Ok(())
    }

    struct FailedSink;

    impl Write for FailedSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[tokio::test]
    async fn sink_failures_are_counted_and_shutdown_returns_typed_error() -> TestResult {
        let guard = LoggerGuard::with_sink(small_config(), FailedSink)?;
        guard.writer().report_error(&"safe static failure");
        assert!(matches!(
            guard
                .shutdown(Instant::now() + Duration::from_secs(2))
                .await,
            Err(LoggingError::Sink)
        ));
        assert_eq!(guard.metrics().write_errors, 2);
        assert_eq!(guard.metrics().dropped_records, 1);
        assert_eq!(guard.metrics().depth, 0);
        Ok(())
    }

    #[derive(Default)]
    struct Pause {
        released: Mutex<bool>,
        wake: Condvar,
        entered: AtomicBool,
    }

    struct PausedSink(Arc<Pause>);

    impl Write for PausedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.entered.store(true, Ordering::Release);
            let mut released = self.0.released.lock().map_err(|_| io::ErrorKind::Other)?;
            while !*released {
                released = self
                    .0
                    .wake
                    .wait(released)
                    .map_err(|_| io::ErrorKind::Other)?;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Release(Arc<Pause>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self
                .0
                .released
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = true;
            self.0.wake.notify_one();
        }
    }

    #[test]
    fn stalled_sink_bounds_records_http_timer_shutdown_and_runtime_drop() -> TestResult {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let pause = Arc::new(Pause::default());
        let release = Release(pause.clone());
        let guard = LoggerGuard::with_sink(small_config(), PausedSink(pause.clone()))?;
        let writer = guard.writer();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            writer.report_error(&"initial diagnostic");
            tokio::time::timeout(Duration::from_secs(2), async {
                while !pause.entered.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await?;
            let subscriber = tracing_subscriber::registry().with(JsonLayer(writer.clone()));
            tracing::subscriber::with_default(subscriber, || {
                for index in 0..10_000 {
                    tracing::info!(index, "bounded saturation");
                }
            });
            let metrics = writer.metrics();
            assert_eq!(metrics.depth, 3);
            assert_eq!(metrics.bytes, 1536);
            assert_eq!(metrics.queued_records, 2);
            assert_eq!(metrics.full_records, 9998);
            assert_eq!(metrics.dropped_records, 9998);
            // Real local HTTP socket traffic and timer remain live on a single
            // Tokio thread while the dedicated diagnostic worker is stalled.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let request = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                let mut bytes = [0; 128];
                let _ = socket.read(&mut bytes).await?;
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await?;
                Ok::<_, io::Error>(())
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                let mut client = tokio::net::TcpStream::connect(address).await?;
                client
                    .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                assert!(response.ends_with(b"ok"));
                request.await??;
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<_, Box<dyn std::error::Error>>(())
            })
            .await??;
            let start = Instant::now();
            assert!(matches!(
                guard.shutdown(start + Duration::from_millis(30)).await,
                Err(LoggingError::Deadline)
            ));
            assert!(start.elapsed() < Duration::from_millis(500));
            assert_eq!(writer.metrics().written_records, 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        let start = std::time::Instant::now();
        drop(runtime);
        assert!(start.elapsed() < Duration::from_millis(500));
        // The original worker drains after release; shutdown does not replace it.
        drop(release);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(guard.shutdown(Instant::now() + Duration::from_secs(2)))?;
        assert_eq!(writer.metrics().written_records, 3);
        assert_eq!(writer.metrics().depth, 0);
        assert_eq!(writer.metrics().bytes, 0);
        Ok(())
    }
}

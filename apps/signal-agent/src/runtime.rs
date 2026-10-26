//! One producer and one sender share a bounded durable spool.
use crate::{
    config::AgentConfig,
    http::{BatchSender, Disposition, SendError, retry_delay},
    input::{InputReader, ReadOutcome},
    spool::{CursorProfile, Spool, SpoolError},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent input failed")]
    Input,
    #[error("node worker physical retirement not confirmed")]
    NodeRetirement,
    #[error("agent spool failed")]
    Spool,
    #[error("agent HTTP configuration or admission failed")]
    Http,
    #[error("agent metrics listener failed")]
    Metrics,
    #[error("agent shutdown deadline expired; pending spool is retained")]
    Pending,
}
#[derive(Default)]
pub(crate) struct Counters {
    accepted: AtomicU64,
    retries: AtomicU64,
    pub(crate) rejected: AtomicU64,
    requests: AtomicU64,
    done: AtomicBool,
    pub(crate) changed: Notify,
    pub(crate) syslog: crate::syslog::Metrics,
    node: Option<crate::node_input::Metrics>,
}
#[derive(Clone, Copy, Debug)]
pub struct RuntimeReport {
    pub accepted: u64,
    pub rejected: u64,
    pub retries: u64,
    pub pending: usize,
}

/// Stop source reads before draining with one shutdown deadline.
pub async fn run(
    mut config: AgentConfig,
    stopping: CancellationToken,
) -> Result<RuntimeReport, AgentError> {
    if let Some(node) = &config.node {
        node.validate().map_err(|_| AgentError::Input)?;
        if !config.inputs.is_empty() || config.syslog.is_some() {
            return Err(AgentError::Input);
        }
        if config.batch_bytes != config.spool.max_batch_bytes
            || config.batch_events != config.spool.max_batch_events
        {
            return Err(AgentError::Spool);
        }
        let mut capacity = config.spool.clone();
        capacity.cursor_profile = CursorProfile::KubernetesNode {
            source_binding: [0; 32],
        };
        capacity.validate().map_err(|_| AgentError::Spool)?;
    } else if config.spool.cursor_profile != CursorProfile::Legacy {
        return Err(AgentError::Input);
    }
    config.spool.validate().map_err(|_| AgentError::Spool)?;
    let tls = match &config.tls_config {
        Some(path) => Some(
            crate::tls::load(
                path.clone(),
                Instant::now() + config.request_timeout,
                stopping.clone(),
            )
            .await
            .map_err(|_| AgentError::Http)?,
        ),
        None => None,
    };
    let syslog = match &config.syslog {
        Some(config) => Some(crate::syslog::Receiver::prepare(config, &stopping).await?),
        None => None,
    };
    let sender = BatchSender::with_tls(
        &config.server,
        config.token.as_deref(),
        config.batch_events,
        config.batch_bytes,
        config.request_timeout.min(Duration::from_secs(3)),
        config.request_timeout,
        tls,
    )
    .map_err(|_| AgentError::Http)?;
    let listener = if let Some(address) = config.metrics_listen {
        Some(
            tokio::time::timeout(Duration::from_secs(5), TcpListener::bind(address))
                .await
                .map_err(|_| AgentError::Metrics)?
                .map_err(|_| AgentError::Metrics)?,
        )
    } else {
        None
    };
    let startup_deadline = Instant::now() + config.request_timeout;
    let mut node = match &config.node {
        Some(value) => Some(
            crate::node_input::Reader::prepare(value.clone(), startup_deadline, &stopping)
                .await
                .map_err(|_| AgentError::Input)?,
        ),
        None => None,
    };
    if let Some(profile) = node.as_ref().map(|r| r.profile()) {
        if config.spool.cursor_profile != CursorProfile::Legacy
            && config.spool.cursor_profile != profile
        {
            let deadline = Instant::now() + config.shutdown_timeout;
            close_sources(&mut node, None, deadline).await?;
            return Err(AgentError::Input);
        }
        config.spool.cursor_profile = profile;
    }
    let opening = async {
        Spool::open(config.spool.clone(), &stopping)
            .await
            .map_err(|_| AgentError::Spool)
    };
    let opened = if node.is_some() {
        tokio::time::timeout_at(startup_deadline, opening)
            .await
            .unwrap_or(Err(AgentError::Spool))
    } else {
        opening.await
    };
    let spool = match opened {
        Ok(s) => s,
        Err(error) => {
            let deadline = Instant::now() + config.shutdown_timeout;
            close_sources(&mut node, None, deadline).await?;
            return Err(error);
        }
    };
    let startup = async {
        let reading = spool.cursor_snapshot(&stopping);
        let checkpoints = if node.is_some() {
            tokio::time::timeout_at(startup_deadline, reading)
                .await
                .map_err(|_| AgentError::Spool)?
                .map_err(|_| AgentError::Spool)?
        } else {
            reading.await.map_err(|_| AgentError::Spool)?
        };
        if let Some(reader) = &mut node {
            reader
                .restore(checkpoints.clone(), startup_deadline, &stopping)
                .await
                .map_err(|_| AgentError::Input)?;
        } else {
            crate::input::validate_source_checkpoints(
                &config.inputs,
                &checkpoints,
                spool.metrics().records,
            )
            .map_err(|_| AgentError::Input)?;
        }
        config
            .inputs
            .iter()
            .map(|spec| {
                InputReader::start(
                    spec.clone(),
                    checkpoints.iter().find(|c| c.input == spec.id).cloned(),
                )
                .map_err(|_| AgentError::Input)
            })
            .collect::<Result<Vec<_>, _>>()
    }
    .await;
    let inputs = match startup {
        Ok(value) => value,
        Err(error) => {
            let deadline = Instant::now() + config.shutdown_timeout;
            close_sources(&mut node, Some(&spool), deadline).await?;
            return Err(error);
        }
    };
    let stats = Arc::new(Counters {
        node: node.as_ref().map(|n| n.metrics()),
        ..Default::default()
    });
    let input_stop = stopping.child_token();
    let force_stop = CancellationToken::new();
    let mut failure = None;
    let mut deadline = None;
    {
        let producer = async {
            if let Some(reader) = &mut node {
                produce_node(
                    reader,
                    &spool,
                    &stats,
                    &input_stop,
                    &force_stop,
                    config.request_timeout,
                    config.spool.max_event_bytes,
                )
                .await
            } else if let Some(receiver) = &syslog {
                receiver
                    .run(
                        &spool,
                        &stats,
                        &input_stop,
                        &force_stop,
                        config.spool.max_event_bytes,
                    )
                    .await
            } else {
                produce(
                    &inputs,
                    &spool,
                    &stats,
                    &input_stop,
                    &force_stop,
                    config.spool.max_event_bytes,
                )
                .await
            }
        };
        let consumer = forward(&sender, &spool, &stats, &force_stop, &config);
        let metrics = serve_metrics(listener, &inputs, &spool, &stats, &force_stop);
        tokio::pin!(producer, consumer, metrics);
        let mut producer_done = false;
        loop {
            let clock = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(86400));
            tokio::select! {
                biased;
                _ = stopping.cancelled(), if deadline.is_none() => {
                    input_stop.cancel(); deadline = Some(Instant::now() + config.shutdown_timeout);
                }
                result = &mut producer, if !producer_done => {
                    producer_done = true;
                    stats.done.store(true, Ordering::Release);
                    stats.changed.notify_one();
                    if let Err(error) = result { failure = Some(error); }
                    deadline.get_or_insert_with(|| Instant::now() + config.shutdown_timeout);
                }
                result = &mut consumer => {
                    if let Err(error) = result { failure = Some(error); }
                    break;
                }
                result = &mut metrics => {
                    if result.is_err() { failure = Some(AgentError::Metrics); }
                    break;
                }
                _ = tokio::time::sleep_until(clock), if deadline.is_some() => {
                    failure.get_or_insert(AgentError::Pending); break;
                }
            }
        }
        input_stop.cancel();
        force_stop.cancel();
    }
    // Dropped futures release responses; physical work retains its own permits.
    let close_deadline = deadline.unwrap_or_else(|| Instant::now() + config.shutdown_timeout);
    if let Err(error) = close_sources(&mut node, Some(&spool), close_deadline).await {
        failure.get_or_insert(error);
    }
    let report = RuntimeReport {
        accepted: stats.accepted.load(Ordering::Relaxed),
        rejected: stats.rejected.load(Ordering::Relaxed),
        retries: stats.retries.load(Ordering::Relaxed),
        pending: spool.metrics().records,
    };
    if report.pending != 0 {
        failure.get_or_insert(AgentError::Pending);
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(report),
    }
}

async fn close_sources(
    node: &mut Option<crate::node_input::Reader>,
    spool: Option<&Spool>,
    deadline: Instant,
) -> Result<(), AgentError> {
    let mut error = None;
    if let Some(reader) = node
        && reader.close(deadline).await.is_err()
    {
        error = Some(AgentError::NodeRetirement);
    }
    if let Some(spool) = spool {
        let token = CancellationToken::new();
        if !matches!(
            tokio::time::timeout_at(deadline, spool.close(&token)).await,
            Ok(Ok(()))
        ) {
            error.get_or_insert(AgentError::Spool);
        }
    }
    error.map_or(Ok(()), Err)
}
async fn produce_node(
    reader: &mut crate::node_input::Reader,
    spool: &Spool,
    stats: &Counters,
    stopping: &CancellationToken,
    force_stop: &CancellationToken,
    timeout: Duration,
    max_event_bytes: usize,
) -> Result<(), AgentError> {
    loop {
        if stopping.is_cancelled() {
            return Ok(());
        }
        let outcome = match reader.read(Instant::now() + timeout, stopping).await {
            Ok(v) => v,
            Err(_) if stopping.is_cancelled() => return Ok(()),
            Err(_) => return Err(AgentError::Input),
        };
        match outcome {
            ReadOutcome::End => return Ok(()),
            ReadOutcome::Idle => {}
            ReadOutcome::Record(record) => {
                if let Some(event) = &record.event {
                    let mut count = SizeLimit {
                        bytes: 0,
                        limit: max_event_bytes,
                    };
                    serde_json::to_writer(&mut count, event).map_err(|_| AgentError::Input)?;
                }
                loop {
                    if stopping.is_cancelled() {
                        return Ok(());
                    }
                    let result = if let Some(event) = &record.event {
                        spool
                            .append(event.clone(), record.checkpoint.clone(), force_stop)
                            .await
                            .map(|_| ())
                    } else if let Some(cursor) = &record.checkpoint {
                        spool.checkpoint(cursor.clone(), force_stop).await
                    } else {
                        return Err(AgentError::Input);
                    };
                    match result {
                        Ok(()) => break,
                        Err(SpoolError::Quota | SpoolError::Full) => {
                            tokio::select! {biased;_=stopping.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(50))=>{}}
                        }
                        Err(_) => return Err(AgentError::Spool),
                    }
                }
                stats.rejected.fetch_add(record.rejected, Ordering::Relaxed);
                reader
                    .commit(Instant::now() + timeout, stopping)
                    .await
                    .map_err(|_| AgentError::Input)?;
                stats.changed.notify_one();
            }
        }
        tokio::select! {biased;_=stopping.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(10))=>{}}
    }
}

async fn produce(
    inputs: &[InputReader],
    spool: &Spool,
    stats: &Counters,
    stopping: &CancellationToken,
    force_stop: &CancellationToken,
    max_event_bytes: usize,
) -> Result<(), AgentError> {
    let mut ended = vec![false; inputs.len()];
    while !ended.iter().all(|e| *e) {
        for (index, input) in inputs.iter().enumerate() {
            if ended[index] {
                continue;
            }
            if stopping.is_cancelled() {
                return Ok(());
            }
            let outcome = match input.read(Duration::from_secs(5), stopping).await {
                Ok(value) => value,
                Err(_) if stopping.is_cancelled() => return Ok(()),
                Err(_) => return Err(AgentError::Input),
            };
            match outcome {
                ReadOutcome::End => ended[index] = true,
                ReadOutcome::Idle => {}
                ReadOutcome::Record(record) => {
                    let mut record = *record;
                    stats.rejected.fetch_add(record.rejected, Ordering::Relaxed);
                    if let Some(event) = &record.event {
                        let mut count = SizeLimit {
                            bytes: 0,
                            limit: max_event_bytes,
                        };
                        if serde_json::to_writer(&mut count, event).is_err() {
                            stats.rejected.fetch_add(1, Ordering::Relaxed);
                            record.event = None;
                        }
                    }
                    loop {
                        if stopping.is_cancelled() {
                            return Ok(());
                        }
                        let admitted = if let Some(event) = &record.event {
                            spool
                                .append(event.clone(), record.checkpoint.clone(), force_stop)
                                .await
                                .map(|_| ())
                        } else if let Some(checkpoint) = &record.checkpoint {
                            spool.checkpoint(checkpoint.clone(), force_stop).await
                        } else {
                            Ok(())
                        };
                        match admitted {
                            Ok(()) => break,
                            Err(SpoolError::Quota | SpoolError::Full) => {
                                tokio::select! { biased; _ = stopping.cancelled() => return Ok(()),
                                _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
                            }
                            Err(_) if stopping.is_cancelled() => return Ok(()),
                            Err(_) => return Err(AgentError::Spool),
                        }
                    }
                    if input
                        .commit(Duration::from_secs(5), stopping)
                        .await
                        .is_err()
                    {
                        if stopping.is_cancelled() {
                            return Ok(());
                        }
                        return Err(AgentError::Input);
                    }
                    stats.changed.notify_one();
                }
            }
        }
        tokio::select! { biased; _ = stopping.cancelled() => return Ok(()),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {} }
    }
    Ok(())
}
pub(crate) struct SizeLimit {
    pub(crate) bytes: usize,
    pub(crate) limit: usize,
}
impl io::Write for SizeLimit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > self.limit {
            return Err(io::Error::other("event limit"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn forward(
    sender: &BatchSender,
    spool: &Spool,
    stats: &Counters,
    cancel: &CancellationToken,
    config: &AgentConfig,
) -> Result<(), AgentError> {
    let mut batch_limit = config.batch_events;
    let mut attempt = 0u32;
    loop {
        let mut records = spool
            .read_batch(batch_limit, config.batch_bytes - 64 - batch_limit, cancel)
            .await
            .map_err(|_| AgentError::Spool)?;
        if records.is_empty() {
            if stats.done.load(Ordering::Acquire) {
                return Ok(());
            }
            tokio::select! { biased; _ = cancel.cancelled() => return Err(AgentError::Pending),
            _ = stats.changed.notified() => {}, _ = tokio::time::sleep(config.flush) => {} }
            continue;
        }
        if records.len() < batch_limit && attempt == 0 && !stats.done.load(Ordering::Acquire) {
            tokio::select! { biased; _ = cancel.cancelled() => return Err(AgentError::Pending),
            _ = tokio::time::sleep(config.flush) => {} }
            records = spool
                .read_batch(batch_limit, config.batch_bytes - 64 - batch_limit, cancel)
                .await
                .map_err(|_| AgentError::Spool)?;
        }
        let events: Vec<_> = records.iter().map(|r| r.event.clone()).collect();
        stats.requests.fetch_add(1, Ordering::Relaxed);
        let outcome = sender.send(&events, cancel).await;
        let mut retry = true;
        match outcome {
            Ok(outcome) => {
                if outcome.accepted > 0 {
                    spool
                        .ack(records[outcome.accepted - 1].sequence, cancel)
                        .await
                        .map_err(|_| AgentError::Spool)?;
                    stats
                        .accepted
                        .fetch_add(outcome.accepted as u64, Ordering::Relaxed);
                    attempt = 0;
                }
                match outcome.disposition {
                    Disposition::Complete => retry = false,
                    Disposition::Permanent => return Err(AgentError::Http),
                    Disposition::ReduceBatch if batch_limit > 1 => {
                        batch_limit = (records.len() / 2).max(1)
                    }
                    Disposition::ReduceBatch => return Err(AgentError::Http),
                    Disposition::Retry => {}
                }
            }
            Err(SendError::BatchLimit) if batch_limit > 1 => {
                batch_limit = (records.len() / 2).max(1)
            }
            Err(SendError::BatchLimit | SendError::Serialization | SendError::Configuration) => {
                return Err(AgentError::Http);
            }
            Err(SendError::Cancelled) => return Err(AgentError::Pending),
            Err(_) => {}
        }
        if retry {
            stats.retries.fetch_add(1, Ordering::Relaxed);
            let id = uuid::Uuid::new_v4();
            let mut random = [0u8; 8];
            random.copy_from_slice(&id.as_bytes()[..8]);
            let delay = retry_delay(
                attempt,
                config.retry_base,
                config.retry_max,
                u64::from_be_bytes(random),
            );
            attempt = attempt.saturating_add(1);
            tokio::select! { biased; _ = cancel.cancelled() => return Err(AgentError::Pending),
            _ = tokio::time::sleep(delay) => {} }
        }
    }
}

async fn serve_metrics(
    listener: Option<TcpListener>,
    inputs: &[InputReader],
    spool: &Spool,
    stats: &Counters,
    cancel: &CancellationToken,
) -> Result<(), AgentError> {
    let Some(listener) = listener else {
        cancel.cancelled().await;
        return Ok(());
    };
    loop {
        let (mut socket, _) = tokio::select! { biased; _ = cancel.cancelled() => return Ok(()),
        result = listener.accept() => result.map_err(|_| AgentError::Metrics)? };
        let request = async {
            let mut bytes = [0u8; 1024];
            let mut length = 0;
            while length < bytes.len() {
                let count = socket.read(&mut bytes[length..]).await?;
                if count == 0 {
                    break;
                }
                length += count;
                if bytes[..length].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let valid = bytes[..length].starts_with(b"GET /metrics HTTP/1.")
                && bytes[..length].windows(4).any(|w| w == b"\r\n\r\n");
            let body = if valid {
                metrics_text(inputs, spool, stats)
            } else {
                "not found\n".to_owned()
            };
            let status = if valid { "200 OK" } else { "404 Not Found" };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await?;
            socket.shutdown().await
        };
        tokio::select! { biased; _ = cancel.cancelled() => return Ok(()),
        _ = tokio::time::timeout(Duration::from_secs(2), request) => {} }
    }
}
fn metrics_text(inputs: &[InputReader], spool: &Spool, stats: &Counters) -> String {
    let s = spool.metrics();
    let mut text = format!(
        concat!(
            "signal_agent_spool_events {}\nsignal_agent_spool_capacity_events {}\n",
            "signal_agent_spool_bytes {}\nsignal_agent_spool_capacity_bytes {}\n",
            "signal_agent_spool_command_depth {}\nsignal_agent_spool_command_capacity {}\n",
            "signal_agent_spool_operations {}\nsignal_agent_spool_operation_capacity {}\n",
            "signal_agent_spool_index_bytes {}\nsignal_agent_spool_index_capacity_bytes {}\n",
            "signal_agent_spool_rejections_total {}\nsignal_agent_spool_failures_total {}\n",
            "signal_agent_events_accepted_total {}\nsignal_agent_rejected_lines_total {}\n",
            "signal_agent_retries_total {}\nsignal_agent_requests_total {}\n",
            "signal_agent_http_in_flight_capacity 1\nsignal_agent_metrics_connection_capacity 1\n"
        ),
        s.records,
        s.record_capacity,
        s.disk_bytes,
        s.disk_capacity,
        s.command_depth,
        s.command_capacity,
        s.operations_in_flight,
        s.operation_capacity,
        s.index_bytes,
        s.index_capacity,
        s.rejections,
        s.failures,
        stats.accepted.load(Ordering::Relaxed),
        stats.rejected.load(Ordering::Relaxed),
        stats.retries.load(Ordering::Relaxed),
        stats.requests.load(Ordering::Relaxed)
    );
    text.push_str(&format!(
        "signal_agent_dns_operations {}\nsignal_agent_dns_operation_capacity 1\nsignal_agent_dns_rejections_total {}\n",
        signal_collector_sdk::transport::dns_depth(), signal_collector_sdk::transport::dns_rejections()
    ));
    text.push_str(&stats.syslog.text());
    if let Some(node) = &stats.node {
        text.push_str(&node.text());
    }
    for (index, input) in inputs.iter().enumerate() {
        let i = input.metrics();
        for (name, value) in [
            ("command_depth", i.command_depth),
            ("command_capacity", i.command_capacity),
            ("operations", i.active_operations),
            ("operation_capacity", i.operation_capacity),
            ("buffer_bytes", i.buffered_bytes),
            ("buffer_capacity_bytes", i.buffer_capacity_bytes),
        ] {
            text.push_str(&format!(
                "signal_agent_input_{name}{{input=\"{index}\"}} {value}\n"
            ));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        input::{InputKind, InputSpec, ParseMode},
        spool::SpoolConfig,
    };
    use signal_event::{IngestEvent, Source};

    #[tokio::test]
    async fn stopping_input_preserves_in_flight_append_and_allows_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("input.log");
        std::fs::write(&path, "new durable line\nnot read after stop\n")?;
        let force = CancellationToken::new();
        let stopping = CancellationToken::new();
        let spool = Spool::open(
            SpoolConfig {
                directory: temp.path().join("spool"),
                ..Default::default()
            },
            &force,
        )
        .await?;
        let existing: IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"log"},"message":"existing"}"#,
        )?;
        spool
            .append(existing.normalize(chrono::Utc::now())?, None, &force)
            .await?;
        let stalled = spool.test_stall().await?;
        let input = InputReader::start(
            InputSpec {
                id: 0,
                kind: InputKind::File(path),
                source: Source {
                    source_type: "log".into(),
                    name: None,
                },
                mode: ParseMode::Plain,
                max_line_bytes: 65536,
                follow: true,
            },
            None,
        )?;
        let input_spool = spool.clone();
        let input_force = force.clone();
        let input_stopping = stopping.clone();
        let producer = tokio::spawn(async move {
            produce(
                &[input],
                &input_spool,
                &Counters::default(),
                &input_stopping,
                &input_force,
                65536,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while spool.metrics().operations_in_flight < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        stopping.cancel();
        assert!(!producer.is_finished());
        stalled.release().await?;
        tokio::time::timeout(Duration::from_secs(2), producer).await???;
        assert!(!spool.metrics().closed);
        let records = spool.read_batch(100, 1048576, &force).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].event.message.as_deref(),
            Some("new durable line")
        );
        let cursors = spool.cursor_snapshot(&force).await?;
        assert_eq!(cursors.len(), 1);
        assert_eq!(cursors[0].offset, "new durable line\n".len() as u64);
        spool.ack(records[1].sequence, &force).await?;
        assert_eq!(spool.metrics().records, 0);
        spool.close(&force).await?;
        Ok(())
    }
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn node_programmatic_batch_mismatch_and_expected_binding_refuse_before_spool_or_send() {
        let _serial = crate::node_input::TEST_LOCK.lock().await;
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().join("pods");
        std::fs::create_dir(&root).expect("root");
        let spool = temp.path().join("spool");
        let args = vec![
            "--format".into(),
            "kubernetes-cri".into(),
            "--node-log-root".into(),
            root.to_str().expect("root path").into(),
            "--node-name".into(),
            "node-a".into(),
            "--source-name".into(),
            "cluster".into(),
            "--spool-dir".into(),
            spool.to_str().expect("spool path").into(),
        ];
        let mut cfg = AgentConfig::parse(args.clone()).expect("config");
        cfg.batch_bytes = 4096;
        assert!(matches!(
            run(cfg, CancellationToken::new()).await,
            Err(AgentError::Spool)
        ));
        assert!(!spool.exists());
        let mut cfg = AgentConfig::parse(args).expect("config");
        let cancel = CancellationToken::new();
        let mut reader = crate::node_input::Reader::prepare(
            cfg.node.clone().expect("node"),
            Instant::now() + Duration::from_secs(2),
            &cancel,
        )
        .await
        .expect("reader");
        let CursorProfile::KubernetesNode { mut source_binding } = reader.profile() else {
            panic!("node profile")
        };
        source_binding[0] ^= 1;
        reader
            .close(Instant::now() + Duration::from_secs(2))
            .await
            .expect("close");
        cfg.spool.cursor_profile = CursorProfile::KubernetesNode { source_binding };
        assert!(matches!(
            run(cfg, CancellationToken::new()).await,
            Err(AgentError::Input)
        ));
        assert!(!spool.exists());
    }
}

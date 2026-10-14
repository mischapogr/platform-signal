//! One connection, bounded framing and durable admission; no source ACK protocol.
use crate::{
    runtime::{AgentError, Counters},
    spool::{Spool, SpoolError},
};
use sha2::{Digest, Sha256};
use signal_collector_sdk::syslog::{MAX_FRAME_BYTES, OctetDecoder, normalize_fortigate_ns};
use signal_event::Source;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpListener,
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
pub struct Config {
    pub listen: SocketAddr,
    pub tls: Option<PathBuf>,
    pub peer_sha256: Option<[u8; 32]>,
    pub source: Source,
}
#[derive(Default)]
pub(crate) struct Metrics {
    connections: AtomicUsize,
    buffered: AtomicUsize,
    pending_frames: AtomicUsize,
    refusals: AtomicU64,
}
impl Metrics {
    pub(crate) fn text(&self) -> String {
        format!(
            "signal_agent_syslog_connections {}\nsignal_agent_syslog_connection_capacity 1\nsignal_agent_syslog_buffered_bytes {}\nsignal_agent_syslog_buffer_capacity_bytes {}\nsignal_agent_syslog_refusals_total {}\nsignal_agent_syslog_pending_frames {}\nsignal_agent_syslog_frame_capacity 1\n",
            self.connections.load(Ordering::Relaxed),
            self.buffered.load(Ordering::Relaxed),
            MAX_FRAME_BYTES + 8192 + 5,
            self.refusals.load(Ordering::Relaxed),
            self.pending_frames.load(Ordering::Relaxed)
        )
    }
}
pub(crate) struct Receiver {
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    peer: Option<[u8; 32]>,
    source: Source,
}
impl Receiver {
    pub(crate) async fn prepare(
        config: &Config,
        cancel: &CancellationToken,
    ) -> Result<Self, AgentError> {
        if config.tls.is_some() != config.peer_sha256.is_some()
            || (config.tls.is_none() && !config.listen.ip().is_loopback())
            || config.source.source_type.trim().is_empty()
            || config.source.source_type.len() > 256
            || config
                .source
                .name
                .as_ref()
                .is_none_or(|n| n.trim().is_empty() || n.len() > 256)
        {
            return Err(AgentError::Input);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let tls = if let Some(path) = &config.tls {
            let config = signal_collector_sdk::transport::tls::load_server(
                path.clone(),
                deadline,
                cancel.clone(),
            )
            .await
            .map_err(|_| AgentError::Input)?;
            Some(TlsAcceptor::from(Arc::new(config)))
        } else {
            None
        };
        let listener = tokio::select! {biased; _=cancel.cancelled()=>return Err(AgentError::Input),
        r=tokio::time::timeout_at(deadline,TcpListener::bind(config.listen))=>r.map_err(|_|AgentError::Input)?.map_err(|_|AgentError::Input)?};
        Ok(Self {
            listener,
            tls,
            peer: config.peer_sha256,
            source: config.source.clone(),
        })
    }
    pub(crate) async fn run(
        &self,
        spool: &Spool,
        stats: &Counters,
        stop: &CancellationToken,
        force: &CancellationToken,
        max_event_bytes: usize,
    ) -> Result<(), AgentError> {
        loop {
            let (socket, _) = tokio::select! {biased; _=stop.cancelled()=>return Ok(()),r=self.listener.accept()=>r.map_err(|_|AgentError::Input)?};
            stats.syslog.connections.store(1, Ordering::Relaxed);
            let connection = async {
                if let Some(tls) = &self.tls {
                    let stream = tokio::time::timeout(Duration::from_secs(5), tls.accept(socket))
                        .await
                        .map_err(|_| AgentError::Input)?
                        .map_err(|_| AgentError::Input)?;
                    let leaf = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .ok_or(AgentError::Input)?;
                    let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
                    if Some(digest) != self.peer {
                        return Err(AgentError::Input);
                    }
                    self.read(stream, spool, stats, stop, force, max_event_bytes)
                        .await
                } else {
                    self.read(socket, spool, stats, stop, force, max_event_bytes)
                        .await
                }
            };
            tokio::pin!(connection);
            loop {
                tokio::select! {biased;
                    _=stop.cancelled()=>break,
                    result=&mut connection=>{if matches!(result,Err(AgentError::Spool)){stats.syslog.connections.store(0,Ordering::Relaxed);stats.syslog.buffered.store(0,Ordering::Relaxed);stats.syslog.pending_frames.store(0,Ordering::Relaxed);return result;} else if result.is_err(){stats.syslog.refusals.fetch_add(1,Ordering::Relaxed);stats.rejected.fetch_add(1,Ordering::Relaxed);}break;},
                    extra=self.listener.accept()=>{let (socket,_)=extra.map_err(|_|AgentError::Input)?;drop(socket);stats.syslog.refusals.fetch_add(1,Ordering::Relaxed);}
                }
            }
            stats.syslog.connections.store(0, Ordering::Relaxed);
            stats.syslog.buffered.store(0, Ordering::Relaxed);
            stats.syslog.pending_frames.store(0, Ordering::Relaxed);
        }
    }
    async fn read<R: AsyncRead + Unpin>(
        &self,
        mut stream: R,
        spool: &Spool,
        stats: &Counters,
        stop: &CancellationToken,
        force: &CancellationToken,
        max_event_bytes: usize,
    ) -> Result<(), AgentError> {
        let mut decoder = OctetDecoder::default();
        let mut chunk = [0; 8192];
        let mut deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() >= deadline {
                return Err(AgentError::Input);
            }
            let n = tokio::select! {biased;_=stop.cancelled()=>return Ok(()),r=tokio::time::timeout_at(deadline,stream.read(&mut chunk))=>r.map_err(|_|AgentError::Input)?.map_err(|_|AgentError::Input)?};
            if n == 0 {
                return decoder.finish().map_err(|_| AgentError::Input);
            }
            let mut offset = 0;
            while offset < n {
                let (consumed, frame) = decoder
                    .push(&chunk[offset..n])
                    .map_err(|_| AgentError::Input)?;
                offset += consumed;
                stats
                    .syslog
                    .buffered
                    .store(decoder.buffered_bytes() + n - offset, Ordering::Relaxed);
                if let Some(frame) = frame {
                    stats.syslog.pending_frames.store(1, Ordering::Relaxed);
                    stats
                        .syslog
                        .buffered
                        .store(frame.len() + n - offset, Ordering::Relaxed);
                    let event = normalize_fortigate_ns(
                        &frame,
                        self.source.clone(),
                        Uuid::new_v4(),
                        chrono::Utc::now(),
                    )
                    .map_err(|_| AgentError::Input)?;
                    let mut size = crate::runtime::SizeLimit {
                        bytes: 0,
                        limit: max_event_bytes,
                    };
                    serde_json::to_writer(&mut size, &event).map_err(|_| AgentError::Input)?;
                    loop {
                        if Instant::now() >= deadline {
                            return Err(AgentError::Input);
                        }
                        let result = tokio::select! {biased;_=stop.cancelled()=>return Ok(()),r=tokio::time::timeout_at(deadline,spool.append(event.clone(),None,force))=>r.map_err(|_|AgentError::Input)?};
                        match result {
                            Ok(_) => break,
                            Err(SpoolError::Quota | SpoolError::Full) => {
                                tokio::select! {biased;_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep_until(deadline)=>return Err(AgentError::Input),_=tokio::time::sleep(Duration::from_millis(50))=>{}}
                            }
                            Err(_) => return Err(AgentError::Spool),
                        }
                    }
                    stats.syslog.pending_frames.store(0, Ordering::Relaxed);
                    stats.syslog.buffered.store(n - offset, Ordering::Relaxed);
                    stats.changed.notify_one();
                    deadline = Instant::now() + Duration::from_secs(30);
                }
            }
        }
    }
}

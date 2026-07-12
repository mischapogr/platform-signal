//! Restricted audit transport, separate from ordinary ingest and query storage.
#[cfg(target_os = "linux")]
pub mod outbox;
#[cfg(target_os = "linux")]
pub mod receiver;
use crate::{
    ExtensionContext,
    transport::worker::{Worker, WorkerError},
};
use reqwest::{Client, Url, header};
use signal_protocol::audit::{
    ACK_BYTES, AppendError, AppendFuture, AuditMetrics, AuditSink, PreparedAudit,
};
use std::{
    future::Future,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

static OWNER: Worker = Worker::new();
static CONFIRMED: AtomicU64 = AtomicU64::new(0);
static UNCERTAIN: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
#[error("invalid restricted audit transport configuration")]
pub struct ConfigurationError;

/// No Debug or ordinary API token fallback. The caller supplies the restricted
/// destination's credential, identity and roots explicitly.
pub struct HttpAuditSink {
    client: Client,
    endpoint: Url,
    credential: header::HeaderValue,
}
impl HttpAuditSink {
    pub fn from_private_tls(
        endpoint: &str,
        credential: &str,
        connect_timeout: Duration,
        private_tls_json: &[u8],
    ) -> Result<Self, ConfigurationError> {
        let (endpoint, credential) = configuration(endpoint, credential, connect_timeout, false)?;
        let tls = crate::transport::tls::from_private_json(private_tls_json)
            .map_err(|_| ConfigurationError)?;
        Self::build(endpoint, credential, connect_timeout, Some(tls))
    }
    /// Explicit local simulation only: numeric loopback, nonzero port, HTTP.
    /// Native production configuration must use `from_private_tls`.
    pub fn for_loopback_simulation(
        endpoint: &str,
        credential: &str,
        connect_timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        let (endpoint, credential) = configuration(endpoint, credential, connect_timeout, true)?;
        Self::build(endpoint, credential, connect_timeout, None)
    }
    fn build(
        endpoint: Url,
        credential: header::HeaderValue,
        connect_timeout: Duration,
        tls: Option<rustls::ClientConfig>,
    ) -> Result<Self, ConfigurationError> {
        let client =
            crate::transport::client(connect_timeout, None, tls).map_err(|_| ConfigurationError)?;
        Ok(Self {
            client,
            endpoint,
            credential,
        })
    }
}
fn configuration(
    endpoint: &str,
    credential: &str,
    connect_timeout: Duration,
    simulation: bool,
) -> Result<(Url, header::HeaderValue), ConfigurationError> {
    if endpoint.is_empty()
        || endpoint.len() > 2048
        || credential.is_empty()
        || credential.len() > 4096
        || !credential.bytes().all(|b| b.is_ascii_graphic())
        || connect_timeout.is_zero()
        || connect_timeout > Duration::from_secs(86400)
    {
        return Err(ConfigurationError);
    }
    let mut url = Url::parse(endpoint).map_err(|_| ConfigurationError)?;
    if url.scheme() != if simulation { "http" } else { "https" }
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigurationError);
    }
    if simulation {
        let host = url.host_str().ok_or(ConfigurationError)?;
        let host = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            || url.port_or_known_default().is_none_or(|port| port == 0)
        {
            return Err(ConfigurationError);
        }
    }
    match url.path() {
        "" | "/" | "/v1/audit/records" => url.set_path("/v1/audit/records"),
        _ => return Err(ConfigurationError),
    }
    let mut value = header::HeaderValue::from_str(&format!("Bearer {credential}"))
        .map_err(|_| ConfigurationError)?;
    value.set_sensitive(true);
    Ok((url, value))
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct Attempt(bool);
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.0 {
            UNCERTAIN.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl AuditSink for HttpAuditSink {
    fn append<'a>(
        &'a self,
        record: &'a PreparedAudit,
        deadline: std::time::Instant,
    ) -> AppendFuture<'a> {
        Box::pin(async move {
            let cancel = CancellationToken::new();
            let _cancel_on_drop = CancelOnDrop(cancel.clone());
            let deadline = Instant::from_std(deadline);
            let ctx = ExtensionContext::from_deadline(cancel.clone(), deadline).map_err(|_| {
                UNCERTAIN.fetch_add(1, Ordering::Relaxed);
                AppendError::Uncertain
            })?;
            let mut attempt = Attempt(true);
            // Acquire physical capacity before retaining a body/client/header clone.
            let result = OWNER
                .run_with_factory("signal-audit-append", deadline, cancel, || {
                    let client = self.client.clone();
                    let endpoint = self.endpoint.clone();
                    let credential = self.credential.clone();
                    let body = record.body().to_vec();
                    move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|_| WorkerError::Unavailable)?;
                        runtime.block_on(async {
                            let record = PreparedAudit::from_original(&body)
                                .map_err(|_| WorkerError::Unavailable)?;
                            let work = async {
                                ctx.check().map_err(|_| WorkerError::Timeout)?;
                                let remaining =
                                    ctx.deadline().saturating_duration_since(Instant::now());
                                let mut response = client
                                    .post(endpoint)
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .header(header::ACCEPT, "application/json")
                                    .header(header::AUTHORIZATION, credential)
                                    .body(body)
                                    .timeout(remaining)
                                    .send()
                                    .await
                                    .map_err(|_| WorkerError::Unavailable)?;
                                if response.status().as_u16() != 200
                                    || response
                                        .content_length()
                                        .is_some_and(|n| n > ACK_BYTES as u64)
                                {
                                    return Err(WorkerError::Unavailable);
                                }
                                let mut reply = Vec::with_capacity(ACK_BYTES);
                                while let Some(chunk) = response
                                    .chunk()
                                    .await
                                    .map_err(|_| WorkerError::Unavailable)?
                                {
                                    ctx.check().map_err(|_| WorkerError::Timeout)?;
                                    if chunk.len() > ACK_BYTES - reply.len() {
                                        return Err(WorkerError::Unavailable);
                                    }
                                    reply.extend_from_slice(&chunk);
                                }
                                record
                                    .verify_acknowledgement(&reply)
                                    .map_err(|_| WorkerError::Unavailable)
                            };
                            before_deadline(&ctx, work).await
                        })
                    }
                })
                .await;
            if result.is_ok() && Instant::now() >= deadline {
                return Err(AppendError::Uncertain);
            }
            match result {
                Ok(()) => {
                    attempt.0 = false;
                    CONFIRMED.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(WorkerError::Busy) => {
                    attempt.0 = false;
                    Err(AppendError::Busy)
                }
                Err(_) => Err(AppendError::Uncertain),
            }
        })
    }
    fn metrics(&self) -> AuditMetrics {
        AuditMetrics {
            depth: OWNER.depth(),
            capacity: 1,
            rejected: OWNER.rejections(),
            confirmed: CONFIRMED.load(Ordering::Relaxed),
            uncertain: UNCERTAIN.load(Ordering::Relaxed),
        }
    }
}
async fn before_deadline<T>(
    ctx: &ExtensionContext,
    work: impl Future<Output = Result<T, WorkerError>>,
) -> Result<T, WorkerError> {
    tokio::pin!(work);
    let guarded = std::future::poll_fn(|cx| {
        if ctx.check().is_err() {
            std::task::Poll::Ready(Err(WorkerError::Timeout))
        } else {
            work.as_mut().poll(cx).map(|result| {
                ctx.check().map_err(|_| WorkerError::Timeout)?;
                result
            })
        }
    });
    tokio::select! { biased;
        _ = ctx.cancellation().cancelled() => Err(WorkerError::Cancelled),
        _ = tokio::time::sleep_until(ctx.deadline()) => Err(WorkerError::Timeout),
        result = guarded => result,
    }
}
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;

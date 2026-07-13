//! Separately credentialed one-operation health observation; no append or renewal.
use super::{CancelOnDrop, ConfigurationError, before_deadline, configuration_at};
use crate::{
    ExtensionContext,
    transport::worker::{Worker, WorkerError},
};
use reqwest::{Client, Url, header};
use signal_protocol::audit::{AuditReceiverHealth, HEALTH_BYTES};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::time::Instant;

static OWNER: Worker = Worker::new();
static OBSERVED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum ProbeError {
    #[error("audit health probe capacity is occupied")]
    Busy,
    #[error("current authenticated audit health is unavailable")]
    Unavailable,
}
#[derive(Clone, Copy, Debug)]
pub struct ProbeMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub rejected: u64,
    pub observed: u64,
    pub failed: u64,
}
/// No serialized time or implied validity period. An authenticated held snapshot
/// is a current failure observation. The owner never renews health from a failed
/// probe, old result, quiet source, original ACK or absent telemetry.
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub snapshot: AuditReceiverHealth,
    pub received_at: Instant,
}
pub struct HttpHealthProbe {
    client: Client,
    endpoint: Url,
    credential: header::HeaderValue,
}
impl HttpHealthProbe {
    pub fn from_private_tls(
        endpoint: &str,
        credential: &str,
        connect_timeout: Duration,
        material: &[u8],
    ) -> Result<Self, ConfigurationError> {
        let (endpoint, credential) = configuration_at(
            endpoint,
            credential,
            connect_timeout,
            false,
            "/v1/audit/health",
        )?;
        let tls =
            crate::transport::tls::from_private_json(material).map_err(|_| ConfigurationError)?;
        Self::build(endpoint, credential, connect_timeout, Some(tls))
    }
    /// Explicit synthetic numeric-loopback HTTP only; no production fallback.
    pub fn for_loopback_simulation(
        endpoint: &str,
        credential: &str,
        connect_timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        let (endpoint, credential) = configuration_at(
            endpoint,
            credential,
            connect_timeout,
            true,
            "/v1/audit/health",
        )?;
        Self::build(endpoint, credential, connect_timeout, None)
    }
    fn build(
        endpoint: Url,
        credential: header::HeaderValue,
        connect_timeout: Duration,
        tls: Option<rustls::ClientConfig>,
    ) -> Result<Self, ConfigurationError> {
        Ok(Self {
            client: crate::transport::client(connect_timeout, None, tls)
                .map_err(|_| ConfigurationError)?,
            endpoint,
            credential,
        })
    }
    pub fn metrics(&self) -> ProbeMetrics {
        ProbeMetrics {
            depth: OWNER.depth(),
            capacity: 1,
            rejected: OWNER.rejections(),
            observed: OBSERVED.load(Ordering::Relaxed),
            failed: FAILED.load(Ordering::Relaxed),
        }
    }
    pub async fn observe(&self, context: ExtensionContext) -> Result<Observation, ProbeError> {
        let cancel = context.cancellation().child_token();
        let _guard = CancelOnDrop(cancel.clone());
        let mut attempt = Attempt(true);
        let work = ExtensionContext::from_deadline(cancel.clone(), context.deadline())
            .map_err(|_| ProbeError::Unavailable)?;
        let result = OWNER
            .run_with_factory("signal-audit-health", context.deadline(), cancel, || {
                let client = self.client.clone();
                let endpoint = self.endpoint.clone();
                let credential = self.credential.clone();
                move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| WorkerError::Unavailable)?;
                    runtime.block_on(before_deadline(&work, async {
                        work.check().map_err(|_| WorkerError::Timeout)?;
                        let remaining = work.deadline().saturating_duration_since(Instant::now());
                        let mut response = client
                            .get(endpoint)
                            .header(header::AUTHORIZATION, credential)
                            .header(header::ACCEPT, "application/json")
                            .header(header::CACHE_CONTROL, "no-store")
                            .header(header::PRAGMA, "no-cache")
                            .timeout(remaining)
                            .send()
                            .await
                            .map_err(|_| WorkerError::Unavailable)?;
                        let status = response.status().as_u16();
                        let mut content_type =
                            response.headers().get_all(header::CONTENT_TYPE).iter();
                        let mut cache = response.headers().get_all(header::CACHE_CONTROL).iter();
                        if !matches!(status, 200 | 503)
                            || content_type
                                .next()
                                .is_none_or(|value| value.as_bytes() != b"application/json")
                            || content_type.next().is_some()
                            || cache
                                .next()
                                .is_none_or(|value| value.as_bytes() != b"no-store")
                            || cache.next().is_some()
                            || response
                                .content_length()
                                .is_some_and(|length| length > HEALTH_BYTES as u64)
                        {
                            return Err(WorkerError::Unavailable);
                        }
                        let mut body = Vec::with_capacity(HEALTH_BYTES);
                        while let Some(chunk) = response
                            .chunk()
                            .await
                            .map_err(|_| WorkerError::Unavailable)?
                        {
                            work.check().map_err(|_| WorkerError::Timeout)?;
                            if chunk.len() > HEALTH_BYTES - body.len() {
                                return Err(WorkerError::Unavailable);
                            }
                            body.extend_from_slice(&chunk);
                        }
                        let snapshot = AuditReceiverHealth::from_json(&body)
                            .map_err(|_| WorkerError::Unavailable)?;
                        if (status == 503) != snapshot.held {
                            return Err(WorkerError::Unavailable);
                        }
                        Ok(Observation {
                            snapshot,
                            received_at: Instant::now(),
                        })
                    }))
                }
            })
            .await;
        match result {
            Ok(observation) if context.check().is_ok() => {
                attempt.0 = false;
                OBSERVED.fetch_add(1, Ordering::Relaxed);
                Ok(observation)
            }
            Err(WorkerError::Busy) => {
                attempt.0 = false;
                Err(ProbeError::Busy)
            }
            _ => Err(ProbeError::Unavailable),
        }
    }
}
struct Attempt(bool);
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.0 {
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[cfg(test)]
mod tests;

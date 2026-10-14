//! Fresh authenticated object custody; no source ACK, automatic deletion or M3 proof.
use crate::{
    ExtensionContext,
    transport::{
        self,
        worker::{Worker, WorkerError},
    },
};
use reqwest::{Url, header};
use signal_protocol::object_custody::{
    CONFIRM_PATH, ConfirmRequest, Confirmation, Description, WIRE_BYTES,
};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
static HTTP: Worker = Worker::new();
static REJECTED: AtomicU64 = AtomicU64::new(0);
static CONFIRMED: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CustodyError {
    #[error("invalid custody client configuration or description")]
    Invalid,
    #[error("custody physical worker is full")]
    Full,
    #[error("custody confirmation cancelled")]
    Cancelled,
    #[error("custody confirmation deadline expired")]
    Timeout,
    #[error("custody confirmation refused or uncertain; retain original")]
    Unavailable,
}
impl From<WorkerError> for CustodyError {
    fn from(e: WorkerError) -> Self {
        match e {
            WorkerError::Busy => Self::Full,
            WorkerError::Timeout => Self::Timeout,
            WorkerError::Cancelled => Self::Cancelled,
            WorkerError::Configuration => Self::Invalid,
            _ => Self::Unavailable,
        }
    }
}
#[derive(Clone)]
struct Config {
    endpoint: Url,
    token: header::HeaderValue,
    connect_timeout: Duration,
    tls: Option<rustls::ClientConfig>,
}
/// One process-wide physical HTTP seat; no proxy, redirect or retry. Credentials
/// and trust are host supplied and are never Debug or serialized.
pub struct ObjectCustodyClient {
    config: Config,
}
pub struct CustodyClientMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub confirmed: u64,
    pub rejected: u64,
}
impl ObjectCustodyClient {
    pub fn new(
        endpoint: &str,
        token: &str,
        connect_timeout: Duration,
        tls: Option<rustls::ClientConfig>,
        allow_loopback_http: bool,
    ) -> Result<Self, CustodyError> {
        let url = Url::parse(endpoint).map_err(|_| CustodyError::Invalid)?;
        let loopback = url
            .host_str()
            .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if endpoint.len() > 2048
            || url.path() != CONFIRM_PATH
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !(url.scheme() == "https"
                || (url.scheme() == "http" && allow_loopback_http && loopback && tls.is_none()))
            || token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|b| b.is_ascii_graphic())
            || connect_timeout.is_zero()
            || connect_timeout > Duration::from_secs(5)
        {
            return Err(CustodyError::Invalid);
        }
        let mut token = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CustodyError::Invalid)?;
        token.set_sensitive(true);
        Ok(Self {
            config: Config {
                endpoint: url,
                token,
                connect_timeout,
                tls,
            },
        })
    }
    pub fn metrics(&self) -> CustodyClientMetrics {
        CustodyClientMetrics {
            depth: HTTP.depth(),
            capacity: 1,
            confirmed: CONFIRMED.load(Ordering::Relaxed),
            rejected: REJECTED.load(Ordering::Relaxed),
        }
    }
    pub async fn confirm(
        &self,
        description: &Description,
        context: &ExtensionContext,
    ) -> Result<FreshCustodyPermit, CustodyError> {
        let mut attempt = Attempt(false);
        description.validate().map_err(|_| CustodyError::Invalid)?;
        if description.retain_until <= chrono::Utc::now() {
            return Err(CustodyError::Invalid);
        }
        let started = Instant::now();
        let deadline = context.deadline().min(started + Duration::from_secs(5));
        let cancellation = context.cancellation().child_token();
        let nonce = Uuid::new_v4();
        let reply=HTTP.run_with_factory("signal-custody-http",deadline,cancellation.clone(),||{
            let config=self.config.clone();let request=ConfirmRequest{schema_version:1,request_nonce:nonce,description:description.clone()};let cancellation=cancellation.clone();
            move || {
                let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|WorkerError::Unavailable)?;
                runtime.block_on(async move {
                    let operation=async {
                        let body=serde_json::to_vec(&request).map_err(|_|CustodyError::Invalid)?;if body.len()>WIRE_BYTES{return Err(CustodyError::Invalid);}
                        let client=transport::client(config.connect_timeout,None,config.tls).map_err(CustodyError::from)?;
                        let mut response=client.post(config.endpoint).header(header::AUTHORIZATION,config.token).header(header::CONTENT_TYPE,"application/json").body(body).send().await.map_err(|_|CustodyError::Unavailable)?;
                        if response.status()!=reqwest::StatusCode::OK || response.content_length().is_some_and(|n|n>WIRE_BYTES as u64){return Err(CustodyError::Unavailable);}
                        let mut bytes=Vec::new();while let Some(chunk)=response.chunk().await.map_err(|_|CustodyError::Unavailable)? {if chunk.len()>WIRE_BYTES.saturating_sub(bytes.len()){return Err(CustodyError::Unavailable);}bytes.extend_from_slice(&chunk);}
                        let confirmation:Confirmation=serde_json::from_slice(&bytes).map_err(|_|CustodyError::Unavailable)?;
                        confirmation.validate_for(&request).map_err(|_|CustodyError::Unavailable)?;Ok(confirmation)
                    };
                    Ok(tokio::select!{biased; _=cancellation.cancelled()=>Err(CustodyError::Cancelled),r=tokio::time::timeout_at(deadline,operation)=>r.unwrap_or(Err(CustodyError::Timeout))})
                })
            }
        }).await.map_err(CustodyError::from)??;
        // Anchor elapsed + remaining server budget to our earlier request start.
        // Neither response arrival nor a different wall clock restarts a lease.
        let permit_deadline = deadline.min(
            started
                + Duration::from_millis(
                    u64::from(reply.server_elapsed_ms) + u64::from(reply.valid_for_ms),
                ),
        );
        let permit = FreshCustodyPermit {
            confirmation: reply,
            deadline: permit_deadline,
            cancellation,
        };
        permit.checked_confirmation()?;
        attempt.0 = true;
        CONFIRMED.fetch_add(1, Ordering::Relaxed);
        Ok(permit)
    }
}
struct Attempt(bool);
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.0 {
            REJECTED.fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// Non-cloneable/non-deserializable, valid only in the original fresh request
/// context. A restart must confirm the original immutable description/ID again.
pub struct FreshCustodyPermit {
    confirmation: Confirmation,
    deadline: Instant,
    cancellation: CancellationToken,
}
impl FreshCustodyPermit {
    pub fn checked_confirmation(&self) -> Result<&Confirmation, CustodyError> {
        if self.cancellation.is_cancelled() {
            return Err(CustodyError::Cancelled);
        }
        if Instant::now() >= self.deadline
            || self.confirmation.description.retain_until <= chrono::Utc::now()
            || self.confirmation.valid_until <= chrono::Utc::now()
        {
            return Err(CustodyError::Timeout);
        }
        Ok(&self.confirmation)
    }
}
#[cfg(test)]
#[path = "object_custody_tests.rs"]
mod tests;

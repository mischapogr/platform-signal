//! Bounded selected Cato security eventsFeed transport. Private policy owns
//! credentials, initial-marker authority, durable custody and coverage checks.
use crate::ExtensionContext;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Url;
use std::time::Duration;
use thiserror::Error;
pub mod page;
pub const FEED: &str = "Security";
pub const MAX_MARKER_BYTES: usize = 4096;
pub const QUERY: &str = "query SignalSecurity($accountIDs: [ID!], $marker: String) { eventsFeed(accountIDs: $accountIDs, marker: $marker, filters: [{fieldName: event_type, operator: is, values: [\"Security\"]}]) { marker fetchedCount accounts { id errorString records { time fieldsMap } } } }";
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_URL_BYTES: usize = 4096;
pub const MAX_ATTEMPTS: usize = 5;
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid Cato eventsFeed route configuration")]
    Configuration,
    #[error("Cato eventsFeed request admission is busy")]
    Busy,
    #[error("Cato eventsFeed origin/tenant/feed scope mismatch")]
    Scope,
    #[error("Cato eventsFeed response/URI limit")]
    Limit,
    #[error("Cato eventsFeed request cancelled")]
    Cancelled,
    #[error("Cato eventsFeed original deadline expired")]
    Timeout,
    #[error("Cato eventsFeed authentication refused")]
    Authentication,
    #[error("Cato eventsFeed provider unavailable or retries exhausted")]
    Unavailable,
    #[error("Cato eventsFeed source content expired; coverage gap")]
    Expired,
    #[error("invalid Cato eventsFeed provider response")]
    Response,
    #[error("Cato eventsFeed conflicting identity, cursor or journal revision")]
    Conflict,
    #[error("Cato eventsFeed atomic journal failed; reload durable state")]
    Journal,
}
/// Opaque private API key; intentionally no Debug or serialization.
pub struct ApiKey(String);
impl ApiKey {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty() || value.len() > 4096 || value.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(Error::Authentication);
        }
        Ok(Self(value))
    }
}
/// Trusted application-owned API key retrieval implementation. The
/// adapter wraps each invocation in the same original deadline/cancellation;
/// implementations must retain physical work ownership after front cancellation.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn key(&self, context: &ExtensionContext) -> Result<ApiKey, Error>;
}
fn check(context: &ExtensionContext) -> Result<(), Error> {
    if context.cancellation().is_cancelled() {
        return Err(Error::Cancelled);
    }
    if tokio::time::Instant::now() >= context.deadline() {
        return Err(Error::Timeout);
    }
    Ok(())
}
async fn within<T>(
    context: &ExtensionContext,
    work: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    check(context)?;
    let result = tokio::select! {biased;_=context.cancellation().cancelled()=>Err(Error::Cancelled),
    r=tokio::time::timeout_at(context.deadline(),work)=>r.map_err(|_|Error::Timeout)?};
    check(context)?;
    result
}
/// Explicit latest bootstrap cannot promise historical coverage. A resumed
/// marker is bound to its last durable receipt time; never reset after expiry.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", deny_unknown_fields)]
pub enum Position {
    Latest,
    Resume {
        marker: String,
        committed_at: DateTime<Utc>,
    },
}
impl Position {
    fn validate_shape(&self) -> Result<(), Error> {
        if let Self::Resume {
            marker,
            committed_at,
        } = self
        {
            use chrono::Datelike;
            if marker.is_empty()
                || marker.len() > MAX_MARKER_BYTES
                || marker.chars().any(char::is_control)
                || !(1..=9999).contains(&committed_at.year())
            {
                return Err(Error::Scope);
            }
        }
        Ok(())
    }
    fn marker(&self) -> Result<Option<&str>, Error> {
        self.validate_shape()?;
        match self {
            Self::Latest => Ok(None),
            Self::Resume {
                marker,
                committed_at,
            } => {
                let age = Utc::now().signed_duration_since(*committed_at);
                if age < chrono::Duration::zero() || age >= chrono::Duration::days(3) {
                    return Err(Error::Expired);
                }
                Ok(Some(marker))
            }
        }
    }
}
/// Complete finite entity bytes, no durable receipt or checkpoint grant.
pub struct CapturedResponse {
    pub original_bytes: Vec<u8>,
}
pub struct EventsClient {
    http: reqwest::Client,
    endpoint: Url,
    account: String,
    admission: tokio::sync::Semaphore,
    failures: std::sync::atomic::AtomicU64,
}
impl EventsClient {
    /// Selected public endpoint with caller-owned TLS trust and one account.
    pub fn new(account: String, tls: rustls::ClientConfig) -> Result<Self, Error> {
        Self::configured("https://api.catonetworks.com", account, Some(tls), false)
    }
    /// Synthetic provider only: literal loopback HTTP, no redirects or proxy.
    pub fn local_fixture(origin: &str, account: String) -> Result<Self, Error> {
        Self::configured(origin, account, None, true)
    }
    fn configured(
        origin: &str,
        account: String,
        tls: Option<rustls::ClientConfig>,
        fixture: bool,
    ) -> Result<Self, Error> {
        if account.is_empty()
            || account.len() > 20
            || !account.bytes().all(|b| b.is_ascii_digit())
            || account.starts_with('0')
            || origin.len() > MAX_URL_BYTES
        {
            return Err(Error::Configuration);
        }
        let mut endpoint = Url::parse(origin).map_err(|_| Error::Configuration)?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(Error::Configuration);
        }
        if fixture {
            if endpoint.scheme() != "http"
                || !endpoint
                    .host_str()
                    .and_then(|h| h.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
            {
                return Err(Error::Configuration);
            }
        } else if endpoint.scheme() != "https"
            || endpoint.host_str() != Some("api.catonetworks.com")
            || endpoint.port().is_some()
        {
            return Err(Error::Configuration);
        }
        endpoint.set_path("/api/v1/graphql2");
        let http = crate::transport::client(Duration::from_secs(5), None, tls)
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            http,
            endpoint,
            account,
            admission: tokio::sync::Semaphore::new(1),
            failures: std::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }
    /// Active request depth/capacity and counted failures, including abandoned
    /// capture futures. Admission rejects immediately rather than queuing.
    pub fn metrics(&self) -> (usize, usize, u64) {
        (
            1 - self.admission.available_permits(),
            1,
            self.failures.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
    pub async fn capture(
        &self,
        position: &Position,
        keys: &impl KeyProvider,
        context: &ExtensionContext,
    ) -> Result<CapturedResponse, Error> {
        struct Outcome<'a> {
            counter: &'a std::sync::atomic::AtomicU64,
            success: bool,
        }
        impl Drop for Outcome<'_> {
            fn drop(&mut self) {
                if !self.success {
                    self.counter
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        let mut outcome = Outcome {
            counter: &self.failures,
            success: false,
        };
        let _lease = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        let result = self.capture_inner(position, keys, context).await;
        outcome.success = result.is_ok();
        result
    }
    async fn capture_inner(
        &self,
        position: &Position,
        keys: &impl KeyProvider,
        context: &ExtensionContext,
    ) -> Result<CapturedResponse, Error> {
        // Marker validation precedes private key acquisition and every retry.
        position.marker()?;
        let key = within(context, keys.key(context)).await?;
        for attempt in 0..MAX_ATTEMPTS {
            check(context)?;
            let marker = position.marker()?;
            let request = serde_json::json!({"query": QUERY, "variables": {"accountIDs": [&self.account], "marker": marker}});
            let reply = within(context, async {
                self.http
                    .post(self.endpoint.clone())
                    .header("x-api-key", &key.0)
                    .json(&request)
                    .send()
                    .await
                    .map_err(|_| Error::Unavailable)
            })
            .await;
            let mut reply = match reply {
                Ok(r) => r,
                Err(Error::Unavailable) if attempt + 1 < MAX_ATTEMPTS => {
                    self.pause(context, Duration::from_millis(50)).await?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let status = reply.status().as_u16();
            if status == 401 || status == 403 {
                return Err(Error::Authentication);
            }
            if status == 404 || status == 410 {
                return Err(Error::Expired);
            }
            if status == 429 || (500..=599).contains(&status) {
                if attempt + 1 == MAX_ATTEMPTS {
                    return Err(Error::Unavailable);
                }
                let delay = match reply.headers().get("Retry-After") {
                    Some(v) => Duration::from_secs(
                        v.to_str()
                            .ok()
                            .and_then(|v| v.parse::<u64>().ok())
                            .filter(|s| *s <= 60)
                            .ok_or(Error::Response)?,
                    ),
                    None => Duration::from_millis(50),
                };
                drop(reply);
                self.pause(context, delay).await?;
                continue;
            }
            if status != 200 {
                return Err(Error::Response);
            }
            if reply
                .content_length()
                .is_some_and(|n| n > MAX_BODY_BYTES as u64)
            {
                return Err(Error::Limit);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = within(context, async {
                reply.chunk().await.map_err(|_| Error::Unavailable)
            })
            .await?
            {
                if chunk.len() > MAX_BODY_BYTES - bytes.len() {
                    return Err(Error::Limit);
                }
                bytes.extend_from_slice(&chunk);
            }
            check(context)?;
            return Ok(CapturedResponse {
                original_bytes: bytes,
            });
        }
        Err(Error::Unavailable)
    }
    async fn pause(&self, context: &ExtensionContext, delay: Duration) -> Result<(), Error> {
        within(context, async {
            tokio::time::sleep(delay).await;
            Ok(())
        })
        .await
    }
}

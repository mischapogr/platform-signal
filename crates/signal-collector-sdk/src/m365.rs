//! Bounded selected Management Activity API transport. Private policy owns
//! subscriptions, tenant permissions, credentials and durable receipt/checkpoint.
use crate::ExtensionContext;
use async_trait::async_trait;
use reqwest::Url;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;
pub mod page;
pub const FEED: &str = "Audit.AzureActiveDirectory";
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_URL_BYTES: usize = 4096;
pub const MAX_ATTEMPTS: usize = 5;
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid management activity route configuration")]
    Configuration,
    #[error("management activity request admission is busy")]
    Busy,
    #[error("management activity origin/tenant/feed scope mismatch")]
    Scope,
    #[error("management activity response/URI limit")]
    Limit,
    #[error("management activity request cancelled")]
    Cancelled,
    #[error("management activity original deadline expired")]
    Timeout,
    #[error("management activity authentication refused")]
    Authentication,
    #[error("management activity provider unavailable or retries exhausted")]
    Unavailable,
    #[error("management activity source content expired; coverage gap")]
    Expired,
    #[error("invalid management activity provider response")]
    Response,
    #[error("management activity conflicting identity, cursor or journal revision")]
    Conflict,
    #[error("management activity atomic journal failed; reload durable state")]
    Journal,
}
/// Opaque private access token; intentionally no Debug or serialization.
pub struct AccessToken(String);
impl AccessToken {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty() || value.len() > 4096 || value.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(Error::Authentication);
        }
        Ok(Self(value))
    }
}
/// Trusted application-owned OAuth credentials/refresh implementation. The
/// adapter wraps each invocation in the same original deadline/cancellation;
/// implementations must retain physical work ownership after front cancellation.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn token(&self, refresh: bool, context: &ExtensionContext) -> Result<AccessToken, Error>;
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
/// Full finite response capture, no cursor/coverage/ACK grant.
pub struct CapturedResponse {
    pub original_bytes: Vec<u8>,
    pub next_page_uri: Option<String>,
}
pub struct ActivityClient {
    http: reqwest::Client,
    root: Url,
    tenant: Uuid,
    admission: tokio::sync::Semaphore,
    failures: std::sync::atomic::AtomicU64,
}
impl ActivityClient {
    /// Public cloud selected endpoint with explicit caller-owned TLS trust.
    /// Government endpoints require a separately selected profile.
    pub fn new(tenant: Uuid, tls: rustls::ClientConfig) -> Result<Self, Error> {
        Self::configured("https://manage.office.com", tenant, Some(tls), false)
    }
    /// Explicit local provider simulation, literal loopback HTTP only. No ambient
    /// cloud credentials or proxy/redirect destination is accepted.
    pub fn local_fixture(origin: &str, tenant: Uuid) -> Result<Self, Error> {
        Self::configured(origin, tenant, None, true)
    }
    fn configured(
        origin: &str,
        tenant: Uuid,
        tls: Option<rustls::ClientConfig>,
        fixture: bool,
    ) -> Result<Self, Error> {
        if tenant.is_nil() || origin.len() > MAX_URL_BYTES {
            return Err(Error::Configuration);
        }
        let mut root = Url::parse(origin).map_err(|_| Error::Configuration)?;
        if !root.username().is_empty()
            || root.password().is_some()
            || root.query().is_some()
            || root.fragment().is_some()
            || root.path() != "/"
        {
            return Err(Error::Configuration);
        }
        if fixture {
            if root.scheme() != "http"
                || !root
                    .host_str()
                    .and_then(|h| h.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
            {
                return Err(Error::Configuration);
            }
        } else if root.scheme() != "https"
            || root.host_str() != Some("manage.office.com")
            || root.port().is_some()
        {
            return Err(Error::Configuration);
        }
        root.set_path(&format!("/api/v1.0/{tenant}/activity/feed/"));
        let http = crate::transport::client(Duration::from_secs(5), None, tls)
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            http,
            root,
            tenant,
            admission: tokio::sync::Semaphore::new(1),
            failures: std::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn tenant(&self) -> Uuid {
        self.tenant
    }
    pub fn root(&self) -> &str {
        self.root.as_str()
    }
    /// URL validation precedes token acquisition and forwarding. Exact configured
    /// origin, tenant path, list feed and operation whitelist are mandatory.
    pub fn validate_uri(&self, value: &str) -> Result<Url, Error> {
        if value.len() > MAX_URL_BYTES {
            return Err(Error::Limit);
        }
        let url = Url::parse(value).map_err(|_| Error::Scope)?;
        if url.origin() != self.root.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || value.contains('\\')
            || value
                .split('?')
                .next()
                .is_some_and(|path| path.contains('%'))
        {
            return Err(Error::Scope);
        }
        let alias = format!("/api/v1/{}/activity/feed/", self.tenant);
        let (tail, is_alias) = if let Some(tail) = url.path().strip_prefix(self.root.path()) {
            (tail, false)
        } else if let Some(tail) = url.path().strip_prefix(&alias) {
            (tail, true)
        } else {
            return Err(Error::Scope);
        };
        if is_alias && tail != "subscriptions/content" {
            return Err(Error::Scope);
        }
        if tail == "subscriptions/content" {
            let mut feed = None;
            for (key, value) in url.query_pairs() {
                if key == "contentType" {
                    if feed.is_some() {
                        return Err(Error::Scope);
                    }
                    feed = Some(value.into_owned());
                }
            }
            if feed.as_deref() != Some(FEED) {
                return Err(Error::Scope);
            }
        } else if !tail
            .strip_prefix("audit/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/'))
        {
            return Err(Error::Scope);
        }
        Ok(url)
    }
    pub(super) fn is_listing_uri(&self, url: &Url) -> bool {
        url.path() == format!("{}subscriptions/content", self.root.path())
            || url.path()
                == format!(
                    "/api/v1/{}/activity/feed/subscriptions/content",
                    self.tenant
                )
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
        uri: &str,
        tokens: &impl TokenProvider,
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
        let result = self.capture_inner(uri, tokens, context).await;
        outcome.success = result.is_ok();
        result
    }
    async fn capture_inner(
        &self,
        uri: &str,
        tokens: &impl TokenProvider,
        context: &ExtensionContext,
    ) -> Result<CapturedResponse, Error> {
        let url = self.validate_uri(uri)?;
        let mut token = within(context, tokens.token(false, context)).await?;
        let mut refreshed = false;
        for attempt in 0..MAX_ATTEMPTS {
            check(context)?;
            let reply = within(context, async {
                self.http
                    .get(url.clone())
                    .bearer_auth(&token.0)
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
            if status == 401 {
                if refreshed || attempt + 1 == MAX_ATTEMPTS {
                    return Err(Error::Authentication);
                }
                drop(reply);
                token = within(context, tokens.token(true, context)).await?;
                refreshed = true;
                continue;
            }
            if status == 403 {
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
            let mut next = reply.headers().get_all("NextPageUri").iter();
            let first = next.next();
            if next.next().is_some() {
                return Err(Error::Response);
            }
            if first.is_some_and(|v| v.as_bytes().len() > MAX_URL_BYTES) {
                return Err(Error::Limit);
            }
            let next_page_uri = first
                .map(|v| v.to_str().map(str::to_owned).map_err(|_| Error::Response))
                .transpose()?;
            if let Some(next) = &next_page_uri {
                self.validate_uri(next)?;
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
                next_page_uri,
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

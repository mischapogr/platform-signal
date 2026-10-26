//! Scoped metadata transport. The host owns trust configuration and tokens;
//! response content never selects a destination, source identity or timeout.
use super::{Kind, Profile, Reconciler, Snapshot};
use crate::ExtensionContext;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::{Response, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid Kubernetes API origin, trust or route configuration")]
    Configuration,
    #[error("Kubernetes API request cancelled")]
    Cancelled,
    #[error("Kubernetes API original deadline expired")]
    Timeout,
    #[error("Kubernetes API credentials or permissions refused")]
    Permission,
    #[error("Kubernetes API history expired; full relist required")]
    Expired,
    #[error("Kubernetes API transport or response failed")]
    Response,
    #[error("Kubernetes API response/stream limit exceeded")]
    Limit,
    #[error("Kubernetes API watch closed; full relist required")]
    Closed,
    #[error(transparent)]
    Reconcile(#[from] super::Error),
}
/// Opaque, nonserialized Bearer credential. Never include it in diagnostics.
pub struct AccessToken(String);
impl AccessToken {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty() || value.len() > 4096 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Permission);
        }
        Ok(Self(value))
    }
}
/// The host retains physical work after cancellation where applicable. There is
/// no ambient token source, implicit refresh, credential cache or retry here.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn token(&self, context: &ExtensionContext) -> Result<AccessToken, Error>;
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
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    check(context)?;
    let result = tokio::select! {biased;_=context.cancellation().cancelled()=>Err(Error::Cancelled),
    result=tokio::time::timeout_at(context.deadline(),work)=>result.map_err(|_|Error::Timeout)?};
    check(context)?;
    result
}
fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn dns_node(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(dns_label)
}
fn resource(kind: Kind) -> &'static str {
    match kind {
        Kind::Pod => "pods",
        Kind::Node => "nodes",
        Kind::Namespace => "namespaces",
        Kind::Role => "roles",
        Kind::ClusterRole => "clusterroles",
        Kind::RoleBinding => "rolebindings",
        Kind::ClusterRoleBinding => "clusterrolebindings",
    }
}
fn url(
    base: &Url,
    profile: &Profile,
    continuation: Option<&str>,
    watch_revision: Option<&str>,
) -> Result<Url, Error> {
    let mut url = base.clone();
    let prefix = if matches!(profile.kind, Kind::Pod | Kind::Node | Kind::Namespace) {
        "/api/v1"
    } else {
        "/apis/rbac.authorization.k8s.io/v1"
    };
    let path = match &profile.namespace {
        Some(namespace) => format!("{prefix}/namespaces/{namespace}/{}", resource(profile.kind)),
        None => format!("{prefix}/{}", resource(profile.kind)),
    };
    url.set_path(&path);
    {
        let mut query = url.query_pairs_mut();
        if let Some(node) = &profile.node {
            query.append_pair("fieldSelector", &format!("spec.nodeName={node}"));
        }
        if let Some(revision) = watch_revision {
            query
                .append_pair("watch", "true")
                .append_pair("allowWatchBookmarks", "true")
                .append_pair("resourceVersion", revision);
        } else {
            query.append_pair("limit", &profile.limits.max_objects.min(128).to_string());
            if let Some(token) = continuation {
                query.append_pair("continue", token);
            }
        }
    }
    if url.as_str().len() > 4096 {
        return Err(Error::Limit);
    }
    Ok(url)
}
async fn send(
    http: &reqwest::Client,
    url: Url,
    tokens: &impl TokenProvider,
    context: &ExtensionContext,
) -> Result<Response, Error> {
    let token = within(context, tokens.token(context)).await?;
    let response = within(context, async {
        http.get(url)
            .bearer_auth(&token.0)
            .send()
            .await
            .map_err(|_| Error::Response)
    })
    .await?;
    match response.status().as_u16() {
        200 => {}
        401 | 403 => return Err(Error::Permission),
        410 => return Err(Error::Expired),
        _ => return Err(Error::Response),
    }
    if response
        .headers()
        .contains_key(reqwest::header::CONTENT_ENCODING)
    {
        return Err(Error::Response);
    }
    Ok(response)
}
#[derive(Default)]
struct Counters {
    active: AtomicUsize,
    invalidated: AtomicU64,
}
#[derive(Clone)]
pub struct Metrics(Arc<Counters>);
#[derive(Clone, Copy, Serialize, Debug)]
pub struct MetricSnapshot {
    pub active: usize,
    pub capacity: usize,
    pub invalidated_operations: u64,
}
impl Metrics {
    pub fn snapshot(&self) -> MetricSnapshot {
        MetricSnapshot {
            active: self.0.active.load(Ordering::Relaxed),
            capacity: 1,
            invalidated_operations: self.0.invalidated.load(Ordering::Relaxed),
        }
    }
}
struct Operation<'a> {
    state: &'a mut Reconciler,
    counters: &'a Counters,
    complete: bool,
}
impl<'a> Operation<'a> {
    fn new(state: &'a mut Reconciler, counters: &'a Counters) -> Self {
        counters.active.store(1, Ordering::Relaxed);
        Self {
            state,
            counters,
            complete: false,
        }
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.state.invalidate();
            self.counters.invalidated.fetch_add(1, Ordering::Relaxed);
        }
        self.counters.active.store(0, Ordering::Relaxed);
    }
}
#[derive(Serialize)]
pub struct BoundSnapshot<'a> {
    pub schema_version: u16,
    pub source_binding: &'a str,
    pub collection: Snapshot<'a>,
}
/// One mutable owner serializes requests and owns its state. It has no import or
/// endpoint/trust mutation API, and never accepts native continuation URLs.
pub struct Collector {
    http: reqwest::Client,
    base: Url,
    profile: Profile,
    state: Reconciler,
    binding: String,
    counters: Arc<Counters>,
}
impl Collector {
    /// TLS settings and matching trust revision belong to the trusted caller;
    /// the digest identifies configuration, not proof of an opaque TLS config.
    pub fn new(
        origin: &str,
        profile: Profile,
        tls: rustls::ClientConfig,
        trust_revision: [u8; 32],
    ) -> Result<Self, Error> {
        Self::configured(origin, profile, Some(tls), trust_revision, false)
    }
    /// Explicit literal-loopback HTTP simulation only; no ambient credentials.
    pub fn local_fixture(origin: &str, profile: Profile) -> Result<Self, Error> {
        Self::configured(origin, profile, None, [0; 32], true)
    }
    fn configured(
        origin: &str,
        profile: Profile,
        tls: Option<rustls::ClientConfig>,
        trust_revision: [u8; 32],
        fixture: bool,
    ) -> Result<Self, Error> {
        if origin.len() > 2048
            || origin.contains('\\')
            || profile.namespace.as_ref().is_some_and(|s| !dns_label(s))
            || profile.node.as_ref().is_some_and(|s| !dns_node(s))
        {
            return Err(Error::Configuration);
        }
        let base = Url::parse(origin).map_err(|_| Error::Configuration)?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
            || base.host_str().is_none()
        {
            return Err(Error::Configuration);
        }
        if fixture {
            if base.scheme() != "http"
                || !base
                    .host_str()
                    .and_then(|h| h.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
            {
                return Err(Error::Configuration);
            }
        } else if base.scheme() != "https" {
            return Err(Error::Configuration);
        }
        url(&base, &profile, None, None)?;
        let http = crate::transport::client(Duration::from_secs(3), None, tls)
            .map_err(|_| Error::Configuration)?;
        let mut hash = Sha256::new();
        hash.update(b"platform-signal/kubernetes-context-api/v1\0");
        for part in [
            base.as_str().as_bytes(),
            &trust_revision,
            profile.binding().as_bytes(),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        let binding = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            http,
            base,
            state: Reconciler::new(profile.clone()),
            profile,
            binding,
            counters: Arc::new(Counters::default()),
        })
    }
    pub fn source_binding(&self) -> &str {
        &self.binding
    }
    pub fn metrics(&self) -> Metrics {
        Metrics(self.counters.clone())
    }
    pub fn snapshot(&mut self) -> BoundSnapshot<'_> {
        BoundSnapshot {
            schema_version: 1,
            source_binding: &self.binding,
            collection: self.state.snapshot(Utc::now()),
        }
    }
    pub async fn list(
        &mut self,
        tokens: &impl TokenProvider,
        context: &ExtensionContext,
    ) -> Result<(), Error> {
        let mut op = Operation::new(&mut self.state, &self.counters);
        check(context)?;
        let epoch = op.state.begin_list(Utc::now())?;
        let mut continuation = None;
        for _ in 0..self.profile.limits.max_pages {
            let route = url(&self.base, &self.profile, continuation.as_deref(), None)?;
            let mut response = send(&self.http, route, tokens, context).await?;
            if response
                .content_length()
                .is_some_and(|n| n > self.profile.limits.max_page_bytes as u64)
            {
                return Err(Error::Limit);
            }
            let mut bytes = Vec::new();
            loop {
                let chunk = within(context, async {
                    response.chunk().await.map_err(|_| Error::Response)
                })
                .await?;
                let Some(chunk) = chunk else {
                    break;
                };
                if chunk.len() > self.profile.limits.max_page_bytes - bytes.len() {
                    return Err(Error::Limit);
                }
                bytes.extend_from_slice(&chunk);
            }
            check(context)?;
            let complete =
                op.state
                    .list_page(epoch, continuation.as_deref(), &bytes, Utc::now())?;
            check(context)?;
            if complete {
                op.complete = true;
                return Ok(());
            }
            continuation = op.state.listing.as_ref().and_then(|s| s.next.clone());
        }
        Err(Error::Limit)
    }
    pub async fn watch<'a>(
        &'a mut self,
        tokens: &impl TokenProvider,
        context: &ExtensionContext,
    ) -> Result<WatchSession<'a>, Error> {
        let op = Operation::new(&mut self.state, &self.counters);
        check(context)?;
        if !op.state.authoritative(Utc::now()) {
            return Err(Error::Reconcile(super::Error::Stale));
        }
        let revision = op.state.resource_version().ok_or(Error::Closed)?;
        let route = url(&self.base, &self.profile, None, Some(revision))?;
        let response = send(&self.http, route, tokens, context).await?;
        if !op.state.authoritative(Utc::now()) {
            return Err(Error::Reconcile(super::Error::Stale));
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.profile.limits.max_watch_bytes as u64)
        {
            return Err(Error::Limit);
        }
        let epoch = op.state.epoch();
        Ok(WatchSession {
            response: Some(response),
            op,
            binding: &self.binding,
            context: context.clone(),
            epoch,
            sequence: 0,
            pending: Vec::new(),
            offset: 0,
            frame: Vec::new(),
            received: 0,
            max_received: self.profile.limits.max_watch_bytes,
            max_frame: self.profile.limits.max_page_bytes,
            closed: false,
        })
    }
}
/// Dropping a session invalidates continuity even when no frame read is active.
/// The original deadline is retained; subsequent calls cannot renew its budget.
pub struct WatchSession<'a> {
    response: Option<Response>,
    op: Operation<'a>,
    binding: &'a str,
    context: ExtensionContext,
    epoch: u64,
    sequence: u64,
    pending: Vec<u8>,
    offset: usize,
    frame: Vec<u8>,
    received: usize,
    max_received: usize,
    max_frame: usize,
    closed: bool,
}
impl WatchSession<'_> {
    pub fn snapshot(&mut self) -> BoundSnapshot<'_> {
        if check(&self.context).is_err() {
            self.close();
        }
        BoundSnapshot {
            schema_version: 1,
            source_binding: self.binding,
            collection: self.op.state.snapshot(Utc::now()),
        }
    }
    pub fn received_bytes(&self) -> usize {
        self.received
    }
    pub async fn next_frame(&mut self) -> Result<bool, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        // This guard also invalidates on a dropped next_frame future while the
        // session remains owned. It is separate from the session's drop guard.
        let mut read = FrameRead {
            session: self,
            complete: false,
        };
        let result = read.session.read_frame().await;
        read.complete = result.is_ok();
        if !matches!(result, Ok(true)) {
            read.session.close();
        }
        result
    }
    fn close(&mut self) {
        self.closed = true;
        self.response.take();
        self.op.state.invalidate();
    }
    async fn read_frame(&mut self) -> Result<bool, Error> {
        loop {
            check(&self.context)?;
            while self.offset < self.pending.len() {
                let byte = self.pending[self.offset];
                self.offset += 1;
                if byte == b'\n' {
                    if self.frame.is_empty() {
                        continue;
                    }
                    self.sequence = self.sequence.checked_add(1).ok_or(Error::Limit)?;
                    self.op.state.watch_frame(
                        self.epoch,
                        self.sequence,
                        &self.frame,
                        Utc::now(),
                    )?;
                    self.frame.clear();
                    check(&self.context)?;
                    return Ok(true);
                }
                if self.frame.len() >= self.max_frame {
                    return Err(Error::Limit);
                }
                self.frame.push(byte);
            }
            self.pending.clear();
            self.offset = 0;
            let response = self.response.as_mut().ok_or(Error::Closed)?;
            let chunk = within(&self.context, async {
                response.chunk().await.map_err(|_| Error::Response)
            })
            .await?;
            let Some(chunk) = chunk else {
                if !self.frame.is_empty() {
                    return Err(Error::Response);
                }
                return Ok(false);
            };
            self.received = self.received.saturating_add(chunk.len());
            if self.received > self.max_received {
                return Err(Error::Limit);
            }
            // The pending chunk has an independent cap; multiple small frames
            // cannot cause an arbitrarily large one-shot pending allocation.
            if chunk.len() > self.max_frame {
                return Err(Error::Limit);
            }
            self.pending.extend_from_slice(&chunk);
        }
    }
}
struct FrameRead<'s, 'a> {
    session: &'s mut WatchSession<'a>,
    complete: bool,
}
impl Drop for FrameRead<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.session.close();
        }
    }
}
#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

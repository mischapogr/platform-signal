//! Explicit independent receipt role. No ordinary ingest/query/WAL initialization.
mod config;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::Response,
};
use config::{Configuration, Enrollment};
use http_body_util::BodyExt;
use signal_collector_sdk::{
    ExtensionContext,
    audit::receiver::{AuditReceiver, OpenMode, ReceiverError, TrustedProducer},
};
use signal_ingest::{
    server::{self, ConnectionContext, TransportState},
    tls::ServerTls,
};
use signal_protocol::{
    audit::{ACK_BYTES, AuditReceiverHealth, PreparedAudit, RECORD_BYTES},
    transport::{TLS_DOCUMENT_BYTES, TlsMaterial},
};
use std::{
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HostError {
    #[error("invalid independent audit receiver configuration")]
    Invalid,
    #[error("independent audit receiver preparation unavailable")]
    Preparation,
    #[error("independent audit receiver history unavailable")]
    History,
    #[error("independent audit receiver transport unavailable")]
    Transport,
    #[error("independent audit receiver signal setup unavailable")]
    Signal,
    #[error("independent audit receiver operation deadline exceeded")]
    Deadline,
}
#[derive(Clone)]
struct Host {
    receiver: Arc<AuditReceiver>,
    producers: Arc<Vec<Enrollment>>,
    health_credential: axum::http::HeaderValue,
    append_operations: Arc<Semaphore>,
    health_operations: Arc<Semaphore>,
    append_rejected: Arc<AtomicU64>,
    health_rejected: Arc<AtomicU64>,
    request_timeout: Duration,
}
impl Host {
    fn stop(&self) {
        self.append_operations.close();
        self.health_operations.close();
    }
}
fn response(status: StatusCode, body: impl Into<Body>) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}
fn unavailable() -> Response {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        "{\"error\":\"unavailable\"}",
    )
}
fn denied() -> Response {
    response(StatusCode::FORBIDDEN, "{\"error\":\"denied\"}")
}
fn invalid() -> Response {
    response(StatusCode::BAD_REQUEST, "{\"error\":\"invalid request\"}")
}
fn authorization(headers: &HeaderMap) -> Option<&[u8]> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let first = values.next()?;
    if values.next().is_some() || first.as_bytes().len() > 519 {
        return None;
    }
    Some(first.as_bytes())
}
fn credential_eq(provided: &[u8], expected: &axum::http::HeaderValue) -> bool {
    bool::from(provided.ct_eq(expected.as_bytes()))
}
async fn within<T>(
    context: &ExtensionContext,
    work: impl Future<Output = Result<T, HostError>>,
) -> Result<T, HostError> {
    tokio::pin!(work);
    let guarded = std::future::poll_fn(|cx| {
        if context.check().is_err() {
            return Poll::Ready(Err(HostError::Deadline));
        }
        work.as_mut().poll(cx).map(|result| {
            context.check().map_err(|_| HostError::Deadline)?;
            result
        })
    });
    tokio::select! { biased;
        _ = context.cancellation().cancelled() => Err(HostError::Deadline),
        result = tokio::time::timeout_at(context.deadline(), guarded) => result.map_err(|_| HostError::Deadline)?,
    }
}
async fn body(body: Body, cap: usize, context: &ExtensionContext) -> Result<Vec<u8>, HostError> {
    within(context, async {
        let mut body = body;
        let mut bytes = Vec::with_capacity(cap);
        while let Some(frame) = body.frame().await {
            context.check().map_err(|_| HostError::Deadline)?;
            let data = frame
                .map_err(|_| HostError::Invalid)?
                .into_data()
                .map_err(|_| HostError::Invalid)?;
            if data.len() > cap - bytes.len() {
                return Err(HostError::Invalid);
            }
            bytes.extend_from_slice(&data);
        }
        Ok(bytes)
    })
    .await
}
fn request_context(
    request: &Request,
    timeout: Duration,
) -> Result<(ConnectionContext, ExtensionContext), HostError> {
    let connection = request
        .extensions()
        .get::<ConnectionContext>()
        .cloned()
        .ok_or(HostError::Transport)?;
    connection.check().map_err(|_| HostError::Deadline)?;
    let deadline = connection.deadline().min(Instant::now() + timeout);
    let context =
        ExtensionContext::from_deadline(connection.cancellation().child_token(), deadline)
            .map_err(|_| HostError::Deadline)?;
    Ok((connection, context))
}
fn framing(headers: &HeaderMap, cap: usize, health: bool) -> bool {
    if headers.contains_key(header::TRAILER) {
        return false;
    }
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let length = lengths.next();
    if lengths.next().is_some()
        || length.is_some_and(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .is_none_or(|n| n > cap)
        })
    {
        return false;
    }
    let mut encodings = headers.get_all(header::TRANSFER_ENCODING).iter();
    let encoding = encodings.next();
    if encodings.next().is_some()
        || encoding.is_some_and(|v| health || length.is_some() || v.as_bytes() != b"chunked")
    {
        return false;
    }
    true
}
async fn append(State(host): State<Host>, request: Request) -> Response {
    let result = append_request(&host, request).await;
    if !result.status().is_success() {
        host.append_rejected.fetch_add(1, Ordering::Relaxed);
    }
    result
}
async fn append_request(host: &Host, request: Request) -> Response {
    if request.method() != Method::POST
        || request.uri().path() != "/v1/audit/records"
        || request.uri().query().is_some()
    {
        return denied();
    }
    let Some(provided) = authorization(request.headers()) else {
        return denied();
    };
    let Some(enrollment) = host
        .producers
        .iter()
        .find(|p| credential_eq(provided, &p.credential))
    else {
        return denied();
    };
    let producer = match TrustedProducer::from_authenticated_namespace(enrollment.id) {
        Ok(producer) => producer,
        Err(_) => return denied(),
    };
    let mut content_types = request.headers().get_all(header::CONTENT_TYPE).iter();
    if content_types
        .next()
        .is_none_or(|v| v.as_bytes() != b"application/json")
        || content_types.next().is_some()
        || !framing(request.headers(), RECORD_BYTES, false)
    {
        return invalid();
    }
    let (connection, context) = match request_context(&request, host.request_timeout) {
        Ok(c) => c,
        Err(_) => return unavailable(),
    };
    // The transport retains this lease after the handler returns, through actual
    // socket/ACK exit. No body is retained before admission succeeds.
    if connection
        .try_acquire_operation(host.append_operations.clone())
        .is_err()
    {
        return unavailable();
    }
    let _cancel = context.cancellation().clone().drop_guard();
    let bytes = match body(request.into_body(), RECORD_BYTES, &context).await {
        Ok(bytes) => bytes,
        Err(HostError::Invalid) => return invalid(),
        Err(_) => return unavailable(),
    };
    let prepared = match PreparedAudit::from_original(&bytes) {
        Ok(record) => record,
        Err(_) => return invalid(),
    };
    let result = host
        .receiver
        .append(&producer, &prepared, context.clone())
        .await;
    if context.check().is_err() {
        return unavailable();
    }
    match result {
        Ok(ack) if ack.len() <= ACK_BYTES => response(StatusCode::OK, ack),
        Err(ReceiverError::Denied) => denied(),
        Err(ReceiverError::Invalid) => invalid(),
        Err(ReceiverError::Conflict) => response(StatusCode::CONFLICT, "{\"error\":\"conflict\"}"),
        Err(ReceiverError::Full) => response(
            StatusCode::INSUFFICIENT_STORAGE,
            "{\"error\":\"capacity exhausted\"}",
        ),
        _ => unavailable(),
    }
}
async fn health(State(host): State<Host>, request: Request) -> Response {
    let result = health_request(&host, request).await;
    if !result.status().is_success() {
        host.health_rejected.fetch_add(1, Ordering::Relaxed);
    }
    result
}
async fn health_request(host: &Host, request: Request) -> Response {
    if request.method() != Method::GET
        || request.uri().path() != "/v1/audit/health"
        || request.uri().query().is_some()
        || authorization(request.headers())
            .is_none_or(|provided| !credential_eq(provided, &host.health_credential))
    {
        return denied();
    }
    if !framing(request.headers(), 0, true) {
        return invalid();
    }
    let (connection, context) = match request_context(&request, host.request_timeout) {
        Ok(c) => c,
        Err(_) => return unavailable(),
    };
    if connection
        .try_acquire_operation(host.health_operations.clone())
        .is_err()
    {
        return unavailable();
    }
    let _cancel = context.cancellation().clone().drop_guard();
    match body(request.into_body(), 0, &context).await {
        Ok(_) => {}
        Err(HostError::Invalid) => return invalid(),
        Err(_) => return unavailable(),
    }
    let h = host.receiver.health();
    let document = AuditReceiverHealth {
        schema_version: 1,
        held: h.held,
        records: h.records,
        bytes: h.bytes,
        record_capacity: h.record_capacity,
        byte_capacity: h.byte_capacity,
        physical_depth: h.physical_depth,
        physical_capacity: h.physical_capacity,
        physical_rejected: h.physical_rejected,
        rejected: h.rejected,
        uncertain: h.uncertain,
        append_http_depth: 1usize.saturating_sub(host.append_operations.available_permits()),
        append_http_capacity: 1,
        append_http_rejected: host.append_rejected.load(Ordering::Relaxed),
        health_http_rejected: host.health_rejected.load(Ordering::Relaxed),
    };
    let bytes = match document.to_json() {
        Ok(bytes) if bytes.len() <= ACK_BYTES => bytes,
        _ => return unavailable(),
    };
    if context.check().is_err() {
        return unavailable();
    }
    response(
        if h.held {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        },
        bytes,
    )
}
fn routers(host: &Host) -> (Router, Router) {
    (
        Router::new().fallback(append).with_state(host.clone()),
        Router::new().fallback(health).with_state(host.clone()),
    )
}
struct Prepared {
    configuration: Configuration,
    host: Host,
    append_tls: ServerTls,
    health_tls: ServerTls,
}
async fn load_tls(
    path: PathBuf,
    context: &ExtensionContext,
) -> Result<(ServerTls, Vec<Vec<u8>>), HostError> {
    crate::config::read_limited_document(
        path,
        TLS_DOCUMENT_BYTES,
        context.deadline(),
        context.cancellation().clone(),
        |text| {
            let invalid = || crate::config::ConfigError::Invalid("independent audit receiver TLS");
            let material =
                TlsMaterial::from_private_json(text.as_bytes()).map_err(|_| invalid())?;
            let tls = ServerTls::from_private_json(text.as_bytes()).map_err(|_| invalid())?;
            Ok((tls, material.peer_roots_der))
        },
    )
    .await
    .map_err(|_| HostError::Invalid)
}
async fn prepare(
    path: PathBuf,
    initialize: bool,
    context: &ExtensionContext,
) -> Result<Prepared, HostError> {
    let configuration = crate::config::read_limited_document(
        path,
        config::CONFIG_BYTES,
        context.deadline(),
        context.cancellation().clone(),
        |text| {
            config::Wire::parse(text)
                .and_then(|wire| {
                    wire.capture(|name| std::env::var(name).map_err(|_| HostError::Invalid))
                })
                .map_err(|_| {
                    crate::config::ConfigError::Invalid("independent audit receiver configuration")
                })
        },
    )
    .await
    .map_err(|_| HostError::Invalid)?;
    let (append_tls, append_roots) = load_tls(configuration.append_tls.clone(), context).await?;
    let (health_tls, health_roots) = load_tls(configuration.health_tls.clone(), context).await?;
    if append_roots.iter().any(|root| health_roots.contains(root)) {
        return Err(HostError::Invalid);
    }
    let allowed: Vec<_> = configuration
        .producers
        .iter()
        .map(|producer| producer.id)
        .collect();
    let receiver = AuditReceiver::open(
        &configuration.directory,
        if initialize {
            OpenMode::Initialize
        } else {
            OpenMode::Existing
        },
        configuration.receiver_limits,
        &allowed,
        context.clone(),
    )
    .await
    .map_err(|_| HostError::History)?;
    let host = Host {
        receiver: Arc::new(receiver),
        producers: Arc::new(configuration.producers),
        health_credential: configuration.health_credential.clone(),
        append_operations: Arc::new(Semaphore::new(1)),
        health_operations: Arc::new(Semaphore::new(2)),
        append_rejected: Arc::new(AtomicU64::new(0)),
        health_rejected: Arc::new(AtomicU64::new(0)),
        request_timeout: configuration.request_timeout,
    };
    // Configuration no longer duplicates the captured enrollment credentials.
    let configuration = Configuration {
        producers: Vec::new(),
        ..configuration
    };
    Ok(Prepared {
        configuration,
        host,
        append_tls,
        health_tls,
    })
}
pub(crate) async fn run(path: PathBuf, initialize: bool) -> Result<(), HostError> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| HostError::Signal)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| HostError::Signal)?;
    let stopping = CancellationToken::new();
    let _cancel = stopping.clone().drop_guard();
    let startup = ExtensionContext::new(stopping.clone(), Duration::from_secs(15))
        .map_err(|_| HostError::Preparation)?;
    let Prepared {
        configuration,
        host,
        append_tls,
        health_tls,
    } = tokio::select! { biased;
        _ = terminate.recv() => return Err(HostError::Preparation),
        _ = interrupt.recv() => return Err(HostError::Preparation),
        result = within(&startup, prepare(path, initialize, &startup)) => result?,
    };
    if initialize {
        println!(
            "independent audit receipt history initialized; startup opens existing history only"
        );
        return Ok(());
    }
    let listeners = within(&startup, async {
        let append = TcpListener::bind(configuration.append_address)
            .await
            .map_err(|_| HostError::Transport)?;
        let health = TcpListener::bind(configuration.health_address)
            .await
            .map_err(|_| HostError::Transport)?;
        Ok((append, health))
    })
    .await?;
    let (append_router, health_router) = routers(&host);
    let append_state =
        TransportState::independent(stopping.clone(), configuration.header_timeout, false)
            .map_err(|_| HostError::Invalid)?;
    let health_state =
        TransportState::independent(stopping.clone(), configuration.header_timeout, false)
            .map_err(|_| HostError::Invalid)?;
    let append_stop = host.clone();
    let health_stop = host.clone();
    let listeners = async {
        tokio::join!(
            server::serve_transport_router(
                listeners.0,
                append_state,
                append_router,
                configuration.append_limits,
                Arc::new(Semaphore::new(configuration.append_limits.max_connections)),
                Some(append_tls),
                (move || append_stop.stop(), stopping.cancelled())
            ),
            server::serve_transport_router(
                listeners.1,
                health_state,
                health_router,
                configuration.health_limits,
                Arc::new(Semaphore::new(configuration.health_limits.max_connections)),
                Some(health_tls),
                (move || health_stop.stop(), stopping.cancelled())
            )
        )
    };
    tokio::pin!(listeners);
    let result = tokio::select! { biased;
        _ = terminate.recv() => None,
        _ = interrupt.recv() => None,
        result = &mut listeners => Some(result),
    };
    host.stop();
    stopping.cancel();
    let (append, health) = match result {
        Some(result) => result,
        None => tokio::time::timeout(configuration.append_limits.shutdown_timeout, &mut listeners)
            .await
            .map_err(|_| HostError::Deadline)?,
    };
    append.map_err(|_| HostError::Transport)?;
    health.map_err(|_| HostError::Transport)?;
    Ok(())
}

#[cfg(test)]
mod tests;

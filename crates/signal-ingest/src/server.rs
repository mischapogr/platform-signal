//! Bounded HTTP/1 transport with header/lifetime deadlines and graceful cancellation.
use crate::{ConfigError, IngestService};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    future::Future,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

/// Connection-only metrics; independent routers report no fabricated ingest/WAL
/// admissions. Existing ingest metric names and counter semantics are preserved.
#[derive(Default)]
pub struct TransportMetrics {
    pub(crate) connections: AtomicU64,
    pub(crate) connection_capacity: AtomicU64,
    pub(crate) connection_timeouts: AtomicU64,
    pub(crate) connection_errors: AtomicU64,
}
#[derive(Clone, Copy, Debug)]
pub struct TransportSnapshot {
    pub connections: u64,
    pub capacity: u64,
    pub timeouts: u64,
    pub errors: u64,
}
impl TransportMetrics {
    pub fn snapshot(&self) -> TransportSnapshot {
        TransportSnapshot {
            connections: self.connections.load(Ordering::Relaxed),
            capacity: self.connection_capacity.load(Ordering::Relaxed),
            timeouts: self.connection_timeouts.load(Ordering::Relaxed),
            errors: self.connection_errors.load(Ordering::Relaxed),
        }
    }
}
#[derive(Clone)]
pub struct TransportState {
    metrics: Arc<TransportMetrics>,
    stopping: CancellationToken,
    header_timeout: Duration,
    keep_alive: bool,
}
impl TransportState {
    pub fn independent(
        stopping: CancellationToken,
        header_timeout: Duration,
        keep_alive: bool,
    ) -> Result<Self, ConfigError> {
        if header_timeout.is_zero() || header_timeout > Duration::from_secs(3600) {
            return Err(ConfigError::Invalid(
                "HTTP header timeout must be positive and at most one hour",
            ));
        }
        Ok(Self {
            metrics: Arc::new(TransportMetrics::default()),
            stopping,
            header_timeout,
            keep_alive,
        })
    }
    pub fn metrics(&self) -> Arc<TransportMetrics> {
        self.metrics.clone()
    }
    fn for_service(service: &IngestService) -> Self {
        Self {
            metrics: service.shared.metrics.transport.clone(),
            stopping: service.shared.stopping.clone(),
            header_timeout: service.shared.config.request_timeout,
            keep_alive: true,
        }
    }
}
/// Created only by the accepted connection engine. Carries lifetime/cancellation,
/// never actor, certificate identity or request authority. A single operation
/// lease remains owned through actual socket/response exit (or longer if the host
/// retains this context); it is suitable for one-request independent connections.
#[derive(Clone)]
pub struct ConnectionContext {
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
    lease: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("HTTP connection operation unavailable")]
pub struct OperationUnavailable;
struct AdmissionGuard<S: FnOnce()> {
    stop: Option<S>,
    cancellation: CancellationToken,
}
impl<S: FnOnce()> AdmissionGuard<S> {
    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
        self.cancellation.cancel();
    }
}
impl<S: FnOnce()> Drop for AdmissionGuard<S> {
    fn drop(&mut self) {
        self.stop();
    }
}
impl ConnectionContext {
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    pub fn check(&self) -> Result<(), OperationUnavailable> {
        if self.cancellation.is_cancelled() || tokio::time::Instant::now() >= self.deadline {
            Err(OperationUnavailable)
        } else {
            Ok(())
        }
    }
    pub fn try_acquire_operation(
        &self,
        budget: Arc<Semaphore>,
    ) -> Result<(), OperationUnavailable> {
        self.check()?;
        let mut lease = self.lease.lock().map_err(|_| OperationUnavailable)?;
        if lease.is_some() {
            return Err(OperationUnavailable);
        }
        *lease = Some(
            budget
                .try_acquire_owned()
                .map_err(|_| OperationUnavailable)?,
        );
        self.check()
    }
}

// Tokio timeout polls the operation before its timer. Guard both the physical
// poll and the ready handoff, so scheduling delay cannot dispatch expired HTTP
// work or accept a handshake that finishes after its original deadline.
async fn before_deadline<T>(
    deadline: tokio::time::Instant,
    work: impl Future<Output = T>,
) -> Result<T, ()> {
    tokio::pin!(work);
    let guarded = std::future::poll_fn(|cx| {
        if tokio::time::Instant::now() >= deadline {
            Poll::Ready(Err(()))
        } else {
            work.as_mut().poll(cx).map(|result| {
                if tokio::time::Instant::now() >= deadline {
                    Err(())
                } else {
                    Ok(result)
                }
            })
        }
    });
    tokio::time::timeout_at(deadline, guarded)
        .await
        .map_err(|_| ())?
}

trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportIo for T {}

#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub shutdown_timeout: Duration,
}
impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            connection_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}
impl ServerLimits {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0
            || self.max_connections > 65_536
            || self.connection_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
            || self.connection_timeout > Duration::from_secs(3600)
            || self.shutdown_timeout > Duration::from_secs(3600)
        {
            return Err(ConfigError::Invalid(
                "connection limits must be positive; timeouts must not exceed one hour",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("HTTP listener accept failed")]
    Accept(#[source] io::Error),
    #[error("HTTP shutdown exceeded its deadline")]
    ShutdownTimeout,
}

/// The accept loop and connection tasks stop on shutdown. There are at most
/// max_connections tasks, each with a header deadline and total lifetime bound.
pub async fn serve(
    listener: TcpListener,
    service: IngestService,
    limits: ServerLimits,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServerError> {
    let app = service.router();
    serve_router(listener, service, app, limits, shutdown).await
}

/// Serve the composed monolith router using the same bounded transport as ingest.
pub async fn serve_router(
    listener: TcpListener,
    service: IngestService,
    app: axum::Router,
    limits: ServerLimits,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServerError> {
    limits.validate()?;
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    serve_router_with_budget(listener, service, app, limits, permits, shutdown).await
}

/// Two listeners may share this connection budget. Capacity is configured once
/// by their caller; an idle accept can reserve a slot but cannot exceed the budget.
pub async fn serve_router_with_budget(
    listener: TcpListener,
    service: IngestService,
    app: axum::Router,
    limits: ServerLimits,
    permits: Arc<Semaphore>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServerError> {
    serve_router_with_tls_budget(listener, service, app, limits, permits, None, shutdown).await
}

/// TLS handshake and HTTP share the original physical connection budget/lifetime.
/// None preserves the explicit development plaintext transport. Some never falls
/// back to plaintext and requires a verified client certificate on every listener.
pub async fn serve_router_with_tls_budget(
    listener: TcpListener,
    service: IngestService,
    app: axum::Router,
    limits: ServerLimits,
    permits: Arc<Semaphore>,
    tls: Option<crate::tls::ServerTls>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServerError> {
    let state = TransportState::for_service(&service);
    serve_transport_router(
        listener,
        state,
        app,
        limits,
        permits,
        tls,
        (move || service.stop_admission(), shutdown),
    )
    .await
}

/// One bounded HTTP engine for independently hosted routers. The synchronous
/// host-selected stop callback must stop its admission before cancellation; no
/// EventSink or ordinary readiness service is constructed by this entry point.
pub async fn serve_transport_router(
    listener: TcpListener,
    state: TransportState,
    app: axum::Router,
    limits: ServerLimits,
    permits: Arc<Semaphore>,
    tls: Option<crate::tls::ServerTls>,
    shutdown: (impl FnOnce() + Send, impl Future<Output = ()> + Send),
) -> Result<(), ServerError> {
    let (stop_admission, shutdown) = shutdown;
    limits.validate()?;
    state
        .metrics
        .connection_capacity
        .store(limits.max_connections as u64, Ordering::Relaxed);

    let mut tasks = JoinSet::new();
    // Created after JoinSet so cancellation/drop closes host admission before
    // aborting connection tasks. It also owns the callback on future abort.
    let mut admission = AdmissionGuard {
        stop: Some(stop_admission),
        cancellation: state.stopping.clone(),
    };
    tokio::pin!(shutdown);
    let mut accept_error = None;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = state.stopping.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_err() { tracing::warn!("HTTP connection task failed"); }
            },
            result = async {
                let permit = permits.clone().acquire_owned().await.map_err(|_| io::Error::other("connection admission closed"))?;
                listener.accept().await.map(|pair| (pair, permit))
            }, if tasks.len() < limits.max_connections => {
                let ((stream, _), permit) = match result {
                    Ok(pair) => pair,
                    Err(error) => { accept_error = Some(error); break; }
                };
                let app = app.clone();
                let tls = tls.clone();
                let cancellation = state.stopping.child_token();
                let header_timeout = state.header_timeout;
                let metrics = state.metrics.clone();
                metrics.connections.fetch_add(1, Ordering::Relaxed);
                let started = tokio::time::Instant::now();
                let context=ConnectionContext{deadline:started+limits.connection_timeout,cancellation:cancellation.clone(),lease:Arc::new(Mutex::new(None))};
                let guard = ConnectionGuard{metrics:metrics.clone(),context:context.clone()};
                let keep_alive=state.keep_alive;
                tasks.spawn(async move {
                    let _permit = permit;
                    let _guard = guard;
                    let connection_deadline = started + limits.connection_timeout;
                    let handshake_deadline = started + header_timeout.min(limits.connection_timeout);
                    let stream: Box<dyn TransportIo> = match tls {
                        Some(tls) => {
                            let handshake = tokio::select! { biased;
                                _ = cancellation.cancelled() => return,
                                result = before_deadline(handshake_deadline, tls.acceptor.accept(stream)) => result,
                            };
                            match handshake {
                                Ok(Ok(stream)) => Box::new(stream),
                                Ok(Err(_)) => {
                                    metrics.connection_errors.fetch_add(1, Ordering::Relaxed);
                                    tracing::debug!("TLS peer handshake denied");
                                    return;
                                },
                                Err(_) => {
                                    metrics.connection_timeouts.fetch_add(1, Ordering::Relaxed);
                                    return;
                                },
                            }
                        },
                        None => Box::new(stream),
                    };
                    if cancellation.is_cancelled() { return; }
                    if tokio::time::Instant::now() >= connection_deadline {
                        metrics.connection_timeouts.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(header_timeout).max_buf_size(32_768).keep_alive(keep_alive);
                    let app=app.layer(axum::Extension(context));
                    let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
                    tokio::pin!(connection);
                    let lifetime = async {
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                connection.await
                            },
                            result = &mut connection => result,
                        }
                    };
                    match before_deadline(connection_deadline, lifetime).await {
                        Ok(Ok(())) => {},
                        Ok(Err(error)) => {
                            metrics.connection_errors.fetch_add(1, Ordering::Relaxed);
                            if error.is_timeout() { metrics.connection_timeouts.fetch_add(1, Ordering::Relaxed); }
                            tracing::debug!("HTTP connection closed with a protocol or I/O error");
                        },
                        Err(_) => { metrics.connection_timeouts.fetch_add(1, Ordering::Relaxed); tracing::debug!("HTTP connection lifetime exceeded"); },
                    }
                });
            }
        }
    }
    // close() serializes with sink admission before pending handlers are cancelled.
    admission.stop();
    drop(listener);
    if timeout(limits.shutdown_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        // Dropping JoinSet cancels the bounded set of sockets/handlers.
        return Err(ServerError::ShutdownTimeout);
    }
    if let Some(error) = accept_error {
        return Err(ServerError::Accept(error));
    }
    Ok(())
}

struct ConnectionGuard {
    metrics: Arc<TransportMetrics>,
    context: ConnectionContext,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.context.cancellation.cancel();
        self.metrics.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod deadline_tests {
    use super::*;
    use std::{
        cell::Cell,
        task::{Context, Waker},
    };

    #[tokio::test]
    async fn operation_lease_checks_original_context_and_survives_expiry_until_all_owners_drop() {
        let budget = Arc::new(Semaphore::new(1));
        let cancellation = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
        let context = ConnectionContext {
            deadline,
            cancellation: cancellation.clone(),
            lease: Arc::new(Mutex::new(None)),
        };
        context.try_acquire_operation(budget.clone()).unwrap();
        assert_eq!(budget.available_permits(), 0);
        assert!(context.try_acquire_operation(budget.clone()).is_err());
        let owner = context.clone();
        assert_eq!(owner.deadline(), deadline);
        std::thread::sleep(
            deadline.saturating_duration_since(tokio::time::Instant::now())
                + Duration::from_millis(5),
        );
        assert!(context.check().is_err());
        assert_eq!(budget.available_permits(), 0);
        cancellation.cancel();
        assert!(owner.check().is_err());
        drop(context);
        assert_eq!(budget.available_permits(), 0);
        drop(owner);
        assert_eq!(budget.available_permits(), 1);
        let context = ConnectionContext {
            deadline: tokio::time::Instant::now(),
            cancellation: CancellationToken::new(),
            lease: Arc::new(Mutex::new(None)),
        };
        assert!(context.try_acquire_operation(budget.clone()).is_err());
        assert_eq!(budget.available_permits(), 1);
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let context = ConnectionContext {
            deadline: tokio::time::Instant::now() + Duration::from_secs(1),
            cancellation: cancelled,
            lease: Arc::new(Mutex::new(None)),
        };
        assert!(context.try_acquire_operation(budget.clone()).is_err());
        assert_eq!(budget.available_permits(), 1);
    }

    #[tokio::test]
    async fn late_ready_handshake_handoff_never_polls_http_work() {
        let ready = Cell::new(false);
        let polls = Cell::new(0);
        let http_dispatches = Cell::new(0);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let handshake = std::future::poll_fn(|_| {
            polls.set(polls.get() + 1);
            if ready.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        let handoff = async {
            before_deadline(deadline, handshake).await?;
            http_dispatches.set(http_dispatches.get() + 1);
            Ok::<_, ()>(())
        };
        tokio::pin!(handoff);
        assert!(
            handoff
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ready.set(true);
        std::thread::sleep(
            deadline.saturating_duration_since(tokio::time::Instant::now())
                + Duration::from_millis(10),
        );
        assert_eq!(handoff.await, Err(()));
        assert_eq!(polls.get(), 1);
        assert_eq!(http_dispatches.get(), 0);
    }

    #[tokio::test]
    async fn connection_result_crossing_original_deadline_is_rejected() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let result = before_deadline(deadline, async {
            std::thread::sleep(Duration::from_millis(25));
            7
        })
        .await;
        assert_eq!(result, Err(()));
    }
}

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
    sync::{Arc, atomic::Ordering},
    task::Poll,
    time::Duration,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};

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
    limits.validate()?;
    service
        .shared
        .metrics
        .connection_capacity
        .store(limits.max_connections as u64, Ordering::Relaxed);
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let mut accept_error = None;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = service.shared.stopping.cancelled() => break,
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
                let cancellation = service.cancellation();
                let header_timeout = service.shared.config.request_timeout;
                let metrics = service.shared.metrics.clone();
                metrics.connections.fetch_add(1, Ordering::Relaxed);
                let guard = ConnectionGuard(metrics.clone());
                let started = tokio::time::Instant::now();
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
                    builder.timer(TokioTimer::new()).header_read_timeout(header_timeout).max_buf_size(32_768);
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
    service.stop_admission();
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

struct ConnectionGuard(Arc<crate::HttpMetrics>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
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

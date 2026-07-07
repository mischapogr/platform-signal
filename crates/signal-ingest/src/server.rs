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
    time::Duration,
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};

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
                let cancellation = service.cancellation();
                let header_timeout = service.shared.config.request_timeout;
                let metrics = service.shared.metrics.clone();
                metrics.connections.fetch_add(1, Ordering::Relaxed);
                let guard = ConnectionGuard(metrics.clone());
                tasks.spawn(async move {
                    let _permit = permit;
                    let _guard = guard;
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
                    match timeout(limits.connection_timeout, lifetime).await {
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

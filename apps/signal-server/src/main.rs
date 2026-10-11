//! HTTP ingest, bounded WAL, replay-safe Parquet persistence and URL queries.
mod access;
mod audit;
mod audit_receiver;
mod config;
mod coverage_api;
mod finding_api;
mod logging;
mod pipeline;
mod query_api;
mod runtime_config;
mod standard;
#[cfg(feature = "s3-query")]
mod standard_config;
mod storage;
mod tls;
mod ui;
use config::Settings;
use logging::{LoggerGuard, LoggingConfig};
use pipeline::{DetectionPipeline, PipelineSink};
#[cfg(test)]
use signal_buffer::BufferConfig;
use signal_buffer::DurableBuffer;
use signal_findings::{FindingContext, FindingStore};
use signal_ingest::{ConfigError, IngestService, server};
use signal_protocol::EventSink;
use signal_query::{QueryEngine, QueryError};
use signal_rules::RuleContext;
#[cfg(test)]
use signal_storage::StorageConfig;
use signal_storage::{OperationContext, StorageError};
use std::{
    env,
    process::ExitCode,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};
use storage::Backend;
use thiserror::Error;
use tokio::{
    net::TcpListener,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    Control(#[from] signal_control::ControlError),
    #[cfg(feature = "s3-query")]
    #[error(transparent)]
    Shared(#[from] standard::Error),
    #[error(transparent)]
    AuditReceiver(#[from] audit_receiver::HostError),
    #[error(transparent)]
    Audit(#[from] audit::Unavailable),
    #[error(transparent)]
    Identity(#[from] signal_ingest::identity::IdentityError),
    #[error(transparent)]
    Coverage(#[from] signal_coverage::CoverageError),
    #[error(transparent)]
    Settings(#[from] config::ConfigError),
    #[error(transparent)]
    Finding(#[from] signal_findings::FindingError),
    #[error(transparent)]
    Rules(#[from] signal_rules::RuleError),
    #[error(transparent)]
    Logger(#[from] logging::LoggingError),
    #[error(transparent)]
    Reported(Box<AppError>),
    #[error("invalid configuration variable {0}")]
    Environment(&'static str),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("HTTP listen deadline exceeded")]
    BindTimeout,
    #[error("HTTP listener bind failed")]
    Bind(#[source] std::io::Error),
    #[error("shutdown signal setup failed")]
    Signal(#[source] std::io::Error),
    #[error(transparent)]
    Server(#[from] server::ServerError),
    #[error(transparent)]
    Sink(#[from] signal_buffer::BufferError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error(transparent)]
    Pipeline(#[from] pipeline::PipelineError),
    #[error("storage consumer task failed")]
    ConsumerTask,
    #[error("shutdown drain deadline exceeded; unfinished events remain in WAL")]
    DrainTimeout,
    #[error("unknown command-line argument; use --help")]
    Argument,
}
#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        // Typed errors contain static context, never config values, token or event data.
        if !matches!(error, AppError::Reported(_)) {
            let _ =
                logging::report_startup_error(&error, Instant::now() + Duration::from_millis(250))
                    .await;
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), AppError> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [role, config, path]
            if (role == "--audit-receiver" || role == "--initialize-audit-receiver")
                && config == "--config" =>
        {
            return audit_receiver::run(path.into(), role == "--initialize-audit-receiver")
                .await
                .map_err(Into::into);
        }
        _ => {}
    }
    let mut initialize_coverage = false;
    let path = match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("signal-server {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        [flag] if flag == "--help" => {
            println!(
                "signal-server: durable HTTP ingest, Parquet storage and URL queries\nUsage: signal-server [--config PATH | --initialize-coverage [--config PATH] | --audit-receiver --config PATH | --initialize-audit-receiver --config PATH | --help | --version]\nConfiguration: see docs/12-phase3-storage.md and docs/13-phase4-query.md. SIGNAL_LISTEN, SIGNAL_API_TOKEN, SIGNAL_WAL_DIR, SIGNAL_ADMISSION_POLICY and bounded HTTP/WAL limits.\nAccepted events are synced to WAL, then persisted to Parquet before checkpointing. GET /v1/events and /v1/findings query persisted data. SIGNAL_CONFIG loads strict versioned YAML; environment overrides YAML.\nIndependent audit receiver uses its own strict private configuration and mandatory mTLS; see docs/45-independent-audit.md."
            );
            return Ok(());
        }
        [flag, path] if flag == "--config" => Some(path.into()),
        [flag] if flag == "--initialize-coverage" => {
            initialize_coverage = true;
            None
        }
        [flag, config, path] if flag == "--initialize-coverage" && config == "--config" => {
            initialize_coverage = true;
            Some(path.into())
        }
        [] => None,
        _ => return Err(AppError::Argument),
    };
    let settings = Settings::load(
        path,
        Instant::now() + Duration::from_secs(5),
        CancellationToken::new(),
    )
    .await?;
    if initialize_coverage {
        let configuration = coverage_api::Configuration::load(&settings).await?.ok_or(
            config::ConfigError::Invalid("coverage configuration required for initialization"),
        )?;
        configuration.initialize().await?;
        println!("coverage history initialized; normal startup only opens existing history");
        return Ok(());
    }
    let logger = LoggerGuard::stderr(LoggingConfig {
        queue_records: settings.number("SIGNAL_LOG_RECORDS", 1024)?,
        queue_bytes: settings.number("SIGNAL_LOG_BYTES", 1_048_576)?,
        max_record_bytes: settings.number("SIGNAL_LOG_RECORD_BYTES", 8192)?,
    })?;
    logger.install()?;
    let result = run_configured(settings, &logger).await;
    if matches!(&result, Err(AppError::Reported(_))) {
        return result;
    }
    if let Err(error) = &result {
        logger.writer().report_error(error);
    }
    let logging_stopped = logger
        .shutdown(Instant::now() + Duration::from_millis(250))
        .await;
    result.map_err(|e| AppError::Reported(Box::new(e)))?;
    logging_stopped.map_err(|e| AppError::Reported(Box::new(e.into())))?;
    Ok(())
}

async fn run_configured(settings: Settings, logger: &LoggerGuard) -> Result<(), AppError> {
    if settings.optional("SIGNAL_SHARED_CONFIG")?.is_some() {
        return standard::run(settings, logger).await;
    }
    // One original clock spans preparation, recovery and every selected fresh
    // startup confirmation. Ordinary unselected startup retains its own limits.
    let startup_cancellation = CancellationToken::new();
    let _startup_guard = startup_cancellation.clone().drop_guard();
    let startup = signal_collector_sdk::ExtensionContext::new(
        startup_cancellation.clone(),
        Duration::from_secs(60),
    )
    .map_err(|_| ConfigError::Invalid("startup audit budget"))?;
    // Install signal handlers before readiness; setup failure cannot leave a running server.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(AppError::Signal)?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(AppError::Signal)?;
    let query_audit = audit::Control::load(&settings, &startup).await?;
    let preparation = async {
        let runtime_config::RuntimeConfig {
            config,
            limits,
            tls,
            identity,
            coverage_configuration,
            listen,
            metrics_listen,
            wal_config,
            storage_config,
            query_config,
            query_timeout,
            query_limit,
            consumer_config,
            finding_config,
            finding_limit,
            finding_bytes,
            finding_timeout,
            max_finding_rows,
            max_finding_bytes,
            rule_limits,
            rule_timeout_ms,
            rules,
        } = runtime_config::load(&settings).await?;
        // Capture exactly the retained validated objects before moving them into
        // the inactive runtime. Never reopen configuration/rule files or settings.
        let runtime_revision = match &query_audit {
            Some(control)
                if control
                    .selects_activation(signal_protocol::audit::ConfigurationKind::Runtime) =>
            {
                Some(audit::runtime_revision(
                    audit::RuntimeInputs {
                        ingest: &config,
                        server: &limits,
                        buffer: &wal_config,
                        storage: &storage_config,
                        query: &query_config,
                        findings: &finding_config,
                        rules: &rule_limits,
                        consumer: &consumer_config,
                        rule_timeout: Duration::from_millis(rule_timeout_ms as u64),
                        tls: tls.is_some(),
                        identity: identity.is_some(),
                        coverage: coverage_configuration.is_some(),
                        separate_metrics: metrics_listen.is_some(),
                    },
                    &startup,
                )?)
            }
            _ => None,
        };
        let rules_revision = match &query_audit {
            Some(control)
                if control.selects_activation(signal_protocol::audit::ConfigurationKind::Rules) =>
            {
                let mut writer = audit::HashWriter::new();
                rules.write_revision(
                    &mut writer,
                    64 * 1024 * 1024,
                    &RuleContext {
                        deadline: startup.deadline(),
                        cancellation: startup_cancellation.clone(),
                    },
                )?;
                Some(writer.finish())
            }
            _ => None,
        };
        let sink = Arc::new(DurableBuffer::open(wal_config).await?);
        let wal = sink.snapshot();
        let store = Arc::new(Backend::open(&settings, storage_config, wal.stream_id).await?);
        let high_water = store.metrics().high_water;
        if high_water > wal.last_sequence
            || wal.checkpoint.saturating_sub(high_water) > wal.dropped
            || store.retired_through() > wal.checkpoint
        {
            sink.shutdown().await?;
            store
                .shutdown(OperationContext::new(Duration::from_secs(5)))
                .await?;
            return Err(StorageError::Config(
                "storage high water and WAL checkpoint are incompatible",
            )
            .into());
        }
        let findings = Arc::new(FindingStore::open(finding_config, wal.stream_id).await?);
        if identity.is_some() {
            findings
                .enable_scopes(FindingContext::new(finding_timeout))
                .await?;
        }
        let detection = Arc::new(DetectionPipeline {
            authenticated_after: identity.as_ref().map(|_| wal.last_sequence),
            rules,
            findings: findings.clone(),
            max_rows: max_finding_rows,
            max_bytes: max_finding_bytes,
            evaluated: AtomicU64::new(0),
            matches: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        });
        let query = Arc::new(QueryEngine::with_source(query_config, store.clone())?);
        let query_auth = config.clone();
        let coverage_stopping = CancellationToken::new();
        let coverage = match coverage_configuration {
            Some(configuration) => Some(
                configuration
                    .open_with_identity(
                        query_auth.request_timeout,
                        coverage_stopping.clone(),
                        identity.clone(),
                        query_audit.clone(),
                    )
                    .await?,
            ),
            None => None,
        };
        let pipeline = Arc::new(PipelineSink {
            audit: query_audit.clone(),
            buffer: sink.clone(),
            store: store.clone(),
            query: Some(query.clone()),
            detection: Some(detection),
            logging: Some(logger.writer()),
            coverage: coverage.as_ref().map(|state| state.store.clone()),
        });
        let service = IngestService::new_with_security(
            config,
            pipeline.clone(),
            identity.clone(),
            query_audit
                .as_ref()
                .and_then(|control| control.ingest_auditor()),
        )?;
        let query_cancel = service.cancellation();
        let mut router = service
            .router()
            .merge(query_api::router_with_identity(
                query.clone(),
                query_auth.clone(),
                query_limit,
                query_timeout,
                query_cancel.clone(),
                identity.clone(),
                query_audit.clone(),
            ))
            .merge(finding_api::router_with_security(
                findings.clone(),
                query_auth,
                finding_limit,
                finding_bytes,
                finding_timeout,
                query_cancel.clone(),
                finding_api::Security {
                    identity: identity.clone(),
                    audit: query_audit.clone(),
                },
            ))
            .merge(ui::router());
        if let Some(coverage) = &coverage {
            let routes = coverage.router();
            router = router.merge(routes);
        }
        let listener = timeout(Duration::from_secs(5), TcpListener::bind(listen))
            .await
            .map_err(|_| AppError::BindTimeout)?
            .map_err(AppError::Bind)?;
        let metrics_listener = match metrics_listen {
            Some(address) => Some(
                timeout(Duration::from_secs(5), TcpListener::bind(address))
                    .await
                    .map_err(|_| AppError::BindTimeout)?
                    .map_err(AppError::Bind)?,
            ),
            None => None,
        };
        Ok::<_, AppError>((
            service,
            sink,
            store,
            findings,
            query,
            identity,
            coverage,
            coverage_stopping,
            pipeline,
            consumer_config,
            query_cancel,
            listener,
            metrics_listener,
            limits,
            tls,
            router,
            runtime_revision,
            rules_revision,
        ))
    };
    let prepared = if query_audit
        .as_ref()
        .is_some_and(|control| control.has_activations())
    {
        let guarded = audit::within_startup(&startup, preparation);
        #[cfg(unix)]
        let result = tokio::select! {
            biased;
            _ = terminate.recv() => Err(audit::Unavailable.into()),
            _ = interrupt.recv() => Err(audit::Unavailable.into()),
            result = guarded => result,
        };
        #[cfg(not(unix))]
        let result = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => Err(audit::Unavailable.into()),
            result = guarded => result,
        };
        result
    } else {
        preparation.await
    };
    let (
        service,
        sink,
        store,
        findings,
        query,
        identity,
        coverage,
        coverage_stopping,
        pipeline,
        consumer_config,
        query_cancel,
        listener,
        metrics_listener,
        limits,
        tls,
        router,
        runtime_revision,
        rules_revision,
    ) = prepared?;
    if let Some(control) = query_audit
        .as_ref()
        .filter(|control| control.has_activations())
    {
        let activate = async {
            if let Some(revision) = runtime_revision {
                control
                    .activate(
                        signal_protocol::audit::ConfigurationKind::Runtime,
                        revision,
                        startup.clone(),
                    )
                    .await?;
            }
            if let Some(revision) = rules_revision {
                control
                    .activate(
                        signal_protocol::audit::ConfigurationKind::Rules,
                        revision,
                        startup.clone(),
                    )
                    .await?;
            }
            startup.check().map_err(|_| audit::Unavailable)
        };
        #[cfg(unix)]
        let activated = tokio::select! {
            biased;
            _ = terminate.recv() => Err(audit::Unavailable),
            _ = interrupt.recv() => Err(audit::Unavailable),
            result = activate => result,
        };
        #[cfg(not(unix))]
        let activated = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => Err(audit::Unavailable),
            result = activate => result,
        };
        // Recheck after the ready select handoff, before enabling any work.
        let activated = activated.and_then(|()| startup.check().map_err(|_| audit::Unavailable));
        if let Err(error) = activated {
            startup_cancellation.cancel();
            service.stop_admission();
            coverage_stopping.cancel();
            if let Some(identity) = &identity {
                let _ = identity.close();
            }
            // Cleanup has a separate finite budget; it cannot renew activation.
            let deadline = Instant::now() + limits.shutdown_timeout;
            let _ = query
                .shutdown(OperationContext {
                    deadline,
                    cancellation: CancellationToken::new(),
                })
                .await;
            let _ = store
                .shutdown(OperationContext {
                    deadline,
                    cancellation: CancellationToken::new(),
                })
                .await;
            let _ = findings
                .shutdown(FindingContext {
                    deadline,
                    cancellation: CancellationToken::new(),
                })
                .await;
            if let Some(coverage) = &coverage {
                let _ = coverage
                    .store
                    .shutdown(signal_coverage::OperationContext {
                        deadline,
                        cancellation: CancellationToken::new(),
                    })
                    .await;
            }
            let _ = timeout_at(deadline, sink.shutdown()).await;
            return Err(error.into());
        }
    }
    let drain = CancellationToken::new();
    let cancel = CancellationToken::new();
    let failed = CancellationToken::new();
    let consumer = tokio::spawn(pipeline::consume(
        pipeline,
        consumer_config,
        drain.clone(),
        cancel.clone(),
        failed.clone(),
    ));
    tracing::warn!(listen = %listener.local_addr().map_err(AppError::Bind)?, queue_capacity = sink.metrics().capacity, "durable ingest and Parquet storage ready");
    let shutdown = async {
        #[cfg(unix)]
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {}, _ = failed.cancelled() => {} }
        #[cfg(not(unix))]
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("shutdown signal failed");
        }
    };
    let transport_stopping = service.cancellation();
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let transport = async {
        let api = server::serve_router_with_tls_budget(
            listener,
            service.clone(),
            router,
            limits,
            permits.clone(),
            tls.clone(),
            std::future::pending::<()>(),
        );
        if let Some(metrics_listener) = metrics_listener {
            let metrics = server::serve_router_with_tls_budget(
                metrics_listener,
                service.clone(),
                service.metrics_router(),
                limits,
                permits,
                tls,
                std::future::pending::<()>(),
            );
            let (api, metrics) = tokio::join!(api, metrics);
            api.and(metrics)
        } else {
            api.await
        }
    };
    tokio::pin!(transport);
    let finished = tokio::select! {
        biased;
        _ = shutdown => None,
        _ = transport_stopping.cancelled() => None,
        result = &mut transport => Some(result),
    };
    let deadline = Instant::now() + limits.shutdown_timeout;
    service.stop_admission();
    let identity_closed = match &identity {
        Some(identity) => identity.close().map_err(AppError::from),
        None => Ok(()),
    };
    coverage_stopping.cancel();
    let result = match finished {
        Some(result) => result,
        None => timeout_at(deadline, &mut transport)
            .await
            .unwrap_or(Err(server::ServerError::ShutdownTimeout)),
    };
    query_cancel.cancel();
    coverage_stopping.cancel();
    service.stop_admission();
    let query_stopped = query
        .shutdown(OperationContext {
            deadline,
            cancellation: CancellationToken::new(),
        })
        .await;
    let stopped = stop_pipeline(
        &sink,
        &store,
        consumer,
        drain,
        cancel,
        deadline,
        query_stopped.is_ok(),
    )
    .await;
    let findings_flushed = if stopped.is_ok() {
        findings
            .flush(FindingContext {
                deadline,
                cancellation: CancellationToken::new(),
            })
            .await
    } else {
        Ok(())
    };
    let findings_stopped = findings
        .shutdown(FindingContext {
            deadline,
            cancellation: CancellationToken::new(),
        })
        .await;
    let coverage_stopped = match &coverage {
        Some(coverage) => coverage
            .store
            .shutdown(signal_coverage::OperationContext {
                deadline,
                cancellation: CancellationToken::new(),
            })
            .await
            .map_err(AppError::from),
        None => Ok(()),
    };
    let identity_stopped = match &identity {
        Some(identity) => identity.shutdown(deadline).await.map_err(AppError::from),
        None => Ok(()),
    };
    tracing::info!(
        pending_events = sink.metrics().depth,
        persisted_sequence = store.metrics().high_water,
        "ingest stopped; persisted events checkpointed, unfinished events remain in WAL"
    );
    let result = result
        .map_err(AppError::from)
        .and(stopped)
        .and(findings_flushed.map_err(AppError::from))
        .and(findings_stopped.map_err(AppError::from))
        .and(query_stopped.map_err(AppError::from))
        .and(identity_closed)
        .and(identity_stopped)
        .and(coverage_stopped);
    if let Err(error) = &result {
        logger.writer().report_error(error);
    }
    let logging_stopped = logger.shutdown(deadline).await;
    result.map_err(|error| AppError::Reported(Box::new(error)))?;
    logging_stopped.map_err(|error| AppError::Reported(Box::new(error.into())))?;
    Ok(())
}

async fn stop_pipeline(
    sink: &DurableBuffer,
    store: &Backend,
    mut consumer: tokio::task::JoinHandle<Result<(), pipeline::PipelineError>>,
    drain: CancellationToken,
    cancel: CancellationToken,
    deadline: Instant,
    release_source: bool,
) -> Result<(), AppError> {
    drain.cancel();
    // Retain the handle through the deadline. Cancelling never starts a second disk worker.
    let consumed = match timeout_at(deadline, &mut consumer).await {
        Ok(joined) => match joined {
            Ok(result) => result.map_err(AppError::from),
            Err(_) => Err(AppError::ConsumerTask),
        },
        Err(_) => {
            cancel.cancel();
            consumer.abort();
            let _ = consumer.await;
            Err(AppError::DrainTimeout)
        }
    };
    let flushed = if consumed.is_ok() && release_source {
        store
            .flush(OperationContext {
                deadline,
                cancellation: CancellationToken::new(),
            })
            .await
    } else {
        Ok(())
    };
    let storage_stopped = if release_source {
        store
            .shutdown(OperationContext {
                deadline,
                cancellation: CancellationToken::new(),
            })
            .await
    } else {
        // Physical query jobs retain the source through error/drop cleanup.
        // Explicit source shutdown would release its owner before those jobs exit.
        Err(StorageError::Timeout)
    };
    let wal_stopped = timeout_at(deadline, sink.shutdown())
        .await
        .map_err(|_| AppError::DrainTimeout);
    consumed?;
    flushed?;
    storage_stopped?;
    wal_stopped??;
    Ok(())
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn stalled_consumer_has_one_shutdown_budget_and_keeps_wal_replayable() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let config = BufferConfig {
            directory: temp.path().join("wal"),
            ..Default::default()
        };
        let sink = DurableBuffer::open(config.clone()).await?;
        let input: signal_event::IngestEvent = serde_json::from_str(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"shutdown-test"},"message":"unfinished"}"#,
        )?;
        let observed = input.timestamp;
        let event = input.normalize(observed)?;
        sink.admit(event.clone()).await?;
        let store = Backend::local(
            signal_storage::ParquetStore::open(
                StorageConfig {
                    directory: temp.path().join("events"),
                    ..Default::default()
                },
                sink.snapshot().stream_id,
            )
            .await?,
        );
        let consumer = tokio::spawn(std::future::pending::<Result<(), pipeline::PipelineError>>());
        sink.close();
        let started = Instant::now();
        let result = stop_pipeline(
            &sink,
            &store,
            consumer,
            CancellationToken::new(),
            CancellationToken::new(),
            started + Duration::from_millis(50),
            true,
        )
        .await;
        assert!(matches!(result, Err(AppError::DrainTimeout)));
        assert!(started.elapsed() < Duration::from_millis(300));
        assert_eq!(sink.snapshot().checkpoint, 0);
        assert_eq!(store.metrics().high_water, 0);
        // Fixed workers finish their shutdown without creating replacement workers.
        sink.shutdown().await?;
        store
            .shutdown(OperationContext::new(Duration::from_secs(2)))
            .await?;
        let replay = DurableBuffer::open(config).await?;
        assert_eq!(replay.read_batch(1, 4096).await?[0].event, event);
        replay.shutdown().await?;
        Ok(())
    }
}

//! HTTP ingest, bounded WAL, replay-safe Parquet persistence and URL queries.
mod config;
mod coverage_api;
mod finding_api;
mod logging;
mod pipeline;
mod query_api;
mod storage;
mod ui;
use config::Settings;
use logging::{LoggerGuard, LoggingConfig};
use pipeline::{ConsumerConfig, DetectionPipeline, PipelineSink};
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_findings::{FindingConfig, FindingContext, FindingStore};
use signal_ingest::{
    ConfigError, IngestConfig, IngestService,
    server::{self, ServerLimits},
};
use signal_protocol::EventSink;
use signal_query::{QueryConfig, QueryEngine, QueryError};
use signal_rules::{RuleContext, RuleLimits, RuleSet};
use signal_storage::{OperationContext, StorageConfig, StorageError};
use std::{
    env,
    net::SocketAddr,
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
    let mut initialize_coverage = false;
    let path = match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("signal-server {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        [flag] if flag == "--help" => {
            println!(
                "signal-server: durable HTTP ingest, Parquet storage and URL queries\nUsage: signal-server [--config PATH | --initialize-coverage [--config PATH] | --help | --version]\nConfiguration: see docs/12-phase3-storage.md and docs/13-phase4-query.md. SIGNAL_LISTEN, SIGNAL_API_TOKEN, SIGNAL_WAL_DIR, SIGNAL_ADMISSION_POLICY and bounded HTTP/WAL limits.\nAccepted events are synced to WAL, then persisted to Parquet before checkpointing. GET /v1/events and /v1/findings query persisted data. SIGNAL_CONFIG loads strict versioned YAML; environment overrides YAML."
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
    let config = IngestConfig {
        max_request_bytes: settings.number("SIGNAL_MAX_REQUEST_BYTES", 1_048_576)?,
        max_batch_events: settings.number("SIGNAL_MAX_BATCH_EVENTS", 1000)?,
        max_in_flight: settings.number("SIGNAL_MAX_IN_FLIGHT", 64)?,
        request_timeout: Duration::from_millis(
            settings.number("SIGNAL_REQUEST_TIMEOUT_MS", 5000)? as u64
        ),
        api_token: settings.optional("SIGNAL_API_TOKEN")?,
    };
    let limits = ServerLimits {
        max_connections: settings.number("SIGNAL_MAX_CONNECTIONS", 128)?,
        connection_timeout: Duration::from_millis(
            settings.number("SIGNAL_CONNECTION_TIMEOUT_MS", 60_000)? as u64,
        ),
        shutdown_timeout: Duration::from_millis(
            settings.number("SIGNAL_SHUTDOWN_TIMEOUT_MS", 10_000)? as u64,
        ),
    };
    config.validate()?;
    limits.validate()?;
    let coverage_configuration = coverage_api::Configuration::load(&settings).await?;
    let listen: SocketAddr = settings
        .optional("SIGNAL_LISTEN")?
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
        .parse()
        .map_err(|_| AppError::Environment("SIGNAL_LISTEN"))?;
    let metrics_listen: Option<SocketAddr> = settings
        .optional("SIGNAL_METRICS_LISTEN")?
        .map(|value| {
            value
                .parse()
                .map_err(|_| AppError::Environment("SIGNAL_METRICS_LISTEN"))
        })
        .transpose()?;
    let metrics_listen = metrics_listen.filter(|address| *address != listen);
    if metrics_listen.is_some() && limits.max_connections < 2 {
        return Err(ConfigError::Invalid(
            "separate metrics listener requires at least two connection slots",
        )
        .into());
    }
    let wal_config = BufferConfig {
        directory: settings
            .optional("SIGNAL_WAL_DIR")?
            .unwrap_or_else(|| "data/wal".to_owned())
            .into(),
        max_events: settings.number("SIGNAL_MEMORY_EVENTS", 10_000)?,
        max_memory_bytes: settings.number("SIGNAL_MEMORY_BYTES", 67_108_864)?,
        max_record_bytes: settings.number("SIGNAL_WAL_RECORD_BYTES", 2_097_152)?,
        max_wal_bytes: settings.number("SIGNAL_WAL_BYTES", 268_435_456)? as u64,
        segment_bytes: settings.number("SIGNAL_WAL_SEGMENT_BYTES", 8_388_608)? as u64,
        max_segments: settings.number("SIGNAL_WAL_SEGMENTS", 128)?,
        command_capacity: settings.number("SIGNAL_WAL_COMMANDS", 64)?,
        max_waiters: settings.number("SIGNAL_WAL_WAITERS", 64)?,
        policy: settings
            .optional("SIGNAL_ADMISSION_POLICY")?
            .unwrap_or_else(|| "reject_new".to_owned())
            .parse()?,
        operation_timeout: Duration::from_millis(
            settings.number("SIGNAL_WAL_TIMEOUT_MS", 5000)? as u64
        ),
        block_timeout: Duration::from_millis(
            settings.number("SIGNAL_WAL_BLOCK_TIMEOUT_MS", 1000)? as u64
        ),
    };
    let storage_config = StorageConfig {
        directory: settings
            .optional("SIGNAL_STORAGE_DIR")?
            .unwrap_or_else(|| "data/events".to_owned())
            .into(),
        max_batch_events: settings.number("SIGNAL_STORAGE_BATCH_EVENTS", 1000)?,
        max_batch_bytes: settings.number("SIGNAL_STORAGE_BATCH_BYTES", 8_388_608)?,
        max_event_bytes: settings.number("SIGNAL_STORAGE_EVENT_BYTES", 2_097_152)?,
        max_disk_bytes: settings.number("SIGNAL_STORAGE_BYTES", 1_073_741_824)? as u64,
        max_files: settings.number("SIGNAL_STORAGE_FILES", 100_000)?,
        command_capacity: settings.number("SIGNAL_STORAGE_COMMANDS", 8)?,
        operation_timeout: Duration::from_millis(
            settings.number("SIGNAL_STORAGE_TIMEOUT_MS", 120_000)? as u64,
        ),
        compression: settings
            .optional("SIGNAL_STORAGE_COMPRESSION")?
            .unwrap_or_else(|| "snappy".to_owned())
            .parse()?,
    };
    let query_config = QueryConfig {
        memory_bytes: settings.number("SIGNAL_QUERY_MEMORY_BYTES", 268_435_456)?,
        max_concurrent: settings.number("SIGNAL_QUERY_CONCURRENCY", 4)?,
        max_files: settings.number("SIGNAL_QUERY_FILES", 1024)?,
        max_limit: settings.number("SIGNAL_QUERY_LIMIT", 1000)?,
        max_response_bytes: settings.number("SIGNAL_QUERY_RESPONSE_BYTES", 8_388_608)?,
        batch_rows: settings.number("SIGNAL_QUERY_BATCH_ROWS", 128)?,
        target_partitions: settings.number("SIGNAL_QUERY_PARTITIONS", 1)?,
        timeout: Duration::from_millis(settings.number("SIGNAL_QUERY_TIMEOUT_MS", 10_000)? as u64),
    };
    query_config.validate()?;
    let query_timeout = query_config.timeout.min(config.request_timeout);
    let query_limit = query_config.max_limit;
    wal_config.validate()?;
    storage_config.validate()?;
    let consumer_config = ConsumerConfig {
        max_events: storage_config.max_batch_events.min(wal_config.max_events),
        max_bytes: storage_config
            .max_batch_bytes
            .min(wal_config.max_memory_bytes),
        operation_timeout: storage_config.operation_timeout,
        flush_interval: Duration::from_millis(
            settings.number("SIGNAL_STORAGE_FLUSH_MS", 1000)? as u64
        ),
    };
    if consumer_config.flush_interval.is_zero()
        || consumer_config.flush_interval > Duration::from_secs(60)
    {
        return Err(StorageError::Config("storage flush interval must be 1..60000ms").into());
    }
    if storage_config.max_event_bytes < wal_config.max_record_bytes
        || consumer_config.max_bytes < wal_config.max_record_bytes
    {
        return Err(StorageError::Config("storage limits must fit the maximum WAL record").into());
    }
    let finding_config = FindingConfig {
        directory: settings
            .optional("SIGNAL_FINDINGS_DIR")?
            .unwrap_or_else(|| "data/findings".into())
            .into(),
        max_disk_bytes: settings.number("SIGNAL_FINDINGS_BYTES", 268_435_456)? as u64,
        max_findings: settings.number("SIGNAL_FINDINGS_MAX_FINDINGS", 100_000)?,
        max_record_bytes: settings.number("SIGNAL_FINDINGS_RECORD_BYTES", 65_536)?,
        max_append_rows: settings.number("SIGNAL_FINDINGS_BATCH_EVENTS", 1000)?,
        max_append_bytes: settings.number("SIGNAL_FINDINGS_BATCH_BYTES", 1_048_576)?,
        max_query_rows: settings.number("SIGNAL_FINDINGS_QUERY_LIMIT", 1000)?,
        max_query_bytes: settings.number("SIGNAL_FINDINGS_QUERY_BYTES", 8_388_608)?,
        max_index_bytes: settings.number("SIGNAL_FINDINGS_INDEX_BYTES", 16_777_216)?,
        command_capacity: settings.number("SIGNAL_FINDINGS_COMMANDS", 8)?,
        operation_timeout: Duration::from_millis(
            settings.number("SIGNAL_FINDINGS_TIMEOUT_MS", 5000)? as u64,
        ),
    };
    finding_config.validate_feed()?;
    let finding_limit = finding_config.max_query_rows;
    let finding_bytes = finding_config.max_query_bytes;
    let finding_timeout = finding_config.operation_timeout.min(config.request_timeout);
    let max_finding_rows = finding_config.max_append_rows;
    let max_finding_bytes = finding_config.max_append_bytes;
    let rule_limits = RuleLimits {
        max_rules: settings.number("SIGNAL_RULES_MAX_RULES", 256)?,
        max_directory_entries: settings.number("SIGNAL_RULES_MAX_DIRECTORY_ENTRIES", 4096)?,
        max_document_bytes: settings.number("SIGNAL_RULES_MAX_DOCUMENT_BYTES", 65_536)?,
        max_total_bytes: settings.number("SIGNAL_RULES_MAX_TOTAL_BYTES", 4_194_304)?,
        max_predicates: settings.number("SIGNAL_RULES_MAX_PREDICATES", 128)?,
        max_value_nodes: settings.number("SIGNAL_RULES_MAX_VALUE_NODES", 4096)?,
        max_depth: settings.number("SIGNAL_RULES_MAX_DEPTH", 32)?,
        max_field_bytes: settings.number("SIGNAL_RULES_MAX_FIELD_BYTES", 512)?,
        max_title_bytes: settings.number("SIGNAL_RULES_MAX_TITLE_BYTES", 4096)?,
    };
    let rule_timeout_ms = settings.number("SIGNAL_RULES_TIMEOUT_MS", 5000)?;
    if !(1..=300_000).contains(&rule_timeout_ms) {
        return Err(ConfigError::Invalid("rule load timeout must be 1..300000ms").into());
    }
    let rules = RuleSet::load(
        &settings.rules_directories()?,
        rule_limits,
        RuleContext::new(Duration::from_millis(rule_timeout_ms as u64)),
    )
    .await?;
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
        return Err(
            StorageError::Config("storage high water and WAL checkpoint are incompatible").into(),
        );
    }
    let findings = Arc::new(FindingStore::open(finding_config, wal.stream_id).await?);
    let detection = Arc::new(DetectionPipeline {
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
                .open(query_auth.request_timeout, coverage_stopping.clone())
                .await?,
        ),
        None => None,
    };
    let pipeline = Arc::new(PipelineSink {
        buffer: sink.clone(),
        store: store.clone(),
        query: Some(query.clone()),
        detection: Some(detection),
        logging: Some(logger.writer()),
        coverage: coverage.as_ref().map(|state| state.store.clone()),
    });
    let service = IngestService::new(config, pipeline.clone())?;
    let query_cancel = service.cancellation();
    let mut router = service
        .router()
        .merge(query_api::router(
            query.clone(),
            query_auth.clone(),
            query_limit,
            query_timeout,
            query_cancel.clone(),
        ))
        .merge(finding_api::router(
            findings.clone(),
            query_auth,
            finding_limit,
            finding_bytes,
            finding_timeout,
            query_cancel.clone(),
        ))
        .merge(ui::router());
    if let Some(coverage) = &coverage {
        router = router.merge(coverage.router());
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
    // Install signal handlers before readiness; setup failure cannot leave a running server.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(AppError::Signal)?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(AppError::Signal)?;
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
        let api = server::serve_router_with_budget(
            listener,
            service.clone(),
            router,
            limits,
            permits.clone(),
            std::future::pending::<()>(),
        );
        if let Some(metrics_listener) = metrics_listener {
            let metrics = server::serve_router_with_budget(
                metrics_listener,
                service.clone(),
                service.metrics_router(),
                limits,
                permits,
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

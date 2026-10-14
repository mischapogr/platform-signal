//! Validated common server controls captured once before either runtime opens.
use crate::{AppError, access, config::Settings, coverage_api, pipeline::ConsumerConfig, tls};
use signal_buffer::BufferConfig;
use signal_findings::FindingConfig;
use signal_ingest::{ConfigError, IngestConfig, server::ServerLimits};
use signal_query::QueryConfig;
use signal_rules::{RuleContext, RuleLimits, RuleSet};
use signal_storage::{StorageConfig, StorageError};
use std::{net::SocketAddr, time::Duration};
pub(crate) struct RuntimeConfig {
    pub config: IngestConfig,
    pub limits: ServerLimits,
    pub tls: Option<signal_ingest::tls::ServerTls>,
    pub identity: Option<signal_ingest::identity::IdentityBackend>,
    pub coverage_configuration: Option<coverage_api::Configuration>,
    pub onboarding: Option<std::sync::Arc<crate::onboarding::Host>>,
    pub window_configuration: Option<crate::window::Configuration>,
    pub sensor_configuration: Option<crate::sensor_runtime::Configuration>,
    pub listen: SocketAddr,
    pub metrics_listen: Option<SocketAddr>,
    pub wal_config: BufferConfig,
    pub storage_config: StorageConfig,
    pub query_config: QueryConfig,
    pub query_timeout: Duration,
    pub query_limit: usize,
    pub consumer_config: ConsumerConfig,
    pub finding_config: FindingConfig,
    pub finding_limit: usize,
    pub finding_bytes: usize,
    pub finding_timeout: Duration,
    pub max_finding_rows: usize,
    pub max_finding_bytes: usize,
    pub rule_limits: RuleLimits,
    pub rule_timeout_ms: usize,
    pub rules: RuleSet,
}
pub(crate) async fn load(settings: &Settings) -> Result<RuntimeConfig, AppError> {
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
    let tls = tls::load(settings).await?;
    let identity_configuration = access::Configuration::load(settings).await?;
    let coverage_configuration = coverage_api::Configuration::load(settings).await?;
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
        rule_limits.clone(),
        RuleContext::new(Duration::from_millis(rule_timeout_ms as u64)),
    )
    .await?;
    // Validate provider transport/policy before opening persistence or readiness.
    let window_configuration = crate::window::Configuration::load(settings).await?;
    let sensor_configuration = crate::sensor_runtime::Configuration::load(settings).await?;
    if let Some(sensor) = &sensor_configuration {
        if identity_configuration.is_none() {
            return Err(ConfigError::Invalid("sensor health requires native identity").into());
        }
        if settings.optional("SIGNAL_SHARED_CONFIG")?.is_some() {
            return Err(
                ConfigError::Invalid("shared sensor health integration is not qualified").into(),
            );
        }
        if wal_config.policy == signal_buffer::Policy::DropOldest {
            return Err(
                ConfigError::Invalid("sensor health requires continuous WAL delivery").into(),
            );
        }
        if rules
            .rule_ids()
            .any(|id| id == sensor.detector.policy.rule_id)
            || window_configuration
                .as_ref()
                .is_some_and(|w| w.policy.rule_id == sensor.detector.policy.rule_id)
        {
            return Err(ConfigError::Invalid("duplicate sensor health rule ID").into());
        }
    }
    if window_configuration
        .as_ref()
        .is_some_and(|w| w.shared().is_some())
        && settings.optional("SIGNAL_SHARED_CONFIG")?.is_none()
    {
        return Err(ConfigError::Invalid("shared window requires Standard runtime").into());
    }
    if window_configuration.is_some() {
        if settings.optional("SIGNAL_SHARED_CONFIG")?.is_some()
            && window_configuration
                .as_ref()
                .is_some_and(|w| w.shared().is_none())
        {
            return Err(ConfigError::Invalid("Standard window requires shared persistence").into());
        }
        if wal_config.policy == signal_buffer::Policy::DropOldest {
            return Err(ConfigError::Invalid("window requires continuous WAL delivery").into());
        }
    }
    let onboarding = match &window_configuration {
        Some(window) => {
            crate::onboarding::Host::load_with_detection(
                settings,
                &rules,
                Some(&window.policy.rule_id),
            )
            .await?
        }
        None => crate::onboarding::Host::load(settings, &rules).await?,
    };
    if window_configuration.is_some() && onboarding.is_none() {
        return Err(ConfigError::Invalid("window requires independent onboarding coverage").into());
    }
    if let Some(host) = &onboarding {
        if identity_configuration.is_none() {
            return Err(ConfigError::Invalid("onboarding requires native identity").into());
        }
        coverage_configuration
            .as_ref()
            .ok_or(ConfigError::Invalid("onboarding requires scoped coverage"))?
            .validate_onboarding(host)?;
    }
    let identity = identity_configuration
        .map(access::Configuration::open)
        .transpose()?;
    Ok(RuntimeConfig {
        config,
        limits,
        tls,
        identity,
        coverage_configuration,
        onboarding,
        window_configuration,
        sensor_configuration,
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
    })
}

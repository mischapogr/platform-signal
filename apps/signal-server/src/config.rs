//! Strict version 1 settings. Environment overrides YAML without changing process env.
use serde::{
    Deserialize, Deserializer,
    de::{self, Visitor},
};
use std::{
    collections::BTreeMap,
    env, fmt,
    fs::{self, File},
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    thread,
};
use thiserror::Error;
use tokio::{
    sync::{Semaphore, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const MAX_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_BYTES: usize = 512 * 1024;
const MAX_RULE_DIRECTORIES: usize = 64;
static WORKER: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);
static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid server configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid configuration environment variable {0}")]
    Environment(&'static str),
    #[error("configuration file read failed")]
    Io,
    #[error("configuration read deadline exceeded")]
    Timeout,
    #[error("configuration read cancelled")]
    Cancelled,
    #[error("configuration worker unavailable")]
    Unavailable,
    #[error("configuration worker capacity is full")]
    Full,
}
// No Debug or Display implementation can expose configuration strings or tokens.
struct Text(String);
struct Count(usize);
impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct StringVisitor;
        impl Visitor<'_> for StringVisitor {
            type Value = Text;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Text, E> {
                Ok(Text(value.to_owned()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Text, E> {
                Ok(Text(value))
            }
        }
        de.deserialize_any(StringVisitor)
    }
}
impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct NumberVisitor;
        impl Visitor<'_> for NumberVisitor {
            type Value = Count;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a positive integer")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Count, E> {
                let value = usize::try_from(value).map_err(|_| E::custom("integer capacity"))?;
                if value == 0 {
                    return Err(E::custom("positive capacity"));
                }
                Ok(Count(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Count, E> {
                self.visit_u64(u64::try_from(value).map_err(|_| E::custom("positive capacity"))?)
            }
        }
        de.deserialize_any(NumberVisitor)
    }
}
fn non_null<'de, D: Deserializer<'de>, T: Deserialize<'de>>(de: D) -> Result<Option<T>, D::Error> {
    T::deserialize(de).map(Some)
}
fn version<'de, D: Deserializer<'de>>(de: D) -> Result<u16, D::Error> {
    let Count(value) = Count::deserialize(de)?;
    u16::try_from(value).map_err(|_| de::Error::custom("schema version capacity"))
}
fn section_map<'de, D: Deserializer<'de>, T: Deserialize<'de>>(de: D) -> Result<T, D::Error> {
    struct MapVisitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for MapVisitor<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a configuration mapping")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    de.deserialize_any(MapVisitor(std::marker::PhantomData))
}
macro_rules! section {
    ($name:ident { $($(#[$meta:meta])* $field:ident:$kind:ty),* $(,)? }) => {
        #[derive(Default,Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name { $( $(#[$meta])* #[serde(default,deserialize_with="non_null")] $field:Option<$kind>, )* }
    };
}
section!(Server {
    listen: Text,
    tls_config: Text,
    max_connections: Count,
    connection_timeout: Text,
    connection_timeout_ms: Count,
    shutdown_timeout: Text,
    shutdown_timeout_ms: Count,
});
section!(Ingest {
    max_request_bytes: Count,
    max_batch_events: Count,
    max_in_flight: Count,
    request_timeout: Text,
    request_timeout_ms: Count,
    api_token_env: Text,
    api_token: Text,
});
section!(Buffer {
    wal_directory: Text,
    #[serde(alias = "max_events")]
    memory_events: Count,
    #[serde(alias = "max_memory_bytes")]
    memory_bytes: Count,
    max_record_bytes: Count,
    max_wal_bytes: Count,
    segment_bytes: Count,
    max_segments: Count,
    command_capacity: Count,
    max_waiters: Count,
    #[serde(alias = "policy")]
    admission_policy: Text,
    operation_timeout: Text,
    operation_timeout_ms: Count,
    block_timeout: Text,
    block_timeout_ms: Count,
});
section!(Storage {
    #[serde(rename = "type")]
    storage_type: Text,
    directory: Text,
    s3_endpoint: Text,
    s3_region: Text,
    s3_bucket: Text,
    s3_backend_id: Text,
    s3_cache_directory: Text,
    s3_cache_files: Count,
    s3_cache_bytes: Count,
    s3_object_bytes: Count,
    s3_inventory_objects: Count,
    s3_catalog_bytes: Count,
    s3_allow_loopback_http: Text,
    s3_kms_key_id: Text,
    s3_bucket_key: Text,
    #[serde(alias = "max_batch_events")]
    flush_events: Count,
    max_batch_bytes: Count,
    max_event_bytes: Count,
    max_disk_bytes: Count,
    max_files: Count,
    command_capacity: Count,
    operation_timeout: Text,
    operation_timeout_ms: Count,
    compression: Text,
    flush_interval: Text,
    #[serde(alias = "flush_ms")]
    flush_interval_ms: Count,
});
section!(Query {
    memory_bytes: Count,
    #[serde(alias = "concurrency")]
    max_concurrent: Count,
    max_files: Count,
    max_limit: Count,
    max_response_bytes: Count,
    batch_rows: Count,
    target_partitions: Count,
    timeout: Text,
    timeout_ms: Count,
});
section!(Rules {
    directories: Vec<Text>,
    max_rules: Count,
    max_directory_entries: Count,
    #[serde(alias = "max_rule_bytes")]
    max_document_bytes: Count,
    max_total_bytes: Count,
    #[serde(alias = "max_nodes")]
    max_value_nodes: Count,
    max_depth: Count,
    max_predicates: Count,
    max_field_bytes: Count,
    max_title_bytes: Count,
    timeout: Text,
    timeout_ms: Count,
});
section!(Findings {
    directory: Text,
    max_disk_bytes: Count,
    max_findings: Count,
    max_record_bytes: Count,
    #[serde(alias = "max_batch_events")]
    max_append_rows: Count,
    #[serde(alias = "max_batch_bytes")]
    max_append_bytes: Count,
    #[serde(alias = "max_query_limit")]
    max_query_rows: Count,
    max_query_bytes: Count,
    max_index_bytes: Count,
    command_capacity: Count,
    operation_timeout: Text,
    operation_timeout_ms: Count,
});
section!(Telemetry {
    metrics_listen: Text,
    queue_records: Count,
    queue_bytes: Count,
    max_record_bytes: Count,
});
section!(Coverage { config: Text });
section!(Access { config: Text });
section!(Audit { config: Text });
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(deserialize_with = "version")]
    schema_version: u16,
    #[serde(default, deserialize_with = "section_map")]
    server: Server,
    #[serde(default, deserialize_with = "section_map")]
    ingest: Ingest,
    #[serde(default, deserialize_with = "section_map")]
    buffer: Buffer,
    #[serde(default, deserialize_with = "section_map")]
    storage: Storage,
    #[serde(default, deserialize_with = "section_map")]
    query: Query,
    #[serde(default, deserialize_with = "section_map")]
    rules: Rules,
    #[serde(default, deserialize_with = "section_map")]
    findings: Findings,
    #[serde(default, deserialize_with = "section_map")]
    telemetry: Telemetry,
    #[serde(default, deserialize_with = "section_map")]
    coverage: Coverage,
    #[serde(default, deserialize_with = "section_map")]
    access: Access,
    #[serde(default, deserialize_with = "section_map")]
    audit: Audit,
}
trait Value {
    fn setting_value(&self) -> String;
}
impl Value for Text {
    fn setting_value(&self) -> String {
        self.0.clone()
    }
}
impl Value for Count {
    fn setting_value(&self) -> String {
        self.0.to_string()
    }
}
fn put<T: Value>(
    values: &mut BTreeMap<&'static str, String>,
    name: &'static str,
    value: Option<&T>,
) {
    if let Some(value) = value {
        values.insert(name, value.setting_value());
    }
}
macro_rules! mapping {
    ($values:ident,$section:expr,{$($field:ident=>$env:literal),* $(,)?}) => {$(put(&mut $values,$env,$section.$field.as_ref());)*};
}
fn duration(
    values: &mut BTreeMap<&'static str, String>,
    name: &'static str,
    text: Option<&Text>,
    ms: Option<&Count>,
    max: usize,
) -> Result<(), ConfigError> {
    if text.is_some() && ms.is_some() {
        return Err(ConfigError::Invalid("conflicting duration fields"));
    }
    let value = if let Some(text) = text {
        let (digits, multiplier) = if let Some(n) = text.0.strip_suffix("ms") {
            (n, 1usize)
        } else if let Some(n) = text.0.strip_suffix('s') {
            (n, 1000usize)
        } else {
            return Err(ConfigError::Invalid("duration unit"));
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ConfigError::Invalid("duration format"));
        }
        Some(
            digits
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_mul(multiplier))
                .ok_or(ConfigError::Invalid("duration capacity"))?,
        )
    } else {
        ms.map(|ms| ms.0)
    };
    if let Some(value) = value {
        if value == 0 || value > max {
            return Err(ConfigError::Invalid("duration bounds"));
        }
        values.insert(name, value.to_string());
    }
    Ok(())
}
fn environment(name: &str) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(value) if value.len() <= MAX_BYTES => Ok(Some(value)),
        Ok(_) => Err(ConfigError::Invalid("environment value capacity")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(ConfigError::Invalid("environment encoding")),
    }
}
enum Environment {
    Live,
    #[cfg(test)]
    Injected(BTreeMap<String, String>),
}
impl Environment {
    fn get(&self, name: &str) -> Result<Option<String>, ConfigError> {
        match self {
            Self::Live => environment(name),
            #[cfg(test)]
            Self::Injected(values) => Ok(values.get(name).cloned()),
        }
    }
}
/// Resolved YAML values with direct environment precedence. Deliberately not Debug.
pub struct Settings {
    values: BTreeMap<&'static str, String>,
    directories: Vec<PathBuf>,
    token_env: Option<String>,
    environment: Environment,
}
impl Settings {
    #[cfg(test)]
    pub(crate) fn for_test(yaml: &str, entries: &[(&str, &str)]) -> Result<Self, ConfigError> {
        Self::from_document(
            parse(yaml)?,
            Environment::Injected(
                entries
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        )
    }
    pub async fn load(
        path: Option<PathBuf>,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Result<Self, ConfigError> {
        Self::load_with_environment(path, deadline, cancellation, Environment::Live).await
    }
    async fn load_with_environment(
        path: Option<PathBuf>,
        deadline: Instant,
        cancellation: CancellationToken,
        environment: Environment,
    ) -> Result<Self, ConfigError> {
        check(deadline, &cancellation)?;
        let path = match path {
            Some(path) => Some(path),
            None => environment.get("SIGNAL_CONFIG")?.map(PathBuf::from),
        };
        let Some(path) = path else {
            return Self::from_document(
                Document {
                    schema_version: 1,
                    ..Default::default()
                },
                environment,
            );
        };
        let worker_cancel = cancellation.child_token();
        let operation_cancel = worker_cancel.clone();
        let guard = CancelOnDrop(worker_cancel.clone());
        let result = run_worker(deadline, &worker_cancel, move || {
            let text = read_file(path, deadline, &operation_cancel)?;
            check(deadline, &operation_cancel)?;
            let document = parse(&text)?;
            check(deadline, &operation_cancel)?;
            Self::from_document(document, environment)
        })
        .await;
        drop(guard);
        result
    }
    fn from_document(document: Document, environment: Environment) -> Result<Self, ConfigError> {
        if document.schema_version != 1 {
            return Err(ConfigError::Invalid("schema_version"));
        }
        if document
            .storage
            .storage_type
            .as_ref()
            .is_some_and(|s| !matches!(s.0.as_str(), "parquet" | "s3"))
        {
            return Err(ConfigError::Invalid("storage type"));
        }
        if document.buffer.admission_policy.as_ref().is_some_and(|s| {
            !matches!(
                s.0.as_str(),
                "reject_new" | "drop_oldest" | "block_with_timeout"
            )
        }) {
            return Err(ConfigError::Invalid("admission policy"));
        }
        if document
            .storage
            .compression
            .as_ref()
            .is_some_and(|s| !matches!(s.0.as_str(), "snappy" | "zstd" | "uncompressed"))
        {
            return Err(ConfigError::Invalid("compression"));
        }
        if document.ingest.api_token_env.is_some() && document.ingest.api_token.is_some() {
            return Err(ConfigError::Invalid("conflicting API token sources"));
        }
        let token_env = document.ingest.api_token_env.as_ref().map(|t| t.0.clone());
        if let Some(name) = &token_env
            && (name.is_empty()
                || name.len() > 128
                || !name.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                }))
        {
            return Err(ConfigError::Invalid("API token environment name"));
        }
        let mut values = BTreeMap::new();
        mapping!(values,document.server,{listen=>"SIGNAL_LISTEN",tls_config=>"SIGNAL_TLS_CONFIG",max_connections=>"SIGNAL_MAX_CONNECTIONS"});
        mapping!(values,document.ingest,{max_request_bytes=>"SIGNAL_MAX_REQUEST_BYTES",max_batch_events=>"SIGNAL_MAX_BATCH_EVENTS",max_in_flight=>"SIGNAL_MAX_IN_FLIGHT",api_token=>"SIGNAL_API_TOKEN"});
        mapping!(values,document.buffer,{wal_directory=>"SIGNAL_WAL_DIR",memory_events=>"SIGNAL_MEMORY_EVENTS",memory_bytes=>"SIGNAL_MEMORY_BYTES",max_record_bytes=>"SIGNAL_WAL_RECORD_BYTES",max_wal_bytes=>"SIGNAL_WAL_BYTES",segment_bytes=>"SIGNAL_WAL_SEGMENT_BYTES",max_segments=>"SIGNAL_WAL_SEGMENTS",command_capacity=>"SIGNAL_WAL_COMMANDS",max_waiters=>"SIGNAL_WAL_WAITERS",admission_policy=>"SIGNAL_ADMISSION_POLICY"});
        mapping!(values,document.storage,{storage_type=>"SIGNAL_STORAGE_TYPE",s3_endpoint=>"SIGNAL_S3_ENDPOINT",s3_region=>"SIGNAL_S3_REGION",s3_bucket=>"SIGNAL_S3_BUCKET",s3_backend_id=>"SIGNAL_S3_BACKEND_ID",s3_cache_directory=>"SIGNAL_S3_CACHE_DIR",s3_cache_files=>"SIGNAL_S3_CACHE_FILES",s3_cache_bytes=>"SIGNAL_S3_CACHE_BYTES",s3_object_bytes=>"SIGNAL_S3_OBJECT_BYTES",s3_inventory_objects=>"SIGNAL_S3_INVENTORY_OBJECTS",s3_catalog_bytes=>"SIGNAL_S3_CATALOG_BYTES",s3_allow_loopback_http=>"SIGNAL_S3_ALLOW_LOOPBACK_HTTP",s3_kms_key_id=>"SIGNAL_S3_KMS_KEY_ID",s3_bucket_key=>"SIGNAL_S3_BUCKET_KEY",directory=>"SIGNAL_STORAGE_DIR",flush_events=>"SIGNAL_STORAGE_BATCH_EVENTS",max_batch_bytes=>"SIGNAL_STORAGE_BATCH_BYTES",max_event_bytes=>"SIGNAL_STORAGE_EVENT_BYTES",max_disk_bytes=>"SIGNAL_STORAGE_BYTES",max_files=>"SIGNAL_STORAGE_FILES",command_capacity=>"SIGNAL_STORAGE_COMMANDS",compression=>"SIGNAL_STORAGE_COMPRESSION"});
        mapping!(values,document.query,{memory_bytes=>"SIGNAL_QUERY_MEMORY_BYTES",max_concurrent=>"SIGNAL_QUERY_CONCURRENCY",max_files=>"SIGNAL_QUERY_FILES",max_limit=>"SIGNAL_QUERY_LIMIT",max_response_bytes=>"SIGNAL_QUERY_RESPONSE_BYTES",batch_rows=>"SIGNAL_QUERY_BATCH_ROWS",target_partitions=>"SIGNAL_QUERY_PARTITIONS"});
        mapping!(values,document.rules,{max_rules=>"SIGNAL_RULES_MAX_RULES",max_directory_entries=>"SIGNAL_RULES_MAX_DIRECTORY_ENTRIES",max_document_bytes=>"SIGNAL_RULES_MAX_DOCUMENT_BYTES",max_total_bytes=>"SIGNAL_RULES_MAX_TOTAL_BYTES",max_value_nodes=>"SIGNAL_RULES_MAX_VALUE_NODES",max_depth=>"SIGNAL_RULES_MAX_DEPTH",max_predicates=>"SIGNAL_RULES_MAX_PREDICATES",max_field_bytes=>"SIGNAL_RULES_MAX_FIELD_BYTES",max_title_bytes=>"SIGNAL_RULES_MAX_TITLE_BYTES"});
        mapping!(values,document.findings,{directory=>"SIGNAL_FINDINGS_DIR",max_disk_bytes=>"SIGNAL_FINDINGS_BYTES",max_findings=>"SIGNAL_FINDINGS_MAX_FINDINGS",max_record_bytes=>"SIGNAL_FINDINGS_RECORD_BYTES",max_append_rows=>"SIGNAL_FINDINGS_BATCH_EVENTS",max_append_bytes=>"SIGNAL_FINDINGS_BATCH_BYTES",max_query_rows=>"SIGNAL_FINDINGS_QUERY_LIMIT",max_query_bytes=>"SIGNAL_FINDINGS_QUERY_BYTES",max_index_bytes=>"SIGNAL_FINDINGS_INDEX_BYTES",command_capacity=>"SIGNAL_FINDINGS_COMMANDS"});
        mapping!(values,document.telemetry,{metrics_listen=>"SIGNAL_METRICS_LISTEN",queue_records=>"SIGNAL_LOG_RECORDS",queue_bytes=>"SIGNAL_LOG_BYTES",max_record_bytes=>"SIGNAL_LOG_RECORD_BYTES"});
        mapping!(values,document.coverage,{config=>"SIGNAL_COVERAGE_CONFIG"});
        mapping!(values,document.access,{config=>"SIGNAL_ACCESS_CONFIG"});
        mapping!(values,document.audit,{config=>"SIGNAL_AUDIT_CONFIG"});
        duration(
            &mut values,
            "SIGNAL_CONNECTION_TIMEOUT_MS",
            document.server.connection_timeout.as_ref(),
            document.server.connection_timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_SHUTDOWN_TIMEOUT_MS",
            document.server.shutdown_timeout.as_ref(),
            document.server.shutdown_timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_REQUEST_TIMEOUT_MS",
            document.ingest.request_timeout.as_ref(),
            document.ingest.request_timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_WAL_TIMEOUT_MS",
            document.buffer.operation_timeout.as_ref(),
            document.buffer.operation_timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_WAL_BLOCK_TIMEOUT_MS",
            document.buffer.block_timeout.as_ref(),
            document.buffer.block_timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_STORAGE_TIMEOUT_MS",
            document.storage.operation_timeout.as_ref(),
            document.storage.operation_timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_STORAGE_FLUSH_MS",
            document.storage.flush_interval.as_ref(),
            document.storage.flush_interval_ms.as_ref(),
            60_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_QUERY_TIMEOUT_MS",
            document.query.timeout.as_ref(),
            document.query.timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_RULES_TIMEOUT_MS",
            document.rules.timeout.as_ref(),
            document.rules.timeout_ms.as_ref(),
            3_600_000,
        )?;
        duration(
            &mut values,
            "SIGNAL_FINDINGS_TIMEOUT_MS",
            document.findings.operation_timeout.as_ref(),
            document.findings.operation_timeout_ms.as_ref(),
            300_000,
        )?;
        let directories = document
            .rules
            .directories
            .unwrap_or_default()
            .into_iter()
            .map(|text| PathBuf::from(text.0))
            .collect::<Vec<_>>();
        validate_directories(&directories)?;
        let settings = Self {
            values,
            directories,
            token_env,
            environment,
        };
        // An explicitly configured token environment must resolve before readiness.
        if settings.token_env.is_some() {
            let _ = settings.optional("SIGNAL_API_TOKEN")?;
        }
        Ok(settings)
    }
    pub fn optional(&self, name: &'static str) -> Result<Option<String>, ConfigError> {
        if let Some(value) = self.environment.get(name)? {
            return Ok(Some(value));
        }
        if name == "SIGNAL_API_TOKEN"
            && let Some(token_env) = &self.token_env
        {
            return self
                .environment
                .get(token_env)?
                .map(Some)
                .ok_or(ConfigError::Invalid("API token environment is missing"));
        }
        Ok(self.values.get(name).cloned())
    }
    pub fn number(&self, name: &'static str, default: usize) -> Result<usize, ConfigError> {
        match self.optional(name)? {
            Some(value) => value.parse().map_err(|_| ConfigError::Environment(name)),
            None => Ok(default),
        }
    }
    pub fn secret_environment(&self, name: &str) -> Result<String, ConfigError> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            || name.as_bytes()[0].is_ascii_digit()
        {
            return Err(ConfigError::Invalid("coverage credential environment name"));
        }
        self.environment.get(name)?.ok_or(ConfigError::Invalid(
            "coverage credential environment missing",
        ))
    }
    pub fn rules_directories(&self) -> Result<Vec<PathBuf>, ConfigError> {
        let directories = if let Some(paths) = self.environment.get("SIGNAL_RULE_DIRS")? {
            env::split_paths(&paths)
                .take(MAX_RULE_DIRECTORIES + 1)
                .collect()
        } else {
            self.directories.clone()
        };
        validate_directories(&directories)?;
        Ok(directories)
    }
}
fn validate_directories(paths: &[PathBuf]) -> Result<(), ConfigError> {
    if paths.len() > MAX_RULE_DIRECTORIES || paths.iter().any(|path| path.as_os_str().is_empty()) {
        return Err(ConfigError::Invalid("rule directories"));
    }
    Ok(())
}
fn parse(text: &str) -> Result<Document, ConfigError> {
    if text.len() > MAX_BYTES {
        return Err(ConfigError::Invalid("configuration byte capacity"));
    }
    let options = serde_saphyr::options! {
        budget:serde_saphyr::budget!{max_nodes:8192,max_depth:32,max_anchors:0,max_aliases:0,max_documents:1},
        duplicate_keys:serde_saphyr::DuplicateKeyPolicy::Error,
        merge_keys:serde_saphyr::MergeKeyPolicy::Error,
        emit_comments:false,with_snippet:false,reject_unsupported_tags:true,strict_booleans:true,
    };
    serde_saphyr::from_str_with_options(text, options)
        .map_err(|_| ConfigError::Invalid("YAML schema or parser budget"))
}
fn check(deadline: Instant, cancellation: &CancellationToken) -> Result<(), ConfigError> {
    if Instant::now() >= deadline {
        return Err(ConfigError::Timeout);
    }
    if cancellation.is_cancelled() {
        return Err(ConfigError::Cancelled);
    }
    Ok(())
}
fn read_file(
    path: PathBuf,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<String, ConfigError> {
    read_file_limited(path, MAX_BYTES, deadline, cancellation)
}
fn read_file_limited(
    path: PathBuf,
    max_bytes: usize,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<String, ConfigError> {
    check(deadline, cancellation)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| ConfigError::Io)?;
    if !metadata.is_file() {
        return Err(ConfigError::Invalid("configuration file must be regular"));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(ConfigError::Invalid("configuration byte capacity"));
    }
    let file = File::open(path).map_err(|_| ConfigError::Io)?;
    if !file.metadata().map_err(|_| ConfigError::Io)?.is_file() {
        return Err(ConfigError::Invalid("configuration file must be regular"));
    }
    let mut file = file.take(max_bytes as u64 + 1);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut chunk = [0; 4096];
    loop {
        check(deadline, cancellation)?;
        let count = file.read(&mut chunk).map_err(|_| ConfigError::Io)?;
        if count == 0 {
            break;
        }
        if count > max_bytes.saturating_sub(bytes.len()) {
            return Err(ConfigError::Invalid("configuration byte capacity"));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(bytes).map_err(|_| ConfigError::Invalid("configuration encoding"))
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn run_worker<F, T>(
    deadline: Instant,
    cancellation: &CancellationToken,
    operation: F,
) -> Result<T, ConfigError>
where
    F: FnOnce() -> Result<T, ConfigError> + Send + 'static,
    T: Send + 'static,
{
    check(deadline, cancellation)?;
    let permit = Arc::new(
        CAPACITY
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConfigError::Full)?,
    );
    let worker_permit = permit.clone();
    let (reply, response) = oneshot::channel();
    {
        let mut worker = WORKER.lock().map_err(|_| ConfigError::Unavailable)?;
        if worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return Err(ConfigError::Full);
        }
        if let Some(previous) = worker.take() {
            previous.join().map_err(|_| ConfigError::Unavailable)?;
        }
        *worker = Some(
            thread::Builder::new()
                .name("signal-config".into())
                .spawn(move || {
                    let _permit = worker_permit;
                    let _ = reply.send(operation());
                })
                .map_err(|_| ConfigError::Io)?,
        );
    }
    let result = tokio::select! {result=timeout_at(deadline,response)=>match result{Ok(Ok(result))=>result,Ok(Err(_))=>Err(ConfigError::Unavailable),Err(_)=>Err(ConfigError::Timeout)},()=cancellation.cancelled()=>Err(ConfigError::Cancelled)};
    if matches!(result, Err(ConfigError::Timeout | ConfigError::Cancelled)) {
        return result;
    }
    loop {
        if WORKER
            .lock()
            .map_err(|_| ConfigError::Unavailable)?
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
        {
            break;
        }
        check(deadline, cancellation)?;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    if let Some(worker) = WORKER.lock().map_err(|_| ConfigError::Unavailable)?.take() {
        worker.join().map_err(|_| ConfigError::Unavailable)?;
    }
    drop(permit);
    // A completed reply is not a timely reply if the caller resumes late.
    check(deadline, cancellation)?;
    result
}

/// Reuses the settings worker and physical lease; never spawns detached file I/O.
pub async fn read_document<T, F>(
    path: PathBuf,
    deadline: Instant,
    cancellation: CancellationToken,
    parse: F,
) -> Result<T, ConfigError>
where
    T: Send + 'static,
    F: FnOnce(&str) -> Result<T, ConfigError> + Send + 'static,
{
    read_limited_document(path, MAX_BYTES, deadline, cancellation, parse).await
}
/// Caller-selected finite byte ceiling; settings/coverage retain their 64KiB cap.
pub async fn read_limited_document<T, F>(
    path: PathBuf,
    max_bytes: usize,
    deadline: Instant,
    cancellation: CancellationToken,
    parse: F,
) -> Result<T, ConfigError>
where
    T: Send + 'static,
    F: FnOnce(&str) -> Result<T, ConfigError> + Send + 'static,
{
    if max_bytes == 0 || max_bytes > MAX_PRIVATE_BYTES {
        return Err(ConfigError::Invalid("configuration byte ceiling"));
    }
    let worker_cancel = cancellation.child_token();
    let operation_cancel = worker_cancel.clone();
    let guard = CancelOnDrop(worker_cancel.clone());
    let result = run_worker(deadline, &worker_cancel, move || {
        let text = read_file_limited(path, max_bytes, deadline, &operation_cancel)?;
        check(deadline, &operation_cancel)?;
        let result = parse(&text)?;
        check(deadline, &operation_cancel)?;
        Ok(result)
    })
    .await;
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn injected(entries: &[(&str, &str)]) -> Environment {
        Environment::Injected(
            entries
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        )
    }
    fn settings(yaml: &str, entries: &[(&str, &str)]) -> Result<Settings, ConfigError> {
        Settings::from_document(parse(yaml)?, injected(entries))
    }
    #[test]
    fn strict_schema_null_duplicate_types_and_static_redaction() -> TestResult {
        let invalid = [
            "server: {listen: '127.0.0.1:8080'}",
            "schema_version: 2",
            "schema_version: '1'",
            "schema_version: 1\nschema_version: 1",
            "schema_version: 1\nunknown: true",
            "schema_version: 1\nserver: {unknown: 1}",
            "schema_version: 1\ningest: {max_request_bytes: 3, max_request_bytes: 4}",
            "schema_version: 1\nserver: null",
            "schema_version: 1\ningest: {api_token: null}",
            "schema_version: 1\nbuffer: {memory_events: null}",
            "schema_version: 1\ningest: {max_request_bytes: '3'}",
            "schema_version: 1\ningest: {max_request_bytes: true}",
            "schema_version: 1\ningest: {max_request_bytes: 0}",
            "schema_version: 1\ningest: {max_request_bytes: -1}",
            "schema_version: 1\ningest: {max_request_bytes: 1.5}",
            "schema_version: 1\ningest: {max_request_bytes: 18446744073709551616}",
            "schema_version: 1\nserver: {listen: 8080}",
            "schema_version: 1\nrules: {directories: [null]}",
            "schema_version: 1\nserver: &anchor {listen: 'localhost:80'}",
            "schema_version: 1\nserver: {<<: {listen: 'localhost:80'}}",
            "schema_version: 1\nserver: !custom {listen: 'localhost:80'}",
            "schema_version: 1\n---\nschema_version: 1",
            "schema_version: 1\nstorage: {type: unsupported}",
            "schema_version: 1\nstorage: {flush_interval: '0ms'}",
            "schema_version: 1\nstorage: {flush_interval: '61s'}",
            "schema_version: 1\nstorage: {flush_interval: '1.5s'}",
            "schema_version: 1\nstorage: {flush_interval: '18446744073709551616s'}",
            "schema_version: 1\nstorage: {flush_interval: '1s', flush_interval_ms: 2}",
            "schema_version: 1\ningest: {api_token_env: 'invalid-name'}",
            "schema_version: 1\ningest: {api_token_env: '1INVALID'}",
            "schema_version: 1\ningest: {api_token_env: 'VALID', api_token: 'dont-print-this-secret'}",
            "schema_version: 1\ningest: {api_token: 'dont-print-this-secret', unknown: true}",
        ];
        for (index, yaml) in invalid.into_iter().enumerate() {
            match settings(yaml, &[]) {
                Err(error) => {
                    let message = format!("{error:?} {error}");
                    assert!(!message.contains("dont-print-this-secret"));
                    assert!(!message.contains(yaml));
                }
                Ok(_) => {
                    return Err(format!(
                        "unexpected configuration acceptance at test case {index}"
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
    #[test]
    fn current_yaml_shape_and_complete_limits_map_to_existing_environment_names() -> TestResult {
        let settings = settings(
            r#"
schema_version: 1
server:
  listen: '0.0.0.0:8080'
  max_connections: 24
  shutdown_timeout: '9s'
ingest:
  max_request_bytes: 1048576
  max_batch_events: 300
  max_in_flight: 8
  request_timeout_ms: 500
  api_token_env: CUSTOM_API_TOKEN
buffer:
  memory_events: 10000
  memory_bytes: 67108864
  wal_directory: './data/wal'
  max_wal_bytes: 1073741824
  max_record_bytes: 2097152
  segment_bytes: 8388608
  max_segments: 128
  command_capacity: 12
  max_waiters: 16
  admission_policy: reject_new
  operation_timeout: '5s'
  block_timeout: '500ms'
storage:
  type: parquet
  directory: './data/events'
  flush_events: 5000
  flush_interval: '5s'
  max_batch_bytes: 8388608
  max_event_bytes: 2097152
  max_disk_bytes: 1073741824
  max_files: 10000
  command_capacity: 8
  operation_timeout_ms: 120000
  compression: zstd
query:
  memory_bytes: 268435456
  max_concurrent: 4
  max_files: 120
  max_limit: 1000
  max_response_bytes: 8388608
  batch_rows: 128
  target_partitions: 1
  timeout: '10s'
rules:
  directories: ['./rules', './security-rules']
  max_rules: 50
  max_nodes: 1000
findings:
  directory: './data/findings'
  max_disk_bytes: 100000
  max_findings: 90
  max_record_bytes: 65536
  max_append_rows: 20
  max_append_bytes: 200000
  max_query_rows: 100
  max_query_bytes: 200000
  max_index_bytes: 100000
  command_capacity: 5
  operation_timeout: '2s'
telemetry:
  metrics_listen: '0.0.0.0:9090'
  queue_records: 100
  queue_bytes: 65536
  max_record_bytes: 4096
"#,
            &[("CUSTOM_API_TOKEN", "private-token")],
        )?;
        for (key, expected) in [
            ("SIGNAL_MAX_REQUEST_BYTES", 1048576),
            ("SIGNAL_MAX_BATCH_EVENTS", 300),
            ("SIGNAL_MEMORY_EVENTS", 10000),
            ("SIGNAL_WAL_COMMANDS", 12),
            ("SIGNAL_WAL_BYTES", 1073741824),
            ("SIGNAL_WAL_BLOCK_TIMEOUT_MS", 500),
            ("SIGNAL_STORAGE_BATCH_EVENTS", 5000),
            ("SIGNAL_STORAGE_FLUSH_MS", 5000),
            ("SIGNAL_QUERY_FILES", 120),
            ("SIGNAL_QUERY_TIMEOUT_MS", 10000),
            ("SIGNAL_FINDINGS_MAX_FINDINGS", 90),
            ("SIGNAL_FINDINGS_BATCH_EVENTS", 20),
            ("SIGNAL_FINDINGS_QUERY_LIMIT", 100),
            ("SIGNAL_FINDINGS_TIMEOUT_MS", 2000),
            ("SIGNAL_LOG_RECORDS", 100),
            ("SIGNAL_LOG_BYTES", 65536),
            ("SIGNAL_LOG_RECORD_BYTES", 4096),
        ] {
            assert_eq!(settings.number(key, 1)?, expected);
        }
        assert_eq!(
            settings.optional("SIGNAL_WAL_DIR")?.as_deref(),
            Some("./data/wal")
        );
        assert_eq!(
            settings.optional("SIGNAL_API_TOKEN")?.as_deref(),
            Some("private-token")
        );
        assert_eq!(
            settings.optional("SIGNAL_STORAGE_COMPRESSION")?.as_deref(),
            Some("zstd")
        );
        assert_eq!(
            settings.optional("SIGNAL_METRICS_LISTEN")?.as_deref(),
            Some("0.0.0.0:9090")
        );
        assert_eq!(
            settings.rules_directories()?,
            vec![PathBuf::from("./rules"), PathBuf::from("./security-rules")]
        );
        Ok(())
    }
    #[test]
    fn environment_precedence_defaults_and_token_sources_use_injected_environment() -> TestResult {
        let yaml = "schema_version: 1\ningest: {api_token_env: CUSTOM_TOKEN, max_batch_events: 5}\nrules: {directories: ['./yaml-rules']}";
        let settings = settings(
            yaml,
            &[
                ("SIGNAL_API_TOKEN", "env-token"),
                ("SIGNAL_MAX_BATCH_EVENTS", "9"),
                ("SIGNAL_RULE_DIRS", "./env-a:./env-b"),
            ],
        )?;
        assert_eq!(
            settings.optional("SIGNAL_API_TOKEN")?.as_deref(),
            Some("env-token")
        );
        assert_eq!(settings.number("SIGNAL_MAX_BATCH_EVENTS", 1000)?, 9);
        assert_eq!(settings.number("SIGNAL_MAX_CONNECTIONS", 128)?, 128);
        assert_eq!(
            settings.rules_directories()?,
            vec![PathBuf::from("./env-a"), PathBuf::from("./env-b")]
        );
        assert!(matches!(
            super::tests::settings(yaml, &[]),
            Err(ConfigError::Invalid("API token environment is missing"))
        ));
        let inline = super::tests::settings(
            "schema_version: 1\ningest: {api_token: 'inline-secret'}",
            &[],
        )?;
        assert_eq!(
            inline.optional("SIGNAL_API_TOKEN")?.as_deref(),
            Some("inline-secret")
        );
        let bad = super::tests::settings(
            "schema_version: 1",
            &[("SIGNAL_MAX_CONNECTIONS", "dont-print-this-secret")],
        )?;
        let error = bad
            .number("SIGNAL_MAX_CONNECTIONS", 128)
            .err()
            .ok_or("numeric error missing")?;
        assert!(!format!("{error:?} {error}").contains("dont-print-this-secret"));
        let empty = super::tests::settings("schema_version: 1", &[])?;
        assert!(empty.rules_directories()?.is_empty());
        assert!(empty.optional("SIGNAL_API_TOKEN")?.is_none());
        let access = super::tests::settings(
            "schema_version: 1\naccess: {config: './private-access.json'}",
            &[("SIGNAL_ACCESS_CONFIG", "./override-access.json")],
        )?;
        assert_eq!(
            access.optional("SIGNAL_ACCESS_CONFIG")?.as_deref(),
            Some("./override-access.json")
        );
        assert!(super::tests::settings("schema_version: 1\naccess: null", &[]).is_err());
        assert!(super::tests::settings("schema_version: 1\naccess: {config: null}", &[]).is_err());
        let audit = super::tests::settings(
            "schema_version: 1\naudit: {config: '/private/audit.json'}",
            &[("SIGNAL_AUDIT_CONFIG", "/private/override-audit.json")],
        )?;
        assert_eq!(
            audit.optional("SIGNAL_AUDIT_CONFIG")?.as_deref(),
            Some("/private/override-audit.json")
        );
        for yaml in [
            "schema_version: 1\naudit: null",
            "schema_version: 1\naudit: {config: null}",
            "schema_version: 1\naudit: {token: 'synthetic-secret'}",
        ] {
            assert!(super::tests::settings(yaml, &[]).is_err());
        }
        assert!(
            super::tests::settings("schema_version: 1\naccess: {config: 'a', config: 'b'}", &[])
                .is_err()
        );
        Ok(())
    }
    #[tokio::test]
    async fn bounded_file_reader_cancellation_and_retained_worker_are_qualified() -> TestResult {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("server.yaml");
        fs::write(
            &path,
            b"schema_version: 1\nserver: {listen: '127.0.0.1:8181'}",
        )?;
        let load = |path| {
            Settings::load_with_environment(
                path,
                Instant::now() + Duration::from_secs(2),
                CancellationToken::new(),
                injected(&[]),
            )
        };
        let loaded = load(Some(path.clone())).await?;
        assert_eq!(
            loaded.optional("SIGNAL_LISTEN")?.as_deref(),
            Some("127.0.0.1:8181")
        );
        let from_env = Settings::load_with_environment(
            None,
            Instant::now() + Duration::from_secs(2),
            CancellationToken::new(),
            injected(&[("SIGNAL_CONFIG", path.to_str().ok_or("UTF8 test path")?)]),
        )
        .await?;
        assert_eq!(
            from_env.optional("SIGNAL_LISTEN")?.as_deref(),
            Some("127.0.0.1:8181")
        );
        fs::write(&path, vec![b'x'; MAX_BYTES + 1])?;
        assert!(matches!(
            load(Some(path.clone())).await,
            Err(ConfigError::Invalid("configuration byte capacity"))
        ));
        assert!(matches!(
            load(Some(temp.path().to_owned())).await,
            Err(ConfigError::Invalid("configuration file must be regular"))
        ));
        #[cfg(unix)]
        {
            let link = temp.path().join("link.yaml");
            std::os::unix::fs::symlink(&path, &link)?;
            assert!(matches!(
                load(Some(link)).await,
                Err(ConfigError::Invalid("configuration file must be regular"))
            ));
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            Settings::load_with_environment(
                Some(path.clone()),
                Instant::now() + Duration::from_secs(2),
                cancelled,
                injected(&[])
            )
            .await,
            Err(ConfigError::Cancelled)
        ));
        assert!(matches!(
            Settings::load_with_environment(
                Some(path),
                Instant::now(),
                CancellationToken::new(),
                injected(&[])
            )
            .await,
            Err(ConfigError::Timeout)
        ));
        // A paused operation models a started kernel read that cannot be interrupted.
        let (started, ready) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let _guard = CancelOnDrop(worker_cancel.clone());
            run_worker(
                Instant::now() + Duration::from_millis(100),
                &worker_cancel,
                move || {
                    let _ = started.send(());
                    wait.recv_timeout(Duration::from_secs(2))
                        .map_err(|_| ConfigError::Timeout)?;
                    Settings::from_document(
                        Document {
                            schema_version: 1,
                            ..Default::default()
                        },
                        injected(&[]),
                    )
                },
            )
            .await
        });
        ready.await?;
        assert!(matches!(task.await?, Err(ConfigError::Timeout)));
        assert!(matches!(
            run_worker(
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
                || Settings::from_document(
                    Document {
                        schema_version: 1,
                        ..Default::default()
                    },
                    injected(&[])
                )
            )
            .await,
            Err(ConfigError::Full)
        ));
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while CAPACITY
                .get()
                .is_some_and(|capacity| capacity.available_permits() == 0)
                || WORKER
                    .lock()
                    .map(|worker| worker.as_ref().is_some_and(|worker| !worker.is_finished()))
                    .unwrap_or(true)
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let recovered = run_worker(
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
            || {
                Settings::from_document(
                    Document {
                        schema_version: 1,
                        ..Default::default()
                    },
                    injected(&[]),
                )
            },
        )
        .await?;
        assert_eq!(recovered.number("SIGNAL_MAX_CONNECTIONS", 128)?, 128);
        // Complete physical work, then resume its caller after the deadline.
        // timeout_at can observe a ready reply before its elapsed timer.
        use std::{future::Future, task::Poll};
        let deadline = Instant::now() + Duration::from_secs(2);
        let cancel = CancellationToken::new();
        let (started, ready) = oneshot::channel();
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let mut late = Box::pin(run_worker(deadline, &cancel, move || {
            let _ = started.send(());
            wait.recv_timeout(Duration::from_secs(3))
                .map_err(|_| ConfigError::Timeout)?;
            Ok(7u8)
        }));
        std::future::poll_fn(|context| {
            // Physical work cannot finish until the test releases it; Pending
            // is now a proved state rather than a scheduling assumption.
            assert!(late.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::timeout_at(deadline, ready).await??;
        release.send(())?;
        while WORKER
            .lock()
            .map_err(|_| "fixture worker state poisoned")?
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            assert!(
                Instant::now() < deadline,
                "physical reply must finish before its deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
        );
        assert!(matches!(late.await, Err(ConfigError::Timeout)));
        let path = temp.path().join("bounded-private.json");
        fs::write(&path, vec![b'x'; MAX_BYTES + 1])?;
        assert!(matches!(
            read_document(
                path.clone(),
                Instant::now() + Duration::from_secs(2),
                CancellationToken::new(),
                |text| Ok(text.len())
            )
            .await,
            Err(ConfigError::Invalid("configuration byte capacity"))
        ));
        assert_eq!(
            read_limited_document(
                path.clone(),
                MAX_PRIVATE_BYTES,
                Instant::now() + Duration::from_secs(2),
                CancellationToken::new(),
                |text| Ok(text.len())
            )
            .await?,
            MAX_BYTES + 1
        );
        assert!(matches!(
            read_limited_document(
                path,
                MAX_PRIVATE_BYTES + 1,
                Instant::now() + Duration::from_secs(2),
                CancellationToken::new(),
                |text| Ok(text.len())
            )
            .await,
            Err(ConfigError::Invalid("configuration byte ceiling"))
        ));
        Ok(())
    }
}

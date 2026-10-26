use super::*;
use crate::config::{ConfigError, Settings};
use serde::Deserialize;
use signal_findings::{FindingStore, cases::CaseConfig};
use std::path::PathBuf;

const CONFIG_BYTES: usize = 256 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u16,
    namespace: Uuid,
    directory: PathBuf,
    /// Enroll the actual Small store's physically verified canonical derivation.
    /// Every exact row still needs provenance; this cannot promote unknown rows
    /// or enroll multi-scope episode publications.
    provider: ProviderKind,
    request_timeout_ms: u64,
    max_response_bytes: usize,
    max_cases: usize,
    max_operations: usize,
    max_disk_bytes: u64,
    max_state_bytes: usize,
    request_capacity: usize,
    directory_observer: Option<eligibility::Configuration>,
    #[serde(default)]
    episode_providers: Vec<episode::Configuration>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProviderKind {
    CanonicalSmall,
}
pub struct Configuration {
    namespace: Uuid,
    store: CaseConfig,
    timeout: Duration,
    response_bytes: usize,
    capacity: usize,
    directory: Option<Arc<eligibility::Directory>>,
    episodes: Vec<Arc<episode::Provider>>,
}
fn invalid() -> ConfigError {
    ConfigError::Invalid("SOC case configuration or prerequisites")
}
impl Configuration {
    /// A local Small handle cannot silently stand in for shared persistence.
    pub fn validate_runtime(settings: &Settings) -> Result<(), ConfigError> {
        if settings.optional("SIGNAL_CASE_CONFIG")?.is_some()
            && settings.optional("SIGNAL_SHARED_CONFIG")?.is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn validate_audit(audit: Option<&crate::audit::Control>) -> Result<(), ConfigError> {
        if !audit.is_some_and(|a| {
            [
                Operation::ReadCases,
                Operation::CreateCases,
                Operation::AssignCases,
                Operation::ReadEvidence,
            ]
            .iter()
            .all(|op| a.selected(*op))
        }) {
            return Err(invalid());
        }
        Ok(())
    }
    pub async fn load(settings: &Settings) -> Result<Option<Self>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_CASE_CONFIG")? else {
            return Ok(None);
        };
        if path.is_empty() || path.len() > 4096 {
            return Err(invalid());
        }
        crate::config::read_limited_document(
            path.into(),
            CONFIG_BYTES,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            Self::parse,
        )
        .await
        .map(Some)
    }
    pub(super) fn parse(text: &str) -> Result<Self, ConfigError> {
        let wire: Wire = serde_json::from_str(text).map_err(|_| invalid())?;
        if text.len() > CONFIG_BYTES
            || wire.schema_version != 1
            || wire.namespace.is_nil()
            || !wire.directory.is_absolute()
            || wire.directory.as_os_str().len() > 4096
            || !(1..=5000).contains(&wire.request_timeout_ms)
            || !(1024..=4 * 1024 * 1024).contains(&wire.max_response_bytes)
            || !(1..=100_000).contains(&wire.max_cases)
            || !(wire.max_cases..=100_000).contains(&wire.max_operations)
            || !(4096..=1024 * 1024 * 1024).contains(&wire.max_disk_bytes)
            || !(4096..=512 * 1024 * 1024).contains(&wire.max_state_bytes)
            || !(1..=16).contains(&wire.request_capacity)
            || wire.episode_providers.len() > 16
        {
            return Err(invalid());
        }
        let ProviderKind::CanonicalSmall = wire.provider;
        let directory = wire
            .directory_observer
            .map(|c| {
                eligibility::Directory::new(c, wire.namespace)
                    .map(Arc::new)
                    .map_err(|_| invalid())
            })
            .transpose()?;
        let episodes = wire
            .episode_providers
            .into_iter()
            .map(|c| episode::Provider::new(c, wire.namespace).map_err(|_| invalid()))
            .collect::<Result<Vec<_>, _>>()?;
        if episodes
            .iter()
            .map(|p| p.stream())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != episodes.len()
        {
            return Err(invalid());
        }
        Ok(Self {
            namespace: wire.namespace,
            store: CaseConfig {
                directory: wire.directory,
                max_cases: wire.max_cases,
                max_operations: wire.max_operations,
                max_disk_bytes: wire.max_disk_bytes,
                max_state_bytes: wire.max_state_bytes,
                operation_capacity: wire.request_capacity,
                operation_timeout: Duration::from_millis(wire.request_timeout_ms),
                max_page_bytes: wire.max_response_bytes,
                ..Default::default()
            },
            timeout: Duration::from_millis(wire.request_timeout_ms),
            response_bytes: wire.max_response_bytes,
            capacity: wire.request_capacity,
            directory,
            episodes,
        })
    }
    pub async fn open(
        self,
        stream: Uuid,
        findings: Arc<FindingStore>,
        identity: Option<IdentityBackend>,
        audit: Option<Arc<crate::audit::Control>>,
        stopping: CancellationToken,
    ) -> Result<Arc<Host>, crate::AppError> {
        let identity = identity.ok_or_else(invalid)?;
        Self::validate_audit(audit.as_deref())?;
        let audit = audit.ok_or_else(invalid)?;
        let mut registry =
            reference::Registry::canonical(stream, findings).map_err(|_| invalid())?;
        for provider in self.episodes {
            registry.enroll_episode(provider).map_err(|_| invalid())?;
        }
        let store = Arc::new(
            CaseStore::open(
                self.store,
                self.namespace,
                FindingContext::new(self.timeout),
            )
            .await?,
        );
        Ok(Arc::new(Host {
            namespace: self.namespace,
            store,
            registry,
            directory: self.directory,
            identity,
            audit,
            slots: Semaphore::new(self.capacity),
            capacity: self.capacity,
            rejected: AtomicU64::new(0),
            timeout: self.timeout,
            response_bytes: self.response_bytes,
            stopping,
        }))
    }
}

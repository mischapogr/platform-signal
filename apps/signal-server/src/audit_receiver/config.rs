//! Private finite receiver configuration. No ordinary settings or token fallback.
use super::HostError;
use axum::http::HeaderValue;
use serde::Deserialize;
use signal_collector_sdk::audit::receiver::ReceiverLimits;
use signal_ingest::server::ServerLimits;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use uuid::Uuid;

pub(super) const CONFIG_BYTES: usize = 65_536;
const CREDENTIAL_BYTES: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Wire {
    schema_version: u16,
    directory: PathBuf,
    append: Listener,
    health: Listener,
    producers: Vec<Producer>,
    health_credential_env: String,
    max_bytes: u64,
    max_records: usize,
    request_timeout_ms: u64,
    header_timeout_ms: u64,
    connection_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listener {
    listen: SocketAddr,
    tls_config: PathBuf,
    max_connections: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    producer_id: Uuid,
    credential_env: String,
}
pub(super) struct Enrollment {
    pub id: Uuid,
    pub credential: HeaderValue,
}
pub(super) struct Configuration {
    pub directory: PathBuf,
    pub append_address: SocketAddr,
    pub health_address: SocketAddr,
    pub append_tls: PathBuf,
    pub health_tls: PathBuf,
    pub append_limits: ServerLimits,
    pub health_limits: ServerLimits,
    pub receiver_limits: ReceiverLimits,
    pub producers: Vec<Enrollment>,
    pub health_credential: HeaderValue,
    pub header_timeout: Duration,
    pub request_timeout: Duration,
}
fn path(path: &std::path::Path) -> bool {
    path.is_absolute() && path.as_os_str().len() <= 4096
}
fn name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "SIGNAL_API_TOKEN"
        && name
            .bytes()
            .enumerate()
            .all(|(n, b)| b == b'_' || b.is_ascii_uppercase() || (n != 0 && b.is_ascii_digit()))
}
fn credential(value: String) -> Result<HeaderValue, HostError> {
    if value.is_empty()
        || value.len() > CREDENTIAL_BYTES
        || !value.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(HostError::Invalid);
    }
    let mut value =
        HeaderValue::from_str(&format!("Bearer {value}")).map_err(|_| HostError::Invalid)?;
    value.set_sensitive(true);
    Ok(value)
}
impl Wire {
    pub fn parse(text: &str) -> Result<Self, HostError> {
        if text.is_empty() || text.len() > CONFIG_BYTES {
            return Err(HostError::Invalid);
        }
        // Serde's derived structs also accept positional sequences. Require the
        // private wire's object shapes explicitly, then parse the original text
        // again so duplicate fields are still rejected at every struct boundary.
        let shape: serde_json::Value =
            serde_json::from_str(text).map_err(|_| HostError::Invalid)?;
        if !shape.is_object()
            || !shape
                .get("append")
                .is_some_and(serde_json::Value::is_object)
            || !shape
                .get("health")
                .is_some_and(serde_json::Value::is_object)
            || !shape
                .get("producers")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|producers| producers.iter().all(serde_json::Value::is_object))
        {
            return Err(HostError::Invalid);
        }
        serde_json::from_str(text).map_err(|_| HostError::Invalid)
    }
    pub fn capture(
        self,
        mut environment: impl FnMut(&str) -> Result<String, HostError>,
    ) -> Result<Configuration, HostError> {
        if self.schema_version != 1
            || !path(&self.directory)
            || !path(&self.append.tls_config)
            || !path(&self.health.tls_config)
            || self.append.tls_config == self.health.tls_config
            || self.append.listen.port() == 0
            || self.health.listen.port() == 0
            || self.append.listen == self.health.listen
            || !(1..=64).contains(&self.append.max_connections)
            || !(1..=16).contains(&self.health.max_connections)
            || self.producers.is_empty()
            || self.producers.len() > 32
            || !(1..=16_384).contains(&self.max_records)
            || !(4168..=64 * 1024 * 1024).contains(&self.max_bytes)
            || !(1..=30_000).contains(&self.request_timeout_ms)
            || !(1..=30_000).contains(&self.header_timeout_ms)
            || !(1..=60_000).contains(&self.connection_timeout_ms)
            || !(1..=30_000).contains(&self.shutdown_timeout_ms)
            || !name(&self.health_credential_env)
            || self.producers.iter().enumerate().any(|(n, p)| {
                p.producer_id.is_nil()
                    || !name(&p.credential_env)
                    || p.credential_env == self.health_credential_env
                    || self.producers[..n].iter().any(|previous| {
                        previous.producer_id == p.producer_id
                            || previous.credential_env == p.credential_env
                    })
            })
        {
            return Err(HostError::Invalid);
        }
        let health_credential = credential(environment(&self.health_credential_env)?)?;
        let mut producers: Vec<Enrollment> = Vec::with_capacity(self.producers.len());
        for producer in self.producers {
            let value = credential(environment(&producer.credential_env)?)?;
            if value == health_credential || producers.iter().any(|p| p.credential == value) {
                return Err(HostError::Invalid);
            }
            producers.push(Enrollment {
                id: producer.producer_id,
                credential: value,
            });
        }
        let limits = |count| ServerLimits {
            max_connections: count,
            connection_timeout: Duration::from_millis(self.connection_timeout_ms),
            shutdown_timeout: Duration::from_millis(self.shutdown_timeout_ms),
        };
        Ok(Configuration {
            directory: self.directory,
            append_address: self.append.listen,
            health_address: self.health.listen,
            append_tls: self.append.tls_config,
            health_tls: self.health.tls_config,
            append_limits: limits(self.append.max_connections),
            health_limits: limits(self.health.max_connections),
            receiver_limits: ReceiverLimits {
                max_bytes: self.max_bytes,
                max_records: self.max_records,
                max_producers: producers.len(),
            },
            producers,
            health_credential,
            header_timeout: Duration::from_millis(self.header_timeout_ms),
            request_timeout: Duration::from_millis(self.request_timeout_ms),
        })
    }
}

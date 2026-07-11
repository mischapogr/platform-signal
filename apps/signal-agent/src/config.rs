//! Finite CLI/environment limits, validated before starting workers.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use signal_event::Source;
use thiserror::Error;

use crate::{
    input::{InputKind, InputSpec, ParseMode},
    spool::SpoolConfig,
};

#[derive(Debug, Error)]
#[error("invalid agent configuration: {0}")]
pub struct ConfigError(pub &'static str);

/// Intentionally has no Debug implementation: the token is secret.
pub struct AgentConfig {
    pub server: String,
    pub token: Option<String>,
    pub tls_config: Option<PathBuf>,
    pub inputs: Vec<InputSpec>,
    pub spool: SpoolConfig,
    pub batch_events: usize,
    pub batch_bytes: usize,
    pub flush: Duration,
    pub request_timeout: Duration,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub shutdown_timeout: Duration,
    pub metrics_listen: Option<SocketAddr>,
}

fn env(name: &str, fallback: &str) -> Result<String, ConfigError> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(fallback.to_owned()),
        Err(_) => Err(ConfigError("environment value must be UTF-8")),
    }
}

fn number(value: &str, min: usize, max: usize) -> Result<usize, ConfigError> {
    let value = value
        .parse::<usize>()
        .map_err(|_| ConfigError("numeric limit"))?;
    if !(min..=max).contains(&value) {
        return Err(ConfigError("numeric limit"));
    }
    Ok(value)
}

impl AgentConfig {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, ConfigError> {
        let mut server = env("SIGNAL_AGENT_SERVER", "http://127.0.0.1:8080")?;
        let mut directory = env("SIGNAL_AGENT_SPOOL_DIR", "data/agent-spool")?;
        let mut format = env("SIGNAL_AGENT_FORMAT", "auto")?;
        let mut source_type = env("SIGNAL_AGENT_SOURCE_TYPE", "log")?;
        let mut source_name = match std::env::var("SIGNAL_AGENT_SOURCE_NAME") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err(ConfigError("source name must be UTF-8")),
        };
        let mut limits = std::collections::BTreeMap::new();
        for (flag, name, default) in [
            ("--batch-events", "SIGNAL_AGENT_BATCH_EVENTS", "100"),
            ("--batch-bytes", "SIGNAL_AGENT_BATCH_BYTES", "1048576"),
            ("--flush-ms", "SIGNAL_AGENT_FLUSH_MS", "1000"),
            (
                "--request-timeout-ms",
                "SIGNAL_AGENT_REQUEST_TIMEOUT_MS",
                "5000",
            ),
            ("--retry-base-ms", "SIGNAL_AGENT_RETRY_BASE_MS", "100"),
            ("--retry-max-ms", "SIGNAL_AGENT_RETRY_MAX_MS", "5000"),
            (
                "--shutdown-timeout-ms",
                "SIGNAL_AGENT_SHUTDOWN_TIMEOUT_MS",
                "10000",
            ),
            (
                "--max-spool-bytes",
                "SIGNAL_AGENT_MAX_SPOOL_BYTES",
                "67108864",
            ),
            (
                "--max-spool-events",
                "SIGNAL_AGENT_MAX_SPOOL_EVENTS",
                "10000",
            ),
            ("--max-line-bytes", "SIGNAL_AGENT_MAX_LINE_BYTES", "65536"),
            ("--max-event-bytes", "SIGNAL_AGENT_MAX_EVENT_BYTES", "65536"),
        ] {
            limits.insert(flag, env(name, default)?);
        }
        let mut metrics = env("SIGNAL_AGENT_METRICS_LISTEN", "")?;
        let mut kinds = Vec::new();
        let mut once = false;
        let mut stdin = false;
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--stdin" => {
                    if stdin {
                        return Err(ConfigError("duplicate stdin"));
                    }
                    stdin = true;
                    kinds.push(InputKind::Stdin);
                }
                "--once" => once = true,
                _ => {
                    let value = args.next().ok_or(ConfigError("missing flag value"))?;
                    match flag.as_str() {
                        "--server" => server = value,
                        "--spool-dir" => directory = value,
                        "--format" => format = value,
                        "--source-type" => source_type = value,
                        "--source-name" => source_name = Some(value),
                        "--metrics-listen" => metrics = value,
                        "--file" => {
                            if value.is_empty() || value.len() > 4096 {
                                return Err(ConfigError("file path"));
                            }
                            kinds.push(InputKind::File(PathBuf::from(value)));
                        }
                        flag if limits.contains_key(flag) => {
                            limits.insert(
                                limits.get_key_value(flag).ok_or(ConfigError("flag"))?.0,
                                value,
                            );
                        }
                        _ => return Err(ConfigError("unknown flag")),
                    }
                }
            }
            if kinds.len() > 16 {
                return Err(ConfigError("at most 16 inputs"));
            }
        }
        if kinds.is_empty() {
            kinds.push(InputKind::Stdin);
        }
        if server.len() > 4096
            || directory.is_empty()
            || directory.len() > 4096
            || source_type.trim().is_empty()
            || source_type.len() > 256
            || source_name
                .as_ref()
                .is_some_and(|v| v.trim().is_empty() || v.len() > 256)
        {
            return Err(ConfigError("source, endpoint or spool path"));
        }
        let mode = match format.as_str() {
            "auto" => ParseMode::Auto,
            "plain" => ParseMode::Plain,
            "json" => ParseMode::Json,
            _ => return Err(ConfigError("format must be auto, plain or json")),
        };
        let n = |flag, min, max| {
            number(
                limits.get(flag).ok_or(ConfigError("missing limit"))?,
                min,
                max,
            )
        };
        let batch_events = n("--batch-events", 1, 1000)?;
        let batch_bytes = n("--batch-bytes", 4096, 16 * 1024 * 1024)?;
        let max_line_bytes = n("--max-line-bytes", 1, 65536)?;
        let event_bytes = n("--max-event-bytes", 1024, 1024 * 1024)?;
        if event_bytes + 64 + batch_events > batch_bytes {
            return Err(ConfigError("event must fit batch envelope"));
        }
        let ms = |flag, max| n(flag, 1, max).map(|v| Duration::from_millis(v as u64));
        let retry_base = ms("--retry-base-ms", 60000)?;
        let retry_max = ms("--retry-max-ms", 60000)?;
        if retry_base > retry_max {
            return Err(ConfigError("retry base exceeds cap"));
        }
        let token = match std::env::var("SIGNAL_AGENT_API_TOKEN") {
            Ok(value) if !value.is_empty() && value.len() <= 4096 => Some(value),
            Ok(_) | Err(std::env::VarError::NotUnicode(_)) => return Err(ConfigError("API token")),
            Err(std::env::VarError::NotPresent) => None,
        };
        let tls_config = match std::env::var("SIGNAL_AGENT_TLS_CONFIG") {
            Ok(value) if !value.is_empty() && value.len() <= 4096 => Some(value.into()),
            Err(std::env::VarError::NotPresent) => None,
            _ => return Err(ConfigError("TLS configuration path")),
        };
        let source = Source {
            source_type,
            name: source_name,
        };
        let inputs = kinds
            .into_iter()
            .enumerate()
            .map(|(id, kind)| InputSpec {
                id: id as u16,
                kind,
                source: source.clone(),
                mode,
                max_line_bytes,
                follow: !once,
            })
            .collect();
        let spool = SpoolConfig {
            directory: PathBuf::from(directory),
            max_disk_bytes: n("--max-spool-bytes", 32768, 1024 * 1024 * 1024)? as u64,
            max_records: n("--max-spool-events", 1, 100000)?,
            max_event_bytes: event_bytes,
            max_batch_events: batch_events,
            max_batch_bytes: batch_bytes,
            ..SpoolConfig::default()
        };
        Ok(Self {
            server,
            token,
            tls_config,
            inputs,
            spool,
            batch_events,
            batch_bytes,
            flush: ms("--flush-ms", 60000)?,
            request_timeout: ms("--request-timeout-ms", 60000)?,
            retry_base,
            retry_max,
            shutdown_timeout: ms("--shutdown-timeout-ms", 60000)?,
            metrics_listen: if metrics.is_empty() {
                None
            } else {
                Some(
                    metrics
                        .parse()
                        .map_err(|_| ConfigError("metrics address"))?,
                )
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_capacity_and_retry_inconsistency() {
        for args in [
            vec!["--batch-events", "0"],
            vec!["--max-line-bytes", "65537"],
            vec!["--retry-base-ms", "1000", "--retry-max-ms", "1"],
            vec!["--max-event-bytes", "8192", "--batch-bytes", "4096"],
            vec!["--stdin", "--stdin"],
            vec!["--api-token", "secret"],
        ] {
            assert!(AgentConfig::parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }
}

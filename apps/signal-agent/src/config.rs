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
    pub syslog: Option<crate::syslog::Config>,
    pub node: Option<crate::node_input::Config>,
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
        let mut explicit_event_bytes = std::env::var_os("SIGNAL_AGENT_MAX_EVENT_BYTES").is_some();
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
        let mut node_root = env("SIGNAL_AGENT_NODE_LOG_ROOT", "")?;
        let mut node_name = env("SIGNAL_AGENT_NODE_NAME", "")?;
        let mut node_namespace = env("SIGNAL_AGENT_NODE_NAMESPACE", "")?;
        let mut runtime_boot_id = String::new();
        let mut audit_policy_sha256 = String::new();
        let mut syslog_listen = String::new();
        let mut syslog_tls = String::new();
        let mut syslog_peer = String::new();
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
                        "--node-log-root" => node_root = value,
                        "--node-name" => node_name = value,
                        "--node-namespace" => {
                            if value.is_empty() {
                                return Err(ConfigError("node namespace"));
                            }
                            node_namespace = value;
                        }
                        "--runtime-boot-id" => runtime_boot_id = value,
                        "--audit-policy-sha256" => audit_policy_sha256 = value,
                        "--syslog-listen" => syslog_listen = value,
                        "--syslog-tls-config" => syslog_tls = value,
                        "--syslog-peer-sha256" => syslog_peer = value,
                        "--file" => {
                            if value.is_empty() || value.len() > 4096 {
                                return Err(ConfigError("file path"));
                            }
                            kinds.push(InputKind::File(PathBuf::from(value)));
                        }
                        flag if limits.contains_key(flag) => {
                            if flag == "--max-event-bytes" {
                                explicit_event_bytes = true;
                            }
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
        let node_mode = format == "kubernetes-cri";
        if node_mode {
            if node_root.is_empty()
                || node_name.is_empty()
                || source_name.is_none()
                || !kinds.is_empty()
                || !syslog_listen.is_empty()
                || !["log", "kubernetes.container"].contains(&source_type.as_str())
            {
                return Err(ConfigError(
                    "node mode requires dedicated root/node/cluster configuration",
                ));
            }
            if !explicit_event_bytes {
                limits.insert(
                    "--max-event-bytes",
                    signal_collector_sdk::kubernetes_log::MAX_EVENT_BYTES.to_string(),
                );
            }
        } else if !node_root.is_empty() || !node_name.is_empty() || !node_namespace.is_empty() {
            return Err(ConfigError("node root/name require kubernetes-cri mode"));
        }
        if !syslog_listen.is_empty()
            && (!kinds.is_empty() || once || format != "fortigate" || source_name.is_none())
        {
            return Err(ConfigError(
                "syslog requires dedicated fortigate mode and explicit source name",
            ));
        }
        if syslog_listen.is_empty() && (!syslog_tls.is_empty() || !syslog_peer.is_empty()) {
            return Err(ConfigError("syslog TLS requires a listener"));
        }
        if kinds.is_empty() && syslog_listen.is_empty() && !node_mode {
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
        if format != "falco-json" && !runtime_boot_id.is_empty() {
            return Err(ConfigError("runtime boot ID requires falco-json mode"));
        }
        if format != "kubernetes-audit-json" && !audit_policy_sha256.is_empty() {
            return Err(ConfigError(
                "audit policy requires kubernetes-audit-json mode",
            ));
        }
        let mode = match format.as_str() {
            "kubernetes-cri" => {
                source_type = "kubernetes.container".into();
                ParseMode::Plain
            }
            "kubernetes-audit-json" => {
                if stdin
                    || kinds.iter().any(|k| !matches!(k, InputKind::File(_)))
                    || audit_policy_sha256.len() != 64
                    || !audit_policy_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    || !["log", "kubernetes.audit"].contains(&source_type.as_str())
                {
                    return Err(ConfigError(
                        "audit requires regular files and exact policy SHA256",
                    ));
                }
                let cluster = source_name
                    .as_deref()
                    .ok_or(ConfigError("audit requires cluster source name"))?;
                signal_collector_sdk::kubernetes_audit::Profile::new(cluster, &audit_policy_sha256)
                    .map_err(|_| ConfigError("audit source profile"))?;
                let mut digest = [0; 32];
                for (i, byte) in digest.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&audit_policy_sha256[i * 2..i * 2 + 2], 16)
                        .map_err(|_| ConfigError("audit policy SHA256"))?;
                }
                source_type = "kubernetes.audit".into();
                ParseMode::KubernetesAudit {
                    policy_sha256: digest,
                }
            }
            "auto" => ParseMode::Auto,
            "plain" => ParseMode::Plain,
            "json" => ParseMode::Json,
            "auth-json" => ParseMode::AuthenticationJson,
            "fortigate" => ParseMode::Fortigate,
            "falco-json" => {
                let boot_id = runtime_boot_id
                    .parse::<uuid::Uuid>()
                    .map_err(|_| ConfigError("runtime boot ID"))?;
                let host = source_name
                    .as_deref()
                    .ok_or(ConfigError("runtime requires configured host source name"))?;
                signal_collector_sdk::falco::Profile::new(host, boot_id)
                    .map_err(|_| ConfigError("runtime source profile"))?;
                ParseMode::Falco { boot_id }
            }
            _ => {
                return Err(ConfigError(
                    "format must be auto, plain, json, auth-json, fortigate, falco-json or kubernetes-audit-json or kubernetes-cri",
                ));
            }
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
        if node_mode && event_bytes < signal_collector_sdk::kubernetes_log::MAX_EVENT_BYTES {
            return Err(ConfigError(
                "node canonical event budget must be at least 512 KiB",
            ));
        }
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
        let node = if node_mode {
            let value = crate::node_input::Config {
                root: node_root.into(),
                cluster: source.name.clone().ok_or(ConfigError("node cluster"))?,
                node: node_name,
                namespace: if node_namespace.is_empty() {
                    None
                } else {
                    Some(node_namespace)
                },
                max_line_bytes,
                follow: !once,
                limits: crate::node_root::Limits::default(),
                scan_interval: Duration::from_millis(250),
            };
            value
                .validate()
                .map_err(|_| ConfigError("node source configuration"))?;
            Some(value)
        } else {
            None
        };
        let syslog = if syslog_listen.is_empty() {
            None
        } else {
            let listen: SocketAddr = syslog_listen
                .parse()
                .map_err(|_| ConfigError("syslog address"))?;
            if syslog_tls.is_empty() && (!listen.ip().is_loopback() || !syslog_peer.is_empty()) {
                return Err(ConfigError(
                    "plain syslog is loopback-only; TLS pin requires TLS material",
                ));
            }
            let peer_sha256 = if syslog_tls.is_empty() {
                None
            } else {
                if syslog_tls.len() > 4096
                    || syslog_peer.len() != 64
                    || !syslog_peer.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(ConfigError(
                        "syslog TLS material and exact peer SHA256 required",
                    ));
                }
                let mut digest = [0; 32];
                for (i, byte) in digest.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&syslog_peer[i * 2..i * 2 + 2], 16)
                        .map_err(|_| ConfigError("syslog peer digest"))?;
                }
                Some(digest)
            };
            Some(crate::syslog::Config {
                listen,
                tls: if syslog_tls.is_empty() {
                    None
                } else {
                    Some(syslog_tls.into())
                },
                peer_sha256,
                source: source.clone(),
            })
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
            syslog,
            node,
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
    fn dedicated_syslog_requires_explicit_scope_and_private_peer_binding() {
        let parse = |args: &[&str]| AgentConfig::parse(args.iter().map(|v| v.to_string()));
        let base = [
            "--syslog-listen",
            "127.0.0.1:6514",
            "--format",
            "fortigate",
            "--source-name",
            "site",
        ];
        assert!(parse(&base).is_ok());
        for tail in [
            &["--stdin"][..],
            &["--once"],
            &["--format", "plain"],
            &["--syslog-tls-config", "private.json"],
            &["--syslog-peer-sha256", "00"],
        ] {
            let mut args = base.to_vec();
            args.extend_from_slice(tail);
            assert!(parse(&args).is_err());
        }
        assert!(
            parse(&[
                "--syslog-listen",
                "0.0.0.0:6514",
                "--format",
                "fortigate",
                "--source-name",
                "site"
            ])
            .is_err()
        );
        assert!(parse(&["--syslog-listen", "127.0.0.1:6514", "--format", "fortigate"]).is_err());
        let pin = "a".repeat(64);
        let mut args = base.to_vec();
        args.extend_from_slice(&[
            "--syslog-tls-config",
            "private.json",
            "--syslog-peer-sha256",
            &pin,
        ]);
        assert!(parse(&args).is_ok());
    }
    #[test]
    fn falco_requires_explicit_host_boot_binding_and_rejects_mixed_profile_flags() {
        let parse = |args: &[&str]| AgentConfig::parse(args.iter().map(|v| v.to_string()));
        assert!(parse(&["--format", "falco-json"]).is_err());
        assert!(
            parse(&[
                "--format",
                "falco-json",
                "--runtime-boot-id",
                "00000000-0000-0000-0000-000000000001"
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "--format",
                "falco-json",
                "--source-name",
                "host",
                "--runtime-boot-id",
                "00000000-0000-0000-0000-000000000000"
            ])
            .is_err()
        );
        assert!(parse(&["--runtime-boot-id", "00000000-0000-0000-0000-000000000001"]).is_err());
        assert!(
            parse(&[
                "--format",
                "falco-json",
                "--source-name",
                "host",
                "--runtime-boot-id",
                "00000000-0000-0000-0000-000000000001"
            ])
            .is_ok()
        );
    }
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
    #[test]
    fn audit_mode_requires_explicit_file_cluster_and_policy_binding() {
        let policy = "AB".repeat(32);
        let parse = |args: &[&str]| AgentConfig::parse(args.iter().map(|v| v.to_string()));
        let valid = [
            "--format",
            "kubernetes-audit-json",
            "--file",
            "/synthetic/audit.log",
            "--source-name",
            "cluster",
            "--audit-policy-sha256",
            &policy,
        ];
        let config = match parse(&valid) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(config.inputs[0].source.source_type, "kubernetes.audit");
        assert!(
            matches!(config.inputs[0].mode, ParseMode::KubernetesAudit { policy_sha256 } if policy_sha256 == [0xab;32])
        );
        for args in [
            vec!["--format", "kubernetes-audit-json"],
            vec![
                "--format",
                "kubernetes-audit-json",
                "--source-name",
                "cluster",
                "--audit-policy-sha256",
                &policy,
            ],
            vec![
                "--format",
                "kubernetes-audit-json",
                "--file",
                "/synthetic/audit.log",
                "--audit-policy-sha256",
                &policy,
            ],
            vec!["--audit-policy-sha256", &policy],
        ] {
            assert!(parse(&args).is_err());
        }
        for suffix in [
            vec!["--stdin"],
            vec!["--runtime-boot-id", "00000000-0000-0000-0000-000000000001"],
            vec!["--source-type", "forged"],
            vec!["--audit-policy-sha256", "bad"],
        ] {
            let mut args = valid.to_vec();
            args.extend(suffix);
            assert!(parse(&args).is_err());
        }
    }
    #[test]
    #[allow(clippy::expect_used)]
    fn dedicated_node_flags_validate_profile_and_canonical_capacity_without_stdin() {
        fn parse(args: &[&str]) -> Result<AgentConfig, ConfigError> {
            AgentConfig::parse(args.iter().map(|v| v.to_string()))
        }
        let valid = [
            "--format",
            "kubernetes-cri",
            "--node-log-root",
            "/var/log/pods",
            "--node-name",
            "node-a",
            "--source-name",
            "cluster",
        ];
        let cfg = parse(&valid).expect("node config");
        assert!(cfg.inputs.is_empty() && cfg.syslog.is_none() && cfg.node.is_some());
        assert_eq!(
            cfg.spool.max_event_bytes,
            signal_collector_sdk::kubernetes_log::MAX_EVENT_BYTES
        );
        for suffix in [
            vec!["--stdin"],
            vec!["--file", "/tmp/file"],
            vec!["--syslog-listen", "127.0.0.1:514"],
            vec!["--audit-policy-sha256", "bad"],
            vec!["--max-event-bytes", "65536"],
            vec!["--node-log-root", "relative"],
        ] {
            let mut args = valid.to_vec();
            args.extend(suffix);
            assert!(parse(&args).is_err());
        }
        assert!(parse(&["--format", "plain", "--node-name", "node-a"]).is_err());
    }
}

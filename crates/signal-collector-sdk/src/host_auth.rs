//! Selected structured authentication evidence; transport identity and sensor
//! coverage remain independent trusted-host decisions.
use chrono::{DateTime, Utc};
use serde::Deserialize;
use signal_event::{IngestEvent, SignalEvent, Source};
use std::net::IpAddr;
use thiserror::Error;

pub const MAX_RECORD_BYTES: usize = 65536;
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("authentication source record exceeds byte limit")]
    TooLarge,
    #[error("invalid structured authentication source record")]
    InvalidRecord,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u16,
    timestamp: DateTime<Utc>,
    outcome: Outcome,
    identity_authority: String,
    principal_id: String,
    target_id: String,
    method: Method,
    session_id: String,
    #[serde(default)]
    client_ip: Option<IpAddr>,
    producer: Producer,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Success,
    Failure,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Method {
    Password,
    PublicKey,
    Mfa,
    Token,
    Federated,
    Other,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    boot_id: String,
    sequence: u64,
    checkpoint: u64,
    dropped_events: u64,
}
fn identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
/// Normalize one selected v1 record. No I/O, authorization, checkpoint advance,
/// runtime observation or source-coverage grant occurs here. Unknown fields are
/// rejected rather than copying possible passwords/tokens into event attributes.
pub fn normalize_authentication_json(
    bytes: &[u8],
    source: Source,
    observed_at: DateTime<Utc>,
) -> Result<SignalEvent, AuthenticationError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(AuthenticationError::TooLarge);
    }
    let r: Record =
        serde_json::from_slice(bytes).map_err(|_| AuthenticationError::InvalidRecord)?;
    if r.schema_version != 1
        || [
            &r.identity_authority,
            &r.principal_id,
            &r.target_id,
            &r.session_id,
            &r.producer.boot_id,
        ]
        .iter()
        .any(|value| !identity(value))
    {
        return Err(AuthenticationError::InvalidRecord);
    }
    let (outcome, message, severity) = match r.outcome {
        Outcome::Success => ("success", "Authentication succeeded", "info"),
        Outcome::Failure => ("failure", "Authentication failed", "warn"),
    };
    let method = match r.method {
        Method::Password => "password",
        Method::PublicKey => "public_key",
        Method::Mfa => "mfa",
        Method::Token => "token",
        Method::Federated => "federated",
        Method::Other => "other",
    };
    let input: IngestEvent = serde_json::from_value(serde_json::json!({
        "timestamp":r.timestamp,"source":source,"message":message,"severity":severity,
        "attributes":{
            "authentication":{"outcome":outcome,"identity_authority":r.identity_authority,
                "principal_id":r.principal_id,"target_id":r.target_id,"method":method,
                "session_id":r.session_id,"client_ip":r.client_ip.map(|ip|ip.to_string())},
            "producer":{"boot_id":r.producer.boot_id,"sequence":r.producer.sequence,
                "checkpoint":r.producer.checkpoint,"dropped_events":r.producer.dropped_events},
            "evidence":{"profile":"host-auth-json-v1","runtime_sensor_coverage":"not_assessed"}
        }
    }))
    .map_err(|_| AuthenticationError::InvalidRecord)?;
    input
        .normalize(observed_at)
        .map_err(|_| AuthenticationError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn record() -> Value {
        json!({"schema_version":1,"timestamp":"2026-10-14T12:00:00Z","outcome":"success",
            "identity_authority":"fixture-authority","principal_id":"fixture-user","target_id":"fixture-host",
            "method":"public_key","session_id":"fixture-session","client_ip":"198.51.100.10",
            "producer":{"boot_id":"fixture-boot","sequence":1,"checkpoint":1,"dropped_events":0}})
    }
    fn normalize(r: &Value) -> Result<SignalEvent, AuthenticationError> {
        let source = Source {
            source_type: "host-authentication".into(),
            name: Some("fixture".into()),
        };
        normalize_authentication_json(
            &serde_json::to_vec(r).map_err(|_| AuthenticationError::InvalidRecord)?,
            source,
            "2026-10-14T12:00:01Z"
                .parse()
                .map_err(|_| AuthenticationError::InvalidRecord)?,
        )
    }
    #[test]
    fn success_failure_preserve_identity_source_time_and_checkpoint_without_sensor_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        for outcome in ["success", "failure"] {
            let mut r = record();
            r["outcome"] = outcome.into();
            let e = normalize(&r)?;
            assert_eq!(e.timestamp.to_rfc3339(), "2026-10-14T12:00:00+00:00");
            assert!(e.observed_at > e.timestamp);
            assert_eq!(
                e.attributes["authentication"]["principal_id"],
                "fixture-user"
            );
            assert_eq!(e.attributes["authentication"]["outcome"], outcome);
            assert_eq!(e.attributes["producer"]["checkpoint"], 1);
            assert_eq!(
                e.attributes["evidence"]["runtime_sensor_coverage"],
                "not_assessed"
            );
        }
        Ok(())
    }
    #[test]
    fn credential_unknown_and_invalid_identity_records_are_rejected() {
        for (field, value) in [
            ("password", json!("secret")),
            ("token", json!("secret")),
            ("schema_version", json!(2)),
            ("principal_id", json!("")),
            ("client_ip", json!("not-ip")),
            ("method", json!("invented")),
        ] {
            let mut r = record();
            r[field] = value;
            assert_eq!(normalize(&r), Err(AuthenticationError::InvalidRecord));
        }
        let mut r = record();
        r["producer"]["token"] = json!("secret");
        assert_eq!(normalize(&r), Err(AuthenticationError::InvalidRecord));
        r = record();
        r["producer"]["sequence"] = json!(true);
        assert_eq!(normalize(&r), Err(AuthenticationError::InvalidRecord));
    }
    #[test]
    fn missing_timestamp_principal_checkpoint_and_oversized_record_fail() {
        for key in ["timestamp", "principal_id", "producer"] {
            let mut r = record();
            let _ = r.as_object_mut().map(|o| o.remove(key));
            assert_eq!(normalize(&r), Err(AuthenticationError::InvalidRecord));
        }
        let source = Source {
            source_type: "host-authentication".into(),
            name: None,
        };
        assert_eq!(
            normalize_authentication_json(&vec![b' '; MAX_RECORD_BYTES + 1], source, Utc::now()),
            Err(AuthenticationError::TooLarge)
        );
    }
    #[test]
    fn ip_is_context_not_principal_identity() -> Result<(), Box<dyn std::error::Error>> {
        let mut r = record();
        let first = normalize(&r)?;
        r["client_ip"] = json!("2001:db8::1");
        let second = normalize(&r)?;
        assert_eq!(
            first.attributes["authentication"]["principal_id"],
            second.attributes["authentication"]["principal_id"]
        );
        assert_ne!(
            first.attributes["authentication"]["client_ip"],
            second.attributes["authentication"]["client_ip"]
        );
        Ok(())
    }
}

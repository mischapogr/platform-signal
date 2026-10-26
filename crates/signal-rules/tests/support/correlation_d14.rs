#![allow(clippy::unwrap_used, clippy::expect_used)]
use chrono::{DateTime, Utc};
use serde_json::json;
use signal_event::{IngestEvent, SignalEvent};
use signal_findings::DetectionSeverity;
use signal_rules::{RuleContext, correlation::d14::*};
use std::time::Duration;
use uuid::Uuid;
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const BASE: u64 = 1792987440000000000;
pub fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(10))
}
pub fn ns(n: u64) -> DateTime<Utc> {
    DateTime::from_timestamp((n / 1_000_000_000) as i64, (n % 1_000_000_000) as u32).unwrap()
}
pub fn config() -> RuntimeConfig {
    RuntimeConfig {
        schema_version: 2,
        partition: Uuid::from_u128(10),
        revision: "runtime-policy-1".into(),
        title: "Protected read and egress candidate".into(),
        severity: DetectionSeverity::High,
        authority_keys_sha256: [1; 32],
        sources: vec![RuntimeSource {
            stream: Uuid::from_u128(1),
            binding: [2; 32],
            config_revision: "runtime-source-1".into(),
            source_type: "runtime".into(),
            source_name: "owned-source".into(),
            host: "synthetic-host".into(),
            metadata_config_sha256: [7; 32],
            audit_arch: 0xc000003e,
            reads: true,
            connects: true,
        }],
        policy_authorities: [Role::Asset, Role::Destination]
            .into_iter()
            .enumerate()
            .map(|(i, role)| PolicyAuthority {
                id: Uuid::from_u128(100 + i as u128),
                binding: [10 + i as u8; 32],
                source_type: "historical-policy".into(),
                source_name: format!("policy-{i}"),
                account: None,
                resource: None,
                config_revision: "policy-source-1".into(),
                authority_keys_sha256: [20 + i as u8; 32],
                role,
                policy_revision: "historical-policy-1".into(),
                policy_config_sha256: [30 + i as u8; 32],
            })
            .collect(),
        correlation_ms: 20,
        lateness_ms: 1,
        ttl_ms: 1000,
        max_events: 32,
        max_keys: 16,
        max_episodes: 16,
        max_state_bytes: 1024 * 1024,
    }
}
pub fn event(read: bool) -> Result<SignalEvent> {
    let process = json!({"host":"synthetic-host","boot":Uuid::from_u128(3),"capture":Uuid::from_u128(4),"pid":100,"start_ticks":1000,"clock_ticks":100,"mount_ns":1,"audit_arch":0xc000003eu32,"execution_generation":1});
    let object = json!({"object_type":if read{0o100000}else{0o140000},"dev_major":8,"dev_minor":1,"inode":100,"mount_id":30,"ctime_sec":1792987440,"ctime_nsec":0});
    let entry = BASE + if read { 0 } else { 10_000_000 };
    let exit = entry + 1_000_000;
    let mut operation = json!({"kind":if read{"read"}else{"connect"},"fd":3,"object":object,"interval":{"entry_ns":entry,"exit_ns":exit},"result":if read{16}else{0},"error":false});
    if read {
        operation["requested"] = json!(64);
    } else {
        operation["address"] = json!("198.51.100.10");
        operation["port"] = json!(443);
        operation["scope_id"] = json!(0);
    }
    let input: IngestEvent = serde_json::from_value(
        json!({"id":Uuid::from_u128(if read{10}else{11}),"timestamp":ns(exit+100),"source":{"type":"runtime","name":"owned-source"},"severity":"info","message":"Synthetic owned metadata","resource":{"kind":"host","id":"synthetic-host"},"attributes":{"runtime_metadata":{"schema_version":1,"native":{"capture":Uuid::from_u128(4),"sequence":if read{2}else{3}},"process":process,"config_sha256":vec![7;32],"original_record_sha256":vec![8;32],"observed_ns":exit+100,"operation":operation},"evidence":{"profile":PROFILE,"runtime_sensor_coverage":"not_assessed","policy_classification":"private"}}}),
    )?;
    Ok(input.normalize(ns(BASE + 100_000_000))?)
}
pub fn input(b: &RuntimeBinding, event: &SignalEvent, c: &RuleContext) -> Result<Input> {
    Ok(Input::new(b, Uuid::from_u128(1), event, c)?)
}
pub fn verification(
    b: &RuntimeBinding,
    i: &Input,
    yes: bool,
    c: &RuleContext,
) -> Result<Verification> {
    let role = if matches!(i.operation(), Operation::Read { .. }) {
        Role::Asset
    } else {
        Role::Destination
    };
    let a = b
        .config()
        .policy_authorities
        .iter()
        .find(|a| a.role == role)
        .unwrap();
    Ok(Verification {
        claim: i.claim(c)?,
        authority: a.id,
        authority_binding: a.binding,
        config_revision: a.config_revision.clone(),
        authority_keys_sha256: a.authority_keys_sha256,
        policy_revision: a.policy_revision.clone(),
        policy_config_sha256: a.policy_config_sha256,
        decision: if role == Role::Asset {
            Decision::Asset {
                protected_credential: yes,
            }
        } else {
            Decision::Destination { suspicious: yes }
        },
        covered_from: ns(BASE - 1_000_000),
        covered_through: ns(BASE + 100_000_000),
        reference: "fixture://independent-policy-result".into(),
        verified_at: ns(BASE + 100_000_000),
        verified_until: ns(BASE + 60_000_000_000),
        now: ns(BASE + 100_000_000),
        authenticated: true,
    })
}
pub fn decision(
    b: &RuntimeBinding,
    i: &Input,
    yes: bool,
    c: &RuleContext,
) -> Result<DecisionEvidence> {
    Ok(CurrentDecision::new(b, i, verification(b, i, yes, c)?, c)?.retained(b, i, c)?)
}

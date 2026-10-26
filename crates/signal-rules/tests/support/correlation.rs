use chrono::{DateTime, Utc};
use signal_event::{IngestEvent, SignalEvent};
use signal_findings::DetectionSeverity;
use signal_rules::{RuleContext, correlation::*};
use std::time::Duration;
use uuid::Uuid;
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(10))
}
pub fn time(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1792972800 + seconds, 0).unwrap_or(DateTime::UNIX_EPOCH)
}
pub fn config() -> Config {
    Config {
        schema_version: 1,
        partition: Uuid::from_u128(9),
        revision: "fixture-policy-1".into(),
        title: "Authentication episode candidate".into(),
        severity: DetectionSeverity::High,
        authority_keys_sha256: [3; 32],
        sources: (1..=2)
            .map(|n| Source {
                stream: Uuid::from_u128(n),
                binding: [n as u8; 32],
                config_revision: "fixture-source-1".into(),
                source_type: format!("authentication-{n}"),
                source_name: format!("fixture-source-{n}"),
                identity_authority: "fixture-authority".into(),
                failures: true,
                successes: true,
            })
            .collect(),
        threshold: 3,
        window_ms: 60_000,
        correlation_ms: 120_000,
        lateness_ms: 10_000,
        ttl_ms: 190_000,
        max_events: 32,
        max_keys: 16,
        max_episodes: 16,
        max_state_bytes: 1024 * 1024,
    }
}
pub fn verification(s: &Source, frontier: DateTime<Utc>, complete: bool) -> Verification {
    Verification {
        stream: s.stream,
        position: 1_000_000,
        source_binding: s.binding,
        source_config_revision: s.config_revision.clone(),
        authority_keys_sha256: [3; 32],
        verification_reference: format!("fixture://source-proof/{}", s.stream),
        verified_at: time(590),
        verified_until: time(900),
        now: time(600),
        coverage_from: time(-300),
        frontier,
        complete,
        authenticated: true,
    }
}
pub fn epoch(b: &Binding, frontier: DateTime<Utc>, complete: bool) -> Result<Epoch> {
    Ok(Epoch::new(
        b,
        b.config()
            .sources
            .iter()
            .map(|s| verification(s, frontier, complete))
            .collect(),
        &context(),
    )?)
}
pub fn event(source: usize, sequence: u64, second: i64, success: bool) -> Result<SignalEvent> {
    let cfg = config();
    let s = &cfg.sources[source];
    let input: IngestEvent = serde_json::from_value(
        serde_json::json!({"id":Uuid::from_u128((source as u128+1)*1000+sequence as u128),"timestamp":time(second),"source":{"type":s.source_type,"name":s.source_name},"message":"Synthetic authentication attempt",
        "attributes":{"authentication":{"identity_authority":"fixture-authority","principal_id":"fixture-user","target_id":"fixture-target","outcome":if success{"success"}else{"failure"},"method":"password","session_id":format!("session-{sequence}")},"producer":{"boot_id":"fixture-boot","sequence":sequence,"checkpoint":sequence,"dropped_events":0},"evidence":{"profile":"host-auth-json-v1","runtime_sensor_coverage":"not_assessed"}}}),
    )?;
    Ok(input.normalize(time(500))?)
}
pub fn inputs() -> Result<Vec<SignalEvent>> {
    Ok(vec![
        event(0, 1, 1, false)?,
        event(0, 2, 2, false)?,
        event(0, 3, 3, false)?,
        event(1, 1, 10, true)?,
    ])
}
pub fn load(b: &Binding, events: &[SignalEvent], order: &[usize]) -> Result<State> {
    let ep = epoch(b, time(100), true)?;
    let mut state = State::new(b);
    let mut positions = [0_u64; 2];
    for &i in order {
        let source = if events[i].source.source_type.ends_with('1') {
            0
        } else {
            1
        };
        positions[source] += 1;
        state.admit(
            b,
            b.config().sources[source].stream,
            positions[source],
            &events[i],
            &ep,
            &context(),
        )?;
    }
    Ok(state)
}

/// Synthetic host verifies the known fixture prefix before sealing; no live source claim.
pub fn seal_epoch(
    b: &Binding,
    state: &State,
    frontier: DateTime<Utc>,
    complete: bool,
) -> Result<Epoch> {
    let proofs = b
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, frontier, complete);
            p.position = state
                .source_positions()
                .iter()
                .find(|(stream, _)| *stream == s.stream)
                .map_or(0, |(_, n)| *n);
            p
        })
        .collect();
    Ok(Epoch::new(b, proofs, &context())?)
}
#[allow(dead_code)]
pub fn journal_epoch(
    b: &Binding,
    record: Option<&signal_rules::state_journal::Record>,
    frontier: DateTime<Utc>,
    complete: bool,
) -> Result<Epoch> {
    let state = record
        .map(|r| signal_rules::correlation::journal::recover(b, r, &context()))
        .transpose()?
        .unwrap_or_else(|| State::new(b));
    seal_epoch(b, &state, frontier, complete)
}

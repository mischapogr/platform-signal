#![allow(clippy::unwrap_used)]

use super::*;

fn policy() -> Policy {
    Policy {
        schema_version: 1,
        rule_id: "laboratory-heartbeat".into(),
        revision: "fixture-v1".into(),
        heartbeat_ms: 100,
        grace_ms: 20,
        observer_freshness_ms: 500,
        max_sources: 2,
        max_state_bytes: 8192,
        expected: vec![ExpectedSource {
            source_id: Uuid::from_u128(1),
            binding: [1; 32],
            observer_id: Uuid::from_u128(2),
            expected_since_ms: 1000,
            require_checkpoint: true,
        }],
    }
}
fn observation(sequence: u64, observed: i64, heartbeat: Option<i64>) -> Observation {
    Observation {
        schema_version: 1,
        source_id: Uuid::from_u128(1),
        binding: [1; 32],
        observer_id: Uuid::from_u128(2),
        sequence,
        observed_at_ms: observed,
        health: ObserverHealth::Healthy,
        heartbeat_at_ms: heartbeat,
        checkpoint: heartbeat.map(|_| sequence),
    }
}
fn one(m: &mut Monitor, now: i64) -> Assessment {
    m.assess(now).unwrap().remove(0)
}

#[test]
fn positive_negative_missing_data_and_exact_grace_boundary() {
    let mut m = Monitor::new(policy(), 1000).unwrap();
    assert_eq!(one(&mut m, 1000).reason, Reason::ObserverUnknown);
    m.observe(observation(1, 1000, None), 1000).unwrap();
    assert_eq!(one(&mut m, 1119).outcome, Outcome::NoMatch);
    m.observe(observation(2, 1120, None), 1120).unwrap();
    let gap = one(&mut m, 1120);
    assert_eq!(
        (gap.outcome, gap.reason),
        (Outcome::Match, Reason::HeartbeatAbsent)
    );
    assert_eq!(gap.gap_id, one(&mut m, 1121).gap_id);
    m.observe(observation(3, 1130, Some(1130)), 1130).unwrap();
    assert_eq!(one(&mut m, 1249).reason, Reason::HeartbeatCurrent);
    m.observe(observation(4, 1250, Some(1130)), 1250).unwrap();
    assert_eq!(one(&mut m, 1250).outcome, Outcome::Match);
    assert_ne!(gap.gap_id, one(&mut m, 1251).gap_id);
}

#[test]
fn replay_and_restore_never_refresh_observer_or_heartbeat() {
    let p = policy();
    let mut m = Monitor::new(p.clone(), 1000).unwrap();
    let original = observation(1, 1000, Some(1000));
    m.observe(original.clone(), 1000).unwrap();
    let bytes = m.snapshot().unwrap();
    assert_eq!(m.observe(original.clone(), 1400), Ok(Admission::Replayed));
    assert_eq!(bytes, m.snapshot().unwrap());
    let mut restored = Monitor::restore(p, &bytes).unwrap();
    restored.observe(original, 1499).unwrap();
    assert_eq!(
        one(&mut restored, 1499).reason,
        Reason::ObservationIncomplete
    );
    assert_eq!(one(&mut restored, 1500).reason, Reason::ObserverStale);
    assert_eq!(restored.metrics().replayed, 1);
}

#[test]
fn fresh_independent_probe_of_old_heartbeat_preserves_gap_identity_and_deadline() {
    let mut m = Monitor::new(policy(), 1000).unwrap();
    m.observe(observation(1, 1120, Some(1000)), 1120).unwrap();
    let gap = one(&mut m, 1120);
    let mut new = observation(2, 1600, Some(1000));
    new.checkpoint = Some(1);
    m.observe(new, 1600).unwrap();
    let same_gap = one(&mut m, 1600);
    assert_eq!(
        (same_gap.gap_id, same_gap.deadline_ms),
        (gap.gap_id, gap.deadline_ms)
    );
}

#[test]
fn unhealthy_or_stale_observer_and_missing_checkpoint_are_indeterminate() {
    let mut m = Monitor::new(policy(), 1000).unwrap();
    let mut o = observation(1, 1000, Some(1000));
    o.checkpoint = None;
    m.observe(o, 1000).unwrap();
    assert_eq!(one(&mut m, 1200).reason, Reason::CheckpointMissing);
    let mut unhealthy = observation(2, 1300, None);
    unhealthy.health = ObserverHealth::Unhealthy;
    m.observe(unhealthy, 1300).unwrap();
    let a = one(&mut m, 1400);
    assert_eq!(a.outcome, Outcome::Indeterminate);
    assert_eq!(a.reason, Reason::ObserverUnhealthy);
    assert_eq!(a.gap_id, None);
    m.observe(observation(3, 1500, None), 1500).unwrap();
    assert_eq!(one(&mut m, 1500).outcome, Outcome::Match);
    assert_eq!(one(&mut m, 2000).reason, Reason::ObserverStale);
}

#[test]
fn identity_scope_clock_heartbeat_and_checkpoint_conflicts_leave_snapshot_exact() {
    let mut m = Monitor::new(policy(), 1000).unwrap();
    m.observe(observation(2, 1100, Some(1050)), 1100).unwrap();
    let original = m.snapshot().unwrap();
    let mut cases = vec![
        observation(1, 1200, Some(1100)),
        observation(2, 1200, Some(1100)),
        observation(3, 1100, Some(1100)),
        observation(3, 1200, Some(1049)),
    ];
    let mut o = observation(3, 1200, Some(1100));
    o.checkpoint = Some(1);
    cases.push(o);
    let mut o = observation(3, 1200, Some(1100));
    o.binding = [2; 32];
    cases.push(o);
    let mut o = observation(3, 1200, Some(1100));
    o.observer_id = Uuid::from_u128(3);
    cases.push(o);
    let mut o = observation(3, 1200, Some(1100));
    o.source_id = Uuid::from_u128(5);
    cases.push(o);
    cases.push(observation(3, 1201, Some(1100)));
    cases.push(observation(3, 1200, Some(1201)));
    let mut o = observation(3, 1200, Some(1100));
    o.health = ObserverHealth::Unhealthy;
    cases.push(o);
    for o in cases {
        assert!(m.observe(o, 1200).is_err());
        assert_eq!(m.snapshot().unwrap(), original);
    }
    assert_eq!(m.metrics().rejected, 11);
}

#[test]
fn monotonic_clock_is_preserved_across_restore_and_future_expectation_refuses() {
    let p = policy();
    let mut m = Monitor::new(p.clone(), 1000).unwrap();
    one(&mut m, 1500);
    let original = m.snapshot().unwrap();
    assert_eq!(m.assess(1499), Err(Error::Clock));
    let mut restored = Monitor::restore(p.clone(), &original).unwrap();
    assert_eq!(
        restored.observe(observation(1, 1400, None), 1499),
        Err(Error::Clock)
    );
    assert_eq!(restored.snapshot().unwrap(), original);
    assert!(matches!(Monitor::new(p, 999), Err(Error::Clock)));
}

#[test]
fn restore_refuses_revision_inventory_unknown_fields_and_inconsistent_retained_state() {
    let p = policy();
    let mut m = Monitor::new(p.clone(), 1000).unwrap();
    m.observe(observation(1, 1000, Some(1000)), 1000).unwrap();
    let bytes = m.snapshot().unwrap();
    let mut changed = p.clone();
    changed.revision = "fixture-v2".into();
    assert!(Monitor::restore(changed, &bytes).is_err());
    let mut changed = p.clone();
    changed.expected[0].binding = [3; 32];
    assert!(Monitor::restore(changed, &bytes).is_err());
    for (path, value) in [
        ("schema_version", serde_json::json!(2)),
        ("clock_ms", serde_json::json!(999)),
        ("extra", serde_json::json!(true)),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v[path] = value;
        assert!(Monitor::restore(p.clone(), &serde_json::to_vec(&v).unwrap()).is_err());
    }
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["slots"][0]["heartbeat_at_ms"] = serde_json::json!(1001);
    assert!(Monitor::restore(p.clone(), &serde_json::to_vec(&v).unwrap()).is_err());
    v["slots"][0]["latest"] = serde_json::Value::Null;
    assert!(Monitor::restore(p, &serde_json::to_vec(&v).unwrap()).is_err());
}

#[test]
fn inventory_and_serialized_state_are_finite_and_capacity_refusal_is_atomic() {
    let mut p = policy();
    p.max_sources = 1;
    p.expected.push(ExpectedSource {
        source_id: Uuid::from_u128(3),
        ..p.expected[0].clone()
    });
    assert_eq!(p.validate(), Err(Error::Capacity));
    p.max_sources = 2;
    p.expected[1].source_id = p.expected[0].source_id;
    assert_eq!(p.validate(), Err(Error::Configuration));
    let mut p = policy();
    p.max_state_bytes = 1024;
    p.rule_id = "a".repeat(256);
    p.revision = "b".repeat(128);
    let mut m = Monitor::new(p.clone(), 1000).unwrap();
    let before = m.snapshot().unwrap();
    assert_eq!(
        m.observe(observation(1, 1000, Some(1000)), 1000),
        Err(Error::Capacity)
    );
    assert_eq!(before, m.snapshot().unwrap());
    assert!(matches!(
        Monitor::restore(p, &vec![b' '; 1025]),
        Err(Error::Capacity)
    ));
}

#[test]
fn multiple_expected_sources_are_isolated_and_output_count_is_bounded() {
    let mut p = policy();
    p.expected.push(ExpectedSource {
        source_id: Uuid::from_u128(3),
        binding: [3; 32],
        ..p.expected[0].clone()
    });
    let mut m = Monitor::new(p, 1000).unwrap();
    m.observe(observation(1, 1120, Some(1000)), 1120).unwrap();
    let result = m.assess(1120).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].outcome, Outcome::Match);
    assert_eq!(result[1].reason, Reason::ObserverUnknown);
}

#[test]
fn timestamp_overflow_refuses_instead_of_wrapping_or_advancing_state() {
    let mut m = Monitor::new(policy(), 1000).unwrap();
    m.observe(observation(1, MAX_TIME, Some(MAX_TIME)), MAX_TIME)
        .unwrap();
    let before = m.snapshot().unwrap();
    assert_eq!(m.assess(MAX_TIME), Err(Error::Clock));
    assert_eq!(m.snapshot().unwrap(), before);
}

#[test]
fn evaluation_clock_growth_cannot_exceed_committed_byte_budget() {
    let mut p = policy();
    p.rule_id = "a".repeat(256);
    p.revision = "b".repeat(128);
    let mut calibration = Monitor::new(p.clone(), 1000).unwrap();
    calibration
        .observe(observation(1, 1000, Some(1000)), 1000)
        .unwrap();
    p.max_state_bytes = calibration.snapshot().unwrap().len();
    assert!((1024..=9999).contains(&p.max_state_bytes));
    let mut m = Monitor::new(p, 1000).unwrap();
    m.observe(observation(1, 1000, Some(1000)), 1000).unwrap();
    let original = m.snapshot().unwrap();
    assert_eq!(m.assess(MAX_TIME), Err(Error::Capacity));
    assert_eq!(m.snapshot().unwrap(), original);
}

#[test]
fn fresh_observer_report_cannot_prove_absence_after_its_observation_time() {
    let mut m = Monitor::new(policy(), 1000).unwrap();
    m.observe(observation(1, 1000, Some(1000)), 1000).unwrap();
    let unknown = one(&mut m, 1120);
    assert_eq!(unknown.outcome, Outcome::Indeterminate);
    assert_eq!(unknown.gap_id, None);
    let mut later = observation(2, 1120, Some(1000));
    later.checkpoint = Some(1);
    m.observe(later, 1120).unwrap();
    assert_eq!(one(&mut m, 1120).outcome, Outcome::Match);
}

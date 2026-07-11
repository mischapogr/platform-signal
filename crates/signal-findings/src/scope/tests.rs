#![allow(clippy::unwrap_used)] // Assertions in bounded test fixtures only.
use super::*;
use crate::DetectionSeverity;

fn event(account: &str) -> SignalEvent {
    serde_json::from_value(
        serde_json::json!({"schema_version":1,"id":Uuid::from_u128(1),
        "timestamp":"2026-09-01T00:00:00Z","observed_at":"2026-09-01T00:00:00Z",
        "source":{"type":"audit"},"message":"synthetic","severity":"info",
        "attributes":{"account":"spoof","signal.scope.v1":{"account":"spoof"}},
        "resource":{"kind":"host","id":"host-a","account_id":account},"tags":[]}),
    )
    .unwrap()
}
fn derived(account: &str) -> DerivedFinding {
    let event = event(account);
    DerivedFinding::from_event(
        Finding::for_event("rule", &event, DetectionSeverity::High, "Title").unwrap(),
        &event,
        true,
    )
    .unwrap()
}
#[test]
fn canonical_builder_ignores_attributes_and_requires_exact_deterministic_base() {
    let generation = Uuid::from_u128(2);
    let boundary = Boundary {
        generation,
        cursor: FindingsCursor::initial(Uuid::from_u128(3)).unwrap(),
        bytes: 24,
        journal_digest: [0; 32],
    };
    let finding = derived("a").annotated(generation);
    let facts = boundary.facts(&finding, 36);
    assert_eq!(
        (facts.source, facts.account, facts.resource),
        (Some("audit"), Some("a"), Some("host-a"))
    );
    assert_eq!(boundary.facts(&finding, 24).account, None);
    let mut base = derived("a").base;
    base.attributes.insert("foreign".into(), Value::Bool(true));
    assert!(DerivedFinding::from_event(base, &event("a"), true).is_err());
}
#[test]
fn unknown_overlong_facts_still_distinguish_canonical_replay_bindings() {
    let generation = Uuid::from_u128(2);
    let a = derived(&"a".repeat(257)).annotated(generation);
    let b = derived(&"b".repeat(257)).annotated(generation);
    assert_ne!(a, b);
    assert_eq!(a.attributes[KEY]["account"], Value::Null);
}
#[test]
fn scope_control_fixed_roundtrip_and_every_byte_corruption_fail() {
    let control = Boundary {
        generation: Uuid::from_u128(4),
        cursor: FindingsCursor::initial(Uuid::from_u128(3)).unwrap(),
        bytes: 24,
        journal_digest: [0; 32],
    };
    let encoded = control.encode();
    let decoded = Boundary::decode(&encoded).unwrap();
    assert_eq!(decoded.generation, control.generation);
    assert_eq!(decoded.cursor.encode(), control.cursor.encode());
    assert_eq!(decoded.bytes, 24);
    for index in 0..encoded.len() {
        let mut bad = encoded;
        bad[index] ^= 1;
        assert!(Boundary::decode(&bad).is_err());
    }
    assert!(Boundary::decode(&encoded[..encoded.len() - 1]).is_err());
}

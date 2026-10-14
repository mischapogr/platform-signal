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

#[test]
fn sealed_shared_payload_binds_original_canonical_facts_and_reserved_bytes() {
    let generation = Uuid::from_u128(22);
    let payload = derived("a").into_scoped(generation).unwrap();
    let original = event("a");
    assert_eq!(payload.generation(), generation);
    assert_eq!(payload.finding().event_ids, [original.id]);
    assert_eq!(payload.finding(), &derived("a").annotated(generation));
    let facts = payload.facts();
    assert_eq!(facts.source, Some("audit"));
    assert_eq!(facts.account, Some("a"));
    assert_eq!(facts.resource, Some("host-a"));
    assert_eq!(
        payload.finding().attributes[KEY]["binding_digest"],
        payload.binding_digest()
    );
    assert_eq!(payload.binding_digest().len(), 64);
}

#[test]
fn shared_payload_refuses_unverified_replay_and_missing_activation() {
    let original = event("a");
    let base = Finding::for_event("rule", &original, DetectionSeverity::High, "Title").unwrap();
    let unverified = DerivedFinding::from_event(base, &original, false).unwrap();
    assert!(unverified.into_scoped(Uuid::from_u128(22)).is_err());
    assert!(derived("a").into_scoped(Uuid::nil()).is_err());
}

#[test]
fn sealed_unknown_selectors_preserve_full_binding_without_truncation() {
    let generation = Uuid::from_u128(22);
    let a = derived(&"a".repeat(257)).into_scoped(generation).unwrap();
    let b = derived(&"b".repeat(257)).into_scoped(generation).unwrap();
    assert_eq!(a.facts().account, None);
    assert_eq!(a.finding().attributes[KEY]["account"], Value::Null);
    assert_ne!(a.binding_digest(), b.binding_digest());
    assert_ne!(a.finding(), b.finding());
    assert_eq!(a.finding().id, b.finding().id);
}

#[test]
fn multi_event_derivation_requires_complete_distinct_same_scope_references() {
    let a = event("a");
    let mut b = event("a");
    b.id = Uuid::from_u128(2);
    let mut base =
        Finding::for_event("window-rule", &a, DetectionSeverity::Medium, "Window").unwrap();
    base.id = Uuid::from_u128(10);
    base.event_ids.push(b.id);
    let derived = DerivedFinding::from_events(base.clone(), &[&a, &b], true).unwrap();
    let scoped = derived.into_scoped(Uuid::from_u128(3)).unwrap();
    assert_eq!(scoped.facts().account, Some("a"));
    assert_eq!(scoped.finding().event_ids, vec![a.id, b.id]);
    assert!(DerivedFinding::from_events(base.clone(), &[&a], true).is_err());
    assert!(DerivedFinding::from_events(base.clone(), &[&b, &a], true).is_err());
    assert!(DerivedFinding::from_events(base.clone(), &[&a, &a], true).is_err());
    for dimension in ["account", "resource", "source"] {
        let mut other = b.clone();
        match dimension {
            "account" => other.resource.as_mut().unwrap().account_id = Some("other".into()),
            "resource" => other.resource.as_mut().unwrap().id = "other".into(),
            _ => other.source.source_type = "other".into(),
        }
        assert!(DerivedFinding::from_events(base.clone(), &[&a, &other], true).is_err());
    }
    let mut spoofed = base.clone();
    spoofed
        .attributes
        .insert(KEY.into(), serde_json::json!({"account":"a"}));
    assert!(DerivedFinding::from_events(spoofed, &[&a, &b], true).is_err());
    let mut duplicate = base;
    duplicate.event_ids = vec![a.id, a.id];
    assert!(DerivedFinding::from_events(duplicate, &[&a, &a], true).is_err());
}

#[test]
fn multi_event_unverified_admission_cannot_gain_scope() {
    let a = event("a");
    let base = Finding::for_event("window-rule", &a, DetectionSeverity::Medium, "Window").unwrap();
    let derived = DerivedFinding::from_events(base, &[&a], false).unwrap();
    assert!(derived.into_scoped(Uuid::from_u128(3)).is_err());
}

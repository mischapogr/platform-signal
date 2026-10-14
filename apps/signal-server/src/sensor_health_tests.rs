#![allow(clippy::unwrap_used)]
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use signal_rules::sensor_health::{
    Admission, ExpectedSource, Monitor, ObserverHealth, Outcome, Reason,
};

fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn policy() -> Policy {
    Policy {
        schema_version: 1,
        rule_id: "fixture-heartbeat".into(),
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
fn key(observer: u128, signer: &Ed25519KeyPair) -> ObserverKey {
    ObserverKey {
        schema_version: 1,
        observer_id: Uuid::from_u128(observer),
        public_key: signer.public_key().as_ref().try_into().unwrap(),
    }
}
fn verifier() -> Verifier {
    Verifier::new(policy(), vec![key(2, &signer(3))]).unwrap()
}
fn observation() -> Observation {
    Observation {
        schema_version: 1,
        source_id: Uuid::from_u128(1),
        binding: [1; 32],
        observer_id: Uuid::from_u128(2),
        sequence: 1,
        observed_at_ms: 1000,
        health: ObserverHealth::Healthy,
        heartbeat_at_ms: Some(1000),
        checkpoint: Some(1),
    }
}
fn payload(v: &Verifier, o: Observation) -> Vec<u8> {
    serde_json::to_vec(&Payload {
        schema_version: 1,
        policy_sha256: v.policy_sha256(),
        observation: o,
    })
    .unwrap()
}
fn signed(raw: &[u8], signer: &Ed25519KeyPair, domain: &[u8], outer: u128) -> Vec<u8> {
    let mut signing = domain.to_vec();
    signing.extend_from_slice(raw);
    serde_json::to_vec(&serde_json::json!({"schema_version":1,"observer_id":Uuid::from_u128(outer),
        "payload_base64":STANDARD.encode(raw),"signature_base64":STANDARD.encode(signer.sign(&signing).as_ref())})).unwrap()
}
fn proof(v: &Verifier, o: Observation) -> Vec<u8> {
    signed(&payload(v, o), &signer(3), DOMAIN, 2)
}

#[test]
fn authenticated_original_bytes_and_policy_bound_observation_drive_gap_assessment() {
    let v = verifier();
    let raw = payload(&v, observation());
    let original = signed(&raw, &signer(3), DOMAIN, 2);
    let verified = v.verify(&original, 1120).unwrap();
    assert_eq!(verified.original_envelope(), original);
    assert_eq!(
        verified.payload_sha256(),
        <[u8; 32]>::from(Sha256::digest(&raw))
    );
    assert_eq!(verified.policy_sha256(), v.policy_sha256());
    assert_eq!(verified.enrollment_sha256(), v.enrollment_sha256());
    assert_eq!(verified.valid_until_ms(), 1500);
    let mut monitor = Monitor::new(policy(), 1000).unwrap();
    monitor
        .observe(verified.observation().clone(), 1120)
        .unwrap();
    let result = monitor.assess(1120).unwrap();
    assert_eq!(result[0].outcome, Outcome::Match);
    assert!(result[0].gap_id.is_some());
}

#[test]
fn verified_replay_cannot_extend_freshness_and_exact_expiry_matches_evaluator() {
    let v = verifier();
    let bytes = proof(&v, observation());
    let mut monitor = Monitor::new(policy(), 1000).unwrap();
    monitor
        .observe(v.verify(&bytes, 1000).unwrap().observation().clone(), 1000)
        .unwrap();
    let before = monitor.snapshot().unwrap();
    let replay = v.verify(&bytes, 1499).unwrap();
    assert_eq!(replay.valid_until_ms(), 1500);
    assert_eq!(
        monitor.observe(replay.observation().clone(), 1499),
        Ok(Admission::Replayed)
    );
    assert_eq!(monitor.snapshot().unwrap(), before);
    assert!(matches!(v.verify(&bytes, 1500), Err(Error::Expired)));
    assert_eq!(
        monitor.assess(1500).unwrap()[0].reason,
        Reason::ObserverStale
    );
    let mut restored = Monitor::restore(policy(), &before).unwrap();
    assert_eq!(
        restored.assess(1500).unwrap()[0].outcome,
        Outcome::Indeterminate
    );
}

#[test]
fn signature_checks_exact_payload_bytes_and_domain_without_normalizing_json() {
    let v = verifier();
    let raw = serde_json::to_vec_pretty(
        &serde_json::from_slice::<serde_json::Value>(&payload(&v, observation())).unwrap(),
    )
    .unwrap();
    let original = signed(&raw, &signer(3), DOMAIN, 2);
    assert!(v.verify(&original, 1000).is_ok());
    let mut envelope: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let mut changed = raw;
    changed.push(b'\n');
    envelope["payload_base64"] = STANDARD.encode(changed).into();
    assert!(matches!(
        v.verify(&serde_json::to_vec(&envelope).unwrap(), 1000),
        Err(Error::Signature)
    ));
    assert!(matches!(
        v.verify(
            &signed(
                &payload(&v, observation()),
                &signer(3),
                b"other-protocol\0",
                2
            ),
            1000
        ),
        Err(Error::Signature)
    ));
    assert!(matches!(
        v.verify(
            &signed(&payload(&v, observation()), &signer(4), DOMAIN, 2),
            1000
        ),
        Err(Error::Signature)
    ));
}

#[test]
fn authenticated_payload_still_requires_exact_policy_source_binding_and_observer() {
    let v = verifier();
    let bytes = proof(&v, observation());
    let mut changed = policy();
    changed.revision = "fixture-v2".into();
    let other = Verifier::new(changed, vec![key(2, &signer(3))]).unwrap();
    assert!(matches!(other.verify(&bytes, 1000), Err(Error::Scope)));
    let mut o = observation();
    o.source_id = Uuid::from_u128(9);
    assert!(matches!(v.verify(&proof(&v, o), 1000), Err(Error::Scope)));
    let mut o = observation();
    o.binding = [9; 32];
    assert!(matches!(
        v.verify(&proof(&v, o), 1000),
        Err(Error::Observation(
            signal_rules::sensor_health::Error::Scope
        ))
    ));
    let mut o = observation();
    o.observer_id = Uuid::from_u128(9);
    assert!(matches!(v.verify(&proof(&v, o), 1000), Err(Error::Scope)));
    assert!(matches!(
        v.verify(
            &signed(&payload(&v, observation()), &signer(3), DOMAIN, 9),
            1000
        ),
        Err(Error::Scope)
    ));
}

#[test]
fn signed_future_or_malformed_observations_and_invalid_receiver_clocks_are_refused() {
    let v = verifier();
    let mut bad = vec![];
    let mut o = observation();
    o.sequence = 0;
    bad.push(o);
    let mut o = observation();
    o.schema_version = 2;
    bad.push(o);
    let mut o = observation();
    o.observed_at_ms = 1001;
    bad.push(o);
    let mut o = observation();
    o.heartbeat_at_ms = Some(1001);
    bad.push(o);
    let mut o = observation();
    o.health = ObserverHealth::Unhealthy;
    bad.push(o);
    for o in bad {
        assert!(matches!(
            v.verify(&proof(&v, o), 1000),
            Err(Error::Observation(_))
        ));
    }
    for now in [-1, 253_402_300_800_000] {
        assert!(matches!(
            v.verify(&proof(&v, observation()), now),
            Err(Error::Observation(
                signal_rules::sensor_health::Error::Clock
            ))
        ));
    }
}

#[test]
fn signed_unhealthy_or_incomplete_report_never_becomes_healthy_absence() {
    let v = verifier();
    let mut monitor = Monitor::new(policy(), 1000).unwrap();
    let mut o = observation();
    o.health = ObserverHealth::Unhealthy;
    o.heartbeat_at_ms = None;
    o.checkpoint = None;
    monitor
        .observe(
            v.verify(&proof(&v, o), 1120).unwrap().observation().clone(),
            1120,
        )
        .unwrap();
    assert_eq!(
        monitor.assess(1120).unwrap()[0].reason,
        Reason::ObserverUnhealthy
    );
    let mut o = observation();
    o.sequence = 2;
    o.observed_at_ms = 1200;
    o.checkpoint = None;
    monitor
        .observe(
            v.verify(&proof(&v, o), 1200).unwrap().observation().clone(),
            1200,
        )
        .unwrap();
    assert_eq!(
        monitor.assess(1200).unwrap()[0].reason,
        Reason::CheckpointMissing
    );
}

#[test]
fn envelope_and_payload_versions_unknown_fields_and_duplicate_fields_are_refused() {
    let v = verifier();
    let original = proof(&v, observation());
    for (name, value) in [
        ("schema_version", serde_json::json!(2)),
        ("extra", serde_json::json!(true)),
    ] {
        let mut envelope: serde_json::Value = serde_json::from_slice(&original).unwrap();
        envelope[name] = value;
        assert!(matches!(
            v.verify(&serde_json::to_vec(&envelope).unwrap(), 1000),
            Err(Error::Envelope)
        ));
    }
    let mut document: serde_json::Value =
        serde_json::from_slice(&payload(&v, observation())).unwrap();
    document["extra"] = true.into();
    assert!(matches!(
        v.verify(
            &signed(
                &serde_json::to_vec(&document).unwrap(),
                &signer(3),
                DOMAIN,
                2
            ),
            1000
        ),
        Err(Error::Envelope)
    ));
    document.as_object_mut().unwrap().remove("extra");
    document["observation"]["extra"] = true.into();
    assert!(matches!(
        v.verify(
            &signed(
                &serde_json::to_vec(&document).unwrap(),
                &signer(3),
                DOMAIN,
                2
            ),
            1000
        ),
        Err(Error::Envelope)
    ));
    let duplicate = String::from_utf8(original)
        .unwrap()
        .replacen('{', "{\"schema_version\":1,", 1);
    assert!(matches!(
        v.verify(duplicate.as_bytes(), 1000),
        Err(Error::Envelope)
    ));
}

#[test]
fn empty_oversized_and_invalid_base64_inputs_have_bounded_refusals() {
    let v = verifier();
    assert!(matches!(v.verify(&[], 1000), Err(Error::Capacity)));
    assert!(matches!(
        v.verify(&vec![b' '; MAX_ENVELOPE_BYTES + 1], 1000),
        Err(Error::Capacity)
    ));
    let oversized = signed(&vec![b' '; MAX_PAYLOAD_BYTES + 1], &signer(3), DOMAIN, 2);
    assert!(oversized.len() < MAX_ENVELOPE_BYTES);
    assert!(matches!(v.verify(&oversized, 1000), Err(Error::Capacity)));
    for (field, value) in [
        ("payload_base64", "***".to_owned()),
        ("signature_base64", "!".repeat(88)),
    ] {
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&proof(&v, observation())).unwrap();
        envelope[field] = value.into();
        assert!(
            v.verify(&serde_json::to_vec(&envelope).unwrap(), 1000)
                .is_err()
        );
    }
}

#[test]
fn key_enrollment_requires_exact_inventory_and_unique_nonzero_versioned_keys() {
    assert!(matches!(
        Verifier::new(policy(), vec![]),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Verifier::new(policy(), vec![key(9, &signer(3))]),
        Err(Error::Configuration)
    ));
    let mut k = key(2, &signer(3));
    k.public_key = [0; 32];
    assert!(matches!(
        Verifier::new(policy(), vec![k]),
        Err(Error::Configuration)
    ));
    let mut k = key(2, &signer(3));
    k.schema_version = 2;
    assert!(matches!(
        Verifier::new(policy(), vec![k]),
        Err(Error::Configuration)
    ));
    let mut p = policy();
    p.expected.push(ExpectedSource {
        source_id: Uuid::from_u128(3),
        observer_id: Uuid::from_u128(4),
        ..p.expected[0].clone()
    });
    assert!(matches!(
        Verifier::new(p, vec![key(2, &signer(3)), key(2, &signer(3))]),
        Err(Error::Configuration)
    ));
}

#[test]
fn each_independent_observer_uses_its_own_enrolled_key() {
    let mut p = policy();
    p.expected.push(ExpectedSource {
        source_id: Uuid::from_u128(3),
        observer_id: Uuid::from_u128(4),
        binding: [3; 32],
        ..p.expected[0].clone()
    });
    let v = Verifier::new(p, vec![key(2, &signer(3)), key(4, &signer(5))]).unwrap();
    let mut o = observation();
    o.source_id = Uuid::from_u128(3);
    o.observer_id = Uuid::from_u128(4);
    o.binding = [3; 32];
    let raw = payload(&v, o);
    assert!(v.verify(&signed(&raw, &signer(5), DOMAIN, 4), 1000).is_ok());
    assert!(matches!(
        v.verify(&signed(&raw, &signer(3), DOMAIN, 4), 1000),
        Err(Error::Signature)
    ));
}

#[test]
fn fresh_signed_probe_of_old_heartbeat_renews_only_observer_visibility() {
    let v = verifier();
    let mut monitor = Monitor::new(policy(), 1000).unwrap();
    monitor
        .observe(
            v.verify(&proof(&v, observation()), 1000)
                .unwrap()
                .observation()
                .clone(),
            1000,
        )
        .unwrap();
    let original = monitor.assess(1120).unwrap().remove(0);
    assert_eq!(
        monitor.assess(1500).unwrap()[0].reason,
        Reason::ObserverStale
    );
    let mut o = observation();
    o.sequence = 2;
    o.observed_at_ms = 1600;
    monitor
        .observe(
            v.verify(&proof(&v, o), 1600).unwrap().observation().clone(),
            1600,
        )
        .unwrap();
    let current = monitor.assess(1600).unwrap().remove(0);
    assert_eq!(current.outcome, Outcome::Match);
    assert_eq!(
        (current.gap_id, current.deadline_ms),
        (original.gap_id, original.deadline_ms)
    );
}

#[test]
fn complete_enrollment_digest_fences_key_rotation_and_is_key_order_independent() {
    let v = verifier();
    let rotated = Verifier::new(policy(), vec![key(2, &signer(4))]).unwrap();
    assert_eq!(v.policy_sha256(), rotated.policy_sha256());
    assert_ne!(v.enrollment_sha256(), rotated.enrollment_sha256());
    assert!(matches!(
        rotated.verify(&proof(&v, observation()), 1000),
        Err(Error::Signature)
    ));
    let mut p = policy();
    p.expected.push(ExpectedSource {
        source_id: Uuid::from_u128(3),
        observer_id: Uuid::from_u128(4),
        ..p.expected[0].clone()
    });
    let first = Verifier::new(p.clone(), vec![key(2, &signer(3)), key(4, &signer(5))]).unwrap();
    let reordered = Verifier::new(p, vec![key(4, &signer(5)), key(2, &signer(3))]).unwrap();
    assert_eq!(first.enrollment_sha256(), reordered.enrollment_sha256());
}

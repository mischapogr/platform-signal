#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/correlation_d14.rs"]
mod support;
use serde_json::json;
use signal_rules::correlation::{Error, d14::*};
use std::time::Duration;
use support::*;
use uuid::Uuid;

fn runtime_proofs(b: &RuntimeBinding) -> Vec<RuntimeVerification> {
    b.config()
        .sources
        .iter()
        .map(|s| RuntimeVerification {
            source: signal_rules::correlation::Verification {
                stream: s.stream,
                position: 10,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: b.config().authority_keys_sha256,
                verification_reference: "fixture://independent-capture-clock-prefix".into(),
                verified_at: ns(BASE + 100_000_000),
                verified_until: ns(BASE + 60_000_000_000),
                now: ns(BASE + 100_000_000),
                coverage_from: ns(BASE - 10_000_000),
                frontier: ns(BASE + 50_000_000),
                complete: true,
                authenticated: true,
            },
            capture: CaptureEvidence {
                enrollment_sha256: b.enrollment_sha256(),
                metadata_only: true,
                execution_continuity: true,
                clock_continuity: true,
            },
        })
        .collect()
}
fn policy_coverage(b: &RuntimeBinding) -> Vec<PolicyCoverageVerification> {
    b.config()
        .policy_authorities
        .iter()
        .enumerate()
        .map(|(i, a)| PolicyCoverageVerification {
            enrollment_sha256: b.enrollment_sha256(),
            authority: a.id,
            authority_binding: a.binding,
            config_revision: a.config_revision.clone(),
            authority_keys_sha256: a.authority_keys_sha256,
            policy_revision: a.policy_revision.clone(),
            policy_config_sha256: a.policy_config_sha256,
            reference: "fixture://independent-policy-coverage".into(),
            verified_at: ns(BASE + 100_000_000),
            verified_until: ns(BASE + 60_000_000_000),
            now: ns(BASE + 100_000_000),
            coverage_from: ns(BASE - 10_000_000),
            frontier: ns(BASE + 40_000_000 - i as u64 * 10_000_000),
            complete: true,
            authenticated: true,
        })
        .collect()
}

#[test]
fn runtime_epoch_minimum_includes_all_policy_proofs_without_delivery_ordinals() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
    assert_eq!(ep.watermark(&b, &c)?, Some(ns(BASE + 29_000_000)));
    assert!(!ep.has_coverage_gap(&b, &c)?);
    let i = input(&b, &event(true)?, &c)?;
    ep.verify_input(&b, &i, 2, &c)?;
    assert_eq!(ep.verify_input(&b, &i, 0, &c), Err(Error::Conflict));
    assert_eq!(ep.verify_input(&b, &i, 11, &c), Err(Error::Unverified));
    let mut sources = runtime_proofs(&b);
    sources[0].source.coverage_from = ns(BASE + 1);
    let ep = RuntimeEpoch::new(&b, sources, policy_coverage(&b), &c)?;
    assert_eq!(ep.verify_input(&b, &i, 2, &c), Err(Error::Unverified));
    Ok(())
}

#[test]
fn missing_incomplete_and_unverified_clock_coverage_never_prove_clean_history() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let mut policies = policy_coverage(&b);
    policies.pop();
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policies, &c)?;
    assert_eq!(ep.watermark(&b, &c)?, None);
    assert!(ep.has_coverage_gap(&b, &c)?);
    let ep = RuntimeEpoch::new(&b, vec![], policy_coverage(&b), &c)?;
    assert_eq!(ep.watermark(&b, &c)?, None);
    for clock in [false, true] {
        let mut sources = runtime_proofs(&b);
        sources[0].capture.clock_continuity = clock;
        sources[0].capture.execution_continuity = !clock;
        let ep = RuntimeEpoch::new(&b, sources, policy_coverage(&b), &c)?;
        assert!(ep.has_coverage_gap(&b, &c)?);
    }
    let mut policies = policy_coverage(&b);
    policies[0].complete = false;
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policies, &c)?;
    assert!(ep.watermark(&b, &c)?.is_some());
    assert!(ep.has_coverage_gap(&b, &c)?);
    Ok(())
}

#[test]
fn runtime_epoch_pins_enrollment_capture_privacy_policy_and_source_authority() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for edit in 0..4 {
        let mut sources = runtime_proofs(&b);
        match edit {
            0 => sources[0].capture.metadata_only = false,
            1 => sources[0].capture.enrollment_sha256 = [9; 32],
            2 => sources[0].source.authenticated = false,
            _ => sources[0].source.authority_keys_sha256 = [9; 32],
        }
        assert!(
            RuntimeEpoch::new(&b, sources, policy_coverage(&b), &c).is_err(),
            "source{edit}"
        );
    }
    for edit in 0..7 {
        let mut policies = policy_coverage(&b);
        match edit {
            0 => policies[0].enrollment_sha256 = [9; 32],
            1 => policies[0].authenticated = false,
            2 => policies[0].authority_binding = [9; 32],
            3 => policies[0].policy_revision = "other".into(),
            4 => policies[0].verified_until = policies[0].now,
            5 => policies[1].authority = policies[0].authority,
            _ => policies[0].frontier = ns(BASE + 101_000_000),
        }
        assert!(
            RuntimeEpoch::new(&b, runtime_proofs(&b), policies, &c).is_err(),
            "policy{edit}"
        );
    }
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
    let mut cfg = config();
    cfg.policy_authorities[0].account = Some("other-account".into());
    let other = RuntimeBinding::new(cfg, &c)?;
    assert_eq!(ep.watermark(&other, &c), Err(Error::Conflict));
    Ok(())
}

#[tokio::test]
async fn runtime_epoch_preserves_original_cancellation_and_minimum_source_policy_expiry() -> Result
{
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let original = context();
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &original)?;
    original.cancellation.cancel();
    assert_eq!(ep.watermark(&b, &c), Err(Error::Cancelled));
    for source_first in [true, false] {
        let mut sources = runtime_proofs(&b);
        let mut policies = policy_coverage(&b);
        if source_first {
            sources[0].source.verified_until =
                sources[0].source.now + chrono::TimeDelta::milliseconds(2);
        } else {
            policies[0].verified_until = policies[0].now + chrono::TimeDelta::milliseconds(2);
        }
        let ep = RuntimeEpoch::new(&b, sources, policies, &c)?;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(ep.watermark(&b, &c), Err(Error::Cancelled));
    }
    Ok(())
}

#[test]
fn runtime_inventory_and_policy_roles_are_separate_bounded_and_pinned() -> Result {
    let c = context();
    RuntimeBinding::new(config(), &c)?;
    for edit in 0..10 {
        let mut cfg = config();
        match edit {
            0 => cfg.schema_version = 1,
            1 => cfg.sources[0].connects = false,
            2 => cfg.policy_authorities.pop().map(|_| ()).unwrap(),
            3 => cfg.policy_authorities[1].role = Role::Asset,
            4 => cfg.policy_authorities[0].id = cfg.sources[0].stream,
            5 => cfg.policy_authorities[0].authority_keys_sha256 = [0; 32],
            6 => cfg.ttl_ms = 20,
            7 => cfg.max_events = 1,
            8 => cfg.sources[0].host = "x".repeat(257),
            _ => cfg.sources[0].audit_arch = 0x40000003,
        }
        assert!(RuntimeBinding::new(cfg, &c).is_err(), "case{edit}");
    }
    for host in ["x".repeat(129), "invalid host".into()] {
        let mut cfg = config();
        cfg.sources[0].host = host;
        assert!(RuntimeBinding::new(cfg, &c).is_err());
    }
    Ok(())
}

#[test]
fn metadata_contract_process_roles_and_original_commitments_are_exact() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let original = event(true)?;
    let first = input(&b, &original, &c)?;
    let mut replay = original.clone();
    replay.id = Uuid::from_u128(99);
    replay.observed_at += chrono::TimeDelta::seconds(1);
    let alias = input(&b, &replay, &c)?;
    assert_ne!(first.canonical_sha256(), alias.canonical_sha256());
    assert_eq!(first.content_sha256(), alias.content_sha256());
    assert_eq!(first.process().capture, Uuid::from_u128(4));
    assert_eq!(first.native_sequence(), 2);
    for edit in 0..12 {
        let mut e = original.clone();
        let m = &mut e.attributes["runtime_metadata"];
        match edit {
            0 => m["process"]["host"] = json!("other-host"),
            1 => m["native"]["capture"] = json!(Uuid::from_u128(5)),
            2 => m["process"]["boot"] = json!(Uuid::nil()),
            3 => m["process"]["start_ticks"] = json!(0),
            4 => m["config_sha256"] = json!(vec![6; 32]),
            5 => m["operation"]["protected_credential"] = json!(true),
            6 => m["operation"]["result"] = json!(65),
            7 => m["operation"]["interval"]["exit_ns"] = json!(BASE + 100_000_000),
            8 => m["original_record_sha256"] = json!(vec![0; 32]),
            9 => m["observed_ns"] = json!(BASE),
            10 => m["operation"]["object"]["ctime_nsec"] = json!(1_000_000_000),
            _ => m["operation"]["error"] = json!(true),
        }
        assert!(input(&b, &e, &c).is_err(), "case{edit}");
    }
    assert!(Input::new(&b, Uuid::from_u128(999), &original, &c).is_err());
    let mut oversized = original.clone();
    oversized
        .attributes
        .insert("private_large".into(), json!("x".repeat(70_000)));
    assert!(
        matches!(input(&b,&oversized,&c),Err(e) if e.downcast_ref::<Error>()==Some(&Error::Capacity))
    );
    Ok(())
}

#[test]
fn producer_classification_flags_never_create_a_current_decision() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let mut e = event(true)?;
    e.attributes.insert(
        "private_policy".into(),
        json!({"protected_read":true,"authenticated":true,"suspicious":true}),
    );
    let i = input(&b, &e, &c)?;
    let mut proof = verification(&b, &i, true, &c)?;
    proof.authenticated = false;
    assert!(matches!(
        CurrentDecision::new(&b, &i, proof, &c),
        Err(Error::Unverified)
    ));
    for result in [0, -14] {
        let mut e = event(true)?;
        e.attributes["runtime_metadata"]["operation"]["result"] = json!(result);
        e.attributes["runtime_metadata"]["operation"]["error"] = json!(result < 0);
        let i = input(&b, &e, &c)?;
        assert_eq!(i.claim(&c), Err(Error::Invalid));
    }
    let mut e = event(true)?;
    e.attributes["runtime_metadata"]["operation"]["object"]["object_type"] = json!(0o140000);
    assert_eq!(input(&b, &e, &c)?.claim(&c), Err(Error::Invalid));
    Ok(())
}

#[test]
fn policy_scope_is_committed_and_retained_as_required_authorization_not_a_grant() -> Result {
    let c = context();
    let mut cfg = config();
    cfg.policy_authorities[0].account = Some("synthetic-account".into());
    cfg.policy_authorities[0].resource = Some("synthetic-policy-resource".into());
    let b = RuntimeBinding::new(cfg.clone(), &c)?;
    let i = input(&b, &event(true)?, &c)?;
    let evidence = decision(&b, &i, true, &c)?;
    let scope = evidence.contributor(&b, &i, &c)?;
    assert_eq!(scope.account.as_deref(), Some("synthetic-account"));
    assert_eq!(scope.resource.as_deref(), Some("synthetic-policy-resource"));
    assert_eq!(scope.stream, Uuid::from_u128(100));
    cfg.policy_authorities[0].account = Some("other-account".into());
    let other = RuntimeBinding::new(cfg, &c)?;
    assert!(evidence.contributor(&other, &i, &c).is_err());
    for field in ["account", "resource"] {
        let mut cfg = config();
        let invalid = Some("x".repeat(257));
        if field == "account" {
            cfg.policy_authorities[0].account = invalid;
        } else {
            cfg.policy_authorities[0].resource = invalid;
        }
        assert!(RuntimeBinding::new(cfg, &c).is_err());
    }
    Ok(())
}

#[test]
fn classification_binds_input_authority_policy_keys_role_and_complete_interval() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let e = event(true)?;
    let i = input(&b, &e, &c)?;
    for edit in 0..14 {
        let mut p = verification(&b, &i, true, &c)?;
        match edit {
            0 => p.authority_binding = [9; 32],
            1 => p.authority_keys_sha256 = [9; 32],
            2 => p.policy_config_sha256 = [9; 32],
            3 => p.policy_revision = "other-policy".into(),
            4 => p.config_revision = "other-source-config".into(),
            5 => p.decision = Decision::Destination { suspicious: true },
            6 => p.covered_from = ns(BASE + 1),
            7 => p.covered_through = ns(BASE + 999_999),
            8 => p.verified_until = p.now,
            9 => p.verified_at = p.now + chrono::TimeDelta::seconds(1),
            10 => p.claim = input(&b, &event(false)?, &c)?.claim(&c)?,
            11 => p.reference = "x".repeat(257),
            12 => {
                p.now = ns(BASE + 1_000_001);
                p.verified_at = p.now;
            }
            _ => {
                p.now = ns(BASE + 2_000_000);
                p.verified_at = p.now;
            }
        }
        assert!(CurrentDecision::new(&b, &i, p, &c).is_err(), "case{edit}");
    }
    let exact =
        CurrentDecision::new(&b, &i, verification(&b, &i, true, &c)?, &c)?.retained(&b, &i, &c)?;
    let restored: DecisionEvidence = serde_json::from_slice(&serde_json::to_vec(&exact)?)?;
    restored.validate_historical(&b, &i, &c)?;
    let mut changed = e.clone();
    changed.id = Uuid::from_u128(900);
    let new = input(&b, &changed, &c)?;
    assert!(restored.validate_historical(&b, &new, &c).is_err());
    let mut newer = config();
    newer.policy_authorities[0].policy_revision = "new-policy".into();
    assert!(
        restored
            .validate_historical(&RuntimeBinding::new(newer, &c)?, &i, &c)
            .is_err()
    );
    Ok(())
}

#[test]
fn pair_relation_uses_exact_execution_identity_policy_and_interval_uncertainty() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let r = input(&b, &event(true)?, &c)?;
    let a = decision(&b, &r, true, &c)?;
    let con = input(&b, &event(false)?, &c)?;
    let d = decision(&b, &con, true, &c)?;
    assert_eq!(relation(&b, &r, &a, &con, &d, &c)?, Relation::Match);
    let no = decision(&b, &con, false, &c)?;
    assert_eq!(
        relation(&b, &r, &a, &con, &no, &c)?,
        Relation::NotApplicable
    );
    for (key, value) in [
        ("boot", json!(Uuid::from_u128(9))),
        ("capture", json!(Uuid::from_u128(9))),
        ("pid", json!(101)),
        ("start_ticks", json!(1001)),
        ("execution_generation", json!(2)),
    ] {
        let mut e = event(false)?;
        e.attributes["runtime_metadata"]["process"][key] = value.clone();
        if key == "capture" {
            e.attributes["runtime_metadata"]["native"]["capture"] = value;
        }
        let i = input(&b, &e, &c)?;
        let p = decision(&b, &i, true, &c)?;
        assert_eq!(
            relation(&b, &r, &a, &i, &p, &c)?,
            Relation::NotApplicable,
            "{key}"
        );
    }
    for (entry, exit, expected) in [
        (10_000_000, 20_000_000, Relation::Match),
        (10_000_000, 20_000_001, Relation::Uncertain),
        (1_000_000, 2_000_000, Relation::Uncertain),
        (22_000_000, 23_000_000, Relation::NotApplicable),
    ] {
        let mut e = event(false)?;
        let m = &mut e.attributes["runtime_metadata"];
        m["operation"]["interval"] = json!({"entry_ns":BASE+entry,"exit_ns":BASE+exit});
        m["observed_ns"] = json!(BASE + exit + 100);
        e.timestamp = ns(BASE + exit + 100);
        let i = input(&b, &e, &c)?;
        let p = decision(&b, &i, true, &c)?;
        assert_eq!(
            relation(&b, &r, &a, &i, &p, &c)?,
            expected,
            "{entry}-{exit}"
        );
    }
    let mut e = event(false)?;
    e.attributes["runtime_metadata"]["native"]["sequence"] = json!(2);
    let i = input(&b, &e, &c)?;
    let p = decision(&b, &i, true, &c)?;
    assert_eq!(relation(&b, &r, &a, &i, &p, &c)?, Relation::Uncertain);
    Ok(())
}

#[tokio::test]
async fn current_lifetime_preserves_both_cancellation_tokens_and_historical_data_is_not_authority()
-> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let original = context();
    let e = event(true)?;
    let i = input(&b, &e, &original)?;
    let current = CurrentDecision::new(&b, &i, verification(&b, &i, true, &c)?, &c)?;
    let saved = current.retained(&b, &i, &c)?;
    original.cancellation.cancel();
    assert_eq!(current.retained(&b, &i, &c), Err(Error::Cancelled));
    assert_eq!(i.claim(&c), Err(Error::Cancelled));
    saved.validate_historical(&b, &i, &context())?;
    let i = input(&b, &e, &c)?;
    let proof_context = context();
    let current = CurrentDecision::new(
        &b,
        &i,
        verification(&b, &i, true, &proof_context)?,
        &proof_context,
    )?;
    proof_context.cancellation.cancel();
    assert_eq!(current.retained(&b, &i, &c), Err(Error::Cancelled));
    let i = input(&b, &e, &c)?;
    let mut p = verification(&b, &i, true, &c)?;
    p.verified_until = p.now + chrono::TimeDelta::milliseconds(2);
    let short = CurrentDecision::new(&b, &i, p, &c)?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(short.retained(&b, &i, &c), Err(Error::Cancelled));
    Ok(())
}

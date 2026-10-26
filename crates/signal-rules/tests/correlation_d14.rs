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

#[test]
fn runtime_admission_retains_first_unknown_negative_and_positive_classification_on_native_replay()
-> Result {
    use signal_rules::correlation::Admission;
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for classified in [None, Some(false), Some(true)] {
        let e = event(true)?;
        let i = input(&b, &e, &c)?;
        let current = classified
            .map(|yes| -> Result<CurrentDecision> {
                Ok(CurrentDecision::new(
                    &b,
                    &i,
                    verification(&b, &i, yes, &c)?,
                    &c,
                )?)
            })
            .transpose()?;
        let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
        let mut state = RuntimeState::new(&b);
        assert_eq!(
            state.admit(&b, &i, 1, &ep, current.as_ref(), &c)?,
            Admission::New
        );
        let first: serde_json::Value = serde_json::from_slice(&state.encode(&b, &c)?)?;
        let original = first["observations"][0].clone();
        // A restart and an intervening unrelated native operation cannot cause
        // an old operation to gain a new policy decision or source proof.
        let mut state = RuntimeState::decode(&b, &state.encode(&b, &c)?, &c)?;
        let unrelated = input(&b, &event(false)?, &c)?;
        state.admit(&b, &unrelated, 2, &ep, None, &c)?;
        let opposite = CurrentDecision::new(
            &b,
            &i,
            verification(&b, &i, !classified.unwrap_or(false), &c)?,
            &c,
        )?;
        assert_eq!(
            state.admit(&b, &i, 1, &ep, Some(&opposite), &c)?,
            Admission::Duplicate
        );
        let mut alias = e.clone();
        alias.id = Uuid::from_u128(999);
        alias.observed_at += chrono::TimeDelta::seconds(1);
        let ai = input(&b, &alias, &c)?;
        let mut alias_proof = verification(&b, &ai, true, &c)?;
        alias_proof.now = ns(BASE + 2_000_000_000);
        alias_proof.verified_at = alias_proof.now;
        let permit = CurrentDecision::new(&b, &ai, alias_proof, &c)?;
        assert_eq!(
            state.admit(&b, &ai, 3, &ep, Some(&permit), &c)?,
            Admission::Duplicate
        );
        let bytes = state.encode(&b, &c)?;
        let after: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(after["observations"][0], original);
        assert_eq!(state.metrics(&b)?.retained_events, 2);
        assert_eq!(state.metrics(&b)?.retained_aliases, 3);
        assert_eq!(
            state.source_positions(),
            &[(b.config().sources[0].stream, 3)]
        );
        assert_eq!(RuntimeState::decode(&b, &bytes, &c)?.encode(&b, &c)?, bytes);
    }
    Ok(())
}

#[test]
fn runtime_admission_refuses_conflicts_gaps_in_positions_and_incomplete_intervals_atomically()
-> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
    let e = event(true)?;
    let i = input(&b, &e, &c)?;
    let mut state = RuntimeState::new(&b);
    let empty = state.encode(&b, &c)?;
    assert_eq!(state.admit(&b, &i, 2, &ep, None, &c), Err(Error::Conflict));
    assert_eq!(state.encode(&b, &c)?, empty);
    let mut proofs = runtime_proofs(&b);
    proofs[0].source.coverage_from = ns(BASE + 1);
    let short = RuntimeEpoch::new(&b, proofs, policy_coverage(&b), &c)?;
    assert_eq!(
        state.admit(&b, &i, 1, &short, None, &c),
        Err(Error::Unverified)
    );
    assert_eq!(state.encode(&b, &c)?, empty);
    state.admit(&b, &i, 1, &ep, None, &c)?;
    let saved = state.encode(&b, &c)?;
    for native_conflict in [false, true] {
        let mut changed = e.clone();
        if native_conflict {
            changed.id = Uuid::from_u128(999);
        }
        changed.message = Some("Conflicting native metadata".into());
        let i = input(&b, &changed, &c)?;
        assert_eq!(state.admit(&b, &i, 2, &ep, None, &c), Err(Error::Conflict));
        assert_eq!(state.encode(&b, &c)?, saved);
    }
    // A policy proof for another exact input cannot classify this admission.
    let con = input(&b, &event(false)?, &c)?;
    let wrong = CurrentDecision::new(&b, &con, verification(&b, &con, true, &c)?, &c)?;
    let mut other = event(true)?;
    other.id = Uuid::from_u128(44);
    other.attributes["runtime_metadata"]["native"]["sequence"] = json!(4);
    let i = input(&b, &other, &c)?;
    assert!(state.admit(&b, &i, 2, &ep, Some(&wrong), &c).is_err());
    assert_eq!(state.encode(&b, &c)?, saved);
    Ok(())
}

#[test]
fn runtime_decode_rebuilds_exact_projections_decisions_and_detector_domains() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
    let i = input(&b, &event(true)?, &c)?;
    let permit = CurrentDecision::new(&b, &i, verification(&b, &i, true, &c)?, &c)?;
    let mut state = RuntimeState::new(&b);
    state.admit(&b, &i, 1, &ep, Some(&permit), &c)?;
    let bytes = state.encode(&b, &c)?;
    for edit in 0..15 {
        let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;
        match edit {
            0 => v["schema_version"] = json!(1),
            1 => v["observations"][0]["runtime"] = serde_json::Value::Null,
            2 => {
                v["observations"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("runtime");
            }
            3 => {
                v["observations"][0]["runtime"]["projection"]["process"]["execution_generation"] =
                    json!(2)
            }
            4 => v["observations"][0]["runtime"]["decision"]["policy_revision"] = json!("other"),
            5 => {
                v["observations"][0]["runtime"]["decision"]["claim"]["input_sha256"] =
                    json!(vec![9; 32])
            }
            6 => v["observations"][0]["verification"]["runtime"]["metadata_only"] = json!(false),
            7 => v["observations"][0]["verification"]["runtime"]["clock_continuity"] = json!(false),
            8 => v["observations"][0]["success"] = json!(true),
            9 => {
                v["observations"][0]["key"] =
                    json!({"authority":"fake","principal":"fake","target":"fake"})
            }
            10 => v["positions"][0][1] = json!(0),
            11 => v["watermark"] = json!(ns(BASE + 49_000_000)),
            12 => v["last_seal_evidence"] = json!([v["observations"][0]["verification"].clone()]),
            13 => v["degraded_through"] = json!(ns(BASE)),
            _ => v["retired_late_inputs"] = json!(1),
        }
        assert!(
            RuntimeState::decode(&b, &serde_json::to_vec(&v)?, &c).is_err(),
            "edit{edit}"
        );
    }
    let mut other = config();
    other.policy_authorities[0].account = Some("new-scope".into());
    assert!(RuntimeState::decode(&RuntimeBinding::new(other, &c)?, &bytes, &c).is_err());
    Ok(())
}

#[test]
fn runtime_hot_event_key_and_byte_caps_preserve_original_identity() -> Result {
    for cap in ["events", "keys", "bytes"] {
        let c = context();
        let mut cfg = config();
        match cap {
            "events" => cfg.max_events = 2,
            "keys" => cfg.max_keys = 1,
            _ => cfg.max_state_bytes = 4096,
        }
        let b = RuntimeBinding::new(cfg, &c)?;
        let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
        let mut state = RuntimeState::new(&b);
        let saved = state.encode(&b, &c)?;
        if cap == "bytes" {
            let i = input(&b, &event(true)?, &c)?;
            let permit = CurrentDecision::new(&b, &i, verification(&b, &i, true, &c)?, &c)?;
            assert_eq!(
                state.admit(&b, &i, 1, &ep, Some(&permit), &c),
                Err(Error::Capacity)
            );
            assert_eq!(state.encode(&b, &c)?, saved);
            continue;
        }
        for seq in 1..=2 {
            let mut e = event(true)?;
            e.id = Uuid::from_u128(100 + seq);
            e.attributes["runtime_metadata"]["native"]["sequence"] = json!(seq);
            let i = input(&b, &e, &c)?;
            state.admit(&b, &i, seq as u64, &ep, None, &c)?;
        }
        let saved = state.encode(&b, &c)?;
        let mut e = event(false)?;
        if cap == "keys" {
            e.attributes["runtime_metadata"]["process"]["pid"] = json!(101);
        }
        let i = input(&b, &e, &c)?;
        assert_eq!(state.admit(&b, &i, 3, &ep, None, &c), Err(Error::Capacity));
        assert_eq!(state.encode(&b, &c)?, saved);
    }
    Ok(())
}

#[tokio::test]
async fn runtime_admission_preserves_input_epoch_and_classification_contexts() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for which in ["input", "epoch", "decision"] {
        let input_context = context();
        let epoch_context = context();
        let decision_context = context();
        let i = input(&b, &event(true)?, &input_context)?;
        let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &epoch_context)?;
        let decision = CurrentDecision::new(
            &b,
            &i,
            verification(&b, &i, true, &decision_context)?,
            &decision_context,
        )?;
        let mut state = RuntimeState::new(&b);
        let saved = state.encode(&b, &c)?;
        match which {
            "input" => input_context.cancellation.cancel(),
            "epoch" => epoch_context.cancellation.cancel(),
            _ => decision_context.cancellation.cancel(),
        }
        assert_eq!(
            state.admit(&b, &i, 1, &ep, Some(&decision), &c),
            Err(Error::Cancelled)
        );
        assert_eq!(state.encode(&b, &c)?, saved);
    }
    let i = input(&b, &event(true)?, &c)?;
    let ep = RuntimeEpoch::new(&b, runtime_proofs(&b), policy_coverage(&b), &c)?;
    let mut p = verification(&b, &i, true, &c)?;
    p.verified_until = p.now + chrono::TimeDelta::milliseconds(2);
    let short = CurrentDecision::new(&b, &i, p, &c)?;
    let mut state = RuntimeState::new(&b);
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(
        state.admit(&b, &i, 1, &ep, Some(&short), &c),
        Err(Error::Cancelled)
    );
    Ok(())
}

#[test]
fn unknown_runtime_operations_and_incomplete_capture_remain_original_gap_data() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let mut proofs = runtime_proofs(&b);
    proofs[0].capture.execution_continuity = false;
    let ep = RuntimeEpoch::new(&b, proofs, policy_coverage(&b), &c)?;
    let mut e = event(true)?;
    e.attributes["runtime_metadata"]["operation"] =
        json!({"kind":"gap","stops":1,"reason":"unsupported_syscall"});
    let i = input(&b, &e, &c)?;
    assert_eq!(i.claim(&c), Err(Error::Invalid));
    let mut state = RuntimeState::new(&b);
    assert_eq!(
        state.admit(&b, &i, 1, &ep, None, &c)?,
        signal_rules::correlation::Admission::New
    );
    let bytes = state.encode(&b, &c)?;
    let data: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        data["observations"][0]["runtime"]["projection"]["operation"]["kind"],
        "gap"
    );
    assert_eq!(
        data["observations"][0]["runtime"]["decision"],
        serde_json::Value::Null
    );
    assert_eq!(data["observations"][0]["verification"]["complete"], false);
    assert_eq!(
        RuntimeState::decode(&b, &bytes, &context())?.encode(&b, &c)?,
        bytes
    );
    Ok(())
}

fn sealing_epoch(b: &RuntimeBinding, position: u64, complete: bool) -> Result<RuntimeEpoch> {
    let mut proofs = runtime_proofs(b);
    for p in &mut proofs {
        p.source.position = position;
        p.source.complete = complete;
    }
    Ok(RuntimeEpoch::new(
        b,
        proofs,
        policy_coverage(b),
        &context(),
    )?)
}
fn admit_runtime(
    state: &mut RuntimeState,
    b: &RuntimeBinding,
    e: &signal_event::SignalEvent,
    position: u64,
    classified: Option<bool>,
) -> Result {
    let c = context();
    let i = input(b, e, &c)?;
    let permit = classified
        .map(|yes| -> Result<CurrentDecision> {
            Ok(CurrentDecision::new(
                b,
                &i,
                verification(b, &i, yes, &c)?,
                &c,
            )?)
        })
        .transpose()?;
    state.admit(
        b,
        &i,
        position,
        &sealing_epoch(b, position, true)?,
        permit.as_ref(),
        &c,
    )?;
    Ok(())
}
#[test]
fn runtime_seal_has_stable_native_pair_scopes_and_exact_source_policy_proofs() -> Result {
    use signal_rules::correlation::Status;
    let c = context();
    let mut cfg = config();
    cfg.policy_authorities[0].account = Some("private-policy-scope".into());
    let b = RuntimeBinding::new(cfg, &c)?;
    let events = [event(true)?, event(false)?];
    let mut ids = Vec::new();
    for order in [[0, 1], [1, 0]] {
        let mut state = RuntimeState::new(&b);
        for (n, i) in order.into_iter().enumerate() {
            admit_runtime(&mut state, &b, &events[i], n as u64 + 1, Some(true))?;
        }
        let ep = sealing_epoch(&b, 2, true)?;
        let sealed = state.seal(&b, &ep, &c)?;
        assert_eq!(sealed.new_episodes, 1);
        assert!(!sealed.coverage_gap);
        let e = &state.episodes()[0];
        assert_eq!(e.status, Status::Match);
        assert_eq!(e.rule_id, "SIG-D14");
        assert_eq!(e.event_ids, vec![events[0].id, events[1].id]);
        assert_eq!(
            e.contributors
                .iter()
                .filter(|s| s.stream == Uuid::from_u128(100))
                .count(),
            1
        );
        assert!(
            e.contributors
                .iter()
                .any(|s| s.account.as_deref() == Some("private-policy-scope"))
        );
        assert_eq!(e.runtime.as_ref().unwrap().policy_coverage.len(), 2);
        ids.push((e.id, e.finding.as_ref().unwrap().id));
        let bytes = state.encode(&b, &c)?;
        let mut reopened = RuntimeState::decode(&b, &bytes, &c)?;
        assert_eq!(reopened.seal(&b, &ep, &c)?.new_episodes, 0);
        assert_eq!(reopened.encode(&b, &c)?, bytes);
        let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;
        v["runtime_seal"]["policy"].as_array_mut().unwrap().pop();
        assert!(RuntimeState::decode(&b, &serde_json::to_vec(&v)?, &c).is_err());
    }
    assert_eq!(ids[0], ids[1]);
    Ok(())
}
#[test]
fn runtime_clean_negative_unknown_interval_and_degraded_match_are_distinct() -> Result {
    use signal_rules::correlation::Status;
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for case in [
        "clean",
        "unknown",
        "uncertain",
        "degraded",
        "different_execution",
        "eof",
        "failed_read",
        "gap",
    ] {
        let mut r = event(true)?;
        let con = event(false)?;
        match case {
            "uncertain" => {
                r.attributes["runtime_metadata"]["operation"]["interval"]["exit_ns"] =
                    json!(BASE + 10_000_000)
            }
            "different_execution" => {
                r.attributes["runtime_metadata"]["process"]["execution_generation"] = json!(2)
            }
            "eof" => r.attributes["runtime_metadata"]["operation"]["result"] = json!(0),
            "failed_read" => {
                r.attributes["runtime_metadata"]["operation"]["result"] = json!(-14);
                r.attributes["runtime_metadata"]["operation"]["error"] = json!(true);
            }
            "gap" => {
                r.attributes["runtime_metadata"]["operation"] =
                    json!({"kind":"gap","stops":1,"reason":"unsupported_syscall"})
            }
            _ => (),
        }
        if case == "uncertain" {
            r.attributes["runtime_metadata"]["observed_ns"] = json!(BASE + 10_000_001);
            r.timestamp = ns(BASE + 10_000_001);
        }
        let mut state = RuntimeState::new(&b);
        let classified = if ["unknown", "eof", "failed_read", "gap"].contains(&case) {
            None
        } else {
            Some(case != "clean")
        };
        admit_runtime(&mut state, &b, &r, 1, classified)?;
        admit_runtime(&mut state, &b, &con, 2, Some(true))?;
        state.seal(&b, &sealing_epoch(&b, 2, case != "degraded")?, &c)?;
        let e = state
            .episodes()
            .iter()
            .find(|e| e.originals.last().unwrap().id == con.id)
            .unwrap();
        let expected = match case {
            "unknown" | "uncertain" | "gap" => Status::Indeterminate,
            "degraded" => Status::Match,
            _ => Status::NoMatch,
        };
        assert_eq!(e.status, expected, "{case}");
        assert_eq!(
            e.coverage_gap,
            ["unknown", "uncertain", "degraded", "gap"].contains(&case),
            "{case}"
        );
        if case == "gap" {
            assert!(state.episodes().iter().any(
                |e| e.originals.last().unwrap().id == r.id && e.status == Status::Indeterminate
            ));
        }
    }
    Ok(())
}
#[test]
fn runtime_seals_use_operation_time_and_require_exact_positions_and_policy_monotonicity() -> Result
{
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let mut state = RuntimeState::new(&b);
    let r = event(true)?;
    let mut con = event(false)?;
    con.timestamp = ns(BASE + 45_000_000);
    con.attributes["runtime_metadata"]["observed_ns"] = json!(BASE + 45_000_000);
    admit_runtime(&mut state, &b, &r, 1, Some(true))?;
    admit_runtime(&mut state, &b, &con, 2, Some(true))?;
    let before = state.encode(&b, &c)?;
    assert_eq!(
        state.seal(&b, &sealing_epoch(&b, 3, true)?, &c),
        Err(Error::Conflict)
    );
    assert_eq!(state.encode(&b, &c)?, before);
    assert_eq!(
        state
            .seal(&b, &sealing_epoch(&b, 2, true)?, &c)?
            .new_episodes,
        1
    );
    assert_eq!(state.episodes()[0].anchor, ns(BASE + 11_000_000));
    let saved = state.encode(&b, &c)?;
    let mut sources = runtime_proofs(&b);
    sources[0].source.position = 2;
    let mut policies = policy_coverage(&b);
    policies[0].frontier -= chrono::TimeDelta::milliseconds(1);
    // The minimum watermark does not move; a non-minimum policy still cannot regress.
    let ep = RuntimeEpoch::new(&b, sources, policies, &c)?;
    assert_eq!(state.seal(&b, &ep, &c), Err(Error::Conflict));
    assert_eq!(state.encode(&b, &c)?, saved);
    Ok(())
}

#[test]
fn runtime_newer_uncertain_or_unknown_read_cannot_hide_an_older_definite_match() -> Result {
    use signal_rules::correlation::Status;
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for uncertain in [true, false] {
        let first = event(true)?;
        let mut newer = first.clone();
        newer.id = Uuid::from_u128(20);
        newer.attributes["runtime_metadata"]["native"]["sequence"] = json!(3);
        newer.attributes["runtime_metadata"]["operation"]["interval"] = json!({"entry_ns":BASE+5_000_000,"exit_ns":BASE+if uncertain{10_000_000}else{6_000_000}});
        newer.attributes["runtime_metadata"]["observed_ns"] = json!(BASE + 10_000_001);
        newer.timestamp = ns(BASE + 10_000_001);
        let mut con = event(false)?;
        con.attributes["runtime_metadata"]["native"]["sequence"] = json!(4);
        let events = [first, newer, con];
        let mut original = None;
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut state = RuntimeState::new(&b);
            for (n, index) in order.into_iter().enumerate() {
                let classification = if index == 1 && !uncertain {
                    None
                } else {
                    Some(true)
                };
                admit_runtime(&mut state, &b, &events[index], n as u64 + 1, classification)?;
            }
            state.seal(&b, &sealing_epoch(&b, 3, true)?, &c)?;
            let e = &state.episodes()[0];
            assert_eq!(e.status, Status::Match);
            assert!(e.coverage_gap);
            assert_eq!(e.event_ids, vec![events[0].id, events[2].id]);
            let bytes = serde_json::to_vec(e)?;
            if let Some(expected) = &original {
                assert_eq!(&bytes, expected);
            } else {
                original = Some(bytes);
            }
        }
    }
    Ok(())
}
#[test]
fn runtime_ttl_and_late_admission_use_operation_end_with_full_precision() -> Result {
    use signal_rules::correlation::{Admission, Status};
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for over in [0, 1] {
        let mut state = RuntimeState::new(&b);
        admit_runtime(&mut state, &b, &event(true)?, 1, Some(true))?;
        admit_runtime(&mut state, &b, &event(false)?, 2, Some(true))?;
        let frontier = ns(BASE + 11_000_000 + 1_000_000_000 + over + 1_000_000);
        let mut proofs = runtime_proofs(&b);
        proofs[0].source.position = 2;
        proofs[0].source.frontier = frontier;
        proofs[0].source.now = ns(BASE + 2_000_000_000);
        let mut policies = policy_coverage(&b);
        for p in &mut policies {
            p.frontier = frontier;
            p.now = ns(BASE + 2_000_000_000);
        }
        state.seal(&b, &RuntimeEpoch::new(&b, proofs, policies, &c)?, &c)?;
        assert_eq!(
            state.episodes()[0].status,
            if over == 0 {
                Status::Match
            } else {
                Status::Indeterminate
            }
        );
    }
    let mut state = RuntimeState::new(&b);
    state.seal(&b, &sealing_epoch(&b, 0, true)?, &c)?;
    let mut e = event(false)?;
    e.timestamp = ns(BASE + 45_000_000);
    e.attributes["runtime_metadata"]["observed_ns"] = json!(BASE + 45_000_000);
    let i = input(&b, &e, &c)?;
    let permit = CurrentDecision::new(&b, &i, verification(&b, &i, true, &c)?, &c)?;
    assert_eq!(
        state.admit(&b, &i, 1, &sealing_epoch(&b, 1, true)?, Some(&permit), &c)?,
        Admission::Late
    );
    assert_eq!(state.metrics(&b)?.late_inputs, 1);
    state.seal(&b, &sealing_epoch(&b, 1, true)?, &c)?;
    assert_eq!(state.episodes()[0].status, Status::Indeterminate);
    Ok(())
}

#[test]
fn later_complete_seal_cannot_upgrade_original_unknown_clock_or_execution() -> Result {
    use signal_rules::correlation::Status;
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    for bad_read in [true, false] {
        for clock in [true, false] {
            let mut state = RuntimeState::new(&b);
            for (n, read) in [true, false].into_iter().enumerate() {
                let e = event(read)?;
                let i = input(&b, &e, &c)?;
                let decision = CurrentDecision::new(&b, &i, verification(&b, &i, true, &c)?, &c)?;
                let mut proofs = runtime_proofs(&b);
                proofs[0].source.position = n as u64 + 1;
                if read == bad_read {
                    if clock {
                        proofs[0].capture.clock_continuity = false;
                    } else {
                        proofs[0].capture.execution_continuity = false;
                    }
                }
                let ep = RuntimeEpoch::new(&b, proofs, policy_coverage(&b), &c)?;
                state.admit(&b, &i, n as u64 + 1, &ep, Some(&decision), &c)?;
            }
            state.seal(&b, &sealing_epoch(&b, 2, true)?, &c)?;
            assert_eq!(state.episodes()[0].status, Status::Indeterminate);
            assert!(state.episodes()[0].coverage_gap);
            let bytes = state.encode(&b, &c)?;
            assert_eq!(RuntimeState::decode(&b, &bytes, &c)?.encode(&b, &c)?, bytes);
        }
    }
    Ok(())
}

#[tokio::test]
async fn runtime_seal_missing_policy_expiry_and_cancellation_preserve_prior_state() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let mut state = RuntimeState::new(&b);
    admit_runtime(&mut state, &b, &event(true)?, 1, Some(true))?;
    admit_runtime(&mut state, &b, &event(false)?, 2, Some(true))?;
    let saved = state.encode(&b, &c)?;
    let mut sources = runtime_proofs(&b);
    sources[0].source.position = 2;
    let mut policies = policy_coverage(&b);
    policies.pop();
    let missing = RuntimeEpoch::new(&b, sources, policies, &c)?;
    let result = state.seal(&b, &missing, &c)?;
    assert!(result.coverage_gap);
    assert_eq!(result.new_episodes, 0);
    assert_eq!(result.watermark, None);
    assert_eq!(state.encode(&b, &c)?, saved);
    for expired in [true, false] {
        let original = context();
        let mut sources = runtime_proofs(&b);
        sources[0].source.position = 2;
        let mut policies = policy_coverage(&b);
        if expired {
            policies[0].verified_until = policies[0].now + chrono::TimeDelta::milliseconds(2);
        }
        let ep = RuntimeEpoch::new(&b, sources, policies, &original)?;
        if expired {
            tokio::time::sleep(Duration::from_millis(5)).await;
        } else {
            original.cancellation.cancel();
        }
        assert_eq!(state.seal(&b, &ep, &c), Err(Error::Cancelled));
        assert_eq!(state.encode(&b, &c)?, saved);
    }
    Ok(())
}

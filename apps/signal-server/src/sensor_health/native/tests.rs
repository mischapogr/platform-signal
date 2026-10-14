#![allow(clippy::unwrap_used)]
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use signal_event::IngestEvent;
use std::{os::unix::fs::PermissionsExt, time::Duration};

fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(5))
}
fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap()
}
fn config() -> Config {
    Config {
        schema_version: 1,
        policy: core::Policy {
            schema_version: 1,
            rule_id: "fixture-heartbeat".into(),
            revision: "fixture-v1".into(),
            heartbeat_ms: 100,
            grace_ms: 20,
            observer_freshness_ms: 500,
            max_sources: 1,
            max_state_bytes: 8192,
            expected: vec![core::ExpectedSource {
                source_id: Uuid::from_u128(1),
                observer_id: Uuid::from_u128(2),
                binding: [1; 32],
                expected_since_ms: 1000,
                require_checkpoint: true,
            }],
        },
        observer_keys: vec![ObserverKey {
            schema_version: 1,
            observer_id: Uuid::from_u128(2),
            public_key: signer().public_key().as_ref().try_into().unwrap(),
        }],
        source_scopes: vec![SourceScope {
            schema_version: 1,
            source_id: Uuid::from_u128(1),
            event_scope: EventScope {
                schema_version: 1,
                source: "fixture-observer".into(),
                account: "fixture-account".into(),
                resource: "fixture-resource".into(),
            },
        }],
        title: "Fixture missing telemetry".into(),
        severity: DetectionSeverity::High,
        max_proofs: 3,
        max_event_bytes: 16384,
        max_state_bytes: 262144,
        max_record_bytes: 1048576,
        max_outputs: 4,
        max_output_bytes: 65536,
    }
}
fn epoch(checkpoint: u64, last: u64, now: i64) -> Epoch {
    Epoch {
        schema_version: 1,
        source_stream: Uuid::from_u128(1),
        source_binding: [1; 32],
        checkpoint,
        last_sequence: last,
        now_ms: now,
    }
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn row(
    config: &Config,
    wal: u64,
    id: u128,
    sequence: u64,
    observed: i64,
    heartbeat: Option<i64>,
) -> SequencedEvent {
    let verifier = Verifier::new(config.policy.clone(), config.observer_keys.clone()).unwrap();
    let observation = core::Observation {
        schema_version: 1,
        source_id: Uuid::from_u128(1),
        observer_id: Uuid::from_u128(2),
        binding: [1; 32],
        sequence,
        observed_at_ms: observed,
        health: core::ObserverHealth::Healthy,
        heartbeat_at_ms: heartbeat,
        checkpoint: heartbeat.map(|_| sequence),
    };
    let payload=serde_json::to_vec(&serde_json::json!({"schema_version":1,"policy_sha256":verifier.policy_sha256(),"observation":observation})).unwrap();
    let mut signed = super::super::DOMAIN.to_vec();
    signed.extend_from_slice(&payload);
    let envelope=serde_json::to_string(&serde_json::json!({"schema_version":1,"observer_id":Uuid::from_u128(2),"payload_base64":STANDARD.encode(&payload),"signature_base64":STANDARD.encode(signer().sign(&signed).as_ref())})).unwrap();
    let at = DateTime::<Utc>::from_timestamp_millis(observed).unwrap();
    let input:IngestEvent=serde_json::from_value(serde_json::json!({"id":Uuid::from_u128(id),"timestamp":at,"observed_at":at,"source":{"type":"fixture-observer"},"resource":{"kind":"fixture","id":"fixture-resource","account_id":"fixture-account"},"attributes":{ATTRIBUTE:envelope,"private_metadata":{"nested":[1,{"enabled":true}]}}})).unwrap();
    SequencedEvent {
        sequence: wal,
        event: input.normalize(at).unwrap(),
    }
}

#[tokio::test]
async fn report_expiring_after_admission_advances_checkpoint_without_gaining_authority() {
    let dir = directory();
    let cfg = config();
    let input = row(&cfg, 1, 10, 1, 1120, Some(1000));
    let verifier = Verifier::new(cfg.policy.clone(), cfg.observer_keys.clone()).unwrap();
    cfg.validate_event(&input.event, &verifier, 1120).unwrap();
    let mut session = Session::open(
        cfg,
        dir.path().join("native.sqlite"),
        epoch(0, 0, 1000),
        context(),
    )
    .await
    .unwrap();
    let result = session
        .complete(&[input], 1620, true, context())
        .await
        .unwrap();
    assert_eq!(result.assessments[0].outcome, Outcome::Indeterminate);
    assert!(result.findings.is_empty());
    assert_eq!(result.proofs, 0);
    assert_eq!(
        session
            .journal
            .load(context())
            .await
            .unwrap()
            .unwrap()
            .checkpoint,
        1
    );
    session.shutdown(context()).await.unwrap();
}

#[tokio::test]
async fn actual_journal_retains_original_scoped_outbox_and_restart_does_not_renew_authority() {
    let dir = directory();
    let path = dir.path().join("native.sqlite");
    let cfg = config();
    let input = row(&cfg, 1, 10, 1, 1120, Some(1000));
    let mut first = Session::open(cfg.clone(), path.clone(), epoch(0, 0, 1000), context())
        .await
        .unwrap();
    let result = first
        .complete(std::slice::from_ref(&input), 1120, true, context())
        .await
        .unwrap();
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.assessments[0].outcome, Outcome::Match);
    let original = result.findings[0].budget_preview();
    let committed = first.journal.load(context()).await.unwrap().unwrap();
    let saved: State = serde_json::from_slice(&committed.state).unwrap();
    let stored_original = saved.known[0].finding.clone();
    assert_eq!(
        saved.proofs[0].event.attributes["private_metadata"],
        input.event.attributes["private_metadata"]
    );
    first.shutdown(context()).await.unwrap();
    let mut restarted = Session::open(cfg.clone(), path, epoch(0, 1, 1121), context())
        .await
        .unwrap();
    let pending = restarted
        .complete(std::slice::from_ref(&input), 1121, true, context())
        .await
        .unwrap();
    assert_eq!(pending.findings[0].budget_preview(), original);
    assert_eq!(pending.assessments[0].outcome, Outcome::Indeterminate);
    restarted
        .acknowledge(pending.revision, pending.published_prefix, context())
        .await
        .unwrap();
    let mut duplicate = input;
    duplicate.sequence = 2;
    let replay = restarted
        .complete(&[duplicate], 1122, true, context())
        .await
        .unwrap();
    assert!(replay.findings.is_empty());
    assert_eq!(replay.assessments[0].outcome, Outcome::Indeterminate);
    let fresh = row(&cfg, 3, 11, 2, 1123, Some(1000));
    let result = restarted
        .complete(&[fresh], 1123, true, context())
        .await
        .unwrap();
    assert_eq!(result.assessments[0].outcome, Outcome::Match);
    assert!(result.findings.is_empty());
    let current = restarted.journal.load(context()).await.unwrap().unwrap();
    let current: State = serde_json::from_slice(&current.state).unwrap();
    assert_eq!(current.known[0].finding, stored_original);
    assert_eq!(current.known[0].evidence[0].wal_sequence, 1);
    restarted.shutdown(context()).await.unwrap();
}

#[tokio::test]
async fn changed_canonical_retry_and_unverified_retained_input_cannot_gain_scope() {
    let dir = directory();
    let cfg = config();
    let mut session = Session::open(
        cfg.clone(),
        dir.path().join("native.sqlite"),
        epoch(0, 0, 1000),
        context(),
    )
    .await
    .unwrap();
    let input = row(&cfg, 1, 10, 1, 1120, Some(1000));
    session
        .complete(std::slice::from_ref(&input), 1120, true, context())
        .await
        .unwrap();
    let before = session.journal.load(context()).await.unwrap();
    let mut changed = input;
    changed.sequence = 2;
    changed.event.message = Some("changed canonical content".into());
    assert!(matches!(
        session.complete(&[changed], 1121, true, context()).await,
        Err(Error::Conflict)
    ));
    assert_eq!(session.journal.load(context()).await.unwrap(), before);
    session.shutdown(context()).await.unwrap();
    let dir = directory();
    let mut held = Session::open(
        cfg.clone(),
        dir.path().join("held.sqlite"),
        epoch(0, 1, 1000),
        context(),
    )
    .await
    .unwrap();
    let old = row(&cfg, 1, 20, 1, 1000, Some(1000));
    let result = held.complete(&[old], 1120, true, context()).await.unwrap();
    assert!(result.findings.is_empty());
    assert_eq!(result.assessments[0].outcome, Outcome::Indeterminate);
    held.shutdown(context()).await.unwrap();
}

#[tokio::test]
async fn native_output_configuration_enrollment_and_scope_bindings_refuse_foreign_recovery() {
    let dir = directory();
    let path = dir.path().join("native.sqlite");
    let cfg = config();
    let mut session = Session::open(cfg.clone(), path.clone(), epoch(0, 0, 1000), context())
        .await
        .unwrap();
    session
        .complete(
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    session.shutdown(context()).await.unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut changed = cfg.clone();
    changed.title = "changed output body".into();
    assert!(matches!(
        Session::open(changed, path.clone(), epoch(0, 1, 1121), context()).await,
        Err(Error::Journal(state_journal::Error::Conflict))
    ));
    let mut foreign = epoch(0, 1, 1121);
    foreign.source_binding = [9; 32];
    assert!(
        Session::open(cfg, path.clone(), foreign, context())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[tokio::test]
async fn native_payload_validation_rejects_validly_framed_wrong_original_proof_or_finding() {
    for tamper in ["digest", "finding", "monitor"] {
        let dir = directory();
        let cfg = config();
        let mut session = Session::open(
            cfg.clone(),
            dir.path().join("native.sqlite"),
            epoch(0, 0, 1000),
            context(),
        )
        .await
        .unwrap();
        session
            .complete(
                &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
                1120,
                true,
                context(),
            )
            .await
            .unwrap();
        let mut record = session.journal.load(context()).await.unwrap().unwrap();
        let mut state: State = serde_json::from_slice(&record.state).unwrap();
        match tamper {
            "digest" => state.proofs[0].payload_sha256 = [9; 32],
            "finding" => state.known[0].finding.title = "forged finding".into(),
            _ => {
                let mut value: serde_json::Value = serde_json::from_slice(&state.monitor).unwrap();
                value["slots"][0]["heartbeat_at_ms"] = serde_json::json!(999);
                state.monitor = serde_json::to_vec(&value).unwrap();
            }
        }
        record.revision += 1;
        record.state = serde_json::to_vec(&state).unwrap();
        session
            .journal
            .commit(record.revision - 1, record, context())
            .await
            .unwrap();
        assert!(session.complete(&[], 1121, true, context()).await.is_err());
        session.shutdown(context()).await.unwrap();
    }
}

#[tokio::test]
async fn outbox_quota_rolls_back_entire_native_candidate_and_old_ack_cannot_retire_new_gap() {
    let dir = directory();
    let mut cfg = config();
    cfg.max_outputs = 1;
    let mut session = Session::open(
        cfg.clone(),
        dir.path().join("native.sqlite"),
        epoch(0, 0, 1000),
        context(),
    )
    .await
    .unwrap();
    let first = session
        .complete(
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    let before = session.journal.load(context()).await.unwrap();
    let next = row(&cfg, 2, 11, 2, 1121, Some(1001));
    assert!(matches!(
        session
            .complete(std::slice::from_ref(&next), 1121, true, context())
            .await,
        Err(Error::Capacity)
    ));
    assert_eq!(session.journal.load(context()).await.unwrap(), before);
    session
        .acknowledge(first.revision, first.published_prefix, context())
        .await
        .unwrap();
    let second = session
        .complete(&[next], 1121, true, context())
        .await
        .unwrap();
    assert_eq!(second.findings.len(), 1);
    assert_ne!(
        second.findings[0].budget_preview().id,
        first.findings[0].budget_preview().id
    );
    assert!(
        session
            .acknowledge(first.revision, first.published_prefix, context())
            .await
            .is_err()
    );
    session.shutdown(context()).await.unwrap();
}

#[tokio::test]
async fn proof_retention_is_bounded_while_original_pending_gap_evidence_stays_exact() {
    let dir = directory();
    let cfg = config();
    let mut session = Session::open(
        cfg.clone(),
        dir.path().join("native.sqlite"),
        epoch(0, 0, 1000),
        context(),
    )
    .await
    .unwrap();
    session
        .complete(
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    let first = session.journal.load(context()).await.unwrap().unwrap();
    for sequence in 2..=12 {
        session
            .complete(
                &[row(
                    &cfg,
                    sequence,
                    10 + u128::from(sequence),
                    sequence,
                    1120 + sequence as i64,
                    Some(1000),
                )],
                1120 + sequence as i64,
                true,
                context(),
            )
            .await
            .unwrap();
        let record = session.journal.load(context()).await.unwrap().unwrap();
        let state: State = serde_json::from_slice(&record.state).unwrap();
        assert!(state.proofs.len() <= 3);
        assert_eq!(record.outbox, first.outbox);
        assert_eq!(state.known[0].evidence[0].wal_sequence, 1);
    }
    session.shutdown(context()).await.unwrap();
}

#[tokio::test]
async fn saved_future_clock_refuses_before_native_session_opens() {
    let dir = directory();
    let path = dir.path().join("native.sqlite");
    let cfg = config();
    let mut session = Session::open(cfg.clone(), path.clone(), epoch(0, 0, 1000), context())
        .await
        .unwrap();
    session
        .complete(
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    session.shutdown(context()).await.unwrap();
    assert!(matches!(
        Session::open(cfg, path, epoch(0, 1, 1119), context()).await,
        Err(Error::Core(core::Error::Clock))
    ));
}

#[tokio::test]
async fn a_valid_observer_signature_cannot_retarget_canonical_account_or_resource() {
    let dir = directory();
    let cfg = config();
    let mut session = Session::open(
        cfg.clone(),
        dir.path().join("native.sqlite"),
        epoch(0, 0, 1000),
        context(),
    )
    .await
    .unwrap();
    for field in ["account", "resource"] {
        let mut input = row(&cfg, 1, 10, 1, 1120, Some(1000));
        let resource = input.event.resource.as_mut().unwrap();
        if field == "account" {
            resource.account_id = Some("other-fixture-account".into());
        } else {
            resource.id = "other-fixture-resource".into();
        }
        assert!(matches!(
            session.complete(&[input], 1120, true, context()).await,
            Err(Error::Conflict)
        ));
        assert!(session.journal.load(context()).await.unwrap().is_none());
    }
    session.shutdown(context()).await.unwrap();
}

#![allow(clippy::unwrap_used)]
use super::{
    tests::{config, context, epoch, row},
    *,
};

#[tokio::test]
async fn shared_metadata_hydrates_exact_original_history_outbox_and_private_attributes() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let mut input = row(&cfg, 1, 10, 1, 1120, Some(1000));
    input.event.attributes.insert(
        "event".into(),
        serde_json::json!({"event":{"private":[1,true,{"amount":-0.0}]}}),
    );
    let candidate = engine
        .prepare(None, &[input], 1120, true, context())
        .await
        .unwrap();
    let snapshot = candidate.snapshot();
    let detached = engine.detach(snapshot, &context()).unwrap();
    assert_eq!(detached.retained.len(), 1);
    assert_eq!(detached.canonical_sequences.len(), 1);
    // The generic protected state envelope accepts the exact canonical hash map.
    signal_control::MultiEventStateEnvelope {
        schema_version: 1,
        scope_generation: Uuid::from_u128(3),
        checkpoint: 1,
        metadata: detached.metadata.clone(),
        canonical_sequences: detached.canonical_sequences.clone(),
    }
    .encode()
    .unwrap();
    let restored = engine
        .hydrate(
            &detached.metadata,
            &detached.canonical_sequences,
            &detached.retained,
            &context(),
        )
        .unwrap();
    assert!(restored == *snapshot);
    let mut restarted = Engine::new(cfg, epoch(0, 1, 1121), Some(&restored), &context()).unwrap();
    let pending = restarted
        .prepare(Some(&restored), &[], 1121, true, context())
        .await
        .unwrap();
    assert_eq!(pending.snapshot().record().outbox, snapshot.record().outbox);
    assert_eq!(
        restarted.preview(&pending, &context()).unwrap().assessments[0].outcome,
        Outcome::Indeterminate
    );
}

#[tokio::test]
async fn shared_metadata_refuses_missing_changed_duplicate_and_unreferenced_canonical_data() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    let detached = engine.detach(candidate.snapshot(), &context()).unwrap();
    assert!(
        engine
            .hydrate(
                &detached.metadata,
                &detached.canonical_sequences,
                &[],
                &context()
            )
            .is_err()
    );
    let mut extra = detached.retained[0].clone();
    extra.sequence = 999;
    extra.event.id = Uuid::from_u128(999);
    assert!(
        engine
            .hydrate(
                &detached.metadata,
                &detached.canonical_sequences,
                &[detached.retained[0].clone(), extra],
                &context(),
            )
            .is_err()
    );
    let mut changed = detached.retained.clone();
    changed[0].event.message = Some("replaced original".into());
    assert!(
        engine
            .hydrate(
                &detached.metadata,
                &detached.canonical_sequences,
                &changed,
                &context()
            )
            .is_err()
    );
    let duplicate = vec![detached.retained[0].clone(), detached.retained[0].clone()];
    assert!(
        engine
            .hydrate(
                &detached.metadata,
                &detached.canonical_sequences,
                &duplicate,
                &context()
            )
            .is_err()
    );
    let mut alias = detached.retained[0].clone();
    alias.event.id = Uuid::from_u128(99);
    assert!(
        engine
            .hydrate(
                &detached.metadata,
                &detached.canonical_sequences,
                &[detached.retained[0].clone(), alias],
                &context()
            )
            .is_err()
    );
    let mut sequences = detached.canonical_sequences.clone();
    sequences.insert(detached.retained[0].event.id, 2);
    assert!(
        engine
            .hydrate(
                &detached.metadata,
                &sequences,
                &detached.retained,
                &context()
            )
            .is_err()
    );
    let mut metadata = detached.metadata.clone();
    metadata["snapshot"]["source_binding"] = serde_json::json!(vec![2; 32]);
    assert!(
        engine
            .hydrate(
                &metadata,
                &detached.canonical_sequences,
                &detached.retained,
                &context()
            )
            .is_err()
    );
    let extra = Uuid::from_u128(999);
    let mut metadata = detached.metadata.clone();
    metadata["canonical_sha256"][extra.to_string()] = serde_json::json!(vec![1; 32]);
    let mut sequences = detached.canonical_sequences.clone();
    sequences.insert(extra, 1);
    assert!(
        engine
            .hydrate(&metadata, &sequences, &detached.retained, &context())
            .is_err()
    );
}

#[tokio::test]
async fn shared_metadata_capacity_refuses_without_discarding_original_history() {
    let mut cfg = config();
    cfg.max_history_assessments = 128;
    cfg.max_history_bytes = 1024 * 1024;
    cfg.max_state_bytes = 2 * 1024 * 1024;
    cfg.max_record_bytes = 8 * 1024 * 1024;
    cfg.max_proofs = 128;
    cfg.policy.max_sources = 128;
    cfg.policy.max_state_bytes = 128 * 1024;
    cfg.policy.revision = "v".repeat(256);
    let expected = cfg.policy.expected[0].clone();
    let scope = cfg.source_scopes[0].clone();
    cfg.policy.expected = (1..=128)
        .map(|id| core::ExpectedSource {
            source_id: Uuid::from_u128(id),
            ..expected.clone()
        })
        .collect();
    cfg.source_scopes = (1..=128)
        .map(|id| SourceScope {
            source_id: Uuid::from_u128(id),
            ..scope.clone()
        })
        .collect();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1010, Some(1010))],
            1010,
            true,
            context(),
        )
        .await
        .unwrap();
    let original = candidate.snapshot();
    let error = engine.detach(original, &context()).err();
    assert!(matches!(error, Some(Error::Capacity)), "{error:?}");
    let state: State = serde_json::from_slice(&original.record().state).unwrap();
    assert_eq!(state.history.entries.len(), 128);
    assert_eq!(state.history.evicted, 0);
}

#[tokio::test]
async fn preparation_is_not_confirmation_and_discarded_work_cannot_renew_health() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let input = row(&cfg, 1, 10, 1, 1010, Some(1010));
    let proposed = engine
        .prepare(None, &[input], 1010, true, context())
        .await
        .unwrap();
    assert_eq!(
        engine.preview(&proposed, &context()).unwrap().assessments[0].outcome,
        Outcome::NoMatch
    );
    let empty = engine
        .prepare(None, &[], 1011, true, context())
        .await
        .unwrap();
    assert_eq!(
        engine.preview(&empty, &context()).unwrap().assessments[0].outcome,
        Outcome::Indeterminate
    );
    assert!(matches!(
        engine.preview(&proposed, &context()),
        Err(Error::Conflict)
    ));
    let persisted = empty.snapshot().record().clone();
    assert_eq!(
        engine
            .confirm(empty, &persisted, &context())
            .unwrap()
            .assessments[0]
            .outcome,
        Outcome::Indeterminate
    );
    assert!(matches!(
        engine.prepare(None, &[], 1012, true, context()).await,
        Err(Error::Conflict)
    ));
}

#[tokio::test]
async fn exact_receipt_and_originating_engine_are_required_for_fresh_authority() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let mut foreign = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1010, Some(1010))],
            1010,
            true,
            context(),
        )
        .await
        .unwrap();
    let original = candidate.snapshot().record().clone();
    assert!(matches!(
        foreign.confirm(candidate, &original, &context()),
        Err(Error::Conflict)
    ));
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1010, Some(1010))],
            1010,
            true,
            context(),
        )
        .await
        .unwrap();
    let mut wrong = candidate.snapshot().record().clone();
    wrong.checkpoint += 1;
    assert!(matches!(
        engine.confirm(candidate, &wrong, &context()),
        Err(Error::Conflict)
    ));
    let unknown = engine
        .prepare(None, &[], 1011, true, context())
        .await
        .unwrap();
    assert_eq!(
        engine.preview(&unknown, &context()).unwrap().assessments[0].outcome,
        Outcome::Indeterminate
    );
}

#[tokio::test]
async fn late_confirmation_and_restart_keep_original_outbox_without_renewing_authority() {
    let cfg = config();
    let mut first = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = first
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    let snapshot = candidate.snapshot().clone();
    let original = snapshot.record().outbox.clone();
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        first.confirm(candidate, snapshot.record(), &cancelled),
        Err(Error::Journal(state_journal::Error::Cancelled))
    ));
    // A completed physical effect may be found after a lost reply. Observing it
    // cannot install the discarded candidate's in-memory authority.
    let unknown = first
        .prepare(Some(&snapshot), &[], 1121, true, context())
        .await
        .unwrap();
    assert_eq!(
        first.preview(&unknown, &context()).unwrap().assessments[0].outcome,
        Outcome::Indeterminate
    );
    let serialized = serde_json::to_vec(&snapshot).unwrap();
    let restored: Snapshot = serde_json::from_slice(&serialized).unwrap();
    let mut restarted = Engine::new(cfg, epoch(0, 1, 1122), Some(&restored), &context()).unwrap();
    let pending = restarted
        .prepare(Some(&restored), &[], 1122, true, context())
        .await
        .unwrap();
    assert_eq!(pending.snapshot().record().outbox, original);
    let preview = restarted.preview(&pending, &context()).unwrap();
    assert_eq!(preview.assessments[0].outcome, Outcome::Indeterminate);
    assert_eq!(preview.findings.len(), 1);
}

#[tokio::test]
async fn snapshot_source_policy_and_revision_conflicts_are_refused() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = engine
        .prepare(None, &[], 1000, true, context())
        .await
        .unwrap();
    let original = candidate.snapshot().clone();
    engine
        .confirm(candidate, original.record(), &context())
        .unwrap();
    let mut changed_epoch = epoch(0, 0, 1001);
    changed_epoch.source_binding = [2; 32];
    assert!(matches!(
        Engine::new(cfg.clone(), changed_epoch, Some(&original), &context()),
        Err(Error::Conflict)
    ));
    let mut changed = cfg;
    changed.title = "different output policy".into();
    assert!(matches!(
        Engine::new(changed, epoch(0, 0, 1001), Some(&original), &context()),
        Err(Error::Conflict)
    ));
    let mut wire = serde_json::to_value(&original).unwrap();
    wire["record"]["state"] =
        serde_json::json!(serde_json::to_vec(&serde_json::json!({"schema_version":2})).unwrap());
    let invalid: Snapshot = serde_json::from_value(wire).unwrap();
    assert!(
        engine
            .prepare(Some(&invalid), &[], 1001, true, context())
            .await
            .is_err()
    );
    let candidate = engine
        .prepare(Some(&original), &[], 1001, true, context())
        .await
        .unwrap();
    let newer = candidate.snapshot().clone();
    engine
        .confirm(candidate, newer.record(), &context())
        .unwrap();
    assert!(matches!(
        engine
            .prepare(Some(&original), &[], 1002, true, context())
            .await,
        Err(Error::Conflict)
    ));
}

#[tokio::test]
async fn shared_binding_refuses_foreign_scope_key_revision_generation_and_checkpoint() {
    use signal_control::{ProducerEnrollment, Scope, StateReadResult};
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    let mut binding = SharedBinding {
        producer: ProducerEnrollment {
            scope: Scope {
                schema_version: 1,
                store_id: Uuid::from_u128(20),
                generation: Uuid::from_u128(21),
                tenant: "fixture".into(),
                stream: Uuid::from_u128(1),
                partition_id: Uuid::from_u128(22),
            },
            scope_generation: Uuid::from_u128(23),
            startup: Uuid::from_u128(24),
            wal_floor: 0,
        },
        key: "sensor-fixture".into(),
        rule_revision: [2; 32],
    };
    let (value, detached) = binding
        .encode(&engine, candidate.snapshot(), &context())
        .unwrap();
    let read = StateReadResult {
        schema_version: 1,
        partition_id: binding.producer.scope.partition_id,
        head: Some(Uuid::from_u128(25)),
        checkpoint: 1,
        state: Some(value),
    };
    assert_eq!(
        binding.references(&engine, &read, &context()).unwrap(),
        detached.canonical_sequences
    );
    let (restored, prior) = binding
        .restore(&engine, &read, &detached.retained, &context())
        .unwrap();
    assert!(restored == *candidate.snapshot());
    assert_eq!(prior.checkpoint, 1);
    assert_eq!(
        prior.value_sha256,
        <[u8; 32]>::from(Sha256::digest(&read.state.as_ref().unwrap().bytes))
    );
    for change in 0..11 {
        let mut invalid = read.clone();
        match change {
            0 => invalid.partition_id = Uuid::new_v4(),
            1 => invalid.head = None,
            2 => invalid.checkpoint = 2,
            3 => invalid.state.as_mut().unwrap().key = "foreign".into(),
            4 => invalid.state.as_mut().unwrap().revision = [3; 32],
            _ => {
                let value = invalid.state.as_mut().unwrap();
                let mut envelope: serde_json::Value = serde_json::from_slice(&value.bytes).unwrap();
                match change {
                    5 => envelope["scope_generation"] = serde_json::json!(Uuid::new_v4()),
                    6 => envelope["metadata"]["scope"]["tenant"] = serde_json::json!("foreign"),
                    7 => envelope["metadata"]["key"] = serde_json::json!("foreign"),
                    8 => envelope["metadata"]["rule_revision"] = serde_json::json!(vec![3; 32]),
                    9 => envelope["checkpoint"] = serde_json::json!(2),
                    _ => {
                        envelope["checkpoint"] = serde_json::json!(2);
                        invalid.checkpoint = 2;
                    }
                }
                value.bytes = serde_json::to_vec(&envelope).unwrap();
            }
        }
        assert!(
            binding
                .restore(&engine, &invalid, &detached.retained, &context())
                .is_err(),
            "mutation {change}"
        );
    }
    let mut changed = detached.retained.clone();
    changed[0].event.message = Some("changed".into());
    assert!(
        binding
            .restore(&engine, &read, &changed, &context())
            .is_err()
    );
    let restarted_engine =
        Engine::new(cfg, epoch(0, 1, 1121), Some(&restored), &context()).unwrap();
    binding.producer.wal_floor = 2;
    assert!(
        binding
            .restore(&restarted_engine, &read, &detached.retained, &context())
            .is_err()
    );
    // Original enrollment survives restart; the engine's later captured floor
    // still excludes every retained report from current observer authority.
    binding.producer.wal_floor = 0;
    let (again, _) = binding
        .restore(&restarted_engine, &read, &detached.retained, &context())
        .unwrap();
    let mut restarted_engine = restarted_engine;
    let next = restarted_engine
        .prepare(Some(&again), &[], 1121, true, context())
        .await
        .unwrap();
    assert_eq!(
        restarted_engine
            .preview(&next, &context())
            .unwrap()
            .assessments[0]
            .outcome,
        Outcome::Indeterminate
    );
}

#[tokio::test]
async fn idle_retirement_keeps_checkpoint_and_only_confirmation_changes_original_outbox() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1120, Some(1000))],
            1120,
            true,
            context(),
        )
        .await
        .unwrap();
    let current = candidate.snapshot().clone();
    engine
        .confirm(candidate, current.record(), &context())
        .unwrap();
    assert_eq!(current.record().outbox.len(), 1);
    let inspected = engine.inspect(&current, 1121, &context()).unwrap();
    assert_eq!(inspected.published_prefix, 1);
    assert_eq!(inspected.assessments[0].outcome, Outcome::Indeterminate);
    assert_eq!(inspected.valid_until_ms, 0);
    assert!(
        engine
            .prepare_retiring(&current, 2, 1121, context())
            .await
            .is_err()
    );
    let retired = engine
        .prepare_retiring(&current, 1, 1121, context())
        .await
        .unwrap();
    assert!(retired.snapshot().record().outbox.is_empty());
    assert_eq!(
        retired.snapshot().record().checkpoint,
        current.record().checkpoint
    );
    assert_eq!(
        engine
            .inspect(&current, 1121, &context())
            .unwrap()
            .published_prefix,
        1
    );
    let saved = retired.snapshot().clone();
    engine.confirm(retired, saved.record(), &context()).unwrap();
    assert_eq!(saved.record().revision, current.record().revision + 1);
    let expired = engine
        .prepare_retiring(&saved, 0, 1620, context())
        .await
        .unwrap();
    let preview = engine.preview(&expired, &context()).unwrap();
    assert!(preview.findings.is_empty());
    assert_eq!(preview.assessments[0].outcome, Outcome::Indeterminate);
    assert_eq!(expired.snapshot().record().checkpoint, 1);
}

#[tokio::test]
async fn empty_checkpoint_state_recovers_ticks_and_then_admits_first_signed_event() {
    use signal_control::{ProducerEnrollment, Scope, StateReadResult};
    let cfg = config();
    let binding = SharedBinding {
        producer: ProducerEnrollment {
            scope: Scope {
                schema_version: 1,
                store_id: Uuid::from_u128(20),
                generation: Uuid::from_u128(21),
                tenant: "fixture".into(),
                stream: Uuid::from_u128(1),
                partition_id: Uuid::from_u128(22),
            },
            scope_generation: Uuid::from_u128(23),
            startup: Uuid::from_u128(24),
            wal_floor: 0,
        },
        key: "sensor-zero".into(),
        rule_revision: [2; 32],
    };
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let initial = engine
        .prepare(None, &[], 1000, true, context())
        .await
        .unwrap();
    let snapshot = initial.snapshot().clone();
    let (value, original) = binding.encode(&engine, &snapshot, &context()).unwrap();
    assert!(original.retained.is_empty());
    assert!(original.canonical_sequences.is_empty());
    let view = engine
        .confirm(initial, snapshot.record(), &context())
        .unwrap();
    assert_eq!(view.assessments[0].outcome, Outcome::Indeterminate);
    assert_eq!(view.history_assessments, 1);
    assert!(view.findings.is_empty());
    let read = StateReadResult {
        schema_version: 1,
        partition_id: binding.producer.scope.partition_id,
        head: None,
        checkpoint: 0,
        state: Some(value),
    };
    let (recovered, prior) = binding.restore(&engine, &read, &[], &context()).unwrap();
    assert_eq!(prior.checkpoint, 0);
    let mut restarted =
        Engine::new(cfg.clone(), epoch(0, 0, 1001), Some(&recovered), &context()).unwrap();
    let tick = restarted
        .prepare_retiring(&recovered, 0, 1001, context())
        .await
        .unwrap();
    let current = tick.snapshot().clone();
    restarted
        .confirm(tick, current.record(), &context())
        .unwrap();
    assert_eq!(current.record().checkpoint, 0);
    assert_eq!(current.record().revision, 2);
    let report = row(&cfg, 1, 10, 1, 1120, Some(1000));
    let admitted = restarted
        .prepare(Some(&current), &[report], 1120, true, context())
        .await
        .unwrap();
    let preview = restarted.preview(&admitted, &context()).unwrap();
    assert_eq!(preview.findings.len(), 1);
    assert_eq!(admitted.snapshot().record().checkpoint, 1);
    let (_, retained) = binding
        .encode(&restarted, admitted.snapshot(), &context())
        .unwrap();
    assert_eq!(retained.retained.len(), 1);
}

#[tokio::test]
async fn fresh_caller_context_cannot_confirm_a_cancelled_original_candidate() {
    let cfg = config();
    let mut engine = Engine::new(cfg.clone(), epoch(0, 0, 1000), None, &context()).unwrap();
    let original = context();
    let candidate = engine
        .prepare(
            None,
            &[row(&cfg, 1, 10, 1, 1010, Some(1010))],
            1010,
            true,
            original.clone(),
        )
        .await
        .unwrap();
    let confirmed = candidate.snapshot().record().clone();
    original.cancellation.cancel();
    assert!(matches!(
        engine.confirm(candidate, &confirmed, &context()),
        Err(Error::Journal(state_journal::Error::Cancelled))
    ));
}

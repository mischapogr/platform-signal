//! Synthetic root bindings and cursors; filesystem/node composition is separate.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::contracts::{NodeSourceIdentity, NodeTermination};
use signal_collector_sdk::kubernetes_log::{self, LogIdentity, Profile};
use uuid::Uuid;

fn configuration(path: &Path) -> SpoolConfig {
    SpoolConfig {
        directory: path.into(),
        cursor_profile: CursorProfile::KubernetesNode {
            source_binding: [0xab; 32],
        },
        max_event_bytes: kubernetes_log::MAX_EVENT_BYTES,
        ..Default::default()
    }
}
fn checkpoint(slot: u16, uid: &str) -> SourceCheckpoint {
    SourceCheckpoint {
        input: slot,
        device: 1,
        inode: 2,
        offset: 5,
        anchor: b"done\n".to_vec(),
        source_binding: CursorProfile::KubernetesNode {
            source_binding: [0xab; 32],
        }
        .binding(),
        source_identity: Some(NodeSourceIdentity {
            schema_version: 1,
            source: LogIdentity::from_relative(&format!("team_workload_{uid}"), "main", "0.log")
                .unwrap(),
            file_name: "0.log".into(),
            terminal: None,
        }),
    }
}
fn maximal(slot: u16) -> SourceCheckpoint {
    let mut c = checkpoint(slot, "runtime");
    c.device = u64::MAX;
    c.inode = u64::MAX;
    c.offset = u64::MAX;
    c.anchor = vec![255; 64];
    c.source_identity = Some(NodeSourceIdentity {
        schema_version: 1,
        source: LogIdentity {
            schema_version: 1,
            namespace: "n".repeat(63),
            pod_name: "p".repeat(62),
            runtime_pod_uid: "\"".repeat(128),
            container: "c".repeat(63),
            restart_count: u32::MAX,
        },
        file_name: format!("{}.log.{}", u32::MAX, "r".repeat(113)),
        terminal: Some(NodeTermination::CompressedGeneration),
    });
    c
}
fn event(c: &SourceCheckpoint, payload: u8, large: bool) -> SignalEvent {
    let mut raw = b"2026-10-25T12:00:00Z stdout P ".to_vec();
    if large {
        raw.resize(kubernetes_log::MAX_RECORD_BYTES - 1, payload);
    } else {
        raw.extend_from_slice(b"fragment");
    }
    raw.push(b'\n');
    kubernetes_log::normalize_record(
        &raw,
        &Profile::new("owned-cluster", "node-a").unwrap(),
        &c.source_identity.as_ref().unwrap().source,
        Uuid::new_v4(),
        chrono::Utc::now(),
    )
    .unwrap()
}
fn context() -> Context {
    Context {
        deadline: Instant::now() + Duration::from_secs(5),
        cancellation: CancellationToken::new(),
    }
}
fn framed(path: &Path, value: &impl Serialize) {
    let data = serde_json::to_vec(value).unwrap();
    let mut bytes = header(&data).to_vec();
    bytes.extend(data);
    fs::write(path, bytes).unwrap();
}
fn state(path: &Path, config: &SpoolConfig) -> State {
    let raw = read_frame(
        &path.join("state"),
        config.cursor_profile.state_limit(),
        false,
    )
    .unwrap()
    .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[test]
fn sixteen_maximally_escaped_node_cursors_fit_state_envelope_and_numeric_headroom() {
    let c = maximal(15);
    configuration(Path::new("/synthetic"))
        .cursor_profile
        .checkpoint(&c)
        .unwrap();
    let e = event(&c, 0, true);
    let encoded = serde_json::to_vec(&e).unwrap();
    assert!(encoded.len() > 64 * 1024);
    assert!(encoded.len() <= kubernetes_log::MAX_EVENT_BYTES);
    let record = DiskRecord {
        version: 1,
        sequence: u64::MAX,
        event: e,
        checkpoint: Some(c.clone()),
    };
    assert!(serde_json::to_vec(&record).unwrap().len() - encoded.len() <= NODE_CHECKPOINT_BYTES);
    let profile = configuration(Path::new("/synthetic")).cursor_profile;
    let s = State {
        version: 2,
        profile_binding: profile.binding(),
        acknowledged: u64::MAX,
        next_sequence: u64::MAX,
        cursors: (0..16).map(maximal).collect(),
    };
    let bytes = serde_json::to_vec(&s).unwrap();
    assert!(bytes.len() > STATE_LIMIT);
    assert!(bytes.len() <= profile.state_limit());
    assert!((bytes.len() + FRAME_BYTES) * 2 <= NODE_METADATA_RESERVE as usize);
}
#[test]
fn node_capacity_validation_refuses_legacy_event_budget_and_impossible_batch() {
    let mut cfg = configuration(Path::new("/synthetic"));
    cfg.validate().unwrap();
    cfg.max_event_bytes = 65536;
    assert!(cfg.validate().is_err());
    cfg.max_event_bytes = kubernetes_log::MAX_EVENT_BYTES;
    cfg.max_batch_bytes = cfg.max_event_bytes;
    assert!(cfg.validate().is_err());
    cfg.max_batch_bytes = usize::MAX;
    assert!(cfg.validate().is_err());
}
#[tokio::test]
async fn empty_node_profile_is_durable_and_drift_refuses_before_recovery_cleanup() {
    let d = tempfile::tempdir().unwrap();
    let cfg = configuration(d.path());
    let cancel = CancellationToken::new();
    let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
    s.close(&cancel).await.unwrap();
    let original = fs::read(d.path().join("state")).unwrap();
    assert_eq!(state(d.path(), &cfg).version, 2);
    fs::write(
        d.path().join("state.tmp"),
        b"retain-before-profile-validation",
    )
    .unwrap();
    for profile in [
        CursorProfile::Legacy,
        CursorProfile::KubernetesNode {
            source_binding: [0xcd; 32],
        },
    ] {
        let mut foreign = cfg.clone();
        foreign.cursor_profile = profile;
        assert!(Spool::open(foreign, &cancel).await.is_err());
        assert_eq!(fs::read(d.path().join("state")).unwrap(), original);
        assert_eq!(
            fs::read(d.path().join("state.tmp")).unwrap(),
            b"retain-before-profile-validation"
        );
    }
    let s = Spool::open(cfg, &cancel).await.unwrap();
    assert!(!d.path().join("state.tmp").exists());
    s.close(&cancel).await.unwrap();
}
#[tokio::test]
async fn invalid_or_foreign_checkpoints_refuse_before_any_record_or_state_write() {
    let d = tempfile::tempdir().unwrap();
    let cfg = configuration(d.path());
    let cancel = CancellationToken::new();
    let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
    let before = fs::read(d.path().join("state")).unwrap();
    let valid = checkpoint(0, "original");
    let e = event(&valid, b'x', false);
    let mut missing = valid.clone();
    missing.source_identity = None;
    let mut binding = valid.clone();
    binding.source_binding = Some("c".repeat(64));
    let mut escape = valid.clone();
    escape.source_identity.as_mut().unwrap().file_name = "../escape".into();
    let mut schema = valid.clone();
    schema.source_identity.as_mut().unwrap().schema_version = 2;
    let mut anchor = valid.clone();
    anchor.offset = 0;
    for c in [missing, binding, escape, schema, anchor] {
        assert!(s.append(e.clone(), Some(c.clone()), &cancel).await.is_err());
        assert!(s.checkpoint(c, &cancel).await.is_err());
    }
    assert!(s.append(e.clone(), None, &cancel).await.is_err());
    assert_eq!(fs::read(d.path().join("state")).unwrap(), before);
    assert!(fs::read_dir(d.path()).unwrap().all(|p| {
        !p.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("record-")
    }));
    s.close(&cancel).await.unwrap();
    let legacy = tempfile::tempdir().unwrap();
    let s = Spool::open(
        SpoolConfig {
            directory: legacy.path().into(),
            ..Default::default()
        },
        &cancel,
    )
    .await
    .unwrap();
    assert!(s.append(e, Some(valid), &cancel).await.is_err());
    assert_eq!(s.metrics().records, 0);
    s.close(&cancel).await.unwrap();
}
#[tokio::test]
async fn historical_events_keep_identity_while_cursor_slot_reuse_survives_restart_and_ack() {
    let d = tempfile::tempdir().unwrap();
    let cfg = configuration(d.path());
    let cancel = CancellationToken::new();
    let first = checkpoint(0, "original-runtime");
    let original = event(&first, b'x', false);
    let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
    s.append(original.clone(), Some(first), &cancel)
        .await
        .unwrap();
    let mut next = checkpoint(0, "replacement-runtime");
    next.offset = 20;
    s.checkpoint(next.clone(), &cancel).await.unwrap();
    s.close(&cancel).await.unwrap();
    let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
    let saved = s
        .read_batch(10, cfg.max_batch_bytes, &cancel)
        .await
        .unwrap();
    assert_eq!(saved[0].event, original);
    assert_eq!(
        s.cursor_snapshot(&cancel).await.unwrap(),
        vec![next.clone()]
    );
    let replacement = event(&next, b'x', false);
    next.offset = 30;
    s.append(replacement.clone(), Some(next.clone()), &cancel)
        .await
        .unwrap();
    s.close(&cancel).await.unwrap();
    let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
    let saved = s
        .read_batch(10, cfg.max_batch_bytes, &cancel)
        .await
        .unwrap();
    assert_eq!(
        saved.iter().map(|v| v.event.clone()).collect::<Vec<_>>(),
        vec![original, replacement]
    );
    assert_eq!(
        s.cursor_snapshot(&cancel).await.unwrap(),
        vec![next.clone()]
    );
    s.ack(2, &cancel).await.unwrap();
    s.close(&cancel).await.unwrap();
    let s = Spool::open(cfg, &cancel).await.unwrap();
    assert_eq!(s.metrics().records, 0);
    assert_eq!(s.cursor_snapshot(&cancel).await.unwrap(), vec![next]);
    s.close(&cancel).await.unwrap();
}
#[tokio::test]
async fn full_node_state_and_expanded_native_payload_admit_ack_and_reopen_at_minimum_quota() {
    for byte in [0, 0xff] {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = configuration(d.path());
        cfg.max_disk_bytes = NODE_METADATA_RESERVE
            + cfg.max_event_bytes as u64
            + NODE_CHECKPOINT_BYTES as u64
            + FRAME_BYTES as u64;
        cfg.validate().unwrap();
        let cancel = CancellationToken::new();
        let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
        for input in 0..16 {
            s.checkpoint(maximal(input), &cancel).await.unwrap();
        }
        let c = maximal(15);
        let original = event(&c, byte, true);
        s.append(original.clone(), Some(c), &cancel).await.unwrap();
        let saved = s
            .read_batch(10, cfg.max_batch_bytes, &cancel)
            .await
            .unwrap();
        assert_eq!(saved[0].event, original);
        assert!(s.metrics().disk_bytes <= cfg.max_disk_bytes);
        s.ack(1, &cancel).await.unwrap();
        s.close(&cancel).await.unwrap();
        let s = Spool::open(cfg, &cancel).await.unwrap();
        assert_eq!(s.metrics().records, 0);
        assert_eq!(s.metrics().disk_bytes, NODE_METADATA_RESERVE);
        assert_eq!(
            s.cursor_snapshot(&cancel).await.unwrap(),
            (0..16).map(maximal).collect::<Vec<_>>()
        );
        s.close(&cancel).await.unwrap();
    }
}
#[test]
fn corrupted_historical_profile_refuses_before_removing_pending_or_temporary_evidence() {
    let d = tempfile::tempdir().unwrap();
    let cfg = configuration(d.path());
    let mut engine = Engine::open(cfg.clone(), &context()).unwrap();
    let c = checkpoint(0, "old-runtime");
    engine
        .perform(
            Work::Append(Box::new(event(&c, b'x', false)), Some(c)),
            &context(),
        )
        .unwrap();
    let latest = checkpoint(0, "new-runtime");
    engine
        .perform(Work::Checkpoint(latest), &context())
        .unwrap();
    drop(engine);
    let file = d.path().join("record-00000000000000000001");
    let raw = read_frame(
        &file,
        kubernetes_log::MAX_EVENT_BYTES + NODE_CHECKPOINT_BYTES,
        false,
    )
    .unwrap()
    .unwrap();
    let mut record: DiskRecord = serde_json::from_slice(&raw).unwrap();
    record.checkpoint.as_mut().unwrap().source_binding = Some("c".repeat(64));
    framed(&file, &record);
    let record_before = fs::read(&file).unwrap();
    let state_before = fs::read(d.path().join("state")).unwrap();
    fs::write(d.path().join("state.tmp"), b"retain-on-foreign-history").unwrap();
    assert!(Engine::open(cfg, &context()).is_err());
    assert_eq!(fs::read(file).unwrap(), record_before);
    assert_eq!(fs::read(d.path().join("state")).unwrap(), state_before);
    assert_eq!(
        fs::read(d.path().join("state.tmp")).unwrap(),
        b"retain-on-foreign-history"
    );
}
#[test]
fn maximum_sequence_growth_ack_and_overflow_refuse_without_new_record() {
    let d = tempfile::tempdir().unwrap();
    let cfg = configuration(d.path());
    let engine = Engine::open(cfg.clone(), &context()).unwrap();
    let mut prepared = engine.state.clone();
    prepared.acknowledged = u64::MAX - 2;
    prepared.next_sequence = u64::MAX - 1;
    prepared.cursors = (0..16).map(maximal).collect();
    engine.persist_state(&prepared, &context()).unwrap();
    drop(engine);
    let mut engine = Engine::open(cfg.clone(), &context()).unwrap();
    let c = maximal(15);
    assert!(
        matches!(engine.perform(Work::Append(Box::new(event(&c,b'x',false)),Some(c)),&context()).unwrap(),Value::Sequence(v) if v==u64::MAX-1)
    );
    engine.perform(Work::Ack(u64::MAX - 1), &context()).unwrap();
    drop(engine);
    let mut engine = Engine::open(cfg, &context()).unwrap();
    let before = fs::read(d.path().join("state")).unwrap();
    let c = maximal(15);
    assert!(matches!(
        engine.perform(
            Work::Append(Box::new(event(&c, b'x', false)), Some(c)),
            &context()
        ),
        Err(SpoolError::Invalid("sequence overflow"))
    ));
    assert_eq!(fs::read(d.path().join("state")).unwrap(), before);
    assert!(engine.entries.is_empty());
    assert!(!engine.record_path(u64::MAX).exists());
}
#[tokio::test]
async fn legacy_json_and_minimal_quota_remain_unchanged() {
    assert_eq!(
        serde_json::to_vec(&State::default()).unwrap(),
        br#"{"version":1,"acknowledged":0,"next_sequence":1,"cursors":[]}"#
    );
    let c = SourceCheckpoint {
        input: 0,
        device: 1,
        inode: 2,
        offset: 5,
        anchor: vec![],
        source_binding: None,
        source_identity: None,
    };
    let encoded = serde_json::to_value(&c).unwrap();
    assert!(encoded.get("source_identity").is_none());
    assert!(encoded.get("source_binding").is_none());
    let d = tempfile::tempdir().unwrap();
    let cfg = SpoolConfig {
        directory: d.path().into(),
        max_event_bytes: 1024,
        max_disk_bytes: METADATA_RESERVE + 1024 + CHECKPOINT_BYTES as u64 + FRAME_BYTES as u64,
        ..Default::default()
    };
    cfg.validate().unwrap();
    let cancel = CancellationToken::new();
    let s = Spool::open(cfg.clone(), &cancel).await.unwrap();
    let original = event(&checkpoint(0, "fixture"), b'x', false);
    s.append(original, Some(c), &cancel).await.unwrap();
    s.ack(1, &cancel).await.unwrap();
    s.close(&cancel).await.unwrap();
    let s = Spool::open(cfg, &cancel).await.unwrap();
    assert_eq!(s.metrics().disk_bytes, METADATA_RESERVE);
    s.close(&cancel).await.unwrap();
}

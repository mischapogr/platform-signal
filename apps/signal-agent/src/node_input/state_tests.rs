#![allow(clippy::unwrap_used)]
use super::*;
use std::{fs, io::Write, path::PathBuf};
fn fixture(follow: bool) -> (tempfile::TempDir, PathBuf, State) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("pods");
    fs::create_dir_all(root.join("team_workload_runtime-z/main")).unwrap();
    let path = root.join("team_workload_runtime-z/main/0.log");
    let config = Config {
        root: root.clone(),
        cluster: "cluster".into(),
        node: "node-a".into(),
        namespace: None,
        max_line_bytes: 65536,
        follow,
        limits: node_root::Limits::default(),
        scan_interval: Duration::from_millis(1),
    };
    let opened = node_root::Root::open(&root, config.limits).unwrap();
    let profile = CursorProfile::KubernetesNode {
        source_binding: config.binding(&opened),
    };
    let state = State::new(config, opened, profile, Arc::new(Counters::default())).unwrap();
    (temp, path, state)
}
fn ctx() -> Context {
    Context {
        deadline: Instant::now() + Duration::from_secs(3),
        cancel: CancellationToken::new(),
        lifetime: CancellationToken::new(),
    }
}
fn native(message: &str) -> String {
    format!("2026-10-25T12:00:00Z stdout F {message}\n")
}
fn record(s: &mut State) -> InputRecord {
    for _ in 0..100 {
        if let ReadOutcome::Record(r) = s.read(&ctx()).unwrap() {
            return *r;
        }
    }
    panic!("expected record");
}
fn restored(s: &State, cursors: Vec<SourceCheckpoint>) -> State {
    let root = node_root::Root::open(&s.config.root, s.config.limits).unwrap();
    let mut result = State::new(
        s.config.clone(),
        root,
        s.profile,
        Arc::new(Counters::default()),
    )
    .unwrap();
    result.restore(cursors).unwrap();
    result
}
#[test]
fn pending_native_pins_and_cursor_stay_exact_until_commit_then_follow_growth() {
    let (_temp, path, mut s) = fixture(true);
    fs::write(&path, native("first")).unwrap();
    s.restore(vec![]).unwrap();
    let first = record(&mut s);
    let replay = record(&mut s);
    assert_eq!(
        serde_json::to_vec(&first.event).unwrap(),
        serde_json::to_vec(&replay.event).unwrap()
    );
    assert_eq!(first.checkpoint, replay.checkpoint);
    s.commit().unwrap();
    assert!(matches!(s.read(&ctx()).unwrap(), ReadOutcome::Idle));
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(native("second").as_bytes())
        .unwrap();
    let next = record(&mut s);
    assert_eq!(next.event.unwrap().message.as_deref(), Some("second"));
    assert!(next.checkpoint.unwrap().offset > first.checkpoint.unwrap().offset);
}
#[test]
fn restored_slots_survive_new_lexically_earlier_source() {
    let (_temp, path, mut s) = fixture(true);
    fs::write(&path, native("old")).unwrap();
    s.restore(vec![]).unwrap();
    let first = record(&mut s);
    s.commit().unwrap();
    let other = s.config.root.join("team_workload_runtime-a/main");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("0.log"), native("new-a")).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(native("new-z").as_bytes())
        .unwrap();
    let mut next = restored(&s, vec![first.checkpoint.unwrap()]);
    let mut seen = Vec::new();
    for _ in 0..2 {
        let r = record(&mut next);
        seen.push((
            r.event.unwrap().message.unwrap(),
            r.checkpoint.unwrap().input,
        ));
        next.commit().unwrap();
    }
    seen.sort();
    assert_eq!(seen, vec![("new-a".into(), 1), ("new-z".into(), 0)]);
}
#[test]
fn rotation_drains_held_plain_generation_then_admits_durable_gap_before_new_file() {
    let (_temp, path, mut s) = fixture(true);
    fs::write(&path, native("first")).unwrap();
    s.restore(vec![]).unwrap();
    let first = record(&mut s);
    s.commit().unwrap();
    let rotated = path.with_file_name("0.log.rotation");
    fs::rename(&path, &rotated).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&rotated)
        .unwrap()
        .write_all(native("old-tail").as_bytes())
        .unwrap();
    fs::write(&path, native("replacement")).unwrap();
    s.scan_at = None;
    let tail = record(&mut s);
    assert_eq!(tail.event.unwrap().message.as_deref(), Some("old-tail"));
    assert_eq!(
        tail.checkpoint.as_ref().unwrap().inode,
        first.checkpoint.unwrap().inode
    );
    assert_eq!(
        tail.checkpoint.unwrap().source_identity.unwrap().file_name,
        "0.log.rotation"
    );
    s.commit().unwrap();
    let gap = record(&mut s);
    assert_eq!(
        gap.event.as_ref().unwrap().attributes["collection"]["reason"],
        "rotation_observed"
    );
    assert_eq!(
        gap.checkpoint
            .as_ref()
            .unwrap()
            .source_identity
            .as_ref()
            .unwrap()
            .terminal,
        Some(NodeTermination::UncertainRotation)
    );
    assert_eq!(record(&mut s).event.unwrap().id, gap.event.unwrap().id);
    s.commit().unwrap();
    let current = record(&mut s);
    assert_eq!(
        current.event.unwrap().message.as_deref(),
        Some("replacement")
    );
    assert_eq!(current.checkpoint.unwrap().input, 0);
}
#[test]
fn copytruncate_and_same_size_anchor_change_never_silently_reset() {
    let (_temp, path, mut s) = fixture(true);
    fs::write(&path, native("first")).unwrap();
    s.restore(vec![]).unwrap();
    record(&mut s);
    s.commit().unwrap();
    fs::write(&path, native("other")).unwrap();
    let gap = record(&mut s);
    assert_eq!(
        gap.event.unwrap().attributes["collection"]["reason"],
        "changed_anchor"
    );
    s.commit().unwrap();
    let native = record(&mut s);
    assert_eq!(native.event.unwrap().message.as_deref(), Some("other"));
}
#[test]
fn missing_and_compressed_restored_generations_are_terminal_gaps_not_resets() {
    for compressed in [false, true] {
        let (_temp, path, mut s) = fixture(true);
        fs::write(&path, native("first")).unwrap();
        s.restore(vec![]).unwrap();
        let original = record(&mut s);
        s.commit().unwrap();
        if compressed {
            fs::rename(&path, path.with_file_name("0.log.previous.gz")).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        let mut next = restored(&s, vec![original.checkpoint.unwrap()]);
        let gap = record(&mut next);
        assert_eq!(
            gap.event.as_ref().unwrap().source.source_type,
            "kubernetes.collector"
        );
        assert_eq!(
            gap.event.as_ref().unwrap().attributes["collection"]["reason"],
            if compressed {
                "compressed_generation"
            } else {
                "missing_generation"
            }
        );
        let terminal = gap.checkpoint.unwrap();
        next.commit().unwrap();
        let mut again = restored(&next, vec![terminal]);
        assert!(matches!(again.read(&ctx()).unwrap(), ReadOutcome::Idle));
    }
}
#[test]
fn unterminated_once_prefix_is_durable_gap_and_never_reingested_unchanged() {
    let (_temp, path, mut s) = fixture(false);
    let partial = "2026-10-25T12:00:00Z stdout P unfinished";
    fs::write(&path, partial).unwrap();
    s.restore(vec![]).unwrap();
    let gap = record(&mut s);
    assert_eq!(gap.rejected, 1);
    assert_eq!(
        STANDARD
            .decode(
                gap.event.as_ref().unwrap().attributes["collection"]["partial_prefix_base64"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
        partial.as_bytes()
    );
    let terminal = gap.checkpoint.unwrap();
    s.commit().unwrap();
    assert!(matches!(s.read(&ctx()).unwrap(), ReadOutcome::End));
    let mut next = restored(&s, vec![terminal]);
    next.config.follow = true;
    assert!(matches!(next.read(&ctx()).unwrap(), ReadOutcome::Idle));
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    next.scan_at = None;
    let completed = record(&mut next);
    assert_eq!(
        completed.event.unwrap().message.as_deref(),
        Some("unfinished")
    );
}
#[test]
fn finite_once_cutoff_ignores_later_growth_without_claiming_source_completion() {
    let (_temp, path, mut s) = fixture(false);
    fs::write(&path, native("first")).unwrap();
    s.restore(vec![]).unwrap();
    let first = record(&mut s);
    s.commit().unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(native("later").as_bytes())
        .unwrap();
    assert!(matches!(s.read(&ctx()).unwrap(), ReadOutcome::End));
    let mut next = restored(&s, vec![first.checkpoint.unwrap()]);
    next.config.follow = true;
    assert_eq!(
        record(&mut next).event.unwrap().message.as_deref(),
        Some("later")
    );
}
#[test]
fn malformed_oversized_and_binary_physical_frames_keep_bounded_cursors() {
    let (_temp, path, mut s) = fixture(false);
    s.config.max_line_bytes = 128;
    let mut bytes = b"bad\n".to_vec();
    bytes.extend(vec![b'x'; 200]);
    bytes.push(b'\n');
    bytes.extend(b"2026-10-25T12:00:00Z stderr P \xf0\x9f\n");
    fs::write(path, bytes).unwrap();
    s.restore(vec![]).unwrap();
    for _ in 0..2 {
        let reject = record(&mut s);
        assert!(reject.event.is_none());
        assert_eq!(reject.rejected, 1);
        s.commit().unwrap();
    }
    let binary = record(&mut s);
    let e = binary.event.unwrap();
    assert_eq!(e.attributes["log"]["stream"], "stderr");
    assert_eq!(e.attributes["log"]["tag"], "P");
    assert_eq!(
        STANDARD
            .decode(e.attributes["log"]["payload_base64"].as_str().unwrap())
            .unwrap(),
        b"\xf0\x9f"
    );
    s.commit().unwrap();
    assert!(matches!(s.read(&ctx()).unwrap(), ReadOutcome::End));
}
#[test]
fn complete_scan_capacity_and_forged_restore_refuse_without_absence_decision() {
    let (_temp, path, mut s) = fixture(true);
    fs::write(path, native("first")).unwrap();
    s.restore(vec![]).unwrap();
    let first = record(&mut s);
    s.commit().unwrap();
    let mut bad = first.checkpoint.clone().unwrap();
    bad.source_binding = Some("f".repeat(64));
    let root = node_root::Root::open(&s.config.root, s.config.limits).unwrap();
    let mut empty = State::new(
        s.config.clone(),
        root,
        s.profile,
        Arc::new(Counters::default()),
    )
    .unwrap();
    assert!(empty.restore(vec![bad]).is_err());
    assert!(!empty.restored);
    let root = node_root::Root::open(
        &s.config.root,
        node_root::Limits {
            max_entries: 1,
            ..s.config.limits
        },
    )
    .unwrap();
    s.root = root;
    s.scan_at = None;
    assert!(matches!(
        s.read(&ctx()),
        Err(Error::Root(node_root::Error::Capacity))
    ));
    assert!(s.pending.is_none());
    assert_eq!(
        s.slots[0].as_ref().unwrap().position,
        first.checkpoint.unwrap()
    );
    assert_eq!(s.counters.gaps.load(Ordering::Relaxed), 0);
}

#[test]
fn cursor_anchor_pins_consumed_bytes_instead_of_adopting_concurrent_replacement() {
    let (_temp, path, _s) = fixture(true);
    let original = native("original source bytes");
    fs::write(&path, &original).unwrap();
    let file = File::open(&path).unwrap();
    let mut observed = vec![0; original.len()];
    file.read_at(&mut observed, 0).unwrap();
    fs::write(&path, native("replaced source bytes")).unwrap();
    let mut witness = Vec::new();
    extend_anchor(&mut witness, &observed);
    assert_eq!(
        witness,
        original.as_bytes()[original.len().saturating_sub(64)..]
    );
    assert_ne!(witness, anchor(&file, original.len() as u64).unwrap());
}

#[test]
fn rotated_only_full_registry_counts_capacity_and_retires_with_durable_gap_before_reuse() {
    let (_temp, path, mut s) = fixture(true);
    fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    let mut locations = Vec::new();
    for n in 0..16 {
        let directory = s.config.root.join(format!("team_workload_old-{n:02}/main"));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("0.log");
        fs::write(&path, native(&format!("old-{n}"))).unwrap();
        locations.push(path);
    }
    s.restore(vec![]).unwrap();
    for _ in 0..16 {
        let r = record(&mut s);
        assert_eq!(
            r.event.as_ref().unwrap().source.source_type,
            "kubernetes.container"
        );
        s.commit().unwrap();
    }
    for (n, path) in locations.iter().enumerate() {
        fs::rename(path, path.with_file_name("0.log.rotation")).unwrap();
        let new = s.config.root.join(format!("team_workload_new-{n:02}/main"));
        fs::create_dir_all(&new).unwrap();
        fs::write(new.join("0.log"), native(&format!("new-{n}"))).unwrap();
    }
    s.scan_at = None;
    let first_gap = record(&mut s);
    assert_eq!(
        first_gap.event.as_ref().unwrap().attributes["collection"]["reason"],
        "rotation_observed"
    );
    assert!(s.counters.admission_refusals.load(Ordering::Relaxed) > 0);
    assert!(s.slots.iter().flatten().all(|slot| {
        slot.position
            .source_identity
            .as_ref()
            .unwrap()
            .source
            .runtime_pod_uid
            .starts_with("old-")
    }));
    s.commit().unwrap();
    let mut native_new = 0;
    let mut gaps = 1;
    for _ in 0..40 {
        let r = record(&mut s);
        if r.event.as_ref().unwrap().source.source_type == "kubernetes.collector" {
            gaps += 1;
        } else {
            assert!(
                r.event
                    .as_ref()
                    .unwrap()
                    .message
                    .as_deref()
                    .unwrap()
                    .starts_with("new-")
            );
            native_new += 1;
        }
        s.commit().unwrap();
        if gaps == 16 && native_new == 16 {
            break;
        }
    }
    assert_eq!((gaps, native_new), (16, 16));
}
#[test]
fn once_reconciles_initial_replacement_after_gap_with_original_cutoff() {
    let (_temp, path, mut s) = fixture(true);
    fs::write(&path, native("old")).unwrap();
    s.restore(vec![]).unwrap();
    let original = record(&mut s);
    s.commit().unwrap();
    fs::rename(&path, path.with_file_name("0.log.rotation")).unwrap();
    fs::write(&path, native("initial replacement")).unwrap();
    let mut next = restored(&s, vec![original.checkpoint.unwrap()]);
    next.config.follow = false;
    let gap = record(&mut next);
    assert_eq!(
        gap.event.as_ref().unwrap().source.source_type,
        "kubernetes.collector"
    );
    next.commit().unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(native("later outside snapshot").as_bytes())
        .unwrap();
    let replacement = record(&mut next);
    assert_eq!(
        replacement.event.unwrap().message.as_deref(),
        Some("initial replacement")
    );
    next.commit().unwrap();
    assert!(matches!(next.read(&ctx()).unwrap(), ReadOutcome::End));
}

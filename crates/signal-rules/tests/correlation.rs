#[path = "support/correlation.rs"]
mod support;
use signal_rules::{
    correlation::{
        journal::{self, Action},
        *,
    },
    state_journal::Journal,
};
use support::*;
use uuid::Uuid;

#[test]
fn every_arrival_permutation_has_one_identical_multistream_episode() -> Result {
    let b = Binding::new(config(), &context())?;
    let events = inputs()?;
    let mut expected = None;
    let mut count = 0;
    for a in 0..4 {
        for d in 0..4 {
            for c in 0..4 {
                for f in 0..4 {
                    let order = [a, d, c, f];
                    let set: std::collections::BTreeSet<_> = order.into_iter().collect();
                    if set.len() != 4 {
                        continue;
                    }
                    let mut state = load(&b, &events, &order)?;
                    let ep = seal_epoch(&b, &state, time(50), true)?;
                    let report = state.seal(&b, &ep, &context())?;
                    assert_eq!(report.new_episodes, 1);
                    assert!(!report.coverage_gap);
                    let episode = &state.episodes()[0];
                    assert_eq!(episode.status, Status::Match);
                    assert_eq!(episode.event_ids.len(), 4);
                    assert_eq!(episode.contributors.len(), 2);
                    assert_eq!(
                        episode.finding.as_ref().ok_or("finding")?.event_ids,
                        episode.event_ids
                    );
                    let bytes = serde_json::to_vec(episode)?;
                    if let Some(ref expected) = expected {
                        assert_eq!(&bytes, expected);
                    } else {
                        expected = Some(bytes);
                    }
                    assert_eq!(state.seal(&b, &ep, &context())?.new_episodes, 0);
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 24);
    Ok(())
}
#[test]
fn native_duplicates_reserve_canonical_aliases_without_increasing_burst_count() -> Result {
    let b = Binding::new(config(), &context())?;
    let ep = epoch(&b, time(100), true)?;
    let stream = b.config().sources[0].stream;
    let first = event(0, 1, 1, false)?;
    let mut state = State::new(&b);
    state.admit(&b, stream, 1, &first, &ep, &context())?;
    let mut duplicate = first.clone();
    duplicate.id = Uuid::from_u128(888);
    duplicate.observed_at = time(550);
    assert_eq!(
        state.admit(&b, stream, 2, &duplicate, &ep, &context())?,
        Admission::Duplicate
    );
    let before = state.encode(&b, &context())?;
    let mut reused = event(0, 2, 2, false)?;
    reused.id = duplicate.id;
    assert!(matches!(
        state.admit(&b, stream, 3, &reused, &ep, &context()),
        Err(Error::Conflict)
    ));
    assert_eq!(state.encode(&b, &context())?, before);
    let mut conflict = first.clone();
    conflict.id = Uuid::from_u128(999);
    conflict.message = Some("conflicting native content".into());
    assert!(matches!(
        state.admit(&b, stream, 3, &conflict, &ep, &context()),
        Err(Error::Conflict)
    ));
    let success = event(1, 1, 10, true)?;
    state.admit(
        &b,
        b.config().sources[1].stream,
        1,
        &success,
        &ep,
        &context(),
    )?;
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
    assert_eq!(state.episodes()[0].status, Status::NoMatch);
    Ok(())
}
#[test]
fn canonical_collision_across_enrolled_streams_refuses() -> Result {
    let mut cfg = config();
    cfg.sources[1].source_type = cfg.sources[0].source_type.clone();
    cfg.sources[1].source_name = cfg.sources[0].source_name.clone();
    let b = Binding::new(cfg, &context())?;
    let ep = epoch(&b, time(100), true)?;
    let e = event(0, 1, 1, false)?;
    let mut state = State::new(&b);
    state.admit(&b, b.config().sources[0].stream, 1, &e, &ep, &context())?;
    assert!(matches!(
        state.admit(&b, b.config().sources[1].stream, 1, &e, &ep, &context()),
        Err(Error::Conflict)
    ));
    Ok(())
}
#[test]
fn exact_correlation_ttl_and_one_nanosecond_outside_have_distinct_results() -> Result {
    let mut cfg = config();
    cfg.threshold = 1;
    cfg.window_ms = 1000;
    cfg.correlation_ms = 1000;
    cfg.lateness_ms = 0;
    cfg.ttl_ms = 2000;
    let b = Binding::new(cfg, &context())?;
    for (outside_c, expired, expected) in [
        (false, false, Status::Match),
        (true, false, Status::NoMatch),
        (false, true, Status::Indeterminate),
    ] {
        let failure = event(0, 1, 1, false)?;
        let mut success = event(1, 1, 2, true)?;
        if outside_c {
            success.timestamp = plus_ns(success.timestamp);
        }
        let events = vec![failure, success];
        let mut state = load(&b, &events, &[0, 1])?;
        let frontier = if expired { plus_ns(time(4)) } else { time(4) };
        state.seal(&b, &seal_epoch(&b, &state, frontier, true)?, &context())?;
        assert_eq!(
            state.episodes()[0].status,
            expected,
            "C outside={outside_c},TTL expired={expired}"
        );
    }
    Ok(())
}
#[test]
fn missing_fields_tied_order_and_incomplete_lookback_never_prove_clean_absence() -> Result {
    let mut cfg = config();
    cfg.threshold = 1;
    let b = Binding::new(cfg, &context())?;
    let mut missing = event(1, 1, 10, true)?;
    missing.attributes["authentication"]
        .as_object_mut()
        .ok_or("auth")?
        .remove("principal_id");
    for events in [
        vec![missing],
        vec![event(0, 1, 10, false)?, event(1, 1, 10, true)?],
    ] {
        let order: Vec<_> = (0..events.len()).collect();
        let mut state = load(&b, &events, &order)?;
        state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
        assert_eq!(state.episodes()[0].status, Status::Indeterminate);
        assert!(state.episodes()[0].coverage_gap);
    }
    let mut state = State::new(&b);
    let report = state.seal(&b, &seal_epoch(&b, &state, time(50), false)?, &context())?;
    assert!(report.coverage_gap);
    assert_eq!(report.new_episodes, 0);
    let success = event(1, 1, 100, true)?;
    state.admit(
        &b,
        b.config().sources[1].stream,
        1,
        &success,
        &epoch(&b, time(150), true)?,
        &context(),
    )?;
    state.seal(&b, &seal_epoch(&b, &state, time(150), true)?, &context())?;
    assert_eq!(
        state.episodes()[0].status,
        Status::Indeterminate,
        "durable earlier coverage loss overlaps lookback"
    );
    Ok(())
}
#[test]
fn minimum_all_stream_watermark_and_monotonicity_bound_sealing() -> Result {
    let b = Binding::new(config(), &context())?;
    let events = inputs()?;
    let mut state = load(&b, &events, &[0, 1, 2, 3])?;
    let missing = Epoch::new(
        &b,
        vec![verification(&b.config().sources[0], time(100), true)],
        &context(),
    )?;
    let report = state.seal(&b, &missing, &context())?;
    assert!(report.coverage_gap);
    assert_eq!(report.watermark, None);
    assert!(state.episodes().is_empty());
    let slow = Epoch::new(
        &b,
        vec![
            {
                let mut p = verification(&b.config().sources[0], time(100), true);
                p.position = 3;
                p
            },
            {
                let mut p = verification(&b.config().sources[1], time(15), true);
                p.position = 1;
                p
            },
        ],
        &context(),
    )?;
    assert_eq!(state.seal(&b, &slow, &context())?.watermark, Some(time(5)));
    assert!(state.episodes().is_empty());
    let advanced = Epoch::new(
        &b,
        vec![
            {
                let mut p = verification(&b.config().sources[0], time(100), true);
                p.position = 3;
                p
            },
            {
                let mut p = verification(&b.config().sources[1], time(50), true);
                p.position = 1;
                p
            },
        ],
        &context(),
    )?;
    state.seal(&b, &advanced, &context())?;
    let before = state.encode(&b, &context())?;
    assert!(matches!(
        state.seal(&b, &slow, &context()),
        Err(Error::Conflict)
    ));
    assert_eq!(state.encode(&b, &context())?, before);
    Ok(())
}
#[test]
fn late_inputs_and_capacity_refusals_preserve_original_state_and_gaps() -> Result {
    let mut cfg = config();
    cfg.threshold = 1;
    cfg.max_events = 2;
    let b = Binding::new(cfg, &context())?;
    let mut state = State::new(&b);
    let ep = epoch(&b, time(100), true)?;
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
    let failure = event(0, 1, 5, false)?;
    assert_eq!(
        state.admit(
            &b,
            b.config().sources[0].stream,
            1,
            &failure,
            &ep,
            &context()
        )?,
        Admission::Late
    );
    let success = event(1, 1, 50, true)?;
    state.admit(
        &b,
        b.config().sources[1].stream,
        1,
        &success,
        &ep,
        &context(),
    )?;
    let before = state.encode(&b, &context())?;
    assert!(matches!(
        state.admit(
            &b,
            b.config().sources[0].stream,
            2,
            &event(0, 2, 45, false)?,
            &ep,
            &context()
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(state.encode(&b, &context())?, before);
    state.seal(&b, &seal_epoch(&b, &state, time(70), true)?, &context())?;
    assert_eq!(state.episodes()[0].status, Status::Indeterminate);
    Ok(())
}
#[tokio::test]
async fn actual_journal_reopen_keeps_original_episode_and_refuses_history_omission() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let b = Binding::new(config(), &context())?;
    let ep = epoch(&b, time(100), true)?;
    let events = inputs()?;
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = dir.path().join("episodes.sqlite");
    let (db, ready) = Journal::begin_open(path.clone(), b.journal_config(), context())?;
    ready.wait().await?;
    let mut previous = None;
    for (i, event) in events.iter().enumerate() {
        let source = if i < 3 { 0 } else { 1 };
        let position = if i < 3 { i as u64 + 1 } else { 1 };
        let p = journal::prepare(
            &b,
            previous.as_ref(),
            i as u64 + 1,
            Action::Admit {
                stream: b.config().sources[source].stream,
                position,
                event,
            },
            &ep,
            &context(),
        )?;
        previous = Some(p.commit(&db).await?);
    }
    let previous = previous.ok_or("previous")?;
    let mut forged = previous.clone();
    let mut state: serde_json::Value = serde_json::from_slice(&forged.state)?;
    let omitted = state["observations"][0]["event"]["id"].clone();
    state["observations"]
        .as_array_mut()
        .ok_or("observations")?
        .remove(0);
    state["aliases"]
        .as_array_mut()
        .ok_or("aliases")?
        .retain(|a| a["id"] != omitted);
    forged.state = serde_json::to_vec(&state)?;
    let fresh = event(0, 99, 20, false)?;
    let p = journal::prepare(
        &b,
        Some(&forged),
        5,
        Action::Admit {
            stream: b.config().sources[0].stream,
            position: 4,
            event: &fresh,
        },
        &ep,
        &context(),
    )?;
    assert!(matches!(p.commit(&db).await, Err(Error::Conflict)));
    assert_eq!(db.load(context()).await?, Some(previous.clone()));
    let seal = journal::prepare(
        &b,
        Some(&previous),
        4,
        Action::Seal,
        &journal_epoch(&b, Some(&previous), time(50), true)?,
        &context(),
    )?;
    let committed = seal.commit(&db).await?;
    assert_eq!(seal.reconcile(&db, context()).await?, committed);
    let original = committed.outbox[0].clone();
    assert!(matches!(
        journal::prepare(&b, Some(&committed), 5, Action::Seal, &ep, &context()),
        Err(Error::Pending)
    ));
    db.shutdown(context()).await?;
    let (db, ready) = Journal::begin_open(path, b.journal_config(), context())?;
    ready.wait().await?;
    let loaded = db.load(context()).await?.ok_or("loaded")?;
    assert_eq!(loaded, committed);
    assert_eq!(loaded.outbox[0], original);
    let retained = journal::recover(&b, &loaded, &context())?;
    assert_eq!(retained.episodes()[0].status, Status::Match);
    let published = db.retire(loaded.revision, 1, context()).await?;
    assert_eq!(
        journal::recover(&b, &published, &context())?.episodes()[0],
        retained.episodes()[0]
    );
    let mut cfg = config();
    cfg.revision = "new-policy".into();
    cfg.threshold = 4;
    let new = Binding::new(cfg, &context())?;
    assert!(journal::recover(&new, &published, &context()).is_err());
    let mut counterfactual = load(&new, &events, &[0, 1, 2, 3])?;
    counterfactual.seal(
        &new,
        &seal_epoch(&new, &counterfactual, time(50), true)?,
        &context(),
    )?;
    assert_eq!(counterfactual.episodes()[0].status, Status::NoMatch);
    db.shutdown(context()).await?;
    Ok(())
}

#[test]
fn newest_qualifying_burst_and_distinct_successes_have_stable_episode_identities() -> Result {
    let mut cfg = config();
    cfg.threshold = 2;
    cfg.window_ms = 10_000;
    cfg.correlation_ms = 20_000;
    cfg.lateness_ms = 0;
    cfg.ttl_ms = 190_000;
    let b = Binding::new(cfg, &context())?;
    let events = vec![
        event(0, 1, 0, false)?,
        event(0, 2, 1, false)?,
        event(0, 3, 20, false)?,
        event(0, 4, 22, false)?,
        event(1, 1, 30, true)?,
        event(1, 2, 31, true)?,
    ];
    let mut state = load(&b, &events, &[5, 0, 4, 1, 3, 2])?;
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
    assert_eq!(state.episodes().len(), 2);
    for e in state.episodes() {
        assert_eq!(e.status, Status::Match);
        assert_eq!(&e.event_ids[..2], &[events[2].id, events[3].id]);
    }
    assert_ne!(state.episodes()[0].id, state.episodes()[1].id);
    Ok(())
}
#[test]
fn exact_failure_window_and_one_nanosecond_outside_are_distinct() -> Result {
    let mut cfg = config();
    cfg.threshold = 2;
    cfg.window_ms = 1000;
    cfg.correlation_ms = 1000;
    cfg.lateness_ms = 0;
    cfg.ttl_ms = 5000;
    let b = Binding::new(cfg, &context())?;
    for outside in [false, true] {
        let mut first = event(0, 1, 1, false)?;
        if outside {
            first.timestamp -= chrono::TimeDelta::nanoseconds(1);
        }
        let events = vec![first, event(0, 2, 2, false)?, event(1, 1, 3, true)?];
        let mut state = load(&b, &events, &[2, 0, 1])?;
        state.seal(&b, &seal_epoch(&b, &state, time(4), true)?, &context())?;
        assert_eq!(
            state.episodes()[0].status,
            if outside {
                Status::NoMatch
            } else {
                Status::Match
            }
        );
    }
    Ok(())
}
#[test]
fn canonical_alias_capacity_is_finite_and_refuses_without_forgetting_identity() -> Result {
    let b = Binding::new(config(), &context())?;
    let ep = epoch(&b, time(100), true)?;
    let source = b.config().sources[0].stream;
    let first = event(0, 1, 1, false)?;
    let mut state = State::new(&b);
    state.admit(&b, source, 1, &first, &ep, &context())?;
    for n in 1..256 {
        let mut alias = first.clone();
        alias.id = Uuid::from_u128(10000 + n);
        assert_eq!(
            state.admit(&b, source, n as u64 + 1, &alias, &ep, &context())?,
            Admission::Duplicate
        );
    }
    let before = state.encode(&b, &context())?;
    let mut extra = first;
    extra.id = Uuid::from_u128(20000);
    assert!(matches!(
        state.admit(&b, source, 257, &extra, &ep, &context()),
        Err(Error::Capacity)
    ));
    assert_eq!(state.encode(&b, &context())?, before);
    Ok(())
}
#[test]
fn keys_episode_and_wire_byte_caps_refuse_atomically() -> Result {
    for cap in ["keys", "episodes", "bytes"] {
        let mut cfg = config();
        if cap == "keys" {
            cfg.max_keys = 1;
        }
        if cap == "episodes" {
            cfg.max_episodes = 1;
        }
        if cap == "bytes" {
            cfg.max_state_bytes = 4096;
        }
        let b = Binding::new(cfg, &context())?;
        let ep = epoch(&b, time(100), true)?;
        if cap == "episodes" {
            let events = vec![event(1, 1, 10, true)?, event(1, 2, 11, true)?];
            let mut state = load(&b, &events, &[0, 1])?;
            let before = state.encode(&b, &context())?;
            assert!(matches!(
                state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context()),
                Err(Error::Capacity)
            ));
            assert_eq!(state.encode(&b, &context())?, before);
        } else {
            let mut state = State::new(&b);
            if cap == "keys" {
                state.admit(
                    &b,
                    b.config().sources[0].stream,
                    1,
                    &event(0, 1, 1, false)?,
                    &ep,
                    &context(),
                )?;
            }
            let mut extra = event(0, 2, 2, false)?;
            if cap == "keys" {
                extra.attributes["authentication"]["target_id"] = serde_json::json!("other-target");
            } else {
                extra.message = Some("x".repeat(8000));
            }
            let before = state.encode(&b, &context())?;
            assert!(matches!(
                state.admit(
                    &b,
                    b.config().sources[0].stream,
                    if cap == "bytes" { 1 } else { 2 },
                    &extra,
                    &ep,
                    &context()
                ),
                Err(Error::Capacity)
            ));
            assert_eq!(state.encode(&b, &context())?, before);
        }
    }
    Ok(())
}
#[tokio::test]
async fn source_verification_lifetime_and_cancellation_bound_prepared_commit() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let b = Binding::new(config(), &context())?;
    let source = &b.config().sources[0];
    let mut proof = verification(source, time(100), true);
    proof.verified_at = proof.now + chrono::TimeDelta::seconds(1);
    assert!(matches!(
        Epoch::new(&b, vec![proof], &context()),
        Err(Error::Unverified)
    ));
    let mut proof = verification(source, time(100), true);
    proof.source_binding = [99; 32];
    assert!(Epoch::new(&b, vec![proof], &context()).is_err());
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let (db, ready) = Journal::begin_open(
        dir.path().join("state.sqlite"),
        b.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let event = event(0, 1, 1, false)?;
    for cancel in [false, true] {
        let authority = context();
        let proofs = b
            .config()
            .sources
            .iter()
            .map(|s| {
                let mut p = verification(s, time(100), true);
                p.verified_until = p.now + chrono::TimeDelta::milliseconds(80);
                p
            })
            .collect();
        let ep = Epoch::new(&b, proofs, &authority)?;
        let p = journal::prepare(
            &b,
            None,
            1,
            Action::Admit {
                stream: source.stream,
                position: 1,
                event: &event,
            },
            &ep,
            &context(),
        )?;
        if cancel {
            authority.cancellation.cancel();
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(matches!(p.commit(&db).await, Err(Error::Cancelled)));
        assert_eq!(db.load(context()).await?, None);
    }
    db.shutdown(context()).await?;
    Ok(())
}

fn publish_original(dir: &std::path::Path, output: &signal_rules::state_journal::Output) -> Result {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let path = dir.join(format!("published-{}", output.id));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&output.bytes)?;
            file.sync_all()?;
            std::fs::File::open(dir)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            assert!(std::fs::metadata(&path)?.len() <= 65536);
            assert_eq!(std::fs::read(&path)?, output.bytes);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
#[tokio::test]
#[ignore = "owned subprocess crash helper"]
async fn correlation_crash_child() -> Result {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let dir = std::path::PathBuf::from(
        std::env::var_os("CORRELATION_CHILD_DIR").ok_or("owned child directory")?,
    );
    let phase = std::env::var("CORRELATION_CHILD_PHASE")?;
    let b = Binding::new(config(), &context())?;
    let (db, ready) =
        Journal::begin_open(dir.join("episodes.sqlite"), b.journal_config(), context())?;
    ready.wait().await?;
    let events = inputs()?;
    let ep = epoch(&b, time(100), true)?;
    let mut previous = None;
    for (i, event) in events.iter().enumerate() {
        let source = if i < 3 { 0 } else { 1 };
        let position = if i < 3 { i as u64 + 1 } else { 1 };
        previous = Some(
            journal::prepare(
                &b,
                previous.as_ref(),
                i as u64 + 1,
                Action::Admit {
                    stream: b.config().sources[source].stream,
                    position,
                    event,
                },
                &ep,
                &context(),
            )?
            .commit(&db)
            .await?,
        );
    }
    let proposed = journal::prepare(
        &b,
        previous.as_ref(),
        4,
        Action::Seal,
        &journal_epoch(&b, previous.as_ref(), time(50), true)?,
        &context(),
    )?;
    let committed = proposed.commit(&db).await?;
    if phase == "published" {
        publish_original(&dir, &committed.outbox[0])?;
    } else {
        assert_eq!(phase, "committed");
    }
    let mut witness = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("ready.tmp"))?;
    witness.write_all(b"committed-source-ack-withheld")?;
    witness.sync_all()?;
    std::fs::rename(dir.join("ready.tmp"), dir.join("ready"))?;
    std::fs::File::open(&dir)?.sync_all()?;
    std::future::pending::<()>().await;
    println!("CORRELATION-SOURCE-ACK");
    Ok(())
}
struct OwnedCorrelationChild(std::process::Child);
impl Drop for OwnedCorrelationChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[tokio::test]
#[ignore = "requires explicitly owned target evidence directory"]
async fn correlation_process_crash() -> Result {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("root")?
        .join("target")
        .canonicalize()?;
    let output =
        std::path::PathBuf::from(std::env::var_os("CORRELATION_OUTPUT").ok_or("owned output")?)
            .canonicalize()?;
    assert!(output.starts_with(root));
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
    let began = Instant::now();
    let mut cases = Vec::new();
    for phase in ["committed", "published"] {
        let dir = output.join(phase);
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let b = Binding::new(config(), &context())?;
        let ep = epoch(&b, time(100), true)?;
        let events = inputs()?;
        let mut expected = None;
        for (i, event) in events.iter().enumerate() {
            let source = if i < 3 { 0 } else { 1 };
            let position = if i < 3 { i as u64 + 1 } else { 1 };
            expected = Some(
                journal::prepare(
                    &b,
                    expected.as_ref(),
                    i as u64 + 1,
                    Action::Admit {
                        stream: b.config().sources[source].stream,
                        position,
                        event,
                    },
                    &ep,
                    &context(),
                )?
                .record()
                .clone(),
            );
        }
        let expected = journal::prepare(
            &b,
            expected.as_ref(),
            4,
            Action::Seal,
            &journal_epoch(&b, expected.as_ref(), time(50), true)?,
            &context(),
        )?
        .record()
        .clone();
        let log = fs::File::create_new(dir.join("child.log"))?;
        let mut child = OwnedCorrelationChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "correlation_crash_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("CORRELATION_CHILD_DIR", &dir)
                .env("CORRELATION_CHILD_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let pid = child.0.id();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if fs::read(dir.join("ready")).ok().as_deref() == Some(b"committed-source-ack-withheld")
            {
                break;
            }
            if child.0.try_wait()?.is_some() {
                return Err("child exited before durable witness".into());
            }
            if Instant::now() >= deadline {
                return Err("owned child witness deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(child.0.try_wait()?.is_none());
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        assert!(fs::metadata(dir.join("child.log"))?.len() < 16384);
        assert!(!fs::read_to_string(dir.join("child.log"))?.contains("CORRELATION-SOURCE-ACK"));
        let (db, ready) =
            Journal::begin_open(dir.join("episodes.sqlite"), b.journal_config(), context())?;
        ready.wait().await?;
        let loaded = db.load(context()).await?.ok_or("committed original")?;
        assert_eq!(loaded, expected);
        let output_effect = loaded.outbox[0].clone();
        let episode: Episode = serde_json::from_slice(&output_effect.bytes)?;
        assert_eq!(episode.status, Status::Match);
        assert_eq!(episode.originals, events);
        assert_eq!(episode.contributors.len(), 2);
        publish_original(&dir, &output_effect)?;
        let drained = db.retire(loaded.revision, 1, context()).await?;
        let intervening = event(0, 99, 20, false)?;
        let intermediate = journal::prepare(
            &b,
            Some(&drained),
            5,
            Action::Admit {
                stream: b.config().sources[0].stream,
                position: 4,
                event: &intervening,
            },
            &ep,
            &context(),
        )?
        .commit(&db)
        .await?;
        let mut repeated = events[3].clone();
        repeated.id = Uuid::from_u128(99999);
        repeated.observed_at = time(550);
        let duplicate = journal::prepare(
            &b,
            Some(&intermediate),
            6,
            Action::Admit {
                stream: b.config().sources[1].stream,
                position: 2,
                event: &repeated,
            },
            &ep,
            &context(),
        )?;
        assert!(matches!(
            duplicate.applied(),
            journal::Applied::Admission(Admission::Duplicate)
        ));
        let after = duplicate.commit(&db).await?;
        assert!(after.outbox.is_empty());
        assert_eq!(after.checkpoint, 6);
        let retained = journal::recover(&b, &after, &context())?;
        assert_eq!(&retained.episodes()[0], &episode);
        assert_eq!(
            serde_json::to_vec(&retained.episodes()[0])?,
            output_effect.bytes
        );
        let mut cfg = config();
        cfg.revision = "fixture-new-policy".into();
        cfg.threshold = 4;
        let changed = Binding::new(cfg, &context())?;
        let mut counterfactual = load(&changed, &events, &[0, 1, 2, 3])?;
        counterfactual.seal(
            &changed,
            &seal_epoch(&changed, &counterfactual, time(50), true)?,
            &context(),
        )?;
        assert_eq!(counterfactual.episodes()[0].status, Status::NoMatch);
        assert!(journal::recover(&changed, &after, &context()).is_err());
        db.shutdown(context()).await?;
        let (db, ready) =
            Journal::begin_open(dir.join("episodes.sqlite"), b.journal_config(), context())?;
        ready.wait().await?;
        let reopened = db
            .load(context())
            .await?
            .ok_or("original after second reopen")?;
        assert_eq!(reopened, after);
        assert_eq!(
            journal::recover(&b, &reopened, &context())?.episodes()[0],
            episode
        );
        db.shutdown(context()).await?;
        let (wrong, ready) = Journal::begin_open(
            dir.join("episodes.sqlite"),
            changed.journal_config(),
            context(),
        )?;
        assert!(ready.wait().await.is_err());
        drop(wrong);
        cases.push(serde_json::json!({"phase":phase,"pid":pid,"actual_sigkill_signal":9,"source_ack_withheld":true,"original_commit_recovered":true,"new_policy_would_be":"no_match","original_output_returned":"match","published_before_retirement":true,"intervening_input_preserves_original":true,"native_duplicate_new_uuid_preserves_original":true,"checkpoint":6,"changed_enrollment_refused":true,"second_reopen_exact":true}));
    }
    fs::write(
        output.join("process-report.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version":1,"status":"passed_local","rule":"SIG-D11","cases":cases,"actual_sigkill":2,"owned_process_cleanup":true,"elapsed_seconds":began.elapsed().as_secs_f64()}),
        )?,
    )?;
    Ok(())
}

fn plus_ns(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    t + chrono::TimeDelta::nanoseconds(1)
}

#[test]
fn sealing_proofs_bind_exact_processed_prefix_and_persist_verifiable_watermarks() -> Result {
    let b = Binding::new(config(), &context())?;
    let ep = epoch(&b, time(100), true)?;
    let mut state = State::new(&b);
    let first = event(0, 1, 1, false)?;
    assert!(matches!(
        state.admit(&b, b.config().sources[0].stream, 2, &first, &ep, &context()),
        Err(Error::Conflict)
    ));
    state.admit(&b, b.config().sources[0].stream, 1, &first, &ep, &context())?;
    let before = state.encode(&b, &context())?;
    for wrong in [0, 2] {
        let proofs = b
            .config()
            .sources
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut p = verification(s, time(50), true);
                p.position = if i == 0 { wrong } else { 0 };
                p
            })
            .collect();
        let proof = Epoch::new(&b, proofs, &context())?;
        assert!(matches!(
            state.seal(&b, &proof, &context()),
            Err(Error::Conflict)
        ));
        assert_eq!(state.encode(&b, &context())?, before);
    }
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
    let bytes = state.encode(&b, &context())?;
    let restored = State::decode(&b, &bytes, &context())?;
    assert_eq!(restored.watermark(), Some(time(40)));
    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes)?;
    tampered["watermark"] = serde_json::to_value(time(41))?;
    assert!(State::decode(&b, &serde_json::to_vec(&tampered)?, &context()).is_err());
    tampered = serde_json::from_slice(&bytes)?;
    tampered["last_seal_evidence"][0]["position"] = serde_json::json!(2);
    assert!(State::decode(&b, &serde_json::to_vec(&tampered)?, &context()).is_err());
    Ok(())
}
#[tokio::test]
async fn empty_seal_never_advances_delivery_and_reopens_with_all_stream_proofs() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let b = Binding::new(config(), &context())?;
    let empty = State::new(&b);
    let proof = seal_epoch(&b, &empty, time(50), true)?;
    assert!(matches!(
        journal::prepare(&b, None, 100, Action::Seal, &proof, &context()),
        Err(Error::Conflict)
    ));
    let first = event(0, 1, 1, false)?;
    assert!(matches!(
        journal::prepare(
            &b,
            None,
            100,
            Action::Admit {
                stream: b.config().sources[0].stream,
                position: 1,
                event: &first
            },
            &epoch(&b, time(100), true)?,
            &context()
        ),
        Err(Error::Conflict)
    ));
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = dir.path().join("empty.sqlite");
    let (db, ready) = Journal::begin_open(path.clone(), b.journal_config(), context())?;
    ready.wait().await?;
    let record = journal::prepare(&b, None, 0, Action::Seal, &proof, &context())?
        .commit(&db)
        .await?;
    assert_eq!(record.checkpoint, 0);
    db.shutdown(context()).await?;
    let (db, ready) = Journal::begin_open(path, b.journal_config(), context())?;
    ready.wait().await?;
    let loaded = db.load(context()).await?.ok_or("empty sealed record")?;
    assert_eq!(loaded, record);
    assert_eq!(
        journal::recover(&b, &loaded, &context())?.watermark(),
        Some(time(40))
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&loaded.state)?["last_seal_evidence"]
            .as_array()
            .ok_or("proofs")?
            .len(),
        2
    );
    db.shutdown(context()).await?;
    Ok(())
}

use crate::intake_tests::{authority, intake, submission};
use crate::{
    format::{self, HistoryBinding, ProfileDefinition},
    tests::{TestResult, clock, fixture, prepared},
    *,
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use uuid::Uuid;

pub(crate) fn ctx() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
fn cfg(path: &Path) -> CoverageConfig {
    CoverageConfig {
        directory: path.into(),
        ..CoverageConfig::default()
    }
}
pub(crate) fn reports() -> TestResult<(PreparedObservation, PreparedObservation)> {
    let f = fixture()?;
    Ok((
        prepared(&f["chains"][0]["commits"][1], &f)?,
        prepared(&f["chains"][0]["commits"][2], &f)?,
    ))
}
pub(crate) fn linked(p: &PreparedObservation, target: Uuid) -> TestResult<CoverageSubmission> {
    Ok(CoverageSubmission::new(
        p.record_id(),
        &p.raw,
        Some(target),
    )?)
}
fn accepted(outcome: IntakeOutcome) -> TestResult<Receipt> {
    match outcome {
        IntakeOutcome::Accepted(r) => Ok(r),
        _ => Err("expected admission".into()),
    }
}
async fn seed(c: CoverageConfig, p: &PreparedObservation) -> TestResult<(CoverageStore, Receipt)> {
    let store =
        CoverageStore::initialize(c, Uuid::new_v4(), clock("2026-10-07T00:06:29Z")?).await?;
    let r = accepted(
        store
            .submit(submission(p)?, intake(p, "2026-10-07T00:06:30Z")?, ctx())
            .await?,
    )?;
    Ok((store, r))
}
fn variant(
    p: &PreparedObservation,
    change: impl FnOnce(&mut Value),
) -> TestResult<PreparedObservation> {
    let mut value: Value = serde_json::from_slice(&p.raw)?;
    value["record_id"] = json!(Uuid::new_v4());
    change(&mut value);
    let raw = serde_json::to_vec(&value)?;
    let (binding, _) = HistoryBinding::from_record(&raw)?;
    let f = fixture()?;
    let mut profile = f["profiles"][0]["input"].clone();
    profile["id"] = value["coverage_profile"]["id"].clone();
    profile["revision"] = value["coverage_profile"]["revision"].clone();
    Ok(PreparedObservation::prepare(
        &raw,
        ProfileDefinition::parse(&serde_json::to_vec(&profile)?)?,
        binding,
        AdmissionMetadata {
            authority_revision: "fixture-authority-v1".into(),
            accepted_at: clock("2026-10-07T00:12:00Z")?,
            replay_until: clock("2026-10-07T00:17:00Z")?,
            identity_until: clock("2026-10-07T00:22:00Z")?,
        },
    )?)
}
async fn original(store: &CoverageStore, p: &PreparedObservation, r: &Receipt) -> TestResult {
    let row = store
        .get_authorized(p.record_id(), authority(p)?, ctx())
        .await?
        .ok_or("original")?;
    assert_eq!(&row.receipt, r);
    assert_eq!(row.raw.as_deref(), Some(p.raw.as_slice()));
    Ok(())
}

#[tokio::test]
async fn correction_admission_matches_frozen_chain_and_preserves_failed_original() -> TestResult {
    let t = tempfile::tempdir()?;
    let f = fixture()?;
    let c = cfg(&t.path().join("coverage"));
    let store = CoverageStore::initialize(
        c.clone(),
        Uuid::parse_str(f["chains"][0]["history_id"].as_str().ok_or("history")?)?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let mut receipts = Vec::new();
    for v in f["chains"][0]["commits"].as_array().ok_or("chain")? {
        let p = prepared(v, &f)?;
        let target = v["input"]["correction_of"]
            .as_str()
            .map(Uuid::parse_str)
            .transpose()?;
        let r = accepted(
            store
                .submit(
                    CoverageSubmission::new(p.record_id(), &p.raw, target)?,
                    intake(&p, v["input"]["accepted_at"].as_str().ok_or("time")?)?,
                    ctx(),
                )
                .await?,
        )?;
        assert_eq!(r.prefix_digest, v["prefix_digest"]);
        assert_eq!(r.correction_of, target);
        receipts.push(r);
    }
    let (failed, correction) = reports()?;
    original(&store, &failed, &receipts[1]).await?;
    let r = receipts[2].clone();
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(
        store
            .retry(
                r.clone(),
                linked(&correction, failed.record_id())?,
                IntakeContext::new(
                    authority(&correction)?,
                    clock("2026-10-07T00:07:31Z")?,
                    None,
                    IntakePolicy::new(1, 0, 2, 2)?
                ),
                ctx()
            )
            .await?,
        IntakeOutcome::Replayed(r)
    );
    original(&store, &failed, &receipts[1]).await?;
    assert_eq!(store.metrics().committed_sequence, 3);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn correction_rejects_self_missing_and_not_yet_committed_targets() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    assert!(matches!(
        store
            .submit(
                linked(&correction, correction.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::InvalidCorrection("self reference"))
    ));
    let future = variant(&failed, |_| {})?;
    for target in [Uuid::new_v4(), future.record_id()] {
        assert!(matches!(
            store
                .submit(
                    linked(&correction, target)?,
                    intake(&correction, "2026-10-07T00:07:30Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::CorrectionTargetUnavailable)
        ));
    }
    assert_eq!(store.metrics().committed_sequence, 1);
    accepted(
        store
            .submit(
                submission(&future)?,
                intake(&future, "2026-10-07T00:06:31Z")?,
                ctx(),
            )
            .await?,
    )?;
    let r2 = accepted(
        store
            .submit(
                linked(&correction, future.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(r2.sequence, "3");
    original(&store, &failed, &r).await?;
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn correction_authorization_checks_all_ten_target_binding_dimensions() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    for path in [
        "/source_id",
        "/collector_id",
        "/resource_scope/kind",
        "/resource_scope/id",
        "/resource_scope/attributes",
        "/expected_stream",
        "/coverage_profile/id",
        "/coverage_profile/revision",
        "/collection_config_revision",
        "/provenance/observer_id",
    ] {
        let changed = variant(&correction, |v| {
            if let Some(slot) = v.pointer_mut(path) {
                *slot = if path.ends_with("attributes") {
                    json!({"team":"other"})
                } else {
                    json!("other")
                };
            }
        })?;
        assert!(
            matches!(
                store
                    .submit(
                        linked(&changed, failed.record_id())?,
                        intake(&changed, "2026-10-07T00:07:30Z")?,
                        ctx()
                    )
                    .await,
                Err(CoverageError::CorrectionBindingMismatch)
            ),
            "{path}"
        );
        assert_eq!(store.metrics().committed_sequence, 1);
    }
    original(&store, &failed, &r).await?;
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn correction_overlap_is_half_open_at_nanosecond_boundaries() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    for (start, end) in [
        ("2026-10-07T00:06:00Z", "2026-10-07T00:06:30Z"),
        ("2026-10-07T00:04:00Z", "2026-10-07T00:05:00Z"),
    ] {
        let p = variant(&correction, |v| {
            v["coverage_start"] = json!(start);
            v["coverage_end"] = json!(end);
        })?;
        assert!(matches!(
            store
                .submit(
                    linked(&p, failed.record_id())?,
                    intake(&p, "2026-10-07T00:07:30Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::InvalidCorrection("nonoverlapping interval"))
        ));
    }
    for (start, end) in [
        ("2026-10-07T00:05:59.999999999Z", "2026-10-07T00:06:30Z"),
        ("2026-10-07T00:04:00Z", "2026-10-07T00:05:00.000000001Z"),
    ] {
        let p = variant(&correction, |v| {
            v["coverage_start"] = json!(start);
            v["coverage_end"] = json!(end);
        })?;
        accepted(
            store
                .submit(
                    linked(&p, failed.record_id())?,
                    intake(&p, "2026-10-07T00:07:30Z")?,
                    ctx(),
                )
                .await?,
        )?;
    }
    assert_eq!(store.metrics().committed_sequence, 3);
    original(&store, &failed, &r).await?;
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn correction_verification_must_be_strictly_later_without_rounding() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    for time in [
        "2026-10-07T00:05:59.999999999Z",
        "2026-10-07T00:06:00Z",
        "2026-10-07T00:06:00.000000001Z",
    ] {
        let p = variant(&correction, |v| {
            v["coverage_end"] = json!("2026-10-07T00:05:59Z");
            v["last_verified_at"] = json!(time);
            v["valid_until"] = json!("2026-10-07T00:06:59Z");
            v["provenance"]["observed_at"] = json!("2026-10-07T00:06:00.000000001Z");
        })?;
        let result = store
            .submit(
                linked(&p, failed.record_id())?,
                intake(&p, "2026-10-07T00:06:30Z")?,
                ctx(),
            )
            .await;
        if time.ends_with("000000001Z") {
            accepted(result?)?;
        } else {
            assert!(matches!(
                result,
                Err(CoverageError::InvalidCorrection(
                    "verification is not later"
                ))
            ));
        }
    }
    assert_eq!(store.metrics().committed_sequence, 2);
    original(&store, &failed, &r).await?;
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn expired_target_still_accepts_late_backfill_if_original_evidence_remains() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    let late = variant(&correction, |v| {
        v["last_verified_at"] = json!("2026-10-07T00:11:30Z");
        v["valid_until"] = json!("2026-10-07T00:12:30Z");
        v["provenance"]["observed_at"] = json!("2026-10-07T00:11:30Z");
    })?;
    let r2 = accepted(
        store
            .submit(
                linked(&late, failed.record_id())?,
                intake(&late, "2026-10-07T00:11:31Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(r2.correction_of, Some(failed.record_id()));
    original(&store, &failed, &r).await?;
    assert_eq!(r.replay_until, "2026-10-07T00:11:30.000000000Z");
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn full_quota_preserves_original_and_allows_exact_correction_replay() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 2;
    c.max_identities = 2;
    c.max_bindings = 1;
    let (store, r) = seed(c, &failed).await?;
    let r2 = accepted(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    let next = variant(&correction, |_| {})?;
    assert!(matches!(
        store
            .submit(
                linked(&next, failed.record_id())?,
                intake(&next, "2026-10-07T00:07:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::Quota)
    ));
    assert_eq!(
        store
            .retry(
                r2.clone(),
                linked(&correction, failed.record_id())?,
                IntakeContext::new(
                    authority(&correction)?,
                    clock("2026-10-07T00:07:31Z")?,
                    None,
                    IntakePolicy::new(1, 0, 2, 2)?
                ),
                ctx()
            )
            .await?,
        IntakeOutcome::Replayed(r2)
    );
    for target in [None, Some(Uuid::new_v4())] {
        assert!(matches!(
            store
                .submit(
                    CoverageSubmission::new(correction.record_id(), &correction.raw, target)?,
                    intake(&correction, "2026-10-07T00:07:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::IdContentConflict)
        ));
    }
    original(&store, &failed, &r).await?;
    assert_eq!(store.metrics().committed_sequence, 2);
    assert_eq!(store.metrics().replayed, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_identical_corrections_commit_one_immutable_link() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    let (a, b) = tokio::join!(
        store.submit(
            linked(&correction, failed.record_id())?,
            intake(&correction, "2026-10-07T00:07:30Z")?,
            ctx()
        ),
        store.submit(
            linked(&correction, failed.record_id())?,
            intake(&correction, "2026-10-07T00:07:30Z")?,
            ctx()
        )
    );
    let (new, replay) = match (a?, b?) {
        (IntakeOutcome::Accepted(n), IntakeOutcome::Replayed(r))
        | (IntakeOutcome::Replayed(r), IntakeOutcome::Accepted(n)) => (n, r),
        _ => return Err("concurrent correction results".into()),
    };
    assert_eq!(new, replay);
    assert_eq!(new.correction_of, Some(failed.record_id()));
    assert_eq!(store.metrics().committed_sequence, 2);
    original(&store, &failed, &r).await?;
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn corrupted_target_fails_closed_before_correction_commit() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, _) = seed(c.clone(), &failed).await?;
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    db.execute(
        "UPDATE entries SET raw=?1 WHERE record_id=?2",
        rusqlite::params![b"changed".as_slice(), failed.record_id().as_bytes()],
    )?;
    db.close().map_err(|(_, e)| e)?;
    assert!(matches!(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::Corrupt(_))
    ));
    assert!(!store.metrics().available);
    assert_eq!(store.metrics().committed_sequence, 1);
    assert!(matches!(
        store.shutdown(ctx()).await,
        Err(CoverageError::Unavailable)
    ));
    assert!(matches!(
        CoverageStore::open(c).await,
        Err(CoverageError::Corrupt(_))
    ));
    Ok(())
}

// Construct a future-compatible persisted fixture, not a pruning implementation/test.
fn pruned_fixture(c: &CoverageConfig, target: &PreparedObservation, r: &Receipt) -> TestResult {
    let mut db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let bytes: Vec<u8> = db.query_row("SELECT data FROM state WHERE id=1", [], |row| row.get(0))?;
    let mut state = format::State::decode(&bytes)?;
    state.payload_pruned_through = r.sequence.parse()?;
    let prefix = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&r.prefix_digest[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    state.payload_anchor = prefix.try_into().map_err(|_| "prefix")?;
    state.payload_count -= 1;
    state.ledger_charge -= target.raw.len() as u64 + 256;
    state.clock_floor = clock("2026-10-07T00:11:30Z")?;
    let bytes = state.encode()?;
    let tx = db.transaction()?;
    tx.execute(
        "UPDATE entries SET raw=NULL WHERE record_id=?1",
        [target.record_id().as_bytes()],
    )?;
    tx.execute(
        "UPDATE state SET data=?1,checksum=?2 WHERE id=1",
        rusqlite::params![&bytes, format::sha256(&bytes).as_slice()],
    )?;
    tx.commit()?;
    db.close().map_err(|(_, e)| e)?;
    Ok(())
}

#[tokio::test]
async fn unavailable_original_payload_rejects_new_link_but_keeps_admitted_replay() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, r) = seed(c.clone(), &failed).await?;
    let r2 = accepted(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    store.shutdown(ctx()).await?;
    pruned_fixture(&c, &failed, &r)?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(
        store
            .retry(
                r2.clone(),
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:11:31Z")?,
                ctx()
            )
            .await?,
        IntakeOutcome::Replayed(r2)
    );
    let next = variant(&correction, |v| {
        v["last_verified_at"] = json!("2026-10-07T00:11:30Z");
        v["valid_until"] = json!("2026-10-07T00:12:30Z");
        v["provenance"]["observed_at"] = json!("2026-10-07T00:11:30Z");
    })?;
    assert!(matches!(
        store
            .submit(
                linked(&next, failed.record_id())?,
                intake(&next, "2026-10-07T00:11:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::CorrectionTargetUnavailable)
    ));
    let old = store
        .get_authorized(failed.record_id(), authority(&failed)?, ctx())
        .await?
        .ok_or("retained identity")?;
    assert_eq!(old.receipt, r);
    assert!(old.raw.is_none());
    assert_eq!(store.metrics().committed_sequence, 2);
    // Only the direct target is required; its pruned parent must not be traversed.
    let r3 = accepted(
        store
            .submit(
                linked(&next, correction.record_id())?,
                intake(&next, "2026-10-07T00:11:31Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(r3.correction_of, Some(correction.record_id()));
    assert_eq!(r3.sequence, "3");
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn correction_of_correction_is_one_hop_and_keeps_every_original() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let (store, r) = seed(cfg(&t.path().join("coverage")), &failed).await?;
    let r2 = accepted(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    let next = variant(&correction, |v| {
        v["last_verified_at"] = json!("2026-10-07T00:08:00Z");
        v["valid_until"] = json!("2026-10-07T00:09:00Z");
        v["provenance"]["observed_at"] = json!("2026-10-07T00:08:00Z");
    })?;
    let r3 = accepted(
        store
            .submit(
                linked(&next, correction.record_id())?,
                intake(&next, "2026-10-07T00:08:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(r3.correction_of, Some(correction.record_id()));
    assert_eq!(r3.sequence, "3");
    original(&store, &failed, &r).await?;
    original(&store, &correction, &r2).await?;
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn committed_correction_link_is_bound_to_its_prefix() -> TestResult {
    let t = tempfile::tempdir()?;
    let (failed, correction) = reports()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, _) = seed(c.clone(), &failed).await?;
    accepted(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let bytes: Vec<u8> = db.query_row(
        "SELECT metadata FROM entries WHERE record_id=?1",
        [correction.record_id().as_bytes()],
        |r| r.get(0),
    )?;
    let mut metadata = format::CommitMetadata::decode(&bytes)?;
    assert_eq!(metadata.correction_of, Some(failed.record_id()));
    metadata.correction_of = None;
    db.execute(
        "UPDATE entries SET metadata=?1 WHERE record_id=?2",
        rusqlite::params![metadata.encode()?, correction.record_id().as_bytes()],
    )?;
    db.close().map_err(|(_, e)| e)?;
    assert!(matches!(
        store
            .get_authorized(correction.record_id(), authority(&correction)?, ctx())
            .await,
        Err(CoverageError::Corrupt(_))
    ));
    assert!(!store.metrics().available);
    assert!(matches!(
        store.shutdown(ctx()).await,
        Err(CoverageError::Unavailable)
    ));
    assert!(matches!(
        CoverageStore::open(c).await,
        Err(CoverageError::Corrupt(_))
    ));
    Ok(())
}

#[tokio::test]
async fn correction_process_loss_recovers_only_complete_atomic_links() -> TestResult {
    if let Ok(path) = std::env::var("SIGNAL_COVERAGE_CORRECTION_ROOT") {
        let (failed, correction) = reports()?;
        let (store, _) = seed(cfg(Path::new(&path)), &failed).await?;
        accepted(
            store
                .submit(
                    linked(&correction, failed.record_id())?,
                    intake(&correction, "2026-10-07T00:07:30Z")?,
                    ctx(),
                )
                .await?,
        )?;
        store.shutdown(ctx()).await?;
        return Ok(());
    }
    use std::{
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
    };
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (failed, correction) = reports()?;
    for stage in ["after_entry", "before_commit", "after_commit"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "correction_tests::correction_process_loss_recovers_only_complete_atomic_links",
                    "--nocapture",
                ])
                .env("SIGNAL_COVERAGE_CORRECTION_ROOT", &c.directory)
                .env("SIGNAL_COVERAGE_TEST_CHECKPOINT", stage)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let stdout = child.0.stdout.take().ok_or("stdout")?;
        let (ready, wait) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let found = BufReader::new(stdout)
                .lines()
                .any(|l| l.ok().as_deref() == Some("COVERAGE-CHECKPOINT"));
            let _ = ready.send(found);
        });
        let reached = wait.recv_timeout(Duration::from_secs(10));
        if !matches!(reached, Ok(true)) {
            child.0.kill()?;
            child.0.wait()?;
            reader.join().map_err(|_| "reader")?;
            return Err("checkpoint missing".into());
        }
        reader.join().map_err(|_| "reader")?;
        assert!(matches!(
            CoverageStore::open(c.clone()).await,
            Err(CoverageError::Locked)
        ));
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let store = CoverageStore::open(c).await?;
        let old = store
            .get_authorized(failed.record_id(), authority(&failed)?, ctx())
            .await?
            .ok_or("original")?;
        assert_eq!(old.raw, Some(failed.raw.clone()));
        assert_eq!(old.receipt.sequence, "1");
        assert_eq!(old.receipt.correction_of, None);
        let row = store
            .get_authorized(correction.record_id(), authority(&correction)?, ctx())
            .await?;
        if stage == "after_commit" {
            let row = row.ok_or("lost response correction")?;
            assert_eq!(row.raw, Some(correction.raw.clone()));
            assert_eq!(row.receipt.sequence, "2");
            assert_eq!(row.receipt.correction_of, Some(failed.record_id()));
            assert_eq!(row.receipt.accepted_at, "2026-10-07T00:07:30.000000000Z");
            assert_eq!(row.receipt.replay_until, "2026-10-07T00:12:30.000000000Z");
            assert_eq!(
                store
                    .submit(
                        linked(&correction, failed.record_id())?,
                        intake(&correction, "2026-10-07T00:07:31Z")?,
                        ctx()
                    )
                    .await?,
                IntakeOutcome::Replayed(row.receipt)
            );
            assert_eq!(store.metrics().committed_sequence, 2);
        } else {
            assert!(row.is_none());
            assert_eq!(store.metrics().committed_sequence, 1);
        }
        store.shutdown(ctx()).await?;
    }
    Ok(())
}

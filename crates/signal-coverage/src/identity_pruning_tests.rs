use crate::{
    correction_tests::{ctx, linked, reports},
    format::{self, HistoryBinding, ProfileDefinition, State},
    intake_tests::{authority, intake, submission},
    tests::{TestResult, clock, fixture, prepared},
    *,
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use uuid::Uuid;

fn cfg(path: &Path) -> CoverageConfig {
    CoverageConfig {
        directory: path.into(),
        ..CoverageConfig::default()
    }
}
fn sample() -> TestResult<PreparedObservation> {
    let f = fixture()?;
    prepared(&f["chains"][0]["commits"][0], &f)
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
        p.admission.clone(),
    )?)
}
fn deadlines(
    mut p: PreparedObservation,
    admitted: &str,
    replay: &str,
    identity: &str,
) -> TestResult<PreparedObservation> {
    p.admission.accepted_at = clock(admitted)?;
    p.admission.replay_until = clock(replay)?;
    p.admission.identity_until = clock(identity)?;
    Ok(p)
}
fn accepted(outcome: IntakeOutcome) -> TestResult<Receipt> {
    match outcome {
        IntakeOutcome::Accepted(r) => Ok(r),
        _ => Err("expected admission".into()),
    }
}
fn state(c: &CoverageConfig) -> TestResult<State> {
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let bytes: Vec<u8> = db.query_row("SELECT data FROM state WHERE id=1", [], |r| r.get(0))?;
    let state = State::decode(&bytes)?;
    db.close().map_err(|(_, e)| e)?;
    Ok(state)
}
fn persist_state(db: &rusqlite::Connection, state: &State) -> TestResult {
    let bytes = state.encode()?;
    db.execute(
        "UPDATE state SET data=?1,checksum=?2 WHERE id=1",
        rusqlite::params![&bytes, format::sha256(&bytes).as_slice()],
    )?;
    Ok(())
}
fn metadata(c: &CoverageConfig, p: &PreparedObservation) -> TestResult<Vec<u8>> {
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let bytes = db.query_row(
        "SELECT metadata FROM entries WHERE record_id=?1",
        [p.record_id().as_bytes()],
        |r| r.get(0),
    )?;
    db.close().map_err(|(_, e)| e)?;
    Ok(bytes)
}
async fn chain(
    c: CoverageConfig,
) -> TestResult<(CoverageStore, Vec<PreparedObservation>, Vec<Receipt>)> {
    let f = fixture()?;
    let store = CoverageStore::initialize(
        c,
        Uuid::parse_str(f["chains"][0]["history_id"].as_str().ok_or("history")?)?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let mut observations = Vec::new();
    let mut receipts = Vec::new();
    for item in f["chains"][0]["commits"].as_array().ok_or("commits")? {
        let p = prepared(item, &f)?;
        let target = item["input"]["correction_of"]
            .as_str()
            .map(Uuid::parse_str)
            .transpose()?;
        let r = accepted(
            store
                .submit(
                    CoverageSubmission::new(p.record_id(), &p.raw, target)?,
                    intake(&p, item["input"]["accepted_at"].as_str().ok_or("time")?)?,
                    ctx(),
                )
                .await?,
        )?;
        assert_eq!(r.prefix_digest, item["prefix_digest"]);
        observations.push(p);
        receipts.push(r);
    }
    Ok((store, observations, receipts))
}
async fn prune_raw(store: &CoverageStore, now: &str, records: u64) -> TestResult {
    store
        .prune_payloads(
            clock(now)?,
            PayloadPruneBudget {
                max_records: records,
                max_raw_bytes: records * 65536,
            },
            ctx(),
        )
        .await?;
    Ok(())
}

fn budget(max_records: u64, max_metadata_bytes: u64) -> IdentityPruneBudget {
    IdentityPruneBudget {
        max_records,
        max_metadata_bytes,
    }
}
async fn initialize(c: CoverageConfig) -> TestResult<CoverageStore> {
    Ok(CoverageStore::initialize(c, Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?).await?)
}

#[tokio::test]
async fn identity_deadline_equality_preserves_frozen_tail_payload_anchor_and_surviving_receipt()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, observations, receipts) = chain(c.clone()).await?;
    prune_raw(&store, "2026-10-07T00:12:30Z", 3).await?;
    let before = state(&c)?;
    let no_op = store
        .prune_identities(
            clock("2026-10-07T00:15:29.999999999Z")?,
            budget(3, 3 * 73728),
            ctx(),
        )
        .await?;
    assert_eq!(no_op.pruned_records, 0);
    assert_eq!(state(&c)?.encode()?, before.encode()?);
    let first_bytes = metadata(&c, &observations[0])?.len() as u64;
    let first = store
        .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(3, 3 * 73728), ctx())
        .await?;
    assert_eq!(first.pruned_records, 1);
    assert_eq!(first.pruned_metadata_bytes, first_bytes);
    assert_eq!(first.reclaimed_ledger_bytes, first_bytes + 8192);
    assert_eq!(first.identity_pruned_through, 1);
    assert!(
        store
            .load(observations[0].record_id(), ctx())
            .await?
            .is_none()
    );
    let second = store
        .prune_identities(clock("2026-10-07T00:16:30Z")?, budget(3, 3 * 73728), ctx())
        .await?;
    assert_eq!(second.pruned_records, 1);
    assert_eq!(second.identity_pruned_through, 2);
    let s = state(&c)?;
    assert_eq!(format::hex(&s.identity_anchor), receipts[1].prefix_digest);
    assert_eq!(s.committed_prefix, before.committed_prefix);
    assert_eq!(s.payload_anchor, before.payload_anchor);
    assert_eq!(s.payload_pruned_through, 3);
    assert_eq!(s.payload_count, 0);
    assert_eq!(s.identity_count, 1);
    let remaining = store
        .get_authorized(
            observations[2].record_id(),
            authority(&observations[2])?,
            ctx(),
        )
        .await?
        .ok_or("correction survives")?;
    assert_eq!(remaining.receipt, receipts[2]);
    assert_eq!(
        remaining.receipt.correction_of,
        Some(observations[1].record_id())
    );
    assert!(remaining.raw.is_none());
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(
        store
            .load(observations[2].record_id(), ctx())
            .await?
            .ok_or("remaining")?
            .receipt,
        receipts[2]
    );
    assert!(
        store
            .load(observations[1].record_id(), ctx())
            .await?
            .is_none()
    );
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn global_oldest_identity_time_or_retained_payload_blocks_younger_rows() -> TestResult {
    for blocker in ["deadline", "payload"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let store = initialize(c.clone()).await?;
        let oldest = deadlines(
            sample()?,
            "2026-10-07T00:05:30Z",
            "2026-10-07T00:10:30Z",
            if blocker == "deadline" {
                "2026-10-07T00:25:30Z"
            } else {
                "2026-10-07T00:10:30Z"
            },
        )?;
        let later = deadlines(
            variant(&oldest, |v| {
                v["collector_id"] = json!("another-fixture-collector")
            })?,
            "2026-10-07T00:05:31Z",
            "2026-10-07T00:10:31Z",
            "2026-10-07T00:11:31Z",
        )?;
        store.append(oldest.clone(), ctx()).await?;
        store.append(later.clone(), ctx()).await?;
        if blocker == "deadline" {
            prune_raw(&store, "2026-10-07T00:10:31Z", 2).await?;
        }
        let before = state(&c)?.encode()?;
        let result = store
            .prune_identities(clock("2026-10-07T00:12:00Z")?, budget(2, 2 * 73728), ctx())
            .await?;
        assert_eq!(result.pruned_records, 0, "{blocker}");
        assert_eq!(result.identity_pruned_through, 0);
        assert_eq!(result.reclaimed_ledger_bytes, 0);
        assert_eq!(result.pruned_metadata_bytes, 0);
        assert_eq!(state(&c)?.encode()?, before);
        assert!(store.load(oldest.record_id(), ctx()).await?.is_some());
        assert!(store.load(later.record_id(), ctx()).await?.is_some());
        if blocker == "payload" {
            prune_raw(&store, "2026-10-07T00:12:00Z", 2).await?;
        }
        let result = store
            .prune_identities(clock("2026-10-07T00:25:30Z")?, budget(2, 2 * 73728), ctx())
            .await?;
        assert_eq!(result.pruned_records, 2);
        assert_eq!(state(&c)?.identity_count, 0);
        store.shutdown(ctx()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn metadata_and_record_budgets_do_not_skip_oversized_oldest_identity() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store = initialize(c.clone()).await?;
    let mut oldest = sample()?;
    oldest.admission.authority_revision = "a".repeat(1000);
    let mut later = variant(&oldest, |_| {})?;
    later.admission.authority_revision = "fixture-authority-v1".into();
    let third = variant(&later, |_| {})?;
    for p in [&oldest, &later, &third] {
        store.append(p.clone(), ctx()).await?;
    }
    let oldest_bytes = metadata(&c, &oldest)?.len() as u64;
    let later_bytes = metadata(&c, &later)?.len() as u64;
    assert!(oldest_bytes > later_bytes);
    prune_raw(&store, "2026-10-07T00:10:30Z", 3).await?;
    let before = state(&c)?.encode()?;
    let result = store
        .prune_identities(
            clock("2026-10-07T00:15:30Z")?,
            budget(3, later_bytes),
            ctx(),
        )
        .await?;
    assert_eq!(result.pruned_records, 0);
    assert_eq!(state(&c)?.encode()?, before);
    let result = store
        .prune_identities(
            clock("2026-10-07T00:15:30Z")?,
            budget(3, oldest_bytes),
            ctx(),
        )
        .await?;
    assert_eq!(result.pruned_records, 1);
    assert_eq!(result.pruned_metadata_bytes, oldest_bytes);
    let result = store
        .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(1, 3 * 73728), ctx())
        .await?;
    assert_eq!(result.pruned_records, 1);
    assert_eq!(result.identity_pruned_through, 2);
    assert!(store.load(third.record_id(), ctx()).await?.is_some());
    let third_bytes = metadata(&c, &third)?.len() as u64;
    let result = store
        .prune_identities(
            clock("2026-10-07T00:15:30Z")?,
            budget(3, third_bytes - 1),
            ctx(),
        )
        .await?;
    assert_eq!(result.pruned_records, 0);
    let result = store
        .prune_identities(
            clock("2026-10-07T00:15:30Z")?,
            budget(3, third_bytes),
            ctx(),
        )
        .await?;
    assert_eq!(result.pruned_records, 1);
    assert_eq!(result.pruned_metadata_bytes, third_bytes);
    assert_eq!(state(&c)?.ledger_charge, format::ROOT_CHARGE);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn shared_registry_pins_survive_until_last_reference_and_charges_are_reclaimed_exactly()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store = initialize(c.clone()).await?;
    let first = sample()?;
    let second = variant(&first, |_| {})?;
    let third = variant(&first, |v| {
        v["collector_id"] = json!("another-fixture-collector")
    })?;
    let fourth = variant(&first, |v| {
        v["coverage_profile"]["id"] = json!("another-fixture-profile")
    })?;
    let observations = [first, second, third, fourth];
    for p in &observations {
        store.append(p.clone(), ctx()).await?;
    }
    let metadata_sizes = observations
        .iter()
        .map(|p| Ok(metadata(&c, p)?.len() as u64))
        .collect::<TestResult<Vec<_>>>()?;
    prune_raw(&store, "2026-10-07T00:10:30Z", 4).await?;
    let pins = [(3, 2), (2, 2), (1, 1), (0, 0)];
    for (i, p) in observations.iter().enumerate() {
        let before = state(&c)?;
        let result = store
            .prune_identities(
                clock("2026-10-07T00:15:30Z")?,
                budget(1, metadata_sizes[i]),
                ctx(),
            )
            .await?;
        let extra = match i {
            0 => 0,
            1 => p.binding.encoded().len() as u64 + 4096,
            2 | 3 => {
                p.binding.encoded().len() as u64 + 4096 + p.profile.encoded().len() as u64 + 4096
            }
            _ => return Err("pin case".into()),
        };
        let reclaimed = metadata_sizes[i] + 8192 + extra;
        assert_eq!(result.pruned_records, 1);
        assert_eq!(result.reclaimed_ledger_bytes, reclaimed);
        let after = state(&c)?;
        assert_eq!(before.ledger_charge - after.ledger_charge, reclaimed);
        assert_eq!((after.binding_count, after.profile_count), pins[i]);
        assert_eq!(after.identity_count, 3 - i as u64);
        for remaining in &observations[i + 1..] {
            let row = store
                .get_authorized(remaining.record_id(), authority(remaining)?, ctx())
                .await?
                .ok_or("shared pin survivor")?;
            assert_eq!(row.binding.encoded(), remaining.binding.encoded());
            assert_eq!(row.profile.encoded(), remaining.profile.encoded());
        }
    }
    assert_eq!(state(&c)?.ledger_charge, format::ROOT_CHARGE);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn all_pruned_restart_keeps_uuid_and_tail_and_reopens_identity_binding_quota() -> TestResult {
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 1;
    c.max_identities = 1;
    c.max_bindings = 1;
    let store = initialize(c.clone()).await?;
    let p = sample()?;
    let original = store.append(p.clone(), ctx()).await?;
    prune_raw(&store, "2026-10-07T00:10:30Z", 1).await?;
    let rejected = deadlines(
        variant(&p, |v| {
            v["coverage_profile"]["id"] = json!("new-fixture-profile")
        })?,
        "2026-10-07T00:15:30Z",
        "2026-10-07T00:20:30Z",
        "2026-10-07T00:25:30Z",
    )?;
    assert!(matches!(
        store.append(rejected.clone(), ctx()).await,
        Err(CoverageError::Quota)
    ));
    store
        .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(1, 73728), ctx())
        .await?;
    let pruned = state(&c)?;
    assert_eq!(pruned.history_id, original.history_id);
    assert_eq!(pruned.committed_sequence, 1);
    assert_eq!(pruned.identity_anchor, pruned.committed_prefix);
    assert_eq!(pruned.payload_anchor, pruned.committed_prefix);
    assert_eq!(pruned.ledger_charge, format::ROOT_CHARGE);
    assert_eq!(
        (
            pruned.identity_count,
            pruned.binding_count,
            pruned.profile_count
        ),
        (0, 0, 0)
    );
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c.clone()).await?;
    assert_eq!(state(&c)?.encode()?, pruned.encode()?);
    let appended = store.append(rejected, ctx()).await?;
    assert_eq!(appended.sequence, "2");
    assert_eq!(appended.history_id, original.history_id);
    assert_ne!(appended.prefix_digest, original.prefix_digest);
    assert_eq!(store.metrics().identities, 1);
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(store.metrics().committed_sequence, 2);
    assert_eq!(store.metrics().history_id, original.history_id);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn stale_receipts_require_current_grant_and_matching_history_before_identity_pruned()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, observations, receipts) = chain(c.clone()).await?;
    prune_raw(&store, "2026-10-07T00:12:30Z", 3).await?;
    store
        .prune_identities(clock("2026-10-07T00:16:30Z")?, budget(2, 2 * 73728), ctx())
        .await?;
    let before = state(&c)?.encode()?;
    for (p, r) in observations[..2].iter().zip(&receipts[..2]) {
        assert!(matches!(
            store
                .retry(
                    r.clone(),
                    submission(p)?,
                    intake(p, "2026-10-07T00:16:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::IdentityPruned)
        ));
        let wrong_grant = variant(p, |v| {
            v["collector_id"] = json!("unauthorized-fixture-collector")
        })?;
        assert!(matches!(
            store
                .retry(
                    r.clone(),
                    submission(p)?,
                    intake(&wrong_grant, "2026-10-07T00:16:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::NotAuthorized)
        ));
        let mut wrong_history = r.clone();
        wrong_history.history_id = Uuid::new_v4();
        assert!(matches!(
            store
                .retry(
                    wrong_history,
                    submission(p)?,
                    intake(p, "2026-10-07T00:16:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::HistoryUnavailable)
        ));
        let mut future = r.clone();
        future.sequence = "4".into();
        assert!(matches!(
            store
                .retry(
                    future,
                    submission(p)?,
                    intake(p, "2026-10-07T00:16:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::HistoryUnavailable)
        ));
    }
    let mut changed_marker_prefix = receipts[1].clone();
    changed_marker_prefix.prefix_digest = "00".repeat(32);
    assert!(matches!(
        store
            .retry(
                changed_marker_prefix,
                submission(&observations[1])?,
                intake(&observations[1], "2026-10-07T00:16:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::ReceiptMismatch)
    ));
    // Below the retained anchor, the result describes unavailability and cannot authenticate deleted history.
    let mut changed_older_prefix = receipts[0].clone();
    changed_older_prefix.prefix_digest = "00".repeat(32);
    assert!(matches!(
        store
            .retry(
                changed_older_prefix,
                submission(&observations[0])?,
                intake(&observations[0], "2026-10-07T00:16:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::IdentityPruned)
    ));
    assert_eq!(state(&c)?.encode()?, before);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn unknown_bare_id_has_no_lifetime_deduplication_after_identity_pruning() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store = initialize(c.clone()).await?;
    let p = sample()?;
    let original = accepted(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    prune_raw(&store, "2026-10-07T00:10:30Z", 1).await?;
    store
        .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(1, 73728), ctx())
        .await?;
    assert!(
        store
            .get_authorized(p.record_id(), authority(&p)?, ctx())
            .await?
            .is_none()
    );
    // Old report age still prevents unchanged deleted bytes from becoming fresh evidence.
    assert!(matches!(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:16:00Z")?, ctx())
            .await,
        Err(CoverageError::ReportTooOld)
    ));
    let template = deadlines(
        p.clone(),
        "2026-10-07T00:16:00Z",
        "2026-10-07T00:21:00Z",
        "2026-10-07T00:26:00Z",
    )?;
    let reused = variant(&template, |v| {
        v["record_id"] = json!(p.record_id());
        v["last_verified_at"] = json!("2026-10-07T00:16:00Z");
        v["valid_until"] = json!("2026-10-07T00:17:00Z");
        v["provenance"]["observed_at"] = json!("2026-10-07T00:16:00Z");
    })?;
    let new_receipt = accepted(
        store
            .submit(
                submission(&reused)?,
                intake(&reused, "2026-10-07T00:16:00Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(new_receipt.record_id, original.record_id);
    assert_eq!(new_receipt.sequence, "2");
    assert_ne!(new_receipt.content_sha256, original.content_sha256);
    assert!(matches!(
        store
            .retry(
                original,
                submission(&p)?,
                intake(&p, "2026-10-07T00:16:01Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::IdentityPruned)
    ));
    assert_eq!(
        store
            .load(p.record_id(), ctx())
            .await?
            .ok_or("new identity")?
            .receipt,
        new_receipt
    );
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn correction_replays_after_its_target_identity_is_deleted() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let (failed, correction) = reports()?;
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:06:29Z")?)
            .await?;
    let shorter_identity = IntakeContext::new(
        authority(&failed)?,
        clock("2026-10-07T00:06:30Z")?,
        Some(failed.profile.clone()),
        IntakePolicy::new(60, 2, 300, 300)?,
    );
    let target_receipt = accepted(
        store
            .submit(submission(&failed)?, shorter_identity, ctx())
            .await?,
    )?;
    let correction_receipt = accepted(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    prune_raw(&store, "2026-10-07T00:11:30Z", 2).await?;
    let result = store
        .prune_identities(clock("2026-10-07T00:11:30Z")?, budget(2, 2 * 73728), ctx())
        .await?;
    assert_eq!(result.pruned_records, 1);
    assert!(store.load(failed.record_id(), ctx()).await?.is_none());
    let survivor = store
        .load(correction.record_id(), ctx())
        .await?
        .ok_or("correction")?;
    assert_eq!(survivor.raw.as_deref(), Some(correction.raw.as_slice()));
    assert_eq!(survivor.receipt, correction_receipt);
    assert_eq!(survivor.receipt.correction_of, Some(failed.record_id()));
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(
        store
            .retry(
                correction_receipt.clone(),
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:11:31Z")?,
                ctx()
            )
            .await?,
        IntakeOutcome::Replayed(correction_receipt)
    );
    assert!(matches!(
        store
            .retry(
                target_receipt,
                submission(&failed)?,
                intake(&failed, "2026-10-07T00:11:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::IdentityPruned)
    ));
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn invalid_identity_budgets_and_unordered_receipt_times_never_mutate_history() -> TestResult {
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 3;
    c.max_identities = 3;
    c.max_bindings = 1;
    let (store, observations, receipts) = chain(c.clone()).await?;
    prune_raw(&store, "2026-10-07T00:12:30Z", 3).await?;
    let before = state(&c)?.encode()?;
    for b in [
        budget(0, 73728),
        budget(1, 0),
        budget(4, 1),
        budget(1, 3 * 73728 + 1),
        budget(1, c.max_ledger_bytes + 1),
    ] {
        assert!(matches!(
            store
                .prune_identities(clock("2026-10-07T00:17:30Z")?, b, ctx())
                .await,
            Err(CoverageError::Invalid(_))
        ));
    }
    for ordering in ["accepted_equals_replay", "replay_after_identity"] {
        let mut r = receipts[0].clone();
        if ordering == "accepted_equals_replay" {
            r.accepted_at = r.replay_until.clone();
        } else {
            r.identity_until = r.accepted_at.clone();
        }
        assert!(
            matches!(
                store
                    .retry(
                        r,
                        submission(&observations[0])?,
                        intake(&observations[0], "2026-10-07T00:17:30Z")?,
                        ctx()
                    )
                    .await,
                Err(CoverageError::Invalid(_))
            ),
            "{ordering}"
        );
    }
    assert_eq!(state(&c)?.encode()?, before);
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn no_op_identity_pruning_does_not_raise_floor_and_regression_rejects_after_restart()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store = initialize(c.clone()).await?;
    let p = sample()?;
    store.append(p.clone(), ctx()).await?;
    prune_raw(&store, "2026-10-07T00:10:30Z", 1).await?;
    store
        .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(1, 73728), ctx())
        .await?;
    let before = state(&c)?.encode()?;
    for time in ["2026-10-07T00:15:30Z", "2026-10-07T00:16:30Z"] {
        let no_op = store
            .prune_identities(clock(time)?, budget(1, 73728), ctx())
            .await?;
        assert_eq!(no_op.pruned_records, 0);
        assert_eq!(no_op.identity_pruned_through, 1);
        assert_eq!(state(&c)?.encode()?, before);
    }
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c.clone()).await?;
    assert!(matches!(
        store
            .prune_identities(
                clock("2026-10-07T00:15:29.999999999Z")?,
                budget(1, 73728),
                ctx()
            )
            .await,
        Err(CoverageError::ClockRegression)
    ));
    assert_eq!(state(&c)?.encode()?, before);
    let next = deadlines(
        variant(&p, |_| {})?,
        "2026-10-07T00:15:31Z",
        "2026-10-07T00:20:31Z",
        "2026-10-07T00:25:31Z",
    )?;
    store.append(next, ctx()).await?;
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn lower_identity_capacity_never_deletes_acknowledged_history_to_reopen() -> TestResult {
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_bindings = 1;
    let (store, observations, receipts) = chain(c.clone()).await?;
    store.shutdown(ctx()).await?;
    let before = state(&c)?.encode()?;
    let original = c.clone();
    c.max_payloads = 1;
    c.max_identities = 1;
    assert!(matches!(
        CoverageStore::open(c.clone()).await,
        Err(CoverageError::Quota)
    ));
    assert_eq!(state(&c)?.encode()?, before);
    let store = CoverageStore::open(original).await?;
    for (p, receipt) in observations.iter().zip(receipts) {
        let row = store.load(p.record_id(), ctx()).await?.ok_or("retained")?;
        assert_eq!(row.raw.as_deref(), Some(p.raw.as_slice()));
        assert_eq!(row.receipt, receipt);
    }
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn malformed_metadata_or_missing_identity_prefix_fails_closed_without_partial_deletion()
-> TestResult {
    for corruption in ["nil_uuid", "missing_middle", "missing_tail"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let (store, observations, _) = chain(c.clone()).await?;
        prune_raw(&store, "2026-10-07T00:12:30Z", 3).await?;
        let before = state(&c)?.encode()?;
        let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
        if corruption == "nil_uuid" {
            let mut bytes = metadata(&c, &observations[0])?;
            let producer_id = observations[0].record_id();
            let offset = bytes
                .windows(16)
                .position(|window| window == producer_id.as_bytes())
                .ok_or("encoded UUID")?;
            bytes[offset..offset + 16].copy_from_slice(Uuid::nil().as_bytes());
            db.execute(
                "UPDATE entries SET metadata=?1 WHERE record_id=?2",
                rusqlite::params![bytes, producer_id.as_bytes()],
            )?;
        } else {
            let removed = if corruption == "missing_middle" { 1 } else { 2 };
            db.execute(
                "DELETE FROM entries WHERE record_id=?1",
                [observations[removed].record_id().as_bytes()],
            )?;
        }
        let count_before: i64 = db.query_row("SELECT count(*) FROM entries", [], |r| r.get(0))?;
        db.close().map_err(|(_, e)| e)?;
        assert!(
            matches!(
                store
                    .prune_identities(clock("2026-10-07T00:17:30Z")?, budget(3, 3 * 73728), ctx())
                    .await,
                Err(CoverageError::Corrupt(_))
            ),
            "{corruption}"
        );
        assert!(!store.metrics().available);
        assert_eq!(state(&c)?.encode()?, before);
        let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
        let count_after: i64 = db.query_row("SELECT count(*) FROM entries", [], |r| r.get(0))?;
        assert_eq!(count_after, count_before);
        db.close().map_err(|(_, e)| e)?;
        assert!(matches!(
            store.shutdown(ctx()).await,
            Err(CoverageError::Unavailable)
        ));
        let error = CoverageStore::open(c)
            .await
            .err()
            .ok_or("corrupt identity history accepted")?;
        assert!(
            matches!(
                error,
                CoverageError::Corrupt(_) | CoverageError::Invalid("nil UUID")
            ),
            "{corruption}: {error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn changed_identity_marker_or_anchor_with_fresh_state_checksum_fails_recovery() -> TestResult
{
    for corruption in ["marker", "anchor"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let (store, observations, receipts) = chain(c.clone()).await?;
        let second_metadata_bytes = metadata(&c, &observations[1])?.len() as u64;
        prune_raw(&store, "2026-10-07T00:12:30Z", 3).await?;
        store
            .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(1, 73728), ctx())
            .await?;
        store.shutdown(ctx()).await?;
        let mut s = state(&c)?;
        if corruption == "marker" {
            s.identity_pruned_through = 2;
            s.identity_count -= 1;
            s.ledger_charge -= second_metadata_bytes + 8192;
            s.identity_anchor = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&receipts[1].prefix_digest[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| "prefix width")?;
        } else {
            s.identity_anchor[0] ^= 1;
        }
        let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
        persist_state(&db, &s)?;
        db.close().map_err(|(_, e)| e)?;
        assert!(
            matches!(CoverageStore::open(c).await, Err(CoverageError::Corrupt(_))),
            "{corruption}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn identity_pruning_sigkill_recovers_complete_prefix_and_shared_pins_before_or_after_commit()
-> TestResult {
    if let Ok(path) = std::env::var("SIGNAL_COVERAGE_IDENTITY_PRUNING_ROOT") {
        let (store, _, _) = chain(cfg(Path::new(&path))).await?;
        prune_raw(&store, "2026-10-07T00:12:30Z", 3).await?;
        store
            .prune_identities(clock("2026-10-07T00:16:30Z")?, budget(2, 2 * 73728), ctx())
            .await?;
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
    let f = fixture()?;
    let observations = f["chains"][0]["commits"]
        .as_array()
        .ok_or("commits")?
        .iter()
        .map(|item| prepared(item, &f))
        .collect::<TestResult<Vec<_>>>()?;
    for stage in [
        "identity_prune_before_commit",
        "identity_prune_after_commit",
    ] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let mut child = OwnedChild(Command::new(std::env::current_exe()?)
            .args(["--exact", "identity_pruning_tests::identity_pruning_sigkill_recovers_complete_prefix_and_shared_pins_before_or_after_commit", "--nocapture"])
            .env("SIGNAL_COVERAGE_IDENTITY_PRUNING_ROOT", &c.directory)
            .env("SIGNAL_COVERAGE_TEST_CHECKPOINT", stage)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?);
        let stdout = child.0.stdout.take().ok_or("stdout")?;
        let (ready, wait) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let found = BufReader::new(stdout)
                .lines()
                .any(|line| line.ok().as_deref() == Some("COVERAGE-CHECKPOINT"));
            let _ = ready.send(found);
        });
        if !matches!(wait.recv_timeout(Duration::from_secs(10)), Ok(true)) {
            child.0.kill()?;
            child.0.wait()?;
            reader.join().map_err(|_| "checkpoint reader")?;
            return Err("identity pruning checkpoint missing".into());
        }
        reader.join().map_err(|_| "checkpoint reader")?;
        assert!(matches!(
            CoverageStore::open(c.clone()).await,
            Err(CoverageError::Locked)
        ));
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let store = CoverageStore::open(c.clone()).await?;
        let committed = stage == "identity_prune_after_commit";
        let s = state(&c)?;
        assert_eq!(s.identity_pruned_through, if committed { 2 } else { 0 });
        assert_eq!(s.identity_count, if committed { 1 } else { 3 });
        assert_eq!(s.payload_pruned_through, 3);
        assert_eq!(s.payload_count, 0);
        assert_eq!(s.committed_sequence, 3);
        assert_eq!((s.binding_count, s.profile_count), (1, 1));
        assert_eq!(
            s.clock_floor,
            clock(if committed {
                "2026-10-07T00:16:30Z"
            } else {
                "2026-10-07T00:12:30Z"
            })?
        );
        assert_eq!(
            format::hex(&s.committed_prefix),
            f["chains"][0]["commits"][2]["prefix_digest"]
        );
        assert_eq!(s.payload_anchor, s.committed_prefix);
        for (i, p) in observations.iter().enumerate() {
            let row = store.load(p.record_id(), ctx()).await?;
            if committed && i < 2 {
                assert!(row.is_none());
            } else {
                let row = row.ok_or("retained identity")?;
                assert!(row.raw.is_none());
                assert_eq!(
                    row.receipt.prefix_digest,
                    f["chains"][0]["commits"][i]["prefix_digest"]
                );
                assert_eq!(row.binding.encoded(), p.binding.encoded());
                assert_eq!(row.profile.encoded(), p.profile.encoded());
            }
        }
        let reconciled = store
            .prune_identities(clock("2026-10-07T00:16:30Z")?, budget(2, 2 * 73728), ctx())
            .await?;
        assert_eq!(reconciled.pruned_records, if committed { 0 } else { 2 });
        assert_eq!(state(&c)?.identity_pruned_through, 2);
        store.shutdown(ctx()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn complete_identity_pruning_sigkill_recovers_final_pin_deletion_and_append_tail()
-> TestResult {
    fn observations() -> TestResult<[PreparedObservation; 2]> {
        let first = sample()?;
        let second = variant(&first, |v| {
            v["record_id"] = json!(Uuid::from_u128(0x10000000000040008000000000000001));
            v["collector_id"] = json!("second-fixture-collector");
        })?;
        Ok([first, second])
    }
    if let Ok(path) = std::env::var("SIGNAL_COVERAGE_COMPLETE_IDENTITY_ROOT") {
        let f = fixture()?;
        let store = CoverageStore::initialize(
            cfg(Path::new(&path)),
            Uuid::parse_str(f["chains"][0]["history_id"].as_str().ok_or("history")?)?,
            clock("2026-10-07T00:05:29Z")?,
        )
        .await?;
        let mut receipts = Vec::new();
        for p in observations()? {
            receipts.push(store.append(p, ctx()).await?);
        }
        let receipt_path = std::env::var("SIGNAL_COVERAGE_COMPLETE_IDENTITY_RECEIPTS")?;
        std::fs::write(receipt_path, serde_json::to_vec(&receipts)?)?;
        prune_raw(&store, "2026-10-07T00:10:30Z", 2).await?;
        store
            .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(2, 2 * 73728), ctx())
            .await?;
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
    let observations = observations()?;
    for stage in [
        "identity_prune_before_commit",
        "identity_prune_after_commit",
    ] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let receipt_path = t.path().join("original-receipts.json");
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "identity_pruning_tests::complete_identity_pruning_sigkill_recovers_final_pin_deletion_and_append_tail",
                    "--nocapture",
                ])
                .env("SIGNAL_COVERAGE_COMPLETE_IDENTITY_ROOT", &c.directory)
                .env("SIGNAL_COVERAGE_COMPLETE_IDENTITY_RECEIPTS", &receipt_path)
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
                .any(|line| line.ok().as_deref() == Some("COVERAGE-CHECKPOINT"));
            let _ = ready.send(found);
        });
        if !matches!(wait.recv_timeout(Duration::from_secs(10)), Ok(true)) {
            child.0.kill()?;
            child.0.wait()?;
            reader.join().map_err(|_| "checkpoint reader")?;
            return Err("complete identity pruning checkpoint missing".into());
        }
        reader.join().map_err(|_| "checkpoint reader")?;
        let receipts: Vec<Receipt> = serde_json::from_slice(&std::fs::read(receipt_path)?)?;
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].sequence, "1");
        assert_eq!(receipts[1].sequence, "2");
        assert!(matches!(
            CoverageStore::open(c.clone()).await,
            Err(CoverageError::Locked)
        ));
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let store = CoverageStore::open(c.clone()).await?;
        let committed = stage == "identity_prune_after_commit";
        let s = state(&c)?;
        assert_eq!(s.history_id, receipts[0].history_id);
        assert_eq!(s.history_id, receipts[1].history_id);
        assert_eq!(s.committed_sequence, 2);
        assert_eq!(format::hex(&s.committed_prefix), receipts[1].prefix_digest);
        assert_eq!(s.payload_pruned_through, 2);
        assert_eq!(s.payload_anchor, s.committed_prefix);
        assert_eq!(s.payload_count, 0);
        assert_eq!(s.identity_pruned_through, if committed { 2 } else { 0 });
        assert_eq!(s.identity_count, if committed { 0 } else { 2 });
        assert_eq!(s.binding_count, if committed { 0 } else { 2 });
        assert_eq!(s.profile_count, if committed { 0 } else { 1 });
        assert_eq!(
            s.clock_floor,
            clock(if committed {
                "2026-10-07T00:15:30Z"
            } else {
                "2026-10-07T00:10:30Z"
            })?
        );
        if committed {
            assert_eq!(s.identity_anchor, s.committed_prefix);
            assert_eq!(s.ledger_charge, format::ROOT_CHARGE);
        } else {
            assert_eq!(s.identity_anchor, format::genesis(s.history_id)?);
            let identities = observations
                .iter()
                .map(|p| Ok(metadata(&c, p)?.len() as u64 + 8192))
                .collect::<TestResult<Vec<_>>>()?;
            let bindings: u64 = observations
                .iter()
                .map(|p| p.binding.encoded().len() as u64 + 4096)
                .sum();
            let profile = observations[0].profile.encoded().len() as u64 + 4096;
            assert_eq!(
                s.ledger_charge,
                format::ROOT_CHARGE + identities.iter().sum::<u64>() + bindings + profile
            );
        }
        for (p, receipt) in observations.iter().zip(&receipts) {
            let row = store
                .get_authorized(p.record_id(), authority(p)?, ctx())
                .await?;
            if committed {
                assert!(row.is_none());
            } else {
                let row = row.ok_or("uncommitted deletion survivor")?;
                assert_eq!(&row.receipt, receipt);
                assert!(row.raw.is_none());
                assert_eq!(row.binding.encoded(), p.binding.encoded());
                assert_eq!(row.profile.encoded(), p.profile.encoded());
            }
        }
        let reconciled = store
            .prune_identities(clock("2026-10-07T00:15:30Z")?, budget(2, 2 * 73728), ctx())
            .await?;
        assert_eq!(reconciled.pruned_records, if committed { 0 } else { 2 });
        let empty = state(&c)?;
        assert_eq!(empty.ledger_charge, format::ROOT_CHARGE);
        assert_eq!(
            (
                empty.identity_count,
                empty.binding_count,
                empty.profile_count
            ),
            (0, 0, 0)
        );
        assert_eq!(empty.identity_anchor, s.committed_prefix);
        let next = deadlines(
            variant(&observations[0], |_| {})?,
            "2026-10-07T00:15:31Z",
            "2026-10-07T00:20:31Z",
            "2026-10-07T00:25:31Z",
        )?;
        let appended = store.append(next.clone(), ctx()).await?;
        assert_eq!(appended.sequence, "3");
        assert_eq!(appended.history_id, s.history_id);
        let expected_prefix = format::prefix(s.committed_prefix, &metadata(&c, &next)?);
        assert_eq!(appended.prefix_digest, format::hex(&expected_prefix));
        store.shutdown(ctx()).await?;
        let store = CoverageStore::open(c).await?;
        assert_eq!(
            store
                .load(next.record_id(), ctx())
                .await?
                .ok_or("new tail")?
                .receipt,
            appended
        );
        store.shutdown(ctx()).await?;
    }
    Ok(())
}

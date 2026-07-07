use crate::{
    correction_tests::{ctx, linked, reports},
    format::{self, HistoryBinding, State},
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
fn budget(max_records: u64, max_raw_bytes: u64) -> PayloadPruneBudget {
    PayloadPruneBudget {
        max_records,
        max_raw_bytes,
    }
}
fn sample() -> TestResult<PreparedObservation> {
    let f = fixture()?;
    prepared(&f["chains"][0]["commits"][0], &f)
}
fn accepted(outcome: IntakeOutcome) -> TestResult<Receipt> {
    match outcome {
        IntakeOutcome::Accepted(receipt) => Ok(receipt),
        _ => Err("expected admission".into()),
    }
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
    Ok(PreparedObservation::prepare(
        &raw,
        p.profile.clone(),
        binding,
        p.admission.clone(),
    )?)
}
fn deadlines(
    mut p: PreparedObservation,
    accepted_at: &str,
    replay_until: &str,
) -> TestResult<PreparedObservation> {
    p.admission.accepted_at = clock(accepted_at)?;
    p.admission.replay_until = clock(replay_until)?;
    p.admission.identity_until = clock("2026-10-07T01:00:00Z")?;
    Ok(p)
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
async fn row(store: &CoverageStore, p: &PreparedObservation) -> TestResult<StoredObservation> {
    Ok(store
        .get_authorized(p.record_id(), authority(p)?, ctx())
        .await?
        .ok_or("retained identity")?)
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

#[tokio::test]
async fn equality_prunes_only_expired_global_prefix_and_keeps_frozen_anchors() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, observations, receipts) = chain(c.clone()).await?;
    let before = state(&c)?;
    let no_op = store
        .prune_payloads(
            clock("2026-10-07T00:10:29.999999999Z")?,
            budget(3, 65536),
            ctx(),
        )
        .await?;
    assert_eq!(no_op.pruned_records, 0);
    assert_eq!(state(&c)?.encode()?, before.encode()?);
    let first = store
        .prune_payloads(
            clock("2026-10-07T00:11:29.999999999Z")?,
            budget(3, 65536),
            ctx(),
        )
        .await?;
    assert_eq!(first.pruned_records, 1);
    assert_eq!(first.payload_pruned_through, 1);
    assert_eq!(first.pruned_raw_bytes, observations[0].raw.len() as u64);
    assert_eq!(
        first.reclaimed_ledger_bytes,
        observations[0].raw.len() as u64 + 256
    );
    let second = store
        .prune_payloads(clock("2026-10-07T00:11:30Z")?, budget(3, 65536), ctx())
        .await?;
    assert_eq!(second.pruned_records, 1);
    assert_eq!(second.payload_pruned_through, 2);
    let s = state(&c)?;
    assert_eq!(format::hex(&s.payload_anchor), receipts[1].prefix_digest);
    assert_eq!(s.committed_prefix, before.committed_prefix);
    assert_eq!(s.identity_anchor, before.identity_anchor);
    assert_eq!(s.identity_pruned_through, 0);
    assert_eq!(s.identity_count, 3);
    for (i, p) in observations.iter().enumerate() {
        let stored = row(&store, p).await?;
        assert_eq!(stored.receipt, receipts[i]);
        assert_eq!(
            stored.raw.as_deref(),
            if i < 2 { None } else { Some(p.raw.as_slice()) }
        );
        assert_eq!(stored.profile.encoded(), p.profile.encoded());
        assert_eq!(stored.binding.encoded(), p.binding.encoded());
    }
    let final_batch = store
        .prune_payloads(clock("2026-10-07T00:12:30Z")?, budget(3, 65536), ctx())
        .await?;
    assert_eq!(final_batch.pruned_records, 1);
    assert_eq!(final_batch.payload_pruned_through, 3);
    let final_state = state(&c)?;
    assert_eq!(final_state.payload_anchor, final_state.committed_prefix);
    assert_eq!(final_state.payload_count, 0);
    assert_eq!(store.metrics().payload_pruned_through, 3);
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(store.metrics().payloads, 0);
    assert_eq!(store.metrics().identities, 3);
    for (p, receipt) in observations.iter().zip(receipts) {
        let stored = row(&store, p).await?;
        assert!(stored.raw.is_none());
        assert_eq!(stored.receipt, receipt);
    }
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn unexpired_oldest_blocks_later_expired_bindings_and_no_op_does_not_set_floor() -> TestResult
{
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
            .await?;
    let oldest = deadlines(sample()?, "2026-10-07T00:05:30Z", "2026-10-07T00:25:30Z")?;
    let later = deadlines(
        variant(&oldest, |v| {
            v["collector_id"] = json!("second-fixture-collector")
        })?,
        "2026-10-07T00:05:31Z",
        "2026-10-07T00:06:31Z",
    )?;
    store.append(oldest.clone(), ctx()).await?;
    store.append(later.clone(), ctx()).await?;
    let before = state(&c)?.encode()?;
    let outcome = store
        .prune_payloads(clock("2026-10-07T00:06:31Z")?, budget(3, 65536), ctx())
        .await?;
    assert_eq!(outcome.pruned_records, 0);
    assert_eq!(outcome.payload_pruned_through, 0);
    assert_eq!(outcome.pruned_raw_bytes, 0);
    assert_eq!(outcome.reclaimed_ledger_bytes, 0);
    assert_eq!(state(&c)?.encode()?, before);
    assert_eq!(row(&store, &oldest).await?.raw, Some(oldest.raw.clone()));
    assert_eq!(row(&store, &later).await?.raw, Some(later.raw.clone()));
    let third = deadlines(
        variant(&later, |_| {})?,
        "2026-10-07T00:05:32Z",
        "2026-10-07T00:06:32Z",
    )?;
    store.append(third, ctx()).await?;
    let outcome = store
        .prune_payloads(clock("2026-10-07T00:25:30Z")?, budget(3, 65536), ctx())
        .await?;
    assert_eq!(outcome.pruned_records, 3);
    assert_eq!(outcome.payload_pruned_through, 3);
    assert_eq!(store.metrics().bindings, 2);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn strict_raw_byte_and_record_budgets_never_skip_a_large_oldest_payload() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
            .await?;
    let mut oldest = sample()?;
    oldest.raw.extend_from_slice(&[b' '; 5000]);
    let later = variant(&oldest, |_| {})?;
    let third = variant(&later, |_| {})?;
    for p in [&oldest, &later, &third] {
        store.append(p.clone(), ctx()).await?;
    }
    assert!(oldest.raw.len() > later.raw.len());
    let before = state(&c)?.encode()?;
    let outcome = store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            budget(3, later.raw.len() as u64),
            ctx(),
        )
        .await?;
    assert_eq!(outcome.pruned_records, 0);
    assert_eq!(state(&c)?.encode()?, before);
    let outcome = store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            budget(3, oldest.raw.len() as u64),
            ctx(),
        )
        .await?;
    assert_eq!(outcome.pruned_records, 1);
    assert_eq!(outcome.pruned_raw_bytes, oldest.raw.len() as u64);
    let outcome = store
        .prune_payloads(clock("2026-10-07T00:10:30Z")?, budget(1, 65536), ctx())
        .await?;
    assert_eq!(outcome.pruned_records, 1);
    assert_eq!(outcome.payload_pruned_through, 2);
    assert_eq!(row(&store, &third).await?.raw, Some(third.raw.clone()));
    let outcome = store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            budget(3, third.raw.len() as u64 - 1),
            ctx(),
        )
        .await?;
    assert_eq!(outcome.pruned_records, 0);
    let outcome = store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            budget(3, third.raw.len() as u64),
            ctx(),
        )
        .await?;
    assert_eq!(outcome.pruned_records, 1);
    assert_eq!(outcome.pruned_raw_bytes, third.raw.len() as u64);
    assert_eq!(state(&c)?.payload_count, 0);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn payload_reclamation_reopens_capacity_but_keeps_identity_and_registry_charges() -> TestResult
{
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 1;
    c.max_identities = 3;
    c.max_bindings = 1;
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
            .await?;
    let p = sample()?;
    let r = store.append(p.clone(), ctx()).await?;
    let before = state(&c)?;
    let later = deadlines(
        variant(&p, |_| {})?,
        "2026-10-07T00:10:30Z",
        "2026-10-07T00:15:30Z",
    )?;
    assert!(matches!(
        store.append(later.clone(), ctx()).await,
        Err(CoverageError::Quota)
    ));
    let outcome = store
        .prune_payloads(clock("2026-10-07T00:10:30Z")?, budget(1, 65536), ctx())
        .await?;
    let after = state(&c)?;
    assert_eq!(
        after.ledger_charge,
        before.ledger_charge - p.raw.len() as u64 - 256
    );
    assert_eq!(
        outcome.reclaimed_ledger_bytes,
        before.ledger_charge - after.ledger_charge
    );
    assert_eq!(after.identity_count, before.identity_count);
    assert_eq!(after.binding_count, before.binding_count);
    assert_eq!(after.profile_count, before.profile_count);
    assert_eq!(after.committed_prefix, before.committed_prefix);
    let retained = row(&store, &p).await?;
    assert_eq!(retained.receipt, r);
    assert_eq!(retained.profile.encoded(), p.profile.encoded());
    assert_eq!(retained.binding.encoded(), p.binding.encoded());
    assert!(retained.raw.is_none());
    assert!(matches!(
        store.append(p.clone(), ctx()).await,
        Err(CoverageError::ClockRegression)
    ));
    assert!(matches!(
        store
            .append(
                deadlines(p.clone(), "2026-10-07T00:10:30Z", "2026-10-07T00:15:30Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::IdentityExists)
    ));
    let r2 = store.append(later.clone(), ctx()).await?;
    assert_eq!(r2.sequence, "2");
    assert_eq!(store.metrics().payloads, 1);
    assert_eq!(store.metrics().identities, 2);
    assert!(matches!(
        store.append(variant(&later, |_| {})?, ctx()).await,
        Err(CoverageError::Quota)
    ));
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(row(&store, &p).await?.receipt, r);
    assert_eq!(row(&store, &later).await?.receipt, r2);
    assert_eq!(store.metrics().identities, 2);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn replay_never_renews_deadlines_and_only_real_pruning_advances_clock_floor() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
            .await?;
    let p = sample()?;
    let r = accepted(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    let later_policy = IntakeContext::new(
        authority(&p)?,
        clock("2026-10-07T00:09:30Z")?,
        None,
        IntakePolicy::new(60, 2, 3600, 7200)?,
    );
    assert_eq!(
        store
            .retry(r.clone(), submission(&p)?, later_policy, ctx())
            .await?,
        IntakeOutcome::Replayed(r.clone())
    );
    let outcome = store
        .prune_payloads(clock("2026-10-07T00:10:30Z")?, budget(1, 65536), ctx())
        .await?;
    assert_eq!(outcome.pruned_records, 1);
    assert_eq!(row(&store, &p).await?.receipt, r);
    assert!(row(&store, &p).await?.raw.is_none());
    assert!(matches!(
        store
            .retry(
                r,
                submission(&p)?,
                intake(&p, "2026-10-07T00:10:30Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::ReplayWindowExpired)
    ));
    let before = state(&c)?.encode()?;
    assert!(matches!(
        store
            .prune_payloads(
                clock("2026-10-07T00:10:29.999999999Z")?,
                budget(1, 65536),
                ctx()
            )
            .await,
        Err(CoverageError::ClockRegression)
    ));
    for time in ["2026-10-07T00:10:30Z", "2026-10-07T00:11:30Z"] {
        let no_op = store
            .prune_payloads(clock(time)?, budget(1, 65536), ctx())
            .await?;
        assert_eq!(no_op.pruned_records, 0);
        assert_eq!(no_op.payload_pruned_through, 1);
        assert_eq!(state(&c)?.encode()?, before);
    }
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c.clone()).await?;
    assert_eq!(state(&c)?.clock_floor, clock("2026-10-07T00:10:30Z")?);
    let next = deadlines(
        variant(&p, |_| {})?,
        "2026-10-07T00:10:31Z",
        "2026-10-07T00:15:31Z",
    )?;
    store.append(next, ctx()).await?;
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn pruned_correction_target_rejects_new_link_but_admitted_correction_stays_valid()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let (failed, correction) = reports()?;
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:06:29Z")?)
            .await?;
    let r = accepted(
        store
            .submit(
                submission(&failed)?,
                intake(&failed, "2026-10-07T00:06:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    let r2 = accepted(
        store
            .submit(
                linked(&correction, failed.record_id())?,
                intake(&correction, "2026-10-07T00:07:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    let outcome = store
        .prune_payloads(clock("2026-10-07T00:11:30Z")?, budget(2, 65536), ctx())
        .await?;
    assert_eq!(outcome.pruned_records, 1);
    assert_eq!(row(&store, &failed).await?.receipt, r);
    assert!(row(&store, &failed).await?.raw.is_none());
    store.shutdown(ctx()).await?;
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
        IntakeOutcome::Replayed(r2.clone())
    );
    let template = deadlines(
        correction.clone(),
        "2026-10-07T00:12:00Z",
        "2026-10-07T00:17:00Z",
    )?;
    let next = variant(&template, |v| {
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
    assert_eq!(row(&store, &correction).await?.receipt, r2);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn reopening_with_lower_payload_capacity_preserves_unexpired_acknowledgements() -> TestResult
{
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    let (store, observations, receipts) = chain(c.clone()).await?;
    store.shutdown(ctx()).await?;
    let before = state(&c)?.encode()?;
    let original_cap = c.max_payloads;
    c.max_payloads = 1;
    assert!(matches!(
        CoverageStore::open(c.clone()).await,
        Err(CoverageError::Quota)
    ));
    assert_eq!(state(&c)?.encode()?, before);
    c.max_payloads = original_cap;
    let store = CoverageStore::open(c.clone()).await?;
    assert_eq!(store.metrics().payloads, 3);
    let no_op = store
        .prune_payloads(clock("2026-10-07T00:08:30Z")?, budget(1, 65536), ctx())
        .await?;
    assert_eq!(no_op.pruned_records, 0);
    assert_eq!(state(&c)?.encode()?, before);
    for (p, receipt) in observations.iter().zip(receipts) {
        let stored = row(&store, p).await?;
        assert_eq!(stored.raw.as_deref(), Some(p.raw.as_slice()));
        assert_eq!(stored.receipt, receipt);
    }
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn invalid_pruning_budgets_reject_before_mutation() -> TestResult {
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 3;
    let (store, _, _) = chain(c.clone()).await?;
    let before = state(&c)?.encode()?;
    for b in [
        budget(0, 65536),
        budget(1, 0),
        budget(c.max_payloads + 1, 1),
        budget(1, c.max_payloads * 65536 + 1),
        budget(1, c.max_ledger_bytes + 1),
    ] {
        assert!(matches!(
            store
                .prune_payloads(clock("2026-10-07T00:12:30Z")?, b, ctx())
                .await,
            Err(CoverageError::Invalid(_))
        ));
        assert_eq!(state(&c)?.encode()?, before);
    }
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn pruning_marker_anchor_and_missing_payload_corruption_fail_closed_on_recovery() -> TestResult
{
    for corruption in ["marker", "anchor", "missing_payload"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let (store, observations, receipts) = chain(c.clone()).await?;
        store
            .prune_payloads(clock("2026-10-07T00:11:30Z")?, budget(1, 65536), ctx())
            .await?;
        store.shutdown(ctx()).await?;
        let mut s = state(&c)?;
        let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
        match corruption {
            "marker" => {
                s.payload_pruned_through = 2;
                s.payload_count -= 1;
                s.payload_anchor = (0..64)
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&receipts[1].prefix_digest[i..i + 2], 16))
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| "prefix width")?;
                s.ledger_charge -= observations[1].raw.len() as u64 + 256;
                persist_state(&db, &s)?;
            }
            "anchor" => {
                s.payload_anchor[0] ^= 1;
                persist_state(&db, &s)?;
            }
            "missing_payload" => {
                db.execute(
                    "UPDATE entries SET raw=NULL WHERE record_id=?1",
                    [observations[2].record_id().as_bytes()],
                )?;
            }
            _ => return Err("unknown corruption case".into()),
        }
        db.close().map_err(|(_, e)| e)?;
        let error = CoverageStore::open(c)
            .await
            .err()
            .ok_or("corrupt store accepted")?;
        assert!(
            matches!(error, CoverageError::Corrupt(_) | CoverageError::Sqlite(_)),
            "{corruption}: {error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_persisted_metadata_fails_closed_before_pruning_mutation() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let (store, observations, _) = chain(c.clone()).await?;
    let before = state(&c)?.encode()?;
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let metadata: Vec<u8> = db.query_row(
        "SELECT metadata FROM entries WHERE record_id=?1",
        [observations[0].record_id().as_bytes()],
        |r| r.get(0),
    )?;
    // Change the encoded producer ID directly so semantic encoder validation cannot mask recovery.
    let original_id = observations[0].record_id();
    let offset = metadata
        .windows(16)
        .position(|window| window == original_id.as_bytes())
        .ok_or("producer UUID in metadata")?;
    let mut bytes = metadata;
    bytes[offset..offset + 16].copy_from_slice(Uuid::nil().as_bytes());
    db.execute(
        "UPDATE entries SET metadata=?1 WHERE record_id=?2",
        rusqlite::params![bytes, original_id.as_bytes()],
    )?;
    db.close().map_err(|(_, e)| e)?;
    assert!(matches!(
        store
            .prune_payloads(clock("2026-10-07T00:12:30Z")?, budget(3, 65536), ctx())
            .await,
        Err(CoverageError::Corrupt(_))
    ));
    assert!(!store.metrics().available);
    assert_eq!(state(&c)?.encode()?, before);
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let available: i64 = db.query_row(
        "SELECT count(*) FROM entries WHERE raw IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(available, 3);
    db.close().map_err(|(_, e)| e)?;
    assert!(matches!(
        store.shutdown(ctx()).await,
        Err(CoverageError::Unavailable)
    ));
    let error = CoverageStore::open(c)
        .await
        .err()
        .ok_or("malformed metadata accepted")?;
    assert!(
        matches!(
            error,
            CoverageError::Corrupt(_) | CoverageError::Invalid("nil UUID")
        ),
        "{error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn pruning_process_loss_recovers_only_complete_atomic_prefixes() -> TestResult {
    if let Ok(path) = std::env::var("SIGNAL_COVERAGE_PRUNING_ROOT") {
        let (store, _, _) = chain(cfg(Path::new(&path))).await?;
        store
            .prune_payloads(clock("2026-10-07T00:11:30Z")?, budget(2, 65536), ctx())
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
    for stage in ["prune_before_commit", "prune_after_commit"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "pruning_tests::pruning_process_loss_recovers_only_complete_atomic_prefixes",
                    "--nocapture",
                ])
                .env("SIGNAL_COVERAGE_PRUNING_ROOT", &c.directory)
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
            return Err("pruning checkpoint missing".into());
        }
        reader.join().map_err(|_| "checkpoint reader")?;
        assert!(matches!(
            CoverageStore::open(c.clone()).await,
            Err(CoverageError::Locked)
        ));
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let store = CoverageStore::open(c.clone()).await?;
        let s = state(&c)?;
        let committed = stage == "prune_after_commit";
        assert_eq!(s.payload_pruned_through, if committed { 2 } else { 0 });
        assert_eq!(s.payload_count, if committed { 1 } else { 3 });
        assert_eq!(s.identity_count, 3);
        assert_eq!(s.committed_sequence, 3);
        assert_eq!(
            s.clock_floor,
            clock(if committed {
                "2026-10-07T00:11:30Z"
            } else {
                "2026-10-07T00:07:30Z"
            })?
        );
        for (i, p) in observations.iter().enumerate() {
            let stored = row(&store, p).await?;
            assert_eq!(
                stored.raw.as_deref(),
                if committed && i < 2 {
                    None
                } else {
                    Some(p.raw.as_slice())
                }
            );
            assert_eq!(
                stored.receipt.prefix_digest,
                f["chains"][0]["commits"][i]["prefix_digest"]
            );
        }
        let outcome = store
            .prune_payloads(clock("2026-10-07T00:11:30Z")?, budget(2, 65536), ctx())
            .await?;
        assert_eq!(outcome.pruned_records, if committed { 0 } else { 2 });
        assert_eq!(state(&c)?.payload_pruned_through, 2);
        store.shutdown(ctx()).await?;
    }
    Ok(())
}

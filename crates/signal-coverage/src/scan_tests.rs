use crate::{
    correction_tests::ctx,
    format::{self, HistoryBinding, ProfileDefinition, State},
    intake_tests::authority,
    tests::{TestResult, clock, fixture, prepared},
    *,
};
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

const CURSOR_DOMAIN: &[u8] = b"SIGNAL-COVERAGE-SCAN-V1\0";

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
fn budget(records: u64, scanned: u64, response: u64, work: u64) -> ScanBudget {
    ScanBudget {
        max_records: records,
        max_response_bytes: response,
        max_scanned_records: scanned,
        max_scanned_bytes: work,
    }
}
fn wide(records: u64) -> ScanBudget {
    budget(
        records,
        records,
        397312,
        (records * 217088).min(4 * 1024 * 1024),
    )
}
fn response_header(p: &PreparedObservation) -> u64 {
    4096 + 2 * (CURSOR_DOMAIN.len() as u64 + 152 + p.binding.encoded().len() as u64)
}
fn response_row(p: &PreparedObservation) -> u64 {
    p.raw.len() as u64 + 8192
}
fn state(c: &CoverageConfig) -> TestResult<State> {
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let bytes: Vec<u8> = db.query_row("SELECT data FROM state WHERE id=1", [], |r| r.get(0))?;
    let state = State::decode(&bytes)?;
    db.close().map_err(|(_, e)| e)?;
    Ok(state)
}
fn work_row(c: &CoverageConfig, p: &PreparedObservation) -> TestResult<u64> {
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    let metadata: Vec<u8> = db.query_row(
        "SELECT metadata FROM entries WHERE record_id=?1",
        [p.record_id().as_bytes()],
        |r| r.get(0),
    )?;
    db.close().map_err(|(_, e)| e)?;
    Ok(metadata.len() as u64
        + p.raw.len() as u64
        + p.binding.encoded().len() as u64
        + p.profile.encoded().len() as u64
        + 4096)
}
async fn seed(
    c: CoverageConfig,
    observations: &[PreparedObservation],
    history_id: Uuid,
) -> TestResult<(CoverageStore, Vec<Receipt>)> {
    let store = CoverageStore::initialize(c, history_id, clock("2026-10-07T00:05:29Z")?).await?;
    let mut receipts = Vec::new();
    for p in observations {
        receipts.push(store.append(p.clone(), ctx()).await?);
    }
    Ok((store, receipts))
}
fn cursor(page: &ScanPage) -> TestResult<ScanCursor> {
    Ok(ScanCursor::parse(
        page.continuation().ok_or("expected continuation")?.as_str(),
    )?)
}
fn cursor_bytes(cursor: &ScanCursor) -> TestResult<Vec<u8>> {
    let token = cursor.as_str();
    Ok((0..token.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&token[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?)
}
fn frontier_offset(bytes: &[u8]) -> TestResult<usize> {
    let offset = CURSOR_DOMAIN.len() + 20;
    let len = u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("cursor binding length")?
            .try_into()?,
    ) as usize;
    Ok(offset + 4 + len)
}
fn rewritten_cursor(mut bytes: Vec<u8>) -> TestResult<ScanCursor> {
    let end = bytes.len().checked_sub(32).ok_or("cursor checksum")?;
    let checksum = format::sha256(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
    Ok(ScanCursor::parse(&format::hex(&bytes))?)
}

#[tokio::test]
async fn first_page_captures_frontier_and_later_appends_are_excluded_from_continuation()
-> TestResult {
    let t = tempfile::tempdir()?;
    let p1 = sample()?;
    let p2 = variant(&p1, |_| {})?;
    let p3 = variant(&p1, |_| {})?;
    let (store, receipts) = seed(
        cfg(&t.path().join("coverage")),
        &[p1.clone(), p2.clone(), p3.clone()],
        Uuid::new_v4(),
    )
    .await?;
    let page = store.scan(authority(&p1)?, None, wide(1), ctx()).await?;
    assert_eq!(page.frontier(), 3);
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipts[0]);
    let mut next = cursor(&page)?;
    drop(page);
    let p4 = variant(&p1, |_| {})?;
    let appended = store.append(p4, ctx()).await?;
    assert_eq!(appended.sequence, "4");
    for (i, receipt) in receipts[1..].iter().enumerate() {
        let grant = AuthorizedBinding::new(
            p1.binding.observer_id(),
            p1.binding.clone(),
            format!("current-grant-{i}"),
        )?;
        let page = store.scan(grant, Some(next), wide(1), ctx()).await?;
        assert_eq!(page.frontier(), 3);
        assert_eq!(page.records().len(), 1);
        assert_eq!(&page.records()[0].receipt, receipt);
        if i == 0 {
            next = cursor(&page)?;
        } else {
            assert!(page.continuation().is_none());
            break;
        }
    }
    let fresh = store.scan(authority(&p1)?, None, wide(4), ctx()).await?;
    assert_eq!(fresh.frontier(), 4);
    assert_eq!(
        fresh.records().last().ok_or("new append")?.receipt,
        appended
    );
    drop(fresh);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn sparse_empty_pages_continue_until_the_captured_frontier_is_exhausted() -> TestResult {
    let t = tempfile::tempdir()?;
    let a1 = sample()?;
    let b2 = variant(&a1, |v| {
        v["collector_id"] = json!("other-fixture-collector")
    })?;
    let a3 = variant(&a1, |_| {})?;
    let (store, receipts) = seed(
        cfg(&t.path().join("coverage")),
        &[a1, b2.clone(), a3],
        Uuid::new_v4(),
    )
    .await?;
    let first = store.scan(authority(&b2)?, None, wide(1), ctx()).await?;
    assert!(first.records().is_empty());
    assert_eq!(first.scanned_records(), 1);
    assert_eq!(first.frontier(), 3);
    let next = cursor(&first)?;
    drop(first);
    let second = store
        .scan(authority(&b2)?, Some(next), wide(1), ctx())
        .await?;
    assert_eq!(second.records().len(), 1);
    assert_eq!(second.records()[0].receipt, receipts[1]);
    let next = cursor(&second)?;
    drop(second);
    let last = store
        .scan(authority(&b2)?, Some(next), wide(1), ctx())
        .await?;
    assert!(last.records().is_empty());
    assert_eq!(last.scanned_records(), 1);
    assert!(last.continuation().is_none());
    drop(last);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn pagination_uses_commit_sequence_for_equal_receiver_times_and_late_source_intervals()
-> TestResult {
    let t = tempfile::tempdir()?;
    let f = fixture()?;
    let mut newer = prepared(&f["chains"][0]["commits"][1], &f)?;
    let mut older = sample()?;
    for p in [&mut newer, &mut older] {
        p.admission.accepted_at = clock("2026-10-07T00:07:30Z")?;
        p.admission.replay_until = clock("2026-10-07T00:12:30Z")?;
        p.admission.identity_until = clock("2026-10-07T00:17:30Z")?;
    }
    let later = variant(&newer, |_| {})?;
    let observations = [newer, older, later];
    let (store, receipts) = seed(
        cfg(&t.path().join("coverage")),
        &observations,
        Uuid::new_v4(),
    )
    .await?;
    let mut next = None;
    for receipt in receipts {
        let page = store
            .scan(authority(&observations[0])?, next, wide(1), ctx())
            .await?;
        assert_eq!(page.records().len(), 1);
        assert_eq!(page.records()[0].receipt, receipt);
        next = page
            .continuation()
            .map(|c| ScanCursor::parse(c.as_str()))
            .transpose()?;
    }
    assert!(next.is_none());
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn every_page_requires_current_full_binding_and_observer_grant() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let second = variant(&p, |_| {})?;
    let (store, _) = seed(
        cfg(&t.path().join("coverage")),
        &[p.clone(), second],
        Uuid::new_v4(),
    )
    .await?;
    let first = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    let next = cursor(&first)?;
    drop(first);
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
        let wrong = variant(&p, |v| {
            if let Some(slot) = v.pointer_mut(path) {
                *slot = if path.ends_with("attributes") {
                    json!({"team":"another"})
                } else {
                    json!("another")
                };
            }
        })?;
        assert!(
            matches!(
                store
                    .scan(
                        authority(&wrong)?,
                        Some(ScanCursor::parse(next.as_str())?),
                        wide(1),
                        ctx()
                    )
                    .await,
                Err(CoverageError::NotAuthorized)
            ),
            "{path}"
        );
    }
    let current = AuthorizedBinding::new(
        p.binding.observer_id(),
        p.binding.clone(),
        "fresh-authority-revision".into(),
    )?;
    let page = store.scan(current, Some(next), wide(1), ctx()).await?;
    assert_eq!(page.records().len(), 1);
    assert!(page.continuation().is_none());
    drop(page);
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn opaque_cursor_is_canonical_versioned_bounded_and_rejects_impossible_positions()
-> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let (store, _) = seed(
        cfg(&t.path().join("coverage")),
        &[p.clone(), variant(&p, |_| {})?],
        Uuid::new_v4(),
    )
    .await?;
    let page = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    let next = cursor(&page)?;
    drop(page);
    assert_eq!(ScanCursor::parse(next.as_str())?.as_str(), next.as_str());
    for token in [
        String::new(),
        "not-a-cursor".into(),
        next.as_str().to_uppercase(),
        format!("{}00", next.as_str()),
        "0".repeat(131585),
    ] {
        assert!(matches!(
            ScanCursor::parse(&token),
            Err(CoverageError::InvalidCursor)
        ));
    }
    let mut bytes = cursor_bytes(&next)?;
    assert_eq!(&bytes[..CURSOR_DOMAIN.len()], CURSOR_DOMAIN);
    bytes[CURSOR_DOMAIN.len()..CURSOR_DOMAIN.len() + 4].copy_from_slice(&2_u32.to_be_bytes());
    assert!(
        matches!(rewritten_cursor(bytes), Err(error) if matches!(error.downcast_ref::<CoverageError>(), Some(CoverageError::InvalidCursor)))
    );
    let mut bytes = cursor_bytes(&next)?;
    let offset = frontier_offset(&bytes)?;
    bytes[offset + 40..offset + 48].copy_from_slice(&3_u64.to_be_bytes());
    assert!(
        matches!(rewritten_cursor(bytes), Err(error) if matches!(error.downcast_ref::<CoverageError>(), Some(CoverageError::InvalidCursor)))
    );
    let mut bytes = cursor_bytes(&next)?;
    bytes[offset + 80..offset + 88].copy_from_slice(&0_u64.to_be_bytes());
    bytes[offset + 88..offset + 96].copy_from_slice(&1_u64.to_be_bytes());
    assert!(
        matches!(rewritten_cursor(bytes), Err(error) if matches!(error.downcast_ref::<CoverageError>(), Some(CoverageError::InvalidCursor)))
    );
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn first_oversized_response_rejects_without_progress_and_later_matching_row_is_not_skipped()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let first = sample()?;
    let second = variant(&first, |_| {})?;
    let (store, receipts) =
        seed(c.clone(), &[first.clone(), second.clone()], Uuid::new_v4()).await?;
    let before = state(&c)?.encode()?;
    let header = response_header(&first);
    let exact = header + response_row(&first);
    for response in [header - 1, exact - 1] {
        assert!(matches!(
            store
                .scan(
                    authority(&first)?,
                    None,
                    budget(2, 2, response, 2 * 217088),
                    ctx()
                )
                .await,
            Err(CoverageError::ResponseLimit)
        ));
        assert_eq!(state(&c)?.encode()?, before);
    }
    let page = store
        .scan(
            authority(&first)?,
            None,
            budget(2, 2, exact, 2 * 217088),
            ctx(),
        )
        .await?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipts[0]);
    assert_eq!(page.response_bytes(), exact);
    let next = cursor(&page)?;
    drop(page);
    let bytes = cursor_bytes(&next)?;
    let offset = frontier_offset(&bytes)?;
    assert_eq!(
        u64::from_be_bytes(bytes[offset + 40..offset + 48].try_into()?),
        1
    );
    let page = store
        .scan(
            authority(&second)?,
            Some(next),
            budget(
                2,
                2,
                response_header(&second) + response_row(&second),
                2 * 217088,
            ),
            ctx(),
        )
        .await?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipts[1]);
    assert!(page.continuation().is_none());
    drop(page);
    assert_eq!(state(&c)?.encode()?, before);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn oversized_matching_response_after_sparse_rows_does_not_advance_callers_cursor()
-> TestResult {
    let t = tempfile::tempdir()?;
    let other = sample()?;
    let matching = variant(&other, |v| {
        v["collector_id"] = json!("matching-fixture-collector")
    })?;
    let (store, receipts) = seed(
        cfg(&t.path().join("coverage")),
        &[other, matching.clone()],
        Uuid::new_v4(),
    )
    .await?;
    let response = response_header(&matching) + response_row(&matching) - 1;
    assert!(matches!(
        store
            .scan(
                authority(&matching)?,
                None,
                budget(2, 2, response, 2 * 217088),
                ctx()
            )
            .await,
        Err(CoverageError::ResponseLimit)
    ));
    let page = store
        .scan(authority(&matching)?, None, wide(2), ctx())
        .await?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipts[1]);
    assert_eq!(page.scanned_records(), 2);
    assert!(page.continuation().is_none());
    drop(page);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn exact_scan_work_budget_bounds_examined_rows_and_first_work_overflow_is_typed() -> TestResult
{
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let first = sample()?;
    let second = variant(&first, |_| {})?;
    let (store, receipts) =
        seed(c.clone(), &[first.clone(), second.clone()], Uuid::new_v4()).await?;
    let first_work = work_row(&c, &first)?;
    assert!(matches!(
        store
            .scan(
                authority(&first)?,
                None,
                budget(2, 2, 397312, first_work - 1),
                ctx()
            )
            .await,
        Err(CoverageError::ScanWorkLimit)
    ));
    let page = store
        .scan(
            authority(&first)?,
            None,
            budget(2, 2, 397312, first_work),
            ctx(),
        )
        .await?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipts[0]);
    assert_eq!(page.scanned_records(), 1);
    assert_eq!(page.scanned_bytes(), first_work);
    let next = cursor(&page)?;
    drop(page);
    let second_work = work_row(&c, &second)?;
    let page = store
        .scan(
            authority(&second)?,
            Some(next),
            budget(2, 2, 397312, second_work),
            ctx(),
        )
        .await?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipts[1]);
    assert_eq!(page.scanned_bytes(), second_work);
    assert!(page.continuation().is_none());
    drop(page);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn maximum_raw_record_fits_a_valid_single_page_and_retains_original_bytes() -> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let mut p = sample()?;
    p.raw.resize(65536, b' ');
    let (store, receipts) = seed(c.clone(), &[p.clone()], Uuid::new_v4()).await?;
    let page = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].raw.as_deref(), Some(p.raw.as_slice()));
    assert_eq!(page.records()[0].receipt, receipts[0]);
    assert_eq!(
        page.response_bytes(),
        response_header(&p) + response_row(&p)
    );
    assert_eq!(page.scanned_bytes(), work_row(&c, &p)?);
    assert!(page.continuation().is_none());
    drop(page);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn first_page_discloses_pruned_payload_markers_and_preserves_original_identity_receipt()
-> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let second = variant(&p, |_| {})?;
    let (store, receipts) = seed(
        cfg(&t.path().join("coverage")),
        &[p.clone(), second],
        Uuid::new_v4(),
    )
    .await?;
    store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            PayloadPruneBudget {
                max_records: 1,
                max_raw_bytes: 65536,
            },
            ctx(),
        )
        .await?;
    let page = store.scan(authority(&p)?, None, wide(2), ctx()).await?;
    let availability = page.availability();
    assert_eq!(availability.history_id, receipts[0].history_id);
    assert_eq!(availability.committed_sequence, 2);
    assert_eq!(availability.payload_pruned_through, 1);
    assert_eq!(availability.identity_pruned_through, 0);
    assert_eq!(page.records().len(), 2);
    assert_eq!(page.records()[0].receipt, receipts[0]);
    assert!(page.records()[0].raw.is_none());
    assert!(page.records()[1].raw.is_some());
    drop(page);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn any_pruning_marker_advance_invalidates_continuation_with_explicit_availability()
-> TestResult {
    for maintenance in ["payload", "identity"] {
        let t = tempfile::tempdir()?;
        let p = sample()?;
        let observations = [p.clone(), variant(&p, |_| {})?, variant(&p, |_| {})?];
        let (store, _) = seed(
            cfg(&t.path().join("coverage")),
            &observations,
            Uuid::new_v4(),
        )
        .await?;
        if maintenance == "identity" {
            store
                .prune_payloads(
                    clock("2026-10-07T00:10:30Z")?,
                    PayloadPruneBudget {
                        max_records: 3,
                        max_raw_bytes: 3 * 65536,
                    },
                    ctx(),
                )
                .await?;
        }
        let page = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
        let next = cursor(&page)?;
        let original = page.availability();
        drop(page);
        if maintenance == "payload" {
            store
                .prune_payloads(
                    clock("2026-10-07T00:10:30Z")?,
                    PayloadPruneBudget {
                        max_records: 1,
                        max_raw_bytes: 65536,
                    },
                    ctx(),
                )
                .await?;
        } else {
            store
                .prune_identities(
                    clock("2026-10-07T00:15:30Z")?,
                    IdentityPruneBudget {
                        max_records: 1,
                        max_metadata_bytes: 73728,
                    },
                    ctx(),
                )
                .await?;
        }
        let error = store
            .scan(authority(&p)?, Some(next), wide(3), ctx())
            .await
            .err()
            .ok_or("pruning silently accepted")?;
        let CoverageError::HistoryPruned(availability) = error else {
            return Err(format!("expected history pruning: {error:?}").into());
        };
        assert_eq!(availability.history_id, original.history_id);
        assert_eq!(availability.committed_sequence, 3);
        if maintenance == "payload" {
            assert_eq!(availability.payload_pruned_through, 1);
            assert_eq!(availability.identity_pruned_through, 0);
        } else {
            assert_eq!(availability.payload_pruned_through, 3);
            assert_eq!(availability.identity_pruned_through, 1);
        }
        assert!(store.metrics().available);
        store.shutdown(ctx()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn frozen_three_commit_chain_has_an_independently_derived_exact_cursor_token() -> TestResult {
    // Derived outside the Rust encoder using struct.pack big-endian fields and hashlib.sha256
    // from backend-vectors.json: chain 1 frontier 3, consumed 1, and both initial markers 0.
    const GOLDEN: &str = concat!(
        "5349474e414c2d434f5645524147452d5343414e2d5631000000000111111111111141118111111111111111000000bc",
        "5349474e414c2d434f5645524147452d42494e44494e472d5631000000000e666978747572652d736f7572636500000011",
        "666978747572652d636f6c6c6563746f720000000d666978747572652d73636f706500000010666978747572652d7265736f75726365",
        "000000000000000d666978747572652d61756469740000000d666978747572652d6261736963000000027631",
        "00000011666978747572652d636f6e6669672d763100000010666978747572652d6f62736572766572",
        "0000000000000003c7aca881f882cb5a1aaebf57d98f42076d33d99d1f0d6c1a1c814356388e878a",
        "0000000000000001ba102c245eee6b2c5835afb4a3dfc994f0b50b786f2d357523796b99fb1b1115",
        "000000000000000000000000000000002b4c6952275f8eacd9c6c16e1e2745a17a490cee9b70534e1173229444b83d32",
    );
    let t = tempfile::tempdir()?;
    let f = fixture()?;
    let store = CoverageStore::initialize(
        cfg(&t.path().join("coverage")),
        Uuid::parse_str(f["chains"][0]["history_id"].as_str().ok_or("history")?)?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    for item in f["chains"][0]["commits"].as_array().ok_or("commits")? {
        let p = prepared(item, &f)?;
        let target = item["input"]["correction_of"]
            .as_str()
            .map(Uuid::parse_str)
            .transpose()?;
        let outcome = store
            .submit(
                CoverageSubmission::new(p.record_id(), &p.raw, target)?,
                crate::intake_tests::intake(
                    &p,
                    item["input"]["accepted_at"].as_str().ok_or("time")?,
                )?,
                ctx(),
            )
            .await?;
        let IntakeOutcome::Accepted(receipt) = outcome else {
            return Err("frozen admission replayed".into());
        };
        assert_eq!(receipt.prefix_digest, item["prefix_digest"]);
    }
    let p = sample()?;
    let page = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    assert_eq!(
        page.continuation().ok_or("golden continuation")?.as_str(),
        GOLDEN
    );
    assert_eq!(ScanCursor::parse(GOLDEN)?.as_str(), GOLDEN);
    drop(page);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn same_history_restores_must_match_frontier_and_consumed_prefix_witnesses() -> TestResult {
    let t = tempfile::tempdir()?;
    let first = sample()?;
    let observations = [
        first.clone(),
        variant(&first, |_| {})?,
        variant(&first, |_| {})?,
    ];
    let history = Uuid::new_v4();
    let (original, _) = seed(cfg(&t.path().join("original")), &observations, history).await?;
    let page = original
        .scan(authority(&first)?, None, wide(1), ctx())
        .await?;
    let next = cursor(&page)?;
    drop(page);
    original.shutdown(ctx()).await?;
    for restoration in [
        "wrong_history",
        "missing_frontier",
        "frontier_diverged",
        "consumed_diverged",
    ] {
        let c = cfg(&t.path().join(restoration));
        let mut restored_records = observations.to_vec();
        if restoration == "missing_frontier" {
            restored_records.pop();
        }
        if restoration == "frontier_diverged" {
            restored_records[2].raw.push(b' ');
        }
        if restoration == "consumed_diverged" {
            restored_records[0].raw.push(b' ');
        }
        let id = if restoration == "wrong_history" {
            Uuid::new_v4()
        } else {
            history
        };
        let (restored, _) = seed(c.clone(), &restored_records, id).await?;
        let supplied = if restoration == "consumed_diverged" {
            // Make the frontier witness match this clone, isolating validation of consumed H(1).
            let mut bytes = cursor_bytes(&next)?;
            let offset = frontier_offset(&bytes)?;
            bytes[offset + 8..offset + 40].copy_from_slice(&state(&c)?.committed_prefix);
            rewritten_cursor(bytes)?
        } else {
            ScanCursor::parse(next.as_str())?
        };
        let before = state(&c)?.encode()?;
        assert!(
            matches!(
                restored
                    .scan(authority(&first)?, Some(supplied), wide(3), ctx())
                    .await,
                Err(CoverageError::HistoryUnavailable)
            ),
            "{restoration}"
        );
        assert_eq!(state(&c)?.encode()?, before);
        assert!(restored.metrics().available);
        restored.shutdown(ctx()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn restored_lower_pruning_markers_reject_cursor_instead_of_rehydrating_its_snapshot()
-> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let observations = [p.clone(), variant(&p, |_| {})?];
    let history = Uuid::new_v4();
    let (original, _) = seed(cfg(&t.path().join("original")), &observations, history).await?;
    original
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            PayloadPruneBudget {
                max_records: 1,
                max_raw_bytes: 65536,
            },
            ctx(),
        )
        .await?;
    let page = original.scan(authority(&p)?, None, wide(1), ctx()).await?;
    assert!(page.records()[0].raw.is_none());
    let next = cursor(&page)?;
    drop(page);
    original.shutdown(ctx()).await?;
    let (restored, _) = seed(cfg(&t.path().join("restored")), &observations, history).await?;
    assert!(matches!(
        restored
            .scan(authority(&p)?, Some(next), wide(2), ctx())
            .await,
        Err(CoverageError::HistoryUnavailable)
    ));
    assert!(restored.metrics().available);
    restored.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn held_page_keeps_operation_capacity_until_drop_and_snapshot_survives_shutdown() -> TestResult
{
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.operation_capacity = 1;
    let p = sample()?;
    let second = variant(&p, |_| {})?;
    let (store, receipts) = seed(c.clone(), &[p.clone(), second], Uuid::new_v4()).await?;
    let held = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    let next = cursor(&held)?;
    assert_eq!(store.metrics().operations_in_flight, 1);
    assert!(matches!(
        store.scan(authority(&p)?, None, wide(1), ctx()).await,
        Err(CoverageError::Capacity)
    ));
    drop(held);
    assert_eq!(store.metrics().operations_in_flight, 0);
    let held = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    store.shutdown(ctx()).await?;
    assert_eq!(held.records()[0].receipt, receipts[0]);
    assert_eq!(held.records()[0].raw.as_deref(), Some(p.raw.as_slice()));
    assert!(matches!(
        store.scan(authority(&p)?, None, wide(1), ctx()).await,
        Err(CoverageError::Closed | CoverageError::Unavailable)
    ));
    // The page owns a memory reservation, not a filesystem lease or shadow worker.
    let reopened = CoverageStore::open(c).await?;
    let page = reopened
        .scan(authority(&p)?, Some(next), wide(1), ctx())
        .await?;
    assert_eq!(page.records()[0].receipt, receipts[1]);
    assert!(page.continuation().is_none());
    drop(page);
    reopened.shutdown(ctx()).await?;
    assert_eq!(held.records()[0].receipt, receipts[0]);
    drop(held);
    Ok(())
}

#[tokio::test]
async fn scanning_and_restart_leave_durable_clock_accounting_and_commit_state_unchanged()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let p = sample()?;
    let (store, _) = seed(
        c.clone(),
        &[p.clone(), variant(&p, |_| {})?],
        Uuid::new_v4(),
    )
    .await?;
    let before = state(&c)?.encode()?;
    let metrics = store.metrics();
    let first = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    let next = cursor(&first)?;
    drop(first);
    assert_eq!(state(&c)?.encode()?, before);
    assert_eq!(
        store.metrics().committed_sequence,
        metrics.committed_sequence
    );
    assert_eq!(store.metrics().ledger_bytes, metrics.ledger_bytes);
    assert_eq!(store.metrics().accepted, metrics.accepted);
    assert_eq!(store.metrics().replayed, metrics.replayed);
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c.clone()).await?;
    let page = store
        .scan(authority(&p)?, Some(next), wide(2), ctx())
        .await?;
    assert_eq!(page.records().len(), 1);
    assert!(page.continuation().is_none());
    drop(page);
    assert_eq!(state(&c)?.encode()?, before);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn persisted_metadata_raw_profile_and_prefix_corruption_fail_closed_during_scan() -> TestResult
{
    for corruption in ["metadata", "raw", "profile", "prefix", "binding_pin"] {
        let t = tempfile::tempdir()?;
        let c = cfg(&t.path().join("coverage"));
        let p = sample()?;
        let (store, _) = seed(
            c.clone(),
            &[p.clone(), variant(&p, |_| {})?],
            Uuid::new_v4(),
        )
        .await?;
        let before = state(&c)?.encode()?;
        let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
        match corruption {
            "metadata" => {
                let mut bytes: Vec<u8> = db.query_row(
                    "SELECT metadata FROM entries WHERE record_id=?1",
                    [p.record_id().as_bytes()],
                    |r| r.get(0),
                )?;
                let id = p.record_id();
                let offset = bytes
                    .windows(16)
                    .position(|window| window == id.as_bytes())
                    .ok_or("metadata producer UUID")?;
                bytes[offset..offset + 16].copy_from_slice(Uuid::nil().as_bytes());
                db.execute(
                    "UPDATE entries SET metadata=?1 WHERE record_id=?2",
                    rusqlite::params![bytes, id.as_bytes()],
                )?;
            }
            "raw" => {
                db.execute(
                    "UPDATE entries SET raw=x'6368616e676564' WHERE record_id=?1",
                    [p.record_id().as_bytes()],
                )?;
            }
            "profile" => {
                db.execute("UPDATE profiles SET definition=zeroblob(100)", [])?;
            }
            "prefix" => {
                db.execute(
                    "UPDATE entries SET prefix=zeroblob(32) WHERE record_id=?1",
                    [p.record_id().as_bytes()],
                )?;
            }
            "binding_pin" => {
                db.execute_batch("PRAGMA foreign_keys=OFF")?;
                db.execute("DELETE FROM bindings", [])?;
            }
            _ => return Err("corruption case".into()),
        }
        db.close().map_err(|(_, e)| e)?;
        let error = store
            .scan(authority(&p)?, None, wide(2), ctx())
            .await
            .err()
            .ok_or("corrupt scan accepted")?;
        assert!(
            matches!(error, CoverageError::Corrupt(_) | CoverageError::Sqlite(_)),
            "{corruption}: {error:?}"
        );
        assert!(!store.metrics().available);
        assert_eq!(state(&c)?.encode()?, before);
        assert!(matches!(
            store.shutdown(ctx()).await,
            Err(CoverageError::Unavailable)
        ));
        assert!(CoverageStore::open(c).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn maximal_unsigned_frontier_scans_match_or_exhaust_without_overflow_or_overshoot()
-> TestResult {
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
            .await?;
    store.shutdown(ctx()).await?;
    // A consistent all-pruned suffix fixture; deleted history has no retained raw authenticity proof.
    let mut s = state(&c)?;
    s.committed_sequence = u64::MAX - 1;
    s.payload_pruned_through = u64::MAX - 1;
    s.identity_pruned_through = u64::MAX - 1;
    let bytes = s.encode()?;
    let db = rusqlite::Connection::open(c.directory.join("coverage.sqlite3"))?;
    db.execute(
        "UPDATE state SET data=?1,checksum=?2 WHERE id=1",
        rusqlite::params![&bytes, format::sha256(&bytes).as_slice()],
    )?;
    db.close().map_err(|(_, e)| e)?;
    let store = CoverageStore::open(c.clone()).await?;
    let p = sample()?;
    let receipt = store.append(p.clone(), ctx()).await?;
    assert_eq!(receipt.sequence, u64::MAX.to_string());
    let page = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    assert_eq!(page.frontier(), u64::MAX);
    assert_eq!(page.availability().identity_pruned_through, u64::MAX - 1);
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].receipt, receipt);
    assert!(page.continuation().is_none());
    drop(page);
    let other = variant(&p, |v| v["collector_id"] = json!("other-fixture-collector"))?;
    let page = store.scan(authority(&other)?, None, wide(1), ctx()).await?;
    assert!(page.records().is_empty());
    assert_eq!(page.scanned_records(), 1);
    assert_eq!(page.frontier(), u64::MAX);
    assert!(page.continuation().is_none());
    drop(page);
    store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            PayloadPruneBudget {
                max_records: 1,
                max_raw_bytes: 65536,
            },
            ctx(),
        )
        .await?;
    store
        .prune_identities(
            clock("2026-10-07T00:15:30Z")?,
            IdentityPruneBudget {
                max_records: 1,
                max_metadata_bytes: 73728,
            },
            ctx(),
        )
        .await?;
    let empty = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    assert_eq!(empty.frontier(), u64::MAX);
    assert_eq!(empty.availability().identity_pruned_through, u64::MAX);
    assert!(empty.records().is_empty());
    assert!(empty.continuation().is_none());
    assert_eq!(empty.scanned_records(), 0);
    drop(empty);
    assert_eq!(state(&c)?.committed_sequence, u64::MAX);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn invalid_record_response_and_work_limits_reject_without_durable_mutation() -> TestResult {
    let t = tempfile::tempdir()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 3;
    c.max_identities = 3;
    c.max_bindings = 1;
    let p = sample()?;
    let (store, _) = seed(
        c.clone(),
        &[p.clone(), variant(&p, |_| {})?],
        Uuid::new_v4(),
    )
    .await?;
    let before = state(&c)?.encode()?;
    for invalid in [
        budget(0, 1, 397312, 217088),
        budget(4, 1, 397312, 217088),
        budget(1, 0, 397312, 217088),
        budget(1, 4, 397312, 217088),
        budget(1, 1, 4095, 217088),
        budget(1, 1, 397313, 217088),
        budget(1, 1, 397312, 0),
        budget(1, 1, 397312, 3 * 217088 + 1),
        budget(1, 1, 397312, c.max_ledger_bytes + 1),
    ] {
        assert!(matches!(
            store.scan(authority(&p)?, None, invalid, ctx()).await,
            Err(CoverageError::Invalid(_))
        ));
        assert_eq!(state(&c)?.encode()?, before);
    }
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn terminal_cursor_still_requires_authorization_prefix_and_retention_validation() -> TestResult
{
    let t = tempfile::tempdir()?;
    let c = cfg(&t.path().join("coverage"));
    let p = sample()?;
    let (store, _) = seed(
        c.clone(),
        &[p.clone(), variant(&p, |_| {})?],
        Uuid::new_v4(),
    )
    .await?;
    let first = store.scan(authority(&p)?, None, wide(1), ctx()).await?;
    let mut bytes = cursor_bytes(&cursor(&first)?)?;
    drop(first);
    let offset = frontier_offset(&bytes)?;
    bytes[offset + 40..offset + 48].copy_from_slice(&2_u64.to_be_bytes());
    bytes[offset + 48..offset + 80].copy_from_slice(&state(&c)?.committed_prefix);
    let terminal = rewritten_cursor(bytes)?;
    let page = store
        .scan(authority(&p)?, Some(terminal.clone()), wide(2), ctx())
        .await?;
    assert!(page.records().is_empty());
    assert_eq!(page.scanned_records(), 0);
    assert!(page.continuation().is_none());
    drop(page);
    let wrong = variant(&p, |v| {
        v["provenance"]["observer_id"] = json!("different-fixture-observer")
    })?;
    assert!(matches!(
        store
            .scan(authority(&wrong)?, Some(terminal.clone()), wide(2), ctx())
            .await,
        Err(CoverageError::NotAuthorized)
    ));
    let mut bytes = cursor_bytes(&terminal)?;
    bytes[offset + 8..offset + 40].fill(0);
    bytes[offset + 48..offset + 80].fill(0);
    assert!(matches!(
        store
            .scan(
                authority(&p)?,
                Some(rewritten_cursor(bytes)?),
                wide(2),
                ctx()
            )
            .await,
        Err(CoverageError::HistoryUnavailable)
    ));
    store
        .prune_payloads(
            clock("2026-10-07T00:10:30Z")?,
            PayloadPruneBudget {
                max_records: 1,
                max_raw_bytes: 65536,
            },
            ctx(),
        )
        .await?;
    assert!(matches!(
        store
            .scan(authority(&p)?, Some(terminal), wide(2), ctx())
            .await,
        Err(CoverageError::HistoryPruned(_))
    ));
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

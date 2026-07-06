use crate::format::{HistoryBinding, ProfileDefinition};
use crate::{
    tests::{TestResult, clock, fixture, prepared},
    *,
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use uuid::Uuid;

fn ctx() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
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
fn policy() -> TestResult<IntakePolicy> {
    Ok(IntakePolicy::new(60, 2, 300, 600)?)
}
pub(crate) fn authority(p: &PreparedObservation) -> TestResult<AuthorizedBinding> {
    Ok(AuthorizedBinding::new(
        p.binding.observer_id(),
        p.binding.clone(),
        "fixture-authority-v1".into(),
    )?)
}
pub(crate) fn intake(p: &PreparedObservation, time: &str) -> TestResult<IntakeContext> {
    Ok(IntakeContext::new(
        authority(p)?,
        clock(time)?,
        Some(p.profile.clone()),
        policy()?,
    ))
}
pub(crate) fn submission(p: &PreparedObservation) -> TestResult<CoverageSubmission> {
    Ok(CoverageSubmission::new(p.record_id(), &p.raw, None)?)
}
fn receipt(outcome: IntakeOutcome) -> TestResult<Receipt> {
    match outcome {
        IntakeOutcome::Accepted(r) => Ok(r),
        _ => Err("expected new admission".into()),
    }
}
async fn initialize(path: &Path) -> TestResult<CoverageStore> {
    let f = fixture()?;
    Ok(CoverageStore::initialize(
        cfg(path),
        Uuid::parse_str(f["chains"][0]["history_id"].as_str().ok_or("history")?)?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?)
}
fn altered(
    p: &PreparedObservation,
    change: impl FnOnce(&mut Value),
) -> TestResult<CoverageSubmission> {
    let mut value: Value = serde_json::from_slice(&p.raw)?;
    let id = Uuid::new_v4();
    value["record_id"] = json!(id);
    change(&mut value);
    Ok(CoverageSubmission::new(
        id,
        &serde_json::to_vec(&value)?,
        None,
    )?)
}

#[tokio::test]
async fn admission_replay_keeps_frozen_receipt_bytes_and_fixed_deadlines() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    let f = fixture()?;
    assert_eq!(
        r.prefix_digest,
        f["chains"][0]["commits"][0]["prefix_digest"]
    );
    assert_eq!(r.replay_until, "2026-10-07T00:10:30.000000000Z");
    assert_eq!(r.identity_until, "2026-10-07T00:15:30.000000000Z");
    let before = store.metrics();
    let current = IntakeContext::new(
        AuthorizedBinding::new(
            p.binding.observer_id(),
            p.binding.clone(),
            "new-authority".into(),
        )?,
        clock("2026-10-07T00:09:30Z")?,
        None,
        IntakePolicy::new(1, 0, 2, 2)?,
    );
    assert_eq!(
        store
            .submit(submission(&p)?, current.clone(), ctx())
            .await?,
        IntakeOutcome::Replayed(r.clone())
    );
    let decoded: Receipt = serde_json::from_slice(&serde_json::to_vec(&r)?)?;
    let retry = store
        .retry(decoded, submission(&p)?, current, ctx())
        .await?;
    let IntakeOutcome::Replayed(replayed) = retry else {
        return Err("retry admitted".into());
    };
    assert_eq!(serde_json::to_vec(&replayed)?, serde_json::to_vec(&r)?);
    let after = store.metrics();
    assert_eq!(after.accepted, 1);
    assert_eq!(after.replayed, 2);
    assert_eq!(after.committed_sequence, before.committed_sequence);
    assert_eq!(after.ledger_bytes, before.ledger_bytes);
    // A retry's later receiver time must not advance the durable admission floor.
    let next = altered(&p, |_| {})?;
    let n = receipt(
        store
            .submit(next, intake(&p, "2026-10-07T00:05:31Z")?, ctx())
            .await?,
    )?;
    assert_eq!(n.sequence, "2");
    assert_eq!(
        store
            .get_authorized(p.record_id(), authority(&p)?, ctx())
            .await?
            .ok_or("retained")?
            .raw,
        Some(p.raw)
    );
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn exact_retry_survives_full_new_write_quota_and_restart() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let mut c = cfg(&t.path().join("coverage"));
    c.max_payloads = 1;
    c.max_identities = 1;
    c.max_bindings = 1;
    let store =
        CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
            .await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    assert!(matches!(
        store
            .submit(
                altered(&p, |_| {})?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::Quota)
    ));
    store.shutdown(ctx()).await?;
    let store = CoverageStore::open(c).await?;
    assert_eq!(
        store
            .retry(
                r.clone(),
                submission(&p)?,
                intake(&p, "2026-10-07T00:06:00Z")?,
                ctx()
            )
            .await?,
        IntakeOutcome::Replayed(r)
    );
    assert_eq!(store.metrics().committed_sequence, 1);
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_identical_submissions_allocate_one_sequence() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let (a, b) = tokio::join!(
        store.submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx()),
        store.submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
    );
    let (r, replay) = match (a?, b?) {
        (IntakeOutcome::Accepted(r), IntakeOutcome::Replayed(replay))
        | (IntakeOutcome::Replayed(replay), IntakeOutcome::Accepted(r)) => (r, replay),
        _ => return Err("concurrent results".into()),
    };
    assert_eq!(r, replay);
    assert_eq!(store.metrics().committed_sequence, 1);
    assert_eq!(store.metrics().accepted, 1);
    assert_eq!(store.metrics().replayed, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn retained_identity_conflict_precedes_new_report_validation() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    let mut whitespace = p.raw.clone();
    whitespace.push(b' ');
    let json: Value = serde_json::from_slice(&p.raw)?;
    for raw in [
        whitespace,
        serde_json::to_vec_pretty(&json)?,
        b"invalid JSON".to_vec(),
    ] {
        assert!(matches!(
            store
                .submit(
                    CoverageSubmission::new(p.record_id(), &raw, None)?,
                    intake(&p, "2026-10-07T00:05:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::IdContentConflict)
        ));
    }
    assert!(matches!(
        store
            .submit(
                CoverageSubmission::new(p.record_id(), &p.raw, Some(Uuid::new_v4()))?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::IdContentConflict)
    ));
    let new = altered(&p, |_| {})?;
    assert!(matches!(
        store
            .submit(
                CoverageSubmission::new(new.record_id, &new.raw, Some(p.record_id()))?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::CorrectionUnsupported)
    ));
    assert_eq!(
        store
            .get_authorized(p.record_id(), authority(&p)?, ctx())
            .await?
            .ok_or("retained")?
            .receipt,
        r
    );
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn authorization_covers_every_original_binding_dimension_before_disclosure() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    assert!(matches!(
        AuthorizedBinding::new("different-observer", p.binding.clone(), "rev".into()),
        Err(CoverageError::NotAuthorized)
    ));
    let f = fixture()?;
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
        "/observer_id",
    ] {
        let mut value = f["bindings"][0]["input"].clone();
        *value.pointer_mut(path).ok_or("binding path")? = if path.ends_with("attributes") {
            json!({"team":"other"})
        } else {
            json!("different")
        };
        let binding = HistoryBinding::parse(&serde_json::to_vec(&value)?)?;
        let grant = AuthorizedBinding::new(binding.observer_id(), binding.clone(), "rev".into())?;
        assert!(
            matches!(
                store
                    .get_authorized(p.record_id(), grant.clone(), ctx())
                    .await,
                Err(CoverageError::NotAuthorized)
            ),
            "{path}"
        );
        let trusted = IntakeContext::new(grant, clock("2026-10-07T00:20:30Z")?, None, policy()?);
        assert!(
            matches!(
                store.submit(submission(&p)?, trusted.clone(), ctx()).await,
                Err(CoverageError::NotAuthorized)
            ),
            "{path}"
        );
        let mut forged = r.clone();
        forged.prefix_digest = "0".repeat(64);
        assert!(
            matches!(
                store
                    .retry(forged, submission(&p)?, trusted.clone(), ctx())
                    .await,
                Err(CoverageError::NotAuthorized)
            ),
            "{path}"
        );
        assert!(
            matches!(
                store
                    .submit(
                        altered(&p, |_| {})?,
                        IntakeContext::new(
                            trusted.authority,
                            clock("2026-10-07T00:05:31Z")?,
                            Some(p.profile.clone()),
                            policy()?
                        ),
                        ctx()
                    )
                    .await,
                Err(CoverageError::NotAuthorized)
            ),
            "{path}"
        );
    }
    assert_eq!(store.metrics().committed_sequence, 1);
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn report_age_is_observed_time_and_expired_verification_stays_historical() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let old = altered(&p, |_| {})?;
    assert!(matches!(
        store
            .submit(old, intake(&p, "2026-10-07T00:06:00.000000001Z")?, ctx())
            .await,
        Err(CoverageError::ReportTooOld)
    ));
    let boundary = receipt(
        store
            .submit(
                altered(&p, |_| {})?,
                intake(&p, "2026-10-07T00:06:00Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(boundary.sequence, "1");
    let historical = altered(&p, |v| {
        v["provenance"]["observed_at"] = json!("2026-10-07T00:10:00Z");
    })?;
    let id = historical.record_id;
    let r = receipt(
        store
            .submit(
                historical,
                intake(&p, "2026-10-07T00:10:30.123456789Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(r.replay_until, "2026-10-07T00:15:30.123456789Z");
    assert_eq!(r.identity_until, "2026-10-07T00:20:30.123456789Z");
    let stored = store
        .get_authorized(id, authority(&p)?, ctx())
        .await?
        .ok_or("historical")?;
    let raw: Value = serde_json::from_slice(&stored.raw.ok_or("raw")?)?;
    assert_eq!(raw["valid_until"], "2026-10-07T00:06:00Z");
    assert_eq!(raw["last_verified_at"], "2026-10-07T00:05:00Z");
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn future_skew_nanosecond_boundary_rejects_before_mutation() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let future = |v: &mut Value, time: &str| {
        v["last_verified_at"] = json!(time);
        v["provenance"]["observed_at"] = json!(time);
        v["valid_until"] = json!("2026-10-07T00:06:32Z");
    };
    assert!(matches!(
        store
            .submit(
                altered(&p, |v| future(v, "2026-10-07T00:05:32.000000001Z"))?,
                intake(&p, "2026-10-07T00:05:30Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::Invalid(_))
    ));
    receipt(
        store
            .submit(
                altered(&p, |v| future(v, "2026-10-07T00:05:32Z"))?,
                intake(&p, "2026-10-07T00:05:30Z")?,
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn replay_expiry_and_regression_never_renew_original_history() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    assert!(matches!(
        store
            .retry(
                r.clone(),
                submission(&p)?,
                intake(&p, "2026-10-07T00:05:29Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::ClockRegression)
    ));
    assert!(matches!(
        store
            .submit(
                altered(&p, |_| {})?,
                intake(&p, "2026-10-07T00:05:29Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::ClockRegression)
    ));
    assert_eq!(
        store
            .retry(
                r.clone(),
                submission(&p)?,
                intake(&p, "2026-10-07T00:10:29.999999999Z")?,
                ctx()
            )
            .await?,
        IntakeOutcome::Replayed(r.clone())
    );
    for time in ["2026-10-07T00:10:30Z", "2026-10-07T00:16:30Z"] {
        assert!(matches!(
            store
                .retry(r.clone(), submission(&p)?, intake(&p, time)?, ctx())
                .await,
            Err(CoverageError::ReplayWindowExpired)
        ));
    }
    assert_eq!(
        store
            .get_authorized(p.record_id(), authority(&p)?, ctx())
            .await?
            .ok_or("read")?
            .receipt,
        r
    );
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn profile_pin_is_reused_for_replay_but_never_redefined_for_new_ids() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    let f = fixture()?;
    let mut value = f["profiles"][0]["input"].clone();
    value["max_interval_seconds"] = json!(7200);
    let profile = ProfileDefinition::parse(&serde_json::to_vec(&value)?)?;
    let context = IntakeContext::new(
        authority(&p)?,
        clock("2026-10-07T00:05:31Z")?,
        Some(profile),
        policy()?,
    );
    assert_eq!(
        store
            .submit(submission(&p)?, context.clone(), ctx())
            .await?,
        IntakeOutcome::Replayed(r)
    );
    assert!(matches!(
        store.submit(altered(&p, |_| {})?, context, ctx()).await,
        Err(CoverageError::ProfileRevisionConflict)
    ));
    assert!(matches!(
        store
            .submit(
                altered(&p, |_| {})?,
                IntakeContext::new(
                    authority(&p)?,
                    clock("2026-10-07T00:05:31Z")?,
                    None,
                    policy()?
                ),
                ctx()
            )
            .await,
        Err(CoverageError::ProfileUnavailable)
    ));
    assert!(matches!(
        store
            .submit(
                altered(&p, |_| {})?,
                IntakeContext::new(
                    authority(&p)?,
                    clock("2026-10-07T00:05:31Z")?,
                    Some(p.profile.clone()),
                    IntakePolicy::new(60, 0, 300, 600)?
                ),
                ctx()
            )
            .await,
        Err(CoverageError::Invalid(_))
    ));
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn old_receipt_cannot_admit_missing_or_divergent_restored_history() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("original")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    store.shutdown(ctx()).await?;
    let restored = initialize(&t.path().join("missing")).await?;
    assert!(matches!(
        restored
            .retry(
                r.clone(),
                submission(&p)?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::HistoryUnavailable)
    ));
    assert_eq!(restored.metrics().committed_sequence, 0);
    // Same history ID, same producer bytes and position, but changed committed metadata/prefix.
    receipt(
        restored
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:31Z")?, ctx())
            .await?,
    )?;
    assert!(matches!(
        restored
            .retry(
                r,
                submission(&p)?,
                intake(&p, "2026-10-07T00:05:32Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::ReceiptMismatch)
    ));
    assert_eq!(restored.metrics().committed_sequence, 1);
    restored.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn receipt_shape_and_every_original_field_are_checked() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let r = receipt(
        store
            .submit(submission(&p)?, intake(&p, "2026-10-07T00:05:30Z")?, ctx())
            .await?,
    )?;
    for field in [
        "content_sha256",
        "prefix_digest",
        "profile_fingerprint",
        "authority_revision",
        "accepted_at",
        "replay_until",
        "identity_until",
        "correction_of",
    ] {
        let mut value = serde_json::to_value(&r)?;
        value[field] = match field {
            "authority_revision" => json!("different"),
            "accepted_at" | "replay_until" | "identity_until" => {
                json!("2026-10-07T00:05:31.000000000Z")
            }
            "correction_of" => json!(Uuid::new_v4()),
            _ => json!("0".repeat(64)),
        };
        let forged: Receipt = serde_json::from_value(value)?;
        assert!(
            matches!(
                store
                    .retry(
                        forged,
                        submission(&p)?,
                        intake(&p, "2026-10-07T00:05:31Z")?,
                        ctx()
                    )
                    .await,
                Err(CoverageError::ReceiptMismatch)
            ),
            "{field}"
        );
    }
    let mut wrong = r.clone();
    wrong.history_id = Uuid::new_v4();
    assert!(matches!(
        store
            .retry(
                wrong,
                submission(&p)?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::HistoryUnavailable)
    ));
    let mut future = r.clone();
    future.sequence = "2".into();
    assert!(matches!(
        store
            .retry(
                future,
                submission(&p)?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::HistoryUnavailable)
    ));
    for sequence in [
        "0",
        "01",
        "-1",
        "18446744073709551616",
        "111111111111111111111",
    ] {
        let mut wrong = r.clone();
        wrong.sequence = sequence.into();
        let rejected = store.metrics().rejected;
        assert!(matches!(
            store
                .retry(
                    wrong,
                    submission(&p)?,
                    intake(&p, "2026-10-07T00:05:31Z")?,
                    ctx()
                )
                .await,
            Err(CoverageError::Invalid(_))
        ));
        assert_eq!(store.metrics().rejected, rejected + 1);
    }
    let rejected = store.metrics().rejected;
    let mut wrong = r.clone();
    wrong.record_id = Uuid::new_v4();
    assert!(matches!(
        store
            .retry(
                wrong,
                submission(&p)?,
                intake(&p, "2026-10-07T00:05:31Z")?,
                ctx()
            )
            .await,
        Err(CoverageError::ReceiptMismatch)
    ));
    assert_eq!(store.metrics().rejected, rejected + 1);
    let mut value = serde_json::to_value(&r)?;
    value["extra"] = json!(true);
    assert!(serde_json::from_value::<Receipt>(value).is_err());
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[test]
fn finite_policy_and_input_bounds_use_checked_nanos_preserving_time() -> TestResult {
    for values in [
        (0, 0, 1, 1),
        (1, 301, 500, 500),
        (60, 2, 62, 63),
        (60, 2, 300, 299),
        (u32::MAX, 0, u32::MAX, u32::MAX),
    ] {
        assert!(IntakePolicy::new(values.0, values.1, values.2, values.3).is_err());
    }
    let maximum = IntakePolicy::new(1, 0, u32::MAX, u32::MAX)?;
    assert!(
        maximum
            .admission(clock("9999-12-31T23:59:59Z")?, "rev".into())
            .is_err()
    );
    let p = sample()?;
    for raw in [&b""[..], &vec![b' '; 65_537][..]] {
        assert!(CoverageSubmission::new(p.record_id(), raw, None).is_err());
    }
    assert!(CoverageSubmission::new(Uuid::nil(), &p.raw, None).is_err());
    assert!(CoverageSubmission::new(p.record_id(), &p.raw, Some(Uuid::nil())).is_err());
    for revision in [
        "".into(),
        " ".into(),
        "line\nbreak".into(),
        "a".repeat(1025),
    ] {
        assert!(
            AuthorizedBinding::new(p.binding.observer_id(), p.binding.clone(), revision).is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn valid_nongreen_assertions_are_retained_without_health_inference() -> TestResult {
    let t = tempfile::tempdir()?;
    let p = sample()?;
    let store = initialize(&t.path().join("coverage")).await?;
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/source-coverage/contract.json"
    ))?;
    for (index, status) in ["failed", "partial", "unknown", "unsupported"]
        .into_iter()
        .enumerate()
    {
        let case = f["record_cases"]
            .as_array()
            .ok_or("cases")?
            .iter()
            .find(|c| {
                c["record"]["validation_status"] == status && c["expected_semantics"] == "valid"
            })
            .ok_or("valid nongreen case")?;
        let raw = serde_json::to_vec(&case["record"])?;
        let (binding, times) = HistoryBinding::from_record(&raw)?;
        let grant = AuthorizedBinding::new(
            binding.observer_id(),
            binding.clone(),
            "fixture-authority-v1".into(),
        )?;
        let profile = f["profiles"]
            .as_array()
            .ok_or("profiles")?
            .iter()
            .find(|v| {
                v["id"] == case["record"]["coverage_profile"]["id"]
                    && v["revision"] == case["record"]["coverage_profile"]["revision"]
            })
            .ok_or("profile")?;
        let outcome = receipt(
            store
                .submit(
                    CoverageSubmission::new(times.id, &raw, None)?,
                    IntakeContext::new(
                        grant.clone(),
                        clock("2026-10-07T00:06:00Z")?,
                        Some(ProfileDefinition::parse(&serde_json::to_vec(profile)?)?),
                        policy()?,
                    ),
                    ctx(),
                )
                .await?,
        )?;
        assert_eq!(outcome.sequence, (index + 1).to_string());
        assert_eq!(
            store
                .get_authorized(times.id, grant, ctx())
                .await?
                .ok_or("stored")?
                .raw,
            Some(raw)
        );
    }
    // The ordinary positive fixture was not consumed by selecting only green results.
    assert!(
        store
            .get_authorized(p.record_id(), authority(&p)?, ctx())
            .await?
            .is_none()
    );
    store.shutdown(ctx()).await?;
    Ok(())
}

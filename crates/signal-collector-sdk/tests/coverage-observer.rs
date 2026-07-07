use serde_json::{Value, json};
use signal_collector_sdk::{
    ExtensionContext, ExtensionError,
    coverage::{CoverageProfile, CoverageReason, CoverageStatus, MAX_RECORD_BYTES, observer::*},
};
use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/source-coverage/contract.json"
    ))?)
}
fn setup() -> TestResult<(CoverageObserver, Value, Value)> {
    let f = fixture()?;
    let profile = CoverageProfile::parse(&serde_json::to_vec(&f["profiles"][0])?)?;
    let context = f["assessment_cases"][0]["context"].clone();
    let record = f["record_cases"][0]["record"].clone();
    Ok((
        CoverageObserver::new(profile, &bytes(&context)?)?,
        context,
        record,
    ))
}
fn bytes(value: &Value) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
fn ctx() -> TestResult<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(5),
    )?)
}
enum Mode {
    Report(Vec<u8>),
    Failure(ProbeFailure),
    Stall,
}
struct Probe {
    mode: Mode,
    calls: AtomicUsize,
    started: Notify,
    dropped: AtomicBool,
}
impl Probe {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            dropped: AtomicBool::new(false),
        }
    }
    fn report(v: &Value) -> TestResult<Self> {
        Ok(Self::new(Mode::Report(bytes(v)?)))
    }
}
struct DropFlag<'a>(&'a AtomicBool);
impl Drop for DropFlag<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[signal_collector_sdk::extension]
impl CoverageProbe for Probe {
    async fn probe(
        &self,
        request: &ProbeRequest<'_>,
        _: &ExtensionContext,
    ) -> Result<ProbeReport, ProbeFailure> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let _drop = DropFlag(&self.dropped);
        self.started.notify_one();
        if request.profile().id() != "fixture-basic"
            || request.context_bytes().len() > MAX_RECORD_BYTES
        {
            return Err(ProbeFailure::Unsupported);
        }
        match &self.mode {
            Mode::Report(raw) => ProbeReport::new(raw).map_err(|_| ProbeFailure::Unavailable),
            Mode::Failure(error) => Err(*error),
            Mode::Stall => std::future::pending().await,
        }
    }
}
fn next_id(v: &mut Value) {
    v["record_id"] = "ecf5f7a0-a788-4e02-b8ee-b924e3e8bf4c".into();
}
#[test]
fn report_bounds_and_trusted_profile_scope_precede_any_probe() -> TestResult {
    assert!(ProbeReport::new(&[]).is_err());
    assert!(ProbeReport::new(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
    assert!(ProbeReport::new(&vec![0; MAX_RECORD_BYTES]).is_ok());
    let f = fixture()?;
    let profile = CoverageProfile::parse(&bytes(&f["profiles"][0])?)?;
    let mut c = f["assessment_cases"][0]["context"].clone();
    c["binding"]["coverage_profile"]["revision"] = "different".into();
    assert!(matches!(
        CoverageObserver::new(profile, &bytes(&c)?),
        Err(ObserverError::Scope)
    ));
    Ok(())
}
#[tokio::test]
async fn silence_requires_independent_proof_and_observer_owned_health() -> TestResult {
    let (mut observer, mut context, record) = setup()?;
    assert_eq!(observer.health(), ObserverHealth::Unknown);
    assert_eq!(observer.retained_bytes(), 0);
    let a = observer.assess(&bytes(&context)?)?;
    assert_eq!(a.status(), CoverageStatus::Unknown);
    assert_eq!(a.reason_codes(), &[CoverageReason::ObserverUnknown]);
    let probe = Probe::report(&record)?;
    let result = observer.poll(&probe, &bytes(&context)?, &ctx()?).await?;
    assert_eq!(result.assessment().status(), CoverageStatus::Verified);
    assert_eq!(observer.health(), ObserverHealth::Healthy);
    assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
    context["observer_status"] = "unhealthy".into();
    assert_eq!(
        observer.assess(&bytes(&context)?)?.status(),
        CoverageStatus::Verified
    );
    let unavailable = Probe::new(Mode::Failure(ProbeFailure::Unavailable));
    assert!(matches!(
        observer
            .poll(&unavailable, &bytes(&context)?, &ctx()?)
            .await,
        Err(ObserverError::Probe(ProbeFailure::Unavailable))
    ));
    context["observer_status"] = "healthy".into();
    assert_eq!(
        observer.assess(&bytes(&context)?)?.reason_codes(),
        &[CoverageReason::ObserverUnhealthy]
    );
    assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
    Ok(())
}
#[tokio::test]
async fn later_data_and_report_time_never_renew_equal_verification() -> TestResult {
    let (mut observer, mut context, record) = setup()?;
    observer
        .poll(&Probe::report(&record)?, &bytes(&context)?, &ctx()?)
        .await?;
    let mut later = record.clone();
    later["last_observed_at"] = "2026-10-07T00:05:40Z".into();
    later["provenance"]["observed_at"] = "2026-10-07T00:05:40Z".into();
    next_id(&mut later);
    context["at"] = "2026-10-07T00:05:45Z".into();
    observer
        .poll(&Probe::report(&later)?, &bytes(&context)?, &ctx()?)
        .await?;
    assert_eq!(observer.latest_bytes(), Some(bytes(&later)?.as_slice()));
    context["at"] = "2026-10-07T00:06:00Z".into();
    assert_eq!(
        observer.assess(&bytes(&context)?)?.reason_codes(),
        &[CoverageReason::Expired]
    );
    let mut renewed = later.clone();
    renewed["valid_until"] = "2026-10-07T00:06:01Z".into();
    next_id(&mut renewed);
    assert!(matches!(
        observer
            .poll(&Probe::report(&renewed)?, &bytes(&context)?, &ctx()?)
            .await,
        Err(ObserverError::Validation(_))
    ));
    assert_eq!(observer.latest_bytes(), Some(bytes(&later)?.as_slice()));
    Ok(())
}
#[tokio::test]
async fn equal_verification_pins_claims_and_new_verification_changes_them() -> TestResult {
    let (_, context, record) = setup()?;
    let mut changes = Vec::new();
    let mut v = record.clone();
    v["checkpoint"]["value"] = "next-position".into();
    changes.push(v);
    let mut v = record.clone();
    v["coverage_start"] = "2026-10-06T23:59:59Z".into();
    changes.push(v);
    let mut v = record.clone();
    v["valid_until"] = "2026-10-07T00:05:59Z".into();
    changes.push(v);
    let mut v = record.clone();
    v["provenance"]["proof_refs"] = json!(["fixture://new-proof"]);
    changes.push(v);
    let mut v = record.clone();
    v["provenance"]["method"] = "different-probe".into();
    changes.push(v);
    let mut v = record.clone();
    v["validation"]["continuity"] = "unknown".into();
    v["validation_status"] = "unknown".into();
    changes.push(v);
    for mut v in changes {
        next_id(&mut v);
        let (mut observer, _, _) = setup()?;
        observer
            .poll(&Probe::report(&record)?, &bytes(&context)?, &ctx()?)
            .await?;
        assert!(matches!(
            observer
                .poll(&Probe::report(&v)?, &bytes(&context)?, &ctx()?)
                .await,
            Err(ObserverError::ChangedClaims)
        ));
        assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
        v["last_verified_at"] = "2026-10-07T00:05:01Z".into();
        v["provenance"]["observed_at"] = "2026-10-07T00:05:01Z".into();
        observer
            .poll(&Probe::report(&v)?, &bytes(&context)?, &ctx()?)
            .await?;
        assert_eq!(observer.latest_bytes(), Some(bytes(&v)?.as_slice()));
    }
    Ok(())
}
#[tokio::test]
async fn foreign_malformed_future_regressed_reports_keep_prior_bytes() -> TestResult {
    let (_, context, record) = setup()?;
    let mut cases = Vec::new();
    for (key, value) in [
        ("source_id", "other-source"),
        ("collection_config_revision", "revoked"),
        ("expected_stream", "other-stream"),
    ] {
        let mut v = record.clone();
        v[key] = value.into();
        cases.push(bytes(&v)?);
    }
    let mut v = record.clone();
    v["provenance"]["observer_id"] = "another-observer".into();
    cases.push(bytes(&v)?);
    let mut v = record.clone();
    v["last_verified_at"] = "2026-10-07T00:05:40Z".into();
    v["provenance"]["observed_at"] = "2026-10-07T00:05:40Z".into();
    v["valid_until"] = "2026-10-07T00:06:00Z".into();
    cases.push(bytes(&v)?);
    let mut v = record.clone();
    v["coverage_end"] = "2026-10-07T00:04:59Z".into();
    v["last_verified_at"] = "2026-10-07T00:04:59Z".into();
    v["valid_until"] = "2026-10-07T00:05:59Z".into();
    cases.push(bytes(&v)?);
    cases.push(b"{malformed-secret-never-echo".to_vec());
    for raw in cases {
        let (mut observer, _, _) = setup()?;
        observer
            .poll(&Probe::report(&record)?, &bytes(&context)?, &ctx()?)
            .await?;
        assert!(
            observer
                .poll(&Probe::new(Mode::Report(raw)), &bytes(&context)?, &ctx()?)
                .await
                .is_err()
        );
        assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
        assert_eq!(observer.health(), ObserverHealth::Unhealthy);
    }
    Ok(())
}
#[tokio::test]
async fn cancelled_or_timed_out_probe_is_dropped_without_evidence_mutation() -> TestResult {
    for cancel in [false, true] {
        let (mut observer, context, record) = setup()?;
        observer
            .poll(&Probe::report(&record)?, &bytes(&context)?, &ctx()?)
            .await?;
        let probe = Probe::new(Mode::Stall);
        let token = CancellationToken::new();
        let operation = ExtensionContext::new(token.clone(), Duration::from_millis(30))?;
        let request = bytes(&context)?;
        let result = if cancel {
            let (r, _) = tokio::join!(observer.poll(&probe, &request, &operation), async {
                probe.started.notified().await;
                token.cancel();
            });
            r
        } else {
            observer.poll(&probe, &request, &operation).await
        };
        assert!(matches!(
            result,
            Err(ObserverError::Operation(
                ExtensionError::Cancelled | ExtensionError::Timeout
            ))
        ));
        assert!(probe.dropped.load(Ordering::Acquire));
        assert_eq!(probe.calls.load(Ordering::Acquire), 1);
        assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
        assert_eq!(
            observer.assess(&request)?.reason_codes(),
            &[CoverageReason::ObserverUnhealthy]
        );
    }
    Ok(())
}
#[tokio::test]
async fn dropped_poll_stays_unknown_and_exact_replay_recovers_health() -> TestResult {
    let (mut observer, context, record) = setup()?;
    let request = bytes(&context)?;
    observer
        .poll(&Probe::report(&record)?, &request, &ctx()?)
        .await?;
    let probe = Probe::new(Mode::Stall);
    let operation = ctx()?;
    let mut polling = Box::pin(observer.poll(&probe, &request, &operation));
    tokio::select! {result=&mut polling=>{result?;return Err("probe unexpectedly completed".into());},_=probe.started.notified()=>()}
    drop(polling);
    assert!(probe.dropped.load(Ordering::Acquire));
    assert_eq!(observer.health(), ObserverHealth::Unknown);
    assert_eq!(
        observer.assess(&request)?.reason_codes(),
        &[CoverageReason::ObserverUnknown]
    );
    assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
    observer
        .poll(&Probe::report(&record)?, &request, &ctx()?)
        .await?;
    assert_eq!(
        observer.assess(&request)?.status(),
        CoverageStatus::Verified
    );
    Ok(())
}
#[tokio::test]
async fn rejected_request_never_dispatches_or_overwrites_current_scope() -> TestResult {
    let (mut observer, mut context, record) = setup()?;
    observer
        .poll(&Probe::report(&record)?, &bytes(&context)?, &ctx()?)
        .await?;
    let probe = Probe::report(&record)?;
    context["binding"]["collection_config_revision"] = "revoked".into();
    assert!(matches!(
        observer.poll(&probe, &bytes(&context)?, &ctx()?).await,
        Err(ObserverError::Scope)
    ));
    assert_eq!(probe.calls.load(Ordering::Acquire), 0);
    assert_eq!(observer.health(), ObserverHealth::Healthy);
    assert!(matches!(
        observer.assess(&bytes(&context)?),
        Err(ObserverError::Scope)
    ));
    assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
    Ok(())
}
#[tokio::test]
async fn retained_record_id_accepts_only_exact_original_bytes() -> TestResult {
    let (mut observer, context, record) = setup()?;
    let request = bytes(&context)?;
    observer
        .poll(&Probe::report(&record)?, &request, &ctx()?)
        .await?;
    for (n, mut changed) in [record.clone(), record.clone()].into_iter().enumerate() {
        if n == 1 {
            changed["last_verified_at"] = "2026-10-07T00:05:01Z".into();
        }
        changed["last_observed_at"] = "2026-10-07T00:05:10Z".into();
        changed["provenance"]["observed_at"] = "2026-10-07T00:05:10Z".into();
        assert!(matches!(
            observer
                .poll(&Probe::report(&changed)?, &request, &ctx()?)
                .await,
            Err(ObserverError::IdentityConflict)
        ));
        assert_eq!(observer.latest_bytes(), Some(bytes(&record)?.as_slice()));
    }
    observer
        .poll(&Probe::report(&record)?, &request, &ctx()?)
        .await?;
    Ok(())
}

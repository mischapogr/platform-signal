use crate::{
    format::{HistoryBinding, ProfileDefinition},
    intake_tests::{authority, intake},
    tests::{TestResult, clock, fixture, prepared},
    *,
};
use serde_json::{Value, json};
use signal_collector_sdk::{
    ExtensionContext,
    coverage::{CoverageProfile, CoverageStatus, observer::*},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
struct Provider {
    intake: IntakeContext,
    calls: AtomicUsize,
    denied: AtomicBool,
    stall: bool,
    started: Notify,
}
#[signal_collector_sdk::extension]
impl CoverageIntakeProvider for Provider {
    async fn current(&self, _: &ExtensionContext) -> Result<IntakeContext, ProbeFailure> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.started.notify_one();
        if self.stall {
            std::future::pending::<()>().await;
        }
        if self.denied.load(Ordering::Acquire) {
            return Err(ProbeFailure::Denied);
        }
        Ok(self.intake.clone())
    }
}
fn provider(p: &PreparedObservation) -> TestResult<Arc<Provider>> {
    Ok(Arc::new(Provider {
        intake: intake(p, "2026-10-07T00:05:30Z")?,
        calls: AtomicUsize::new(0),
        denied: AtomicBool::new(false),
        stall: false,
        started: Notify::new(),
    }))
}
struct Probe(Vec<u8>);
#[signal_collector_sdk::extension]
impl CoverageProbe for Probe {
    async fn probe(
        &self,
        _: &ProbeRequest<'_>,
        _: &ExtensionContext,
    ) -> Result<ProbeReport, ProbeFailure> {
        ProbeReport::new(&self.0).map_err(|_| ProbeFailure::Malformed)
    }
}
fn sample() -> TestResult<PreparedObservation> {
    let f = fixture()?;
    prepared(&f["chains"][0]["commits"][0], &f)
}
fn context(p: &PreparedObservation) -> TestResult<Vec<u8>> {
    let r: Value = serde_json::from_slice(&p.raw)?;
    Ok(serde_json::to_vec(
        &json!({"at":"2026-10-07T00:05:30Z","mode":"current","observer_status":"healthy","observer_id":r["provenance"]["observer_id"],
        "binding":{"source_id":r["source_id"],"collector_id":r["collector_id"],"resource_scope":r["resource_scope"],"expected_stream":r["expected_stream"],
            "coverage_profile":r["coverage_profile"],"collection_config_revision":r["collection_config_revision"]},
        "interval":{"start":r["coverage_start"],"end":r["coverage_end"]}}),
    )?)
}
fn ctx() -> TestResult<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(10),
    )?)
}
fn operation() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
async fn store(path: &std::path::Path) -> TestResult<Arc<CoverageStore>> {
    Ok(Arc::new(
        CoverageStore::initialize(
            CoverageConfig {
                directory: path.into(),
                ..Default::default()
            },
            Uuid::new_v4(),
            clock("2026-10-07T00:05:29Z")?,
        )
        .await?,
    ))
}
#[tokio::test]
async fn observer_physical_admission_and_replay_keep_exact_pins_and_receipts() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    let provider = provider(&p)?;
    let sink = HistoryReportSink::new(store.clone(), provider.clone());
    let raw = context(&p)?;
    let probe = Probe(p.raw.clone());
    let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    let result = observer
        .poll_persisted(&probe, &sink, &raw, &ctx()?)
        .await?;
    assert_eq!(result.commit(), Some(ReportCommit::Accepted));
    assert_eq!(result.assessment().status(), CoverageStatus::Verified);
    let original = store
        .get_authorized(p.record_id(), authority(&p)?, operation())
        .await?
        .ok_or("original")?;
    assert_eq!(original.raw.as_deref(), Some(p.raw.as_slice()));
    assert_eq!(original.profile.fingerprint(), p.profile.fingerprint());
    let mut restarted_observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    assert_eq!(
        restarted_observer
            .poll_persisted(&probe, &sink, &raw, &ctx()?)
            .await?
            .commit(),
        Some(ReportCommit::Replayed)
    );
    assert_eq!(restarted_observer.health(), ObserverHealth::Unknown);
    assert_eq!(store.metrics().committed_sequence, 1);
    assert_eq!(store.metrics().accepted, 1);
    assert_eq!(store.metrics().replayed, 1);
    let replay = store
        .get_authorized(p.record_id(), authority(&p)?, operation())
        .await?
        .ok_or("replay")?;
    assert_eq!(original.receipt, replay.receipt);
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn global_older_identity_conflict_prevents_cache_or_health_adoption() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    let sink = HistoryReportSink::new(store.clone(), provider(&p)?);
    let raw = context(&p)?;
    let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    observer
        .poll_persisted(&Probe(p.raw.clone()), &sink, &raw, &ctx()?)
        .await?;
    let mut next: Value = serde_json::from_slice(&p.raw)?;
    next["record_id"] = json!(Uuid::new_v4());
    let next = serde_json::to_vec(&next)?;
    observer
        .poll_persisted(&Probe(next.clone()), &sink, &raw, &ctx()?)
        .await?;
    let mut conflict: Value = serde_json::from_slice(&p.raw)?;
    conflict["last_observed_at"] = "2026-10-07T00:04:59Z".into();
    let conflict = serde_json::to_vec(&conflict)?;
    let rejected = store.metrics().rejected;
    assert!(matches!(
        observer
            .poll_persisted(&Probe(conflict), &sink, &raw, &ctx()?)
            .await,
        Err(ObserverError::Probe(ProbeFailure::Malformed))
    ));
    assert_eq!(observer.latest_bytes(), Some(next.as_slice()));
    assert_eq!(observer.health(), ObserverHealth::Unhealthy);
    assert_eq!(store.metrics().committed_sequence, 2);
    assert_eq!(store.metrics().rejected, rejected + 1);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn each_side_effect_refreshes_authority_and_denial_retains_old_cache() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    let provider = provider(&p)?;
    let sink = HistoryReportSink::new(store.clone(), provider.clone());
    let raw = context(&p)?;
    let probe = Probe(p.raw.clone());
    let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    observer
        .poll_persisted(&probe, &sink, &raw, &ctx()?)
        .await?;
    provider.denied.store(true, Ordering::Release);
    assert!(matches!(
        observer.poll_persisted(&probe, &sink, &raw, &ctx()?).await,
        Err(ObserverError::Probe(ProbeFailure::Denied))
    ));
    assert_eq!(observer.latest_bytes(), Some(p.raw.as_slice()));
    assert_eq!(observer.health(), ObserverHealth::Unhealthy);
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn retired_new_write_profile_permits_retained_replay_without_health_healing() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    let raw = context(&p)?;
    let probe = Probe(p.raw.clone());
    let sink = HistoryReportSink::new(store.clone(), provider(&p)?);
    let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    observer
        .poll_persisted(&probe, &sink, &raw, &ctx()?)
        .await?;
    let mut retired = intake(&p, "2026-10-07T00:05:31Z")?;
    retired.profile = None;
    let retired = Arc::new(Provider {
        intake: retired,
        calls: AtomicUsize::new(0),
        denied: AtomicBool::new(false),
        stall: false,
        started: Notify::new(),
    });
    let sink = HistoryReportSink::new(store.clone(), retired);
    let mut restarted = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    assert_eq!(
        restarted
            .poll_persisted(&probe, &sink, &raw, &ctx()?)
            .await?
            .commit(),
        Some(ReportCommit::Replayed)
    );
    assert_eq!(restarted.health(), ObserverHealth::Unknown);
    let mut new: Value = serde_json::from_slice(&p.raw)?;
    new["record_id"] = json!(Uuid::new_v4());
    assert!(matches!(
        restarted
            .poll_persisted(&Probe(serde_json::to_vec(&new)?), &sink, &raw, &ctx()?)
            .await,
        Err(ObserverError::Probe(ProbeFailure::Unavailable))
    ));
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn original_pinned_profile_is_required_even_for_retired_replay() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    assert_eq!(
        HistoryReportSink::new(store.clone(), provider(&p)?)
            .commit(&p.raw, &p.profile.sdk, &ctx()?)
            .await?,
        ReportCommit::Accepted
    );
    let mut retired = intake(&p, "2026-10-07T00:05:31Z")?;
    retired.profile = None;
    let sink = HistoryReportSink::new(
        store.clone(),
        Arc::new(Provider {
            intake: retired,
            calls: AtomicUsize::new(0),
            denied: AtomicBool::new(false),
            stall: false,
            started: Notify::new(),
        }),
    );
    let mut changed: Value = serde_json::from_slice(&p.profile.sdk.definition_bytes()?)?;
    changed["max_verification_age_seconds"] = json!(61);
    let alias = CoverageProfile::parse(&serde_json::to_vec(&changed)?)?;
    assert!(matches!(
        sink.commit(&p.raw, &alias, &ctx()?).await,
        Err(ProbeFailure::Denied)
    ));
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn changed_profile_or_binding_never_reaches_physical_admission() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    for profile_case in [false, true] {
        let mut decision = intake(&p, "2026-10-07T00:05:30Z")?;
        if profile_case {
            let mut changed: Value = serde_json::from_slice(&p.profile.sdk.definition_bytes()?)?;
            changed["max_verification_age_seconds"] = json!(61);
            decision.profile = Some(ProfileDefinition::parse(&serde_json::to_vec(&changed)?)?);
        } else {
            let mut record: Value = serde_json::from_slice(&p.raw)?;
            record["collector_id"] = "foreign".into();
            let (binding, _) = HistoryBinding::from_record(&serde_json::to_vec(&record)?)?;
            decision.authority =
                AuthorizedBinding::new(binding.observer_id(), binding.clone(), "new".into())?;
        }
        let sink = HistoryReportSink::new(
            store.clone(),
            Arc::new(Provider {
                intake: decision,
                calls: AtomicUsize::new(0),
                denied: AtomicBool::new(false),
                stall: false,
                started: Notify::new(),
            }),
        );
        assert!(matches!(
            sink.commit(&p.raw, &p.profile.sdk, &ctx()?).await,
            Err(ProbeFailure::Denied)
        ));
        assert_eq!(store.metrics().committed_sequence, 0);
    }
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn quota_does_not_promote_new_observation_or_evict_retained_replay() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = Arc::new(
        CoverageStore::initialize(
            CoverageConfig {
                directory: temp.path().join("coverage"),
                max_payloads: 1,
                max_identities: 1,
                max_bindings: 1,
                ..Default::default()
            },
            Uuid::new_v4(),
            clock("2026-10-07T00:05:29Z")?,
        )
        .await?,
    );
    let sink = HistoryReportSink::new(store.clone(), provider(&p)?);
    let raw = context(&p)?;
    let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    observer
        .poll_persisted(&Probe(p.raw.clone()), &sink, &raw, &ctx()?)
        .await?;
    let mut new: Value = serde_json::from_slice(&p.raw)?;
    new["record_id"] = json!(Uuid::new_v4());
    assert!(matches!(
        observer
            .poll_persisted(&Probe(serde_json::to_vec(&new)?), &sink, &raw, &ctx()?)
            .await,
        Err(ObserverError::Probe(ProbeFailure::Throttled))
    ));
    observer
        .poll_persisted(&Probe(p.raw.clone()), &sink, &raw, &ctx()?)
        .await?;
    assert_eq!(observer.health(), ObserverHealth::Unhealthy);
    assert_eq!(observer.latest_bytes(), Some(p.raw.as_slice()));
    assert_eq!(store.metrics().committed_sequence, 1);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn malformed_and_expired_or_cancelled_work_do_not_consult_authority() -> TestResult {
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let store = store(&temp.path().join("coverage")).await?;
    let provider = provider(&p)?;
    let sink = HistoryReportSink::new(store.clone(), provider.clone());
    assert!(matches!(
        sink.commit(b"{}", &p.profile.sdk, &ctx()?).await,
        Err(ProbeFailure::Malformed)
    ));
    let cancelled = ctx()?;
    cancelled.cancellation().cancel();
    assert!(matches!(
        sink.commit(&p.raw, &p.profile.sdk, &cancelled).await,
        Err(ProbeFailure::Unavailable)
    ));
    let expired = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(1))?;
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert!(matches!(
        sink.commit(&p.raw, &p.profile.sdk, &expired).await,
        Err(ProbeFailure::Unavailable)
    ));
    assert_eq!(provider.calls.load(Ordering::Acquire), 0);
    assert_eq!(store.metrics().committed_sequence, 0);
    store.shutdown(operation()).await?;
    Ok(())
}
#[tokio::test]
async fn pending_authority_cancels_expires_or_drops_before_physical_intake() -> TestResult {
    for mode in ["cancel", "deadline", "drop"] {
        let temp = tempfile::tempdir()?;
        let p = sample()?;
        let store = store(&temp.path().join("coverage")).await?;
        let provider = Arc::new(Provider {
            intake: intake(&p, "2026-10-07T00:05:30Z")?,
            calls: AtomicUsize::new(0),
            denied: AtomicBool::new(false),
            stall: true,
            started: Notify::new(),
        });
        let sink = HistoryReportSink::new(store.clone(), provider.clone());
        let raw = context(&p)?;
        let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
        let context = ExtensionContext::new(
            CancellationToken::new(),
            Duration::from_millis(if mode == "deadline" { 200 } else { 10000 }),
        )?;
        let probe = Probe(p.raw.clone());
        {
            let work = observer.poll_persisted(&probe, &sink, &raw, &context);
            tokio::pin!(work);
            tokio::select! { result=&mut work=>return Err(format!("early result: {}",result.is_ok()).into()), _=provider.started.notified()=>{} }
            match mode {
                "cancel" => {
                    context.cancellation().cancel();
                    assert!(work.await.is_err());
                }
                "deadline" => assert!(work.await.is_err()),
                _ => {}
            }
        }
        assert!(observer.latest_bytes().is_none());
        assert_eq!(
            observer.health(),
            if mode == "drop" {
                ObserverHealth::Unknown
            } else {
                ObserverHealth::Unhealthy
            }
        );
        assert_eq!(provider.calls.load(Ordering::Acquire), 1);
        assert_eq!(store.metrics().committed_sequence, 0);
        store.shutdown(operation()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn physical_history_restart_keeps_original_receipt_and_observer_health_unknown() -> TestResult
{
    let temp = tempfile::tempdir()?;
    let p = sample()?;
    let path = temp.path().join("coverage");
    let store = store(&path).await?;
    let sink = HistoryReportSink::new(store.clone(), provider(&p)?);
    sink.commit(&p.raw, &p.profile.sdk, &ctx()?).await?;
    let original = store
        .get_authorized(p.record_id(), authority(&p)?, operation())
        .await?
        .ok_or("original")?
        .receipt;
    store.shutdown(operation()).await?;
    drop(sink);
    drop(store);
    let reopened = Arc::new(
        CoverageStore::open(CoverageConfig {
            directory: path,
            ..Default::default()
        })
        .await?,
    );
    let sink = HistoryReportSink::new(reopened.clone(), provider(&p)?);
    let raw = context(&p)?;
    let mut observer = CoverageObserver::new(p.profile.sdk.clone(), &raw)?;
    assert_eq!(
        observer
            .poll_persisted(&Probe(p.raw.clone()), &sink, &raw, &ctx()?)
            .await?
            .commit(),
        Some(ReportCommit::Replayed)
    );
    assert_eq!(observer.health(), ObserverHealth::Unknown);
    assert_eq!(
        reopened
            .get_authorized(p.record_id(), authority(&p)?, operation())
            .await?
            .ok_or("replay")?
            .receipt,
        original
    );
    reopened.shutdown(operation()).await?;
    Ok(())
}

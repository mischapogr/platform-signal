//! Independent source truth -> observer -> real monolith HTTP/history -> local assessment.
//! Native capture/proof APIs are simulated; this is not AWS completeness qualification.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use signal_collector_sdk::{
    ExtensionContext,
    coverage::{
        CoverageContext, CoverageProfile, CoverageReason, CoverageStatus, ValidatedCoverage,
        observer::*,
    },
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
#[path = "coverage-runtime/sink.rs"]
mod sink;
#[path = "coverage-runtime/source.rs"]
mod source;
#[path = "coverage-runtime/support.rs"]
mod support;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../fixtures/source-coverage/backend-vectors.json"
    ))?)
}
fn stamp(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}
fn context(truth: &source::Truth) -> TestResult<Vec<u8>> {
    let binding = fixture()?["bindings"][0]["input"].clone();
    let mut without_observer = binding.clone();
    without_observer
        .as_object_mut()
        .ok_or("binding")?
        .remove("observer_id");
    Ok(serde_json::to_vec(
        &json!({"at":stamp(chrono::Utc::now()),"mode":"current","observer_status":"healthy","observer_id":binding["observer_id"],
        "binding":without_observer,"interval":{"start":truth.interval_start,"end":truth.interval_end}}),
    )?)
}
fn observer(context: &[u8]) -> TestResult<CoverageObserver> {
    let profile =
        CoverageProfile::parse(&serde_json::to_vec(&fixture()?["profiles"][0]["input"])?)?;
    Ok(CoverageObserver::new(profile, context)?)
}
fn ctx() -> TestResult<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(2),
    )?)
}
fn initial() -> source::Truth {
    source::Truth::quiet(chrono::Utc::now() - chrono::TimeDelta::seconds(20))
}
fn advance(truth: &mut source::Truth, seconds: i64) -> TestResult {
    let at = chrono::DateTime::parse_from_rfc3339(&truth.verified_at)?.with_timezone(&chrono::Utc)
        + chrono::TimeDelta::seconds(seconds);
    truth.verified_at = stamp(at);
    truth.interval_end = stamp(at);
    Ok(())
}
#[tokio::test]
async fn independently_verified_quiet_source_and_capture_gap_ignore_ingest_success() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut server = support::Server::new(&temp.path().join("server")).await?;
    server.start().await?;
    let mut truth = initial();
    let mut simulator = source::Simulator::start(truth.clone()).await?;
    let probe = source::Probe::new(&simulator.url)?;
    let mut state = observer(&context(&truth)?)?;
    let sink = sink::HttpSink::new(&server.url)?;
    let quiet = state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(quiet.assessment().status(), CoverageStatus::Verified);
    assert_eq!(state.health(), ObserverHealth::Healthy);
    let quiet_id = quiet.record_id().to_owned();
    let quiet_row = server.record(&quiet_id).await?;
    assert_eq!(quiet_row["current_health"], "unknown");
    let quiet_raw: Value = serde_json::from_str(quiet_row["raw"].as_str().ok_or("raw")?)?;
    assert!(quiet_raw["last_observed_at"].is_null());
    assert_eq!(quiet_raw["checkpoint"]["milestone"], "capture");
    assert_eq!(quiet_raw["gap_summary"]["total"], 0);
    advance(&mut truth, 1)?;
    truth.source_enabled = false;
    simulator.change(truth.clone())?;
    let disabled = state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(disabled.assessment().status(), CoverageStatus::Failed);
    assert_eq!(state.health(), ObserverHealth::Healthy);
    let disabled_row = server.record(disabled.record_id()).await?;
    let disabled_raw: Value =
        serde_json::from_str(disabled_row["raw"].as_str().ok_or("disabled raw")?)?;
    assert_eq!(disabled_raw["validation"]["configuration"], "failed");
    advance(&mut truth, 1)?;
    truth.source_enabled = true;
    truth.expected_positions = 3;
    truth.captured_positions = vec![1, 3];
    simulator.change(truth.clone())?;
    // Successful unrelated telemetry admission must not repair missing source capture.
    let event = json!({"schema_version":1,"id":Uuid::new_v4(),"timestamp":stamp(chrono::Utc::now()),"observed_at":stamp(chrono::Utc::now()),
        "source":{"type":"application","name":"synthetic-supervision"},"severity":"info","message":"synthetic data arrived","attributes":{}});
    assert_eq!(
        support::client()?
            .post(format!("{}/v1/events", server.url))
            .bearer_auth("separate-synthetic-event-token")
            .json(&event)
            .send()
            .await?
            .status(),
        202
    );
    let gap = state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(gap.assessment().status(), CoverageStatus::Failed);
    assert_eq!(state.health(), ObserverHealth::Healthy);
    let gap_id = gap.record_id().to_owned();
    let original = server.record(&gap_id).await?;
    let raw: Value = serde_json::from_str(original["raw"].as_str().ok_or("gap raw")?)?;
    assert_eq!(raw["gaps"][0]["id"], "synthetic-source-position-2");
    assert_eq!(raw["validation"]["continuity"], "failed");
    // Backfill adds a fresh overlapping correction without mutating failed history.
    advance(&mut truth, 1)?;
    truth.captured_positions = vec![1, 2, 3];
    simulator.change(truth.clone())?;
    let mut corrected_sink = sink::HttpSink::new(&server.url)?;
    corrected_sink.correction = Some(Uuid::parse_str(&gap_id)?);
    let recovered = state
        .poll_persisted(&probe, &corrected_sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(recovered.assessment().status(), CoverageStatus::Verified);
    let recovered_row = server.record(recovered.record_id()).await?;
    assert_eq!(recovered_row["receipt"]["correction_of"], gap_id);
    assert_eq!(server.record(&gap_id).await?, original);
    let mut historical: Value = serde_json::from_slice(&context(&truth)?)?;
    historical["mode"] = "historical".into();
    historical["interval"]["end"] = raw["coverage_end"].clone();
    let profile =
        CoverageProfile::parse(original["profile_json"].as_str().ok_or("pin")?.as_bytes())?;
    assert_eq!(
        ValidatedCoverage::parse(
            original["raw"].as_str().ok_or("raw")?.as_bytes(),
            Some(&profile)
        )?
        .assess(&CoverageContext::parse(&serde_json::to_vec(&historical)?)?)
        .status(),
        CoverageStatus::Failed
    );
    simulator.stop().await?;
    server.redacted()?;
    Ok(())
}
#[tokio::test]
async fn source_outage_blind_interval_expiry_and_arrival_cannot_manufacture_healthy_silence()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let mut server = support::Server::new(&temp.path().join("server")).await?;
    server.start().await?;
    let mut truth = initial();
    let mut simulator = source::Simulator::start(truth.clone()).await?;
    let probe = source::Probe::new(&simulator.url)?;
    let mut state = observer(&context(&truth)?)?;
    let sink = sink::HttpSink::new(&server.url)?;
    state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    let original = state.latest_bytes().ok_or("original")?.to_vec();
    for fault in [
        source::Fault::Status(403),
        source::Fault::Status(429),
        source::Fault::Status(503),
        source::Fault::Malformed,
        source::Fault::Oversized,
    ] {
        simulator.fault(fault)?;
        assert!(
            state
                .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
                .await
                .is_err()
        );
        assert_eq!(state.health(), ObserverHealth::Unhealthy);
        assert_eq!(state.latest_bytes(), Some(original.as_slice()));
        let assessment = state.assess(&context(&truth)?)?;
        assert_eq!(assessment.status(), CoverageStatus::Unknown);
        assert_eq!(
            assessment.reason_codes(),
            [CoverageReason::ObserverUnhealthy]
        );
    }
    simulator.fault(source::Fault::None)?;
    advance(&mut truth, 1)?;
    truth.observer_blind = true;
    simulator.change(truth.clone())?;
    let blind = state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(state.health(), ObserverHealth::Healthy);
    assert_eq!(blind.assessment().status(), CoverageStatus::Unknown);
    let blind_id = blind.record_id().to_owned();
    let blind_row = server.record(&blind_id).await?;
    let blind_raw: Value = serde_json::from_str(blind_row["raw"].as_str().ok_or("blind")?)?;
    assert_eq!(blind_raw["gaps"][0]["reason_code"], "observer_unhealthy");
    assert_eq!(blind_raw["gaps"][0]["recoverability"], "unknown");
    advance(&mut truth, 1)?;
    truth.interval_start = blind_raw["coverage_end"].as_str().ok_or("end")?.into();
    truth.observer_blind = false;
    simulator.change(truth.clone())?;
    let recovered = state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(recovered.assessment().status(), CoverageStatus::Verified);
    assert_eq!(server.record(&blind_id).await?, blind_row);
    let fresh: Value = serde_json::from_slice(state.latest_bytes().ok_or("fresh")?)?;
    let mut future: Value = serde_json::from_slice(&context(&truth)?)?;
    future["at"] = fresh["valid_until"].clone();
    assert_eq!(
        state.assess(&serde_json::to_vec(&future)?)?.reason_codes(),
        [CoverageReason::Expired]
    );
    // A newly observed arrival and successful API intake preserve original
    // verification/expiry; neither creates a new source verification proof.
    truth.last_source_arrival = Some(stamp(chrono::Utc::now() - chrono::TimeDelta::seconds(1)));
    simulator.change(truth.clone())?;
    state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    let arrival: Value = serde_json::from_slice(state.latest_bytes().ok_or("arrival")?)?;
    assert_eq!(arrival["last_verified_at"], fresh["last_verified_at"]);
    assert_eq!(arrival["valid_until"], fresh["valid_until"]);
    assert_eq!(
        state.assess(&serde_json::to_vec(&future)?)?.status(),
        CoverageStatus::Unknown
    );
    simulator.stop().await?;
    server.redacted()?;
    Ok(())
}
#[tokio::test]
async fn lost_history_response_and_server_observer_restart_replay_exact_intent_without_healing()
-> TestResult {
    use std::sync::atomic::Ordering;
    let temp = tempfile::tempdir()?;
    let mut server = support::Server::new(&temp.path().join("server")).await?;
    server.start().await?;
    let mut truth = initial();
    let mut simulator = source::Simulator::start(truth.clone()).await?;
    let probe = source::Probe::new(&simulator.url)?;
    let mut state = observer(&context(&truth)?)?;
    let mut sink = sink::HttpSink::new(&server.url)?;
    sink.lose_response.store(true, Ordering::Release);
    assert!(
        state
            .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
            .await
            .is_err()
    );
    assert_eq!(state.health(), ObserverHealth::Unhealthy);
    assert!(state.latest_bytes().is_none());
    let pending = sink.pending()?.ok_or("pending exact report")?;
    let raw: Value = serde_json::from_slice(&pending)?;
    let id = raw["record_id"].as_str().ok_or("ID")?;
    let committed = server.record(id).await?;
    assert_eq!(committed["raw"].as_str().ok_or("raw")?.as_bytes(), pending);
    server.crash()?;
    assert!(
        state
            .poll_persisted(
                &sink::Original(pending.clone()),
                &sink,
                &context(&truth)?,
                &ctx()?
            )
            .await
            .is_err()
    );
    assert_eq!(sink.pending()?, Some(pending.clone()));
    assert_eq!(
        state.assess(&context(&truth)?)?.status(),
        CoverageStatus::Unknown
    );
    server.start().await?;
    sink.url = server.url.clone();
    let replay = state
        .poll_persisted(
            &sink::Original(pending.clone()),
            &sink,
            &context(&truth)?,
            &ctx()?,
        )
        .await?;
    assert_eq!(replay.commit(), Some(ReportCommit::Replayed));
    assert_eq!(state.health(), ObserverHealth::Unhealthy);
    assert_eq!(replay.assessment().status(), CoverageStatus::Unknown);
    assert!(sink.pending()?.is_none());
    assert_eq!(server.record(id).await?, committed);
    let mut restarted = observer(&context(&truth)?)?;
    let cold = restarted
        .poll_persisted(&sink::Original(pending), &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(cold.commit(), Some(ReportCommit::Replayed));
    assert_eq!(restarted.health(), ObserverHealth::Unknown);
    // An aliased current definition cannot reinterpret the retained receipt.
    let mut alias = fixture()?["profiles"][0]["input"].clone();
    alias["max_verification_age_seconds"] = 61.into();
    let mut aliased = CoverageObserver::new(
        CoverageProfile::parse(&serde_json::to_vec(&alias)?)?,
        &context(&truth)?,
    )?;
    let alias_sink = sink::HttpSink::new(&server.url)?;
    let retained_bytes = committed["raw"]
        .as_str()
        .ok_or("retained raw")?
        .as_bytes()
        .to_vec();
    assert!(
        aliased
            .poll_persisted(
                &sink::Original(retained_bytes),
                &alias_sink,
                &context(&truth)?,
                &ctx()?
            )
            .await
            .is_err()
    );
    assert_eq!(aliased.health(), ObserverHealth::Unhealthy);
    assert!(aliased.latest_bytes().is_none());
    assert_eq!(server.record(id).await?, committed);
    advance(&mut truth, 1)?;
    simulator.change(truth.clone())?;
    let fresh = restarted
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    assert_eq!(fresh.commit(), Some(ReportCommit::Accepted));
    assert_eq!(restarted.health(), ObserverHealth::Healthy);
    assert_eq!(fresh.assessment().status(), CoverageStatus::Verified);
    assert_eq!(server.record(id).await?, committed);
    simulator.stop().await?;
    server.redacted()?;
    Ok(())
}
#[tokio::test]
async fn source_timeout_cancellation_and_scope_denial_keep_supervision_bounded() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut server = support::Server::new(&temp.path().join("server")).await?;
    server.start().await?;
    let mut truth = initial();
    let mut simulator = source::Simulator::start(truth.clone()).await?;
    let probe = source::Probe::new(&simulator.url)?;
    let mut state = observer(&context(&truth)?)?;
    let sink = sink::HttpSink::new(&server.url)?;
    state
        .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
        .await?;
    let original = state.latest_bytes().ok_or("original")?.to_vec();
    simulator.fault(source::Fault::Stall)?;
    let short = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(30))?;
    assert!(
        state
            .poll_persisted(&probe, &sink, &context(&truth)?, &short)
            .await
            .is_err()
    );
    assert_eq!(state.health(), ObserverHealth::Unhealthy);
    assert_eq!(state.latest_bytes(), Some(original.as_slice()));
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let extension = ExtensionContext::new(cancelled, Duration::from_secs(2))?;
    assert!(
        state
            .poll_persisted(&probe, &sink, &context(&truth)?, &extension)
            .await
            .is_err()
    );
    assert_eq!(
        state.assess(&context(&truth)?)?.status(),
        CoverageStatus::Unknown
    );
    simulator.fault(source::Fault::None)?;
    truth.expected_stream = "foreign-stream".into();
    simulator.change(truth.clone())?;
    // Trusted expected stream remains the configured fixture stream.
    assert!(
        state
            .poll_persisted(&probe, &sink, &context(&truth)?, &ctx()?)
            .await
            .is_err()
    );
    assert_eq!(state.latest_bytes(), Some(original.as_slice()));
    let mut wrong = sink::HttpSink::new(&server.url)?;
    wrong.token = "wrong-scoped-credential".into();
    assert!(
        state
            .poll_persisted(
                &sink::Original(original.clone()),
                &wrong,
                &context(&truth)?,
                &ctx()?
            )
            .await
            .is_err()
    );
    assert_eq!(state.latest_bytes(), Some(original.as_slice()));
    let (_, id) = {
        let v: Value = serde_json::from_slice(&original)?;
        (v.clone(), v["record_id"].as_str().ok_or("ID")?.to_owned())
    };
    assert_eq!(
        server.record(&id).await?["raw"]
            .as_str()
            .ok_or("raw")?
            .as_bytes(),
        original
    );
    simulator.stop().await?;
    server.redacted()?;
    Ok(())
}

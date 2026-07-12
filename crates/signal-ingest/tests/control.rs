// Fixture assertions intentionally panic on malformed synthetic setup, matching
// the existing local identity/collector fixtures. Production paths have no waiver.
#![allow(clippy::unwrap_used)]

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use serde_json::json;
use signal_ingest::{
    IngestConfig, IngestService,
    control::{AuditContext, AuditFuture, AuditUnavailable, IngestAudit, IngestAuditSession},
    memory::MemorySink,
};
use signal_protocol::{
    AdmissionDisposition, EventSink, IngestResponse,
    audit::{Actor, Completion, Decision},
    verify_admission_response,
};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Copy)]
enum Mode {
    Good,
    DecisionFailure,
    CompletionFailure,
    HoldCompletion,
}

#[tokio::test]
async fn ready_completion_polled_after_original_deadline_cannot_disclose_receipt() -> Result {
    let (service, sink, state) = setup_timeout(Mode::HoldCompletion, 2, Duration::from_secs(1))?;
    let mut request_future = Box::pin(service.router().oneshot(request(Body::from(batch()), true)));
    std::future::poll_fn(|context| {
        assert!(request_future.as_mut().poll(context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(sink.metrics().accepted, 2);
    let context = state
        .context
        .lock()
        .unwrap()
        .clone()
        .ok_or("context missing")?;
    assert!(tokio::time::Instant::now() < context.deadline);
    state.release.notify_one(); // Completion is ready while its caller is unpolled.
    tokio::time::sleep_until(context.deadline + Duration::from_millis(5)).await;
    let (status, response) = decode(request_future.await?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let outcome = verify_admission_response(
        status.as_u16(),
        response,
        &[Uuid::from_u128(1), Uuid::from_u128(2)],
    )?;
    assert_eq!(outcome.accepted, 0);
    assert_eq!(outcome.disposition, AdmissionDisposition::Retry);
    assert_eq!(sink.metrics().accepted, 2);
    assert_eq!(state.incomplete.load(Ordering::Relaxed), 0);
    assert!(state.rows.lock().unwrap()[0].2 == Some(Completion::Success));
    assert_eq!(
        metric(&service, "signal_ingest_rejected_requests_total").await?,
        1
    );
    Ok(())
}
struct State {
    rows: Mutex<Vec<(Actor, Decision, Option<Completion>)>>,
    context: Mutex<Option<AuditContext>>,
    slots: Arc<Semaphore>,
    started: Notify,
    release: Notify,
    incomplete: AtomicUsize,
}
struct Probe {
    state: Arc<State>,
    sink: Arc<MemorySink>,
    mode: Mode,
}
struct Session {
    state: Arc<State>,
    _permit: OwnedSemaphorePermit,
    index: usize,
    mode: Mode,
    complete: bool,
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.complete {
            self.state.incomplete.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl IngestAudit for Probe {
    fn begin(
        &self,
        actor: Actor,
        decision: Decision,
        context: AuditContext,
    ) -> AuditFuture<'_, Box<dyn IngestAuditSession>> {
        Box::pin(async move {
            assert_eq!(
                self.sink.metrics().accepted,
                0,
                "decision before first effect"
            );
            let permit = self
                .state
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| AuditUnavailable)?;
            *self.state.context.lock().unwrap() = Some(context);
            let index = {
                let mut rows = self.state.rows.lock().unwrap();
                assert!(rows.len() < 8);
                let index = rows.len();
                rows.push((actor, decision, None));
                index
            };
            if matches!(self.mode, Mode::DecisionFailure) {
                return Err(AuditUnavailable);
            }
            Ok(Box::new(Session {
                state: self.state.clone(),
                _permit: permit,
                index,
                mode: self.mode,
                complete: false,
            }) as Box<dyn IngestAuditSession>)
        })
    }
}
impl IngestAuditSession for Session {
    fn finish(mut self: Box<Self>, completion: Completion) -> AuditFuture<'static, ()> {
        Box::pin(async move {
            self.state.rows.lock().unwrap()[self.index].2 = Some(completion);
            if matches!(self.mode, Mode::HoldCompletion) {
                self.state.started.notify_one();
                self.state.release.notified().await;
            }
            if matches!(self.mode, Mode::CompletionFailure) {
                return Err(AuditUnavailable);
            }
            self.complete = true;
            Ok(())
        })
    }
}
fn setup(mode: Mode, capacity: usize) -> Result<(IngestService, Arc<MemorySink>, Arc<State>)> {
    setup_timeout(mode, capacity, Duration::from_secs(5))
}
fn setup_timeout(
    mode: Mode,
    capacity: usize,
    request_timeout: Duration,
) -> Result<(IngestService, Arc<MemorySink>, Arc<State>)> {
    let sink = Arc::new(MemorySink::new(capacity, 65536)?);
    let state = Arc::new(State {
        rows: Mutex::new(Vec::new()),
        context: Mutex::new(None),
        slots: Arc::new(Semaphore::new(1)),
        started: Notify::new(),
        release: Notify::new(),
        incomplete: AtomicUsize::new(0),
    });
    let audit = Arc::new(Probe {
        state: state.clone(),
        sink: sink.clone(),
        mode,
    });
    let config = IngestConfig {
        api_token: Some("synthetic-bootstrap".into()),
        request_timeout,
        ..Default::default()
    };
    Ok((
        IngestService::new_with_security(config, sink.clone(), None, Some(audit))?,
        sink,
        state,
    ))
}
fn batch() -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version":1,"events":[
        {"id":Uuid::from_u128(1),"timestamp":"2026-10-01T00:00:00Z","source":{"type":"application"},"message":"synthetic-private-body"},
        {"id":Uuid::from_u128(2),"timestamp":"2026-10-01T00:00:00Z","source":{"type":"application"},"message":"synthetic-private-body"}
    ]})).unwrap()
}
fn request(body: Body, credential: bool) -> Request<Body> {
    let mut builder = Request::post("/v1/events/batch")
        .header("content-type", "application/json")
        .header("x-forwarded-user", "synthetic-forged-subject");
    if credential {
        builder = builder.header("authorization", "Bearer synthetic-bootstrap");
    }
    builder.body(body).unwrap()
}
async fn decode(response: Response) -> Result<(StatusCode, IngestResponse)> {
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}
async fn metric(service: &IngestService, name: &str) -> Result<u64> {
    let response = service
        .router()
        .oneshot(Request::get("/metrics").body(Body::empty())?)
        .await?;
    let bytes = to_bytes(response.into_body(), 32768).await?;
    let text = std::str::from_utf8(&bytes)?;
    Ok(text
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .ok_or("metric missing")?
        .parse()?)
}
#[tokio::test]
async fn confirmed_full_and_partial_receipts_remain_verifier_valid() -> Result {
    for capacity in [1, 2] {
        let (service, sink, state) = setup(Mode::Good, capacity)?;
        let (status, response) = decode(
            service
                .router()
                .oneshot(request(Body::from(batch()), true))
                .await?,
        )
        .await?;
        let outcome = verify_admission_response(
            status.as_u16(),
            response,
            &[Uuid::from_u128(1), Uuid::from_u128(2)],
        )?;
        assert_eq!(outcome.accepted, capacity);
        assert_eq!(
            outcome.disposition,
            if capacity == 2 {
                AdmissionDisposition::Complete
            } else {
                AdmissionDisposition::Retry
            }
        );
        assert_eq!(sink.metrics().accepted, capacity as u64);
        let rows = state.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            matches!(
                rows[0],
                (
                    Actor::Bootstrap {},
                    Decision::Granted,
                    Some(Completion::Success)
                )
            ) == (capacity == 2)
        );
        if capacity == 1 {
            assert!(rows[0].2 == Some(Completion::Failed));
        }
        assert_eq!(state.slots.available_permits(), 1);
    }
    Ok(())
}
#[tokio::test]
async fn lost_completion_withholds_partial_and_full_prefix_without_losing_effect_accounting()
-> Result {
    for capacity in [1, 2] {
        let (service, sink, state) = setup(Mode::CompletionFailure, capacity)?;
        let (status, response) = decode(
            service
                .router()
                .oneshot(request(Body::from(batch()), true))
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!((response.accepted, response.rejected), (0, 0));
        assert!(response.event_ids.is_empty());
        let outcome = verify_admission_response(
            status.as_u16(),
            response,
            &[Uuid::from_u128(1), Uuid::from_u128(2)],
        )?;
        assert_eq!(outcome.accepted, 0);
        assert_eq!(outcome.disposition, AdmissionDisposition::Retry);
        assert_eq!(sink.metrics().accepted, capacity as u64);
        assert_eq!(
            metric(&service, "signal_events_accepted_total").await?,
            capacity as u64
        );
        assert_eq!(
            metric(&service, "signal_events_rejected_total").await?,
            (2 - capacity) as u64
        );
        assert_eq!(
            metric(&service, "signal_ingest_rejected_requests_total").await?,
            1
        );
        for index in 1..=capacity {
            assert_eq!(
                sink.take()?.ok_or("missing admitted effect")?.id,
                Uuid::from_u128(index as u128)
            );
        }
        assert_eq!(state.incomplete.load(Ordering::Relaxed), 1);
    }
    Ok(())
}
struct WatchedBody(Arc<AtomicUsize>);
impl tokio_stream::Stream for WatchedBody {
    type Item = std::result::Result<bytes::Bytes, std::io::Error>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        std::task::Poll::Ready(None)
    }
}
#[tokio::test]
async fn denied_authentication_and_lost_decision_never_read_body_or_admit() -> Result {
    for (mode, credential, status) in [
        (Mode::Good, false, StatusCode::UNAUTHORIZED),
        (Mode::DecisionFailure, true, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let (service, sink, state) = setup(mode, 2)?;
        let polls = Arc::new(AtomicUsize::new(0));
        let (actual, response) = decode(
            service
                .router()
                .oneshot(request(
                    Body::from_stream(WatchedBody(polls.clone())),
                    credential,
                ))
                .await?,
        )
        .await?;
        assert_eq!(actual, status);
        assert_eq!(polls.load(Ordering::Relaxed), 0);
        assert_eq!(sink.metrics().accepted, 0);
        verify_admission_response(actual.as_u16(), response, &[Uuid::from_u128(1)])?;
        let rows = state.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        if !credential {
            assert!(matches!(
                rows[0],
                (
                    Actor::Unattributed {},
                    Decision::Denied,
                    Some(Completion::Denied)
                )
            ));
        } else {
            assert!(matches!(
                rows[0],
                (Actor::Bootstrap {}, Decision::Granted, None)
            ));
        }
    }
    Ok(())
}
#[tokio::test]
async fn malformed_body_is_a_failed_operation_after_granted_decision_without_effect() -> Result {
    let (service, sink, state) = setup(Mode::Good, 2)?;
    let (status, response) = decode(
        service
            .router()
            .oneshot(request(Body::from("{synthetic-private-body"), true))
            .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(sink.metrics().accepted, 0);
    verify_admission_response(status.as_u16(), response, &[Uuid::from_u128(1)])?;
    let rows = state.rows.lock().unwrap();
    assert!(matches!(
        rows[0],
        (
            Actor::Bootstrap {},
            Decision::Granted,
            Some(Completion::Failed)
        )
    ));
    Ok(())
}
#[tokio::test]
async fn aborted_confirmation_cancels_original_context_and_counts_incomplete_without_losing_effects()
-> Result {
    let (service, sink, state) = setup(Mode::HoldCompletion, 2)?;
    let router = service.router();
    let task =
        tokio::spawn(async move { router.oneshot(request(Body::from(batch()), true)).await });
    tokio::time::timeout(Duration::from_secs(2), state.started.notified()).await?;
    assert_eq!(sink.metrics().accepted, 2);
    assert_eq!(state.slots.available_permits(), 0);
    let context = state
        .context
        .lock()
        .unwrap()
        .clone()
        .ok_or("context missing")?;
    task.abort();
    assert!(task.await.is_err());
    assert!(context.cancellation.is_cancelled());
    assert_eq!(state.incomplete.load(Ordering::Relaxed), 1);
    assert_eq!(state.slots.available_permits(), 1);
    assert_eq!(metric(&service, "signal_events_accepted_total").await?, 2);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 0);
    assert_eq!(
        metric(&service, "signal_ingest_rejected_requests_total").await?,
        1
    );
    assert_eq!(metric(&service, "signal_ingest_in_flight").await?, 0);
    Ok(())
}

#[tokio::test]
async fn completion_never_renews_original_deadline_or_discloses_timed_out_full_prefix() -> Result {
    let (service, sink, state) = setup_timeout(Mode::HoldCompletion, 2, Duration::from_millis(50))?;
    let (status, response) = decode(
        service
            .router()
            .oneshot(request(Body::from(batch()), true))
            .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let outcome = verify_admission_response(
        status.as_u16(),
        response,
        &[Uuid::from_u128(1), Uuid::from_u128(2)],
    )?;
    assert_eq!(outcome.accepted, 0);
    assert_eq!(outcome.disposition, AdmissionDisposition::Retry);
    assert_eq!(sink.metrics().accepted, 2);
    let context = state
        .context
        .lock()
        .unwrap()
        .clone()
        .ok_or("context missing")?;
    assert!(tokio::time::Instant::now() >= context.deadline);
    assert!(context.cancellation.is_cancelled());
    assert_eq!(state.incomplete.load(Ordering::Relaxed), 1);
    assert_eq!(state.slots.available_permits(), 1);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 0);
    assert_eq!(
        metric(&service, "signal_ingest_rejected_requests_total").await?,
        1
    );
    Ok(())
}

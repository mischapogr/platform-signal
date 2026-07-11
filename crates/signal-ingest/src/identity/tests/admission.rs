//! Real Axum admission routes against the finite authenticated TLS provider.
use super::*;
use crate::{IngestConfig, IngestService, memory::MemorySink};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use signal_protocol::{AdmissionDisposition, EventSink, IngestResponse, verify_admission_response};
use tower::ServiceExt;

fn producer_policy() -> Arc<CompiledPolicy> {
    signal_protocol::access::AccessPolicy::from_json(br#"{"schema_version":1,"roles":[{"id":"producer","permissions":[{"operation":"ingest_events","scope":{"sources":{"mode":"only","values":["audit"]},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"only","values":["host-a"]}}}]}],"bindings":[{"issuer":"https://identity.example.test","subject":"reader","roles":["producer"]}]}"#).unwrap().compile().unwrap()
}
fn event(id: u128, account: &str) -> Value {
    json!({"id":uuid::Uuid::from_u128(id),"timestamp":"2026-09-01T01:00:00Z","source":{"type":"audit"},"resource":{"kind":"host","id":"host-a","account_id":account},"attributes":{"account_id":"a","roles":["administrator"]}})
}
async fn post(
    service: &IngestService,
    events: Vec<Value>,
    credential: Option<&str>,
) -> (StatusCode, IngestResponse) {
    let mut builder = Request::post("/v1/events/batch")
        .header("content-type", "application/json")
        .header("x-forwarded-user", "reader")
        .header("x-forwarded-roles", "administrator");
    if let Some(credential) = credential {
        builder = builder.header("authorization", credential);
    }
    let response = service
        .router()
        .oneshot(
            builder
                .body(Body::from(
                    serde_json::to_vec(&json!({"schema_version":1,"events":events})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn mixed_unauthorized_batch_commits_nothing_then_fresh_allowed_request_succeeds() {
    let provider = fixture::Fixture::new(
        vec![
            fixture::json_reply(&fixture::valid_body()),
            fixture::json_reply(&fixture::valid_body()),
        ],
        "127.0.0.1",
        "1",
    )
    .await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        producer_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let sink = Arc::new(MemorySink::new(8, 65536).unwrap());
    let service =
        IngestService::new_with_identity(IngestConfig::default(), sink.clone(), backend.clone())
            .unwrap();
    let (status, response) = post(
        &service,
        vec![event(1, "a"), event(2, "b")],
        Some("Bearer opaque"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response.accepted, 0);
    assert_eq!(response.rejected, 2);
    assert_eq!(sink.metrics().accepted, 0);
    assert_eq!(
        verify_admission_response(
            status.as_u16(),
            response,
            &[uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)]
        )
        .unwrap()
        .disposition,
        AdmissionDisposition::Permanent
    );
    let (status, response) = post(&service, vec![event(3, "a")], Some("Bearer opaque")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(response.event_ids, vec![uuid::Uuid::from_u128(3)]);
    assert_eq!(sink.metrics().accepted, 1);
    assert_eq!(provider.requests.load(Ordering::Acquire), 2);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}
#[tokio::test]
async fn forwarded_headers_and_shared_tokens_cannot_bypass_identity_and_close_not_ready() {
    let provider = fixture::Fixture::new(
        vec![fixture::json_reply(&fixture::valid_body())],
        "127.0.0.1",
        "1",
    )
    .await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        producer_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let sink = Arc::new(MemorySink::new(8, 65536).unwrap());
    assert!(
        IngestService::new_with_identity(
            IngestConfig {
                api_token: Some("legacy".into()),
                ..Default::default()
            },
            sink.clone(),
            backend.clone()
        )
        .is_err()
    );
    let service =
        IngestService::new_with_identity(IngestConfig::default(), sink.clone(), backend.clone())
            .unwrap();
    for credential in [None, Some("Basic opaque"), Some("Bearer bad credential")] {
        let (status, response) = post(&service, vec![event(1, "a")], credential).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.accepted, 0);
    }
    let response = service
        .router()
        .oneshot(
            Request::post("/v1/events/batch")
                .header("authorization", "Bearer opaque")
                .header("authorization", "Bearer other")
                .body(Body::from("malformed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(provider.requests.load(Ordering::Acquire), 0);
    assert_eq!(sink.metrics().accepted, 0);
    backend.close().unwrap();
    assert_eq!(
        service
            .router()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (status, _) = post(&service, vec![event(1, "a")], Some("Bearer opaque")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

struct HeldFirstAdmission {
    inner: MemorySink,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    gate: tokio::sync::Semaphore,
}
impl EventSink for HeldFirstAdmission {
    fn admit(&self, event: signal_event::SignalEvent) -> signal_protocol::AdmissionFuture<'_> {
        Box::pin(async move {
            self.inner.admit(event).await?;
            if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.entered.notify_one();
                let _permit = self
                    .gate
                    .acquire()
                    .await
                    .map_err(|_| signal_protocol::AdmissionError::Closed)?;
            }
            Ok(())
        })
    }
    fn metrics(&self) -> signal_protocol::SinkMetrics {
        self.inner.metrics()
    }
    fn close(&self) {
        self.inner.close();
        self.gate.close();
    }
}
#[tokio::test]
async fn lease_exhaustion_keeps_truthful_committed_prefix_and_fresh_suffix_retry() {
    let provider = fixture::Fixture::new(
        vec![
            fixture::json_reply(&fixture::valid_body()),
            fixture::json_reply(&fixture::valid_body()),
        ],
        "127.0.0.1",
        "1",
    )
    .await;
    let lease_profile = IntrospectionProfile::new(
        "https://identity.example.test".into(),
        "synthetic-signal".into(),
        2,
    )
    .unwrap();
    let backend = IdentityBackend::new(
        provider.config(),
        lease_profile,
        producer_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let sink = Arc::new(HeldFirstAdmission {
        inner: MemorySink::new(8, 65536).unwrap(),
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        gate: tokio::sync::Semaphore::new(0),
    });
    let service =
        IngestService::new_with_identity(IngestConfig::default(), sink.clone(), backend.clone())
            .unwrap();
    let request = post(
        &service,
        vec![event(1, "a"), event(2, "a")],
        Some("Bearer opaque"),
    );
    tokio::pin!(request);
    tokio::select! {biased;response=&mut request=>panic!("first admission must wait, got {}",response.0),_=sink.entered.notified()=>{}}
    tokio::time::sleep(Duration::from_millis(2100)).await;
    sink.gate.add_permits(1);
    let (status, response) = request.await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!((response.accepted, response.rejected), (1, 1));
    assert_eq!(response.event_ids, vec![uuid::Uuid::from_u128(1)]);
    let outcome = verify_admission_response(
        status.as_u16(),
        response,
        &[uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
    )
    .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert_eq!(outcome.disposition, AdmissionDisposition::Retry);
    assert_eq!(sink.metrics().accepted, 1);
    assert_eq!(sink.calls.load(Ordering::Acquire), 1);
    let (status, response) = post(&service, vec![event(2, "a")], Some("Bearer opaque")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(response.event_ids, vec![uuid::Uuid::from_u128(2)]);
    assert_eq!(sink.metrics().accepted, 2);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

#[tokio::test]
async fn canonical_scope_and_operation_denials_ignore_attributes_and_revoked_credentials() {
    let mut replies = Vec::new();
    for _ in 0..4 {
        replies.push(fixture::json_reply(&fixture::valid_body()));
    }
    replies.push(fixture::json_reply(br#"{"active":false}"#));
    replies.push(fixture::json_reply(&fixture::valid_body()));
    let provider = fixture::Fixture::new(replies, "127.0.0.1", "1").await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        producer_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let sink = Arc::new(MemorySink::new(8, 65536).unwrap());
    let service =
        IngestService::new_with_identity(IngestConfig::default(), sink.clone(), backend.clone())
            .unwrap();
    let mut wrong_source = event(1, "a");
    wrong_source["source"]["type"] = json!("other");
    let mut wrong_resource = event(2, "a");
    wrong_resource["resource"]["id"] = json!("host-b");
    let mut missing_resource = event(3, "a");
    missing_resource.as_object_mut().unwrap().remove("resource");
    let mut missing_account = event(4, "a");
    missing_account["resource"]
        .as_object_mut()
        .unwrap()
        .remove("account_id");
    for input in [
        wrong_source,
        wrong_resource,
        missing_resource,
        missing_account,
    ] {
        let (status, response) = post(&service, vec![input], Some("Bearer opaque")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response.accepted, 0);
        assert_eq!(sink.metrics().accepted, 0);
    }
    let (status, response) = post(&service, vec![event(5, "a")], Some("Bearer opaque")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response.accepted, 0);
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let reader = IdentityBackend::new(
        provider.config(),
        profile(),
        reader_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let service =
        IngestService::new_with_identity(IngestConfig::default(), sink.clone(), reader.clone())
            .unwrap();
    let (status, response) = post(&service, vec![event(6, "a")], Some("Bearer opaque")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response.accepted, 0);
    assert_eq!(response.rejected, 0);
    assert_eq!(sink.metrics().accepted, 0);
    assert_eq!(provider.requests.load(Ordering::Acquire), 6);
    reader
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

#[tokio::test]
async fn provider_deadline_rejects_before_body_and_exposes_bounded_metrics_without_secrets() {
    let provider = fixture::Fixture::new(vec![fixture::Reply::Stall], "127.0.0.1", "1").await;
    let backend = IdentityBackend::new(
        provider.config(),
        profile(),
        producer_policy(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let sink = Arc::new(MemorySink::new(8, 65536).unwrap());
    let service = IngestService::new_with_identity(
        IngestConfig {
            request_timeout: Duration::from_millis(200),
            ..Default::default()
        },
        sink.clone(),
        backend.clone(),
    )
    .unwrap();
    let (status, response) = post(&service, vec![event(1, "a")], Some("Bearer opaque")).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!((response.accepted, response.rejected), (0, 0));
    assert_eq!(
        verify_admission_response(status.as_u16(), response, &[uuid::Uuid::from_u128(1)])
            .unwrap()
            .disposition,
        AdmissionDisposition::Retry
    );
    idle(&backend).await;
    assert_eq!(sink.metrics().accepted, 0);
    assert_eq!(provider.requests.load(Ordering::Acquire), 1);
    let response = service
        .router()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    let metrics = std::str::from_utf8(&bytes).unwrap();
    assert!(metrics.contains("signal_ingest_timeouts_total 1\n"));
    assert!(metrics.contains("signal_identity_capacity 1\n"));
    assert!(metrics.contains("signal_identity_queue_capacity 1\n"));
    assert!(metrics.contains("signal_identity_depth 0\n"));
    for secret in ["opaque", "synthetic-secret", "synthetic-client", "reader"] {
        assert!(!metrics.contains(secret));
    }
    backend
        .shutdown(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    provider.finish().await;
}

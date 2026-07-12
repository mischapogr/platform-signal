use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use signal_event::{IngestEvent, SignalEvent};
use signal_ingest::{
    IngestConfig, IngestService,
    memory::MemorySink,
    server::{ServerLimits, serve},
};
use signal_protocol::{AdmissionFuture, EventSink, IngestResponse, SinkMetrics};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn event() -> Value {
    json!({"timestamp":"2026-10-06T12:00:00Z","source":{"type":"application"},"message":"hello","attributes":{"user":{"name":"alice"}}})
}
fn setup(
    config: IngestConfig,
    capacity: usize,
    bytes: usize,
) -> Result<(IngestService, Arc<MemorySink>)> {
    let sink = Arc::new(MemorySink::new(capacity, bytes)?);
    Ok((IngestService::new(config, sink.clone())?, sink))
}
async fn post(
    service: &IngestService,
    path: &str,
    value: Value,
) -> Result<(StatusCode, IngestResponse)> {
    let response = service
        .router()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&value)?))?,
        )
        .await?;
    decode(response).await
}
async fn decode(response: Response) -> Result<(StatusCode, IngestResponse)> {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}
async fn metric(service: &IngestService, name: &str) -> Result<u64> {
    let response = service
        .router()
        .oneshot(Request::get("/metrics").body(Body::empty())?)
        .await?;
    let bytes = to_bytes(response.into_body(), 4096).await?;
    let text = std::str::from_utf8(&bytes)?;
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .ok_or("metric missing")?;
    Ok(value.parse()?)
}

#[tokio::test]
async fn single_event_is_normalized_and_retained_with_capacity_metrics() -> Result {
    let (service, sink) = setup(IngestConfig::default(), 10, 4096)?;
    let (status, response) = post(&service, "/v1/events", event()).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!((response.accepted, response.rejected), (1, 0));
    assert_eq!(response.schema_version, 1);
    let stored = sink.take()?.ok_or("retained event missing")?;
    assert_eq!(stored.id, response.event_ids[0]);
    assert_eq!(stored.attributes["user"]["name"], "alice");
    assert_eq!(sink.metrics().depth, 0);
    assert_eq!(sink.metrics().bytes, 0);
    assert_eq!(metric(&service, "signal_queue_capacity").await?, 10);
    assert_eq!(metric(&service, "signal_events_accepted_total").await?, 1);
    Ok(())
}

#[tokio::test]
async fn invalid_batch_has_no_partial_validation_side_effects() -> Result {
    let (service, sink) = setup(IngestConfig::default(), 10, 4096)?;
    let mut invalid = event();
    invalid["timestamp"] = json!("yesterday");
    let (status, response) = post(
        &service,
        "/v1/events/batch",
        json!({"events":[event(),invalid,event()]}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!((response.accepted, response.rejected), (0, 3));
    assert_eq!(response.error.ok_or("error missing")?.index, Some(1));
    assert_eq!(sink.metrics().depth, 0);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 3);
    Ok(())
}

#[tokio::test]
async fn invalid_single_inputs_and_batches_return_typed_errors() -> Result {
    let (service, sink) = setup(IngestConfig::default(), 10, 4096)?;
    for value in [
        json!({}),
        json!({"timestamp":"2026-10-06T12:00:00Z","source":{"type":""},"message":"hello"}),
        {
            let mut value = event();
            value["schema_version"] = json!(2);
            value
        },
    ] {
        let (status, response) = post(&service, "/v1/events", value).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!((response.accepted, response.rejected), (0, 1));
        assert!(response.error.is_some());
    }
    for value in [
        json!({"events":[]}),
        json!({"events":[event()],"schema_version":2}),
        json!({"not_events":[]}),
    ] {
        assert_eq!(
            post(&service, "/v1/events/batch", value).await?.0,
            StatusCode::BAD_REQUEST
        );
    }
    let response = service
        .router()
        .oneshot(
            Request::post("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from("{broken"))?,
        )
        .await?;
    let (status, malformed) = decode(response).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.rejected, 0);
    assert_eq!(sink.metrics().accepted, 0);
    Ok(())
}

#[tokio::test]
async fn oversized_fixed_and_streamed_bodies_and_batch_counts_are_rejected() -> Result {
    let config = IngestConfig {
        max_request_bytes: 128,
        max_batch_events: 1,
        ..IngestConfig::default()
    };
    let (service, sink) = setup(config, 10, 4096)?;
    let mut value = event();
    value["message"] = json!("x".repeat(256));
    let (status, response) = post(&service, "/v1/events", value).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.error.ok_or("error missing")?.code,
        signal_protocol::ErrorCode::PayloadTooLarge
    );
    let stream = tokio_stream::iter([
        Ok::<_, std::io::Error>(vec![b'x'; 100]),
        Ok(vec![b'x'; 100]),
    ]);
    let response = service
        .router()
        .oneshot(
            Request::post("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from_stream(stream))?,
        )
        .await?;
    assert_eq!(decode(response).await?.0, StatusCode::PAYLOAD_TOO_LARGE);
    let (service, _) = setup(
        IngestConfig {
            max_batch_events: 1,
            ..IngestConfig::default()
        },
        10,
        4096,
    )?;
    let (status, response) = post(
        &service,
        "/v1/events/batch",
        json!({"events":[event(),event()]}),
    )
    .await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.rejected, 2);
    assert_eq!(sink.metrics().depth, 0);
    Ok(())
}

#[tokio::test]
async fn optional_authentication_rejects_missing_wrong_and_duplicate_credentials() -> Result {
    let config = IngestConfig {
        api_token: Some("do-not-log-this".into()),
        ..IngestConfig::default()
    };
    assert!(!format!("{config:?}").contains("do-not-log-this"));
    let (service, sink) = setup(config, 10, 4096)?;
    assert_eq!(
        post(&service, "/v1/events", event()).await?.0,
        StatusCode::UNAUTHORIZED
    );
    for credential in [
        "Bearer wrong",
        "Basic do-not-log-this",
        "Bearer do-not-log-thiS",
    ] {
        let response = service
            .router()
            .oneshot(
                Request::post("/v1/events")
                    .header("content-type", "application/json")
                    .header("authorization", credential)
                    .body(Body::from(serde_json::to_vec(&event())?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
        let (_, body) = decode(response).await?;
        assert!(!serde_json::to_string(&body)?.contains("do-not-log"));
    }
    let response = service
        .router()
        .oneshot(
            Request::post("/v1/events")
                .header("content-type", "application/json")
                .header("authorization", "Bearer do-not-log-this")
                .header("authorization", "Bearer do-not-log-this")
                .body(Body::from(serde_json::to_vec(&event())?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = service
        .router()
        .oneshot(
            Request::post("/v1/events")
                .header("content-type", "application/json")
                .header("authorization", "Bearer do-not-log-this")
                .body(Body::from(serde_json::to_vec(&event())?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(sink.metrics().depth, 1);
    Ok(())
}

#[tokio::test]
async fn byte_capacity_and_partial_batch_admission_are_exact() -> Result {
    let normalized =
        serde_json::from_value::<IngestEvent>(event())?.normalize(chrono::Utc::now())?;
    let encoded = serde_json::to_vec(&normalized)?.len();
    let (service, sink) = setup(IngestConfig::default(), 3, 1)?;
    assert_eq!(
        post(&service, "/v1/events", event()).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(sink.metrics().bytes, 0);
    let sink = MemorySink::new(10, encoded)?;
    sink.admit(normalized.clone()).await?;
    assert_eq!(sink.metrics().bytes, encoded);
    assert_eq!(
        sink.admit(normalized.clone()).await,
        Err(signal_protocol::AdmissionError::Full)
    );
    sink.take()?;
    sink.admit(normalized).await?;
    let (service, sink) = setup(IngestConfig::default(), 2, 4096)?;
    let (status, response) = post(
        &service,
        "/v1/events/batch",
        json!({"events":[event(),event(),event()]}),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        (
            response.accepted,
            response.rejected,
            response.event_ids.len()
        ),
        (2, 1, 2)
    );
    assert_eq!(response.error.ok_or("error missing")?.index, Some(2));
    assert_eq!(sink.metrics().depth, 2);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 1);
    Ok(())
}

#[tokio::test]
async fn stop_admission_changes_readiness_and_counts_explicit_volatile_loss() -> Result {
    let (service, sink) = setup(IngestConfig::default(), 10, 4096)?;
    post(&service, "/v1/events", event()).await?;
    assert!(sink.discard_pending().is_err());
    service.stop_admission();
    assert_eq!(
        post(&service, "/v1/events", event()).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for (path, status) in [
        ("/readyz", StatusCode::SERVICE_UNAVAILABLE),
        ("/healthz", StatusCode::OK),
    ] {
        assert_eq!(
            service
                .router()
                .oneshot(Request::get(path).body(Body::empty())?)
                .await?
                .status(),
            status
        );
    }
    assert_eq!(sink.discard_pending()?, 1);
    assert_eq!(metric(&service, "signal_events_dropped_total").await?, 1);
    Ok(())
}

struct PendingSink {
    dropped: Arc<AtomicBool>,
}
struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl EventSink for PendingSink {
    fn admit(&self, _: SignalEvent) -> AdmissionFuture<'_> {
        Box::pin(async move {
            let _flag = DropFlag(self.dropped.clone());
            std::future::pending().await
        })
    }
    fn metrics(&self) -> SinkMetrics {
        SinkMetrics::default()
    }
    fn close(&self) {}
}

#[tokio::test]
async fn sink_deadline_cancels_work_and_reports_unadmitted_remainder() -> Result {
    let dropped = Arc::new(AtomicBool::new(false));
    let config = IngestConfig {
        request_timeout: Duration::from_millis(20),
        ..IngestConfig::default()
    };
    let service = IngestService::new(
        config,
        Arc::new(PendingSink {
            dropped: dropped.clone(),
        }),
    )?;
    let (status, response) = post(
        &service,
        "/v1/events/batch",
        json!({"events":[event(),event()]}),
    )
    .await?;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!((response.accepted, response.rejected), (0, 2));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(metric(&service, "signal_ingest_timeouts_total").await?, 1);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 2);
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_a_pending_request_without_detached_admission() -> Result {
    let dropped = Arc::new(AtomicBool::new(false));
    let service = IngestService::new(
        IngestConfig::default(),
        Arc::new(PendingSink {
            dropped: dropped.clone(),
        }),
    )?;
    let cloned = service.clone();
    let task = tokio::spawn(async move {
        post(&cloned, "/v1/events", event())
            .await
            .map_err(|e| e.to_string())
    });
    sleep(Duration::from_millis(10)).await;
    service.stop_admission();
    let result = timeout(Duration::from_secs(1), task)
        .await??
        .map_err(std::io::Error::other)?;
    assert_eq!(result.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn stalled_body_and_request_concurrency_are_bounded() -> Result {
    let (service, _) = setup(
        IngestConfig {
            request_timeout: Duration::from_millis(50),
            max_in_flight: 1,
            ..IngestConfig::default()
        },
        10,
        4096,
    )?;
    let stream = tokio_stream::pending::<std::result::Result<Vec<u8>, std::io::Error>>();
    let request = Request::post("/v1/events")
        .header("content-type", "application/json")
        .body(Body::from_stream(stream))?;
    let app = service.router();
    let task = tokio::spawn(async move { app.oneshot(request).await });
    for _ in 0..100 {
        if metric(&service, "signal_ingest_in_flight").await? == 1 {
            break;
        }
        sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        post(&service, "/v1/events", event()).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        timeout(Duration::from_secs(1), task).await???.status(),
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!(metric(&service, "signal_ingest_in_flight").await?, 0);
    Ok(())
}

#[test]
fn invalid_config_cannot_create_a_ready_service() -> Result {
    for config in [
        IngestConfig {
            max_request_bytes: 0,
            ..IngestConfig::default()
        },
        IngestConfig {
            max_batch_events: 0,
            ..IngestConfig::default()
        },
        IngestConfig {
            request_timeout: Duration::ZERO,
            ..IngestConfig::default()
        },
        IngestConfig {
            api_token: Some(" ".into()),
            ..IngestConfig::default()
        },
    ] {
        assert!(IngestService::new(config, Arc::new(MemorySink::new(1, 1024)?)).is_err());
    }
    assert!(MemorySink::new(0, 1024).is_err());
    assert!(
        ServerLimits {
            max_connections: 0,
            ..ServerLimits::default()
        }
        .validate()
        .is_err()
    );
    Ok(())
}

async fn wire(
    address: std::net::SocketAddr,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>)> {
    timeout(Duration::from_secs(5),async {
        let mut stream=TcpStream::connect(address).await?;
        let body=body.unwrap_or_default();
        let method=if body.is_empty(){"GET"}else{"POST"};
        let head=format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len());
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        let mut output=Vec::new(); stream.read_to_end(&mut output).await?;
        let split=output.windows(4).position(|w|w==b"\r\n\r\n").ok_or("HTTP separator missing")?;
        let headers=std::str::from_utf8(&output[..split])?;
        let status=headers.split_whitespace().nth(1).ok_or("status missing")?.parse()?;
        Ok((status,output[split+4..].to_vec()))
    }).await?
}

#[tokio::test]
async fn ten_thousand_events_over_tcp_have_deterministic_acceptance_counts() -> Result {
    let (service, sink) = setup(IngestConfig::default(), 5037, 64 * 1024 * 1024)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = CancellationToken::new();
    let signal = stop.clone();
    let server_service = service.clone();
    let task = tokio::spawn(async move {
        serve(
            listener,
            server_service,
            ServerLimits::default(),
            async move { signal.cancelled().await },
        )
        .await
    });
    let body = serde_json::to_vec(&json!({"events":vec![event();100]}))?;
    let mut accepted = 0;
    let mut rejected = 0;
    let mut ids = std::collections::HashSet::new();
    for batch in 0..100 {
        let (status, body) = wire(address, "/v1/events/batch", Some(&body)).await?;
        let result: IngestResponse = serde_json::from_slice(&body)?;
        assert_eq!(status, if batch < 50 { 202 } else { 429 });
        accepted += result.accepted;
        rejected += result.rejected;
        for id in result.event_ids {
            assert!(ids.insert(id));
        }
    }
    assert_eq!((accepted, rejected), (5037, 4963));
    assert_eq!(sink.metrics().depth, 5037);
    assert!(sink.metrics().bytes <= sink.metrics().byte_capacity);
    assert_eq!(
        metric(&service, "signal_events_accepted_total").await?,
        5037
    );
    assert_eq!(
        metric(&service, "signal_events_rejected_total").await?,
        4963
    );
    println!(
        "10,000 events over TCP: accepted={accepted}, rejected={rejected}, unique_ids={}",
        ids.len()
    );
    stop.cancel();
    timeout(Duration::from_secs(2), task).await???;
    assert!(sink.metrics().closed);
    Ok(())
}

#[tokio::test]
async fn connection_capacity_idle_deadline_and_shutdown_release_sockets() -> Result {
    let (service, _) = setup(
        IngestConfig {
            request_timeout: Duration::from_millis(100),
            ..IngestConfig::default()
        },
        10,
        4096,
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = CancellationToken::new();
    let signal = stop.clone();
    let server_service = service.clone();
    let limits = ServerLimits {
        max_connections: 1,
        connection_timeout: Duration::from_millis(200),
        shutdown_timeout: Duration::from_secs(1),
    };
    let task = tokio::spawn(async move {
        serve(listener, server_service, limits, async move {
            signal.cancelled().await
        })
        .await
    });
    let mut idle = TcpStream::connect(address).await?;
    idle.write_all(b"GET /healthz HTTP/1.1\r\n").await?;
    sleep(Duration::from_millis(20)).await;
    assert_eq!(metric(&service, "signal_http_connections").await?, 1);
    assert_eq!(
        metric(&service, "signal_http_connection_capacity").await?,
        1
    );
    let result = wire(address, "/healthz", None).await?;
    assert_eq!(result.0, 200);
    let mut output = Vec::new();
    timeout(Duration::from_secs(1), idle.read_to_end(&mut output)).await??;
    stop.cancel();
    timeout(Duration::from_secs(2), task).await???;
    assert_eq!(metric(&service, "signal_http_connections").await?, 0);
    Ok(())
}

#[tokio::test]
async fn independent_transport_retains_operation_through_pending_response_without_event_sink()
-> Result {
    use axum::{Extension, Router, routing::get};
    use signal_ingest::server::{ConnectionContext, TransportState, serve_transport_router};
    use tokio::sync::Semaphore;
    let state =
        TransportState::independent(CancellationToken::new(), Duration::from_secs(1), false)?;
    let metrics = state.metrics();
    let operation = Arc::new(Semaphore::new(1));
    let entered = Arc::new(AtomicBool::new(false));
    let token = Arc::new(std::sync::Mutex::new(None));
    let app = Router::new().route(
        "/hold",
        get({
            let operation = operation.clone();
            let entered = entered.clone();
            let token = token.clone();
            move |Extension(context): Extension<ConnectionContext>| {
                let operation = operation.clone();
                let entered = entered.clone();
                let token = token.clone();
                async move {
                    if context.try_acquire_operation(operation).is_err() {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    let Ok(mut token) = token.lock() else {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    };
                    *token = Some(context.cancellation());
                    entered.store(true, Ordering::Release);
                    Response::new(Body::from_stream(tokio_stream::pending::<
                        std::result::Result<bytes::Bytes, std::io::Error>,
                    >()))
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = CancellationToken::new();
    let signal = stop.clone();
    let closed = Arc::new(AtomicBool::new(false));
    let close = closed.clone();
    let task = tokio::spawn(serve_transport_router(
        listener,
        state,
        app,
        ServerLimits {
            max_connections: 2,
            connection_timeout: Duration::from_secs(3),
            shutdown_timeout: Duration::from_secs(1),
        },
        Arc::new(Semaphore::new(2)),
        None,
        (
            move || {
                close.store(true, Ordering::Release);
            },
            async move { signal.cancelled().await },
        ),
    ));
    let mut nonreading = TcpStream::connect(address).await?;
    nonreading
        .write_all(b"GET /hold HTTP/1.1\r\nHost: local\r\n\r\n")
        .await?;
    timeout(Duration::from_secs(1), async {
        while !entered.load(Ordering::Acquire) {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    assert_eq!(operation.available_permits(), 0);
    assert_eq!(metrics.snapshot().connections, 1);
    assert_eq!(wire(address, "/hold", None).await?.0, 503);
    assert_eq!(operation.available_permits(), 0);
    timeout(Duration::from_secs(4), async {
        while operation.available_permits() == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    assert!(
        token
            .lock()
            .map_err(|_| std::io::Error::other("fixture mutex"))?
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    );
    assert!(metrics.snapshot().timeouts >= 1);
    assert_eq!(metrics.snapshot().connections, 0);
    stop.cancel();
    timeout(Duration::from_secs(2), task).await???;
    assert!(closed.load(Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn independent_single_request_transport_does_not_dispatch_pipelined_request() -> Result {
    use axum::{Extension, Router, routing::get};
    use signal_ingest::server::{ConnectionContext, TransportState, serve_transport_router};
    use std::sync::atomic::AtomicU64;
    use tokio::sync::Semaphore;
    let calls = Arc::new(AtomicU64::new(0));
    let count = calls.clone();
    let operation = Arc::new(Semaphore::new(1));
    let budget = operation.clone();
    let app = Router::new().route(
        "/one",
        get(move |Extension(context): Extension<ConnectionContext>| {
            let count = count.clone();
            let budget = budget.clone();
            async move {
                if context.try_acquire_operation(budget).is_err() {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                count.fetch_add(1, Ordering::Relaxed);
                "one".into_response()
            }
        }),
    );
    let state =
        TransportState::independent(CancellationToken::new(), Duration::from_millis(200), false)?;
    let metrics = state.metrics();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stop = CancellationToken::new();
    let signal = stop.clone();
    let task = tokio::spawn(serve_transport_router(
        listener,
        state,
        app,
        ServerLimits {
            max_connections: 1,
            connection_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
        },
        Arc::new(Semaphore::new(1)),
        None,
        (|| {}, async move { signal.cancelled().await }),
    ));
    let mut socket = TcpStream::connect(address).await?;
    socket
        .write_all(
            b"GET /one HTTP/1.1\r\nHost: local\r\n\r\nGET /one HTTP/1.1\r\nHost: local\r\n\r\n",
        )
        .await?;
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), socket.read_to_end(&mut reply)).await??;
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(String::from_utf8(reply)?.matches("HTTP/1.1 200").count(), 1);
    assert_eq!(operation.available_permits(), 1);
    assert_eq!(metrics.snapshot().connections, 0);
    stop.cancel();
    timeout(Duration::from_secs(2), task).await???;
    Ok(())
}

#[tokio::test]
async fn independent_transport_abort_stops_admission_before_cancelling_active_connection() -> Result
{
    use axum::{Extension, Router, routing::get};
    use signal_ingest::server::{ConnectionContext, TransportState, serve_transport_router};
    use tokio::sync::Semaphore;
    let entered = Arc::new(AtomicBool::new(false));
    let token = Arc::new(std::sync::Mutex::new(None));
    let operation = Arc::new(Semaphore::new(1));
    let app = Router::new().route(
        "/hold",
        get({
            let entered = entered.clone();
            let token = token.clone();
            let operation = operation.clone();
            move |Extension(context): Extension<ConnectionContext>| {
                let entered = entered.clone();
                let token = token.clone();
                let operation = operation.clone();
                async move {
                    if context.try_acquire_operation(operation).is_err() {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    let Ok(mut token) = token.lock() else {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    };
                    *token = Some(context.cancellation());
                    entered.store(true, Ordering::Release);
                    Response::new(Body::from_stream(tokio_stream::pending::<
                        std::result::Result<bytes::Bytes, std::io::Error>,
                    >()))
                }
            }
        }),
    );
    let state =
        TransportState::independent(CancellationToken::new(), Duration::from_secs(1), false)?;
    let metrics = state.metrics();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let closed = Arc::new(AtomicBool::new(false));
    let ordered = Arc::new(AtomicBool::new(false));
    let close = closed.clone();
    let order = ordered.clone();
    let observe = token.clone();
    let stop_operations = operation.clone();
    let task = tokio::spawn(serve_transport_router(
        listener,
        state,
        app,
        ServerLimits {
            max_connections: 1,
            connection_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(1),
        },
        Arc::new(Semaphore::new(1)),
        None,
        (
            move || {
                order.store(
                    observe.lock().is_ok_and(|token| {
                        token
                            .as_ref()
                            .is_some_and(|t: &CancellationToken| !t.is_cancelled())
                    }),
                    Ordering::Release,
                );
                stop_operations.close();
                close.store(true, Ordering::Release);
            },
            std::future::pending(),
        ),
    ));
    let mut socket = TcpStream::connect(address).await?;
    socket
        .write_all(b"GET /hold HTTP/1.1\r\nHost: local\r\n\r\n")
        .await?;
    timeout(Duration::from_secs(2), async {
        while !entered.load(Ordering::Acquire) {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    task.abort();
    assert!(task.await.is_err_and(|e| e.is_cancelled()));
    assert!(closed.load(Ordering::Acquire));
    assert!(ordered.load(Ordering::Acquire));
    assert!(operation.is_closed());
    timeout(Duration::from_secs(2), async {
        while metrics.snapshot().connections != 0 {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    assert!(
        token
            .lock()
            .map_err(|_| std::io::Error::other("fixture mutex"))?
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
    );
    assert_eq!(operation.available_permits(), 1);
    Ok(())
}

struct PrefixThenPendingSink {
    retained: Arc<MemorySink>,
    dropped: Arc<AtomicBool>,
}
impl EventSink for PrefixThenPendingSink {
    fn admit(&self, event: SignalEvent) -> AdmissionFuture<'_> {
        Box::pin(async move {
            if self.retained.metrics().depth == 0 {
                return self.retained.admit(event).await;
            }
            let _flag = DropFlag(self.dropped.clone());
            std::future::pending().await
        })
    }
    fn metrics(&self) -> SinkMetrics {
        self.retained.metrics()
    }
    fn close(&self) {
        self.retained.close();
    }
}

#[tokio::test]
async fn timeout_preserves_the_committed_prefix_and_rejects_only_the_remainder() -> Result {
    let retained = Arc::new(MemorySink::new(10, 4096)?);
    let dropped = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(PrefixThenPendingSink {
        retained: retained.clone(),
        dropped: dropped.clone(),
    });
    let service = IngestService::new(
        IngestConfig {
            request_timeout: Duration::from_millis(20),
            ..IngestConfig::default()
        },
        sink,
    )?;
    let (status, response) = post(
        &service,
        "/v1/events/batch",
        json!({"events":[event(),event(),event()]}),
    )
    .await?;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(
        (
            response.accepted,
            response.rejected,
            response.event_ids.len()
        ),
        (1, 2, 1)
    );
    assert_eq!(
        retained.take()?.ok_or("committed prefix missing")?.id,
        response.event_ids[0]
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(metric(&service, "signal_events_accepted_total").await?, 1);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 2);
    Ok(())
}

#[tokio::test]
async fn aborting_a_client_request_releases_capacity_and_counts_unadmitted_events() -> Result {
    let dropped = Arc::new(AtomicBool::new(false));
    let service = IngestService::new(
        IngestConfig::default(),
        Arc::new(PendingSink {
            dropped: dropped.clone(),
        }),
    )?;
    let cloned = service.clone();
    let task = tokio::spawn(async move {
        post(&cloned, "/v1/events", event())
            .await
            .map_err(|e| e.to_string())
    });
    for _ in 0..100 {
        if metric(&service, "signal_ingest_in_flight").await? == 1 {
            break;
        }
        sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.is_err());
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(metric(&service, "signal_ingest_in_flight").await?, 0);
    assert_eq!(metric(&service, "signal_events_rejected_total").await?, 1);
    Ok(())
}

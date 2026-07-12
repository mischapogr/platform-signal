use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use signal_protocol::audit::{
    AppendError, AppendFuture, AuditAcknowledgement, AuditMetrics, PreparedAudit,
};
use signal_storage::{OperationContext, ParquetStore, StorageConfig};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};
use tower::ServiceExt;
pub(crate) static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
pub(crate) struct SyncedDestination {
    root: PathBuf,
    pub(crate) calls: AtomicU64,
    lose_on: u64,
}
impl AuditSink for SyncedDestination {
    fn append<'a>(&'a self, record: &'a PreparedAudit, _: std::time::Instant) -> AppendFuture<'a> {
        Box::pin(async move {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let path = self.root.join(record.record().sequence.to_string());
            if path.exists() {
                if fs::read(path).map_err(|_| AppendError::Uncertain)? != record.body() {
                    return Err(AppendError::Uncertain);
                }
            } else {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| AppendError::Uncertain)?;
                file.write_all(record.body())
                    .map_err(|_| AppendError::Uncertain)?;
                file.sync_all().map_err(|_| AppendError::Uncertain)?;
                File::open(&self.root)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| AppendError::Uncertain)?;
            }
            if self.lose_on == n {
                return Err(AppendError::Uncertain);
            }
            let ack = AuditAcknowledgement::for_prepared(record)
                .to_json()
                .map_err(|_| AppendError::Uncertain)?;
            record
                .verify_acknowledgement(&ack)
                .map_err(|_| AppendError::Uncertain)
        })
    }
    fn metrics(&self) -> AuditMetrics {
        AuditMetrics {
            capacity: 1,
            ..Default::default()
        }
    }
}
fn context() -> std::result::Result<ExtensionContext, Box<dyn std::error::Error>> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(10),
    )?)
}
pub(crate) fn root() -> std::io::Result<tempfile::TempDir> {
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    Ok(root)
}
pub(crate) fn destination(root: &Path, lose_on: u64) -> Arc<SyncedDestination> {
    Arc::new(SyncedDestination {
        root: root.into(),
        calls: AtomicU64::new(0),
        lose_on,
    })
}
async fn engine(
    path: &Path,
) -> std::result::Result<
    (Arc<ParquetStore>, Arc<signal_query::QueryEngine>),
    Box<dyn std::error::Error>,
> {
    let store = Arc::new(
        ParquetStore::open(
            StorageConfig {
                directory: path.into(),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await?,
    );
    let engine = Arc::new(signal_query::QueryEngine::new(
        Default::default(),
        store.clone(),
    )?);
    Ok((store, engine))
}
fn router(engine: Arc<signal_query::QueryEngine>, control: Arc<Control>) -> axum::Router {
    crate::query_api::router_with_identity(
        engine,
        signal_ingest::IngestConfig {
            api_token: Some("ordinary-test-secret".into()),
            ..Default::default()
        },
        1000,
        Duration::from_secs(10),
        CancellationToken::new(),
        None,
        Some(control),
    )
}
fn request(uri: &str, token: bool) -> std::result::Result<Request<Body>, axum::http::Error> {
    let mut builder = Request::builder().uri(uri);
    if token {
        builder = builder.header("authorization", "Bearer ordinary-test-secret");
    }
    builder.body(Body::empty())
}
async fn stopped(store: Arc<ParquetStore>, engine: Arc<signal_query::QueryEngine>) -> Result {
    engine
        .shutdown(OperationContext::new(Duration::from_secs(10)))
        .await?;
    store
        .shutdown(OperationContext::new(Duration::from_secs(10)))
        .await?;
    Ok(())
}
#[tokio::test]
async fn query_grant_denial_and_invalid_input_emit_exact_secret_free_control_pairs() -> Result {
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let data = root()?;
    let sink = destination(archive.path(), 0);
    let control = Control::open(
        spool.path(),
        sink.clone(),
        vec![Operation::QueryEvents],
        context()?,
    )
    .await?;
    let (store, engine) = engine(data.path()).await?;
    let routes = router(engine.clone(), control.clone());
    for (uri, token, status) in [
        (
            "/v1/events?contains=synthetic-sensitive-query&limit=1",
            true,
            StatusCode::OK,
        ),
        ("/v1/events", false, StatusCode::UNAUTHORIZED),
        ("/v1/events?limit=0", true, StatusCode::BAD_REQUEST),
    ] {
        let response = routes.clone().oneshot(request(uri, token)?).await?;
        assert_eq!(response.status(), status);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
    assert_eq!(sink.calls.load(Ordering::SeqCst), 6);
    for offset in [1, 3, 5] {
        let body = fs::read(archive.path().join(offset.to_string()))?;
        let end = fs::read(archive.path().join((offset + 1).to_string()))?;
        for record in [&body, &end] {
            let text = String::from_utf8_lossy(record);
            assert!(!text.contains("synthetic-sensitive-query"));
            assert!(!text.contains("ordinary-test-secret"));
            assert!(!text.contains("authorization"));
        }
        let start = PreparedAudit::from_original(&body)?;
        let finish = PreparedAudit::from_original(&end)?;
        assert_eq!(start.record().producer_id, finish.record().producer_id);
        assert_eq!(start.record().sequence + 1, finish.record().sequence);
        let Action::AccessDecision {
            operation_id: before,
            decision,
            ..
        } = start.record().action
        else {
            panic!("decision required")
        };
        let Action::OperationCompletion {
            operation_id: after,
            completion,
            ..
        } = finish.record().action
        else {
            panic!("completion required")
        };
        assert_eq!(before, after);
        if offset == 3 {
            assert!(decision == Decision::Denied && completion == Completion::Denied);
            assert!(matches!(start.record().actor, Actor::Unattributed {}));
        } else {
            assert!(decision == Decision::Granted);
            assert!(matches!(start.record().actor, Actor::Bootstrap {}));
            assert!(
                completion
                    == if offset == 1 {
                        Completion::Success
                    } else {
                        Completion::Failed
                    }
            );
        }
    }
    assert_eq!(engine.metrics().requests, 1);
    assert!(!control.metrics().held);
    assert_eq!(control.metrics().depth, 0);
    stopped(store, engine).await
}
#[tokio::test]
async fn lost_decision_reply_prevents_query_and_exact_reopen_cannot_authorize_fresh_request()
-> Result {
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let data = root()?;
    let sink = destination(archive.path(), 1);
    let control = Control::open(
        spool.path(),
        sink.clone(),
        vec![Operation::QueryEvents],
        context()?,
    )
    .await?;
    let (store, engine) = engine(data.path()).await?;
    let routes = router(engine.clone(), control.clone());
    let response = routes.clone().oneshot(request("/v1/events", true)?).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(engine.metrics().requests, 0);
    let original = fs::read(archive.path().join("1"))?;
    assert!(control.metrics().held);
    assert_eq!(
        routes
            .clone()
            .oneshot(request("/v1/events", true)?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    drop(routes);
    drop(control);
    let reopened = Control::open(
        spool.path(),
        sink.clone(),
        vec![Operation::QueryEvents],
        context()?,
    )
    .await?;
    assert_eq!(fs::read(archive.path().join("1"))?, original);
    assert_eq!(engine.metrics().requests, 0);
    let routes = router(engine.clone(), reopened);
    assert_eq!(
        routes.oneshot(request("/v1/events", true)?).await?.status(),
        StatusCode::OK
    );
    let old = PreparedAudit::from_original(&original)?;
    let fresh = PreparedAudit::from_original(&fs::read(archive.path().join("2"))?)?;
    let Action::AccessDecision {
        operation_id: first,
        ..
    } = old.record().action
    else {
        panic!("old decision")
    };
    let Action::AccessDecision {
        operation_id: second,
        ..
    } = fresh.record().action
    else {
        panic!("new decision")
    };
    assert_ne!(first, second);
    stopped(store, engine).await
}
#[tokio::test]
async fn lost_completion_reply_withholds_query_response_and_preserves_exact_pending() -> Result {
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let data = root()?;
    let sink = destination(archive.path(), 2);
    let control = Control::open(
        spool.path(),
        sink.clone(),
        vec![Operation::QueryEvents],
        context()?,
    )
    .await?;
    let (store, engine) = engine(data.path()).await?;
    let routes = router(engine.clone(), control.clone());
    let response = routes.clone().oneshot(request("/v1/events", true)?).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert!(!String::from_utf8_lossy(&body).contains("events"));
    assert_eq!(engine.metrics().completed, 1);
    let original = fs::read(archive.path().join("2"))?;
    assert!(control.metrics().held);
    assert_eq!(
        routes
            .clone()
            .oneshot(request("/v1/events", true)?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(engine.metrics().requests, 1);
    drop(routes);
    drop(control);
    let reopened =
        Control::open(spool.path(), sink, vec![Operation::QueryEvents], context()?).await?;
    assert_eq!(fs::read(archive.path().join("2"))?, original);
    assert_eq!(reopened.metrics().pending, 0);
    stopped(store, engine).await
}
#[tokio::test]
async fn capacity_and_incomplete_drop_are_visible_without_detached_completion() -> Result {
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let sink = destination(archive.path(), 0);
    let control = Control::open(
        spool.path(),
        sink.clone(),
        vec![Operation::QueryEvents],
        context()?,
    )
    .await?;
    let original = context()?;
    let session = control
        .begin(
            Actor::Anonymous {},
            Decision::Granted,
            Operation::QueryEvents,
            original.deadline(),
            original.cancellation().clone(),
        )
        .await?;
    assert_eq!(control.metrics().depth, 1);
    assert_eq!(control.metrics().capacity, 1);
    assert!(!control.metrics().held);
    assert!(
        control
            .begin(
                Actor::Anonymous {},
                Decision::Granted,
                Operation::QueryEvents,
                original.deadline(),
                original.cancellation().clone()
            )
            .await
            .is_err()
    );
    assert_eq!(control.metrics().rejected, 1);
    drop(session);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.metrics().depth, 0);
    assert_eq!(control.metrics().incomplete, 1);
    assert!(control.metrics().held);
    assert!(
        control
            .begin(
                Actor::Anonymous {},
                Decision::Granted,
                Operation::QueryEvents,
                original.deadline(),
                original.cancellation().clone()
            )
            .await
            .is_err()
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn completion_uses_original_clock_and_denied_decision_cannot_report_success() -> Result {
    let _serial = SERIAL.lock().await;
    for mode in ["cancelled", "expired", "denied"] {
        let denied = mode == "denied";
        let spool = root()?;
        let archive = root()?;
        let sink = destination(archive.path(), 0);
        let control = Control::open(
            spool.path(),
            sink.clone(),
            vec![Operation::QueryEvents],
            context()?,
        )
        .await?;
        let cancel = CancellationToken::new();
        let until = Instant::now() + Duration::from_secs(2);
        let session = control
            .begin(
                Actor::Anonymous {},
                if denied {
                    Decision::Denied
                } else {
                    Decision::Granted
                },
                Operation::QueryEvents,
                until,
                cancel.clone(),
            )
            .await?;
        assert_eq!(session.context.deadline(), until);
        if mode == "cancelled" {
            cancel.cancel();
        } else if mode == "expired" {
            tokio::time::sleep_until(until).await;
        }
        assert!(session.finish(Completion::Success).await.is_err());
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
        assert!(control.metrics().held);
    }
    Ok(())
}
#[test]
fn configuration_is_strict_scoped_bounded_and_never_prints_values() -> Result {
    let original = serde_json::json!({"schema_version":1,"operations":["query_events"],
        "endpoint":"https://audit.example.invalid/v1/audit/records", "tls_config":"/private/tls.json",
        "outbox_directory":"/private/audit", "connect_timeout_ms":1000});
    Wire::parse(&original.to_string())?;
    for operations in [
        serde_json::json!(["read_findings"]),
        serde_json::json!(["read_findings_feed", "query_events"]),
        serde_json::json!(["query_events", "read_findings", "read_findings_feed"]),
        serde_json::json!(["read_coverage", "write_coverage"]),
        serde_json::json!([
            "query_events",
            "read_findings",
            "read_findings_feed",
            "read_coverage",
            "write_coverage"
        ]),
    ] {
        let mut selected = original.clone();
        selected["operations"] = operations;
        Wire::parse(&selected.to_string())?;
    }
    for (key, value) in [
        ("schema_version", serde_json::json!(2)),
        ("operations", serde_json::json!(["ingest_events"])),
        ("operations", serde_json::json!([])),
        (
            "operations",
            serde_json::json!([
                "query_events",
                "read_findings",
                "read_findings_feed",
                "read_findings"
            ]),
        ),
        (
            "operations",
            serde_json::json!(["query_events", "query_events"]),
        ),
        ("outbox_directory", serde_json::json!("relative")),
        ("tls_config", serde_json::json!(null)),
        ("endpoint", serde_json::json!("x".repeat(2049))),
        ("connect_timeout_ms", serde_json::json!(0)),
        ("token", serde_json::json!("synthetic-secret")),
    ] {
        let mut value_doc = original.clone();
        value_doc[key] = value;
        let error = Wire::parse(&value_doc.to_string())
            .err()
            .ok_or("configuration should fail")?;
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
    }
    assert!(Wire::parse(&format!("[{original}]")).is_err());
    assert!(
        Wire::parse(&original.to_string().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1
        ))
        .is_err()
    );
    Ok(())
}

fn read_operations() -> Vec<Operation> {
    vec![
        Operation::QueryEvents,
        Operation::ReadFindings,
        Operation::ReadFindingsFeed,
    ]
}
async fn findings_store(
    path: &Path,
) -> std::result::Result<Arc<signal_findings::FindingStore>, Box<dyn std::error::Error>> {
    let store = Arc::new(
        signal_findings::FindingStore::open(
            signal_findings::FindingConfig {
                directory: path.into(),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await?,
    );
    store
        .append(
            vec![signal_findings::Finding {
                schema_version: 1,
                id: Uuid::new_v4(),
                rule_id: "synthetic.rule".into(),
                created_at: Utc::now(),
                severity: signal_findings::DetectionSeverity::High,
                title: "synthetic-sensitive-finding".into(),
                event_ids: vec![Uuid::new_v4()],
                attributes: Default::default(),
            }],
            signal_findings::FindingContext::new(Duration::from_secs(10)),
        )
        .await?;
    Ok(store)
}
fn findings_router(
    store: Arc<signal_findings::FindingStore>,
    control: Arc<Control>,
) -> axum::Router {
    crate::finding_api::router_with_security(
        store,
        signal_ingest::IngestConfig {
            api_token: Some("ordinary-test-secret".into()),
            ..Default::default()
        },
        1000,
        65536,
        Duration::from_secs(10),
        CancellationToken::new(),
        crate::finding_api::Security {
            identity: None,
            audit: Some(control),
        },
    )
}
async fn finding_shutdown(store: Arc<signal_findings::FindingStore>) -> Result {
    store
        .shutdown(signal_findings::FindingContext::new(Duration::from_secs(
            10,
        )))
        .await?;
    Ok(())
}
#[tokio::test]
async fn findings_list_feed_denials_and_invalid_cursors_emit_exact_control_pairs() -> Result {
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let data = root()?;
    let sink = destination(archive.path(), 0);
    let control = Control::open(spool.path(), sink.clone(), read_operations(), context()?).await?;
    let store = findings_store(data.path()).await?;
    let routes = findings_router(store.clone(), control.clone());
    for (uri, token, expected, operation, completion) in [
        (
            "/v1/findings",
            true,
            StatusCode::OK,
            Operation::ReadFindings,
            Completion::Success,
        ),
        (
            "/v1/findings/feed?after=begin",
            true,
            StatusCode::OK,
            Operation::ReadFindingsFeed,
            Completion::Success,
        ),
        (
            "/v1/findings?rule_id=synthetic-private-filter",
            false,
            StatusCode::UNAUTHORIZED,
            Operation::ReadFindings,
            Completion::Denied,
        ),
        (
            "/v1/findings/feed?after=synthetic-private-cursor",
            false,
            StatusCode::UNAUTHORIZED,
            Operation::ReadFindingsFeed,
            Completion::Denied,
        ),
        (
            "/v1/findings/feed?after=synthetic-private-cursor",
            true,
            StatusCode::BAD_REQUEST,
            Operation::ReadFindingsFeed,
            Completion::Failed,
        ),
    ] {
        let response = routes.clone().oneshot(request(uri, token)?).await?;
        assert_eq!(response.status(), expected);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let body = axum::body::to_bytes(response.into_body(), 65536).await?;
        if expected == StatusCode::OK {
            assert!(String::from_utf8_lossy(&body).contains("synthetic-sensitive-finding"));
        }
        let sequence = sink.calls.load(Ordering::SeqCst);
        let first = PreparedAudit::from_original(&fs::read(
            archive.path().join((sequence - 1).to_string()),
        )?)?;
        let last =
            PreparedAudit::from_original(&fs::read(archive.path().join(sequence.to_string()))?)?;
        let Action::AccessDecision {
            operation: actual,
            operation_id,
            decision,
        } = first.record().action
        else {
            return Err("expected decision".into());
        };
        assert_eq!(actual, operation);
        assert!(
            last.record().action
                == Action::OperationCompletion {
                    operation,
                    operation_id,
                    completion
                }
        );
        assert!(
            decision
                == if completion == Completion::Denied {
                    Decision::Denied
                } else {
                    Decision::Granted
                }
        );
        for prepared in [first, last] {
            let raw = String::from_utf8_lossy(prepared.body());
            for secret in [
                "ordinary-test-secret",
                "synthetic-sensitive-finding",
                "synthetic-private-filter",
                "synthetic-private-cursor",
            ] {
                assert!(!raw.contains(secret));
            }
        }
    }
    assert_eq!(sink.calls.load(Ordering::SeqCst), 10);
    assert!(!control.metrics().held);
    drop(routes);
    drop(control);
    finding_shutdown(store).await
}
#[tokio::test]
async fn findings_lost_decision_or_completion_withholds_data_and_replays_exact_bytes() -> Result {
    let _serial = SERIAL.lock().await;
    for uri in ["/v1/findings", "/v1/findings/feed?after=begin"] {
        for lose_on in [1, 2] {
            let spool = root()?;
            let archive = root()?;
            let data = root()?;
            let sink = destination(archive.path(), lose_on);
            let control =
                Control::open(spool.path(), sink.clone(), read_operations(), context()?).await?;
            let store = findings_store(data.path()).await?;
            let routes = findings_router(store.clone(), control.clone());
            let response = routes.clone().oneshot(request(uri, true)?).await?;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response
                    .headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok()),
                Some("no-store")
            );
            let body = axum::body::to_bytes(response.into_body(), 65536).await?;
            let value: serde_json::Value = serde_json::from_slice(&body)?;
            assert_eq!(value["error"]["code"], "audit_unavailable");
            assert!(value.get("findings").is_none() && value.get("next_cursor").is_none());
            assert!(!String::from_utf8_lossy(&body).contains("synthetic-sensitive-finding"));
            assert!(control.metrics().held);
            let original = fs::read(spool.path().join("pending"))?;
            assert_eq!(
                original,
                fs::read(archive.path().join(lose_on.to_string()))?
            );
            let old = PreparedAudit::from_original(&original)?;
            let old_operation = match old.record().action {
                Action::AccessDecision { operation_id, .. }
                | Action::OperationCompletion { operation_id, .. } => operation_id,
                _ => return Err("expected read action".into()),
            };
            drop(routes);
            drop(control);
            let reopened =
                Control::open(spool.path(), sink.clone(), read_operations(), context()?).await?;
            assert!(!reopened.metrics().held);
            assert_eq!(
                fs::read(archive.path().join(lose_on.to_string()))?,
                original
            );
            let response = findings_router(store.clone(), reopened.clone())
                .oneshot(request(uri, true)?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let fresh = PreparedAudit::from_original(&fs::read(
                archive.path().join((lose_on + 1).to_string()),
            )?)?;
            let Action::AccessDecision { operation_id, .. } = fresh.record().action else {
                return Err("expected new decision".into());
            };
            assert_ne!(operation_id, old_operation);
            assert_eq!(sink.calls.load(Ordering::SeqCst), lose_on + 3);
            drop(reopened);
            finding_shutdown(store).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn selected_reads_share_one_session_without_queueing_or_cross_operation_completion() -> Result
{
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let data = root()?;
    let sink = destination(archive.path(), 0);
    let control = Control::open(spool.path(), sink.clone(), read_operations(), context()?).await?;
    let store = findings_store(data.path()).await?;
    let routes = findings_router(store.clone(), control.clone());
    let ctx = context()?;
    let session = control
        .begin(
            Actor::Anonymous {},
            Decision::Granted,
            Operation::QueryEvents,
            ctx.deadline(),
            ctx.cancellation().clone(),
        )
        .await?;
    for uri in ["/v1/findings", "/v1/findings/feed?after=begin"] {
        let response = routes.clone().oneshot(request(uri, true)?).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.metrics().rejected, 2);
    assert_eq!(control.metrics().capacity, 1);
    assert!(!control.metrics().held);
    session.finish(Completion::Success).await?;
    assert_eq!(
        routes
            .clone()
            .oneshot(request("/v1/findings", true)?)
            .await?
            .status(),
        StatusCode::OK
    );
    let last = PreparedAudit::from_original(&fs::read(archive.path().join("4"))?)?;
    assert!(matches!(
        last.record().action,
        Action::OperationCompletion {
            operation: Operation::ReadFindings,
            completion: Completion::Success,
            ..
        }
    ));
    drop(routes);
    drop(control);
    finding_shutdown(store).await
}
#[tokio::test]
async fn explicit_read_selection_does_not_silently_enable_other_paths() -> Result {
    let _serial = SERIAL.lock().await;
    let spool = root()?;
    let archive = root()?;
    let data = root()?;
    let query_data = root()?;
    let sink = destination(archive.path(), 0);
    let control = Control::open(
        spool.path(),
        sink.clone(),
        vec![Operation::ReadFindings],
        context()?,
    )
    .await?;
    let store = findings_store(data.path()).await?;
    let routes = findings_router(store.clone(), control.clone());
    let (query_store, query_engine) = engine(query_data.path()).await?;
    assert_eq!(
        router(query_engine.clone(), control.clone())
            .oneshot(request("/v1/events", true)?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        routes
            .clone()
            .oneshot(request("/v1/findings/feed?after=begin", true)?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    let ctx = context()?;
    assert!(
        control
            .begin(
                Actor::Anonymous {},
                Decision::Granted,
                Operation::ReadFindingsFeed,
                ctx.deadline(),
                ctx.cancellation().clone()
            )
            .await
            .is_err()
    );
    let session = control
        .begin(
            Actor::Anonymous {},
            Decision::Granted,
            Operation::ReadFindings,
            ctx.deadline(),
            ctx.cancellation().clone(),
        )
        .await?;
    drop(session);
    assert!(control.metrics().held);
    assert_eq!(
        routes
            .clone()
            .oneshot(request("/v1/findings", true)?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        routes
            .clone()
            .oneshot(request("/v1/findings/feed?after=begin", true)?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    drop(routes);
    drop(control);
    finding_shutdown(store).await?;
    stopped(query_store, query_engine).await
}

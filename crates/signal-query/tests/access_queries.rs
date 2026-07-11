//! Real committed Parquet/DataFusion tests of trusted-host request grants.
//! Constructing these grants is not proof of authentication at an HTTP route.
use chrono::Utc;
use serde_json::{Value, json};
use signal_event::{IngestEvent, SignalEvent};
use signal_protocol::{
    EventQuery, QueryOrder,
    access::{AccessPolicy, AuthenticatedIdentity, RequestGrant},
};
use signal_query::{QueryConfig, QueryEngine, QueryError};
use signal_storage::{
    FileSelection, OperationContext, ParquetStore, QueryFileSource, StorageConfig, StoreFuture,
    StoredEvent,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
fn selector(value: Option<&str>) -> Value {
    value.map_or_else(
        || json!({"mode":"all"}),
        |value| json!({"mode":"only","values":[value]}),
    )
}
fn permission(
    operation: &str,
    source: Option<&str>,
    account: Option<&str>,
    resource: Option<&str>,
) -> Value {
    json!({"operation":operation,"scope":{"sources":selector(source),"accounts":selector(account),"resources":selector(resource)}})
}
fn grant(permissions: Vec<Value>, issued: u64, expiry: u64) -> Result<RequestGrant> {
    let roles: Vec<_> = permissions
        .into_iter()
        .enumerate()
        .map(|(i, permission)| json!({"id":format!("role-{i}"),"permissions":[permission]}))
        .collect();
    let names: Vec<_> = (0..roles.len()).map(|i| format!("role-{i}")).collect();
    let policy=AccessPolicy::from_json(&serde_json::to_vec(&json!({"schema_version":1,"roles":roles,"bindings":[{"issuer":"https://identity.example.test","subject":"reader","roles":names}]}))?)?.compile()?;
    Ok(policy.grant(
        AuthenticatedIdentity::from_verified_backend(
            "https://identity.example.test".into(),
            "reader".into(),
            issued,
            expiry,
        )?,
        issued,
    )?)
}
fn event(
    id: u128,
    source: &str,
    account: Option<&str>,
    resource: Option<&str>,
) -> Result<SignalEvent> {
    let mut input = json!({"id":Uuid::from_u128(id),"timestamp":format!("2026-09-01T{:02}:00:00Z",id/10),"source":{"type":source},"message":"synthetic evidence","attributes":{"resource":{"account_id":"a","id":"host-a"},"user":{"roles":["administrator"]}}});
    if let Some(resource) = resource {
        input["resource"] = json!({"kind":"host","id":resource,"account_id":account});
    }
    let input: IngestEvent = serde_json::from_value(input)?;
    Ok(input.normalize(Utc::now())?)
}
async fn store(events: Vec<SignalEvent>) -> Result<(tempfile::TempDir, Arc<ParquetStore>)> {
    let temp = tempfile::tempdir()?;
    let store = Arc::new(
        ParquetStore::open(
            StorageConfig {
                directory: temp.path().join("events"),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await?,
    );
    if !events.is_empty() {
        store
            .append(
                events
                    .into_iter()
                    .enumerate()
                    .map(|(i, event)| StoredEvent {
                        sequence: i as u64 + 1,
                        event,
                    })
                    .collect(),
                context(),
            )
            .await?;
    }
    Ok((temp, store))
}
fn ids(response: signal_protocol::EventQueryResponse) -> Vec<u128> {
    response
        .events
        .iter()
        .map(|event| event.id.as_u128())
        .collect()
}

#[tokio::test]
async fn complete_scope_pairs_precede_sort_limit_and_user_filters() -> Result {
    let (_temp, store) = store(vec![
        event(10, "auth", Some("a"), Some("host-a"))?,
        event(20, "flow", Some("b"), Some("host-b"))?,
        event(30, "auth", Some("b"), Some("host-b"))?,
        event(40, "flow", Some("a"), Some("host-a"))?,
        event(50, "other", Some("c"), Some("host-c"))?,
        event(60, "auth", None, None)?,
    ])
    .await?;
    let engine = QueryEngine::new(QueryConfig::default(), store.clone())?;
    let now = now()?;
    let authority = grant(
        vec![
            permission("query_events", Some("auth"), Some("a"), Some("host-a")),
            permission("query_events", Some("flow"), Some("b"), Some("host-b")),
            permission("read_findings", Some("other"), Some("c"), Some("host-c")),
        ],
        now,
        now + 60,
    )?;
    assert_eq!(
        ids(engine
            .execute_authorized(
                EventQuery {
                    limit: 1,
                    order: QueryOrder::Desc,
                    ..Default::default()
                },
                context(),
                &authority
            )
            .await?),
        vec![20]
    );
    assert_eq!(
        ids(engine
            .execute_authorized(
                EventQuery {
                    limit: 1,
                    order: QueryOrder::Asc,
                    ..Default::default()
                },
                context(),
                &authority
            )
            .await?),
        vec![10]
    );
    assert_eq!(
        ids(engine
            .execute_authorized(
                EventQuery {
                    account: Some("b".into()),
                    ..Default::default()
                },
                context(),
                &authority
            )
            .await?),
        vec![20]
    );
    assert!(
        engine
            .execute_authorized(
                EventQuery {
                    source: Some("auth".into()),
                    account: Some("b".into()),
                    ..Default::default()
                },
                context(),
                &authority
            )
            .await?
            .events
            .is_empty()
    );
    assert_eq!(
        ids(engine
            .execute_authorized(
                EventQuery {
                    order: QueryOrder::Asc,
                    ..Default::default()
                },
                context(),
                &authority
            )
            .await?),
        vec![10, 20]
    );
    engine.shutdown(context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn restricted_selectors_are_literal_and_missing_facts_never_use_attributes() -> Result {
    let (_temp, store) = store(vec![
        event(10, "cloud*", Some("*"), Some("host-a"))?,
        event(20, "cloud-other", Some("*"), Some("host-a"))?,
        event(30, "cloud*", Some("a"), Some("host-a"))?,
        event(40, "cloud*", None, Some("host-a"))?,
        event(50, "cloud*", None, None)?,
    ])
    .await?;
    let engine = QueryEngine::new(QueryConfig::default(), store.clone())?;
    let now = now()?;
    let authority = grant(
        vec![permission(
            "query_events",
            Some("cloud*"),
            Some("*"),
            Some("host-a"),
        )],
        now,
        now + 60,
    )?;
    assert_eq!(
        ids(engine
            .execute_authorized(
                EventQuery {
                    limit: 1,
                    ..Default::default()
                },
                context(),
                &authority
            )
            .await?),
        vec![10]
    );
    engine.shutdown(context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}
struct ObservedSource {
    store: Arc<ParquetStore>,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    gate: Option<Arc<tokio::sync::Semaphore>>,
}
impl QueryFileSource for ObservedSource {
    fn select_query_files(
        &self,
        from: Option<chrono::DateTime<Utc>>,
        to: Option<chrono::DateTime<Utc>>,
        max_files: usize,
        max_decoded_bytes: u64,
        context: OperationContext,
    ) -> StoreFuture<'_, FileSelection> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let selection = self
                .store
                .select_query_files(from, to, max_files, max_decoded_bytes, context)
                .await?;
            self.entered.notify_one();
            if let Some(gate) = &self.gate {
                let _permit = gate
                    .acquire()
                    .await
                    .map_err(|_| signal_storage::StorageError::QueryUnavailable)?;
            }
            Ok(selection)
        })
    }
}

#[tokio::test]
async fn ready_empty_selection_cannot_return_success_after_original_request_deadline() -> Result {
    let (_temp, store) = store(Vec::new()).await?;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let source = Arc::new(ObservedSource {
        store: store.clone(),
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        gate: Some(gate.clone()),
    });
    let engine = QueryEngine::with_source(QueryConfig::default(), source.clone())?;
    let now = now()?;
    let authority = grant(
        vec![permission("query_events", None, None, None)],
        now,
        now + 60,
    )?;
    let request = OperationContext::new(Duration::from_secs(1));
    let deadline = request.deadline;
    let query = engine.execute_authorized(EventQuery::default(), request, &authority);
    tokio::pin!(query);
    tokio::select! {biased;
        result = &mut query => panic!("query must wait, returned {}", result.is_ok()),
        _ = source.entered.notified() => {}
    }
    gate.add_permits(1);
    // Do not poll query until its prepared result and timer are both ready.
    tokio::time::sleep_until(deadline + Duration::from_millis(10)).await;
    assert!(matches!(query.await, Err(QueryError::Timeout)));
    assert_eq!(engine.metrics().completed, 0);
    assert_eq!(engine.metrics().timeouts, 1);
    engine.shutdown(context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn absent_capability_and_expired_grants_deny_before_selection_even_when_empty() -> Result {
    let (_temp, store) = store(Vec::new()).await?;
    let source = Arc::new(ObservedSource {
        store: store.clone(),
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        gate: None,
    });
    let engine = QueryEngine::with_source(QueryConfig::default(), source.clone())?;
    let now = now()?;
    for authority in [
        grant(
            vec![permission("read_findings", None, None, None)],
            now,
            now + 60,
        )?,
        grant(
            vec![permission("query_events", None, None, None)],
            now - 2,
            now - 1,
        )?,
    ] {
        assert!(matches!(
            engine
                .execute_authorized(EventQuery::default(), context(), &authority)
                .await,
            Err(QueryError::Denied)
        ));
        assert!(matches!(
            engine
                .execute_authorized(
                    EventQuery {
                        limit: 0,
                        ..Default::default()
                    },
                    context(),
                    &authority
                )
                .await,
            Err(QueryError::Denied)
        ));
    }
    assert_eq!(source.calls.load(Ordering::Acquire), 0);
    let authority = grant(
        vec![permission("query_events", None, None, None)],
        now,
        now + 60,
    )?;
    assert!(
        engine
            .execute_authorized(EventQuery::default(), context(), &authority)
            .await?
            .events
            .is_empty()
    );
    assert_eq!(source.calls.load(Ordering::Acquire), 1);
    engine.shutdown(context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn expiry_during_selection_denies_before_data_reads_or_empty_success() -> Result {
    for events in [
        Vec::new(),
        vec![event(10, "auth", Some("a"), Some("host-a"))?],
    ] {
        let (_temp, store) = store(events).await?;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let source = Arc::new(ObservedSource {
            store: store.clone(),
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            gate: Some(gate.clone()),
        });
        let engine = QueryEngine::with_source(QueryConfig::default(), source.clone())?;
        let now_at_start = now()?;
        let expiry = now_at_start + 2;
        let authority = grant(
            vec![permission("query_events", None, None, None)],
            now_at_start,
            expiry,
        )?;
        let query = engine.execute_authorized(EventQuery::default(), context(), &authority);
        tokio::pin!(query);
        tokio::select! {biased; result=&mut query=>panic!("query must wait, returned {}",result.is_ok()),_=source.entered.notified()=>{}}
        while now()? < expiry {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        gate.add_permits(1);
        assert!(matches!(query.await, Err(QueryError::Denied)));
        assert_eq!(engine.metrics().io_bytes, 0);
        assert_eq!(engine.metrics().completed, 0);
        engine.shutdown(context()).await?;
        store.shutdown(context()).await?;
    }
    Ok(())
}

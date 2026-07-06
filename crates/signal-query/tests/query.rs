use chrono::{DateTime, Utc};
use serde_json::json;
use signal_event::{IngestEvent, SignalEvent};
use signal_protocol::{AttributeFilter, EventQuery, QueryOrder};
use signal_query::{QueryConfig, QueryEngine, QueryError};
use signal_storage::{OperationContext, ParquetStore, StorageConfig, StoredEvent};
use std::{future::Future, sync::Arc, time::Duration};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
fn timestamp(text: &str) -> TestResult<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(text)?.with_timezone(&Utc))
}
fn event(id: u128, time: &str, message: Option<&str>, severity: &str) -> TestResult<SignalEvent> {
    let input: IngestEvent = serde_json::from_value(json!({
        "id": Uuid::from_u128(id), "timestamp": time, "source": {"type":"application", "name":"api"},
        "severity": severity, "message": message,
        "attributes": {"user":{"name":"alice", "active":true}, "owner.team":"platform", "null":null,
            "number": 5, "array":[1,true], "object":{"key":"value"}},
        "resource":{"kind":"host","id":"node-1","account_id":"test-account"}
    }))?;
    Ok(input.normalize(timestamp("2026-10-06T12:00:00Z")?)?)
}
async fn fixture(
    events: Vec<SignalEvent>,
    config: QueryConfig,
) -> TestResult<(tempfile::TempDir, Arc<ParquetStore>, QueryEngine)> {
    let temp = tempfile::TempDir::new()?;
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
    store
        .append(
            events
                .into_iter()
                .enumerate()
                .map(|(index, event)| StoredEvent {
                    sequence: index as u64 + 1,
                    event,
                })
                .collect(),
            context(),
        )
        .await?;
    let engine = QueryEngine::new(config, store.clone())?;
    Ok((temp, store, engine))
}
fn ids(response: signal_protocol::EventQueryResponse) -> Vec<u128> {
    response
        .events
        .iter()
        .map(|event| event.id.as_u128())
        .collect()
}

#[tokio::test]
async fn actual_parquet_applies_every_filter_and_preserves_canonical_events() -> TestResult {
    let original = event(
        2,
        "2026-10-06T12:00:00.000000001Z",
        Some("failed login"),
        "error",
    )?;
    let (_temp, store, engine) = fixture(
        vec![
            original.clone(),
            event(1, "2026-10-06T12:00:00Z", Some("ordinary"), "info")?,
            event(3, "2026-10-06T13:00:00Z", Some("failed login"), "error")?,
        ],
        QueryConfig::default(),
    )
    .await?;
    let query = EventQuery {
        from: Some(timestamp("2026-10-06T12:00:00.000000001Z")?),
        to: Some(timestamp("2026-10-06T13:00:00Z")?),
        contains: Some("failed".into()),
        severity: Some(signal_event::Severity::Error),
        source_type: Some("application".into()),
        source_name: Some("api".into()),
        resource_kind: Some("host".into()),
        resource_id: Some("node-1".into()),
        account: Some("test-account".into()),
        attributes: vec![
            AttributeFilter {
                path: "user.name".into(),
                value: json!("alice"),
            },
            AttributeFilter {
                path: "user.active".into(),
                value: json!(true),
            },
            AttributeFilter {
                path: "owner.team".into(),
                value: json!("platform"),
            },
        ],
        ..Default::default()
    };
    let response = engine.execute(query, context()).await?;
    assert_eq!(response.events, vec![original]);
    assert_eq!(response.metadata.candidate_partitions, 1);
    assert_eq!(response.metadata.scanned_files, 1);
    assert_eq!(engine.metrics().completed, 1);
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn individual_filters_reject_mismatches_and_aliases_match() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![event(1, "2026-10-06T12:00:00Z", Some("hello"), "warn")?],
        QueryConfig::default(),
    )
    .await?;
    let queries = vec![
        EventQuery {
            contains: Some("missing".into()),
            ..Default::default()
        },
        EventQuery {
            source_type: Some("other".into()),
            ..Default::default()
        },
        EventQuery {
            source_name: Some("other".into()),
            ..Default::default()
        },
        EventQuery {
            resource_kind: Some("other".into()),
            ..Default::default()
        },
        EventQuery {
            resource_id: Some("other".into()),
            ..Default::default()
        },
        EventQuery {
            account: Some("other".into()),
            ..Default::default()
        },
        EventQuery {
            severity: Some(signal_event::Severity::Trace),
            ..Default::default()
        },
    ];
    for query in queries {
        assert!(engine.execute(query, context()).await?.events.is_empty());
    }
    assert_eq!(
        ids(engine
            .execute(
                EventQuery {
                    source: Some("application".into()),
                    resource: Some("node-1".into()),
                    ..Default::default()
                },
                context()
            )
            .await?),
        vec![1]
    );
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn typed_attributes_missing_null_objects_arrays_and_large_numbers_are_exact() -> TestResult {
    let mut original = event(1, "2026-10-06T12:00:00Z", None, "info")?;
    original.attributes.insert(
        "huge".into(),
        serde_json::from_str("1234567890123456789012345678901234567890")?,
    );
    let (_temp, store, engine) = fixture(vec![original], QueryConfig::default()).await?;
    for (path, value, expected) in [
        ("number", json!(5), 1),
        ("number", json!("5"), 0),
        ("null", json!(null), 1),
        ("missing", json!(null), 0),
        ("array", json!([1, true]), 1),
        ("object", json!({"key":"value"}), 1),
        (
            "huge",
            serde_json::from_str("1234567890123456789012345678901234567890")?,
            1,
        ),
        (
            "huge",
            serde_json::from_str("1234567890123456789012345678901234567891")?,
            0,
        ),
    ] {
        let query = EventQuery {
            attributes: vec![AttributeFilter {
                path: path.into(),
                value,
            }],
            ..Default::default()
        };
        assert_eq!(
            engine.execute(query, context()).await?.events.len(),
            expected
        );
    }
    assert!(
        engine
            .execute(
                EventQuery {
                    contains: Some("".into()),
                    ..Default::default()
                },
                context()
            )
            .await?
            .events
            .is_empty()
    );
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn stable_precise_order_limit_and_extreme_rfc3339_timestamps() -> TestResult {
    let events = vec![
        event(3, "9999-12-31T23:59:59.999999999Z", Some("late"), "info")?,
        event(2, "0000-01-01T00:00:00Z", Some("early"), "info")?,
        event(5, "2026-10-06T12:00:00.000000001Z", Some("tie"), "info")?,
        event(4, "2026-10-06T12:00:00.000000001Z", Some("tie"), "info")?,
        event(6, "2016-12-31T23:59:60Z", Some("leap"), "info")?,
    ];
    let (_temp, store, engine) = fixture(events, QueryConfig::default()).await?;
    assert_eq!(
        ids(engine.execute(EventQuery::default(), context()).await?),
        vec![2, 6, 4, 5, 3]
    );
    assert_eq!(
        ids(engine
            .execute(
                EventQuery {
                    order: QueryOrder::Desc,
                    limit: 3,
                    ..Default::default()
                },
                context()
            )
            .await?),
        vec![3, 5, 4]
    );
    assert_eq!(
        ids(engine
            .execute(
                EventQuery {
                    from: Some(timestamp("2016-12-31T23:59:60Z")?),
                    to: Some(timestamp("2017-01-01T00:00:00Z")?),
                    ..Default::default()
                },
                context()
            )
            .await?),
        vec![6]
    );
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn committed_paths_only_and_unrelated_corrupt_partition_is_not_scanned() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![
            event(1, "2026-10-06T12:00:00Z", Some("selected"), "info")?,
            event(2, "2026-10-07T13:00:00Z", Some("unrelated"), "info")?,
        ],
        QueryConfig::default(),
    )
    .await?;
    let selected = store
        .select_files(
            Some(timestamp("2026-10-07T13:00:00Z")?),
            Some(timestamp("2026-10-07T14:00:00Z")?),
            10,
            context(),
        )
        .await?;
    std::fs::write(&selected.files[0].path, b"broken")?;
    let query = EventQuery {
        from: Some(timestamp("2026-10-06T12:00:00Z")?),
        to: Some(timestamp("2026-10-06T13:00:00Z")?),
        ..Default::default()
    };
    let response = engine.execute(query, context()).await?;
    assert_eq!(response.metadata.scanned_files, 1);
    assert_eq!(ids(response), vec![1]);
    assert_eq!(
        engine.execute(EventQuery::default(), context()).await,
        Err(QueryError::Unavailable)
    );
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn configured_limits_bound_response_count_bytes_and_candidate_files() -> TestResult {
    let events = vec![
        event(1, "2026-10-06T12:00:00Z", Some(&"x".repeat(2048)), "info")?,
        event(2, "2026-10-06T13:00:00Z", Some("second"), "info")?,
    ];
    let (_temp, store, engine) = fixture(
        events,
        QueryConfig {
            max_limit: 1,
            max_response_bytes: 1024,
            max_files: 1,
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(
        engine.execute(EventQuery::default(), context()).await,
        Err(QueryError::Invalid)
    );
    assert_eq!(
        engine
            .execute(
                EventQuery {
                    limit: 1,
                    ..Default::default()
                },
                context()
            )
            .await,
        Err(QueryError::Resource)
    );
    let bounded = EventQuery {
        limit: 1,
        from: Some(timestamp("2026-10-06T12:00:00Z")?),
        to: Some(timestamp("2026-10-06T13:00:00Z")?),
        ..Default::default()
    };
    assert_eq!(
        engine.execute(bounded, context()).await,
        Err(QueryError::Resource)
    );
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn shared_memory_pool_exhaustion_has_no_spill_and_recovers() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![event(1, "2026-10-06T12:00:00Z", Some("hello"), "info")?],
        QueryConfig {
            memory_bytes: 1,
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(
        engine.execute(EventQuery::default(), context()).await,
        Err(QueryError::Resource)
    );
    assert!(engine.metrics().memory_bytes <= 1);
    assert_eq!(engine.metrics().depth, 0);
    let empty = EventQuery {
        from: Some(timestamp("2026-10-07T00:00:00Z")?),
        ..Default::default()
    };
    assert!(engine.execute(empty, context()).await?.events.is_empty());
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn admission_saturation_cancellation_and_expiry_release_capacity() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![event(1, "2026-10-06T12:00:00Z", Some("hello"), "info")?],
        QueryConfig {
            max_concurrent: 1,
            ..Default::default()
        },
    )
    .await?;
    let ctx = context();
    let cancellation = ctx.cancellation.clone();
    let mut first = Box::pin(engine.execute(EventQuery::default(), ctx));
    std::future::poll_fn(|ctx| {
        assert!(Future::poll(first.as_mut(), ctx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(engine.metrics().depth, 1);
    assert_eq!(
        engine.execute(EventQuery::default(), context()).await,
        Err(QueryError::Busy)
    );
    cancellation.cancel();
    assert_eq!(first.await, Err(QueryError::Cancelled));
    assert_eq!(engine.metrics().depth, 0);
    let mut expired = context();
    expired.deadline = tokio::time::Instant::now() - Duration::from_secs(1);
    assert_eq!(
        engine.execute(EventQuery::default(), expired).await,
        Err(QueryError::Timeout)
    );
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert_eq!(
        engine.execute(EventQuery::default(), cancelled).await,
        Err(QueryError::Cancelled)
    );
    assert_eq!(
        ids(engine.execute(EventQuery::default(), context()).await?),
        vec![1]
    );
    assert_eq!(engine.metrics().rejected, 1);
    assert_eq!(engine.metrics().timeouts, 1);
    assert_eq!(engine.metrics().cancelled, 2);
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn caller_dropping_query_future_releases_admission() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![event(1, "2026-10-06T12:00:00Z", Some("hello"), "info")?],
        QueryConfig {
            max_concurrent: 1,
            ..Default::default()
        },
    )
    .await?;
    let mut first = Box::pin(engine.execute(EventQuery::default(), context()));
    std::future::poll_fn(|ctx| {
        assert!(Future::poll(first.as_mut(), ctx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(engine.metrics().depth, 1);
    drop(first);
    assert_eq!(engine.metrics().depth, 0);
    assert_eq!(
        ids(engine.execute(EventQuery::default(), context()).await?),
        vec![1]
    );
    store.shutdown(context()).await?;
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected_before_runtime_creation() {
    assert!(matches!(
        QueryConfig {
            max_concurrent: 0,
            ..Default::default()
        }
        .validate(),
        Err(QueryError::Config(_))
    ));
    assert!(matches!(
        QueryConfig {
            timeout: Duration::ZERO,
            ..Default::default()
        }
        .validate(),
        Err(QueryError::Config(_))
    ));
    assert!(matches!(
        QueryConfig {
            batch_rows: usize::MAX,
            ..Default::default()
        }
        .validate(),
        Err(QueryError::Config(_))
    ));
}

#[tokio::test]
async fn compressed_scan_input_is_rejected_before_datafusion_decoding() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![event(
            1,
            "2026-10-06T12:00:00Z",
            Some(&"compressible ".repeat(20_000)),
            "info",
        )?],
        QueryConfig {
            memory_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .await?;
    let files = store.select_files(None, None, 1, context()).await?;
    assert!(files.files[0].bytes < 64 * 1024);
    assert!(files.files[0].uncompressed_bytes > 64 * 1024);
    assert_eq!(
        engine.execute(EventQuery::default(), context()).await,
        Err(QueryError::Resource)
    );
    assert_eq!(engine.metrics().memory_bytes, 0);
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn successful_response_stays_inside_actual_json_budget_and_overflow_fails_whole_query()
-> TestResult {
    let (_temp, store, engine) = fixture(
        vec![
            event(1, "2026-10-06T12:00:00Z", Some(&"x".repeat(1000)), "info")?,
            event(2, "2026-10-06T12:00:00Z", Some(&"y".repeat(1000)), "info")?,
        ],
        QueryConfig {
            max_response_bytes: 2048,
            ..Default::default()
        },
    )
    .await?;
    let first = engine
        .execute(
            EventQuery {
                limit: 1,
                ..Default::default()
            },
            context(),
        )
        .await?;
    assert_eq!(first.events.len(), 1);
    assert!(serde_json::to_vec(&first)?.len() <= 2048);
    assert_eq!(
        engine
            .execute(
                EventQuery {
                    limit: 2,
                    ..Default::default()
                },
                context()
            )
            .await,
        Err(QueryError::Resource)
    );
    assert_eq!(engine.metrics().completed, 1);
    assert_eq!(engine.metrics().failures, 1);
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn relative_storage_roots_and_special_path_characters_use_explicit_file_urls() -> TestResult {
    let temp = tempfile::TempDir::new_in(".")?;
    let directory = temp
        .path()
        .strip_prefix(std::env::current_dir()?)?
        .join("events # % ? ü");
    assert!(!directory.is_absolute());
    let store = Arc::new(
        ParquetStore::open(
            StorageConfig {
                directory,
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await?,
    );
    store
        .append(
            vec![StoredEvent {
                sequence: 1,
                event: event(1, "2026-10-06T12:00:00Z", Some("escaped path"), "info")?,
            }],
            context(),
        )
        .await?;
    let files = store.select_files(None, None, 1, context()).await?;
    assert!(files.files[0].path.is_absolute());
    let engine = QueryEngine::new(QueryConfig::default(), store.clone())?;
    assert_eq!(
        ids(engine.execute(EventQuery::default(), context()).await?),
        vec![1]
    );
    engine.shutdown(context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn one_candidate_file_allows_full_schema_vectored_reads() -> TestResult {
    let (_temp, store, engine) = fixture(
        vec![event(1, "2026-10-06T12:00:00Z", Some("one file"), "info")?],
        QueryConfig {
            max_files: 1,
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(
        ids(engine.execute(EventQuery::default(), context()).await?),
        vec![1]
    );
    engine.shutdown(context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}

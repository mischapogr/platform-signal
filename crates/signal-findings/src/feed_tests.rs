use super::*;
use signal_protocol::findings_feed::{FindingsAfter, FindingsFeedResponse};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn context() -> FindingContext {
    FindingContext::new(Duration::from_secs(3))
}
fn config(path: &Path) -> FindingConfig {
    FindingConfig {
        directory: path.into(),
        ..Default::default()
    }
}
fn finding(n: u128) -> Result<Finding, Box<dyn std::error::Error>> {
    Ok(Finding {
        schema_version: 1,
        id: Uuid::from_u128(n),
        rule_id: "generic.fixture".into(),
        created_at: "2026-10-08T12:00:00Z".parse()?,
        severity: DetectionSeverity::High,
        title: format!("Finding {n}"),
        event_ids: vec![Uuid::from_u128(n + 1000)],
        attributes: Default::default(),
    })
}
async fn page(
    store: &FindingStore,
    after: FindingsAfter,
    limit: usize,
) -> Result<FindingsFeedResponse<Finding>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &store
            .feed(
                FindingsFeedQuery { after, limit },
                8 * 1024 * 1024,
                context(),
            )
            .await?,
    )?)
}
fn after(
    page: &FindingsFeedResponse<Finding>,
) -> Result<FindingsAfter, Box<dyn std::error::Error>> {
    Ok(FindingsAfter::Cursor(FindingsCursor::decode(
        &page.next_cursor,
    )?))
}
fn raw_frame(data: &[u8]) -> Vec<u8> {
    let mut out = frame_header(data).to_vec();
    out.extend_from_slice(data);
    out
}
#[tokio::test]
async fn feed_restart_duplicates_late_findings_and_equal_times_preserve_append_positions()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let cfg = config(temp.path());
    let stream = Uuid::new_v4();
    let store = FindingStore::open(cfg.clone(), stream).await?;
    let empty = page(&store, FindingsAfter::Begin, 1).await?;
    assert!(empty.findings.is_empty() && !empty.has_more);
    assert_eq!(FindingsCursor::decode(&empty.next_cursor)?.position(), 0);
    // Existing batch journal order is finding ID, irrespective of supplied order.
    store
        .append(vec![finding(2)?, finding(1)?], context())
        .await?;
    let first = page(&store, after(&empty)?, 1).await?;
    assert_eq!(first.findings, vec![finding(1)?]);
    assert!(first.has_more);
    assert_eq!(
        page(&store, FindingsAfter::Begin, 1).await?.next_cursor,
        first.next_cursor
    );
    store.shutdown(context()).await?;
    let store = FindingStore::open(cfg, stream).await?;
    assert_eq!(
        store
            .append(vec![finding(1)?, finding(2)?], context())
            .await?
            .duplicates,
        2
    );
    let second = page(&store, after(&first)?, 1).await?;
    assert_eq!(second.findings, vec![finding(2)?]);
    assert!(!second.has_more);
    let mut late = finding(3)?;
    late.created_at = "2020-01-01T00:00:00Z".parse()?;
    store.append(vec![late.clone()], context()).await?;
    let third = page(&store, after(&second)?, 1).await?;
    assert_eq!(third.findings, vec![late]);
    store
        .append((4..=37).map(finding).collect::<Result<_, _>>()?, context())
        .await?;
    let mut previous = third;
    let mut ids = Vec::new();
    loop {
        let p = page(&store, after(&previous)?, 3).await?;
        ids.extend(p.findings.iter().map(|f| f.id));
        let more = p.has_more;
        previous = p;
        if !more {
            break;
        }
    }
    assert_eq!(ids, (4..=37).map(Uuid::from_u128).collect::<Vec<_>>());
    let tail = page(&store, after(&previous)?, 3).await?;
    assert!(tail.findings.is_empty() && !tail.has_more);
    assert_eq!(tail.next_cursor, previous.next_cursor);
    let list = store
        .query(
            FindingQuery {
                limit: 100,
                ..Default::default()
            },
            context(),
        )
        .await?;
    assert_eq!(list[0].id, Uuid::from_u128(3));
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn feed_restore_rejects_unavailable_divergent_or_foreign_prefix_without_tail_reset()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let cfg = config(temp.path());
    let stream = Uuid::new_v4();
    let store = FindingStore::open(cfg.clone(), stream).await?;
    store.append(vec![finding(1)?], context()).await?;
    let first = page(&store, FindingsAfter::Begin, 1).await?;
    store.shutdown(context()).await?;
    let backup = fs::read(temp.path().join("findings.journal"))?;
    let store = FindingStore::open(cfg.clone(), stream).await?;
    store.append(vec![finding(2)?], context()).await?;
    let second = page(&store, after(&first)?, 1).await?;
    store.shutdown(context()).await?;
    fs::write(temp.path().join("findings.journal"), &backup)?;
    let store = FindingStore::open(cfg.clone(), stream).await?;
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: after(&second)?,
                    limit: 1
                },
                65536,
                context()
            )
            .await,
        Err(FindingError::CursorPositionUnavailable)
    ));
    store.append(vec![finding(4)?], context()).await?;
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: after(&second)?,
                    limit: 1
                },
                65536,
                context()
            )
            .await,
        Err(FindingError::CursorHistoryMismatch)
    ));
    assert_eq!(
        page(&store, after(&first)?, 1).await?.findings,
        vec![finding(4)?]
    );
    let foreign = FindingsCursor::initial(Uuid::new_v4())?;
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Cursor(foreign),
                    limit: 1
                },
                65536,
                context()
            )
            .await,
        Err(FindingError::CursorStreamMismatch)
    ));
    assert!(!store.metrics().closed);
    store.shutdown(context()).await?;
    let relocated = tempfile::tempdir()?;
    fs::copy(
        temp.path().join("findings.journal"),
        relocated.path().join("findings.journal"),
    )?;
    let store = FindingStore::open(config(relocated.path()), stream).await?;
    assert_eq!(
        page(&store, after(&first)?, 1).await?.findings,
        vec![finding(4)?]
    );
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn feed_recovery_hashes_original_payload_and_excludes_semantic_duplicate_frames() -> TestResult
{
    let temp = tempfile::tempdir()?;
    let stream = Uuid::new_v4();
    let f = finding(1)?;
    let original = serde_json::to_vec_pretty(&f)?;
    let mut journal = b"SIGFND02".to_vec();
    journal.extend_from_slice(stream.as_bytes());
    journal.extend_from_slice(&raw_frame(&original));
    journal.extend_from_slice(&raw_frame(&serde_json::to_vec(&f)?));
    journal.extend_from_slice(&[1, 2, 3]);
    let complete = journal.len() - 3;
    fs::write(temp.path().join("findings.journal"), journal)?;
    let store = FindingStore::open(config(temp.path()), stream).await?;
    let p = page(&store, FindingsAfter::Begin, 10).await?;
    assert_eq!(p.findings, vec![f]);
    assert!(!p.has_more);
    assert_eq!(
        p.next_cursor,
        FindingsCursor::initial(stream)?
            .advance(&original)?
            .encode()
    );
    assert_eq!(store.metrics().disk_bytes, complete as u64);
    assert_eq!(store.metrics().index_bytes, FINDING_INDEX_BYTES);
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn feed_detects_live_payload_or_header_change_and_closes_instead_of_issuing_old_digest()
-> TestResult {
    for rewrite_checksum in [false, true] {
        let temp = tempfile::tempdir()?;
        let stream = Uuid::new_v4();
        let store = FindingStore::open(config(temp.path()), stream).await?;
        store.append(vec![finding(1)?], context()).await?;
        let path = temp.path().join("findings.journal");
        let mut journal = fs::read(&path)?;
        let old = journal[24 + FINDING_FRAME_BYTES..].to_vec();
        let mut changed = finding(1)?;
        changed.title = "Finding X".into();
        let new = serde_json::to_vec(&changed)?;
        assert_eq!(new.len(), old.len());
        journal[24 + FINDING_FRAME_BYTES..].copy_from_slice(&new);
        if rewrite_checksum {
            journal[24..24 + FINDING_FRAME_BYTES].copy_from_slice(&frame_header(&new));
        }
        fs::write(&path, journal)?;
        assert!(matches!(
            store
                .feed(
                    FindingsFeedQuery {
                        after: FindingsAfter::Begin,
                        limit: 1
                    },
                    65536,
                    context()
                )
                .await,
            Err(FindingError::Corrupt("feed record history"))
        ));
        assert!(store.metrics().closed);
        store.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn feed_response_cap_returns_contiguous_prefix_and_never_skips_oversize_first_row()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let store = FindingStore::open(config(temp.path()), Uuid::new_v4()).await?;
    store
        .append(vec![finding(1)?, finding(2)?], context())
        .await?;
    let one = store
        .feed(
            FindingsFeedQuery {
                after: FindingsAfter::Begin,
                limit: 1,
            },
            65536,
            context(),
        )
        .await?;
    let prefix = store
        .feed(
            FindingsFeedQuery {
                after: FindingsAfter::Begin,
                limit: 2,
            },
            one.len() + 1,
            context(),
        )
        .await?;
    let p: FindingsFeedResponse<Finding> = serde_json::from_slice(&prefix)?;
    assert_eq!(p.findings, vec![finding(1)?]);
    assert!(p.has_more);
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Begin,
                    limit: 1
                },
                one.len() - 2,
                context()
            )
            .await,
        Err(FindingError::PageBudgetExceeded)
    ));
    assert_eq!(
        page(&store, after(&p)?, 2).await?.findings,
        vec![finding(2)?]
    );
    assert!(!store.metrics().closed);
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn feed_memory_and_index_preflight_preserve_read_and_disk_boundaries() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut cfg = config(temp.path());
    cfg.max_index_bytes = FINDING_INDEX_BYTES;
    let store = FindingStore::open(cfg.clone(), Uuid::new_v4()).await?;
    store.append(vec![finding(1)?], context()).await?;
    let before = fs::read(temp.path().join("findings.journal"))?;
    assert!(matches!(
        store.append(vec![finding(2)?], context()).await,
        Err(FindingError::Quota)
    ));
    assert_eq!(fs::read(temp.path().join("findings.journal"))?, before);
    store.shutdown(context()).await?;
    let stream = Uuid::from_slice(&before[8..24])?;
    cfg.max_query_bytes = 2;
    let store = FindingStore::open(cfg, stream).await?;
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Begin,
                    limit: 1
                },
                65536,
                context()
            )
            .await,
        Err(FindingError::PageBudgetExceeded)
    ));
    assert!(!store.metrics().closed);
    store.shutdown(context()).await?;
    let temp = tempfile::tempdir()?;
    let mut cfg = config(temp.path());
    cfg.max_query_bytes = 10000;
    let store = FindingStore::open(cfg.clone(), Uuid::new_v4()).await?;
    store.append(vec![finding(1)?], context()).await?;
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Begin,
                    limit: 1
                },
                65536,
                context()
            )
            .await,
        Err(FindingError::PageBudgetExceeded)
    ));
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn feed_recovery_index_quota_rejects_before_exposing_existing_journal() -> TestResult {
    let temp = tempfile::tempdir()?;
    let stream = Uuid::new_v4();
    let cfg = config(temp.path());
    let store = FindingStore::open(cfg.clone(), stream).await?;
    store
        .append(vec![finding(1)?, finding(2)?], context())
        .await?;
    store.shutdown(context()).await?;
    let before = fs::read(temp.path().join("findings.journal"))?;
    assert!(matches!(
        FindingStore::open(
            FindingConfig {
                max_index_bytes: FINDING_INDEX_BYTES,
                ..cfg
            },
            stream
        )
        .await,
        Err(FindingError::Quota)
    ));
    assert_eq!(fs::read(temp.path().join("findings.journal"))?, before);
    Ok(())
}
#[tokio::test]
async fn feed_cancelled_or_timed_out_read_leaves_store_healthy() -> TestResult {
    let temp = tempfile::tempdir()?;
    let store = FindingStore::open(config(temp.path()), Uuid::new_v4()).await?;
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Begin,
                    limit: 1
                },
                65536,
                cancelled
            )
            .await,
        Err(FindingError::Cancelled)
    ));
    let expired = FindingContext {
        deadline: Instant::now(),
        cancellation: CancellationToken::new(),
    };
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Begin,
                    limit: 1
                },
                65536,
                expired
            )
            .await,
        Err(FindingError::Timeout)
    ));
    assert!(!store.metrics().closed);
    store.append(vec![finding(1)?], context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn feed_queued_abort_retains_physical_capacity_until_worker_retires_it() -> TestResult {
    let temp = tempfile::tempdir()?;
    let store = Arc::new(
        FindingStore::open(
            FindingConfig {
                command_capacity: 2,
                ..config(temp.path())
            },
            Uuid::new_v4(),
        )
        .await?,
    );
    let (started, seen) = std::sync::mpsc::channel();
    let (release, finish) = std::sync::mpsc::channel();
    let s = store.clone();
    let pause = tokio::spawn(async move {
        s.command(Operation::Pause(started, finish, false), context())
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while seen.try_recv().is_err() {
        if Instant::now() >= deadline {
            return Err("worker pause deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let s = store.clone();
    let queued = tokio::spawn(async move {
        s.feed(
            FindingsFeedQuery {
                after: FindingsAfter::Begin,
                limit: 1,
            },
            65536,
            context(),
        )
        .await
    });
    while store.metrics().command_depth == 0 {
        if Instant::now() >= deadline {
            return Err("queue deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    queued.abort();
    assert!(queued.await.is_err());
    assert_eq!(store.metrics().operations_in_flight, 2);
    assert!(matches!(
        store
            .feed(
                FindingsFeedQuery {
                    after: FindingsAfter::Begin,
                    limit: 1
                },
                65536,
                context()
            )
            .await,
        Err(FindingError::Full)
    ));
    release.send(())?;
    pause.await??;
    while store.metrics().operations_in_flight != 0 {
        if Instant::now() >= deadline {
            return Err("retirement deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(!store.metrics().closed);
    store.append(vec![finding(1)?], context()).await?;
    store.shutdown(context()).await?;
    Ok(())
}

#[test]
fn feed_enabled_startup_validates_empty_envelope_without_breaking_cursor_free_library() -> TestResult
{
    let temp = tempfile::tempdir()?;
    let mut cfg = config(temp.path());
    cfg.max_query_bytes = 287;
    assert!(cfg.validate().is_ok());
    assert!(cfg.validate_feed().is_err());
    cfg.max_query_bytes = 288;
    assert!(cfg.validate_feed().is_ok());
    let page = FindingsFeedResponse::<Finding> {
        schema_version: 1,
        findings: Vec::new(),
        next_cursor: FindingsCursor::initial(Uuid::new_v4())?.encode(),
        has_more: false,
    };
    assert_eq!(
        serde_json::to_vec(&page)?.len(),
        signal_protocol::findings_feed::FINDINGS_FEED_EMPTY_BYTES
    );
    Ok(())
}

#[tokio::test]
async fn feed_empty_minimum_budget_preallocates_only_counted_output_capacity() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut cfg = config(temp.path());
    cfg.max_query_bytes = 288;
    cfg.validate_feed()?;
    let store = FindingStore::open(cfg, Uuid::new_v4()).await?;
    let bytes = store
        .feed(
            FindingsFeedQuery {
                after: FindingsAfter::Begin,
                limit: 1,
            },
            288,
            context(),
        )
        .await?;
    assert_eq!(
        bytes.len(),
        signal_protocol::findings_feed::FINDINGS_FEED_EMPTY_BYTES
    );
    assert_eq!(bytes.capacity(), bytes.len());
    let page: FindingsFeedResponse<Finding> = serde_json::from_slice(&bytes)?;
    assert!(page.findings.is_empty() && !page.has_more);
    store.shutdown(context()).await?;
    Ok(())
}

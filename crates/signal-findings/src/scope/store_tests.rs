#![allow(clippy::unwrap_used)] // Assertions in bounded test fixtures only.
use super::*;
use signal_protocol::access::{
    AccessPolicy, AuthenticatedIdentity, Permission, ResourceScope, Role, Selection, SubjectBinding,
};

fn event(id: u128, account: &str) -> signal_event::SignalEvent {
    serde_json::from_value(
        serde_json::json!({"schema_version":1,"id":Uuid::from_u128(id),
        "timestamp":"2026-09-01T00:00:00Z","observed_at":"2026-09-01T00:00:00Z",
        "source":{"type":"audit"},"message":"synthetic","severity":"info",
        "attributes":{"account":"a","signal.scope.v1":{"account":"a"}},
        "resource":{"kind":"host","id":"host","account_id":account},"tags":[]}),
    )
    .unwrap()
}
fn draft(id: u128, account: &str, fresh: bool) -> DerivedFinding {
    let event = event(id, account);
    DerivedFinding::from_event(
        Finding::for_event("rule", &event, DetectionSeverity::High, "Title").unwrap(),
        &event,
        fresh,
    )
    .unwrap()
}
fn ctx() -> FindingContext {
    FindingContext::new(Duration::from_secs(5))
}
fn grant(op: AccessOperation, account: Option<&str>, end: u64) -> Arc<RequestGrant> {
    let scope = ResourceScope {
        sources: Selection::All,
        accounts: account.map_or(Selection::All, |a| Selection::Only(vec![a.into()])),
        resources: Selection::All,
    };
    let policy = AccessPolicy {
        schema_version: 1,
        roles: vec![Role {
            id: "read".into(),
            permissions: vec![Permission {
                operation: op,
                scope,
            }],
        }],
        bindings: vec![SubjectBinding {
            issuer: "https://example.test".into(),
            subject: "reader".into(),
            roles: vec!["read".into()],
        }],
    }
    .compile()
    .unwrap();
    let now = authorization_time().unwrap();
    Arc::new(
        policy
            .grant(
                AuthenticatedIdentity::from_verified_backend(
                    "https://example.test".into(),
                    "reader".into(),
                    now,
                    end,
                )
                .unwrap(),
                now,
            )
            .unwrap(),
    )
}
fn frame(path: &Path, finding: &Finding) {
    let data = serde_json::to_vec(finding).unwrap();
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&frame_header(&data)).unwrap();
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();
}
#[test]
fn physical_duplicate_prefix_reopens_without_upgrading_history() {
    let root = tempfile::tempdir().unwrap();
    let config = FindingConfig {
        directory: root.path().into(),
        ..Default::default()
    };
    let stream = Uuid::new_v4();
    let mut engine = Engine::open(config.clone(), stream, &ctx()).unwrap();
    let historical = draft(1, "a", false).base;
    engine
        .append(
            vec![historical.clone()],
            &ctx(),
            &AtomicBool::new(false),
            false,
        )
        .unwrap();
    drop(engine);
    let journal = root.path().join("findings.journal");
    frame(&journal, &historical); // Old software retained a semantic duplicate frame.
    let original = fs::read(&journal).unwrap();
    let mut engine = Engine::open(config.clone(), stream, &ctx()).unwrap();
    let cursor = engine.prefix.encode();
    engine
        .enable_scope(&ctx(), &AtomicBool::new(false))
        .unwrap();
    let receipt = engine
        .append_derived(vec![draft(1, "a", true)], &ctx(), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(receipt.duplicates, 1);
    assert_eq!(fs::read(&journal).unwrap(), original);
    assert_eq!(engine.prefix.encode(), cursor);
    drop(engine);
    let mut engine = Engine::open(config, stream, &ctx()).unwrap();
    assert_eq!(engine.prefix.encode(), cursor);
    let restricted = grant(
        AccessOperation::ReadFindings,
        Some("a"),
        authorization_time().unwrap() + 60,
    );
    assert!(
        engine
            .query(
                FindingQuery {
                    limit: 10,
                    ..Default::default()
                },
                &ctx(),
                Some(&restricted)
            )
            .unwrap()
            .is_empty()
    );
    let all = grant(
        AccessOperation::ReadFindings,
        None,
        authorization_time().unwrap() + 60,
    );
    assert_eq!(
        engine
            .query(
                FindingQuery {
                    limit: 10,
                    ..Default::default()
                },
                &ctx(),
                Some(&all)
            )
            .unwrap(),
        vec![historical]
    );
}
#[test]
fn trusted_rows_filter_before_limit_and_conflicting_scope_cannot_replace_replay() {
    let root = tempfile::tempdir().unwrap();
    let config = FindingConfig {
        directory: root.path().into(),
        ..Default::default()
    };
    let stream = Uuid::new_v4();
    let mut engine = Engine::open(config.clone(), stream, &ctx()).unwrap();
    engine
        .enable_scope(&ctx(), &AtomicBool::new(false))
        .unwrap();
    engine
        .append_derived(
            vec![
                draft(1, "b", true),
                draft(2, "a", true),
                draft(3, "a", false),
            ],
            &ctx(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let restricted = grant(
        AccessOperation::ReadFindings,
        Some("a"),
        authorization_time().unwrap() + 60,
    );
    let result = engine
        .query(
            FindingQuery {
                limit: 1,
                ..Default::default()
            },
            &ctx(),
            Some(&restricted),
        )
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].event_ids, vec![Uuid::from_u128(2)]);
    let bytes = fs::read(root.path().join("findings.journal")).unwrap();
    assert!(matches!(
        engine.append_derived(vec![draft(2, "b", true)], &ctx(), &AtomicBool::new(false)),
        Err(FindingError::Conflict)
    ));
    assert_eq!(
        fs::read(root.path().join("findings.journal")).unwrap(),
        bytes
    );
    assert_eq!(
        engine
            .append_derived(vec![draft(2, "a", false)], &ctx(), &AtomicBool::new(false))
            .unwrap()
            .duplicates,
        1
    );
    let wrong = grant(
        AccessOperation::QueryEvents,
        Some("a"),
        authorization_time().unwrap() + 60,
    );
    assert!(matches!(
        engine.query(
            FindingQuery {
                limit: 10,
                ..Default::default()
            },
            &ctx(),
            Some(&wrong)
        ),
        Err(FindingError::Denied)
    ));
    drop(engine);
    let mut reopened = Engine::open(config, stream, &ctx()).unwrap();
    assert_eq!(
        reopened
            .query(
                FindingQuery {
                    limit: 10,
                    ..Default::default()
                },
                &ctx(),
                Some(&restricted)
            )
            .unwrap(),
        result
    );
}
#[test]
fn reserved_raw_metadata_rejected_even_before_activation_but_existing_exact_duplicate_preserved() {
    let root = tempfile::tempdir().unwrap();
    let config = FindingConfig {
        directory: root.path().into(),
        ..Default::default()
    };
    let stream = Uuid::new_v4();
    let mut engine = Engine::open(config.clone(), stream, &ctx()).unwrap();
    let legacy = draft(1, "a", true).annotated(Uuid::new_v4());
    assert!(matches!(
        engine.append(vec![legacy.clone()], &ctx(), &AtomicBool::new(false), false),
        Err(FindingError::Invalid(_))
    ));
    drop(engine);
    frame(&root.path().join("findings.journal"), &legacy);
    let mut engine = Engine::open(config, stream, &ctx()).unwrap();
    engine
        .enable_scope(&ctx(), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        engine
            .append(vec![legacy.clone()], &ctx(), &AtomicBool::new(false), false)
            .unwrap()
            .duplicates,
        1
    );
    let restricted = grant(
        AccessOperation::ReadFindings,
        Some("a"),
        authorization_time().unwrap() + 60,
    );
    assert!(
        engine
            .query(
                FindingQuery {
                    limit: 10,
                    ..Default::default()
                },
                &ctx(),
                Some(&restricted)
            )
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        engine.append(
            vec![draft(2, "a", true).annotated(Uuid::new_v4())],
            &ctx(),
            &AtomicBool::new(false),
            false
        ),
        Err(FindingError::Invalid(_))
    ));
}
#[test]
fn invalid_control_keeps_incomplete_journal_tail_and_controls_unchanged() {
    for pending in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = FindingConfig {
            directory: root.path().into(),
            ..Default::default()
        };
        let stream = Uuid::new_v4();
        let mut engine = Engine::open(config.clone(), stream, &ctx()).unwrap();
        engine
            .enable_scope(&ctx(), &AtomicBool::new(false))
            .unwrap();
        drop(engine);
        let control = root.path().join("scope.control");
        let mut data = fs::read(&control).unwrap();
        data[108] ^= 1;
        // Preserve valid CRC: validation must reject the foreign physical prefix.
        let crc = crc32fast::hash(&data[..140]);
        data[140..].copy_from_slice(&crc.to_le_bytes());
        fs::write(&control, &data).unwrap();
        let retained = if pending {
            let target = root.path().join("scope.control.tmp");
            fs::rename(&control, &target).unwrap();
            target
        } else {
            control
        };
        let journal = root.path().join("findings.journal");
        OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(b"tail")
            .unwrap();
        let before = fs::read(&journal).unwrap();
        assert!(matches!(
            Engine::open(config, stream, &ctx()),
            Err(FindingError::Corrupt(_))
        ));
        assert_eq!(fs::read(&journal).unwrap(), before);
        assert_eq!(fs::read(&retained).unwrap(), data);
    }
}
#[test]
fn complete_pending_control_recovers_but_orphan_partial_and_ambiguous_are_held() {
    let root = tempfile::tempdir().unwrap();
    let config = FindingConfig {
        directory: root.path().into(),
        ..Default::default()
    };
    let stream = Uuid::new_v4();
    let mut engine = Engine::open(config.clone(), stream, &ctx()).unwrap();
    engine
        .enable_scope(&ctx(), &AtomicBool::new(false))
        .unwrap();
    drop(engine);
    let current = root.path().join("scope.control");
    let pending = root.path().join("scope.control.tmp");
    let original = fs::read(&current).unwrap();
    fs::rename(&current, &pending).unwrap();
    drop(Engine::open(config.clone(), stream, &ctx()).unwrap());
    assert_eq!(fs::read(&current).unwrap(), original);
    assert!(!pending.exists());
    fs::write(&pending, b"partial").unwrap();
    assert!(matches!(
        Engine::open(config.clone(), stream, &ctx()),
        Err(FindingError::Corrupt(_))
    ));
    assert_eq!(fs::read(&pending).unwrap(), b"partial");
    assert_eq!(fs::read(&current).unwrap(), original);
    fs::remove_file(&current).unwrap();
    fs::remove_file(root.path().join("findings.journal")).unwrap();
    assert!(matches!(
        Engine::open(config, stream, &ctx()),
        Err(FindingError::Corrupt(_))
    ));
    assert!(!root.path().join("findings.journal").exists());
    assert_eq!(fs::read(&pending).unwrap(), b"partial");
}
#[tokio::test]
async fn queued_expiry_and_late_ready_reply_cannot_return_scoped_rows() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FindingStore::open(
            FindingConfig {
                directory: root.path().into(),
                command_capacity: 2,
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
    );
    store.enable_scopes(ctx()).await.unwrap();
    store
        .append_derived(vec![draft(1, "a", true)], ctx())
        .await
        .unwrap();
    let end = authorization_time().unwrap() + 2;
    let restricted = grant(AccessOperation::ReadFindings, Some("a"), end);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let owner = store.clone();
    let hold = tokio::spawn(async move {
        owner
            .command(Operation::Pause(started_tx, release_rx, false), ctx())
            .await
    });
    tokio::task::yield_now().await;
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let mut queued = Box::pin(store.query_authorized(
        FindingQuery {
            limit: 10,
            ..Default::default()
        },
        ctx(),
        restricted,
    ));
    let ready =
        std::future::poll_fn(|cx| std::task::Poll::Ready(queued.as_mut().poll(cx).is_ready()))
            .await;
    assert!(!ready);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    release_tx.send(()).unwrap();
    hold.await.unwrap().unwrap();
    assert!(matches!(queued.await, Err(FindingError::Denied)));
    assert!(!store.metrics().closed);
    // A successful physical reply must still honour the caller's original deadline.
    let context = FindingContext::new(Duration::from_millis(100));
    let mut late = Box::pin(store.query(
        FindingQuery {
            limit: 10,
            ..Default::default()
        },
        context,
    ));
    assert!(
        !std::future::poll_fn(|cx| std::task::Poll::Ready(late.as_mut().poll(cx).is_ready())).await
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(matches!(late.await, Err(FindingError::Timeout)));
    assert!(!store.metrics().closed);
    store.shutdown(ctx()).await.unwrap();
}

#[tokio::test]
async fn post_open_scope_substitution_fails_closed_even_with_recomputed_frame_crc() {
    for update_crc in [false, true] {
        for duplicate in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let store = FindingStore::open(
                FindingConfig {
                    directory: root.path().into(),
                    ..Default::default()
                },
                Uuid::new_v4(),
            )
            .await
            .unwrap();
            store.enable_scopes(ctx()).await.unwrap();
            store
                .append_derived(vec![draft(1, "b", true)], ctx())
                .await
                .unwrap();
            let journal = root.path().join("findings.journal");
            let mut bytes = fs::read(&journal).unwrap();
            let mut row: Finding =
                serde_json::from_slice(&bytes[24 + FINDING_FRAME_BYTES..]).unwrap();
            row.attributes.get_mut(scope::KEY).unwrap()["account"] = serde_json::json!("a");
            let changed = serde_json::to_vec(&row).unwrap();
            assert_eq!(changed.len(), bytes.len() - 24 - FINDING_FRAME_BYTES);
            bytes[24 + FINDING_FRAME_BYTES..].copy_from_slice(&changed);
            if update_crc {
                bytes[24..24 + FINDING_FRAME_BYTES].copy_from_slice(&frame_header(&changed));
            }
            fs::write(&journal, &bytes).unwrap();
            let result = if duplicate {
                store
                    .append_derived(vec![draft(1, "b", true)], ctx())
                    .await
                    .map(|_| ())
            } else {
                store
                    .query_authorized(
                        FindingQuery {
                            limit: 1,
                            ..Default::default()
                        },
                        ctx(),
                        grant(
                            AccessOperation::ReadFindings,
                            Some("a"),
                            authorization_time().unwrap() + 60,
                        ),
                    )
                    .await
                    .map(|_| ())
            };
            assert!(matches!(result, Err(FindingError::Corrupt(_))));
            assert!(store.metrics().closed);
            assert_eq!(fs::read(&journal).unwrap(), bytes);
            store.shutdown(ctx()).await.unwrap();
        }
    }
}
#[test]
fn derived_constructor_and_queue_compact_logically_small_spare_allocations() {
    let event = event(1, "a");
    let mut base = Finding::for_event("rule", &event, DetectionSeverity::High, "Title").unwrap();
    base.title.reserve(1024 * 1024);
    base.rule_id.reserve(1024 * 1024);
    base.event_ids.reserve(100_000);
    let derived = DerivedFinding::from_event(base, &event, true).unwrap();
    assert_eq!(derived.base.title.capacity(), derived.base.title.len());
    assert_eq!(derived.base.rule_id.capacity(), derived.base.rule_id.len());
    assert_eq!(
        derived.base.event_ids.capacity(),
        derived.base.event_ids.len()
    );
    let mut batch = Vec::with_capacity(100_000);
    batch.push(derived);
    let batch = compact_derived_batch(batch);
    assert_eq!(batch.capacity(), 1);
    let batch = compact_derived_batch(Vec::with_capacity(100_000));
    assert_eq!(batch.capacity(), 0);
}

#[test]
fn activation_controls_respect_disk_and_index_reserves_before_mutation() {
    for index_bound in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = FindingConfig {
            directory: root.path().into(),
            max_disk_bytes: if index_bound {
                1024 * 1024
            } else {
                24 + scope::CONTROL_BYTES as u64 - 1
            },
            max_index_bytes: if index_bound {
                INDEX_BYTES
            } else {
                1024 * 1024
            },
            ..Default::default()
        };
        let mut engine = Engine::open(config, Uuid::new_v4(), &ctx()).unwrap();
        if index_bound {
            engine
                .append(
                    vec![draft(1, "a", false).base],
                    &ctx(),
                    &AtomicBool::new(false),
                    false,
                )
                .unwrap();
        }
        let before = fs::read(root.path().join("findings.journal")).unwrap();
        let started = AtomicBool::new(false);
        assert!(matches!(
            engine.enable_scope(&ctx(), &started),
            Err(FindingError::Quota)
        ));
        assert!(!started.load(Ordering::Acquire));
        assert_eq!(
            fs::read(root.path().join("findings.journal")).unwrap(),
            before
        );
        assert!(!root.path().join("scope.control").exists());
        assert!(!root.path().join("scope.control.tmp").exists());
    }
}

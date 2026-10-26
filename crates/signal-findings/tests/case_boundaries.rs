#![allow(clippy::unwrap_used)]
use signal_findings::{FindingContext, cases::*, disposition::FindingReference};
use std::time::Duration;
use uuid::Uuid;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn context() -> FindingContext {
    FindingContext::new(Duration::from_secs(5))
}
fn refs(count: usize) -> Vec<FindingReference> {
    (0..count)
        .map(|n| FindingReference {
            stream_id: id(1),
            finding_id: id(2 + n as u128),
        })
        .collect()
}
fn create() -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: id(10),
        case_id: id(20),
        expected_revision: 0,
        change: CaseChange::Create {
            title: "é".repeat(512),
            references: refs(32),
        },
        note: Some("n".repeat(2048)),
    }
}
fn assign() -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: id(11),
        case_id: id(20),
        expected_revision: 1,
        change: CaseChange::Assign {
            assignee: Some("a".repeat(256)),
        },
        note: None,
    }
}
fn proof(request: &CaseRequest) -> CaseAuthority {
    CaseAuthority::for_write(id(100), "u".repeat(256), refs(32), request, context()).unwrap()
}
fn read() -> CaseAuthority {
    CaseAuthority::for_read(id(100), id(20), "u".repeat(256), refs(32), context()).unwrap()
}
#[tokio::test]
async fn maximal_fields_survive_create_assign_exact_replay_and_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let cfg = CaseConfig {
        directory: dir.path().join("cases"),
        ..CaseConfig::default()
    };
    let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
    let original = store
        .record(proof(&create()), create(), context())
        .await?
        .record;
    let assigned = store
        .record(proof(&assign()), assign(), context())
        .await?
        .record;
    assert_eq!(original.actor.len(), 256);
    assert_eq!(original.head.title.len(), 1024);
    assert_eq!(original.head.references.len(), 32);
    assert_eq!(original.request.note.as_ref().unwrap().len(), 2048);
    assert_eq!(assigned.head.assignee.as_ref().unwrap().len(), 256);
    store.shutdown(context()).await?;
    let store = CaseStore::open(cfg, id(100), context()).await?;
    assert_eq!(store.head(read(), context()).await?, assigned.head);
    let replay = store.record(proof(&create()), create(), context()).await?;
    assert!(replay.replayed);
    assert_eq!(replay.record, original);
    let history = store.history(read(), 0, 2, context()).await?;
    assert_eq!(history.records, vec![original, assigned]);
    Ok(())
}
#[tokio::test]
async fn oversized_payloads_do_not_consume_operation_or_change_head_history() -> TestResult {
    for mode in 0..5 {
        let dir = tempfile::tempdir()?;
        let store = CaseStore::open(
            CaseConfig {
                directory: dir.path().join("cases"),
                ..CaseConfig::default()
            },
            id(100),
            context(),
        )
        .await?;
        let mut invalid = create();
        match mode {
            0 => {
                if let CaseChange::Create { title, .. } = &mut invalid.change {
                    *title = "t".repeat(1025)
                }
            }
            1 => {
                if let CaseChange::Create { references, .. } = &mut invalid.change {
                    *references = refs(33)
                }
            }
            2 => {
                if let CaseChange::Create { references, .. } = &mut invalid.change {
                    references.clear()
                }
            }
            3 => invalid.note = Some("n".repeat(2049)),
            _ => {
                invalid.expected_revision = 1_000_000;
                invalid.change = CaseChange::Assign { assignee: None }
            }
        }
        assert_eq!(
            store
                .record(proof(&create()), invalid, context())
                .await
                .unwrap_err(),
            CaseError::Invalid
        );
        assert_eq!(
            store.head(read(), context()).await.unwrap_err(),
            CaseError::NotFound
        );
        let original = store
            .record(proof(&create()), create(), context())
            .await?
            .record;
        let mut invalid = assign();
        invalid.change = CaseChange::Assign {
            assignee: Some("a".repeat(257)),
        };
        assert_eq!(
            store
                .record(proof(&assign()), invalid, context())
                .await
                .unwrap_err(),
            CaseError::Invalid
        );
        assert_eq!(store.head(read(), context()).await?, original.head);
        assert_eq!(
            store.history(read(), 0, 2, context()).await?.records,
            vec![original]
        );
        assert_eq!(
            store
                .record(proof(&assign()), assign(), context())
                .await?
                .record
                .head
                .revision,
            2
        );
    }
    Ok(())
}
#[test]
fn actor_and_typed_spare_allocations_and_revision_limits_refuse() {
    assert!(matches!(
        CaseAuthority::for_write(id(100), "u".repeat(257), refs(32), &create(), context()),
        Err(CaseError::Invalid)
    ));
    let mut actor = String::with_capacity(257);
    actor.push('u');
    assert!(matches!(
        CaseAuthority::for_write(id(100), actor, refs(32), &create(), context()),
        Err(CaseError::Invalid)
    ));
    let mut title = String::with_capacity(1025);
    title.push('t');
    let mut request = create();
    if let CaseChange::Create { title: target, .. } = &mut request.change {
        *target = title
    };
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut assignee = String::with_capacity(257);
    assignee.push('a');
    let mut request = assign();
    request.change = CaseChange::Assign {
        assignee: Some(assignee),
    };
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut references = Vec::with_capacity(33);
    references.push(refs(1)[0]);
    let mut request = create();
    if let CaseChange::Create {
        references: target, ..
    } = &mut request.change
    {
        *target = references
    };
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut references = Vec::with_capacity(33);
    references.push(refs(1)[0]);
    assert!(matches!(
        CaseAuthority::for_read(id(100), id(20), "u".into(), references, context()),
        Err(CaseError::Invalid)
    ));
    let mut note = String::with_capacity(2049);
    note.push('n');
    let mut request = create();
    request.note = Some(note);
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut request = assign();
    request.expected_revision = 999_999;
    assert!(request.validate().is_ok());
    request.expected_revision = 1_000_000;
    assert_eq!(request.validate(), Err(CaseError::Invalid));
}
#[tokio::test]
async fn exact_page_byte_limit_accepts_and_one_less_refuses_without_progress() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut cfg = CaseConfig {
        directory: dir.path().join("cases"),
        max_page_records: 1,
        ..CaseConfig::default()
    };
    let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
    store.record(proof(&create()), create(), context()).await?;
    let page = store.history(read(), 0, 1, context()).await?;
    cfg.max_page_bytes = serde_json::to_vec(&page)?.len();
    store.shutdown(context()).await?;
    let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
    assert_eq!(
        serde_json::to_vec(&store.history(read(), 0, 1, context()).await?)?,
        serde_json::to_vec(&page)?
    );
    assert_eq!(
        store.history(read(), 0, 2, context()).await.unwrap_err(),
        CaseError::Invalid
    );
    store.shutdown(context()).await?;
    cfg.max_page_bytes -= 1;
    let store = CaseStore::open(cfg, id(100), context()).await?;
    assert_eq!(
        store.history(read(), 0, 1, context()).await.unwrap_err(),
        CaseError::Capacity
    );
    assert_eq!(store.head(read(), context()).await?.revision, 1);
    Ok(())
}

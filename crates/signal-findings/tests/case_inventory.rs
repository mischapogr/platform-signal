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
fn references() -> Vec<FindingReference> {
    vec![
        FindingReference {
            stream_id: id(1),
            finding_id: id(2),
        },
        FindingReference {
            stream_id: id(3),
            finding_id: id(4),
        },
    ]
}
fn create(n: u128) -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: id(100 + n),
        case_id: id(n),
        expected_revision: 0,
        change: CaseChange::Create {
            title: "not catalogue data".into(),
            references: references(),
        },
        note: Some("private note".into()),
    }
}
fn write(r: &CaseRequest) -> CaseAuthority {
    CaseAuthority::for_write(id(500), "actor".into(), references(), r, context()).unwrap()
}
fn inventory() -> CaseInventoryAuthority {
    CaseInventoryAuthority::new(id(500), "host-catalogue-reader".into(), context()).unwrap()
}
#[tokio::test]
async fn sorted_bounded_discovery_preserves_complete_references_and_snapshot_across_reopen()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let cfg = CaseConfig {
        directory: dir.path().join("cases"),
        max_page_records: 2,
        ..CaseConfig::default()
    };
    let store = CaseStore::open(cfg.clone(), id(500), context()).await?;
    let empty = store
        .inventory_page(inventory(), None, None, 2, context())
        .await?;
    assert!(empty.entries().is_empty());
    assert!(!empty.has_more());
    assert_eq!(empty.namespace(), id(500));
    for n in [30, 10, 20] {
        store
            .record(write(&create(n)), create(n), context())
            .await?;
    }
    let page = store
        .inventory_page(inventory(), None, None, 2, context())
        .await?;
    assert_eq!(
        page.entries()
            .iter()
            .map(CaseInventoryEntry::case_id)
            .collect::<Vec<_>>(),
        vec![id(10), id(20)]
    );
    assert!(page.has_more());
    assert_eq!(page.next_case_id(), Some(id(20)));
    for entry in page.entries() {
        assert_eq!(entry.references(), references());
        assert_eq!(entry.revision(), 1);
        assert_eq!(entry.namespace(), id(500));
    }
    let binding = page.commit_binding();
    let tail = store
        .inventory_page(
            inventory(),
            page.next_case_id(),
            Some(binding),
            2,
            context(),
        )
        .await?;
    assert_eq!(tail.entries().len(), 1);
    assert_eq!(tail.entries()[0].case_id(), id(30));
    assert!(!tail.has_more());
    assert!(tail.next_case_id().is_none());
    store.shutdown(context()).await?;
    let store = CaseStore::open(cfg, id(500), context()).await?;
    assert_eq!(
        store
            .inventory_page(inventory(), None, None, 2, context())
            .await?
            .commit_binding(),
        binding
    );
    let mut change = create(20);
    change.operation_id = id(999);
    change.expected_revision = 1;
    change.change = CaseChange::Assign {
        assignee: Some("another".into()),
    };
    store.record(write(&change), change, context()).await?;
    assert!(matches!(
        store
            .inventory_page(inventory(), Some(id(20)), Some(binding), 2, context())
            .await,
        Err(CaseError::Conflict)
    ));
    let entry = store
        .reference_inventory(inventory(), id(20), context())
        .await?;
    assert_eq!(entry.references(), references());
    assert_eq!(entry.revision(), 2);
    Ok(())
}
#[tokio::test]
async fn discovery_refuses_wrong_namespace_invalid_cursor_budget_and_cancelled_proof() -> TestResult
{
    let dir = tempfile::tempdir()?;
    let cfg = CaseConfig {
        directory: dir.path().join("cases"),
        max_page_records: 1,
        max_page_bytes: 128,
        ..CaseConfig::default()
    };
    let store = CaseStore::open(cfg, id(500), context()).await?;
    store
        .record(write(&create(20)), create(20), context())
        .await?;
    assert!(matches!(
        store
            .reference_inventory(inventory(), id(20), context())
            .await,
        Err(CaseError::Capacity)
    ));
    assert!(matches!(
        store
            .inventory_page(inventory(), None, None, 1, context())
            .await,
        Err(CaseError::Capacity)
    ));
    assert!(matches!(
        store
            .inventory_page(inventory(), None, None, 2, context())
            .await,
        Err(CaseError::Invalid)
    ));
    assert!(matches!(
        store
            .inventory_page(inventory(), Some(id(20)), None, 1, context())
            .await,
        Err(CaseError::Invalid)
    ));
    let wrong = CaseInventoryAuthority::new(id(501), "reader".into(), context())?;
    assert!(matches!(
        store.reference_inventory(wrong, id(20), context()).await,
        Err(CaseError::Forbidden)
    ));
    let cancelled = context();
    let proof = CaseInventoryAuthority::new(id(500), "reader".into(), cancelled.clone())?;
    cancelled.cancellation.cancel();
    assert!(matches!(
        store.inventory_page(proof, None, None, 1, context()).await,
        Err(CaseError::Cancelled)
    ));
    assert!(matches!(
        store
            .reference_inventory(inventory(), id(0), context())
            .await,
        Err(CaseError::Invalid)
    ));
    assert!(matches!(
        store
            .reference_inventory(inventory(), id(99), context())
            .await,
        Err(CaseError::NotFound)
    ));
    Ok(())
}
#[tokio::test]
async fn independent_inventory_lease_expires_before_caller_and_damaged_custody_is_error()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let cfg = CaseConfig {
        directory: dir.path().join("cases"),
        ..CaseConfig::default()
    };
    let store = CaseStore::open(cfg.clone(), id(500), context()).await?;
    store
        .record(write(&create(20)), create(20), context())
        .await?;
    let lease = FindingContext::new(Duration::from_millis(100));
    let proof = CaseInventoryAuthority::new(id(500), "reader".into(), lease.clone())?;
    tokio::time::sleep_until(lease.deadline).await;
    assert!(matches!(
        store.reference_inventory(proof, id(20), context()).await,
        Err(CaseError::Timeout)
    ));
    std::fs::remove_file(cfg.directory.join("cases.commit"))?;
    assert!(
        store
            .reference_inventory(inventory(), id(20), context())
            .await
            .is_err()
    );
    assert!(store.metrics().closed);
    Ok(())
}
#[tokio::test]
async fn exact_internal_entry_and_page_byte_budgets_preserve_prior_state() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut cfg = CaseConfig {
        directory: dir.path().join("cases"),
        ..CaseConfig::default()
    };
    let store = CaseStore::open(cfg.clone(), id(500), context()).await?;
    store
        .record(write(&create(20)), create(20), context())
        .await?;
    let entry_bytes = store
        .reference_inventory(inventory(), id(20), context())
        .await?
        .encoded_len()?;
    let page_bytes = store
        .inventory_page(inventory(), None, None, 1, context())
        .await?
        .encoded_len()?;
    let binding = store
        .inventory_page(inventory(), None, None, 1, context())
        .await?
        .commit_binding();
    store.shutdown(context()).await?;
    for limit in [entry_bytes, entry_bytes - 1, page_bytes, page_bytes - 1] {
        cfg.max_page_bytes = limit;
        let store = CaseStore::open(cfg.clone(), id(500), context()).await?;
        match store
            .reference_inventory(inventory(), id(20), context())
            .await
        {
            Ok(entry) => {
                assert!(limit >= entry_bytes);
                assert_eq!(entry.references(), references());
            }
            Err(e) => {
                assert!(limit < entry_bytes);
                assert_eq!(e, CaseError::Capacity);
            }
        }
        match store
            .inventory_page(inventory(), None, None, 1, context())
            .await
        {
            Ok(page) => {
                assert!(limit >= page_bytes);
                assert_eq!(page.commit_binding(), binding);
            }
            Err(e) => {
                assert!(limit < page_bytes);
                assert_eq!(e, CaseError::Capacity);
            }
        }
        assert!(
            store
                .record(write(&create(20)), create(20), context())
                .await?
                .replayed
        );
        store.shutdown(context()).await?;
    }
    Ok(())
}

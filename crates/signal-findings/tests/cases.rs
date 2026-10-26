#![allow(clippy::unwrap_used)]
use signal_findings::{FindingContext, cases::*, disposition::FindingReference};
use std::{fs, io::Write, time::Duration};
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
fn create() -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: id(10),
        case_id: id(20),
        expected_revision: 0,
        change: CaseChange::Create {
            title: "Investigate".into(),
            references: references(),
        },
        note: Some("<script>opaque text</script>".into()),
    }
}
fn assign(revision: u64, assignee: Option<&str>) -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: id(10 + revision as u128),
        case_id: id(20),
        expected_revision: revision,
        change: CaseChange::Assign {
            assignee: assignee.map(str::to_owned),
        },
        note: None,
    }
}
fn write(request: &CaseRequest) -> CaseAuthority {
    CaseAuthority::for_write(id(100), "analyst".into(), references(), request, context()).unwrap()
}
fn read() -> CaseAuthority {
    CaseAuthority::for_read(id(100), id(20), "analyst".into(), references(), context()).unwrap()
}
fn config(dir: &std::path::Path) -> CaseConfig {
    CaseConfig {
        directory: dir.join("cases"),
        ..CaseConfig::default()
    }
}
#[tokio::test]
async fn originals_assignment_and_exact_replay_survive_newer_head_and_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let cfg = config(dir.path());
    let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
    let original = store.record(write(&create()), create(), context()).await?;
    let assigned = assign(1, Some("analyst-two"));
    let second = store
        .record(write(&assigned), assigned.clone(), context())
        .await?;
    let unassigned = assign(2, None);
    store
        .record(write(&unassigned), unassigned, context())
        .await?;
    let retry = store.record(write(&create()), create(), context()).await?;
    assert!(retry.replayed);
    assert_eq!(retry.record, original.record);
    let mut changed = create();
    changed.note = Some("different".into());
    assert_eq!(
        store
            .record(write(&changed), changed, context())
            .await
            .unwrap_err(),
        CaseError::Conflict
    );
    let other =
        CaseAuthority::for_write(id(100), "other".into(), references(), &assigned, context())?;
    assert_eq!(
        store
            .record(other, assigned.clone(), context())
            .await
            .unwrap_err(),
        CaseError::Conflict
    );
    store.shutdown(context()).await?;
    let store = CaseStore::open(cfg, id(100), context()).await?;
    assert_eq!(
        store
            .record(write(&assigned), assigned, context())
            .await?
            .record,
        second.record
    );
    let head = store.head(read(), context()).await?;
    assert_eq!(head.revision, 3);
    assert!(head.assignee.is_none());
    let page = store.history(read(), 0, 2, context()).await?;
    assert!(page.has_more);
    assert_eq!(page.next_revision, 2);
    assert_eq!(page.records[0], original.record);
    let tail = store.history(read(), 2, 2, context()).await?;
    assert_eq!(tail.records.len(), 1);
    assert!(!tail.has_more);
    Ok(())
}
#[tokio::test]
async fn full_inventory_permission_namespace_request_and_cas_are_required() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = CaseStore::open(config(dir.path()), id(100), context()).await?;
    let subset = CaseAuthority::for_write(
        id(100),
        "analyst".into(),
        vec![references()[0]],
        &create(),
        context(),
    )?;
    assert_eq!(
        store.record(subset, create(), context()).await.unwrap_err(),
        CaseError::Forbidden
    );
    store.record(write(&create()), create(), context()).await?;
    let subset = CaseAuthority::for_read(
        id(100),
        id(20),
        "analyst".into(),
        vec![references()[0]],
        context(),
    )?;
    assert_eq!(
        store.head(subset, context()).await.unwrap_err(),
        CaseError::Forbidden
    );
    assert_eq!(
        store.head(write(&create()), context()).await.unwrap_err(),
        CaseError::Forbidden
    );
    let wrong =
        CaseAuthority::for_read(id(101), id(20), "analyst".into(), references(), context())?;
    assert_eq!(
        store.head(wrong, context()).await.unwrap_err(),
        CaseError::Forbidden
    );
    let a = assign(1, Some("one"));
    let mut b = assign(1, Some("two"));
    b.operation_id = id(500);
    let (one, two) = tokio::join!(
        store.record(write(&a), a, context()),
        store.record(write(&b), b, context())
    );
    assert_eq!(
        [one.is_ok(), two.is_ok()].iter().filter(|ok| **ok).count(),
        1
    );
    assert_eq!(one.err().or(two.err()), Some(CaseError::Conflict));
    let q = assign(2, Some("not-authorized"));
    assert_eq!(
        store
            .record(write(&assign(2, Some("allowed"))), q, context())
            .await
            .unwrap_err(),
        CaseError::Forbidden
    );
    assert_eq!(store.head(read(), context()).await?.revision, 2);
    Ok(())
}
#[tokio::test]
async fn committed_truncation_and_whole_last_frame_deletion_never_repair() -> TestResult {
    for whole in [false, true] {
        let dir = tempfile::tempdir()?;
        let cfg = config(dir.path());
        let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
        store.record(write(&create()), create(), context()).await?;
        let first_len = fs::metadata(cfg.directory.join("cases.journal"))?.len();
        let next = assign(1, Some("two"));
        store.record(write(&next), next, context()).await?;
        store.shutdown(context()).await?;
        let path = cfg.directory.join("cases.journal");
        let file = fs::OpenOptions::new().write(true).open(&path)?;
        let len = if whole {
            first_len
        } else {
            file.metadata()?.len() - 1
        };
        file.set_len(len)?;
        file.sync_all()?;
        assert!(matches!(
            CaseStore::open(cfg, id(100), context()).await,
            Err(CaseError::Corrupt)
        ));
        assert_eq!(fs::metadata(path)?.len(), len);
    }
    Ok(())
}
#[tokio::test]
async fn only_uncommitted_suffix_repairs_and_committed_checksum_or_witness_loss_refuses()
-> TestResult {
    for mode in 0..4 {
        let dir = tempfile::tempdir()?;
        let cfg = config(dir.path());
        let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
        let original = store
            .record(write(&create()), create(), context())
            .await?
            .record;
        store.shutdown(context()).await?;
        let path = cfg.directory.join("cases.journal");
        let mut bytes = fs::read(&path)?;
        let committed = bytes.len();
        match mode {
            0 => {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&path)?
                    .write_all(b"uncommitted-tail")?;
            }
            1 => {
                bytes[45] ^= 1;
                fs::write(&path, &bytes)?;
            }
            2 => {
                fs::remove_file(cfg.directory.join("cases.commit"))?;
            }
            _ => {
                fs::remove_file(&path)?;
            }
        }
        let reopened = CaseStore::open(cfg.clone(), id(100), context()).await;
        if mode == 0 {
            let store = reopened?;
            assert_eq!(fs::metadata(path)?.len(), committed as u64);
            assert_eq!(
                store
                    .record(write(&create()), create(), context())
                    .await?
                    .record,
                original
            );
        } else {
            assert!(matches!(reopened, Err(CaseError::Corrupt)));
        }
    }
    Ok(())
}
#[tokio::test]
async fn every_persistence_budget_refuses_atomically_and_preserves_replay() -> TestResult {
    for mode in 0..5 {
        let dir = tempfile::tempdir()?;
        let mut cfg = config(dir.path());
        cfg.max_cases = 1;
        if mode == 0 {
            cfg.max_operations = 1;
        }
        let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
        let original = store
            .record(write(&create()), create(), context())
            .await?
            .record;
        store.shutdown(context()).await?;
        match mode {
            1 => cfg.max_disk_bytes = fs::metadata(cfg.directory.join("cases.journal"))?.len(),
            2 => cfg.max_record_bytes = serde_json::to_vec(&original)?.len(),
            3 => cfg.max_state_bytes = serde_json::to_vec(&original)?.len() * 8 + 4096,
            _ => {}
        }
        let store = CaseStore::open(cfg, id(100), context()).await?;
        let mut next = assign(1, Some("longer-assignee"));
        if mode == 2 {
            next.note = Some("x".repeat(2048));
        }
        if mode == 4 {
            next = create();
            next.case_id = id(21);
            next.operation_id = id(99);
        }
        let proof =
            CaseAuthority::for_write(id(100), "analyst".into(), references(), &next, context())?;
        assert_eq!(
            store.record(proof, next, context()).await.unwrap_err(),
            CaseError::Capacity,
            "budget {mode}"
        );
        assert_eq!(store.head(read(), context()).await?.revision, 1);
        assert_eq!(
            store
                .record(write(&create()), create(), context())
                .await?
                .record,
            original
        );
    }
    Ok(())
}
#[tokio::test]
async fn page_limits_authority_cancellation_and_deadlines_preserve_state() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut cfg = config(dir.path());
    cfg.max_page_records = 1;
    cfg.max_page_bytes = 128;
    let store = CaseStore::open(cfg, id(100), context()).await?;
    store.record(write(&create()), create(), context()).await?;
    assert_eq!(
        store.history(read(), 0, 1, context()).await.unwrap_err(),
        CaseError::Capacity
    );
    assert_eq!(
        store.history(read(), 0, 2, context()).await.unwrap_err(),
        CaseError::Invalid
    );
    let next = assign(1, None);
    let cancelled = context();
    let proof = CaseAuthority::for_write(
        id(100),
        "analyst".into(),
        references(),
        &next,
        cancelled.clone(),
    )?;
    cancelled.cancellation.cancel();
    assert_eq!(
        store
            .record(proof, next.clone(), context())
            .await
            .unwrap_err(),
        CaseError::Cancelled
    );
    let mut expired = context();
    expired.deadline = tokio::time::Instant::now();
    assert_eq!(
        store.record(write(&next), next, expired).await.unwrap_err(),
        CaseError::Timeout
    );
    assert_eq!(store.head(read(), context()).await?.revision, 1);
    assert!(store.metrics().rejections >= 4);
    Ok(())
}
#[tokio::test]
async fn exclusive_namespace_and_hardlinked_or_symlinked_files_refuse() -> TestResult {
    let dir = tempfile::tempdir()?;
    let cfg = config(dir.path());
    let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
    assert!(matches!(
        CaseStore::open(cfg.clone(), id(100), context()).await,
        Err(CaseError::Locked)
    ));
    store.shutdown(context()).await?;
    assert!(matches!(
        CaseStore::open(cfg.clone(), id(101), context()).await,
        Err(CaseError::Corrupt)
    ));
    let path = cfg.directory.join("cases.journal");
    fs::hard_link(&path, dir.path().join("alias"))?;
    assert!(matches!(
        CaseStore::open(cfg, id(100), context()).await,
        Err(CaseError::Corrupt)
    ));
    Ok(())
}
#[test]
fn schema_reference_order_and_typed_allocation_limits_refuse() {
    let mut request = create();
    request.schema_version = 2;
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut request = create();
    if let CaseChange::Create { references, .. } = &mut request.change {
        references.reverse();
    }
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut request = create();
    if let CaseChange::Create { references, .. } = &mut request.change {
        references.push(references[1]);
    }
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut request = create();
    request.note = Some(String::with_capacity(2049));
    assert_eq!(request.validate(), Err(CaseError::Invalid));
    let mut value = serde_json::to_value(create()).unwrap();
    value["unexpected"] = true.into();
    assert!(serde_json::from_value::<CaseRequest>(value).is_err());
}
#[tokio::test]
async fn live_committed_bitrot_witness_or_lock_replacement_closes_original_owner() -> TestResult {
    use std::os::unix::fs::OpenOptionsExt;
    for mode in 0..3 {
        let dir = tempfile::tempdir()?;
        let cfg = config(dir.path());
        let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
        store.record(write(&create()), create(), context()).await?;
        if mode == 0 {
            let path = cfg.directory.join("cases.journal");
            let mut bytes = fs::read(&path)?;
            bytes[45] ^= 1;
            fs::write(path, bytes)?;
        } else if mode == 1 {
            fs::remove_file(cfg.directory.join("cases.commit"))?;
        } else {
            let path = cfg.directory.join(".lock");
            fs::remove_file(&path)?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        assert!(store.head(read(), context()).await.is_err());
        assert!(store.metrics().closed);
        let next = assign(1, None);
        assert_eq!(
            store
                .record(write(&next), next, context())
                .await
                .unwrap_err(),
            CaseError::Unavailable
        );
    }
    Ok(())
}

#[tokio::test]
async fn symlink_and_unsafe_permission_roots_refuse() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir()?;
    let cfg = config(dir.path());
    let store = CaseStore::open(cfg.clone(), id(100), context()).await?;
    store.shutdown(context()).await?;
    let path = cfg.directory.join("cases.journal");
    let saved = dir.path().join("journal-saved");
    fs::rename(&path, &saved)?;
    symlink(&saved, &path)?;
    assert!(matches!(
        CaseStore::open(cfg.clone(), id(100), context()).await,
        Err(CaseError::Corrupt)
    ));
    fs::remove_file(&path)?;
    fs::rename(saved, &path)?;
    fs::set_permissions(&cfg.directory, fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        CaseStore::open(cfg, id(100), context()).await,
        Err(CaseError::Corrupt)
    ));
    Ok(())
}

#![allow(clippy::unwrap_used)]
use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn context() -> FindingContext {
    FindingContext::new(Duration::from_secs(5))
}
fn references() -> Vec<FindingReference> {
    vec![FindingReference {
        stream_id: Uuid::from_u128(1),
        finding_id: Uuid::from_u128(2),
    }]
}
fn create() -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: Uuid::from_u128(10),
        case_id: Uuid::from_u128(20),
        expected_revision: 0,
        change: CaseChange::Create {
            title: "Case".into(),
            references: references(),
        },
        note: None,
    }
}
fn assign(revision: u64) -> CaseRequest {
    CaseRequest {
        schema_version: 1,
        operation_id: Uuid::from_u128(10 + revision as u128),
        case_id: Uuid::from_u128(20),
        expected_revision: revision,
        change: CaseChange::Assign {
            assignee: Some("two".into()),
        },
        note: None,
    }
}
fn write(r: &CaseRequest) -> CaseAuthority {
    CaseAuthority::for_write(
        Uuid::from_u128(100),
        "analyst".into(),
        references(),
        r,
        context(),
    )
    .unwrap()
}
fn read() -> CaseAuthority {
    CaseAuthority::for_read(
        Uuid::from_u128(100),
        Uuid::from_u128(20),
        "analyst".into(),
        references(),
        context(),
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_authority_retains_physical_capacity_until_blocking_work_retires() -> TestResult {
    let dir = tempfile::tempdir()?;
    let config = CaseConfig {
        directory: dir.path().join("cases"),
        operation_capacity: 1,
        ..CaseConfig::default()
    };
    let store = Arc::new(CaseStore::open(config, Uuid::from_u128(100), context()).await?);
    store.record(write(&create()), create(), context()).await?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let authority = read();
    let cancel = authority.context.cancellation.clone();
    let owned = store.clone();
    let call = tokio::spawn(async move {
        owned
            .execute(authority, context(), move |_, _, _| {
                let _ = started.send(());
                wait.recv_timeout(Duration::from_secs(3))
                    .map_err(|_| CaseError::Timeout)?;
                Ok(())
            })
            .await
    });
    ready.await?;
    cancel.cancel();
    assert_eq!(call.await?, Err(CaseError::Cancelled));
    assert_eq!(store.metrics().depth, 1);
    let next = assign(1);
    assert_eq!(
        store
            .record(write(&next), next, context())
            .await
            .unwrap_err(),
        CaseError::Capacity
    );
    release.send(())?;
    let until = Instant::now() + Duration::from_secs(2);
    while store.metrics().depth != 0 && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(store.metrics().depth, 0);
    assert_eq!(store.head(read(), context()).await?.revision, 1);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_authority_expiry_and_aborted_caller_cannot_mutate_or_release_owner() -> TestResult {
    let dir = tempfile::tempdir()?;
    let cfg = CaseConfig {
        directory: dir.path().join("cases"),
        operation_capacity: 2,
        ..CaseConfig::default()
    };
    let store = Arc::new(CaseStore::open(cfg.clone(), Uuid::from_u128(100), context()).await?);
    store.record(write(&create()), create(), context()).await?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let owned = store.clone();
    let first = tokio::spawn(async move {
        owned
            .execute(read(), context(), move |_, _, _| {
                let _ = started.send(());
                wait.recv_timeout(Duration::from_secs(3))
                    .map_err(|_| CaseError::Timeout)?;
                Ok(())
            })
            .await
    });
    ready.await?;
    let next = assign(1);
    let mut proof = write(&next);
    proof.context.deadline = Instant::now() + Duration::from_millis(40);
    let owned = store.clone();
    let queued = tokio::spawn(async move { owned.record(proof, next, context()).await });
    assert_eq!(queued.await?.unwrap_err(), CaseError::Timeout);
    assert_eq!(store.metrics().depth, 2);
    first.abort();
    let _ = first.await;
    assert_eq!(store.metrics().depth, 2);
    assert!(matches!(
        CaseStore::open(cfg.clone(), Uuid::from_u128(100), context()).await,
        Err(CaseError::Locked)
    ));
    release.send(())?;
    let until = Instant::now() + Duration::from_secs(2);
    while store.metrics().depth != 0 && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(store.metrics().depth, 0);
    assert_eq!(store.head(read(), context()).await?.revision, 1);
    Ok(())
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
#[ignore = "owned subprocess helper only"]
async fn case_process_child() -> TestResult {
    if std::env::var("SIGNAL_CASE_CHILD").as_deref() != Ok("1") {
        return Err("requires owned child".into());
    }
    let output = PathBuf::from(std::env::var_os("SIGNAL_CASE_OUTPUT").ok_or("missing output")?);
    let store = CaseStore::open(
        CaseConfig {
            directory: output.join("cases"),
            ..CaseConfig::default()
        },
        Uuid::from_u128(100),
        context(),
    )
    .await?;
    store.record(write(&create()), create(), context()).await?;
    let next = assign(1);
    store.record(write(&next), next, context()).await?;
    Err("cut was not killed".into())
}
#[tokio::test]
#[ignore = "actual owned SIGKILL campaign"]
async fn case_process_crash() -> TestResult {
    for phase in ["prepared", "journaled", "committed"] {
        let output = tempfile::tempdir()?;
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "cases::store::tests::case_process_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("SIGNAL_CASE_CHILD", "1")
                .env("SIGNAL_CASE_CUT", phase)
                .env("SIGNAL_CASE_OUTPUT", output.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let ready = output.path().join("ready.json");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            if child.0.try_wait()?.is_some() {
                return Err("child exited before cut".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(ready.exists(), "missing {phase} cut");
        // The barrier is published after intent bytes are fsynced. Wait for complete JSON,
        // since existence itself is not the publication event.
        let intent: CaseRecord = loop {
            if let Ok(bytes) = fs::read(&ready)
                && let Ok(record) = serde_json::from_slice(&bytes)
            {
                break record;
            }
            if std::time::Instant::now() >= deadline {
                return Err("intent incomplete".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let store = CaseStore::open(
            CaseConfig {
                directory: output.path().join("cases"),
                ..CaseConfig::default()
            },
            Uuid::from_u128(100),
            context(),
        )
        .await?;
        let head = store.head(read(), context()).await?;
        assert_eq!(head.revision, if phase == "committed" { 2 } else { 1 });
        let original = store
            .record(write(&assign(1)), assign(1), context())
            .await?;
        assert_eq!(original.replayed, phase == "committed");
        if phase == "committed" {
            assert_eq!(original.record, intent);
        }
        store
            .record(write(&assign(2)), assign(2), context())
            .await?;
        let retried = store
            .record(write(&assign(1)), assign(1), context())
            .await?;
        assert!(retried.replayed);
        assert_eq!(retried.record, original.record);
        assert_eq!(store.head(read(), context()).await?.revision, 3);
    }
    println!("CASE_PROCESS_SIGKILL_CUTS=3; original replay and intervening input preserved");
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_unpolled_reply_retains_capacity_and_requires_fresh_authority() -> TestResult {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let dir = tempfile::tempdir()?;
    let store = CaseStore::open(
        CaseConfig {
            directory: dir.path().join("cases"),
            operation_capacity: 1,
            ..CaseConfig::default()
        },
        Uuid::from_u128(100),
        context(),
    )
    .await?;
    store.record(write(&create()), create(), context()).await?;
    let next = assign(1);
    let authority = write(&next);
    let cancel = authority.context.cancellation.clone();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let mut call = Box::pin(store.execute(authority, context(), move |e, a, c| {
        wait.recv_timeout(Duration::from_secs(3))
            .map_err(|_| CaseError::Timeout)?;
        e.record(a, next, c)
    }));
    assert!(matches!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    release.send(())?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let complete = store.engine.try_lock().is_ok_and(|e| {
            e.heads
                .get(&Uuid::from_u128(20))
                .is_some_and(|h| h.revision == 2)
        });
        if complete {
            break;
        }
        if Instant::now() >= deadline {
            return Err("physical commit did not retire".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(store.metrics().depth, 1);
    cancel.cancel();
    assert_eq!(call.await.unwrap_err(), CaseError::Cancelled);
    assert!(!store.metrics().closed);
    assert_eq!(store.metrics().depth, 0);
    let retry = store
        .record(write(&assign(1)), assign(1), context())
        .await?;
    assert!(retry.replayed);
    assert_eq!(retry.record.head.revision, 2);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inventory_authority_cancellation_retains_physical_capacity_and_hides_stale_reply()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(
        CaseStore::open(
            CaseConfig {
                directory: dir.path().join("cases"),
                operation_capacity: 1,
                ..CaseConfig::default()
            },
            Uuid::from_u128(100),
            context(),
        )
        .await?,
    );
    store.record(write(&create()), create(), context()).await?;
    let authority =
        CaseInventoryAuthority::new(Uuid::from_u128(100), "host-reader".into(), context())?;
    let cancel = authority.context.cancellation.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let owned = store.clone();
    let task = tokio::spawn(async move {
        owned
            .execute(authority, context(), move |_, _, _| {
                let _ = started.send(());
                wait.recv_timeout(Duration::from_secs(3))
                    .map_err(|_| CaseError::Timeout)?;
                Ok(())
            })
            .await
    });
    ready.await?;
    cancel.cancel();
    assert_eq!(task.await?, Err(CaseError::Cancelled));
    assert_eq!(store.metrics().depth, 1);
    let fresh =
        || CaseInventoryAuthority::new(Uuid::from_u128(100), "host-reader".into(), context());
    assert!(matches!(
        store
            .inventory_page(fresh()?, None, None, 1, context())
            .await,
        Err(CaseError::Capacity)
    ));
    release.send(())?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while store.metrics().depth != 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(store.metrics().depth, 0);
    assert_eq!(
        store
            .inventory_page(fresh()?, None, None, 1, context())
            .await?
            .entries()[0]
            .case_id(),
        Uuid::from_u128(20)
    );
    Ok(())
}

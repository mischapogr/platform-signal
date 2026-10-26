#![allow(clippy::unwrap_used)]
use super::*;
use std::{fs, path::Path};
fn config(path: &Path) -> Config {
    Config {
        root: path.into(),
        cluster: "cluster".into(),
        node: "node-a".into(),
        namespace: None,
        max_line_bytes: 65536,
        follow: false,
        limits: node_root::Limits::default(),
        scan_interval: Duration::from_millis(10),
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
#[tokio::test]
async fn retained_worker_preserves_pending_pins_and_physically_retires_idempotently() {
    let _serial = TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("team_workload_runtime/main");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("0.log"),
        b"2026-10-25T12:00:00Z stderr F exact\r\n",
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let mut r = Reader::prepare(config(temp.path()), deadline(), &cancel)
        .await
        .unwrap();
    assert_eq!(WORKERS.available_permits(), 0);
    r.restore(vec![], deadline(), &cancel).await.unwrap();
    let first = match r.read(deadline(), &cancel).await.unwrap() {
        ReadOutcome::Record(v) => v,
        _ => panic!("record"),
    };
    let second = match r.read(deadline(), &cancel).await.unwrap() {
        ReadOutcome::Record(v) => v,
        _ => panic!("record"),
    };
    assert_eq!(first.event, second.event);
    assert_eq!(first.checkpoint, second.checkpoint);
    assert_eq!(first.event.unwrap().message.as_deref(), Some("exact\r"));
    r.commit(deadline(), &cancel).await.unwrap();
    assert!(matches!(
        r.read(deadline(), &cancel).await.unwrap(),
        ReadOutcome::End
    ));
    let metrics = r.metrics();
    r.close(deadline()).await.unwrap();
    r.close(deadline()).await.unwrap();
    assert_eq!(WORKERS.available_permits(), 1);
    assert!(metrics.text().contains("signal_agent_node_retired 1\n"));
    assert!(metrics.text().contains("signal_agent_node_files 0\n"));
}
#[tokio::test]
async fn timed_out_call_and_close_keep_physical_permit_until_retained_work_finishes() {
    let _serial = TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let cfg = config(temp.path());
    let mut r = Reader::prepare(cfg.clone(), deadline(), &cancel)
        .await
        .unwrap();
    r.restore(vec![], deadline(), &cancel).await.unwrap();
    let (entered, wait) = oneshot::channel();
    let (release, held) = mpsc::sync_channel(1);
    let mut call = Box::pin(r.call(
        Action::Hold(entered, held),
        Instant::now() + Duration::from_millis(40),
        &cancel,
    ));
    tokio::select! {_=&mut call=>panic!("early operation"),r=wait=>r.unwrap()};
    assert!(matches!(call.await, Err(Error::Timeout)));
    assert_eq!(WORKERS.available_permits(), 0);
    assert!(matches!(
        Reader::prepare(cfg, deadline(), &cancel).await,
        Err(Error::Busy)
    ));
    assert!(matches!(
        r.close(Instant::now() + Duration::from_millis(10)).await,
        Err(Error::Timeout)
    ));
    assert_eq!(WORKERS.available_permits(), 0);
    release.send(()).unwrap();
    r.close(deadline()).await.unwrap();
    assert_eq!(WORKERS.available_permits(), 1);
}
#[tokio::test]
async fn dropped_admitted_call_and_precancelled_prepare_never_spawn_replacement_work() {
    let _serial = TEST_LOCK.lock().await;
    let temp = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let cfg = config(temp.path());
    let stopped = CancellationToken::new();
    stopped.cancel();
    assert!(matches!(
        Reader::prepare(cfg.clone(), deadline(), &stopped).await,
        Err(Error::Cancelled)
    ));
    assert_eq!(WORKERS.available_permits(), 1);
    let mut r = Reader::prepare(cfg.clone(), deadline(), &cancel)
        .await
        .unwrap();
    r.restore(vec![], deadline(), &cancel).await.unwrap();
    let (entered, wait) = oneshot::channel();
    let (release, held) = mpsc::sync_channel(1);
    let mut call = Box::pin(r.call(Action::Hold(entered, held), deadline(), &cancel));
    tokio::select! {_=&mut call=>panic!("early operation"),r=wait=>r.unwrap()};
    drop(call);
    assert_eq!(WORKERS.available_permits(), 0);
    assert!(matches!(
        Reader::prepare(cfg, deadline(), &cancel).await,
        Err(Error::Busy)
    ));
    release.send(()).unwrap();
    r.close(deadline()).await.unwrap();
    assert_eq!(WORKERS.available_permits(), 1);
}

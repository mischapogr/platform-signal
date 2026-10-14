//! Owned child processes and real SQLite locks, never production failpoints.
#![allow(clippy::unwrap_used)]
use super::{
    durability_tests::{policy, state},
    *,
};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::{Duration as WallDuration, Instant},
};

fn snapshot(state: State, revision: u64, checkpoint: u64) -> Snapshot {
    let findings = state
        .assessments()
        .iter()
        .filter_map(|a| a.finding(&policy()).unwrap())
        .collect();
    Snapshot {
        history: Default::default(),
        schema_version: 1,
        revision,
        checkpoint,
        source_stream: Uuid::from_u128(1),
        source_binding: [1; 32],
        state,
        findings,
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "invoked only by the owned SIGKILL parent fixture"]
fn crash_boundary_child() {
    let directory =
        std::path::PathBuf::from(std::env::var_os("SIGNAL_WINDOW_CRASH_FIXTURE").unwrap());
    let stage = std::env::var("SIGNAL_WINDOW_CRASH_STAGE").unwrap();
    let path = directory.join("window.sqlite");
    let mut engine = store::Engine::open(&path, policy()).unwrap();
    let first = engine.commit(0, snapshot(state(), 1, 1)).unwrap();
    let mut next = first.state.clone();
    let mut event = next.attempts[0].event.clone();
    event.id = Uuid::from_u128(2);
    event.timestamp += chrono::TimeDelta::milliseconds(500);
    event.observed_at = event.timestamp;
    event.attributes["producer"]["sequence"] = serde_json::json!(2);
    next.admit(&event, true).unwrap();
    next.seal(event.timestamp, true).unwrap();
    let next = snapshot(next, 2, 2);
    let mut uncommitted = None;
    let expected = match stage.as_str() {
        "before_commit" => first,
        "uncommitted" => {
            let writer = rusqlite::Connection::open(&path).unwrap();
            writer
                .execute_batch("PRAGMA synchronous=FULL; PRAGMA cache_size=1; BEGIN IMMEDIATE")
                .unwrap();
            writer
                .execute(
                    "UPDATE window_snapshot SET revision=2,checkpoint=2,payload=?1",
                    [serde_json::to_vec(&next).unwrap()],
                )
                .unwrap();
            writer
                .execute("DELETE FROM window_assessments", [])
                .unwrap();
            assert!(
                directory
                    .join("window.sqlite-journal")
                    .metadata()
                    .unwrap()
                    .len()
                    > 0
            );
            uncommitted = Some(writer);
            first
        }
        "committed" => engine.commit(1, next).unwrap(),
        "retired" => {
            engine.commit(1, next).unwrap();
            engine.retire(2, 2).unwrap()
        }
        _ => panic!("unknown owned fixture stage"),
    };
    let bytes = serde_json::to_vec(&expected).unwrap();
    let temporary = directory.join("boundary.tmp");
    let mut file = std::fs::File::create(&temporary).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::rename(temporary, directory.join("boundary.json")).unwrap();
    // Keep the live connections and transaction intact until the parent kills us.
    loop {
        std::thread::park();
        std::hint::black_box(&uncommitted);
        std::hint::black_box(&engine);
    }
}

#[test]
fn sigkill_recovers_old_or_complete_atomic_state_archive_findings_and_checkpoint() {
    for stage in ["before_commit", "uncommitted", "committed", "retired"] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "window::recovery_tests::crash_boundary_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SIGNAL_WINDOW_CRASH_FIXTURE", temp.path())
            .env("SIGNAL_WINDOW_CRASH_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = OwnedChild(child);
        let deadline = Instant::now() + WallDuration::from_secs(10);
        let boundary = temp.path().join("boundary.json");
        while !boundary.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before {stage}"
            );
            assert!(
                Instant::now() < deadline,
                "child boundary timeout for {stage}"
            );
            std::thread::sleep(WallDuration::from_millis(5));
        }
        let expected: Snapshot = serde_json::from_slice(&std::fs::read(boundary).unwrap()).unwrap();
        child.0.kill().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        let engine = store::Engine::open(&temp.path().join("window.sqlite"), policy()).unwrap();
        let recovered = engine.load().unwrap().unwrap();
        assert_eq!(
            (recovered.revision, recovered.checkpoint),
            (expected.revision, expected.checkpoint),
            "{stage}"
        );
        assert_eq!(recovered.state, expected.state, "{stage}");
        assert_eq!(recovered.findings, expected.findings, "{stage}");
        let history = engine.history(None, 128, 65536).unwrap();
        assert_eq!(
            history.records.len(),
            if expected.checkpoint == 1 { 1 } else { 2 },
            "{stage}"
        );
        assert!(!history.truncated && !history.missing_evidence);
    }
}

// Installed only in unit-test binaries for the exact owned fixture basename.
// Entry proves SQLite reached real writer-lock contention, rather than a queued
// command or a sleep before disk work. Release deterministically ends that I/O.
type BusyProbe = (
    tokio::sync::oneshot::Sender<()>,
    std::sync::mpsc::Receiver<()>,
    bool,
);
static BUSY_PROBE: std::sync::Mutex<Option<BusyProbe>> = std::sync::Mutex::new(None);
pub(super) fn sqlite_busy_probe(_: i32) -> bool {
    let probe = BUSY_PROBE.lock().unwrap().take();
    if let Some((entered, release, retry)) = probe {
        let _ = entered.send(());
        let _ = release.recv();
        return retry;
    }
    false
}

#[tokio::test]
async fn real_sqlite_contention_retains_capacity_after_cancellation_until_physical_completion() {
    for (retry, cancel_caller) in [(false, true), (true, true), (true, false)] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("retained-lock-test.sqlite");
        let context = || crate::RuleContext::new(WallDuration::from_secs(3));
        let (journal, ready) = Journal::begin_open(path.clone(), policy(), context()).unwrap();
        ready.wait().await.unwrap();
        let locker = rusqlite::Connection::open(&path).unwrap();
        locker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (entered, entry) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        *BUSY_PROBE.lock().unwrap() = Some((entered, finish, retry));
        let pending = context();
        let cancellation = pending.cancellation.clone();
        let other = journal.clone();
        let caller =
            tokio::spawn(async move { other.commit(0, snapshot(state(), 1, 1), pending).await });
        tokio::time::timeout(WallDuration::from_secs(3), entry)
            .await
            .unwrap()
            .unwrap();
        if cancel_caller {
            cancellation.cancel();
        }
        let result = caller.await.unwrap();
        assert!(if cancel_caller {
            matches!(result, Err(Error::Cancelled))
        } else {
            matches!(result, Err(Error::Timeout))
        });
        assert_eq!(journal.metrics(), (1, 1, 1));
        assert!(matches!(journal.load(context()).await, Err(Error::Busy)));
        assert_eq!(journal.metrics(), (1, 1, 2));
        if retry {
            locker.execute_batch("ROLLBACK").unwrap();
        }
        release.send(()).unwrap();
        let deadline = tokio::time::Instant::now() + WallDuration::from_secs(3);
        while journal.metrics().0 != 0 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(WallDuration::from_millis(1)).await;
        }
        if retry {
            // Commit completed physically after its cancelled caller had left.
            let recovered = journal.load(context()).await.unwrap().unwrap();
            assert_eq!((recovered.revision, recovered.checkpoint), (1, 1));
            assert_eq!(recovered.findings.len(), 1);
            assert_eq!(recovered.history.assessments, 1);
        } else {
            locker.execute_batch("ROLLBACK").unwrap();
            assert!(journal.load(context()).await.unwrap().is_none());
            journal
                .commit(0, snapshot(state(), 1, 1), context())
                .await
                .unwrap();
        }
        assert_eq!(
            journal.load(context()).await.unwrap().unwrap().checkpoint,
            1
        );
        journal.shutdown(context()).await.unwrap();
    }
}

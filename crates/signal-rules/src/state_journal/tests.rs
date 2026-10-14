#![allow(clippy::unwrap_used)]
use super::*;
use crate::RuleContext;
use std::{
    os::unix::{fs::symlink, process::ExitStatusExt},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Instant,
};
fn config() -> Config {
    Config {
        schema_version: 1,
        source_stream: Uuid::from_u128(1),
        source_binding: [1; 32],
        enrollment_binding: [2; 32],
        max_record_bytes: 16384,
        max_state_bytes: 4096,
        max_outputs: 2,
        max_output_bytes: 512,
    }
}
fn record(revision: u64, checkpoint: u64) -> Record {
    Record {
        schema_version: 1,
        revision,
        checkpoint,
        state: b"original monitor/proof snapshot".to_vec(),
        outbox: vec![Output {
            schema_version: 1,
            id: Uuid::from_u128(2),
            bytes: b"original opaque finding bytes".to_vec(),
        }],
    }
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(3))
}

#[test]
fn atomic_state_outbox_checkpoint_reopen_and_exact_lost_reply_reconciliation() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let mut engine = Engine::open(&path, config()).unwrap();
    let original = record(1, 9);
    engine.commit(0, original.clone()).unwrap();
    drop(engine);
    let mut reopened = Engine::open(&path, config()).unwrap();
    assert_eq!(reopened.load().unwrap(), Some(original.clone()));
    assert_eq!(reopened.commit(0, original.clone()).unwrap(), original);
    assert_eq!(reopened.commit(1, record(2, 8)), Err(Error::Conflict));
    assert_eq!(reopened.load().unwrap(), Some(original));
}

#[test]
fn inherited_lock_descriptor_cannot_retain_lease_after_database_owner_closes() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let mut engine = Engine::open(&path, config()).unwrap();
    engine.commit(0, record(1, 9)).unwrap();
    let inherited = engine._lock.duplicate().unwrap();
    drop(engine);
    let reopened = Engine::open(&path, config()).unwrap();
    assert_eq!(reopened.load().unwrap(), Some(record(1, 9)));
    drop(reopened);
    drop(inherited);
}

#[test]
fn pending_original_outbox_is_immutable_until_explicit_revision_bound_retirement() {
    let dir = directory();
    let mut engine = Engine::open(&dir.path().join("state.sqlite"), config()).unwrap();
    let original = record(1, 4);
    engine.commit(0, original.clone()).unwrap();
    let mut bad = record(2, 4);
    bad.outbox.clear();
    assert_eq!(engine.commit(1, bad), Err(Error::Conflict));
    let mut bad = record(2, 4);
    bad.outbox[0].bytes = b"replacement".to_vec();
    assert_eq!(engine.commit(1, bad), Err(Error::Conflict));
    let mut next = record(2, 4);
    next.state = b"timer evaluation at unchanged source checkpoint".to_vec();
    next.outbox.push(Output {
        schema_version: 1,
        id: Uuid::from_u128(3),
        bytes: b"second original finding".to_vec(),
    });
    engine.commit(1, next.clone()).unwrap();
    assert_eq!(engine.retire(1, 1), Err(Error::Conflict));
    assert_eq!(engine.retire(2, 0), Err(Error::Conflict));
    assert_eq!(engine.retire(2, 3), Err(Error::Conflict));
    let retired = engine.retire(2, 1).unwrap();
    assert_eq!(retired.state, next.state);
    assert_eq!(retired.checkpoint, 4);
    assert_eq!(retired.revision, 3);
    assert_eq!(retired.outbox, &next.outbox[1..]);
    assert_eq!(engine.retire(2, 1), Err(Error::Conflict));
    assert_eq!(engine.load().unwrap(), Some(retired));
}

#[test]
fn source_stream_scope_enrollment_and_quota_changes_refuse_without_changing_original_database() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let mut engine = Engine::open(&path, config()).unwrap();
    engine.commit(0, record(1, 1)).unwrap();
    drop(engine);
    let original = fs::read(&path).unwrap();
    let mut changed = vec![];
    let mut c = config();
    c.source_stream = Uuid::from_u128(9);
    changed.push(c);
    let mut c = config();
    c.source_binding = [3; 32];
    changed.push(c);
    let mut c = config();
    c.enrollment_binding = [4; 32];
    changed.push(c);
    let mut c = config();
    c.max_outputs = 3;
    changed.push(c);
    for c in changed {
        assert!(matches!(Engine::open(&path, c), Err(Error::Conflict)));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn output_count_bytes_state_bytes_and_encoded_frame_limits_refuse_atomically() {
    let dir = directory();
    let mut c = config();
    c.max_record_bytes = 1024;
    c.max_state_bytes = 1024;
    let mut engine = Engine::open(&dir.path().join("state.sqlite"), c).unwrap();
    let original = record(1, 1);
    engine.commit(0, original.clone()).unwrap();
    let mut bad = record(2, 2);
    bad.state = vec![0; 1025];
    assert_eq!(engine.commit(1, bad), Err(Error::Capacity));
    let mut bad = record(2, 2);
    bad.state = vec![255; 256];
    assert_eq!(engine.commit(1, bad), Err(Error::Capacity));
    let mut bad = record(2, 2);
    bad.outbox[0].bytes = vec![0; 513];
    assert_eq!(engine.commit(1, bad), Err(Error::Capacity));
    let mut bad = record(2, 2);
    bad.outbox.extend([
        Output {
            schema_version: 1,
            id: Uuid::from_u128(3),
            bytes: vec![1],
        },
        Output {
            schema_version: 1,
            id: Uuid::from_u128(4),
            bytes: vec![2],
        },
    ]);
    assert_eq!(engine.commit(1, bad), Err(Error::Capacity));
    let mut bad = record(2, 2);
    bad.outbox.push(bad.outbox[0].clone());
    assert_eq!(engine.commit(1, bad), Err(Error::Configuration));
    assert_eq!(engine.load().unwrap(), Some(original));
}

#[test]
fn corrupted_oversized_or_mismatched_rows_are_bounded_and_refused() {
    let dir = directory();
    let mut engine = Engine::open(&dir.path().join("state.sqlite"), config()).unwrap();
    let original = record(1, 1);
    engine.commit(0, original.clone()).unwrap();
    engine
        .connection
        .execute(
            "UPDATE state_snapshot SET payload=zeroblob(?1)",
            [(config().max_record_bytes + 1) as i64],
        )
        .unwrap();
    assert_eq!(engine.load(), Err(Error::Capacity));
    let bytes = original.encode(&config()).unwrap();
    write(&engine.connection, &original, &bytes).unwrap();
    engine
        .connection
        .execute("UPDATE state_snapshot SET digest=zeroblob(32)", [])
        .unwrap();
    assert_eq!(engine.load(), Err(Error::Conflict));
    write(&engine.connection, &original, &bytes).unwrap();
    engine
        .connection
        .execute("UPDATE state_snapshot SET checkpoint=99", [])
        .unwrap();
    assert_eq!(engine.load(), Err(Error::Conflict));
}

#[test]
fn unknown_schema_and_foreign_files_are_not_adopted() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let engine = Engine::open(&path, config()).unwrap();
    engine
        .connection
        .execute_batch("CREATE TABLE unrelated(value TEXT)")
        .unwrap();
    drop(engine);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Engine::open(&path, config()),
        Err(Error::Configuration)
    ));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn sqlite_internal_table_prefix_is_literal_and_cannot_hide_foreign_schema() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let engine = Engine::open(&path, config()).unwrap();
    engine
        .connection
        .execute_batch("CREATE TABLE sqliteXhidden(value TEXT)")
        .unwrap();
    drop(engine);
    let original = fs::read(&path).unwrap();
    assert!(matches!(
        Engine::open(&path, config()),
        Err(Error::Configuration)
    ));
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn private_single_link_files_and_writer_lease_are_required() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let engine = Engine::open(&path, config()).unwrap();
    assert!(matches!(Engine::open(&path, config()), Err(Error::Busy)));
    drop(engine);
    fs::hard_link(&path, dir.path().join("other")).unwrap();
    assert!(matches!(
        Engine::open(&path, config()),
        Err(Error::Configuration)
    ));
    fs::remove_file(dir.path().join("other")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Engine::open(&path, config()),
        Err(Error::Configuration)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&path, dir.path().join("alias.sqlite")).unwrap();
    assert!(matches!(
        Engine::open(&dir.path().join("alias.sqlite"), config()),
        Err(Error::Configuration)
    ));
    symlink(&path, dir.path().join("state.sqlite-journal")).unwrap();
    assert!(Engine::open(&path, config()).is_err());
    fs::remove_file(dir.path().join("state.sqlite-journal")).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Engine::open(&path, config()),
        Err(Error::Configuration)
    ));
}

#[tokio::test]
async fn confirmed_shutdown_releases_database_lease_and_closed_clones_refuse() {
    let dir = directory();
    let path = dir.path().join("state.sqlite");
    let (journal, ready) = Journal::begin_open(path.clone(), config(), context()).unwrap();
    ready.wait().await.unwrap();
    journal.commit(0, record(1, 1), context()).await.unwrap();
    let other = journal.clone();
    journal.shutdown(context()).await.unwrap();
    assert!(other.is_closed());
    assert_eq!(other.load(context()).await, Err(Error::Closed));
    let engine = Engine::open(&path, config()).unwrap();
    assert_eq!(engine.load().unwrap(), Some(record(1, 1)));
}

type Probe = (
    tokio::sync::oneshot::Sender<()>,
    std::sync::mpsc::Receiver<()>,
);
static BUSY: Mutex<Option<Probe>> = Mutex::new(None);
pub(super) fn busy_probe(_: i32) -> bool {
    if let Some((entered, release)) = BUSY.lock().unwrap().take() {
        let _ = entered.send(());
        return release.recv_timeout(Duration::from_secs(3)).is_ok();
    }
    false
}
#[tokio::test]
async fn sqlite_commit_retains_physical_capacity_after_cancel_drop_or_timeout_and_lost_reply_reloads()
 {
    for mode in ["cancel", "drop", "timeout"] {
        let dir = directory();
        let path = dir.path().join("physical.sqlite");
        let (journal, ready) = Journal::begin_open(path.clone(), config(), context()).unwrap();
        ready.wait().await.unwrap();
        let locker = Connection::open(&path).unwrap();
        locker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (enter, entered) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        *BUSY.lock().unwrap() = Some((enter, finish));
        let pending = RuleContext::new(Duration::from_secs(1));
        let cancel = pending.cancellation.clone();
        let other = journal.clone();
        let caller = tokio::spawn(async move { other.commit(0, record(1, 7), pending).await });
        tokio::time::timeout(Duration::from_secs(3), entered)
            .await
            .unwrap()
            .unwrap();
        match mode {
            "cancel" => {
                cancel.cancel();
                assert_eq!(caller.await.unwrap(), Err(Error::Cancelled));
            }
            "drop" => {
                caller.abort();
                assert!(caller.await.unwrap_err().is_cancelled());
            }
            _ => {
                assert_eq!(caller.await.unwrap(), Err(Error::Timeout));
            }
        }
        assert_eq!(journal.metrics(), (1, 1, 1));
        assert_eq!(journal.load(context()).await, Err(Error::Busy));
        assert_eq!(journal.metrics(), (1, 1, 2));
        locker.execute_batch("ROLLBACK").unwrap();
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while journal.metrics().0 != 0 {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(journal.load(context()).await.unwrap(), Some(record(1, 7)));
        journal.shutdown(context()).await.unwrap();
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
#[ignore = "owned subprocess helper; parent performs observed SIGKILL"]
fn crash_child() {
    let dir = std::env::var_os("SIGNAL_STATE_JOURNAL_CHILD").unwrap();
    let dir = Path::new(&dir);
    let mut engine = Engine::open(&dir.join("state.sqlite"), config()).unwrap();
    let mut next = record(2, 2);
    next.state = b"next complete monitor/proof snapshot".to_vec();
    next.outbox.push(Output {
        schema_version: 1,
        id: Uuid::from_u128(3),
        bytes: b"second original finding".to_vec(),
    });
    if std::env::var("SIGNAL_STATE_JOURNAL_PHASE").unwrap() == "before" {
        let tx = engine
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        write(&tx, &next, &next.encode(&config()).unwrap()).unwrap();
        fs::write(dir.join("ready"), b"transaction open").unwrap();
        loop {
            std::thread::park();
        }
    }
    engine.commit(1, next).unwrap();
    fs::write(dir.join("ready"), b"committed").unwrap();
    loop {
        std::thread::park();
    }
}
#[test]
fn actual_sigkill_before_and_after_commit_recovers_only_complete_original_frames() {
    for phase in ["before", "after"] {
        let dir = directory();
        let path = dir.path().join("state.sqlite");
        let mut engine = Engine::open(&path, config()).unwrap();
        let original = record(1, 1);
        engine.commit(0, original.clone()).unwrap();
        drop(engine);
        let mut child = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "state_journal::tests::crash_child"])
                .env("SIGNAL_STATE_JOURNAL_CHILD", dir.path())
                .env("SIGNAL_STATE_JOURNAL_PHASE", phase)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dir.path().join("ready").exists() {
            assert!(Instant::now() < deadline);
            assert!(child.0.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        let recovered = Engine::open(&path, config())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        if phase == "before" {
            assert_eq!(recovered, original);
        } else {
            assert_eq!((recovered.revision, recovered.checkpoint), (2, 2));
            assert_eq!(recovered.outbox[0], original.outbox[0]);
            assert_eq!(recovered.outbox[1].bytes, b"second original finding");
            assert_eq!(recovered.state, b"next complete monitor/proof snapshot");
        }
    }
}

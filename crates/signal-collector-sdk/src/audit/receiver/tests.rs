use super::*;
use chrono::Utc;
use signal_protocol::audit::{Action, Actor, AuditRecord, ConfigurationKind};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn ctx() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5)).unwrap()
}
fn limits() -> ReceiverLimits {
    ReceiverLimits {
        max_bytes: 1024 * 1024,
        max_records: 8,
        max_producers: 2,
    }
}
fn folder() -> tempfile::TempDir {
    let f = tempfile::tempdir().unwrap();
    fs::set_permissions(f.path(), fs::Permissions::from_mode(0o700)).unwrap();
    f
}
fn record(producer: Uuid, sequence: u64) -> PreparedAudit {
    AuditRecord {
        schema_version: 1,
        record_id: Uuid::new_v4(),
        producer_id: producer,
        sequence,
        timestamp: Utc::now(),
        actor: Actor::System {},
        action: Action::ConfigurationActivation {
            configuration: ConfigurationKind::Rules,
            revision_sha256: "a".repeat(64),
        },
    }
    .prepare()
    .unwrap()
}
fn grant(producer: Uuid) -> TrustedProducer {
    TrustedProducer::from_authenticated_namespace(producer).unwrap()
}
async fn open(root: &Path, mode: OpenMode, l: ReceiverLimits, producers: &[Uuid]) -> AuditReceiver {
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match AuditReceiver::open(root, mode, l, producers, ctx()).await {
            Ok(r) => return r,
            Err(ReceiverError::Busy) if tokio::time::Instant::now() < until => {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
            Err(e) => panic!("receiver open: {e}"),
        }
    }
}
fn framed(root: &Path, record: &PreparedAudit) -> Vec<u8> {
    let mut b = Vec::from(&b"AUD1"[..]);
    b.extend_from_slice(&(record.body().len() as u32).to_le_bytes());
    let identity: [u8; CONTROL] = fs::read(root.join("control")).unwrap().try_into().unwrap();
    b.extend_from_slice(&frame_digest(&identity, record.body()));
    let check = header_digest(&identity, &b);
    b.extend_from_slice(&check);
    b.extend_from_slice(record.body());
    b
}

#[tokio::test]
async fn exact_original_ack_interleaved_history_and_reopen_replay() {
    let _serial = SERIAL.lock().await;
    let dir = folder();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let store = open(dir.path(), OpenMode::Initialize, limits(), &[a, b]).await;
    let first = record(a, 1);
    let formatted = PreparedAudit::from_original(
        format!(" \n{}\n ", std::str::from_utf8(first.body()).unwrap()).as_bytes(),
    )
    .unwrap();
    let ack = store.append(&grant(a), &formatted, ctx()).await.unwrap();
    formatted.verify_acknowledgement(&ack).unwrap();
    let second = record(b, 1);
    let third = record(a, 2);
    for r in [&second, &third] {
        r.verify_acknowledgement(
            &store
                .append(&grant(r.record().producer_id), r, ctx())
                .await
                .unwrap(),
        )
        .unwrap();
    }
    let bytes = fs::read(dir.path().join("journal")).unwrap();
    assert!(
        bytes
            .windows(formatted.body().len())
            .any(|b| b == formatted.body())
    );
    assert_eq!(
        store.append(&grant(a), &formatted, ctx()).await.unwrap(),
        ack
    );
    assert_eq!(fs::read(dir.path().join("journal")).unwrap(), bytes);
    assert_eq!(store.health().records, 3);
    drop(store);
    let reopened = open(dir.path(), OpenMode::Existing, limits(), &[a, b]).await;
    assert_eq!(
        reopened.append(&grant(a), &formatted, ctx()).await.unwrap(),
        ack
    );
    assert_eq!(reopened.health().records, 3);
    assert_eq!(fs::read(dir.path().join("journal")).unwrap(), bytes);
}

#[tokio::test]
async fn authenticated_scope_sequence_bytes_and_global_id_conflicts_do_not_mutate() {
    let _serial = SERIAL.lock().await;
    let dir = folder();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    let store = open(dir.path(), OpenMode::Initialize, limits(), &[a, b]).await;
    let first = record(a, 1);
    store.append(&grant(a), &first, ctx()).await.unwrap();
    let baseline = fs::read(dir.path().join("journal")).unwrap();
    assert_eq!(
        store.append(&grant(b), &first, ctx()).await,
        Err(ReceiverError::Denied)
    );
    assert_eq!(
        store
            .append(&grant(foreign), &record(foreign, 1), ctx())
            .await,
        Err(ReceiverError::Denied)
    );
    assert_eq!(
        store.append(&grant(a), &record(a, 3), ctx()).await,
        Err(ReceiverError::Conflict)
    );
    let changed = PreparedAudit::from_original(
        format!(" {}", std::str::from_utf8(first.body()).unwrap()).as_bytes(),
    )
    .unwrap();
    assert_eq!(
        store.append(&grant(a), &changed, ctx()).await,
        Err(ReceiverError::Conflict)
    );
    let mut value: AuditRecord = serde_json::from_slice(first.body()).unwrap();
    value.producer_id = b;
    assert_eq!(
        store
            .append(&grant(b), &value.prepare().unwrap(), ctx())
            .await,
        Err(ReceiverError::Conflict)
    );
    assert_eq!(
        store.append(&grant(a), &record(a, 1), ctx()).await,
        Err(ReceiverError::Conflict)
    );
    assert_eq!(store.health().rejected, 6);
    assert_eq!(store.health().records, 1);
    assert!(!store.health().held);
    assert_eq!(fs::read(dir.path().join("journal")).unwrap(), baseline);
    let cancelled = ctx();
    cancelled.cancellation().cancel();
    assert_eq!(
        store.append(&grant(a), &record(a, 2), cancelled).await,
        Err(ReceiverError::Uncertain)
    );
    assert_eq!(fs::read(dir.path().join("journal")).unwrap(), baseline);
}

#[tokio::test]
async fn finite_record_and_byte_reserves_reject_before_write_but_allow_exact_replay() {
    let _serial = SERIAL.lock().await;
    let dir = folder();
    let a = Uuid::new_v4();
    let first = record(a, 1);
    let mut l = limits();
    l.max_records = 1;
    let store = open(dir.path(), OpenMode::Initialize, l, &[a]).await;
    let ack = store.append(&grant(a), &first, ctx()).await.unwrap();
    let baseline = fs::read(dir.path().join("journal")).unwrap();
    assert_eq!(
        store.append(&grant(a), &record(a, 2), ctx()).await,
        Err(ReceiverError::Full)
    );
    assert_eq!(store.append(&grant(a), &first, ctx()).await.unwrap(), ack);
    assert_eq!(fs::read(dir.path().join("journal")).unwrap(), baseline);
    drop(store);
    assert!(matches!(
        AuditReceiver::open(dir.path(), OpenMode::Initialize, l, &[a], ctx()).await,
        Err(ReceiverError::History)
    ));
    let dir = folder();
    let mut l = limits();
    l.max_bytes = (HEADER + RECORD_BYTES) as u64;
    let store = open(dir.path(), OpenMode::Initialize, l, &[a]).await;
    let padded = PreparedAudit::from_original(
        format!(
            "{}{}",
            std::str::from_utf8(first.body()).unwrap(),
            " ".repeat(RECORD_BYTES - first.body().len())
        )
        .as_bytes(),
    )
    .unwrap();
    store.append(&grant(a), &padded, ctx()).await.unwrap();
    let baseline = fs::read(dir.path().join("journal")).unwrap();
    assert_eq!(
        store.append(&grant(a), &record(a, 2), ctx()).await,
        Err(ReceiverError::Full)
    );
    assert_eq!(fs::read(dir.path().join("journal")).unwrap(), baseline);
    assert_eq!(store.health().bytes, l.max_bytes);
}

#[tokio::test]
async fn explicit_existing_history_hostile_root_and_identity_changes_fail_closed() {
    let _serial = SERIAL.lock().await;
    let a = Uuid::new_v4();
    let empty = folder();
    assert!(matches!(
        AuditReceiver::open(empty.path(), OpenMode::Existing, limits(), &[a], ctx()).await,
        Err(ReceiverError::History)
    ));
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
    assert!(matches!(
        AuditReceiver::open(empty.path(), OpenMode::Initialize, limits(), &[a, a], ctx()).await,
        Err(ReceiverError::Invalid)
    ));
    let store = open(empty.path(), OpenMode::Initialize, limits(), &[a]).await;
    assert!(matches!(
        AuditReceiver::open(empty.path(), OpenMode::Existing, limits(), &[a], ctx()).await,
        Err(ReceiverError::Busy)
    ));
    let mut control = fs::read(empty.path().join("control")).unwrap();
    control[8] ^= 1;
    fs::write(empty.path().join("control"), control).unwrap();
    assert_eq!(
        store.append(&grant(a), &record(a, 1), ctx()).await,
        Err(ReceiverError::History)
    );
    assert!(store.health().held);
    assert_eq!(store.health().records, 0);
    drop(store);
    let dir = folder();
    let store = open(dir.path(), OpenMode::Initialize, limits(), &[a]).await;
    drop(store);
    fs::hard_link(dir.path().join("journal"), dir.path().join("alias")).unwrap();
    assert!(matches!(
        AuditReceiver::open(dir.path(), OpenMode::Existing, limits(), &[a], ctx()).await,
        Err(ReceiverError::History)
    ));
    fs::remove_file(dir.path().join("alias")).unwrap();
    fs::remove_file(dir.path().join("journal")).unwrap();
    symlink(empty.path().join("journal"), dir.path().join("journal")).unwrap();
    assert!(matches!(
        AuditReceiver::open(dir.path(), OpenMode::Existing, limits(), &[a], ctx()).await,
        Err(ReceiverError::History)
    ));
}

#[tokio::test]
async fn recover_only_incomplete_final_body_and_preserve_corrupt_or_partial_headers() {
    let _serial = SERIAL.lock().await;
    let a = Uuid::new_v4();
    for corruption in [
        "torn-body",
        "partial-header",
        "bad-hash",
        "bad-magic",
        "gap",
        "bad-checksum-torn-body",
    ] {
        let dir = folder();
        let store = open(dir.path(), OpenMode::Initialize, limits(), &[a]).await;
        let first = record(a, 1);
        store.append(&grant(a), &first, ctx()).await.unwrap();
        drop(store);
        let path = dir.path().join("journal");
        let baseline = fs::read(&path).unwrap();
        let mut tail = framed(
            dir.path(),
            &record(a, if corruption == "gap" { 3 } else { 2 }),
        );
        match corruption {
            "torn-body" => tail.truncate(HEADER + 5),
            "bad-checksum-torn-body" => {
                tail.truncate(HEADER + 5);
                tail[40] ^= 1;
            }
            "partial-header" => tail.truncate(10),
            "bad-hash" => tail[8] ^= 1,
            "bad-magic" => tail[0] = b'X',
            _ => {}
        }
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&tail).unwrap();
        file.sync_all().unwrap();
        drop(file);
        if corruption == "torn-body" {
            let reopened = open(dir.path(), OpenMode::Existing, limits(), &[a]).await;
            assert_eq!(reopened.health().records, 1);
            assert_eq!(fs::read(path).unwrap(), baseline);
            first
                .verify_acknowledgement(&reopened.append(&grant(a), &first, ctx()).await.unwrap())
                .unwrap();
        } else {
            let altered = fs::read(&path).unwrap();
            assert!(matches!(
                AuditReceiver::open(dir.path(), OpenMode::Existing, limits(), &[a], ctx()).await,
                Err(ReceiverError::History)
            ));
            assert_eq!(fs::read(&path).unwrap(), altered);
        }
    }
}

#[tokio::test]
async fn live_retained_retry_revalidates_exact_disk_bytes_not_only_index() {
    let _serial = SERIAL.lock().await;
    let dir = folder();
    let a = Uuid::new_v4();
    let store = open(dir.path(), OpenMode::Initialize, limits(), &[a]).await;
    let first = record(a, 1);
    store.append(&grant(a), &first, ctx()).await.unwrap();
    let path = dir.path().join("journal");
    let mut altered = fs::read(&path).unwrap();
    altered[HEADER + 5] ^= 1;
    fs::write(&path, &altered).unwrap();
    assert_eq!(
        store.append(&grant(a), &first, ctx()).await,
        Err(ReceiverError::History)
    );
    assert!(store.health().held);
    assert_eq!(fs::read(path).unwrap(), altered);
}

#[tokio::test]
async fn journal_transplant_into_another_valid_root_identity_is_rejected() {
    let _serial = SERIAL.lock().await;
    let a = Uuid::new_v4();
    let left = folder();
    let right = folder();
    let store = open(left.path(), OpenMode::Initialize, limits(), &[a]).await;
    store.append(&grant(a), &record(a, 1), ctx()).await.unwrap();
    drop(store);
    let store = open(right.path(), OpenMode::Initialize, limits(), &[a]).await;
    drop(store);
    assert_ne!(
        fs::read(left.path().join("control")).unwrap(),
        fs::read(right.path().join("control")).unwrap()
    );
    let original = fs::read(left.path().join("journal")).unwrap();
    fs::write(right.path().join("journal"), &original).unwrap();
    assert!(matches!(
        AuditReceiver::open(right.path(), OpenMode::Existing, limits(), &[a], ctx()).await,
        Err(ReceiverError::History)
    ));
    assert_eq!(fs::read(right.path().join("journal")).unwrap(), original);
}

#[tokio::test]
#[ignore = "invoked only by the bounded parent crash fixture"]
async fn receiver_process_child() {
    let root = PathBuf::from(std::env::var("SIGNAL_TEST_AUDIT_RECEIVER_ROOT").unwrap());
    let body = fs::read(std::env::var("SIGNAL_TEST_AUDIT_RECEIVER_RECORD").unwrap()).unwrap();
    let record = PreparedAudit::from_original(&body).unwrap();
    let producer = record.record().producer_id;
    let store = open(&root, OpenMode::Existing, limits(), &[producer]).await;
    store
        .append(&grant(producer), &record, ctx())
        .await
        .unwrap();
    panic!("expected crash stage was not reached");
}

#[tokio::test]
async fn process_crashes_before_write_through_readback_preserve_exact_retry() {
    let _serial = SERIAL.lock().await;
    let producer = Uuid::new_v4();
    for stage in [
        "before-write",
        "header-written",
        "body-written",
        "journal-synced",
        "readback-confirmed",
    ] {
        let dir = folder();
        let root = dir.path().join("store");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = open(&root, OpenMode::Initialize, limits(), &[producer]).await;
        drop(store);
        let first = record(producer, 1);
        let fixture = dir.path().join("original.json");
        fs::write(&fixture, first.body()).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit::receiver::tests::receiver_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SIGNAL_TEST_AUDIT_RECEIVER_ROOT", &root)
            .env("SIGNAL_TEST_AUDIT_RECEIVER_RECORD", &fixture)
            .env("SIGNAL_TEST_AUDIT_RECEIVER_CRASH", stage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= until {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("crash child exceeded finite deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(76), "{stage}");
        let reopened = open(&root, OpenMode::Existing, limits(), &[producer]).await;
        assert_eq!(
            reopened.health().records,
            if matches!(stage, "before-write" | "header-written") {
                0
            } else {
                1
            },
            "{stage}"
        );
        first
            .verify_acknowledgement(
                &reopened
                    .append(&grant(producer), &first, ctx())
                    .await
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(reopened.health().records, 1);
        assert_eq!(
            fs::read(root.join("journal")).unwrap(),
            framed(&root, &first)
        );
    }
}

#[tokio::test]
async fn synced_effect_caller_abort_retains_physical_lock_and_reconciles_exact_retry() {
    let _serial = SERIAL.lock().await;
    let dir = folder();
    let a = Uuid::new_v4();
    let store = Arc::new(open(dir.path(), OpenMode::Initialize, limits(), &[a]).await);
    let first = record(a, 1);
    let body = first.body().to_vec();
    let (entered, seen) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    store.engine.lock().unwrap().pause = Some(Pause {
        entered,
        release: wait,
    });
    let task = {
        let store = store.clone();
        let body = body.clone();
        tokio::spawn(async move {
            store
                .append(
                    &grant(a),
                    &PreparedAudit::from_original(&body).unwrap(),
                    ctx(),
                )
                .await
        })
    };
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if seen.try_recv().is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(store.health().physical_depth, 1);
    assert_eq!(
        fs::read(dir.path().join("journal")).unwrap(),
        framed(dir.path(), &first)
    );
    assert_eq!(
        store.append(&grant(a), &record(a, 2), ctx()).await,
        Err(ReceiverError::Busy)
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(store.health().held);
    assert_eq!(store.health().uncertain, 1);
    assert!(store.engine.try_lock().is_err());
    let directory = File::open(dir.path()).unwrap();
    let lock = open_file(&directory, "lock", false, 0).unwrap();
    assert!(lock.try_lock().is_err());
    drop(store);
    assert!(lock.try_lock().is_err());
    release.send(()).unwrap();
    drop(lock);
    let reopened = open(dir.path(), OpenMode::Existing, limits(), &[a]).await;
    assert_eq!(reopened.health().records, 1);
    let ack = reopened.append(&grant(a), &first, ctx()).await.unwrap();
    first.verify_acknowledgement(&ack).unwrap();
    assert_eq!(
        fs::read(dir.path().join("journal")).unwrap(),
        framed(dir.path(), &first)
    );
    assert!(!reopened.health().held);
}

#[tokio::test]
async fn altered_final_length_never_truncates_an_acknowledged_complete_record() {
    let _serial = SERIAL.lock().await;
    let producer = Uuid::new_v4();
    let dir = folder();
    let store = open(dir.path(), OpenMode::Initialize, limits(), &[producer]).await;
    let first = record(producer, 1);
    store.append(&grant(producer), &first, ctx()).await.unwrap();
    drop(store);
    let path = dir.path().join("journal");
    let mut changed = fs::read(&path).unwrap();
    changed[4..8].copy_from_slice(&((first.body().len() + 1) as u32).to_le_bytes());
    fs::write(&path, &changed).unwrap();
    assert!(
        matches!(
            AuditReceiver::open(dir.path(), OpenMode::Existing, limits(), &[producer], ctx()).await,
            Err(ReceiverError::History)
        ),
        "corrupt length must not become an incomplete-tail recovery"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        changed,
        "accepted original must remain evidence"
    );
}

#[tokio::test]
async fn caller_drop_before_mutation_arm_prevents_write_and_keeps_healthy_history() {
    let _serial = SERIAL.lock().await;
    let dir = folder();
    let a = Uuid::new_v4();
    let store = Arc::new(open(dir.path(), OpenMode::Initialize, limits(), &[a]).await);
    let first = record(a, 1);
    let body = first.body().to_vec();
    let (entered, seen) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    store.engine.lock().unwrap().pause_before_arm = Some(Pause {
        entered,
        release: wait,
    });
    let task = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .append(
                    &grant(a),
                    &PreparedAudit::from_original(&body).unwrap(),
                    ctx(),
                )
                .await
        })
    };
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if seen.try_recv().is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(store.health().physical_depth, 1);
    assert!(store.engine.try_lock().is_err());
    let directory = File::open(dir.path()).unwrap();
    let lock = open_file(&directory, "lock", false, 0).unwrap();
    assert!(lock.try_lock().is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!store.health().held);
    assert_eq!(store.health().uncertain, 0);
    release.send(()).unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    while store.health().physical_depth != 0 {
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        fs::read(dir.path().join("journal")).unwrap().is_empty(),
        "cancelled before arm must prevent disk effects"
    );
    assert!(!store.health().held);
    assert_eq!(store.health().records, 0);
    assert_eq!(store.health().uncertain, 0);
    first
        .verify_acknowledgement(&store.append(&grant(a), &first, ctx()).await.unwrap())
        .unwrap();
    assert_eq!(store.health().records, 1);
}

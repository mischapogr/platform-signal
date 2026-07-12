use super::*;
use signal_protocol::audit::{AppendFuture, AuditMetrics, ConfigurationKind};
use std::{os::unix::fs::PermissionsExt, time::Duration};
use tokio_util::sync::CancellationToken;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn context() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(10)).unwrap()
}
fn action() -> Action {
    Action::ConfigurationActivation {
        configuration: ConfigurationKind::Rules,
        revision_sha256: "a".repeat(64),
    }
}
fn folder() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
async fn opened(path: &Path) -> AuditOutbox {
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match AuditOutbox::open(path, context()).await {
            Ok(outbox) => return outbox,
            Err(OutboxError::Busy) if tokio::time::Instant::now() < until => {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
            _ => panic!("audit outbox did not reopen"),
        }
    }
}
struct SyncedSink {
    root: PathBuf,
    lose_reply: AtomicBool,
}
impl AuditSink for SyncedSink {
    fn append<'a>(
        &'a self,
        record: &'a PreparedAudit,
        deadline: std::time::Instant,
    ) -> AppendFuture<'a> {
        Box::pin(async move {
            assert!(std::time::Instant::now() < deadline);
            assert!(record.record().sequence <= 2);
            let path = self.root.join(record.record().sequence.to_string());
            if path.exists() {
                assert_eq!(fs::read(path).unwrap(), record.body());
            } else {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .unwrap();
                file.write_all(record.body()).unwrap();
                file.sync_all().unwrap();
                File::open(&self.root).unwrap().sync_all().unwrap();
            }
            if self.lose_reply.swap(false, Ordering::AcqRel) {
                return Err(AppendError::Uncertain);
            }
            let ack = AuditAcknowledgement::for_prepared(record)
                .to_json()
                .unwrap();
            record.verify_acknowledgement(&ack).unwrap();
            Ok(())
        })
    }
    fn metrics(&self) -> AuditMetrics {
        AuditMetrics {
            capacity: 1,
            ..AuditMetrics::default()
        }
    }
}
struct ControlInsertedAfterAck {
    sink: SyncedSink,
    outbox: PathBuf,
    name: &'static str,
}
impl AuditSink for ControlInsertedAfterAck {
    fn append<'a>(
        &'a self,
        record: &'a PreparedAudit,
        deadline: std::time::Instant,
    ) -> AppendFuture<'a> {
        Box::pin(async move {
            self.sink.append(record, deadline).await?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.outbox.join(self.name))
                .unwrap();
            file.write_all(b"{divergent-after-exact-ack").unwrap();
            file.sync_all().unwrap();
            Ok(())
        })
    }
    fn metrics(&self) -> AuditMetrics {
        self.sink.metrics()
    }
}
#[tokio::test]
async fn lost_synced_reply_replays_original_bytes_and_advances_only_exact_checkpoint() {
    let _serial = SERIAL.lock().await;
    let root = folder();
    let destination = folder();
    let sink = SyncedSink {
        root: destination.path().to_owned(),
        lose_reply: AtomicBool::new(true),
    };
    let outbox = opened(root.path()).await;
    let first = outbox
        .stage(Actor::System {}, action(), Utc::now(), context())
        .await
        .unwrap();
    assert_eq!(outbox.metrics().depth, 1);
    assert!(matches!(
        outbox
            .stage(Actor::System {}, action(), Utc::now(), context())
            .await,
        Err(OutboxError::Busy)
    ));
    assert_eq!(
        outbox.flush(&sink, context()).await,
        Err(OutboxError::Uncertain)
    );
    assert!(!outbox.metrics().held);
    assert_eq!(
        State::decode(&fs::read(root.path().join("state")).unwrap())
            .unwrap()
            .sequence(),
        0
    );
    drop(outbox);
    let outbox = opened(root.path()).await;
    let replay = outbox.pending(context()).await.unwrap().unwrap();
    assert_eq!(replay.body(), first.body());
    assert_eq!(replay.sha256(), first.sha256());
    assert_eq!(
        outbox.flush(&sink, context()).await.unwrap(),
        Some(first.record().record_id)
    );
    assert_eq!(outbox.metrics().depth, 0);
    let checkpoint = State::decode(&fs::read(root.path().join("state")).unwrap()).unwrap();
    assert!(checkpoint.matches(&first));
    assert!(!root.path().join("pending").exists());
    let second = outbox
        .stage(Actor::System {}, action(), Utc::now(), context())
        .await
        .unwrap();
    assert_eq!(second.record().producer_id, first.record().producer_id);
    assert_eq!(second.record().sequence, 2);
    assert_ne!(second.record().record_id, first.record().record_id);
    outbox.flush(&sink, context()).await.unwrap();
    assert_eq!(outbox.flush(&sink, context()).await.unwrap(), None);
    assert_eq!(
        fs::read(destination.path().join("1")).unwrap(),
        first.body()
    );
    assert_eq!(
        fs::read(destination.path().join("2")).unwrap(),
        second.body()
    );
}

#[tokio::test]
async fn unsafe_roots_and_divergent_history_are_rejected_without_evidence_replacement() {
    let _serial = SERIAL.lock().await;
    for fault in [
        "unknown",
        "symlink",
        "external-link",
        "oversized",
        "permissions",
        "corrupt",
        "foreign-producer",
        "missing-state",
        "array-state",
    ] {
        let d = folder();
        let outbox = opened(d.path()).await;
        let record = outbox
            .stage(Actor::System {}, action(), Utc::now(), context())
            .await
            .unwrap();
        drop(outbox);
        let state_path = d.path().join("state");
        let pending_path = d.path().join("pending");
        let original = fs::read(&state_path).unwrap();
        let external = folder();
        let target = external.path().join("private");
        fs::write(&target, b"synthetic-private-evidence").unwrap();
        match fault {
            "unknown" => fs::write(d.path().join("unexpected"), b"preserve").unwrap(),
            "symlink" => {
                fs::remove_file(&pending_path).unwrap();
                std::os::unix::fs::symlink(&target, &pending_path).unwrap();
            }
            "external-link" => {
                fs::remove_file(&pending_path).unwrap();
                fs::hard_link(&target, &pending_path).unwrap();
            }
            "oversized" => fs::write(&pending_path, vec![b'x'; RECORD_BYTES + 1]).unwrap(),
            "permissions" => {
                fs::set_permissions(&pending_path, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "corrupt" => fs::write(&pending_path, b"{partial").unwrap(),
            "foreign-producer" => {
                let mut value: serde_json::Value = serde_json::from_slice(record.body()).unwrap();
                value["producer_id"] = serde_json::json!(Uuid::new_v4());
                fs::write(&pending_path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            "missing-state" => fs::remove_file(&state_path).unwrap(),
            "array-state" => fs::write(
                &state_path,
                serde_json::to_vec(&(1, record.record().producer_id, Option::<u8>::None)).unwrap(),
            )
            .unwrap(),
            _ => unreachable!(),
        }
        let retained_pending = if fault == "symlink" {
            None
        } else {
            Some(fs::read(&pending_path).unwrap())
        };
        assert!(matches!(
            AuditOutbox::open(d.path(), context()).await,
            Err(OutboxError::History)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"synthetic-private-evidence");
        if let Some(bytes) = retained_pending {
            assert_eq!(fs::read(&pending_path).unwrap(), bytes);
        }
        if !["missing-state", "array-state"].contains(&fault) {
            assert_eq!(fs::read(state_path).unwrap(), original);
        }
    }
    let root = folder();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        AuditOutbox::open(root.path(), context()).await,
        Err(OutboxError::Invalid)
    ));
}

#[tokio::test]
async fn live_temporary_controls_block_delivery_and_checkpoint_advancement() {
    let _serial = SERIAL.lock().await;
    for name in ["state.next", "pending.next"] {
        let d = folder();
        let outbox = opened(d.path()).await;
        outbox
            .stage(Actor::System {}, action(), Utc::now(), context())
            .await
            .unwrap();
        let state = fs::read(d.path().join("state")).unwrap();
        let pending = fs::read(d.path().join("pending")).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(d.path().join(name))
            .unwrap();
        file.write_all(b"{divergent-temporary-control").unwrap();
        file.sync_all().unwrap();
        let destination = folder();
        let sink = SyncedSink {
            root: destination.path().to_owned(),
            lose_reply: AtomicBool::new(false),
        };
        assert_eq!(
            outbox.flush(&sink, context()).await,
            Err(OutboxError::History)
        );
        assert_eq!(
            fs::read_dir(destination.path()).unwrap().count(),
            0,
            "live divergent graph must not reach the sink"
        );
        assert_eq!(fs::read(d.path().join("state")).unwrap(), state);
        assert_eq!(fs::read(d.path().join("pending")).unwrap(), pending);
        assert_eq!(
            fs::read(d.path().join(name)).unwrap(),
            b"{divergent-temporary-control"
        );
    }
    for name in ["state.next", "pending.next"] {
        let d = folder();
        let outbox = opened(d.path()).await;
        let record = outbox
            .stage(Actor::System {}, action(), Utc::now(), context())
            .await
            .unwrap();
        let state = fs::read(d.path().join("state")).unwrap();
        let destination = folder();
        let sink = ControlInsertedAfterAck {
            sink: SyncedSink {
                root: destination.path().to_owned(),
                lose_reply: AtomicBool::new(false),
            },
            outbox: d.path().to_owned(),
            name,
        };
        assert_eq!(
            outbox.flush(&sink, context()).await,
            Err(OutboxError::History)
        );
        assert_eq!(
            fs::read(destination.path().join("1")).unwrap(),
            record.body()
        );
        assert_eq!(fs::read(d.path().join("state")).unwrap(), state);
        assert_eq!(fs::read(d.path().join("pending")).unwrap(), record.body());
        assert_eq!(
            fs::read(d.path().join(name)).unwrap(),
            b"{divergent-after-exact-ack"
        );
    }
}

#[tokio::test]
async fn denied_recovery_preserves_complete_alias_graph() {
    let _serial = SERIAL.lock().await;
    for alias in ["pending", "state"] {
        let d = folder();
        let outbox = opened(d.path()).await;
        let record = outbox
            .stage(Actor::System {}, action(), Utc::now(), context())
            .await
            .unwrap();
        drop(outbox);
        let mut value: serde_json::Value = serde_json::from_slice(record.body()).unwrap();
        value["producer_id"] = serde_json::json!(Uuid::new_v4());
        fs::write(
            d.path().join("pending"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let published = d.path().join(alias);
        let temporary = d.path().join(format!("{alias}.next"));
        fs::hard_link(&published, &temporary).unwrap();
        let original = fs::read(&published).unwrap();
        assert!(matches!(
            AuditOutbox::open(d.path(), context()).await,
            Err(OutboxError::History)
        ));
        assert_eq!(fs::read(&published).unwrap(), original);
        assert_eq!(
            fs::read(&temporary).unwrap(),
            original,
            "all aliases must survive graph denial"
        );
    }
}

#[tokio::test]
async fn physical_metadata_capacity_is_bounded_before_transfer() {
    let _serial = SERIAL.lock().await;
    let d = folder();
    let outbox = opened(d.path()).await;
    let mut key = String::with_capacity(1024 * 1024);
    key.push_str(&"a".repeat(64));
    let mut revision = String::with_capacity(1024 * 1024);
    revision.push_str(&"b".repeat(64));
    let record = outbox
        .stage(
            Actor::VerifiedSubject { key },
            Action::ConfigurationActivation {
                configuration: ConfigurationKind::Rules,
                revision_sha256: revision,
            },
            Utc::now(),
            context(),
        )
        .await
        .unwrap();
    assert!(
        outbox.engine.lock().unwrap().input_capacity <= 64,
        "only bounded metadata may cross into physical work"
    );
    assert!(
        matches!(&record.record().actor, Actor::VerifiedSubject { key } if key == &"a".repeat(64))
    );
}

#[tokio::test]
async fn retained_lock_nested_array_and_live_identity_replacement_never_reset_or_publish() {
    let _serial = SERIAL.lock().await;
    let d = folder();
    let outbox = opened(d.path()).await;
    let record = outbox
        .stage(Actor::System {}, action(), Utc::now(), context())
        .await
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(record.body()).unwrap();
    value["producer_id"] = serde_json::json!(Uuid::new_v4());
    let foreign = serde_json::to_vec(&value).unwrap();
    fs::write(d.path().join("pending"), &foreign).unwrap();
    assert!(matches!(
        outbox.pending(context()).await,
        Err(OutboxError::History)
    ));
    let destination = folder();
    let sink = SyncedSink {
        root: destination.path().to_owned(),
        lose_reply: AtomicBool::new(false),
    };
    assert_eq!(
        outbox.flush(&sink, context()).await,
        Err(OutboxError::History)
    );
    assert_eq!(fs::read_dir(destination.path()).unwrap().count(), 0);
    assert_eq!(fs::read(d.path().join("pending")).unwrap(), foreign);
    drop(outbox);
    let state = serde_json::json!({"schema_version":1,"producer_id":record.record().producer_id,
        "acknowledged":[1,record.record().record_id,record.record().producer_id,record.record().sequence,record.sha256()]});
    assert!(matches!(
        State::decode(&serde_json::to_vec(&state).unwrap()),
        Err(OutboxError::History)
    ));
    let empty = folder();
    drop(opened(empty.path()).await);
    fs::remove_file(empty.path().join("state")).unwrap();
    assert!(matches!(
        AuditOutbox::open(empty.path(), context()).await,
        Err(OutboxError::History)
    ));
    assert!(!empty.path().join("state").exists());
    assert!(!empty.path().join("state.next").exists());
}

#[tokio::test]
async fn abandoned_physical_mutation_keeps_lock_and_capacity_until_retirement() {
    let _serial = SERIAL.lock().await;
    let d = folder();
    let outbox = Arc::new(opened(d.path()).await);
    let (began, started) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let caller_box = outbox.clone();
    let caller = tokio::spawn(async move {
        caller_box
            .run(context(), true, move |engine, ctx, changed| {
                let record = engine.stage(Actor::System {}, action(), Utc::now(), ctx, changed)?;
                began.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(record)
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .unwrap()
        .unwrap();
    let original = fs::read(d.path().join("pending")).unwrap();
    caller.abort();
    assert!(caller.await.err().unwrap().is_cancelled());
    assert_eq!(outbox.metrics().physical_depth, 1);
    assert!(outbox.metrics().held);
    assert!(matches!(
        outbox.pending(context()).await,
        Err(OutboxError::Busy)
    ));
    assert!(matches!(
        Engine::open(
            d.path().to_owned(),
            &context(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false))
        ),
        Err(OutboxError::Busy)
    ));
    drop(outbox);
    release.send(()).unwrap();
    let recovered = opened(d.path()).await;
    assert_eq!(
        recovered.pending(context()).await.unwrap().unwrap().body(),
        original
    );
    // Physical owner unlocks its open description even if an alias survives.
    let alias = recovered.engine.lock().unwrap().lock.0.try_clone().unwrap();
    drop(recovered);
    let successor = opened(d.path()).await;
    drop(alias);
    drop(successor);
}

#[tokio::test]
async fn original_clock_denies_late_start_and_ready_mutation_handoff() {
    let _serial = SERIAL.lock().await;
    let d = folder();
    let outbox = opened(d.path()).await;
    let before = fs::read(d.path().join("state")).unwrap();
    let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(20)).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(matches!(
        outbox
            .stage(Actor::System {}, action(), Utc::now(), ctx)
            .await,
        Err(OutboxError::Uncertain)
    ));
    assert_eq!(fs::read(d.path().join("state")).unwrap(), before);
    assert!(!d.path().join("pending").exists());
    assert!(!outbox.metrics().held);
    {
        let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(1)).unwrap();
        let deadline = ctx.deadline();
        let (began, started) = tokio::sync::oneshot::channel();
        let future = outbox.run(ctx, true, move |engine, ctx, changed| {
            let record = engine.stage(Actor::System {}, action(), Utc::now(), ctx, changed)?;
            began.send(()).unwrap();
            Ok(record)
        });
        tokio::pin!(future);
        tokio::select! { biased;
            r = started => r.unwrap(),
            _ = &mut future => panic!("consumed physical reply before deliberate late handoff"),
        }
        std::thread::sleep(
            deadline.saturating_duration_since(tokio::time::Instant::now())
                + Duration::from_millis(10),
        );
        assert!(matches!(future.await, Err(OutboxError::Uncertain)));
    }
    assert!(outbox.metrics().held);
    assert_eq!(outbox.metrics().uncertain, 1);
    assert!(outbox.pending(context()).await.is_err());
    drop(outbox);
    assert!(
        opened(d.path())
            .await
            .pending(context())
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
#[ignore = "invoked only by the bounded crash recovery parent"]
fn child_crash_fixture() {
    let root = PathBuf::from(std::env::var("SIGNAL_TEST_AUDIT_ROOT").unwrap());
    let mut engine = Engine::open(
        root,
        &context(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let changed = AtomicBool::new(false);
    let record = engine
        .stage(Actor::System {}, action(), Utc::now(), &context(), &changed)
        .unwrap();
    if std::env::var("SIGNAL_TEST_AUDIT_CRASH")
        .unwrap()
        .starts_with("checkpoint")
        || std::env::var("SIGNAL_TEST_AUDIT_CRASH").unwrap() == "pending-removed"
    {
        engine.confirm(record.body(), &context(), &changed).unwrap();
    }
    panic!("requested crash boundary was not reached");
}

#[tokio::test]
async fn process_crashes_reconcile_identity_pending_and_checkpoint_before_reclaim() {
    let _serial = SERIAL.lock().await;
    for stage in [
        "identity-temp",
        "identity-linked",
        "identity-synced",
        "pending-temp",
        "pending-linked",
        "pending-published",
        "pending-synced",
        "checkpoint-temp",
        "checkpoint-published",
        "checkpoint-synced",
        "pending-removed",
    ] {
        let d = folder();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "audit::outbox::tests::child_crash_fixture",
            ])
            .env("SIGNAL_TEST_AUDIT_ROOT", d.path())
            .env("SIGNAL_TEST_AUDIT_CRASH", stage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if tokio::time::Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("finite crash child exceeded deadline");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(status.code(), Some(75), "boundary {stage}");
        let pending_before = ["pending", "pending.next"]
            .into_iter()
            .find_map(|p| fs::read(d.path().join(p)).ok());
        let state_before = ["state", "state.next"]
            .into_iter()
            .find_map(|p| fs::read(d.path().join(p)).ok())
            .unwrap();
        let producer = State::decode(&state_before).unwrap().producer_id;
        let outbox = opened(d.path()).await;
        let state = State::decode(&fs::read(d.path().join("state")).unwrap()).unwrap();
        assert_eq!(
            state.producer_id, producer,
            "producer must not regenerate after {stage}"
        );
        let pending = outbox.pending(context()).await.unwrap();
        if stage.starts_with("pending-") && stage != "pending-removed" {
            assert_eq!(state.sequence(), 0);
            assert_eq!(pending.unwrap().body(), pending_before.unwrap());
        } else if stage.starts_with("checkpoint-") || stage == "pending-removed" {
            assert_eq!(state.sequence(), 1);
            assert!(pending.is_none());
            if let Some(body) = pending_before {
                assert!(state.matches(&PreparedAudit::from_original(&body).unwrap()));
            }
        } else {
            assert_eq!(state.sequence(), 0);
            assert!(pending.is_none());
        }
        assert!(!d.path().join("state.next").exists());
        assert!(!d.path().join("pending.next").exists());
    }
}

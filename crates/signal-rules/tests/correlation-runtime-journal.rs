#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
#[path = "support/correlation_d14.rs"]
mod support;
use signal_rules::{
    RuleContext,
    correlation::{
        self, Admission, Error, Status,
        d14::*,
        journal::{self, Applied, RuntimeAction},
    },
    state_journal::{Journal, Record},
};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};
use support::*;
use uuid::Uuid;

fn epoch(b: &RuntimeBinding, position: u64, c: &RuleContext) -> Result<RuntimeEpoch> {
    let proofs = b
        .config()
        .sources
        .iter()
        .map(|s| RuntimeVerification {
            source: correlation::Verification {
                stream: s.stream,
                position,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: b.config().authority_keys_sha256,
                verification_reference: "fixture://runtime-capture-prefix".into(),
                verified_at: ns(BASE + 100_000_000),
                verified_until: ns(BASE + 60_000_000_000),
                now: ns(BASE + 100_000_000),
                coverage_from: ns(BASE - 10_000_000),
                frontier: ns(BASE + 50_000_000),
                complete: true,
                authenticated: true,
            },
            capture: CaptureEvidence {
                enrollment_sha256: b.enrollment_sha256(),
                metadata_only: true,
                execution_continuity: true,
                clock_continuity: true,
            },
        })
        .collect();
    let policies = b
        .config()
        .policy_authorities
        .iter()
        .map(|a| PolicyCoverageVerification {
            enrollment_sha256: b.enrollment_sha256(),
            authority: a.id,
            authority_binding: a.binding,
            config_revision: a.config_revision.clone(),
            authority_keys_sha256: a.authority_keys_sha256,
            policy_revision: a.policy_revision.clone(),
            policy_config_sha256: a.policy_config_sha256,
            reference: "fixture://policy-coverage".into(),
            verified_at: ns(BASE + 100_000_000),
            verified_until: ns(BASE + 60_000_000_000),
            now: ns(BASE + 100_000_000),
            coverage_from: ns(BASE - 10_000_000),
            frontier: ns(BASE + 50_000_000),
            complete: true,
            authenticated: true,
        })
        .collect();
    Ok(RuntimeEpoch::new(b, proofs, policies, c)?)
}
async fn open(b: &RuntimeBinding, path: &Path) -> Result<Journal> {
    let (db, ready) = Journal::begin_open(path.to_owned(), b.journal_config(), context())?;
    ready.wait().await?;
    Ok(db)
}
fn directory() -> Result<tempfile::TempDir> {
    let d = tempfile::tempdir()?;
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(d)
}
async fn admit(
    db: &Journal,
    b: &RuntimeBinding,
    previous: Option<&Record>,
    e: &signal_event::SignalEvent,
    position: u64,
    classified: Option<bool>,
) -> Result<Record> {
    let c = context();
    let i = input(b, e, &c)?;
    let decision = classified
        .map(|yes| -> Result<CurrentDecision> {
            Ok(CurrentDecision::new(
                b,
                &i,
                verification(b, &i, yes, &c)?,
                &c,
            )?)
        })
        .transpose()?;
    let p = journal::prepare_runtime(
        b,
        previous,
        previous.map_or(1, |r| r.checkpoint + 1),
        RuntimeAction::Admit {
            input: &i,
            position,
            decision: decision.as_ref(),
        },
        &epoch(b, position, &c)?,
        &c,
    )?;
    Ok(p.commit(db).await?)
}
#[tokio::test]
async fn runtime_real_journal_reopen_pending_retirement_and_original_outbox_are_exact() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let path = d.path().join("runtime.sqlite");
    let db = open(&b, &path).await?;
    let read = admit(&db, &b, None, &event(true)?, 1, Some(true)).await?;
    let connect = admit(&db, &b, Some(&read), &event(false)?, 2, Some(true)).await?;
    let seal_authority = context();
    let seal_epoch = epoch(&b, 2, &seal_authority)?;
    let seal =
        journal::prepare_runtime(&b, Some(&connect), 2, RuntimeAction::Seal, &seal_epoch, &c)?;
    let committed = seal.commit(&db).await?;
    assert_eq!(committed.checkpoint, 2);
    assert_eq!(committed.outbox.len(), 1);
    let effect = committed.outbox[0].clone();
    assert!(matches!(
        journal::prepare_runtime(
            &b,
            Some(&committed),
            2,
            RuntimeAction::Seal,
            &epoch(&b, 2, &c)?,
            &c
        ),
        Err(Error::Pending)
    ));
    // A fresh read can recover an original result after its old permit is
    // cancelled; it cannot authorize committing the old operation again.
    seal_authority.cancellation.cancel();
    assert_eq!(seal.commit(&db).await, Err(Error::Cancelled));
    assert_eq!(seal.reconcile(&db, context()).await?, committed);
    db.shutdown(context()).await?;
    let db = open(&b, &path).await?;
    let loaded = db.load(context()).await?.ok_or("record")?;
    assert_eq!(loaded, committed);
    let state = journal::recover_runtime(&b, &loaded, &context())?;
    assert_eq!(state.episodes()[0].status, Status::Match);
    assert_eq!(state.original_effect(effect.id), Some(effect.clone()));
    let retired = db.retire(loaded.revision, 1, context()).await?;
    assert!(retired.outbox.is_empty());
    assert_eq!(
        journal::recover_runtime(&b, &retired, &context())?.original_effect(effect.id),
        Some(effect)
    );
    let mut newer = config();
    newer.policy_authorities[0].policy_revision = "new-private-policy".into();
    assert!(journal::recover_runtime(&RuntimeBinding::new(newer, &c)?, &retired, &c).is_err());
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn runtime_prepared_retains_each_original_input_proof_epoch_and_caller_cancellation() -> Result
{
    for which in [
        "action_input",
        "decision_input",
        "decision_proof",
        "epoch",
        "caller",
    ] {
        let action_context = context();
        let decision_input_context = context();
        let proof_context = context();
        let epoch_context = context();
        let caller = context();
        let b = RuntimeBinding::new(config(), &caller)?;
        let e = event(true)?;
        let i = input(&b, &e, &action_context)?;
        let decision_input = input(&b, &e, &decision_input_context)?;
        let decision = CurrentDecision::new(
            &b,
            &decision_input,
            verification(&b, &decision_input, true, &proof_context)?,
            &proof_context,
        )?;
        let ep = epoch(&b, 1, &epoch_context)?;
        let p = journal::prepare_runtime(
            &b,
            None,
            1,
            RuntimeAction::Admit {
                input: &i,
                position: 1,
                decision: Some(&decision),
            },
            &ep,
            &caller,
        )?;
        let cancel = match which {
            "action_input" => &action_context,
            "decision_input" => &decision_input_context,
            "decision_proof" => &proof_context,
            "epoch" => &epoch_context,
            _ => &caller,
        };
        cancel.cancellation.cancel();
        let d = directory()?;
        let db = open(&b, &d.path().join("cancel.sqlite")).await?;
        assert_eq!(p.commit(&db).await, Err(Error::Cancelled), "{which}");
        assert_eq!(db.load(context()).await?, None);
        db.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn runtime_classification_input_and_proof_expiry_do_not_get_new_commit_budgets() -> Result {
    for which in ["input", "proof", "epoch"] {
        let mut original = context();
        let c = context();
        if which == "input" {
            original.deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        }
        let b = RuntimeBinding::new(config(), &c)?;
        let e = event(true)?;
        let i = input(&b, &e, &original)?;
        let mut proof = verification(&b, &i, true, &c)?;
        if which == "proof" {
            proof.verified_until = proof.now + chrono::TimeDelta::milliseconds(150);
        }
        let decision = CurrentDecision::new(&b, &i, proof, &c)?;
        let mut epoch_context = context();
        if which == "epoch" {
            epoch_context.deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        }
        let ep = epoch(&b, 1, &epoch_context)?;
        let p = journal::prepare_runtime(
            &b,
            None,
            1,
            RuntimeAction::Admit {
                input: &i,
                position: 1,
                decision: Some(&decision),
            },
            &ep,
            &c,
        )?;
        tokio::time::sleep(Duration::from_millis(175)).await;
        let d = directory()?;
        let db = open(&b, &d.path().join("expiry.sqlite")).await?;
        assert_eq!(p.commit(&db).await, Err(Error::Cancelled), "{which}");
        assert_eq!(db.load(context()).await?, None);
        db.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn runtime_duplicate_ignores_cancelled_replacement_decision_and_preserves_first_unknown()
-> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("duplicate.sqlite")).await?;
    let e = event(true)?;
    let first = admit(&db, &b, None, &e, 1, None).await?;
    let cancelled = context();
    let old = input(&b, &e, &cancelled)?;
    let decision = CurrentDecision::new(&b, &old, verification(&b, &old, true, &c)?, &c)?;
    cancelled.cancellation.cancel();
    let fresh = input(&b, &e, &c)?;
    let p = journal::prepare_runtime(
        &b,
        Some(&first),
        2,
        RuntimeAction::Admit {
            input: &fresh,
            position: 1,
            decision: Some(&decision),
        },
        &epoch(&b, 1, &c)?,
        &c,
    )?;
    assert!(matches!(
        p.applied(),
        Applied::Admission(Admission::Duplicate)
    ));
    let duplicate = p.commit(&db).await?;
    assert_eq!(duplicate.state, first.state);
    assert_eq!(duplicate.checkpoint, 2);
    let mut native = e.clone();
    native.id = Uuid::from_u128(100);
    let ni = input(&b, &native, &c)?;
    let p = journal::prepare_runtime(
        &b,
        Some(&duplicate),
        3,
        RuntimeAction::Admit {
            input: &ni,
            position: 2,
            decision: Some(&decision),
        },
        &epoch(&b, 2, &c)?,
        &c,
    )?;
    let alias = p.commit(&db).await?;
    let state: serde_json::Value = serde_json::from_slice(&alias.state)?;
    assert_eq!(
        state["observations"][0]["runtime"]["decision"],
        serde_json::Value::Null
    );
    assert_eq!(state["observations"].as_array().unwrap().len(), 1);
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn runtime_journal_refuses_altered_predecessor_foreign_generation_and_checkpoint_skips()
-> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("predecessor.sqlite")).await?;
    let e = event(true)?;
    let i = input(&b, &e, &c)?;
    let ep = epoch(&b, 1, &c)?;
    assert!(matches!(
        journal::prepare_runtime(
            &b,
            None,
            2,
            RuntimeAction::Admit {
                input: &i,
                position: 1,
                decision: None
            },
            &ep,
            &c
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        journal::prepare_runtime(&b, None, 1, RuntimeAction::Seal, &ep, &c),
        Err(Error::Conflict)
    ));
    let p = journal::prepare_runtime(
        &b,
        None,
        1,
        RuntimeAction::Admit {
            input: &i,
            position: 1,
            decision: None,
        },
        &ep,
        &c,
    )?;
    let expected = p.record().clone();
    let mut altered = expected.clone();
    altered.checkpoint = 0;
    db.commit(0, altered.clone(), context()).await?;
    assert_eq!(p.commit(&db).await, Err(Error::Conflict));
    assert_eq!(p.reconcile(&db, context()).await, Err(Error::Conflict));
    assert_eq!(db.load(context()).await?, Some(altered));
    let mut cfg = config();
    cfg.revision = "other-generation".into();
    let foreign = RuntimeBinding::new(cfg, &c)?;
    let other = open(&foreign, &d.path().join("other.sqlite")).await?;
    assert_eq!(p.commit(&other).await, Err(Error::Conflict));
    assert_eq!(other.load(context()).await?, None);
    assert!(journal::recover_runtime(&foreign, &expected, &c).is_err());
    let mut broken = expected.clone();
    broken.state = serde_json::to_vec(&serde_json::json!({"schema_version":1}))?;
    assert!(journal::recover_runtime(&b, &broken, &c).is_err());
    db.shutdown(context()).await?;
    other.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn runtime_original_cancellation_interrupts_a_real_blocked_predecessor_read() -> Result {
    use std::future::Future;
    for proof_token in [true, false] {
        let c = context();
        let original = context();
        let proof_context = context();
        let b = RuntimeBinding::new(config(), &c)?;
        let e = event(true)?;
        let i = input(&b, &e, &c)?;
        let decision_input = input(&b, &e, &original)?;
        let decision = CurrentDecision::new(
            &b,
            &decision_input,
            verification(&b, &decision_input, true, &proof_context)?,
            &proof_context,
        )?;
        let p = journal::prepare_runtime(
            &b,
            None,
            1,
            RuntimeAction::Admit {
                input: &i,
                position: 1,
                decision: Some(&decision),
            },
            &epoch(&b, 1, &c)?,
            &c,
        )?;
        let d = directory()?;
        let path = d.path().join("blocked.sqlite");
        let db = open(&b, &path).await?;
        // DELETE journal mode: this owned exclusive transaction prevents a
        // successful predecessor read until the test explicitly releases it.
        let blocker = rusqlite::Connection::open(&path)?;
        blocker.execute_batch("BEGIN EXCLUSIVE")?;
        let mut commit = Box::pin(p.commit(&db));
        let first =
            std::future::poll_fn(|cx| std::task::Poll::Ready(commit.as_mut().poll(cx))).await;
        assert!(first.is_pending());
        assert_eq!(db.metrics().0, 1);
        if proof_token {
            proof_context.cancellation.cancel();
        } else {
            original.cancellation.cancel();
        }
        assert_eq!(commit.await, Err(Error::Cancelled));
        blocker.execute_batch("ROLLBACK")?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while db.metrics().0 != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(db.load(context()).await?, None);
        db.shutdown(context()).await?;
    }
    Ok(())
}

fn durable(path: &Path, bytes: &[u8]) -> Result {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::File::open(path.parent().ok_or("parent")?)?.sync_all()?;
    Ok(())
}
#[tokio::test]
#[ignore = "owned journal crash child only"]
async fn runtime_journal_crash_child() -> Result {
    let dir = std::path::PathBuf::from(
        std::env::var_os("SIGNAL_D14_JOURNAL_CHILD").ok_or("owned child directory")?,
    );
    let phase = std::env::var("SIGNAL_D14_JOURNAL_PHASE")?;
    assert!(["prepared", "committed", "published"].contains(&phase.as_str()));
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let db = open(&b, &dir.join("runtime.sqlite")).await?;
    let r = admit(&db, &b, None, &event(true)?, 1, Some(true)).await?;
    let r = admit(&db, &b, Some(&r), &event(false)?, 2, Some(true)).await?;
    let p = journal::prepare_runtime(&b, Some(&r), 2, RuntimeAction::Seal, &epoch(&b, 2, &c)?, &c)?;
    durable(&dir.join("prepared.json"), &serde_json::to_vec(p.record())?)?;
    if phase != "prepared" {
        let record = p.commit(&db).await?;
        if phase == "published" {
            durable(
                &dir.join("published-original.json"),
                &record.outbox[0].bytes,
            )?;
        }
    }
    durable(&dir.join("ready"), phase.as_bytes())?;
    std::future::pending::<()>().await;
    println!("D14-SOURCE-ACK");
    Ok(())
}
struct OwnedRuntimeChild(std::process::Child);
impl Drop for OwnedRuntimeChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[tokio::test]
#[ignore = "requires an explicit owned target evidence directory"]
async fn runtime_journal_process_crash() -> Result {
    use std::{
        fs,
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()?;
    let output = std::path::PathBuf::from(
        std::env::var_os("SIGNAL_D14_JOURNAL_OUTPUT").ok_or("owned output")?,
    )
    .canonicalize()?;
    assert!(output.starts_with(root));
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let mut cases = Vec::new();
    for phase in ["prepared", "committed", "published"] {
        let dir = output.join(phase);
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let log = fs::File::create_new(dir.join("child.log"))?;
        let mut child = OwnedRuntimeChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "runtime_journal_crash_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("SIGNAL_D14_JOURNAL_CHILD", &dir)
                .env("SIGNAL_D14_JOURNAL_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let pid = child.0.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if fs::read(dir.join("ready")).ok().as_deref() == Some(phase.as_bytes()) {
                break;
            }
            if child.0.try_wait()?.is_some() {
                return Err("child exited before durable witness".into());
            }
            if std::time::Instant::now() >= deadline {
                return Err("owned child witness deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(child.0.try_wait()?.is_none());
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        assert!(fs::metadata(dir.join("child.log"))?.len() < 16384);
        assert!(!fs::read_to_string(dir.join("child.log"))?.contains("D14-SOURCE-ACK"));
        let expected: Record = serde_json::from_slice(&fs::read(dir.join("prepared.json"))?)?;
        let db = open(&b, &dir.join("runtime.sqlite")).await?;
        let loaded = db.load(context()).await?.ok_or("reopened record")?;
        let committed = if phase == "prepared" {
            assert_eq!(loaded.revision, 2);
            assert_eq!(loaded.checkpoint, 2);
            assert!(loaded.outbox.is_empty());
            assert!(
                journal::recover_runtime(&b, &loaded, &context())?
                    .episodes()
                    .is_empty()
            );
            let p = journal::prepare_runtime(
                &b,
                Some(&loaded),
                2,
                RuntimeAction::Seal,
                &epoch(&b, 2, &context())?,
                &context(),
            )?;
            assert_eq!(p.record(), &expected);
            p.commit(&db).await?
        } else {
            assert_eq!(loaded, expected);
            loaded
        };
        let effect = committed.outbox[0].clone();
        assert_eq!(
            journal::recover_runtime(&b, &committed, &context())?.episodes()[0].status,
            Status::Match
        );
        if phase == "published" {
            assert_eq!(fs::read(dir.join("published-original.json"))?, effect.bytes);
        } else {
            durable(&dir.join("published-original.json"), &effect.bytes)?;
        }
        let retired = db.retire(committed.revision, 1, context()).await?;
        // A distinct intervening operation and subsequent native replay consume
        // delivery progress without regenerating a published original effect.
        let mut intervening = event(true)?;
        intervening.id = Uuid::from_u128(55);
        intervening.attributes["runtime_metadata"]["native"]["sequence"] = serde_json::json!(4);
        intervening.attributes["runtime_metadata"]["process"]["pid"] = serde_json::json!(101);
        let advanced = admit(&db, &b, Some(&retired), &intervening, 3, None).await?;
        let mut alias = event(true)?;
        alias.id = Uuid::from_u128(999);
        let after = admit(&db, &b, Some(&advanced), &alias, 4, None).await?;
        assert_eq!(after.checkpoint, 4);
        assert!(after.outbox.is_empty());
        assert_eq!(
            journal::recover_runtime(&b, &after, &context())?.original_effect(effect.id),
            Some(effect.clone())
        );
        let mut newer = config();
        newer.revision = "new-runtime-policy".into();
        let changed = RuntimeBinding::new(newer, &context())?;
        assert!(journal::recover_runtime(&changed, &after, &context()).is_err());
        db.shutdown(context()).await?;
        let db = open(&b, &dir.join("runtime.sqlite")).await?;
        assert_eq!(db.load(context()).await?, Some(after));
        db.shutdown(context()).await?;
        cases.push(serde_json::json!({"phase":phase,"pid":pid,"actual_sigkill_signal":9,"source_ack_withheld":true,"original_outbox_exact":true,"published_before_retirement":true,"alias_replay_preserved_effect":true,"different_enrollment_refused":true,"second_reopen_exact":true}));
    }
    durable(
        &output.join("process-report.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version":1,"status":"passed_local","actual_sigkill":3,"source_and_policy_authority":"synthetic","metadata_inputs":"synthetic selected runtime projections","owned_process_cleanup":true,"cases":cases}),
        )?,
    )?;
    Ok(())
}

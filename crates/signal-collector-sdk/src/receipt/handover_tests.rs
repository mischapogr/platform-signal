use super::*;
fn successor() -> Uuid {
    Uuid::from_u128(0x40000000000040008000000000000002)
}
fn grant(b: ReceiptBinding, p: &ReceiptProgress) -> Result<ReceiptRecoveryGrant, ReceiptError> {
    ReceiptRecoveryGrant::from_trusted_checkpoint(
        b,
        p.checksum(),
        "independent-checkpoint-1".into(),
    )
}
async fn admitted(
    cfg: ReceiptConfig,
) -> Result<(ReceiptStore, ReceiptBinding), Box<dyn std::error::Error>> {
    let (raw, b) = vector("prepared")?;
    let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
    s.publish(raw, b.clone(), ctx()).await?;
    Ok((s, b))
}
fn admitted_response(
    r: &ReceiptReplay,
    partial: bool,
) -> Result<ReceiptAttempt, Box<dyn std::error::Error>> {
    let count = r.remaining();
    let accepted = if partial { 1 } else { count };
    let ids = (0..accepted)
        .map(|i| {
            serde_json::from_slice::<signal_event::SignalEvent>(r.suffix_bytes(i).ok_or("suffix")?)
                .map(|e| e.id)
                .map_err(Into::into)
        })
        .collect::<Result<Vec<Uuid>, Box<dyn std::error::Error>>>()?;
    Ok(ReceiptAttempt::Response {
        status: if partial { 429 } else { 202 },
        body: serde_json::to_vec(
            &json!({"schema_version":1,"accepted":accepted,"rejected":count-accepted,"event_ids":ids,"error":if partial {json!({"code":"full","message":"full","index":accepted})}else{Value::Null}}),
        )?,
    })
}
#[tokio::test]
async fn handover_before_partial_and_completed_sends_preserves_pins_and_fences_old_owner()
-> TestResult {
    for prefix in 0..=2 {
        let d = root()?;
        let (s, b) = admitted(config(&d)?).await?;
        if prefix > 0 {
            let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
            s.advance(
                b.clone(),
                r.progress.clone(),
                2,
                admitted_response(&r, prefix == 1)?,
                ctx(),
            )
            .await?;
        }
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let before = r.receipt.bytes.clone();
        let prior = r.progress.checksum();
        let revision = r.progress.revision();
        let auth = grant(b.clone(), &r.progress)?;
        s.transfer_owner(b.clone(), r.progress, auth, successor(), ctx())
            .await?;
        assert!(matches!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
            Err(ReceiptError::Owner)
        ));
        let s = ReceiptStore::open(config(&d)?, successor(), 2, ctx()).await?;
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        assert_eq!(r.receipt.bytes, before);
        assert_eq!(r.progress.verified_prefix(), prefix);
        assert_eq!(r.progress.revision(), revision + 1);
        assert_eq!(r.progress.value["previous_sha256"], format::hex(&prior));
        assert_eq!(r.progress.value["attempt"]["kind"], "none");
        assert_eq!(r.progress.value["owner_generation"], 2);
        assert_eq!(r.progress.value["ack"]["state"], "not_requested");
        if prefix < 2 {
            let count = r.remaining() as u32;
            s.advance(
                b,
                r.progress.clone(),
                count,
                admitted_response(&r, false)?,
                ctx(),
            )
            .await?;
        }
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn stale_independent_checkpoint_and_binding_are_denied_before_mutation() -> TestResult {
    for denied_binding in [false, true] {
        let d = root()?;
        let (s, b) = admitted(config(&d)?).await?;
        let first = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let mut grant_binding = b.clone();
        if denied_binding {
            grant_binding.0["collector_id"] = "other".into();
        }
        let auth = grant(grant_binding, &first.progress)?;
        let next = s
            .advance(
                b.clone(),
                first.progress,
                2,
                ReceiptAttempt::Uncertain,
                ctx(),
            )
            .await?;
        let before = fs::read(d.path().join("control"))?;
        let result = s
            .transfer_owner(b.clone(), next, auth, successor(), ctx())
            .await;
        if denied_binding {
            assert!(matches!(result, Err(ReceiptError::Scope)))
        } else {
            assert!(matches!(result, Err(ReceiptError::History)))
        }
        assert_eq!(fs::read(d.path().join("control"))?, before);
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn independently_current_checkpoint_denies_older_consistent_restored_root() -> TestResult {
    let d = root()?;
    let (s, b) = admitted(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let older = fs::read(d.path().join("control"))?;
    let current = s
        .advance(b.clone(), r.progress, 2, ReceiptAttempt::Uncertain, ctx())
        .await?;
    // Simulate a trusted current checkpoint surviving outside copied root state.
    let auth = grant(b.clone(), &current)?;
    s.close(ctx()).await?;
    fs::write(d.path().join("control"), &older)?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    assert!(matches!(
        s.transfer_owner(b, r.progress, auth, successor(), ctx())
            .await,
        Err(ReceiptError::History)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, older);
    Ok(())
}
#[tokio::test]
async fn stale_snapshot_nil_same_owner_and_generation_overflow_reject() -> TestResult {
    for mode in ["stale", "nil", "same", "overflow"] {
        let d = root()?;
        let generation = if mode == "overflow" { u64::MAX } else { 1 };
        let (raw, b) = vector("prepared")?;
        let s = ReceiptStore::open(config(&d)?, owner(), generation, ctx()).await?;
        s.publish(raw, b.clone(), ctx()).await?;
        let first = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        if mode == "stale" {
            s.advance(
                b.clone(),
                first.progress.clone(),
                2,
                ReceiptAttempt::Uncertain,
                ctx(),
            )
            .await?;
        }
        let before = fs::read(d.path().join("control"))?;
        let auth = grant(b.clone(), &first.progress)?;
        let new_owner = match mode {
            "nil" => Uuid::nil(),
            "same" => owner(),
            _ => successor(),
        };
        let result = s
            .transfer_owner(b, first.progress, auth, new_owner, ctx())
            .await;
        match mode {
            "stale" => assert!(matches!(result, Err(ReceiptError::StaleProgress))),
            "overflow" => assert!(matches!(result, Err(ReceiptError::Owner))),
            _ => assert!(matches!(result, Err(ReceiptError::Configuration))),
        }
        assert_eq!(fs::read(d.path().join("control"))?, before);
        assert!(!d.path().join("control.next").exists());
    }
    Ok(())
}
#[tokio::test]
async fn handover_faults_close_worker_and_reopen_only_settled_control() -> TestResult {
    for stage in [
        Stage::ProgressTempSynced,
        Stage::ProgressRenamed,
        Stage::ProgressDirectorySynced,
    ] {
        let d = root()?;
        let mut cfg = config(&d)?;
        cfg.hook = Some(Arc::new(move |s| {
            if s == stage {
                Err(ReceiptError::Io(std::io::ErrorKind::Other))
            } else {
                Ok(())
            }
        }));
        let (s, b) = admitted(cfg).await?;
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let auth = grant(b.clone(), &r.progress)?;
        assert!(
            s.transfer_owner(b.clone(), r.progress, auth, successor(), ctx())
                .await
                .is_err()
        );
        let reopened = ReceiptStore::open(config(&d)?, successor(), 2, ctx()).await;
        if stage == Stage::ProgressTempSynced {
            assert!(matches!(reopened, Err(ReceiptError::Uncertain)))
        } else {
            let s = reopened?;
            let r = s.replay(b, ctx()).await?.ok_or("r")?;
            assert_eq!(r.progress.verified_prefix(), 0);
            assert_eq!(r.progress.revision(), 1);
            s.close(ctx()).await?;
        }
    }
    Ok(())
}
#[test]
#[ignore = "subprocess-only handover crash helper"]
fn handover_crash_child() -> TestResult {
    let Some(path) = std::env::var_os("SIGNAL_HANDOVER_TEST_ROOT") else {
        return Ok(());
    };
    let stage = std::env::var("SIGNAL_HANDOVER_TEST_STAGE")?;
    let mut cfg = ReceiptConfig::new(path.into(), MIN_QUOTA_BYTES)?;
    cfg.hook = Some(Arc::new(move |s| {
        if format!("{s:?}") == stage {
            std::process::exit(75)
        }
        Ok(())
    }));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (s, b) = admitted(cfg).await?;
            let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
            let auth = grant(b.clone(), &r.progress)?;
            s.transfer_owner(b, r.progress, auth, successor(), ctx())
                .await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    Ok(())
}
#[test]
fn process_loss_at_handover_milestones_preserves_payload_and_owner_fence() -> TestResult {
    for stage in [
        Stage::ProgressTempSynced,
        Stage::ProgressRenamed,
        Stage::ProgressDirectorySynced,
    ] {
        let d = root()?;
        let result = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "receipt::tests::handover_tests::handover_crash_child",
                "--ignored",
            ])
            .env("SIGNAL_HANDOVER_TEST_ROOT", d.path())
            .env("SIGNAL_HANDOVER_TEST_STAGE", format!("{stage:?}"))
            .output()?;
        assert_eq!(result.status.code(), Some(75));
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let opened = ReceiptStore::open(config(&d)?, successor(), 2, ctx()).await;
                if stage == Stage::ProgressTempSynced {
                    assert!(matches!(opened, Err(ReceiptError::Uncertain)))
                } else {
                    let s = opened?;
                    let (raw, b) = vector("prepared")?;
                    let r = s.replay(b, ctx()).await?.ok_or("r")?;
                    assert_eq!(r.receipt.bytes, raw);
                    s.close(ctx()).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
    }
    Ok(())
}

#[tokio::test]
async fn timed_out_or_dropped_handover_keeps_lock_until_physical_exit() -> TestResult {
    for dropped in [false, true] {
        let d = root()?;
        let mut cfg = config(&d)?;
        let (notify, entered) = tokio::sync::oneshot::channel();
        let notify = std::sync::Mutex::new(Some(notify));
        let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
        let gate = std::sync::Mutex::new(gate);
        cfg.hook = Some(Arc::new(move |stage| {
            if stage == Stage::ProgressRenamed
                && let Some(n) = notify.lock().map_err(|_| ReceiptError::Closed)?.take()
            {
                let _ = n.send(());
                gate.lock()
                    .map_err(|_| ReceiptError::Closed)?
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| ReceiptError::Closed)?;
            }
            Ok(())
        }));
        let (s, b) = admitted(cfg).await?;
        let metrics = s.test_metrics();
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let auth = grant(b.clone(), &r.progress)?;
        let budget = if dropped {
            ctx()
        } else {
            ExtensionContext::new(CancellationToken::new(), Duration::from_millis(400))?
        };
        let binding = b.clone();
        let task = tokio::spawn(async move {
            s.transfer_owner(binding, r.progress, auth, successor(), budget)
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered).await??;
        if dropped {
            task.abort();
            let _ = task.await;
        } else {
            assert!(matches!(task.await?, Err(ReceiptError::Timeout)));
        }
        assert!(matches!(
            ReceiptStore::open(config(&d)?, successor(), 2, ctx()).await,
            Err(ReceiptError::Locked)
        ));
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !metrics.stopped.load(Ordering::Acquire) {
                tokio::task::yield_now().await
            }
        })
        .await?;
        assert_eq!(metrics.snapshot().queue_depth, 0);
        assert_eq!(metrics.snapshot().queue_capacity, 1);
        let s = ReceiptStore::open(config(&d)?, successor(), 2, ctx()).await?;
        let r = s.replay(b, ctx()).await?.ok_or("r")?;
        assert_eq!(r.progress.revision(), 1);
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn cancelled_handover_before_admission_closes_without_changing_owner() -> TestResult {
    let d = root()?;
    let (s, b) = admitted(config(&d)?).await?;
    let metrics = s.test_metrics();
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let auth = grant(b.clone(), &r.progress)?;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ExtensionContext::new(cancellation, Duration::from_secs(5))?;
    assert!(matches!(
        s.transfer_owner(b, r.progress, auth, successor(), cancelled)
            .await,
        Err(ReceiptError::Cancelled)
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !metrics.stopped.load(Ordering::Acquire) {
            tokio::task::yield_now().await
        }
    })
    .await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    s.close(ctx()).await?;
    Ok(())
}
#[test]
fn trusted_checkpoint_constructor_bounds_authority_identifier() -> TestResult {
    let (_, b) = vector("prepared")?;
    assert!(matches!(
        ReceiptRecoveryGrant::from_trusted_checkpoint(b.clone(), [0; 32], String::new()),
        Err(ReceiptError::Configuration)
    ));
    assert!(matches!(
        ReceiptRecoveryGrant::from_trusted_checkpoint(b, [0; 32], "a".repeat(129)),
        Err(ReceiptError::Configuration)
    ));
    Ok(())
}

#[tokio::test]
async fn reconciled_open_accepts_exact_independent_checkpoint_and_retains_process_lock()
-> TestResult {
    let d = root()?;
    let (s, b) = admitted(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let p = s
        .advance(b.clone(), r.progress, 2, ReceiptAttempt::Uncertain, ctx())
        .await?;
    s.close(ctx()).await?;
    let s = ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx())
        .await?;
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    let r = s.replay(b, ctx()).await?.ok_or("r")?;
    assert_eq!(r.progress.checksum(), p.checksum());
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn reconciled_open_denies_older_consistent_restore_before_exposing_store() -> TestResult {
    let d = root()?;
    let (s, b) = admitted(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let old = fs::read(d.path().join("control"))?;
    let current = s
        .advance(b.clone(), r.progress, 2, ReceiptAttempt::Uncertain, ctx())
        .await?;
    s.close(ctx()).await?;
    fs::write(d.path().join("control"), &old)?;
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b, &current)?, ctx()).await,
        Err(ReceiptError::History)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, old);
    Ok(())
}
#[tokio::test]
async fn reconciled_open_denies_foreign_binding_and_empty_or_missing_recovery_state() -> TestResult
{
    let d = root()?;
    let (s, b) = admitted(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    s.close(ctx()).await?;
    let mut denied = b.clone();
    denied.0["source_id"] = "other".into();
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(denied, &r.progress)?, ctx())
            .await,
        Err(ReceiptError::Scope)
    ));
    let empty = root()?;
    assert!(matches!(
        ReceiptStore::open_reconciled(
            config(&empty)?,
            owner(),
            1,
            grant(b.clone(), &r.progress)?,
            ctx()
        )
        .await,
        Err(ReceiptError::History)
    ));
    fs::remove_file(d.path().join("control"))?;
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b, &r.progress)?, ctx()).await,
        Err(ReceiptError::Uncertain)
    ));
    Ok(())
}

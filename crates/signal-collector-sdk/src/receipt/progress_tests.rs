use super::*;
fn response(r: &ReceiptReplay, count: usize, accepted: usize) -> TestResultBody {
    let ids = (0..accepted)
        .map(|i| {
            let e: signal_event::SignalEvent =
                serde_json::from_slice(r.suffix_bytes(i).ok_or("suffix")?)?;
            Ok(e.id)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let complete = accepted == count;
    Ok(ReceiptAttempt::Response {
        status: if complete { 202 } else { 429 },
        body: serde_json::to_vec(&json!({
            "schema_version":1,"accepted":accepted,"rejected":count-accepted,"event_ids":ids,
            "error":if complete {Value::Null} else {json!({"code":"full","message":"full","index":accepted})}
        }))?,
    })
}
type TestResultBody = Result<ReceiptAttempt, Box<dyn std::error::Error>>;
async fn prepared(
    cfg: ReceiptConfig,
) -> Result<(ReceiptStore, ReceiptBinding), Box<dyn std::error::Error>> {
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
    s.publish(bytes, b.clone(), ctx()).await?;
    Ok((s, b))
}
#[tokio::test]
async fn partial_prefix_replays_exact_suffix_through_reopen_and_completion() -> TestResult {
    let d = root()?;
    let (s, b) = prepared(config(&d)?).await?;
    let original = fs::read(d.path().join(format!(
        "{}.src",
        s.inspect(b.clone(), ctx()).await?.ok_or("r")?.info.id
    )))?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("replay")?;
    assert_eq!(r.remaining(), 2);
    let suffix = r.suffix_bytes(1).ok_or("suffix")?.to_vec();
    let old_checksum = r.progress.checksum();
    let next = s
        .advance(b.clone(), r.progress.clone(), 2, response(&r, 2, 1)?, ctx())
        .await?;
    assert_eq!(next.verified_prefix(), 1);
    assert_eq!(next.revision(), 1);
    assert_eq!(next.value["previous_sha256"], format::hex(&old_checksum));
    let partial = fixture()?["progress_vectors"]
        .as_array()
        .ok_or("vectors")?
        .iter()
        .find(|v| v["id"] == "partial")
        .ok_or("partial")?["progress"]["prefix_sha256"]
        .clone();
    assert_eq!(next.value["prefix_sha256"], partial);
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("replay")?;
    assert_eq!(r.remaining(), 1);
    assert_eq!(r.suffix_bytes(0).ok_or("suffix")?, suffix);
    let next = s
        .advance(b.clone(), r.progress.clone(), 1, response(&r, 1, 1)?, ctx())
        .await?;
    assert_eq!(next.verified_prefix(), 2);
    assert_eq!(next.revision(), 2);
    let r = s.replay(b.clone(), ctx()).await?.ok_or("replay")?;
    assert_eq!(r.remaining(), 0);
    assert!(r.suffix_bytes(0).is_none());
    assert!(r.suffix_bytes(usize::MAX).is_none());
    assert!(matches!(
        s.advance(b, r.progress, 1, ReceiptAttempt::Uncertain, ctx())
            .await,
        Err(ReceiptError::Invalid(_))
    ));
    assert_eq!(
        fs::read(d.path().join(format!("{}.src", r.receipt.info.id)))?,
        original
    );
    assert_eq!(s.metrics().progress_updates, 1);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn uncertain_and_permanent_attempts_never_advance() -> TestResult {
    let d = root()?;
    let (s, b) = prepared(config(&d)?).await?;
    for (index, outcome) in [ReceiptAttempt::Uncertain, ReceiptAttempt::Permanent]
        .into_iter()
        .enumerate()
    {
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let p = s.advance(b.clone(), r.progress, 2, outcome, ctx()).await?;
        assert_eq!(p.verified_prefix(), 0);
        assert_eq!(p.revision(), index as u64 + 1);
        assert!(p.value["attempt"]["response_sha256"].is_null());
    }
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert_eq!(s.replay(b, ctx()).await?.ok_or("r")?.remaining(), 2);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn stale_snapshot_and_full_binding_deny_before_control_mutation() -> TestResult {
    let d = root()?;
    let (s, b) = prepared(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let p = s
        .advance(
            b.clone(),
            r.progress.clone(),
            2,
            ReceiptAttempt::Uncertain,
            ctx(),
        )
        .await?;
    let before = fs::read(d.path().join("control"))?;
    assert!(matches!(
        s.advance(b.clone(), r.progress, 2, ReceiptAttempt::Uncertain, ctx())
            .await,
        Err(ReceiptError::StaleProgress)
    ));
    let mut denied = b.clone();
    denied.0["authority_revision"] = "revoked".into();
    assert!(matches!(
        s.advance(denied.clone(), p, 2, ReceiptAttempt::Uncertain, ctx())
            .await,
        Err(ReceiptError::Scope)
    ));
    assert!(matches!(
        s.replay(denied, ctx()).await,
        Err(ReceiptError::Scope)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, before);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn forged_response_ids_counts_status_schema_and_duplicate_keys_reject() -> TestResult {
    let d = root()?;
    let (s, b) = prepared(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let ReceiptAttempt::Response { status, body } = response(&r, 2, 1)? else {
        return Err("response".into());
    };
    let good: Value = serde_json::from_slice(&body)?;
    let mut cases = Vec::new();
    for (key, v) in [
        ("accepted", json!(2)),
        ("schema_version", json!(2)),
        ("rejected", json!(0)),
        ("event_ids", json!([Uuid::new_v4()])),
    ] {
        let mut bad = good.clone();
        bad[key] = v;
        cases.push((status, serde_json::to_vec(&bad)?));
    }
    let mut bad = good.clone();
    bad["error"]["index"] = json!(0);
    cases.push((status, serde_json::to_vec(&bad)?));
    cases.extend([
        (202, body.clone()),
        (500, body.clone()),
        (429, b"{".to_vec()),
        (429, vec![b' '; 65537]),
        (429, b"{\"accepted\":0,\"accepted\":1}".to_vec()),
    ]);
    let before = fs::read(d.path().join("control"))?;
    for (status, body) in cases {
        assert!(matches!(
            s.advance(
                b.clone(),
                r.progress.clone(),
                2,
                ReceiptAttempt::Response { status, body },
                ctx()
            )
            .await,
            Err(ReceiptError::InvalidResponse)
        ));
        assert_eq!(fs::read(d.path().join("control"))?, before);
    }
    assert_eq!(s.metrics().progress_updates, 0);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn zero_admission_retry_is_verified_without_prefix_increase() -> TestResult {
    let d = root()?;
    let (s, b) = prepared(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let p = s
        .advance(b, r.progress.clone(), 2, response(&r, 2, 0)?, ctx())
        .await?;
    assert_eq!(p.verified_prefix(), 0);
    assert_eq!(p.value["attempt"]["kind"], "verified");
    assert!(!p.value["attempt"]["response_sha256"].is_null());
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn noninitial_corruption_and_pin_changes_fail_closed_on_reopen() -> TestResult {
    for key in [
        "prefix_sha256",
        "receipt_id",
        "previous_sha256",
        "binding",
        "retention",
        "unknown",
    ] {
        let d = root()?;
        let (s, b) = prepared(config(&d)?).await?;
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let p = s
            .advance(b, r.progress, 2, ReceiptAttempt::Uncertain, ctx())
            .await?;
        s.close(ctx()).await?;
        let mut v = p.value;
        match key {
            "prefix_sha256" => v[key] = "0".repeat(64).into(),
            "receipt_id" => v[key] = Uuid::new_v4().to_string().into(),
            "previous_sha256" => v[key] = Value::Null,
            "binding" => v[key]["authority_revision"] = "other".into(),
            "retention" => v[key]["recovery_budget_seconds"] = json!(1),
            _ => v[key] = json!(1),
        }
        fs::write(d.path().join("control"), progress::encode(&v)?)?;
        assert!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx())
                .await
                .is_err(),
            "{key}"
        );
    }
    Ok(())
}
#[tokio::test]
async fn update_faults_poison_worker_and_reopen_committed_or_uncertain_state() -> TestResult {
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
        let (s, b) = prepared(cfg).await?;
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let before = fs::read(d.path().join("control"))?;
        assert!(
            s.advance(b.clone(), r.progress.clone(), 2, response(&r, 2, 1)?, ctx())
                .await
                .is_err()
        );
        assert!(matches!(
            s.replay(b.clone(), ctx()).await,
            Err(ReceiptError::Uncertain)
        ));
        s.close(ctx()).await?;
        let opened = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await;
        if stage == Stage::ProgressTempSynced {
            assert!(matches!(opened, Err(ReceiptError::Uncertain)));
            assert_eq!(fs::read(d.path().join("control"))?, before);
        } else {
            let s = opened?;
            let r = s.replay(b, ctx()).await?.ok_or("r")?;
            assert_eq!(r.progress.verified_prefix(), 1);
            s.close(ctx()).await?;
        }
    }
    Ok(())
}
#[test]
#[ignore = "subprocess-only crash helper"]
fn progress_crash_child() -> TestResult {
    let Some(path) = std::env::var_os("SIGNAL_PROGRESS_TEST_ROOT") else {
        return Ok(());
    };
    let stage = std::env::var("SIGNAL_PROGRESS_TEST_STAGE")?;
    let mut cfg = ReceiptConfig::new(path.into(), MIN_QUOTA_BYTES)?;
    cfg.hook = Some(Arc::new(move |s| {
        if format!("{s:?}") == stage {
            std::process::exit(74)
        }
        Ok(())
    }));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (s, b) = prepared(cfg).await?;
            let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
            s.advance(b, r.progress.clone(), 2, response(&r, 2, 1)?, ctx())
                .await?;
            s.close(ctx()).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    Ok(())
}
#[test]
fn process_loss_at_progress_milestones_preserves_exact_preparation() -> TestResult {
    for stage in [
        Stage::ProgressTempSynced,
        Stage::ProgressRenamed,
        Stage::ProgressDirectorySynced,
    ] {
        let d = root()?;
        let result = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "receipt::tests::progress_tests::progress_crash_child",
                "--ignored",
            ])
            .env("SIGNAL_PROGRESS_TEST_ROOT", d.path())
            .env("SIGNAL_PROGRESS_TEST_STAGE", format!("{stage:?}"))
            .output()?;
        assert_eq!(result.status.code(), Some(74));
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (raw, b) = vector("prepared")?;
                let r = format::decode(raw.clone(), &ctx())?;
                assert_eq!(fs::read(d.path().join(format!("{}.src", r.info.id)))?, raw);
                let opened = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await;
                if stage == Stage::ProgressTempSynced {
                    assert!(matches!(opened, Err(ReceiptError::Uncertain)))
                } else {
                    let s = opened?;
                    assert_eq!(s.replay(b, ctx()).await?.ok_or("r")?.remaining(), 1);
                    s.close(ctx()).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
    }
    Ok(())
}

#[tokio::test]
async fn update_timeout_keeps_physical_lock_and_queued_cancel_never_mutates() -> TestResult {
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
    let (s, b) = prepared(cfg).await?;
    let s = Arc::new(s);
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let outcome = response(&r, 2, 1)?;
    let short = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(400))?;
    let worker = s.clone();
    let binding = b.clone();
    let update =
        tokio::spawn(async move { worker.advance(binding, r.progress, 2, outcome, short).await });
    tokio::time::timeout(Duration::from_secs(2), entered).await??;
    let cancellation = CancellationToken::new();
    let queued_ctx = ExtensionContext::new(cancellation.clone(), Duration::from_secs(5))?;
    let worker = s.clone();
    let binding = b.clone();
    let queued = tokio::spawn(async move { worker.replay(binding, queued_ctx).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while s.metrics().queue_depth != 1 {
            tokio::task::yield_now().await
        }
    })
    .await?;
    assert!(matches!(
        s.replay(b.clone(), ctx()).await,
        Err(ReceiptError::Busy)
    ));
    cancellation.cancel();
    assert!(matches!(queued.await?, Err(ReceiptError::Cancelled)));
    assert!(matches!(update.await?, Err(ReceiptError::Timeout)));
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    assert_eq!(s.metrics().queue_capacity, 1);
    assert_eq!(s.metrics().queue_depth, 1);
    release.send(())?;
    let s = Arc::try_unwrap(s).map_err(|_| "shared handle")?;
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let r = s.replay(b, ctx()).await?.ok_or("r")?;
    assert_eq!(r.progress.revision(), 1);
    assert_eq!(r.progress.verified_prefix(), 1);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn lost_update_caller_after_commit_keeps_progress_and_immutable_payload() -> TestResult {
    let d = root()?;
    let mut cfg = config(&d)?;
    let (notify, entered) = tokio::sync::oneshot::channel();
    let notify = std::sync::Mutex::new(Some(notify));
    let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
    let gate = std::sync::Mutex::new(gate);
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::ProgressDirectorySynced
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
    let (s, b) = prepared(cfg).await?;
    let s = Arc::new(s);
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let body = r.suffix_bytes(1).ok_or("suffix")?.to_vec();
    let outcome = response(&r, 2, 1)?;
    let worker = s.clone();
    let binding = b.clone();
    let task =
        tokio::spawn(async move { worker.advance(binding, r.progress, 2, outcome, ctx()).await });
    tokio::time::timeout(Duration::from_secs(2), entered).await??;
    task.abort();
    let _ = task.await;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    release.send(())?;
    let r = s.replay(b, ctx()).await?.ok_or("r")?;
    assert_eq!(r.remaining(), 1);
    assert_eq!(r.suffix_bytes(0).ok_or("suffix")?, body);
    assert_eq!(s.metrics().progress_updates, 1);
    assert_eq!(s.metrics().unobserved_results, 1);
    let s = Arc::try_unwrap(s).map_err(|_| "shared handle")?;
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn revision_overflow_and_empty_quarantine_never_create_progress_files() -> TestResult {
    let d = root()?;
    let (s, b) = prepared(config(&d)?).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let p = s
        .advance(b.clone(), r.progress, 2, ReceiptAttempt::Uncertain, ctx())
        .await?;
    s.close(ctx()).await?;
    let mut v = p.value;
    v["revision"] = json!(u64::MAX);
    fs::write(d.path().join("control"), progress::encode(&v)?)?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    assert!(matches!(
        s.advance(b, r.progress, 2, ReceiptAttempt::Uncertain, ctx())
            .await,
        Err(ReceiptError::Invalid("revision overflow"))
    ));
    assert!(!d.path().join("control.next").exists());
    s.close(ctx()).await?;
    let d = root()?;
    let (bytes, b) = vector("object-quarantine")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    s.publish(bytes, b.clone(), ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    assert_eq!(r.remaining(), 0);
    assert!(matches!(
        s.advance(b, r.progress, 1, ReceiptAttempt::Uncertain, ctx())
            .await,
        Err(ReceiptError::Invalid("send range"))
    ));
    assert!(!d.path().join("control.next").exists());
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn first_progress_must_follow_exact_initial_zero_prefix() -> TestResult {
    for wrong_start in [false, true] {
        let d = root()?;
        let (s, b) = prepared(config(&d)?).await?;
        let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
        let p = s
            .advance(b, r.progress, 2, ReceiptAttempt::Uncertain, ctx())
            .await?;
        let mut value = p.value;
        if wrong_start {
            value["verified_prefix"] = json!(1);
            value["prefix_sha256"] = format::hex(&progress::prefix_hash(&r.receipt, 1)?).into();
            value["attempt"]["start"] = json!(1);
            value["attempt"]["count"] = json!(1);
        } else {
            value["previous_sha256"] = "0".repeat(64).into();
        }
        s.close(ctx()).await?;
        fs::write(d.path().join("control"), progress::encode(&value)?)?;
        assert!(matches!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
            Err(ReceiptError::Invalid("first progress predecessor"))
        ));
    }
    Ok(())
}

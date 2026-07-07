use super::*;
const AT: &str = "2026-10-08T12:00:01.000000000Z";
fn grant(b: ReceiptBinding, p: &ReceiptProgress) -> Result<ReceiptRecoveryGrant, ReceiptError> {
    ReceiptRecoveryGrant::from_trusted_checkpoint(
        b,
        p.checksum(),
        "independent-current-retire".into(),
    )
}
async fn ready(
    cfg: ReceiptConfig,
) -> Result<(ReceiptStore, ReceiptBinding, ReceiptProgress), Box<dyn std::error::Error>> {
    let (raw, b) = ack_tests::pure(true)?;
    let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
    s.publish(raw, b.clone(), ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let p = s
        .advance(
            b.clone(),
            r.progress.clone(),
            2,
            progress_tests::response(&r, 2, 2)?,
            ctx(),
        )
        .await?;
    let ReceiptAckCommit::Intent {
        ticket,
        progress: p,
    } = s
        .acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            ReceiptAckUpdate::BeginProcessLocal {
                delivery: SourceDelivery::new(
                    Uuid::new_v4(),
                    "fixture-delete-delivery".into(),
                    "ephemeral-handle".into(),
                )?,
                observed_at: "2026-10-07T12:00:02.000000000Z".into(),
            },
            ctx(),
        )
        .await?
    else {
        return Err("intent".into());
    };
    let ReceiptAckCommit::Settled(p) = s
        .acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            ReceiptAckUpdate::Finish {
                ticket,
                outcome: SourceAckOutcome::from_sqs_json_response(200, b""),
                observed_at: "2026-10-07T12:00:03.000000000Z".into(),
            },
            ctx(),
        )
        .await?
    else {
        return Err("settled".into());
    };
    Ok((s, b, p))
}
fn next_receipt() -> Result<(Vec<u8>, ReceiptBinding), Box<dyn std::error::Error>> {
    let (raw, b) = ack_tests::pure(true)?;
    let r = format::decode(raw, &ctx())?;
    let mut m = r.metadata.clone();
    let id = Uuid::from_u128(0x30000000000040008000000000000002);
    m["receipt_id"] = id.to_string().into();
    let mut frames = Vec::new();
    let mut total = 0;
    for i in 0..r.info.prepared_count {
        let mut e: Value = serde_json::from_slice(r.prepared_bytes(i).ok_or("event")?)?;
        let event_id = Uuid::from_u128(0x20000000000040008000000000000003 + i as u128);
        e["id"] = event_id.to_string().into();
        e["attributes"]["evidence_ref"] = format!("receipt://{id}/record/{i}").into();
        let bytes = format::canonical(&e, 65536)?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        m["records"][i]["prepared_id"] = event_id.to_string().into();
        m["records"][i]["prepared_sha256"] = format::hex(&hash).into();
        total += bytes.len();
        frames.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frames.extend_from_slice(event_id.as_bytes());
        frames.extend_from_slice(&hash);
        frames.extend_from_slice(&bytes);
    }
    let metadata = format::canonical(&m, 1024 * 1024)?;
    let mut out = b"SIGSRC01".to_vec();
    out.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    out.extend_from_slice(&(r.original_bytes().len() as u64).to_be_bytes());
    out.extend_from_slice(&(r.info.prepared_count as u64).to_be_bytes());
    out.extend_from_slice(&(total as u64).to_be_bytes());
    out.extend_from_slice(&metadata);
    out.extend_from_slice(r.original_bytes());
    out.extend_from_slice(&frames);
    Ok((seal(&out), b))
}
#[tokio::test]
async fn complete_retirement_preserves_pins_blocks_dispatch_and_requires_reconciled_reopen()
-> TestResult {
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    let done = s
        .retire(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            AT.into(),
            ctx(),
        )
        .await?;
    assert_eq!(done.revision(), p.revision() + 2);
    assert_eq!(done.value["retirement"]["state"], "complete");
    for key in [
        "receipt_id",
        "receipt_sha256",
        "binding",
        "retention",
        "prepared_count",
        "verified_prefix",
        "prefix_sha256",
        "custody",
        "ack",
    ] {
        assert_eq!(done.value[key], p.value[key]);
    }
    assert!(
        !d.path()
            .join(format!("{}.src", format::uuid(&done.value["receipt_id"])?))
            .exists()
    );
    assert!(matches!(
        s.replay(b.clone(), ctx()).await,
        Err(ReceiptError::Retired)
    ));
    let (raw, _) = ack_tests::pure(true)?;
    assert!(matches!(
        s.publish(raw, b.clone(), ctx()).await,
        Err(ReceiptError::Retired)
    ));
    assert!(matches!(
        s.advance(b.clone(), done.clone(), 1, ReceiptAttempt::Uncertain, ctx())
            .await,
        Err(ReceiptError::Retired)
    ));
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            done.clone(),
            grant(b.clone(), &done)?,
            ReceiptAckUpdate::RecoverUncertain {
                observed_at: AT.into()
            },
            ctx()
        )
        .await,
        Err(ReceiptError::Retired)
    ));
    assert_eq!(
        s.current_control(b.clone(), ctx())
            .await?
            .ok_or("control")?
            .bytes,
        done.bytes
    );
    let same = s
        .retire(
            b.clone(),
            done.clone(),
            grant(b.clone(), &done)?,
            AT.into(),
            ctx(),
        )
        .await?;
    assert_eq!(same.bytes, done.bytes);
    s.close(ctx()).await?;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::History)
    ));
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx()).await,
        Err(ReceiptError::History)
    ));
    let snapshot = ReceiptProgress::inspect_retirement_control(
        &fs::read(d.path().join("control"))?,
        owner(),
        1,
    )?;
    let s =
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &snapshot)?, ctx())
            .await?;
    assert_eq!(
        s.current_control(b, ctx()).await?.ok_or("control")?.bytes,
        done.bytes
    );
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn guards_reject_unexpired_incomplete_ack_and_stale_authority_without_unlink() -> TestResult {
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    let id = format::uuid(&p.value["receipt_id"])?;
    for at in [
        "2026-10-08T12:00:00.999999999Z",
        "2026-10-07T11:00:00.000000000Z",
        "bad",
    ] {
        assert!(
            s.retire(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                at.into(),
                ctx()
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read(d.path().join("control"))?, p.bytes);
        assert!(d.path().join(format!("{id}.src")).exists());
    }
    let mut changed = b.0.clone();
    changed["authority_revision"] = "revoked".into();
    let foreign = ReceiptBinding::from_json(&format::canonical(&changed, 65536)?)?;
    assert!(matches!(
        s.retire(b.clone(), p.clone(), grant(foreign, &p)?, AT.into(), ctx())
            .await,
        Err(ReceiptError::Scope)
    ));
    let bad = ReceiptRecoveryGrant::from_trusted_checkpoint(b.clone(), [0; 32], "stale".into())?;
    assert!(matches!(
        s.retire(b.clone(), p.clone(), bad, AT.into(), ctx()).await,
        Err(ReceiptError::History)
    ));
    let old = progress::decode(
        format::initial(
            &format::decode(ack_tests::pure(true)?.0, &ctx())?,
            owner(),
            1,
        )?,
        &format::decode(ack_tests::pure(true)?.0, &ctx())?,
        owner(),
        1,
    )?;
    assert!(matches!(
        s.retire(b.clone(), old, grant(b.clone(), &p)?, AT.into(), ctx())
            .await,
        Err(ReceiptError::StaleProgress)
    ));
    s.close(ctx()).await?;
    let d = root()?;
    let (raw, b) = ack_tests::pure(false)?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    s.publish(raw, b.clone(), ctx()).await?;
    let p = s.current_control(b.clone(), ctx()).await?.ok_or("p")?;
    assert!(
        s.retire(b.clone(), p.clone(), grant(b, &p)?, AT.into(), ctx())
            .await
            .is_err()
    );
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn retirement_preflights_two_revisions_before_intent_or_unlink() -> TestResult {
    for revision in [u64::MAX - 1, u64::MAX] {
        let d = root()?;
        let (s, b, p) = ready(config(&d)?).await?;
        s.close(ctx()).await?;
        let mut v = p.value.clone();
        v["revision"] = revision.into();
        let bytes = progress::encode(&v)?;
        fs::write(d.path().join("control"), &bytes)?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let p = s.current_control(b.clone(), ctx()).await?.ok_or("p")?;
        assert!(matches!(
            s.retire(b.clone(), p.clone(), grant(b, &p)?, AT.into(), ctx())
                .await,
            Err(ReceiptError::Retirement)
        ));
        assert_eq!(fs::read(d.path().join("control"))?, bytes);
        assert!(
            d.path()
                .join(format!("{}.src", format::uuid(&v["receipt_id"])?))
                .exists()
        );
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn explicit_new_slot_preserves_old_completion_until_new_initial_commit() -> TestResult {
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    let done = s
        .retire(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            AT.into(),
            ctx(),
        )
        .await?;
    let (old_raw, _) = ack_tests::pure(true)?;
    assert!(matches!(
        s.publish_next(
            old_raw,
            b.clone(),
            done.clone(),
            grant(b.clone(), &done)?,
            ctx()
        )
        .await,
        Err(ReceiptError::IdentityConflict)
    ));
    let (raw, new_binding) = next_receipt()?;
    let info = s
        .publish_next(
            raw.clone(),
            new_binding.clone(),
            done.clone(),
            grant(b.clone(), &done)?,
            ctx(),
        )
        .await?;
    assert_ne!(info.id, format::uuid(&done.value["receipt_id"])?);
    let replay = s.replay(new_binding.clone(), ctx()).await?.ok_or("r")?;
    assert_eq!(replay.receipt.bytes, raw);
    assert_eq!(replay.progress.revision(), 0);
    assert_eq!(replay.progress.verified_prefix(), 0);
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert_eq!(
        s.current_control(new_binding, ctx())
            .await?
            .ok_or("p")?
            .revision(),
        0
    );
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn retirement_faults_hold_or_resume_missing_payload_with_fresh_checkpoint() -> TestResult {
    for stage in [
        Stage::RetirementIntentCommitted,
        Stage::ReceiptRemoved,
        Stage::ReclaimDirectorySynced,
        Stage::RetirementCompleteCommitted,
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
        let (s, b, p) = ready(cfg).await?;
        assert!(
            s.retire(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                AT.into(),
                ctx()
            )
            .await
            .is_err()
        );
        assert!(matches!(
            s.current_control(b.clone(), ctx()).await,
            Err(ReceiptError::Uncertain)
        ));
        s.close(ctx()).await?;
        let p = ReceiptProgress::inspect_retirement_control(
            &fs::read(d.path().join("control"))?,
            owner(),
            1,
        )?;
        assert!(matches!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
            Err(ReceiptError::History)
        ));
        let s =
            ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx())
                .await?;
        let done = s
            .retire(b.clone(), p.clone(), grant(b, &p)?, AT.into(), ctx())
            .await?;
        assert_eq!(done.value["retirement"]["state"], "complete");
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn missing_active_present_completed_and_rechecksummed_retired_corruption_fail_closed()
-> TestResult {
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    s.close(ctx()).await?;
    fs::remove_file(
        d.path()
            .join(format!("{}.src", format::uuid(&p.value["receipt_id"])?)),
    )?;
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b, &p)?, ctx()).await,
        Err(ReceiptError::Uncertain)
    ));
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    let done = s
        .retire(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            AT.into(),
            ctx(),
        )
        .await?;
    s.close(ctx()).await?;
    for key in [
        "extra",
        "ack",
        "attempt",
        "time",
        "prefix",
        "count",
        "custody",
        "retention",
        "revision",
    ] {
        let mut v = done.value.clone();
        match key {
            "extra" => v["extra"] = true.into(),
            "ack" => v["ack"]["state"] = "uncertain".into(),
            "attempt" => v["attempt"]["count"] = 1.into(),
            "time" => v["retirement"]["observed_at"] = "2026-10-08T12:00:00.999999999Z".into(),
            "prefix" => v["verified_prefix"] = 1.into(),
            "count" => {
                v["prepared_count"] = 1025.into();
                v["verified_prefix"] = 1025.into();
            }
            "custody" => v["custody"]["witness_id"] = "fake".into(),
            "retention" => v["retention"]["extra"] = true.into(),
            _ => v["revision"] = 4.into(),
        }
        let raw = progress::encode(&v)?;
        assert!(
            ReceiptProgress::inspect_retirement_control(&raw, owner(), 1).is_err(),
            "{key}"
        );
        fs::write(d.path().join("control"), raw)?;
        assert!(
            ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &done)?, ctx())
                .await
                .is_err()
        );
    }
    fs::write(d.path().join("control"), &done.bytes)?;
    let (raw, _) = ack_tests::pure(true)?;
    let path = d
        .path()
        .join(format!("{}.src", format::uuid(&done.value["receipt_id"])?));
    fs::write(&path, raw)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b, &done)?, ctx()).await,
        Err(ReceiptError::Uncertain)
    ));
    Ok(())
}

#[tokio::test]
async fn present_payload_ack_time_and_zero_generation_reject_on_reconciliation() -> TestResult {
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    let mut v = retirement::replacement(&p, AT.into(), false, owner(), 1)?.value;
    v["ack"]["observed_at"] = "2026-10-07T11:00:00.000000000Z".into();
    s.close(ctx()).await?;
    fs::write(d.path().join("control"), progress::encode(&v)?)?;
    assert!(matches!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b, &p)?, ctx()).await,
        Err(ReceiptError::Ack)
    ));
    v["owner_generation"] = 0.into();
    assert!(matches!(
        ReceiptProgress::inspect_retirement_control(&progress::encode(&v)?, owner(), 0),
        Err(ReceiptError::Owner)
    ));
    Ok(())
}
#[tokio::test]
async fn retired_owner_handover_preserves_completed_control_and_fences_previous_owner() -> TestResult
{
    let d = root()?;
    let (s, b, p) = ready(config(&d)?).await?;
    let done = s
        .retire(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            AT.into(),
            ctx(),
        )
        .await?;
    let new = Uuid::new_v4();
    s.transfer_owner(
        b.clone(),
        done.clone(),
        grant(b.clone(), &done)?,
        new,
        ctx(),
    )
    .await?;
    let moved =
        ReceiptProgress::inspect_retirement_control(&fs::read(d.path().join("control"))?, new, 2)?;
    for key in [
        "retirement",
        "ack",
        "prefix_sha256",
        "receipt_sha256",
        "binding",
    ] {
        assert_eq!(moved.value[key], done.value[key]);
    }
    assert!(
        ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &moved)?, ctx())
            .await
            .is_err()
    );
    let s = ReceiptStore::open_reconciled(config(&d)?, new, 2, grant(b, &moved)?, ctx()).await?;
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn actual_unlink_syscall_failure_never_commits_completion() -> TestResult {
    let d = root()?;
    let path = d.path().to_owned();
    let backup = tempfile::tempdir()?;
    let saved = backup.path().join("saved.src");
    let saved_hook = saved.clone();
    let id =
        format::uuid(&format::decode(ack_tests::pure(true)?.0, &ctx())?.metadata["receipt_id"])?;
    let filename = format!("{id}.src");
    let hook_name = filename.clone();
    let mut cfg = config(&d)?;
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::RetirementIntentCommitted {
            fs::rename(path.join(&hook_name), &saved_hook).map_err(io_error)?;
            fs::create_dir(path.join(&hook_name)).map_err(io_error)?;
        }
        Ok(())
    }));
    let (s, b, p) = ready(cfg).await?;
    assert!(matches!(
        s.retire(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            AT.into(),
            ctx()
        )
        .await,
        Err(ReceiptError::Io(_))
    ));
    let v = ReceiptProgress::inspect_retirement_control(
        &fs::read(d.path().join("control"))?,
        owner(),
        1,
    )?;
    assert_eq!(v.value["retirement"]["state"], "intent");
    s.close(ctx()).await?;
    fs::remove_dir(d.path().join(&filename))?;
    fs::rename(saved, d.path().join(filename))?;
    let s = ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &v)?, ctx())
        .await?;
    assert_eq!(
        s.retire(b.clone(), v.clone(), grant(b, &v)?, AT.into(), ctx())
            .await?
            .value["retirement"]["state"],
        "complete"
    );
    s.close(ctx()).await?;
    Ok(())
}
#[test]
#[ignore = "subprocess-only crash helper"]
fn retirement_crash_child() -> TestResult {
    let Some(path) = std::env::var_os("SIGNAL_RETIRE_TEST_ROOT") else {
        return Ok(());
    };
    let stage = std::env::var("SIGNAL_RETIRE_TEST_STAGE")?;
    let hit: usize = std::env::var("SIGNAL_RETIRE_TEST_HIT")?.parse()?;
    let next = std::env::var("SIGNAL_RETIRE_TEST_NEXT")? == "yes";
    let hits = AtomicUsize::new(0);
    let mut cfg = ReceiptConfig::new(path.into(), MIN_QUOTA_BYTES)?;
    cfg.hook = Some(Arc::new(move |s| {
        if format!("{s:?}") == stage && hits.fetch_add(1, Ordering::AcqRel) == hit {
            std::process::exit(76);
        }
        Ok(())
    }));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (s, b, p) = ready(cfg).await?;
            let done = s
                .retire(
                    b.clone(),
                    p.clone(),
                    grant(b.clone(), &p)?,
                    AT.into(),
                    ctx(),
                )
                .await?;
            if next {
                let (raw, new_binding) = next_receipt()?;
                s.publish_next(raw, new_binding, done.clone(), grant(b, &done)?, ctx())
                    .await?;
            }
            s.close(ctx()).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    Ok(())
}
#[test]
fn process_loss_during_retirement_and_new_slot_replacement_is_reconciled_or_held() -> TestResult {
    let mut cases = vec![
        (Stage::RetirementIntentCommitted, 0, false, false),
        (Stage::ReceiptRemoved, 0, false, false),
        (Stage::ReclaimDirectorySynced, 0, false, false),
        (Stage::RetirementCompleteCommitted, 0, false, true),
    ];
    for complete in [false, true] {
        for stage in [
            Stage::ProgressTempSynced,
            Stage::ProgressRenamed,
            Stage::ProgressDirectorySynced,
        ] {
            cases.push((stage, if complete { 4 } else { 3 }, false, complete));
        }
    }
    for stage in [
        Stage::ReceiptTempSynced,
        Stage::ReceiptLinked,
        Stage::ReceiptRenamed,
        Stage::ReceiptDirectorySynced,
    ] {
        cases.push((stage, 1, true, false));
    }
    for stage in [
        Stage::ProgressTempSynced,
        Stage::ProgressRenamed,
        Stage::ProgressDirectorySynced,
    ] {
        cases.push((stage, 5, true, true));
    }
    for (stage, hit, next, complete) in cases {
        let d = root()?;
        let result = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "receipt::tests::retirement_tests::retirement_crash_child",
                "--ignored",
            ])
            .env("SIGNAL_RETIRE_TEST_ROOT", d.path())
            .env("SIGNAL_RETIRE_TEST_STAGE", format!("{stage:?}"))
            .env("SIGNAL_RETIRE_TEST_HIT", hit.to_string())
            .env("SIGNAL_RETIRE_TEST_NEXT", if next { "yes" } else { "no" })
            .output()?;
        assert_eq!(
            result.status.code(),
            Some(76),
            "{stage:?} {hit} {}",
            String::from_utf8_lossy(&result.stderr)
        );
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let raw = fs::read(d.path().join("control"))?;
                let v = progress::parse(raw.clone(), owner(), 1)?;
                let b = ReceiptBinding::from_json(&format::canonical(&v.value["binding"], 65536)?)?;
                let opened = ReceiptStore::open_reconciled(
                    config(&d)?,
                    owner(),
                    1,
                    grant(b.clone(), &v)?,
                    ctx(),
                )
                .await;
                let held = stage == Stage::ProgressTempSynced
                    || (next
                        && !matches!(
                            stage,
                            Stage::ProgressRenamed | Stage::ProgressDirectorySynced
                        ));
                if held {
                    assert!(opened.is_err(), "{stage:?}/{hit}");
                } else {
                    let s = opened?;
                    let p = s.current_control(b.clone(), ctx()).await?.ok_or("p")?;
                    if next {
                        assert_eq!(p.revision(), 0);
                        assert_eq!(p.value["retirement"]["state"], "active");
                    } else {
                        assert_eq!(
                            p.value["retirement"]["state"],
                            if complete { "complete" } else { "intent" }
                        );
                        let done = s
                            .retire(b.clone(), p.clone(), grant(b, &p)?, AT.into(), ctx())
                            .await?;
                        assert_eq!(done.value["retirement"]["state"], "complete");
                    }
                    s.close(ctx()).await?;
                }
                if next
                    && !matches!(
                        stage,
                        Stage::ProgressRenamed | Stage::ProgressDirectorySynced
                    )
                {
                    assert_eq!(v.value["retirement"]["state"], "complete");
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
    }
    Ok(())
}
#[tokio::test]
async fn retire_timeout_keeps_owner_lock_and_intent_until_fresh_recovery() -> TestResult {
    let d = root()?;
    let mut cfg = config(&d)?;
    let (notify, entered) = tokio::sync::oneshot::channel();
    let notify = std::sync::Mutex::new(Some(notify));
    let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
    let gate = std::sync::Mutex::new(gate);
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::ReceiptRemoved
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
    let (s, b, p) = ready(cfg).await?;
    let s = Arc::new(s);
    let worker = s.clone();
    let binding = b.clone();
    let authority = grant(b.clone(), &p)?;
    let short = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(400))?;
    let call =
        tokio::spawn(async move { worker.retire(binding, p, authority, AT.into(), short).await });
    tokio::time::timeout(Duration::from_secs(2), entered).await??;
    assert!(matches!(call.await?, Err(ReceiptError::Timeout)));
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    release.send(())?;
    let s = Arc::try_unwrap(s).map_err(|_| "shared handle")?;
    s.close(ctx()).await?;
    let p = ReceiptProgress::inspect_retirement_control(
        &fs::read(d.path().join("control"))?,
        owner(),
        1,
    )?;
    assert_eq!(p.value["retirement"]["state"], "intent");
    let s = ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx())
        .await?;
    let done = s
        .retire(b.clone(), p.clone(), grant(b, &p)?, AT.into(), ctx())
        .await?;
    assert_eq!(done.value["retirement"]["state"], "complete");
    s.close(ctx()).await?;
    Ok(())
}

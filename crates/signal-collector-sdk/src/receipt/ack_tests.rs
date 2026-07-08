use super::*;
const AT: &str = "2026-10-07T12:00:02.000000000Z";
const LATER: &str = "2026-10-07T12:00:03.000000000Z";
const HANDLE: &str = "synthetic-current-handle-never-persist";
fn grant(b: ReceiptBinding, p: &ReceiptProgress) -> Result<ReceiptRecoveryGrant, ReceiptError> {
    ReceiptRecoveryGrant::from_trusted_checkpoint(b, p.checksum(), "trusted-current-1".into())
}
fn begin(attempt: u128, at: &str) -> Result<ReceiptAckUpdate, ReceiptError> {
    Ok(ReceiptAckUpdate::BeginProcessLocal {
        delivery: SourceDelivery::new(
            Uuid::from_u128(attempt),
            "new-delivery".into(),
            HANDLE.into(),
        )?,
        observed_at: at.into(),
    })
}
// Synthetic control fixture only: remove the final quarantined descriptor, keep
// all original/event bytes intact. This does not attest gzip/source completeness.
pub(super) fn pure(m2: bool) -> Result<(Vec<u8>, ReceiptBinding), Box<dyn std::error::Error>> {
    let (bytes, _) = vector("prepared")?;
    let r = format::decode(bytes, &ctx())?;
    let mut m = r.metadata.clone();
    m["records"].as_array_mut().ok_or("records")?.pop();
    m["binding"]["ack_requires_m2"] = m2.into();
    let metadata = format::canonical(&m, 1024 * 1024)?;
    let mut wire = r.bytes[..36].to_vec();
    wire[8..12].copy_from_slice(&(metadata.len() as u32).to_be_bytes());
    wire.extend_from_slice(&metadata);
    wire.extend_from_slice(&r.bytes[r.metadata_end..r.bytes.len() - 32]);
    Ok((
        seal(&wire),
        ReceiptBinding::from_json(&format::canonical(&m["binding"], 65536)?)?,
    ))
}
async fn opened(
    cfg: ReceiptConfig,
    m2: bool,
) -> Result<(ReceiptStore, ReceiptBinding), Box<dyn std::error::Error>> {
    let (raw, b) = pure(m2)?;
    let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
    s.publish(raw, b.clone(), ctx()).await?;
    Ok((s, b))
}
fn intent(
    c: ReceiptAckCommit,
) -> Result<(SourceAckTicket, ReceiptProgress), Box<dyn std::error::Error>> {
    match c {
        ReceiptAckCommit::Intent { ticket, progress } => Ok((ticket, progress)),
        _ => Err("intent".into()),
    }
}
fn settled(c: ReceiptAckCommit) -> Result<ReceiptProgress, Box<dyn std::error::Error>> {
    match c {
        ReceiptAckCommit::Settled(p) => Ok(p),
        _ => Err("settled".into()),
    }
}
fn finish(ticket: SourceAckTicket, outcome: SourceAckOutcome, at: &str) -> ReceiptAckUpdate {
    ReceiptAckUpdate::Finish {
        ticket,
        outcome,
        observed_at: at.into(),
    }
}
#[test]
fn bounded_ephemeral_delivery_and_json_response_shape() -> TestResult {
    for (attempt, delivery, handle) in [
        (Uuid::nil(), "id".into(), "handle".into()),
        (Uuid::new_v4(), String::new(), "handle".into()),
        (Uuid::new_v4(), "i".repeat(129), "handle".into()),
        (Uuid::new_v4(), "id".into(), "h".repeat(16385)),
        (Uuid::new_v4(), "id".into(), String::new()),
        (Uuid::new_v4(), "id".into(), "secret\n".into()),
    ] {
        assert!(matches!(
            SourceDelivery::new(attempt, delivery, handle),
            Err(ReceiptError::Ack)
        ));
    }
    assert!(SourceDelivery::new(Uuid::new_v4(), "i".repeat(128), "h".repeat(16384)).is_ok());
    Ok(())
}
#[tokio::test]
async fn intent_then_fresh_progress_finish_and_reopen_preserve_bytes() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, false).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("replay")?;
    let original = r.receipt.bytes.clone();
    let (ticket, p) = intent(
        s.acknowledge(
            b.clone(),
            r.progress.clone(),
            grant(b.clone(), &r.progress)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    assert_eq!(ticket.handle(), HANDLE);
    assert_eq!(p.revision(), 1);
    assert_eq!(p.value["ack"]["state"], "intent");
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let count = r.remaining();
    let p = s
        .advance(
            b.clone(),
            r.progress.clone(),
            count as u32,
            progress_tests::response(&r, count, count)?,
            ctx(),
        )
        .await?;
    let p = settled(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            finish(
                ticket,
                SourceAckOutcome::from_sqs_json_response(200, b""),
                LATER,
            ),
            ctx(),
        )
        .await?,
    )?;
    assert_eq!(p.value["ack"]["state"], "confirmed");
    assert_eq!(p.verified_prefix(), 2);
    for entry in fs::read_dir(d.path())? {
        let raw = fs::read(entry?.path())?;
        assert!(!raw.windows(HANDLE.len()).any(|w| w == HANDLE.as_bytes()));
    }
    s.close(ctx()).await?;
    let s = ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx())
        .await?;
    let r = s.replay(b, ctx()).await?.ok_or("r")?;
    assert_eq!(r.receipt.bytes, original);
    assert_eq!(r.progress.bytes, p.bytes);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn uncertain_and_duplicate_redelivery_use_fresh_attempts_and_late_settlement() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, false).await?;
    let mut p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
    for (i, (status, body, expected)) in [
        (403, b"".as_slice(), "uncertain"),
        (429, b"", "uncertain"),
        (500, b"", "uncertain"),
        (200, b"{}", "uncertain"),
        (204, b"", "uncertain"),
        (200, b"", "confirmed"),
        (200, b"", "confirmed"),
    ]
    .into_iter()
    .enumerate()
    {
        let (ticket, next) = intent(
            s.acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                begin(i as u128 + 1, AT)?,
                ctx(),
            )
            .await?,
        )?;
        p = settled(
            s.acknowledge(
                b.clone(),
                next.clone(),
                grant(b.clone(), &next)?,
                finish(
                    ticket,
                    SourceAckOutcome::from_sqs_json_response(status, body),
                    AT,
                ),
                ctx(),
            )
            .await?,
        )?;
        assert_eq!(p.value["ack"]["state"], expected);
        assert_eq!(p.verified_prefix(), 0);
    }
    let (ticket, p) = intent(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(9, AT)?,
            ctx(),
        )
        .await?,
    )?;
    let p = settled(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            finish(
                ticket,
                SourceAckOutcome::uncertain(),
                "2026-10-10T12:00:03.000000000Z",
            ),
            ctx(),
        )
        .await?,
    )?;
    assert_eq!(p.value["ack"]["state"], "uncertain");
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn m2_horizons_backward_time_and_pending_intent_fail_without_mutation() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, true).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let before = r.progress.bytes.clone();
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            r.progress.clone(),
            grant(b.clone(), &r.progress)?,
            begin(1, AT)?,
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, before);
    let p = s
        .advance(
            b.clone(),
            r.progress.clone(),
            2,
            progress_tests::response(&r, 2, 2)?,
            ctx(),
        )
        .await?;
    for at in [
        "2026-10-07T12:00:00.000000000Z",
        "2026-10-08T11:00:01.000000001Z",
        "2026-10-09T12:00:00.000000000Z",
        "bad",
        "2026-10-07T12:00:02Z",
    ] {
        assert!(
            s.acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                begin(1, at)?,
                ctx()
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read(d.path().join("control"))?, p.bytes);
    }
    let (ticket, p) = intent(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(2, LATER)?,
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            finish(
                ticket,
                SourceAckOutcome::uncertain(),
                "2026-10-07T12:00:01.000000000Z"
            ),
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, p.bytes);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn stale_checkpoint_token_and_binding_fail_without_handle_exposure() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, false).await?;
    let initial = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
    let (_, p) = intent(
        s.acknowledge(
            b.clone(),
            initial.clone(),
            grant(b.clone(), &initial)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            initial.clone(),
            grant(b.clone(), &initial)?,
            begin(2, AT)?,
            ctx()
        )
        .await,
        Err(ReceiptError::StaleProgress)
    ));
    let recover = || ReceiptAckUpdate::RecoverUncertain {
        observed_at: LATER.into(),
    };
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &initial)?,
            recover(),
            ctx()
        )
        .await,
        Err(ReceiptError::History)
    ));
    let mut changed = b.0.clone();
    changed["authority_revision"] = "different".into();
    let changed = ReceiptBinding::from_json(&format::canonical(&changed, 65536)?)?;
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(changed.clone(), &p)?,
            recover(),
            ctx()
        )
        .await,
        Err(ReceiptError::Scope)
    ));
    assert!(matches!(
        s.acknowledge(
            changed.clone(),
            p.clone(),
            grant(changed, &p)?,
            recover(),
            ctx()
        )
        .await,
        Err(ReceiptError::Scope)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, p.bytes);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn lost_ticket_recovery_redelivery_and_old_ticket_fencing() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, false).await?;
    let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
    let (old, p) = intent(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    s.close(ctx()).await?;
    let s = ReceiptStore::open_reconciled(config(&d)?, owner(), 1, grant(b.clone(), &p)?, ctx())
        .await?;
    let p = settled(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            ReceiptAckUpdate::RecoverUncertain {
                observed_at: LATER.into(),
            },
            ctx(),
        )
        .await?,
    )?;
    assert_eq!(p.value["ack"]["attempt_id"], Uuid::from_u128(1).to_string());
    assert_eq!(p.value["ack"]["delivery_id"], "new-delivery");
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(1, LATER)?,
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    let (new, p) = intent(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(2, LATER)?,
            ctx(),
        )
        .await?,
    )?;
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            finish(
                old,
                SourceAckOutcome::from_sqs_json_response(200, b""),
                LATER
            ),
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    let p = settled(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            finish(
                new,
                SourceAckOutcome::from_sqs_json_response(200, b""),
                LATER,
            ),
            ctx(),
        )
        .await?,
    )?;
    assert_eq!(p.value["ack"]["state"], "confirmed");
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn owner_handover_invalidates_pending_ack_ticket() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, false).await?;
    let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
    let (ticket, p) = intent(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    let new = Uuid::new_v4();
    s.transfer_owner(b.clone(), p.clone(), grant(b.clone(), &p)?, new, ctx())
        .await?;
    let s = ReceiptStore::open(config(&d)?, new, 2, ctx()).await?;
    let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
    assert!(matches!(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            finish(
                ticket,
                SourceAckOutcome::from_sqs_json_response(200, b""),
                LATER
            ),
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(fs::read(d.path().join("control"))?, p.bytes);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn mixed_quarantine_object_quarantine_and_stronger_modes_cannot_ack() -> TestResult {
    for id in ["prepared", "object-quarantine", "strong"] {
        let d = root()?;
        let (raw, b) = vector(id)?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        s.publish(raw, b.clone(), ctx()).await?;
        let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
        assert!(matches!(
            s.acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                begin(1, AT)?,
                ctx()
            )
            .await,
            Err(ReceiptError::Ack)
        ));
        assert_eq!(fs::read(d.path().join("control"))?, p.bytes);
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn revision_one_ack_predecessor_and_ack_shape_reject_corruption() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, false).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let (_, p) = intent(
        s.acknowledge(
            b.clone(),
            r.progress.clone(),
            grant(b.clone(), &r.progress)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    for key in [
        "previous",
        "prefix",
        "nil",
        "field",
        "delivery",
        "time",
        "state",
        "confirmed",
        "uncertain",
        "late_intent",
        "combined",
    ] {
        let mut v = p.value.clone();
        match key {
            "previous" => v["previous_sha256"] = "0".repeat(64).into(),
            "prefix" => {
                v["verified_prefix"] = 1.into();
                v["prefix_sha256"] = format::hex(&progress::prefix_hash(&r.receipt, 1)?).into();
            }
            "nil" => v["ack"]["attempt_id"] = Uuid::nil().to_string().into(),
            "field" => v["ack"]["handle"] = HANDLE.into(),
            "delivery" => v["ack"]["delivery_id"] = "x".repeat(129).into(),
            "time" => v["ack"]["observed_at"] = "2026-10-07T11:00:00.000000000Z".into(),
            "confirmed" | "uncertain" => v["ack"]["state"] = key.into(),
            "late_intent" => v["ack"]["observed_at"] = "2026-10-08T12:00:00.000000000Z".into(),
            "combined" => {
                v["verified_prefix"] = 1.into();
                v["prefix_sha256"] = format::hex(&progress::prefix_hash(&r.receipt, 1)?).into();
                v["attempt"] = json!({"kind":"verified","start":0,"count":2,"accepted":1,"response_sha256":"0".repeat(64)});
            }
            _ => v["ack"]["state"] = "not_requested".into(),
        }
        assert!(
            progress::decode(progress::encode(&v)?, &r.receipt, owner(), 1).is_err(),
            "{key}"
        );
    }
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn ack_write_faults_never_expose_ticket_and_poison_worker() -> TestResult {
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
        let (s, b) = opened(cfg, false).await?;
        let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
        assert!(
            s.acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                begin(1, AT)?,
                ctx()
            )
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
        } else {
            let s = opened?;
            assert_eq!(
                s.replay(b, ctx()).await?.ok_or("r")?.progress.value["ack"]["state"],
                "intent"
            );
            s.close(ctx()).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn rechecksummed_premature_m2_ack_rejects_on_reopen() -> TestResult {
    let d = root()?;
    let (s, b) = opened(config(&d)?, true).await?;
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
    let (_, p) = intent(
        s.acknowledge(
            b.clone(),
            p.clone(),
            grant(b.clone(), &p)?,
            begin(1, AT)?,
            ctx(),
        )
        .await?,
    )?;
    s.close(ctx()).await?;
    for state in ["intent", "uncertain", "confirmed"] {
        let mut v = p.value.clone();
        v["ack"]["state"] = state.into();
        v["verified_prefix"] = 0.into();
        v["prefix_sha256"] = format::hex(&progress::prefix_hash(&r.receipt, 0)?).into();
        fs::write(d.path().join("control"), progress::encode(&v)?)?;
        assert!(matches!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
            Err(ReceiptError::Ack)
        ));
    }
    Ok(())
}
#[test]
fn emitted_indeterminate_content_remains_eligible_and_both_horizons_are_checked() -> TestResult {
    let (raw, _) = pure(false)?;
    let mut r = format::decode(raw, &ctx())?;
    r.metadata["records"][0]["disposition"] = "emit_indeterminate".into();
    r.metadata["records"][0]["reasons"] = json!(["missing_actor"]);
    let initial = progress::decode(format::initial(&r, owner(), 1)?, &r, owner(), 1)?;
    let replay = ReceiptReplay {
        receipt: r,
        progress: initial,
    };
    assert!(ack::replacement(&replay, begin(1, AT)?, owner(), 1).is_ok());
    let (raw, _) = pure(false)?;
    let mut r = format::decode(raw, &ctx())?;
    r.metadata["retention"]["source_replay_until"] = "2026-10-07T13:00:01.000000000Z".into();
    let p = progress::decode(format::initial(&r, owner(), 1)?, &r, owner(), 1)?;
    let replay = ReceiptReplay {
        receipt: r,
        progress: p,
    };
    assert!(matches!(
        ack::replacement(&replay, begin(1, AT)?, owner(), 1),
        Err(ReceiptError::Ack)
    ));
    Ok(())
}
#[test]
#[ignore = "subprocess-only crash helper"]
fn ack_crash_child() -> TestResult {
    let Some(path) = std::env::var_os("SIGNAL_ACK_TEST_ROOT") else {
        return Ok(());
    };
    let stage = std::env::var("SIGNAL_ACK_TEST_STAGE")?;
    let finish = std::env::var("SIGNAL_ACK_TEST_FINISH")? == "yes";
    let hits = std::sync::atomic::AtomicUsize::new(0);
    let mut cfg = ReceiptConfig::new(path.into(), MIN_QUOTA_BYTES)?;
    cfg.hook = Some(Arc::new(move |s| {
        if format!("{s:?}") == stage && hits.fetch_add(1, Ordering::AcqRel) == usize::from(finish) {
            std::process::exit(75);
        }
        Ok(())
    }));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (s, b) = opened(cfg, false).await?;
            let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
            let (ticket, p) = intent(
                s.acknowledge(
                    b.clone(),
                    p.clone(),
                    grant(b.clone(), &p)?,
                    begin(1, AT)?,
                    ctx(),
                )
                .await?,
            )?;
            if finish {
                s.acknowledge(
                    b.clone(),
                    p.clone(),
                    grant(b, &p)?,
                    self::finish(
                        ticket,
                        SourceAckOutcome::from_sqs_json_response(200, b""),
                        LATER,
                    ),
                    ctx(),
                )
                .await?;
            }
            s.close(ctx()).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    Ok(())
}
#[test]
fn process_loss_during_intent_and_result_never_rewrites_preparation() -> TestResult {
    for finishing in [false, true] {
        for stage in [
            Stage::ProgressTempSynced,
            Stage::ProgressRenamed,
            Stage::ProgressDirectorySynced,
        ] {
            let d = root()?;
            let result = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "receipt::tests::ack_tests::ack_crash_child",
                    "--ignored",
                ])
                .env("SIGNAL_ACK_TEST_ROOT", d.path())
                .env("SIGNAL_ACK_TEST_STAGE", format!("{stage:?}"))
                .env(
                    "SIGNAL_ACK_TEST_FINISH",
                    if finishing { "yes" } else { "no" },
                )
                .output()?;
            assert_eq!(result.status.code(), Some(75));
            let (raw, b) = pure(false)?;
            let r = format::decode(raw.clone(), &ctx())?;
            assert_eq!(fs::read(d.path().join(format!("{}.src", r.info.id)))?, raw);
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let opened = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await;
                    if stage == Stage::ProgressTempSynced {
                        assert!(matches!(opened, Err(ReceiptError::Uncertain)));
                    } else {
                        let s = opened?;
                        let p = s.replay(b, ctx()).await?.ok_or("r")?.progress;
                        assert_eq!(
                            p.value["ack"]["state"],
                            if finishing { "confirmed" } else { "intent" }
                        );
                        s.close(ctx()).await?;
                    }
                    Ok::<_, Box<dyn std::error::Error>>(())
                })?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn ack_timeout_or_lost_caller_keeps_physical_lock_and_bounds_queue() -> TestResult {
    for lost in [false, true] {
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
        let (s, b) = opened(cfg, false).await?;
        let s = Arc::new(s);
        let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
        let authority = grant(b.clone(), &p)?;
        let update = begin(1, AT)?;
        let worker = s.clone();
        let binding = b.clone();
        let short = ExtensionContext::new(
            CancellationToken::new(),
            Duration::from_millis(if lost { 5000 } else { 400 }),
        )?;
        let call = tokio::spawn(async move {
            worker
                .acknowledge(binding, p, authority, update, short)
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered).await??;
        let worker = s.clone();
        let binding = b.clone();
        let cancellation = CancellationToken::new();
        let queued_ctx = ExtensionContext::new(cancellation.clone(), Duration::from_secs(5))?;
        let queued = tokio::spawn(async move { worker.replay(binding, queued_ctx).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while s.metrics().queue_depth != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(matches!(
            s.replay(b.clone(), ctx()).await,
            Err(ReceiptError::Busy)
        ));
        cancellation.cancel();
        assert!(matches!(queued.await?, Err(ReceiptError::Cancelled)));
        if lost {
            call.abort();
            assert!(call.await.is_err());
        } else {
            assert!(matches!(call.await?, Err(ReceiptError::Timeout)));
        }
        assert!(matches!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
            Err(ReceiptError::Locked)
        ));
        release.send(())?;
        let s = Arc::try_unwrap(s).map_err(|_| "shared handle")?;
        s.close(ctx()).await?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let p = s.replay(b.clone(), ctx()).await?.ok_or("r")?.progress;
        assert_eq!(p.value["ack"]["state"], "intent");
        let p = settled(
            s.acknowledge(
                b.clone(),
                p.clone(),
                grant(b, &p)?,
                ReceiptAckUpdate::RecoverUncertain {
                    observed_at: LATER.into(),
                },
                ctx(),
            )
            .await?,
        )?;
        assert_eq!(p.value["ack"]["state"], "uncertain");
        s.close(ctx()).await?;
    }
    Ok(())
}

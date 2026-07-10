use super::*;
use crate::receipt::custody::*;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
const REQUESTED: &str = "2026-10-07T12:00:02.000000000Z";
const VERIFIED: &str = "2026-10-07T12:00:03.000000000Z";
const OBSERVED: &str = "2026-10-07T12:00:04.000000000Z";
const EXPIRES: &str = "2026-10-07T12:00:12.000000000Z";
const RETAINED: &str = "2026-10-10T12:00:01.000000000Z";
fn test_signer() -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| "key generation")?;
    Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(|_| "key loading".into())
}
fn authority(signer: &Ed25519KeyPair) -> Result<CustodyAuthority, Box<dyn std::error::Error>> {
    Ok(CustodyAuthority::new(
        "independent-synthetic-archive",
        "key-v1",
        signer.public_key().as_ref().try_into()?,
        "2026-10-01T00:00:00.000000000Z",
        "2026-11-01T00:00:00.000000000Z",
    )?)
}
fn challenge(purpose: CustodyPurpose) -> Result<CustodyChallenge, ReceiptError> {
    CustodyChallenge::new(Uuid::from_u128(42), REQUESTED, EXPIRES, purpose)
}
fn receipt(id: &str, mode: Option<&str>) -> Result<StoredReceipt, Box<dyn std::error::Error>> {
    // Reuse the explicitly synthetic ACK-control fixture for a prepared-only
    // receipt. This protocol test makes no native parsing/completeness assertion.
    let (bytes, _) = if id == "strong" {
        super::ack_tests::pure(false)?
    } else {
        vector(id)?
    };
    let original = format::decode(bytes, &ctx())?;
    let mode = mode.or_else(|| (id == "strong").then_some("independent_durable"));
    if let Some(mode) = mode {
        let mut metadata = original.metadata.clone();
        metadata["binding"]["custody_mode"] = json!(mode);
        let canonical = format::canonical(&metadata, 1024 * 1024)?;
        let mut bytes = original.bytes[..36].to_vec();
        bytes[8..12].copy_from_slice(&(canonical.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&canonical);
        bytes.extend_from_slice(&original.bytes[original.metadata_end..original.bytes.len() - 32]);
        return Ok(format::decode(seal(&bytes), &ctx())?);
    }
    Ok(original)
}
fn manifest(receipt: &StoredReceipt, purpose: CustodyPurpose) -> Result<Vec<u8>, ReceiptError> {
    prepare_custody_manifest(
        receipt,
        &CustodyArchiveIdentity {
            id: "object-synthetic",
            version: "version-pinned",
            authority_id: "independent-synthetic-archive",
            committed_at: REQUESTED,
            retain_until: RETAINED,
            purpose,
        },
        &ctx(),
    )
}
fn witness(
    manifest: &[u8],
    attestation: &Value,
    signer: &Ed25519KeyPair,
) -> Result<Vec<u8>, ReceiptError> {
    let attestation = format::canonical(attestation, MAX_CUSTODY_ATTESTATION_BYTES)?;
    let mut bytes = b"SIGCUS01".to_vec();
    bytes.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    bytes.extend_from_slice(manifest);
    bytes.extend_from_slice(&(attestation.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&attestation);
    let signature = signer.sign(&bytes);
    bytes.extend_from_slice(signature.as_ref());
    Ok(bytes)
}
fn attestation(manifest: &[u8]) -> Value {
    json!({"schema_version":1,"authority_id":"independent-synthetic-archive","key_revision":"key-v1","manifest_sha256":format::hex(&Sha256::digest(manifest)),"challenge":Uuid::from_u128(42).to_string(),"verified_at":VERIFIED})
}
fn verify(
    receipt: &StoredReceipt,
    manifest: &[u8],
    attestation: &Value,
    signer: &Ed25519KeyPair,
    purpose: CustodyPurpose,
) -> Result<VerifiedCustody, Box<dyn std::error::Error>> {
    Ok(verify_custody_witness(
        receipt,
        &witness(manifest, attestation, signer)?,
        &authority(signer)?,
        &challenge(purpose)?,
        OBSERVED,
        &ctx(),
    )?)
}

fn fresh_token(
    receipt: &StoredReceipt,
    manifest: &[u8],
    signer: &Ed25519KeyPair,
    purpose: CustodyPurpose,
    nonce: u128,
) -> Result<VerifiedCustody, Box<dyn std::error::Error>> {
    fresh_token_context(receipt, manifest, signer, purpose, nonce, &ctx())
}
fn fresh_token_context(
    receipt: &StoredReceipt,
    manifest: &[u8],
    signer: &Ed25519KeyPair,
    purpose: CustodyPurpose,
    nonce: u128,
    context: &ExtensionContext,
) -> Result<VerifiedCustody, Box<dyn std::error::Error>> {
    let nonce = Uuid::from_u128(nonce);
    let challenge = CustodyChallenge::new(nonce, REQUESTED, EXPIRES, purpose)?;
    let mut statement = attestation(manifest);
    statement["challenge"] = json!(nonce.to_string());
    Ok(verify_custody_witness(
        receipt,
        &witness(manifest, &statement, signer)?,
        &authority(signer)?,
        &challenge,
        OBSERVED,
        context,
    )?)
}
fn grant(
    binding: &ReceiptBinding,
    progress: &ReceiptProgress,
) -> Result<ReceiptRecoveryGrant, ReceiptError> {
    ReceiptRecoveryGrant::from_trusted_checkpoint(
        binding.clone(),
        progress.checksum(),
        "synthetic-independent-current-custody-history".into(),
    )
}
async fn publish(
    config: ReceiptConfig,
    receipt: &StoredReceipt,
) -> Result<(ReceiptStore, ReceiptBinding, ReceiptProgress), Box<dyn std::error::Error>> {
    let binding =
        ReceiptBinding::from_json(&format::canonical(&receipt.metadata["binding"], 65536)?)?;
    let store = ReceiptStore::open(config, owner(), 1, ctx()).await?;
    store
        .publish(receipt.bytes.clone(), binding.clone(), ctx())
        .await?;
    let progress = store
        .replay(binding.clone(), ctx())
        .await?
        .ok_or("receipt")?
        .progress;
    Ok((store, binding, progress))
}
fn source_delivery(attempt: u128) -> Result<SourceDelivery, ReceiptError> {
    SourceDelivery::new(
        Uuid::from_u128(attempt),
        "synthetic-current-delivery".into(),
        "custody-ephemeral-handle".into(),
    )
}
fn intent(
    commit: ReceiptAckCommit,
) -> Result<(SourceAckTicket, ReceiptProgress), Box<dyn std::error::Error>> {
    match commit {
        ReceiptAckCommit::Intent { ticket, progress } => Ok((ticket, progress)),
        _ => Err("expected intent".into()),
    }
}
fn settled(commit: ReceiptAckCommit) -> Result<ReceiptProgress, Box<dyn std::error::Error>> {
    match commit {
        ReceiptAckCommit::Settled(progress) => Ok(progress),
        _ => Err("expected settled".into()),
    }
}

#[tokio::test]
async fn durable_custody_cas_reopen_and_idempotent_reverification_preserve_receipt_and_identity()
-> TestResult {
    let directory = root()?;
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let (store, binding, initial) = publish(config(&directory)?, &receipt).await?;
    let bad =
        ReceiptRecoveryGrant::from_trusted_checkpoint(binding.clone(), [0; 32], "stale".into())?;
    assert!(matches!(
        store
            .verify_custody(
                binding.clone(),
                initial.clone(),
                bad,
                fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 1)?,
                OBSERVED.into(),
                ctx()
            )
            .await,
        Err(ReceiptError::History)
    ));
    assert_eq!(fs::read(directory.path().join("control"))?, initial.bytes);
    let progress = store
        .verify_custody(
            binding.clone(),
            initial.clone(),
            grant(&binding, &initial)?,
            fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 2)?,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    assert_eq!(progress.revision(), 1);
    assert_eq!(progress.verified_prefix(), 0);
    assert_eq!(progress.value["custody"]["status"], "verified_independent");
    assert!(matches!(
        store
            .verify_custody(
                binding.clone(),
                initial.clone(),
                grant(&binding, &progress)?,
                fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 3)?,
                OBSERVED.into(),
                ctx()
            )
            .await,
        Err(ReceiptError::StaleProgress)
    ));
    let replayed = store
        .verify_custody(
            binding.clone(),
            progress.clone(),
            grant(&binding, &progress)?,
            fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 4)?,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    assert_eq!(replayed.bytes, progress.bytes);
    let mut substituted: Value = serde_json::from_slice(&manifest)?;
    substituted["archive_version"] = json!("other-pinned-version");
    let substituted = format::canonical(&substituted, MAX_CUSTODY_MANIFEST_BYTES)?;
    assert!(matches!(
        store
            .verify_custody(
                binding.clone(),
                progress.clone(),
                grant(&binding, &progress)?,
                fresh_token(&receipt, &substituted, &signer, CustodyPurpose::Prepared, 5)?,
                OBSERVED.into(),
                ctx()
            )
            .await,
        Err(ReceiptError::Custody)
    ));
    store.close(ctx()).await?;
    // Active plain reopen can inspect/replay syntax. It never manufactures the
    // fresh custody token or independently current grant needed by strong ACK.
    let reopened = ReceiptStore::open(config(&directory)?, owner(), 1, ctx()).await?;
    reopened.close(ctx()).await?;
    let store = ReceiptStore::open_reconciled(
        config(&directory)?,
        owner(),
        1,
        grant(&binding, &progress)?,
        ctx(),
    )
    .await?;
    let replay = store
        .replay(binding.clone(), ctx())
        .await?
        .ok_or("receipt")?;
    assert_eq!(replay.receipt.bytes, receipt.bytes);
    assert_eq!(replay.progress.bytes, progress.bytes);
    let next = store
        .advance(
            binding.clone(),
            progress,
            2,
            progress_tests::response(&replay, 2, 2)?,
            ctx(),
        )
        .await?;
    assert_eq!(next.value["custody"], replayed.value["custody"]);
    assert_eq!(next.verified_prefix(), 2);
    store.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn independent_ack_requires_fresh_exact_witness_on_every_phase_and_fences_owner_transfer()
-> TestResult {
    let directory = root()?;
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let (store, binding, initial) = publish(config(&directory)?, &receipt).await?;
    let p = store
        .verify_custody(
            binding.clone(),
            initial.clone(),
            grant(&binding, &initial)?,
            fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 1)?,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    assert!(matches!(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginProcessLocal {
                    delivery: source_delivery(1)?,
                    observed_at: OBSERVED.into()
                },
                ctx()
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    let (ticket, p) = intent(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(2)?,
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        2,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    assert!(ticket.current_context(&ctx())?.deadline() <= ctx().deadline());
    assert!(matches!(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::RecoverUncertain {
                    observed_at: OBSERVED.into()
                },
                ctx()
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    let new_owner = Uuid::new_v4();
    store
        .transfer_owner(
            binding.clone(),
            p.clone(),
            grant(&binding, &p)?,
            new_owner,
            ctx(),
        )
        .await?;
    assert!(matches!(
        ticket.current_context(&ctx()),
        Err(ReceiptError::Owner)
    ));
    let raw = fs::read(directory.path().join("control"))?;
    let moved = progress::decode(raw, &receipt, new_owner, 2)?;
    let store = ReceiptStore::open_reconciled(
        config(&directory)?,
        new_owner,
        2,
        grant(&binding, &moved)?,
        ctx(),
    )
    .await?;
    assert!(matches!(
        store
            .acknowledge(
                binding.clone(),
                moved.clone(),
                grant(&binding, &moved)?,
                ReceiptAckUpdate::FinishIndependent {
                    ticket,
                    outcome: SourceAckOutcome::from_sqs_json_response(200, b""),
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        3
                    )?),
                    observed_at: OBSERVED.into()
                },
                ctx()
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    let p = settled(
        store
            .acknowledge(
                binding.clone(),
                moved.clone(),
                grant(&binding, &moved)?,
                ReceiptAckUpdate::RecoverIndependent {
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        4,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(p.source_ack_state(), SourceAckState::Uncertain);
    let (ticket, p) = intent(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(3)?,
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        5,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    let p = settled(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::FinishIndependent {
                    ticket,
                    outcome: SourceAckOutcome::from_sqs_json_response(200, b""),
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        6,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(p.source_ack_state(), SourceAckState::Confirmed);
    assert_eq!(p.value["custody"], moved.value["custody"]);
    for entry in fs::read_dir(directory.path())? {
        let bytes = fs::read(entry?.path())?;
        assert!(
            !bytes
                .windows(24)
                .any(|bytes| bytes == b"custody-ephemeral-handle")
        );
    }
    store.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn independent_quarantine_ack_reclaim_and_retired_reopen_do_not_delete_archive() -> TestResult
{
    let directory = root()?;
    let receipt = receipt("object-quarantine", Some("independent_durable"))?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Quarantine)?;
    let (store, binding, initial) = publish(config(&directory)?, &receipt).await?;
    let p = store
        .verify_custody(
            binding.clone(),
            initial.clone(),
            grant(&binding, &initial)?,
            fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Quarantine, 1)?,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    assert_eq!(p.verified_prefix(), 0);
    let (ticket, p) = intent(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(1)?,
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Quarantine,
                        2,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    let p = settled(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::FinishIndependent {
                    ticket,
                    outcome: SourceAckOutcome::from_sqs_json_response(200, b""),
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Quarantine,
                        3,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    let done = store
        .retire(
            binding.clone(),
            p.clone(),
            grant(&binding, &p)?,
            "2026-10-08T12:00:01.000000000Z".into(),
            ctx(),
        )
        .await?;
    assert_eq!(done.value["custody"], p.value["custody"]);
    assert_eq!(done.value["retirement"]["state"], "complete");
    assert!(
        !directory
            .path()
            .join(format!("{}.src", receipt.info.id))
            .exists()
    );
    // Only the local receipt slot is reclaimed. There is no archive client or
    // original-delete authority in this API; the stable manifest is retained.
    assert_eq!(
        serde_json::from_slice::<Value>(&manifest)?["committed_at"],
        REQUESTED
    );
    store.close(ctx()).await?;
    let inspected = ReceiptProgress::inspect_retirement_control(
        &fs::read(directory.path().join("control"))?,
        owner(),
        1,
    )?;
    let store = ReceiptStore::open_reconciled(
        config(&directory)?,
        owner(),
        1,
        grant(&binding, &inspected)?,
        ctx(),
    )
    .await?;
    assert_eq!(
        store
            .current_control(binding, ctx())
            .await?
            .ok_or("control")?
            .bytes,
        done.bytes
    );
    store.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn expired_custody_tokens_and_source_ticket_budgets_never_renew_or_mutate_control()
-> TestResult {
    let directory = root()?;
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let (store, binding, initial) = publish(config(&directory)?, &receipt).await?;
    let short_context = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(50))?;
    let token = fresh_token_context(
        &receipt,
        &manifest,
        &signer,
        CustodyPurpose::Prepared,
        1,
        &short_context,
    )?;
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(matches!(
        store
            .verify_custody(
                binding.clone(),
                initial.clone(),
                grant(&binding, &initial)?,
                token,
                OBSERVED.into(),
                ctx()
            )
            .await,
        Err(ReceiptError::Timeout)
    ));
    assert_eq!(fs::read(directory.path().join("control"))?, initial.bytes);
    let p = store
        .verify_custody(
            binding.clone(),
            initial.clone(),
            grant(&binding, &initial)?,
            fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 2)?,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    let short_context =
        ExtensionContext::new(CancellationToken::new(), Duration::from_millis(300))?;
    let short = fresh_token_context(
        &receipt,
        &manifest,
        &signer,
        CustodyPurpose::Prepared,
        3,
        &short_context,
    )?;
    let (ticket, p) = intent(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(1)?,
                    custody: Box::new(short),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(matches!(
        ticket.current_context(&ctx()),
        Err(ReceiptError::Custody)
    ));
    let wrong_time = "2026-10-07T12:00:04.000000001Z";
    assert!(matches!(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::RecoverIndependent {
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        4
                    )?),
                    observed_at: wrong_time.into()
                },
                ctx()
            )
            .await,
        Err(ReceiptError::Custody)
    ));
    assert_eq!(fs::read(directory.path().join("control"))?, p.bytes);
    store.close(ctx()).await?;
    Ok(())
}

#[test]
#[ignore = "subprocess-only crash helper"]
fn custody_crash_child() -> TestResult {
    let Some(root_path) = std::env::var_os("SIGNAL_CUSTODY_TEST_ROOT") else {
        return Ok(());
    };
    let marker = PathBuf::from(std::env::var_os("SIGNAL_CUSTODY_TEST_MARKER").ok_or("marker")?);
    let stage = std::env::var("SIGNAL_CUSTODY_TEST_STAGE")?;
    let target: usize = std::env::var("SIGNAL_CUSTODY_TEST_HIT")?.parse()?;
    let hit = AtomicUsize::new(0);
    let mut config = ReceiptConfig::new(root_path.into(), MIN_QUOTA_BYTES)?;
    config.hook = Some(Arc::new(move |observed| {
        if format!("{observed:?}") == stage && hit.fetch_add(1, Ordering::AcqRel) == target {
            fs::write(&marker, b"entered").map_err(|e| ReceiptError::Io(e.kind()))?;
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(ReceiptError::Timeout);
        }
        Ok(())
    }));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let receipt = receipt("strong", None)?;
            let signer = test_signer()?;
            let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
            let (store, binding, initial) = publish(config, &receipt).await?;
            let p = store
                .verify_custody(
                    binding.clone(),
                    initial.clone(),
                    grant(&binding, &initial)?,
                    fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 1)?,
                    OBSERVED.into(),
                    ctx(),
                )
                .await?;
            let _ = store
                .acknowledge(
                    binding.clone(),
                    p.clone(),
                    grant(&binding, &p)?,
                    ReceiptAckUpdate::BeginIndependent {
                        delivery: source_delivery(1)?,
                        custody: Box::new(fresh_token(
                            &receipt,
                            &manifest,
                            &signer,
                            CustodyPurpose::Prepared,
                            2,
                        )?),
                        observed_at: OBSERVED.into(),
                    },
                    ctx(),
                )
                .await?;
            store.close(ctx()).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    Ok(())
}

#[test]
fn sigkill_at_custody_and_independent_ack_publication_never_reconstructs_a_ticket() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for hit in [0, 1] {
        for stage in [
            Stage::ProgressTempSynced,
            Stage::ProgressRenamed,
            Stage::ProgressDirectorySynced,
        ] {
            let directory = root()?;
            let markers = tempfile::tempdir()?;
            let marker = markers.path().join("entered");
            let mut child = Child(
                std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "receipt::tests::custody_tests::custody_crash_child",
                        "--ignored",
                    ])
                    .env("SIGNAL_CUSTODY_TEST_ROOT", directory.path())
                    .env("SIGNAL_CUSTODY_TEST_MARKER", &marker)
                    .env("SIGNAL_CUSTODY_TEST_STAGE", format!("{stage:?}"))
                    .env("SIGNAL_CUSTODY_TEST_HIT", hit.to_string())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()?,
            );
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while !marker.exists() {
                assert!(std::time::Instant::now() < until, "child milestone timeout");
                assert!(
                    child.0.try_wait()?.is_none(),
                    "child exited before milestone"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill()?;
            assert_eq!(child.0.wait()?.signal(), Some(9));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let receipt = receipt("strong", None)?;
                    let binding = ReceiptBinding::from_json(&format::canonical(
                        &receipt.metadata["binding"],
                        65536,
                    )?)?;
                    if stage == Stage::ProgressTempSynced {
                        assert!(
                            ReceiptStore::open(config(&directory)?, owner(), 1, ctx())
                                .await
                                .is_err()
                        );
                    } else {
                        let progress = progress::decode(
                            fs::read(directory.path().join("control"))?,
                            &receipt,
                            owner(),
                            1,
                        )?;
                        assert_eq!(progress.revision(), hit as u64 + 1);
                        assert_eq!(
                            progress.source_ack_state(),
                            if hit == 0 {
                                SourceAckState::NotRequested
                            } else {
                                SourceAckState::Intent
                            }
                        );
                        let store = ReceiptStore::open_reconciled(
                            config(&directory)?,
                            owner(),
                            1,
                            grant(&binding, &progress)?,
                            ctx(),
                        )
                        .await?;
                        assert!(matches!(
                            store
                                .acknowledge(
                                    binding.clone(),
                                    progress.clone(),
                                    grant(&binding, &progress)?,
                                    ReceiptAckUpdate::RecoverUncertain {
                                        observed_at: OBSERVED.into()
                                    },
                                    ctx()
                                )
                                .await,
                            Err(ReceiptError::Ack)
                        ));
                        let replay = store.replay(binding, ctx()).await?.ok_or("receipt")?;
                        assert_eq!(replay.receipt.bytes, receipt.bytes);
                        assert_eq!(replay.progress.bytes, progress.bytes);
                        store.close(ctx()).await?;
                    }
                    Ok::<_, Box<dyn std::error::Error>>(())
                })?;
        }
    }
    Ok(())
}

#[test]
fn public_frame_inspection_preserves_exact_bytes_without_manufacturing_custody_or_native_proof()
-> TestResult {
    for id in ["prepared", "strong", "object-quarantine"] {
        let (raw, _) = vector(id)?;
        let receipt = StoredReceipt::from_framed_bytes(raw.clone(), &ctx())?;
        assert_eq!(receipt.framed_bytes(), raw);
        assert_eq!(receipt.info().bytes, raw.len());
        let metadata: Value = serde_json::from_slice(receipt.metadata_bytes())?;
        assert_eq!(metadata["receipt_id"], receipt.info().id.to_string());
        // Inspection only returns immutable bytes/pins. Stronger/quarantine
        // frames remain unacknowledgeable through the process-local path.
        let p = progress::decode(format::initial(&receipt, owner(), 1)?, &receipt, owner(), 1)?;
        let replay = ReceiptReplay {
            receipt,
            progress: p,
        };
        assert!(
            ack::replacement(
                &replay,
                ReceiptAckUpdate::BeginProcessLocal {
                    delivery: source_delivery(1)?,
                    observed_at: OBSERVED.into()
                },
                owner(),
                1,
                CancellationToken::new()
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn public_frame_inspection_bounds_allocation_and_rejects_checksum_shape_and_cancelled_work()
-> TestResult {
    let (raw, _) = vector("prepared")?;
    let mut spare = Vec::with_capacity(MAX_RECEIPT_BYTES + 1);
    spare.extend_from_slice(&raw);
    assert!(matches!(
        StoredReceipt::from_framed_bytes(spare, &ctx()),
        Err(ReceiptError::Invalid("receipt allocation"))
    ));
    let mut altered = raw.clone();
    let tail = altered.len() - 1;
    altered[tail] ^= 1;
    assert!(StoredReceipt::from_framed_bytes(altered, &ctx()).is_err());
    assert!(StoredReceipt::from_framed_bytes(raw[..raw.len() - 1].to_vec(), &ctx()).is_err());
    let cancelled = ctx();
    cancelled.cancellation().cancel();
    assert!(matches!(
        StoredReceipt::from_framed_bytes(raw, &cancelled),
        Err(ReceiptError::Cancelled)
    ));
    Ok(())
}

#[test]
fn independent_signature_binds_every_receipt_byte_and_preserves_original_manifest_time()
-> TestResult {
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let attested = attestation(&manifest);
    let first = verify(
        &receipt,
        &manifest,
        &attested,
        &signer,
        CustodyPurpose::Prepared,
    )?;
    assert_eq!(first.committed_at(), REQUESTED);
    assert_eq!(first.retain_until(), RETAINED);
    let mut fresh = attested.clone();
    fresh["verified_at"] = json!(OBSERVED);
    let second = verify(
        &receipt,
        &manifest,
        &fresh,
        &signer,
        CustodyPurpose::Prepared,
    )?;
    assert_eq!(first.witness_id(), second.witness_id());
    assert_eq!(first.committed_at(), second.committed_at());
    let content: Value = serde_json::from_slice(&manifest)?;
    assert_eq!(
        content["framed_sha256"],
        format::hex(&Sha256::digest(receipt.framed_bytes()))
    );
    assert_ne!(content["framed_sha256"], content["receipt_sha256"]);
    let mut raw = witness(&manifest, &attested, &signer)?;
    let last = raw.len() - 1;
    raw[last] ^= 1;
    assert!(matches!(
        verify_custody_witness(
            &receipt,
            &raw,
            &authority(&signer)?,
            &challenge(CustodyPurpose::Prepared)?,
            OBSERVED,
            &ctx()
        ),
        Err(ReceiptError::Custody)
    ));
    Ok(())
}

#[tokio::test]
async fn independent_custody_does_not_bypass_pinned_m2_admission_requirement() -> TestResult {
    let directory = root()?;
    let receipt = receipt("strong", None)?;
    let mut metadata = receipt.metadata.clone();
    metadata["binding"]["ack_requires_m2"] = json!(true);
    let encoded = format::canonical(&metadata, 1024 * 1024)?;
    let mut raw = receipt.bytes[..36].to_vec();
    raw[8..12].copy_from_slice(&(encoded.len() as u32).to_be_bytes());
    raw.extend_from_slice(&encoded);
    raw.extend_from_slice(&receipt.bytes[receipt.metadata_end..receipt.bytes.len() - 32]);
    let receipt = format::decode(seal(&raw), &ctx())?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let (store, binding, initial) = publish(config(&directory)?, &receipt).await?;
    let p = store
        .verify_custody(
            binding.clone(),
            initial.clone(),
            grant(&binding, &initial)?,
            fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 1)?,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    assert!(matches!(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(1)?,
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        2
                    )?),
                    observed_at: OBSERVED.into()
                },
                ctx()
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(fs::read(directory.path().join("control"))?, p.bytes);
    let replay = store
        .replay(binding.clone(), ctx())
        .await?
        .ok_or("receipt")?;
    let p = store
        .advance(
            binding.clone(),
            p,
            2,
            progress_tests::response(&replay, 2, 2)?,
            ctx(),
        )
        .await?;
    let (_, p) = intent(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(2)?,
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        3,
                    )?),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    assert_eq!(p.source_ack_state(), SourceAckState::Intent);
    assert_eq!(p.verified_prefix(), 2);
    store.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn custody_control_publication_faults_hold_owner_and_never_supply_ack_authority() -> TestResult
{
    for stage in [
        Stage::ProgressTempSynced,
        Stage::ProgressRenamed,
        Stage::ProgressDirectorySynced,
    ] {
        let directory = root()?;
        let receipt = receipt("strong", None)?;
        let signer = test_signer()?;
        let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
        let mut cfg = config(&directory)?;
        cfg.hook = Some(Arc::new(move |hit| {
            if hit == stage {
                Err(ReceiptError::Io(std::io::ErrorKind::Other))
            } else {
                Ok(())
            }
        }));
        let (store, binding, initial) = publish(cfg, &receipt).await?;
        assert!(
            store
                .verify_custody(
                    binding.clone(),
                    initial.clone(),
                    grant(&binding, &initial)?,
                    fresh_token(&receipt, &manifest, &signer, CustodyPurpose::Prepared, 1)?,
                    OBSERVED.into(),
                    ctx()
                )
                .await
                .is_err()
        );
        assert!(matches!(
            store.replay(binding.clone(), ctx()).await,
            Err(ReceiptError::Uncertain)
        ));
        assert!(matches!(
            ReceiptStore::open(config(&directory)?, owner(), 1, ctx()).await,
            Err(ReceiptError::Locked)
        ));
        store.close(ctx()).await?;
        if stage == Stage::ProgressTempSynced {
            assert!(
                ReceiptStore::open(config(&directory)?, owner(), 1, ctx())
                    .await
                    .is_err()
            );
        } else {
            let progress = progress::decode(
                fs::read(directory.path().join("control"))?,
                &receipt,
                owner(),
                1,
            )?;
            let store = ReceiptStore::open_reconciled(
                config(&directory)?,
                owner(),
                1,
                grant(&binding, &progress)?,
                ctx(),
            )
            .await?;
            assert_eq!(progress.value["custody"]["status"], "verified_independent");
            assert!(matches!(
                store
                    .acknowledge(
                        binding.clone(),
                        progress.clone(),
                        grant(&binding, &progress)?,
                        ReceiptAckUpdate::BeginProcessLocal {
                            delivery: source_delivery(1)?,
                            observed_at: OBSERVED.into()
                        },
                        ctx()
                    )
                    .await,
                Err(ReceiptError::Ack)
            ));
            store.close(ctx()).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn witness_expiry_during_disk_work_keeps_physical_lease_and_holds_uncertain_control()
-> TestResult {
    let directory = root()?;
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let (notify, entered) = tokio::sync::oneshot::channel();
    let notify = std::sync::Mutex::new(Some(notify));
    let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
    let gate = std::sync::Mutex::new(gate);
    let mut cfg = config(&directory)?;
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::ProgressTempSynced
            && let Some(notify) = notify.lock().map_err(|_| ReceiptError::Closed)?.take()
        {
            let _ = notify.send(());
            gate.lock()
                .map_err(|_| ReceiptError::Closed)?
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| ReceiptError::Closed)?;
        }
        Ok(())
    }));
    let (store, binding, initial) = publish(cfg, &receipt).await?;
    let store = Arc::new(store);
    let worker = store.clone();
    let worker_binding = binding.clone();
    let root_initial = initial.clone();
    let short_context =
        ExtensionContext::new(CancellationToken::new(), Duration::from_millis(300))?;
    let token = fresh_token_context(
        &receipt,
        &manifest,
        &signer,
        CustodyPurpose::Prepared,
        1,
        &short_context,
    )?;
    let call = tokio::spawn(async move {
        worker
            .verify_custody(
                worker_binding.clone(),
                initial.clone(),
                grant(&worker_binding, &initial).map_err(|_| ReceiptError::History)?,
                token,
                OBSERVED.into(),
                ctx(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), entered).await??;
    let mut oversized_allocation = String::with_capacity(1024 * 1024);
    oversized_allocation.push_str(OBSERVED);
    let before = store.metrics();
    assert!(matches!(
        store
            .acknowledge(
                binding.clone(),
                root_initial.clone(),
                grant(&binding, &root_initial)?,
                ReceiptAckUpdate::RecoverIndependent {
                    custody: Box::new(fresh_token(
                        &receipt,
                        &manifest,
                        &signer,
                        CustodyPurpose::Prepared,
                        2
                    )?),
                    observed_at: oversized_allocation
                },
                ctx()
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(store.metrics().queue_depth, before.queue_depth);
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(matches!(
        ReceiptStore::open(config(&directory)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    release.send(())?;
    assert!(matches!(call.await?, Err(ReceiptError::Timeout)));
    assert!(matches!(
        store.replay(binding, ctx()).await,
        Err(ReceiptError::Uncertain)
    ));
    let store = Arc::try_unwrap(store).map_err(|_| "shared store")?;
    store.close(ctx()).await?;
    assert!(
        ReceiptStore::open(config(&directory)?, owner(), 1, ctx())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn signed_verification_key_window_and_key_retention_expiries_bound_ticket_lifetime()
-> TestResult {
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let manifest = manifest(&receipt, CustodyPurpose::Prepared)?;
    let raw = witness(&manifest, &attestation(&manifest), &signer)?;
    let too_recent = CustodyAuthority::new(
        "independent-synthetic-archive",
        "key-v1",
        signer.public_key().as_ref().try_into()?,
        OBSERVED,
        "2026-11-01T00:00:00.000000000Z",
    )?;
    assert!(matches!(
        verify_custody_witness(
            &receipt,
            &raw,
            &too_recent,
            &challenge(CustodyPurpose::Prepared)?,
            OBSERVED,
            &ctx()
        ),
        Err(ReceiptError::Custody)
    ));
    let nearing_expiry = CustodyAuthority::new(
        "independent-synthetic-archive",
        "key-v1",
        signer.public_key().as_ref().try_into()?,
        REQUESTED,
        "2026-10-07T12:00:05.000000000Z",
    )?;
    let token = verify_custody_witness(
        &receipt,
        &raw,
        &nearing_expiry,
        &challenge(CustodyPurpose::Prepared)?,
        OBSERVED,
        &ctx(),
    )?;
    assert!(
        token
            .deadline()
            .saturating_duration_since(tokio::time::Instant::now())
            <= Duration::from_secs(1)
    );
    let directory = root()?;
    let (store, binding, initial) = publish(config(&directory)?, &receipt).await?;
    let p = store
        .verify_custody(
            binding.clone(),
            initial.clone(),
            grant(&binding, &initial)?,
            token,
            OBSERVED.into(),
            ctx(),
        )
        .await?;
    let token = verify_custody_witness(
        &receipt,
        &raw,
        &nearing_expiry,
        &challenge(CustodyPurpose::Prepared)?,
        OBSERVED,
        &ctx(),
    )?;
    let (ticket, _) = intent(
        store
            .acknowledge(
                binding.clone(),
                p.clone(),
                grant(&binding, &p)?,
                ReceiptAckUpdate::BeginIndependent {
                    delivery: source_delivery(1)?,
                    custody: Box::new(token),
                    observed_at: OBSERVED.into(),
                },
                ctx(),
            )
            .await?,
    )?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        ticket.current_context(&ctx()),
        Err(ReceiptError::Custody)
    ));
    store.close(ctx()).await?;
    let request = "2026-10-10T11:59:59.000000000Z";
    let observed = "2026-10-10T12:00:00.000000000Z";
    let expires = "2026-10-10T12:00:10.000000000Z";
    let late_challenge = CustodyChallenge::new(
        Uuid::from_u128(42),
        request,
        expires,
        CustodyPurpose::Prepared,
    )?;
    let mut late = attestation(&manifest);
    late["verified_at"] = json!(observed);
    let token = verify_custody_witness(
        &receipt,
        &witness(&manifest, &late, &signer)?,
        &authority(&signer)?,
        &late_challenge,
        observed,
        &ctx(),
    )?;
    assert!(
        token
            .deadline()
            .saturating_duration_since(tokio::time::Instant::now())
            <= Duration::from_secs(1)
    );
    Ok(())
}

#[test]
fn authenticated_cross_binding_origin_receipt_and_retention_changes_fail_closed() -> TestResult {
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let baseline: Value = serde_json::from_slice(&manifest(&receipt, CustodyPurpose::Prepared)?)?;
    for (field, changed) in [
        ("receipt_id", json!(Uuid::new_v4().to_string())),
        ("receipt_sha256", json!("00".repeat(32))),
        ("framed_sha256", json!("00".repeat(32))),
        ("authority_id", json!("other-archive")),
        ("retain_until", json!(REQUESTED)),
        ("archive_version", json!("null")),
        ("committed_at", json!(RETAINED)),
        ("mode", json!("process_local")),
        ("purpose", json!("quarantine")),
    ] {
        let mut value = baseline.clone();
        value[field] = changed;
        let raw = format::canonical(&value, MAX_CUSTODY_MANIFEST_BYTES)?;
        assert!(
            verify(
                &receipt,
                &raw,
                &attestation(&raw),
                &signer,
                CustodyPurpose::Prepared
            )
            .is_err(),
            "{field}"
        );
    }
    for field in ["binding", "original", "retention"] {
        let mut value = baseline.clone();
        match field {
            "binding" => value[field]["config_revision"] = json!("different"),
            "original" => value[field]["version_id"] = json!("different"),
            _ => value[field]["source_replay_until"] = json!(RETAINED),
        };
        let raw = format::canonical(&value, MAX_CUSTODY_MANIFEST_BYTES)?;
        assert!(
            verify(
                &receipt,
                &raw,
                &attestation(&raw),
                &signer,
                CustodyPurpose::Prepared
            )
            .is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn challenge_key_revision_time_and_expiry_are_independent_of_signed_producer_fields() -> TestResult
{
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let raw = manifest(&receipt, CustodyPurpose::Prepared)?;
    for (field, changed) in [
        ("schema_version", json!(2)),
        ("authority_id", json!("other-archive")),
        ("key_revision", json!("stale-key")),
        ("manifest_sha256", json!("00".repeat(32))),
        ("challenge", json!(Uuid::new_v4().to_string())),
        ("verified_at", json!("2026-10-07T12:00:01.000000000Z")),
        ("verified_at", json!(EXPIRES)),
    ] {
        let mut statement = attestation(&raw);
        statement[field] = changed;
        assert!(
            verify(
                &receipt,
                &raw,
                &statement,
                &signer,
                CustodyPurpose::Prepared
            )
            .is_err(),
            "{field}"
        );
    }
    let bytes = witness(&raw, &attestation(&raw), &signer)?;
    assert!(
        verify_custody_witness(
            &receipt,
            &bytes,
            &authority(&signer)?,
            &challenge(CustodyPurpose::Prepared)?,
            EXPIRES,
            &ctx()
        )
        .is_err()
    );
    let other = test_signer()?;
    assert!(
        verify_custody_witness(
            &receipt,
            &bytes,
            &authority(&other)?,
            &challenge(CustodyPurpose::Prepared)?,
            OBSERVED,
            &ctx()
        )
        .is_err()
    );
    assert!(
        CustodyChallenge::new(Uuid::nil(), REQUESTED, EXPIRES, CustodyPurpose::Prepared).is_err()
    );
    assert!(
        CustodyChallenge::new(
            Uuid::new_v4(),
            REQUESTED,
            "2026-10-07T12:01:02.000000001Z",
            CustodyPurpose::Prepared
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn quarantined_receipt_needs_explicit_trusted_purpose_and_process_local_stays_denied() -> TestResult
{
    let quarantine = receipt("object-quarantine", Some("independent_durable"))?;
    let signer = test_signer()?;
    assert!(manifest(&quarantine, CustodyPurpose::Prepared).is_err());
    let raw = manifest(&quarantine, CustodyPurpose::Quarantine)?;
    assert!(
        verify(
            &quarantine,
            &raw,
            &attestation(&raw),
            &signer,
            CustodyPurpose::Prepared
        )
        .is_err()
    );
    assert!(
        verify(
            &quarantine,
            &raw,
            &attestation(&raw),
            &signer,
            CustodyPurpose::Quarantine
        )
        .is_ok()
    );
    let local = receipt("prepared", None)?;
    assert!(manifest(&local, CustodyPurpose::Prepared).is_err());
    let replay = receipt("strong", Some("protected_replay"))?;
    assert!(
        prepare_custody_manifest(
            &replay,
            &CustodyArchiveIdentity {
                id: "object-synthetic",
                version: "version-pinned",
                authority_id: "independent-synthetic-archive",
                committed_at: REQUESTED,
                retain_until: "2026-10-08T12:00:01.000000000Z",
                purpose: CustodyPurpose::Prepared
            },
            &ctx()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_frames_duplicate_unknown_fields_and_cancelled_work_produce_no_token() -> TestResult {
    let receipt = receipt("strong", None)?;
    let signer = test_signer()?;
    let raw = manifest(&receipt, CustodyPurpose::Prepared)?;
    let bytes = witness(&raw, &attestation(&raw), &signer)?;
    for candidate in [
        &bytes[..bytes.len() - 1],
        b"not-a-frame".as_slice(),
        &vec![0; MAX_CUSTODY_WITNESS_BYTES + 1],
    ] {
        assert!(
            verify_custody_witness(
                &receipt,
                candidate,
                &authority(&signer)?,
                &challenge(CustodyPurpose::Prepared)?,
                OBSERVED,
                &ctx()
            )
            .is_err()
        );
    }
    let mut value: Value = serde_json::from_slice(&raw)?;
    value["unexpected"] = json!(true);
    let unknown = format::canonical(&value, MAX_CUSTODY_MANIFEST_BYTES)?;
    assert!(
        verify(
            &receipt,
            &unknown,
            &attestation(&unknown),
            &signer,
            CustodyPurpose::Prepared
        )
        .is_err()
    );
    let mut duplicate = raw.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"schema_version\":1}");
    assert!(
        verify(
            &receipt,
            &duplicate,
            &attestation(&duplicate),
            &signer,
            CustodyPurpose::Prepared
        )
        .is_err()
    );
    let cancelled = ctx();
    cancelled.cancellation().cancel();
    assert!(matches!(
        verify_custody_witness(
            &receipt,
            &bytes,
            &authority(&signer)?,
            &challenge(CustodyPurpose::Prepared)?,
            OBSERVED,
            &cancelled
        ),
        Err(ReceiptError::Cancelled)
    ));
    Ok(())
}

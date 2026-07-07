use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use store::Stage;
use tokio_util::sync::CancellationToken;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[path = "capture_tests.rs"]
mod capture_tests;
#[path = "discovery_tests.rs"]
mod discovery_tests;
#[path = "http_publisher_tests.rs"]
mod http_publisher_tests;
#[path = "publisher_tests.rs"]
mod publisher_tests;
fn ctx() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))
        .unwrap_or_else(|_| unreachable!("constant valid context"))
}
fn owner() -> Uuid {
    Uuid::from_u128(0x40000000000040008000000000000001)
}
fn fixture() -> Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/cloudtrail-receipt/contract.json"
    ))
}
fn unhex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks_exact(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?);
    }
    Ok(out)
}
fn vector(id: &str) -> Result<(Vec<u8>, ReceiptBinding), Box<dyn std::error::Error>> {
    let f = fixture()?;
    let v = f["receipt_vectors"]
        .as_array()
        .ok_or("vectors")?
        .iter()
        .find(|v| v["id"] == id)
        .ok_or("vector")?;
    Ok((
        unhex(v["wire_hex"].as_str().ok_or("wire")?)?,
        ReceiptBinding::from_json(&format::canonical(&v["metadata"]["binding"], 65536)?)?,
    ))
}
fn root() -> Result<tempfile::TempDir, std::io::Error> {
    let d = tempfile::tempdir()?;
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700))?;
    Ok(d)
}
fn config(d: &tempfile::TempDir) -> Result<ReceiptConfig, ReceiptError> {
    ReceiptConfig::new(d.path().to_owned(), MIN_QUOTA_BYTES)
}
fn seal(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&Sha256::digest(body));
    out
}
fn initial_fixture(id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let f = fixture()?;
    let v = f["progress_vectors"]
        .as_array()
        .ok_or("vectors")?
        .iter()
        .find(|v| v["id"] == id)
        .ok_or("initial")?;
    unhex(v["wire_hex"].as_str().ok_or("wire")?)
}

#[test]
fn frozen_receipt_and_initial_control_goldens_execute_in_rust() -> TestResult {
    for (id, initial) in [
        ("prepared", "initial"),
        ("object-quarantine", "quarantine-initial"),
        ("strong", "strong-initial"),
    ] {
        let (bytes, _) = vector(id)?;
        let r = format::decode(bytes.clone(), &ctx())?;
        assert_eq!(r.bytes, bytes);
        assert_eq!(format::initial(&r, owner(), 1)?, initial_fixture(initial)?);
        format::verify_initial(&initial_fixture(initial)?, &r, owner(), 1)?;
    }
    Ok(())
}
#[test]
fn immutable_frames_hashes_lengths_and_unknown_fields_reject() -> TestResult {
    let (wire, _) = vector("prepared")?;
    for n in [0, 7, 35, 67, wire.len() - 1] {
        assert!(format::decode(wire[..n].to_vec(), &ctx()).is_err());
    }
    for offset in [0, 8, 12, 20, 28, 40, wire.len() - 40, wire.len() - 1] {
        let mut b = wire.clone();
        b[offset] ^= 1;
        assert!(format::decode(b, &ctx()).is_err());
    }
    let mut b = wire.clone();
    b.push(0);
    assert!(format::decode(b, &ctx()).is_err());
    for (offset, value) in [
        (8, (1024 * 1024 + 1) as u64),
        (12, (8 * 1024 * 1024 + 1) as u64),
        (20, 1025),
        (28, (16 * 1024 * 1024 + 1) as u64),
    ] {
        let mut b = wire[..wire.len() - 32].to_vec();
        let size = if offset == 8 { 4 } else { 8 };
        b[offset..offset + size].copy_from_slice(&value.to_be_bytes()[8 - size..]);
        assert!(format::decode(seal(&b), &ctx()).is_err());
    }
    for raw in [
        b"{\"a\":1,\"a\":2}".as_slice(),
        b"{\"a\":1,\"\\u0061\":2}",
        b"{\"a\":1.0}",
        b"{\"a\":true} ",
        b"{\"a\":-1}",
        b"{\"a\":18446744073709551616}",
        b"{\"a\":\"\\ud800\"}",
    ] {
        assert!(format::json(raw, 1024, 16, 1024).is_err());
    }
    Ok(())
}
#[test]
fn canonical_control_characters_and_literal_utf8_are_exact() -> TestResult {
    let v = json!({"é":[true,false,null,u64::MAX],"z":"café","a":"\0\u{8}\t\n\u{c}\r\"\\/"});
    let expected=b"{\"a\":\"\\u0000\\u0008\\u0009\\u000a\\u000c\\u000d\\\"\\\\/\",\"z\":\"caf\xc3\xa9\",\"\xc3\xa9\":[true,false,null,18446744073709551615]}";
    assert_eq!(format::canonical(&v, 1024)?, expected);
    assert_eq!(format::json(expected, 1024, 16, 1024)?, v);
    Ok(())
}
#[tokio::test]
async fn publish_inspect_reopen_and_exact_replay_preserve_all_bytes() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert!(s.inspect(b.clone(), ctx()).await?.is_none());
    let info = s.publish(bytes.clone(), b.clone(), ctx()).await?;
    assert_eq!(s.publish(bytes.clone(), b.clone(), ctx()).await?, info);
    let r = s.inspect(b.clone(), ctx()).await?.ok_or("receipt")?;
    let v = fixture()?;
    let expected = &v["receipt_vectors"][0];
    assert_eq!(
        r.original_bytes(),
        unhex(expected["original_hex"].as_str().ok_or("original")?)?
    );
    for i in 0..2 {
        assert_eq!(
            r.prepared_bytes(i),
            Some(
                expected["events_utf8"][i]
                    .as_str()
                    .ok_or("event")?
                    .as_bytes()
            )
        );
    }
    assert!(r.prepared_bytes(2).is_none());
    assert_eq!(s.metrics().admitted, 1);
    assert_eq!(s.metrics().replays, 1);
    assert_eq!(s.metrics().queue_capacity, 1);
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert_eq!(s.inspect(b, ctx()).await?.ok_or("receipt")?.bytes, bytes);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn exclusive_owner_and_generation_are_checked() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    s.publish(bytes, b, ctx()).await?;
    s.close(ctx()).await?;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, Uuid::new_v4(), 1, ctx()).await,
        Err(ReceiptError::Owner)
    ));
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 2, ctx()).await,
        Err(ReceiptError::Owner)
    ));
    Ok(())
}
#[tokio::test]
async fn full_binding_revocation_blocks_payload_access_and_mutation() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    s.publish(bytes.clone(), b.clone(), ctx()).await?;
    let mut changed = b.0.clone();
    changed["authority_revision"] = json!("revoked");
    let grant = ReceiptBinding::from_json(&format::canonical(&changed, 65536)?)?;
    assert!(matches!(
        s.inspect(grant.clone(), ctx()).await,
        Err(ReceiptError::Scope)
    ));
    assert!(matches!(
        s.publish(bytes, grant, ctx()).await,
        Err(ReceiptError::Scope)
    ));
    assert!(s.inspect(b, ctx()).await?.is_some());
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn occupied_unexpired_slot_and_changed_bytes_never_replace_receipt() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    s.publish(bytes.clone(), b.clone(), ctx()).await?;
    let (other, grant) = vector("object-quarantine")?;
    assert!(matches!(
        s.publish(other, grant, ctx()).await,
        Err(ReceiptError::Occupied)
    ));
    // Valid shape/checksum, same UUID, changed pinned original delivery metadata.
    let ml = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    let mut m: Value = serde_json::from_slice(&bytes[36..36 + ml])?;
    m["original"]["delivery_id"] = json!("fixture-message-002");
    let meta = format::canonical(&m, 1024 * 1024)?;
    assert_eq!(meta.len(), ml);
    let mut body = bytes[..bytes.len() - 32].to_vec();
    body[36..36 + ml].copy_from_slice(&meta);
    assert!(matches!(
        s.publish(seal(&body), b.clone(), ctx()).await,
        Err(ReceiptError::IdentityConflict)
    ));
    assert_eq!(s.inspect(b, ctx()).await?.ok_or("receipt")?.bytes, bytes);
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn corrupt_missing_control_and_orphan_files_fail_closed_without_cleanup() -> TestResult {
    for kind in ["corrupt", "missing", "temp"] {
        let d = root()?;
        let (bytes, b) = vector("prepared")?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let info = s.publish(bytes, b, ctx()).await?;
        s.close(ctx()).await?;
        match kind {
            "corrupt" => fs::write(d.path().join(format!("{}.src", info.id)), b"bad")?,
            "missing" => fs::remove_file(d.path().join("control"))?,
            _ => {
                fs::write(d.path().join("receipt.next"), b"orphan")?;
                fs::set_permissions(
                    d.path().join("receipt.next"),
                    fs::Permissions::from_mode(0o600),
                )?;
            }
        }
        assert!(
            ReceiptStore::open(config(&d)?, owner(), 1, ctx())
                .await
                .is_err()
        );
        assert!(d.path().join(format!("{}.src", info.id)).exists());
    }
    Ok(())
}
#[tokio::test]
async fn symlinks_hardlinks_and_nonprivate_roots_are_refused() -> TestResult {
    let d = root()?;
    let f = d.path().join("outside");
    fs::write(&f, b"keep")?;
    let other = root()?;
    std::os::unix::fs::symlink(&f, other.path().join("lock"))?;
    assert!(
        ReceiptStore::open(config(&other)?, owner(), 1, ctx())
            .await
            .is_err()
    );
    assert_eq!(fs::read(&f)?, b"keep");
    let linked = root()?;
    let l = linked.path().join("lock");
    fs::write(&l, b"")?;
    fs::set_permissions(&l, fs::Permissions::from_mode(0o600))?;
    fs::hard_link(&l, d.path().join("alias"))?;
    assert!(
        ReceiptStore::open(config(&linked)?, owner(), 1, ctx())
            .await
            .is_err()
    );
    let p = root()?;
    fs::set_permissions(p.path(), fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        ReceiptStore::open(config(&p)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Root)
    ));
    Ok(())
}
#[tokio::test]
async fn wrong_root_inode_or_permissions_poison_inspection() -> TestResult {
    for swap in [true, false] {
        let d = root()?;
        let parent = root()?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let (_, b) = vector("prepared")?;
        if swap {
            fs::rename(d.path(), parent.path().join("moved"))?;
            fs::create_dir(d.path())?;
            fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700))?;
        } else {
            fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755))?;
        }
        assert!(s.inspect(b, ctx()).await.is_err());
        s.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn interrupted_material_counts_against_root_quota() -> TestResult {
    let d = root()?;
    for (name, size) in [
        ("receipt.next", 32 * 1024 * 1024),
        ("30000000-0000-4000-8000-000000000001.src", 32 * 1024 * 1024),
    ] {
        let f = fs::File::create(d.path().join(name))?;
        f.set_len(size)?;
        fs::set_permissions(d.path().join(name), fs::Permissions::from_mode(0o600))?;
    }
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Quota)
    ));
    assert!(d.path().join("receipt.next").exists());
    Ok(())
}
#[tokio::test]
async fn unknown_entries_and_quarantined_ack_progress_are_not_adopted() -> TestResult {
    let d = root()?;
    fs::write(d.path().join("foreign"), b"keep")?;
    assert!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx())
            .await
            .is_err()
    );
    assert_eq!(fs::read(d.path().join("foreign"))?, b"keep");
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    s.publish(bytes, b, ctx()).await?;
    s.close(ctx()).await?;
    let f = fixture()?;
    let p = f["progress_vectors"]
        .as_array()
        .ok_or("vectors")?
        .iter()
        .find(|v| v["id"] == "intent")
        .ok_or("intent")?;
    fs::write(
        d.path().join("control"),
        unhex(p["wire_hex"].as_str().ok_or("wire")?)?,
    )?;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Ack)
    ));
    Ok(())
}
#[tokio::test]
async fn syscall_faults_hold_live_worker_and_reopen_settles_only_complete_controls() -> TestResult {
    for stage in [
        Stage::ReceiptTempSynced,
        Stage::ReceiptLinked,
        Stage::ReceiptRenamed,
        Stage::ReceiptDirectorySynced,
        Stage::ControlTempSynced,
        Stage::ControlLinked,
        Stage::ControlRenamed,
        Stage::ControlDirectorySynced,
    ] {
        let d = root()?;
        let (mut cfg, bytes, b) = (config(&d)?, vector("prepared")?.0, vector("prepared")?.1);
        cfg.hook = Some(Arc::new(move |s| {
            if s == stage {
                Err(ReceiptError::Io(std::io::ErrorKind::Other))
            } else {
                Ok(())
            }
        }));
        let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
        assert!(s.publish(bytes, b.clone(), ctx()).await.is_err());
        assert!(matches!(
            s.inspect(b.clone(), ctx()).await,
            Err(ReceiptError::Uncertain)
        ));
        s.close(ctx()).await?;
        let reopened = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await;
        if matches!(stage, Stage::ControlRenamed | Stage::ControlDirectorySynced) {
            let s = reopened?;
            assert!(s.inspect(b, ctx()).await?.is_some());
            s.close(ctx()).await?;
        } else {
            assert!(reopened.is_err(), "{stage:?}");
        }
    }
    Ok(())
}
#[tokio::test]
async fn exclusive_namespace_creation_does_not_clobber_injected_file() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let dest = d.path().join("30000000-0000-4000-8000-000000000001.src");
    let keep = dest.clone();
    let mut cfg = config(&d)?;
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::ReceiptTempSynced {
            fs::write(&dest, b"keep").map_err(io_error)?;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
        }
        Ok(())
    }));
    let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
    assert!(s.publish(bytes, b, ctx()).await.is_err());
    assert_eq!(fs::read(keep)?, b"keep");
    s.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn cancellation_before_dispatch_has_no_receipt_side_effect() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let c = ctx();
    c.cancellation().cancel();
    assert!(matches!(
        s.publish(bytes, b.clone(), c).await,
        Err(ReceiptError::Cancelled)
    ));
    assert!(s.inspect(b, ctx()).await?.is_none());
    assert_eq!(s.metrics().rejected, 1);
    s.close(ctx()).await?;
    Ok(())
}
#[test]
#[ignore = "subprocess-only crash helper"]
fn crash_child() -> TestResult {
    let Some(path) = std::env::var_os("SIGNAL_RECEIPT_TEST_ROOT") else {
        return Ok(());
    };
    let stage = std::env::var("SIGNAL_RECEIPT_TEST_STAGE")?;
    let mut cfg = ReceiptConfig::new(path.into(), MIN_QUOTA_BYTES)?;
    cfg.hook = Some(Arc::new(move |s| {
        if format!("{s:?}") == stage {
            std::process::exit(73);
        }
        Ok(())
    }));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (bytes, b) = vector("prepared")?;
        let s = ReceiptStore::open(cfg, owner(), 1, ctx()).await?;
        s.publish(bytes, b, ctx()).await?;
        s.close(ctx()).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
#[test]
fn process_loss_at_publication_milestones_reopens_or_holds_without_regeneration() -> TestResult {
    for stage in [
        Stage::ReceiptTempSynced,
        Stage::ReceiptLinked,
        Stage::ReceiptRenamed,
        Stage::ReceiptDirectorySynced,
        Stage::ControlTempSynced,
        Stage::ControlLinked,
        Stage::ControlRenamed,
        Stage::ControlDirectorySynced,
    ] {
        let d = root()?;
        let result = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "receipt::tests::crash_child", "--ignored"])
            .env("SIGNAL_RECEIPT_TEST_ROOT", d.path())
            .env("SIGNAL_RECEIPT_TEST_STAGE", format!("{stage:?}"))
            .output()?;
        assert_eq!(result.status.code(), Some(73));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let opened = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await;
            if matches!(stage, Stage::ControlRenamed | Stage::ControlDirectorySynced) {
                let s = opened?;
                let (_, b) = vector("prepared")?;
                let r = s.inspect(b, ctx()).await?.ok_or("receipt")?;
                assert_eq!(r.bytes, vector("prepared")?.0);
                s.close(ctx()).await?;
            } else {
                assert!(opened.is_err());
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[tokio::test]
async fn stalled_worker_retains_lock_bounds_queue_and_honors_queued_cancellation() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let mut cfg = config(&d)?;
    let (notify, entered) = tokio::sync::oneshot::channel();
    let notify = std::sync::Mutex::new(Some(notify));
    let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
    let gate = std::sync::Mutex::new(gate);
    cfg.hook = Some(Arc::new(move |s| {
        if s == Stage::ReceiptTempSynced
            && let Some(n) = notify.lock().map_err(|_| ReceiptError::Closed)?.take()
        {
            let _ = n.send(());
            let _ = gate
                .lock()
                .map_err(|_| ReceiptError::Closed)?
                .recv_timeout(Duration::from_secs(2));
        }
        Ok(())
    }));
    let s = Arc::new(ReceiptStore::open(cfg, owner(), 1, ctx()).await?);
    let p = s.clone();
    let binding = b.clone();
    let c = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(200))?;
    let publish = tokio::spawn(async move { p.publish(bytes, binding, c).await });
    tokio::time::timeout(Duration::from_secs(1), entered).await??;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    let q = s.clone();
    let binding = b.clone();
    let queued_context = ctx();
    let cancel = queued_context.cancellation().clone();
    let queued = tokio::spawn(async move { q.inspect(binding, queued_context).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while s.metrics().queue_depth != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(matches!(
        s.inspect(b.clone(), ctx()).await,
        Err(ReceiptError::Busy)
    ));
    cancel.cancel();
    assert!(matches!(queued.await?, Err(ReceiptError::Cancelled)));
    assert!(matches!(publish.await?, Err(ReceiptError::Timeout)));
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    assert_eq!(s.metrics().queue_capacity, 1);
    assert_eq!(s.metrics().queue_depth, 1);
    assert!(s.metrics().caller_uncertain >= 2);
    let _ = release.try_send(());
    let s = Arc::try_unwrap(s).map_err(|_| "test handle still shared")?;
    s.close(ctx()).await?;
    assert!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx())
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn lost_caller_after_commit_does_not_erase_publication() -> TestResult {
    let d = root()?;
    let (bytes, b) = vector("prepared")?;
    let mut cfg = config(&d)?;
    let (notify, entered) = tokio::sync::oneshot::channel();
    let notify = std::sync::Mutex::new(Some(notify));
    let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
    let gate = std::sync::Mutex::new(gate);
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::ControlDirectorySynced
            && let Some(n) = notify.lock().map_err(|_| ReceiptError::Closed)?.take()
        {
            let _ = n.send(());
            let _ = gate
                .lock()
                .map_err(|_| ReceiptError::Closed)?
                .recv_timeout(Duration::from_secs(2));
        }
        Ok(())
    }));
    let s = Arc::new(ReceiptStore::open(cfg, owner(), 1, ctx()).await?);
    let worker = s.clone();
    let binding = b.clone();
    let task = tokio::spawn(async move { worker.publish(bytes, binding, ctx()).await });
    tokio::time::timeout(Duration::from_secs(1), entered).await??;
    task.abort();
    let _ = task.await;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    let _ = release.try_send(());
    assert!(s.inspect(b, ctx()).await?.is_some());
    assert_eq!(s.metrics().admitted, 1);
    assert_eq!(s.metrics().unobserved_results, 1);
    let s = Arc::try_unwrap(s).map_err(|_| "test handle still shared")?;
    s.close(ctx()).await?;
    Ok(())
}
#[test]
fn metadata_and_scope_changes_fail_before_publication() -> TestResult {
    let f = fixture()?;
    let base = &f["receipt_vectors"][0]["metadata"]["binding"];
    for (k, v) in [
        ("recipient_accounts", json!([])),
        (
            "recipient_accounts",
            json!(["111122223333", "111122223333"]),
        ),
        ("regions", json!(["UPPER"])),
        ("profile_revision", json!("v2")),
        ("ack_requires_m2", json!(1)),
        ("queue_owner", json!("bad")),
        ("extra", json!(true)),
    ] {
        let mut b = base.clone();
        b[k] = v;
        assert!(ReceiptBinding::from_json(&format::canonical(&b, 65536)?).is_err());
    }
    let mut raw = format::canonical(base, 65536)?;
    raw.push(b'\n');
    assert!(ReceiptBinding::from_json(&raw).is_err());
    assert!(ReceiptConfig::new("/tmp/test".into(), MIN_QUOTA_BYTES - 1).is_err());
    Ok(())
}
fn changed_event(
    mut update: impl FnMut(&mut Value),
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let f = fixture()?;
    let v = &f["receipt_vectors"][0];
    let mut m = v["metadata"].clone();
    let original = unhex(v["original_hex"].as_str().ok_or("original")?)?;
    let mut events: Vec<Vec<u8>> = v["events_utf8"]
        .as_array()
        .ok_or("events")?
        .iter()
        .map(|v| v.as_str().ok_or("event").map(|s| s.as_bytes().to_vec()))
        .collect::<Result<_, _>>()?;
    let mut event: Value = serde_json::from_slice(&events[0])?;
    update(&mut event);
    events[0] = serde_json::to_vec(&event)?;
    m["records"][0]["prepared_sha256"] = json!(format::hex(&Sha256::digest(&events[0])));
    let meta = format::canonical(&m, 1024 * 1024)?;
    let mut wire = b"SIGSRC01".to_vec();
    wire.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    for n in [
        original.len(),
        events.len(),
        events.iter().map(Vec::len).sum(),
    ] {
        wire.extend_from_slice(&(n as u64).to_be_bytes());
    }
    wire.extend_from_slice(&meta);
    wire.extend_from_slice(&original);
    for (i, event) in events.iter().enumerate() {
        wire.extend_from_slice(&(event.len() as u32).to_be_bytes());
        wire.extend_from_slice(format::uuid(&m["records"][i]["prepared_id"])?.as_bytes());
        wire.extend_from_slice(&Sha256::digest(event));
        wire.extend_from_slice(event);
    }
    Ok(seal(&wire))
}
#[test]
fn event_payloads_remain_opaque_and_private_number_keys_are_literal() -> TestResult {
    let bytes = changed_event(|e| {
        e["attributes"]["numbers"] = json!([-1, 1.25, 18446744073709551616u128]);
        e["attributes"]["literal"] = json!({"$serde_json::private::Number":"9e999"});
    })?;
    let receipt = format::decode(bytes.clone(), &ctx())?;
    assert_eq!(receipt.bytes, bytes);
    let event: Value = serde_json::from_slice(receipt.prepared_bytes(0).ok_or("event")?)?;
    assert!(event["attributes"]["numbers"].is_array());
    Ok(())
}
#[test]
fn event_context_and_recipient_scope_are_checked_independently_of_digest() -> TestResult {
    for kind in ["scope", "time", "profile", "ref", "id"] {
        let bytes = changed_event(|e| match kind {
            "scope" => e["resource"]["account_id"] = json!("999988887777"),
            "time" => e["observed_at"] = json!("2026-10-07T12:00:02.000000000Z"),
            "profile" => e["attributes"]["normalizer"]["revision"] = json!("v2"),
            "ref" => e["attributes"]["evidence_ref"] = json!("receipt://wrong/record/0"),
            _ => e["id"] = json!("20000000-0000-4000-8000-000000000099"),
        })?;
        assert!(format::decode(bytes, &ctx()).is_err(), "{kind}");
    }
    Ok(())
}

#[path = "progress_tests.rs"]
mod progress_tests;

#[path = "handover_tests.rs"]
mod handover_tests;

#[path = "ack_tests.rs"]
mod ack_tests;

#[path = "retirement_tests.rs"]
mod retirement_tests;

#[path = "preparation_tests.rs"]
mod preparation_tests;

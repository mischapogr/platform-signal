use crate::{
    format::{self, CommitMetadata, HistoryBinding, ProfileDefinition, State, Timestamp},
    *,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, time::Duration};
use uuid::Uuid;
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../tests/fixtures/source-coverage/backend-vectors.json"
    ))?)
}
fn string(v: &Value) -> TestResult<&str> {
    Ok(v.as_str().ok_or("fixture string")?)
}
fn number(v: &Value) -> TestResult<u64> {
    Ok(v.as_u64().ok_or("fixture integer")?)
}
fn uuid(v: &Value) -> TestResult<Uuid> {
    Ok(Uuid::parse_str(string(v)?)?)
}
fn unhex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex width".into());
    }
    Ok((0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?)
}
fn hash(v: &Value) -> TestResult<[u8; 32]> {
    Ok(unhex(string(v)?)?.try_into().map_err(|_| "hash width")?)
}
pub(crate) fn clock(s: &str) -> TestResult<Timestamp> {
    Ok(Timestamp::parse(s)?)
}
fn ctx() -> OperationContext {
    OperationContext::new(Duration::from_secs(10))
}
fn config(path: &Path) -> CoverageConfig {
    CoverageConfig {
        directory: path.into(),
        ..CoverageConfig::default()
    }
}
pub(crate) fn prepared(item: &Value, f: &Value) -> TestResult<PreparedObservation> {
    let c = &item["input"];
    let profile = f["profiles"]
        .as_array()
        .ok_or("profiles")?
        .iter()
        .find(|p| p["id"] == c["profile"])
        .ok_or("profile reference")?;
    let binding = f["bindings"]
        .as_array()
        .ok_or("bindings")?
        .iter()
        .find(|p| p["id"] == c["binding"])
        .ok_or("binding reference")?;
    Ok(PreparedObservation::prepare(
        string(&c["raw_utf8"])?.as_bytes(),
        ProfileDefinition::parse(&serde_json::to_vec(&profile["input"])?)?,
        HistoryBinding::parse(&serde_json::to_vec(&binding["input"])?)?,
        AdmissionMetadata {
            authority_revision: string(&c["authority_revision"])?.into(),
            accepted_at: clock(string(&c["accepted_at"])?)?,
            replay_until: clock(string(&c["replay_until"])?)?,
            identity_until: clock(string(&c["identity_until"])?)?,
        },
    )?)
}
fn metadata(
    c: &Value,
    p: &BTreeMap<String, ProfileDefinition>,
    b: &BTreeMap<String, HistoryBinding>,
) -> TestResult<CommitMetadata> {
    let raw = string(&c["raw_utf8"])?.as_bytes();
    Ok(CommitMetadata {
        history_id: uuid(&c["history_id"])?,
        sequence: string(&c["sequence"])?.parse()?,
        record_id: uuid(&c["record_id"])?,
        raw_length: raw.len() as u32,
        content_sha256: format::sha256(raw),
        binding: b.get(string(&c["binding"])?).ok_or("binding")?.clone(),
        profile_fingerprint: p
            .get(string(&c["profile"])?)
            .ok_or("profile")?
            .fingerprint(),
        authority_revision: string(&c["authority_revision"])?.into(),
        accepted_at: clock(string(&c["accepted_at"])?)?,
        replay_until: clock(string(&c["replay_until"])?)?,
        identity_until: clock(string(&c["identity_until"])?)?,
        correction_of: if c["correction_of"].is_null() {
            None
        } else {
            Some(uuid(&c["correction_of"])?)
        },
    })
}

#[test]
fn frozen_profiles_bindings_commits_and_prefixes() -> TestResult {
    let f = fixture()?;
    let mut profiles = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    for v in f["profiles"].as_array().ok_or("profiles")? {
        let p = ProfileDefinition::parse(&serde_json::to_vec(&v["input"])?)?;
        assert_eq!(format::hex(p.encoded()), string(&v["encoded_hex"])?);
        assert_eq!(format::hex(&p.fingerprint()), string(&v["sha256"])?);
        assert_eq!(
            ProfileDefinition::decode(p.encoded())?.encoded(),
            p.encoded()
        );
        profiles.insert(string(&v["id"])?.to_owned(), p);
    }
    for v in f["bindings"].as_array().ok_or("bindings")? {
        let b = HistoryBinding::parse(&serde_json::to_vec(&v["input"])?)?;
        assert_eq!(format::hex(b.encoded()), string(&v["encoded_hex"])?);
        assert_eq!(
            format::hex(&format::sha256(b.encoded())),
            string(&v["sha256"])?
        );
        assert_eq!(HistoryBinding::decode(b.encoded())?.encoded(), b.encoded());
        bindings.insert(string(&v["id"])?.to_owned(), b);
    }
    for chain in f["chains"].as_array().ok_or("chains")? {
        let mut h = format::genesis(uuid(&chain["history_id"])?)?;
        assert_eq!(format::hex(&h), string(&chain["initial_prefix"])?);
        for v in chain["commits"].as_array().ok_or("commits")? {
            let m = metadata(&v["input"], &profiles, &bindings)?;
            let data = m.encode()?;
            assert_eq!(format::hex(&data), string(&v["encoded_hex"])?);
            assert_eq!(
                format::hex(&format::sha256(&data)),
                string(&v["commit_sha256"])?
            );
            assert_eq!(CommitMetadata::decode(&data)?.encode()?, data);
            h = format::prefix(h, &data);
            assert_eq!(format::hex(&h), string(&v["prefix_digest"])?);
        }
    }
    for v in f["standalone_commits"]
        .as_array()
        .ok_or("standalone commits")?
    {
        let data = metadata(&v["input"], &profiles, &bindings)?.encode()?;
        assert_eq!(format::hex(&data), string(&v["encoded_hex"])?);
        assert_eq!(
            format::hex(&format::sha256(&data)),
            string(&v["commit_sha256"])?
        );
        assert_eq!(CommitMetadata::decode(&data)?.encode()?, data);
    }
    Ok(())
}
#[test]
fn frozen_times_identity_and_state() -> TestResult {
    let f = fixture()?;
    for v in f["times"].as_array().ok_or("times")? {
        assert_eq!(
            clock(string(&v["input"])?)?.to_string(),
            string(&v["encoded_ascii"])?
        );
    }
    for v in f["identities"].as_array().ok_or("identities")? {
        let id = uuid(&v["history_id"])?;
        let encoded = format::identity(id)?;
        assert_eq!(format::hex(&encoded), string(&v["encoded_hex"])?);
        assert_eq!(format::read_identity(&encoded)?, id);
    }
    for v in f["states"].as_array().ok_or("states")? {
        let c = &v["input"];
        let s = State {
            history_id: uuid(&c["history_id"])?,
            committed_sequence: string(&c["committed_sequence"])?.parse()?,
            committed_prefix: hash(&c["committed_prefix"])?,
            payload_pruned_through: string(&c["payload_pruned_through"])?.parse()?,
            payload_anchor: hash(&c["payload_anchor"])?,
            identity_pruned_through: string(&c["identity_pruned_through"])?.parse()?,
            identity_anchor: hash(&c["identity_anchor"])?,
            clock_floor: clock(string(&c["clock_floor"])?)?,
            payload_count: number(&c["payload_count"])?,
            identity_count: number(&c["identity_count"])?,
            binding_count: number(&c["binding_count"])?,
            profile_count: number(&c["profile_count"])?,
            ledger_charge: number(&c["ledger_charge"])?,
        };
        let data = s.encode()?;
        assert_eq!(format::hex(&data), string(&v["encoded_hex"])?);
        assert_eq!(format::hex(&format::sha256(&data)), string(&v["sha256"])?);
        assert_eq!(State::decode(&data)?.encode()?, data);
    }
    assert_eq!(
        format::hex(&format::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    Ok(())
}
#[test]
fn codecs_reject_truncated_noncanonical_and_duplicate_inputs() -> TestResult {
    let f = fixture()?;
    let encoded = unhex(string(&f["chains"][0]["commits"][0]["encoded_hex"])?)?;
    for cut in 0..encoded.len() {
        assert!(
            CommitMetadata::decode(&encoded[..cut]).is_err(),
            "cut {cut}"
        );
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(CommitMetadata::decode(&trailing).is_err());
    for s in [
        "0000-01-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-10-07T00:00:60Z",
        "2026-10-07T00:00:00+00:00",
        "2026-10-07T00:00:00.1234567890Z",
    ] {
        assert!(Timestamp::parse(s).is_err());
    }
    let raw = serde_json::to_string(&f["bindings"][0]["input"])?;
    let bad = raw.replace(
        "\"attributes\":{}",
        "\"attributes\":{\"key\":\"a\",\"key\":\"b\"}",
    );
    assert!(HistoryBinding::parse(bad.as_bytes()).is_err());
    let mut id = format::identity(uuid(&f["chains"][0]["history_id"])?)?;
    id[30] ^= 1;
    assert!(format::read_identity(&id).is_err());
    Ok(())
}
#[tokio::test]
async fn initialize_append_load_restart_preserves_exact_bytes_and_receipts() -> TestResult {
    if let Ok(directory) = std::env::var("SIGNAL_COVERAGE_TEST_ROOT") {
        let f = fixture()?;
        let mut cfg = config(Path::new(&directory));
        cfg.operation_timeout = Duration::from_secs(300);
        let store = CoverageStore::initialize(
            cfg,
            uuid(&f["chains"][0]["history_id"])?,
            clock("2026-10-07T00:05:29Z")?,
        )
        .await?;
        for v in f["chains"][0]["commits"]
            .as_array()
            .ok_or("commits")?
            .iter()
            .take(2)
        {
            store.append(prepared(v, &f)?, ctx()).await?;
        }
        store.shutdown(ctx()).await?;
        return Ok(());
    }
    let t = tempfile::tempdir()?;
    let cfg = config(&t.path().join("coverage"));
    let f = fixture()?;
    let id = uuid(&f["chains"][0]["history_id"])?;
    let store = CoverageStore::initialize(cfg.clone(), id, clock("2026-10-07T00:05:29Z")?).await?;
    for (index, v) in f["chains"][0]["commits"]
        .as_array()
        .ok_or("commits")?
        .iter()
        .take(2)
        .enumerate()
    {
        let p = prepared(v, &f)?;
        let raw = p.raw.clone();
        let r = store.append(p, ctx()).await?;
        assert_eq!(r.sequence, (index + 1).to_string());
        assert_eq!(r.prefix_digest, string(&v["prefix_digest"])?);
        let loaded = store
            .load(r.record_id, ctx())
            .await?
            .ok_or("stored report")?;
        assert_eq!(loaded.receipt, r);
        assert_eq!(loaded.raw.as_deref(), Some(raw.as_slice()));
    }
    let m = store.metrics();
    assert_eq!(m.committed_sequence, 2);
    assert_eq!(m.payloads, 2);
    assert_eq!(m.bindings, 1);
    let before = store
        .load(
            uuid(&f["chains"][0]["commits"][0]["input"]["record_id"])?,
            ctx(),
        )
        .await?
        .ok_or("receipt")?
        .receipt;
    store.shutdown(ctx()).await?;
    let reopened = CoverageStore::open(cfg).await?;
    assert_eq!(reopened.metrics().committed_sequence, 2);
    assert_eq!(
        reopened
            .load(before.record_id, ctx())
            .await?
            .ok_or("recovered")?
            .receipt,
        before
    );
    reopened.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn child_process_crash_boundaries_preserve_acknowledged_prefix() -> TestResult {
    use std::{
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
    };
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let f = fixture()?;
    for stage in ["after_entry", "before_commit", "after_commit"] {
        let t = tempfile::tempdir()?;
        let cfg = config(&t.path().join("coverage"));
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "tests::initialize_append_load_restart_preserves_exact_bytes_and_receipts",
                    "--nocapture",
                ])
                .env("SIGNAL_COVERAGE_TEST_ROOT", &cfg.directory)
                .env("SIGNAL_COVERAGE_TEST_CHECKPOINT", stage)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let stdout = child.0.stdout.take().ok_or("child stdout")?;
        let (ready, wait) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.ok().as_deref() == Some("COVERAGE-CHECKPOINT") {
                    let _ = ready.send(true);
                    return;
                }
            }
            let _ = ready.send(false);
        });
        let checkpoint = wait.recv_timeout(Duration::from_secs(10));
        if !matches!(checkpoint, Ok(true)) {
            child.0.kill()?;
            child.0.wait()?;
            reader.join().map_err(|_| "reader panic")?;
            return Err("child checkpoint missing".into());
        }
        reader.join().map_err(|_| "reader panic")?;
        assert!(matches!(
            CoverageStore::open(cfg.clone()).await,
            Err(CoverageError::Locked)
        ));
        if let Ok(journal) = std::fs::metadata(cfg.directory.join("coverage.sqlite3-journal")) {
            assert!(journal.len() <= cfg.max_journal_bytes);
        }
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        let recovered = CoverageStore::open(cfg.clone()).await?;
        assert_eq!(
            recovered.metrics().committed_sequence,
            if stage == "after_commit" { 2 } else { 1 },
            "{stage}"
        );
        let first = &f["chains"][0]["commits"][0];
        let r = recovered
            .load(uuid(&first["input"]["record_id"])?, ctx())
            .await?
            .ok_or("old receipt")?;
        assert_eq!(r.receipt.prefix_digest, string(&first["prefix_digest"])?);
        assert_eq!(
            r.raw.as_deref(),
            Some(string(&first["input"]["raw_utf8"])?.as_bytes())
        );
        let second = recovered
            .load(
                uuid(&f["chains"][0]["commits"][1]["input"]["record_id"])?,
                ctx(),
            )
            .await?;
        if stage == "after_commit" {
            let p = prepared(&f["chains"][0]["commits"][1], &f)?;
            let original = second.ok_or("lost-response row")?.receipt;
            assert_eq!(
                original.prefix_digest,
                string(&f["chains"][0]["commits"][1]["prefix_digest"])?
            );
            assert_eq!(
                recovered
                    .retry(
                        original.clone(),
                        crate::intake_tests::submission(&p)?,
                        crate::intake_tests::intake(&p, "2026-10-07T00:06:31Z")?,
                        ctx()
                    )
                    .await?,
                IntakeOutcome::Replayed(original)
            );
            assert_eq!(recovered.metrics().committed_sequence, 2);
        } else {
            assert!(second.is_none());
        }
        recovered.shutdown(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn closed_store_relocation_preserves_identity_metadata_and_contents() -> TestResult {
    use std::os::unix::fs::DirBuilderExt;
    let t = tempfile::tempdir()?;
    let cfg = config(&t.path().join("original"));
    let f = fixture()?;
    let store = CoverageStore::initialize(
        cfg.clone(),
        uuid(&f["chains"][0]["history_id"])?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let receipt = store
        .append(prepared(&f["chains"][0]["commits"][0], &f)?, ctx())
        .await?;
    store.shutdown(ctx()).await?;
    let relocated = config(&t.path().join("relocated"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&relocated.directory)?;
    for name in [".lock", "identity", "coverage.sqlite3"] {
        std::fs::copy(cfg.directory.join(name), relocated.directory.join(name))?;
    }
    let reopened = CoverageStore::open(relocated).await?;
    assert_eq!(
        reopened
            .load(receipt.record_id, ctx())
            .await?
            .ok_or("copied receipt")?
            .receipt,
        receipt
    );
    assert_eq!(reopened.metrics().history_id, receipt.history_id);
    reopened.shutdown(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn ownership_initialization_missing_store_and_modes_fail_closed() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir()?;
    let cfg = config(&t.path().join("coverage"));
    let f = fixture()?;
    let id = uuid(&f["chains"][0]["history_id"])?;
    assert!(CoverageStore::open(cfg.clone()).await.is_err());
    assert!(!cfg.directory.exists());
    let store = CoverageStore::initialize(cfg.clone(), id, clock("2026-10-07T00:05:29Z")?).await?;
    assert!(matches!(
        CoverageStore::open(cfg.clone()).await,
        Err(CoverageError::Locked)
    ));
    assert!(
        CoverageStore::initialize(cfg.clone(), id, clock("2026-10-07T00:05:29Z")?)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::metadata(&cfg.directory)?.permissions().mode() & 0o777,
        0o700
    );
    for name in ["identity", ".lock", "coverage.sqlite3"] {
        assert_eq!(
            std::fs::metadata(cfg.directory.join(name))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    store.shutdown(ctx()).await?;
    let identity = std::fs::read(cfg.directory.join("identity"))?;
    std::fs::rename(
        cfg.directory.join("coverage.sqlite3"),
        t.path().join("saved.sqlite3"),
    )?;
    assert!(CoverageStore::open(cfg.clone()).await.is_err());
    assert!(!cfg.directory.join("coverage.sqlite3").exists());
    assert_eq!(std::fs::read(cfg.directory.join("identity"))?, identity);
    Ok(())
}
#[tokio::test]
async fn exact_identity_profile_revision_and_clock_rejections_do_not_mutate() -> TestResult {
    let t = tempfile::tempdir()?;
    let cfg = config(&t.path().join("coverage"));
    let f = fixture()?;
    let store = CoverageStore::initialize(
        cfg,
        uuid(&f["chains"][0]["history_id"])?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let item = &f["chains"][0]["commits"][0];
    let original = store.append(prepared(item, &f)?, ctx()).await?;
    assert!(matches!(
        store.append(prepared(item, &f)?, ctx()).await,
        Err(CoverageError::IdentityExists)
    ));
    let mut changed = f.clone();
    changed["profiles"][0]["input"]["max_interval_seconds"] = json!(3601);
    let mut second = changed["chains"][0]["commits"][1].clone();
    assert!(matches!(
        store.append(prepared(&second, &changed)?, ctx()).await,
        Err(CoverageError::ProfileRevisionConflict)
    ));
    second["input"]["accepted_at"] = json!("2026-10-07T00:05:29Z");
    let mut p = prepared(item, &f)?;
    p.record_id = Uuid::new_v4();
    p.admission.accepted_at = clock("2026-10-07T00:05:29Z")?;
    assert!(matches!(
        store.append(p, ctx()).await,
        Err(CoverageError::ClockRegression)
    ));
    assert_eq!(store.metrics().committed_sequence, 1);
    assert!(store.metrics().available);
    assert_eq!(
        store
            .load(original.record_id, ctx())
            .await?
            .ok_or("original")?
            .receipt,
        original
    );
    store.shutdown(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn count_key_ledger_quotas_and_reduced_caps_preserve_acknowledged_history() -> TestResult {
    let f = fixture()?;
    for kind in ["count", "key", "ledger"] {
        let t = tempfile::tempdir()?;
        let mut cfg = config(&t.path().join("coverage"));
        if kind == "count" {
            cfg.max_payloads = 1;
            cfg.max_identities = 1;
            cfg.max_bindings = 1;
        }
        if kind == "key" {
            cfg.max_bindings = 1;
        }
        let store = CoverageStore::initialize(
            cfg.clone(),
            uuid(&f["chains"][0]["history_id"])?,
            clock("2026-10-07T00:05:29Z")?,
        )
        .await?;
        let first = store
            .append(prepared(&f["chains"][0]["commits"][0], &f)?, ctx())
            .await?;
        let charge = store.metrics().ledger_bytes;
        store.shutdown(ctx()).await?;
        if kind == "ledger" {
            cfg.max_ledger_bytes = charge;
        }
        let store = CoverageStore::open(cfg.clone()).await?;
        let mut second = prepared(&f["chains"][0]["commits"][1], &f)?;
        if kind == "key" {
            let mut b = f["bindings"][0]["input"].clone();
            b["collection_config_revision"] = json!("fixture-config-v2");
            let mut raw: Value = serde_json::from_slice(&second.raw)?;
            raw["collection_config_revision"] = json!("fixture-config-v2");
            second = PreparedObservation::prepare(
                &serde_json::to_vec(&raw)?,
                second.profile,
                HistoryBinding::parse(&serde_json::to_vec(&b)?)?,
                second.admission,
            )?;
        }
        assert!(
            matches!(store.append(second, ctx()).await, Err(CoverageError::Quota)),
            "{kind}"
        );
        assert!(store.metrics().available);
        assert_eq!(store.metrics().ledger_bytes, charge);
        assert_eq!(
            store
                .load(first.record_id, ctx())
                .await?
                .ok_or("retained")?
                .receipt,
            first
        );
        store.shutdown(ctx()).await?;
        cfg.max_ledger_bytes = charge - 1;
        assert!(matches!(
            CoverageStore::open(cfg).await,
            Err(CoverageError::Quota)
        ));
    }
    Ok(())
}
#[tokio::test]
async fn prepared_gate_rejects_future_mismatch_invalid_and_oversized_receipt() -> TestResult {
    let f = fixture()?;
    let item = &f["chains"][0]["commits"][0];
    let mut earlier = item.clone();
    earlier["input"]["accepted_at"] = json!("2026-10-07T00:04:00Z");
    assert!(prepared(&earlier, &f).is_err());
    let mut mismatch = f.clone();
    mismatch["bindings"][0]["input"]["observer_id"] = json!("different-observer");
    assert!(prepared(item, &mismatch).is_err());
    let mut invalid = item.clone();
    invalid["input"]["raw_utf8"] = json!("{}");
    assert!(prepared(&invalid, &f).is_err());
    let mut excessive_retention = item.clone();
    excessive_retention["input"]["identity_until"] = json!("9999-12-31T23:59:59Z");
    assert!(prepared(&excessive_retention, &f).is_err());
    let t = tempfile::tempdir()?;
    let store = CoverageStore::initialize(
        config(&t.path().join("coverage")),
        uuid(&f["chains"][0]["history_id"])?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let mut p = prepared(item, &f)?;
    p.admission.authority_revision = "\u{0001}".repeat(1024);
    assert!(matches!(
        store.append(p, ctx()).await,
        Err(CoverageError::Invalid(_))
    ));
    assert_eq!(store.metrics().committed_sequence, 0);
    assert!(store.metrics().available);
    store.shutdown(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn live_receipt_read_rejects_changed_prefix_and_quarantines_worker() -> TestResult {
    let t = tempfile::tempdir()?;
    let cfg = config(&t.path().join("coverage"));
    let f = fixture()?;
    let store = CoverageStore::initialize(
        cfg.clone(),
        uuid(&f["chains"][0]["history_id"])?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let receipt = store
        .append(prepared(&f["chains"][0]["commits"][0], &f)?, ctx())
        .await?;
    // Deliberately bypass application ownership to simulate trusted-host file damage.
    let connection = rusqlite::Connection::open(cfg.directory.join("coverage.sqlite3"))?;
    connection.execute("UPDATE entries SET prefix=zeroblob(32)", [])?;
    drop(connection);
    assert!(matches!(
        store.load(receipt.record_id, ctx()).await,
        Err(CoverageError::Corrupt(_))
    ));
    assert!(!store.metrics().available);
    assert!(matches!(
        store.shutdown(ctx()).await,
        Err(CoverageError::Unavailable)
    ));
    assert!(CoverageStore::open(cfg).await.is_err());
    Ok(())
}

#[test]
fn pinned_sqlite_build_and_extreme_operation_duration() -> TestResult {
    let connection = rusqlite::Connection::open_in_memory()?;
    let (version, source_id): (String, String) =
        connection.query_row("SELECT sqlite_version(),sqlite_source_id()", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    assert_eq!(version, "3.53.2");
    assert_eq!(
        source_id,
        "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24"
    );
    let mut statement = connection.prepare("PRAGMA compile_options")?;
    let options = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "SQLITE-BUILD {}",
        serde_json::to_string(
            &json!({"version":version,"source_id":source_id,"compile_options":options})
        )?
    );
    let before = tokio::time::Instant::now();
    let bounded = OperationContext::new(Duration::MAX);
    assert!(bounded.deadline - before < Duration::from_secs(301));
    Ok(())
}
#[tokio::test]
async fn corruption_unknown_entries_and_symlinks_are_not_silently_repaired() -> TestResult {
    use std::os::unix::fs::symlink;
    let f = fixture()?;
    for kind in [
        "payload", "profile", "binding", "state", "sidecar", "schema", "unknown", "symlink",
    ] {
        let t = tempfile::tempdir()?;
        let cfg = config(&t.path().join("coverage"));
        let store = CoverageStore::initialize(
            cfg.clone(),
            uuid(&f["chains"][0]["history_id"])?,
            clock("2026-10-07T00:05:29Z")?,
        )
        .await?;
        store
            .append(prepared(&f["chains"][0]["commits"][0], &f)?, ctx())
            .await?;
        store.shutdown(ctx()).await?;
        if ["payload", "profile", "binding", "state", "schema"].contains(&kind) {
            let c = rusqlite::Connection::open(cfg.directory.join("coverage.sqlite3"))?;
            let sql = match kind {
                "payload" => "UPDATE entries SET raw=x'7b7d'",
                "profile" => "UPDATE profiles SET definition=zeroblob(100)",
                "binding" => "UPDATE bindings SET key=zeroblob(100)",
                "state" => "UPDATE state SET checksum=zeroblob(32)",
                _ => "CREATE TABLE unrelated(x TEXT)",
            };
            c.execute_batch("PRAGMA foreign_keys=OFF")?;
            c.execute_batch(sql)?;
            c.close().map_err(|(_, e)| e)?;
        } else if kind == "sidecar" {
            let mut bytes = std::fs::read(cfg.directory.join("identity"))?;
            bytes[9] ^= 1;
            std::fs::write(cfg.directory.join("identity"), bytes)?;
        } else if kind == "unknown" {
            std::fs::write(cfg.directory.join("unexpected"), b"preserve")?;
        } else {
            std::fs::rename(
                cfg.directory.join("identity"),
                t.path().join("real-identity"),
            )?;
            symlink(
                t.path().join("real-identity"),
                cfg.directory.join("identity"),
            )?;
        }
        let before = std::fs::read(cfg.directory.join("coverage.sqlite3"))?;
        assert!(CoverageStore::open(cfg.clone()).await.is_err(), "{kind}");
        assert_eq!(
            std::fs::read(cfg.directory.join("coverage.sqlite3"))?,
            before,
            "{kind}"
        );
    }
    Ok(())
}
#[tokio::test]
async fn actual_page_exhaustion_recovers_previously_committed_prefix() -> TestResult {
    let t = tempfile::tempdir()?;
    let mut cfg = config(&t.path().join("coverage"));
    cfg.max_database_pages = 16;
    let f = fixture()?;
    let store = CoverageStore::initialize(
        cfg.clone(),
        uuid(&f["chains"][0]["history_id"])?,
        clock("2026-10-07T00:05:29Z")?,
    )
    .await?;
    let receipt = store
        .append(prepared(&f["chains"][0]["commits"][0], &f)?, ctx())
        .await?;
    let mut p = prepared(&f["chains"][0]["commits"][1], &f)?;
    let mut raw: Value = serde_json::from_slice(&prepared(&f["chains"][0]["commits"][0], &f)?.raw)?;
    raw["record_id"] = json!(p.record_id.to_string());
    raw["provenance"]["proof_refs"] = json!(
        (0..32)
            .map(|i| format!("fixture://proof/{i}/{}", "x".repeat(900)))
            .collect::<Vec<_>>()
    );
    raw["resource_scope"]["attributes"] = json!(
        (0..16)
            .map(|i| (format!("key{i}"), "x".repeat(900)))
            .collect::<BTreeMap<_, _>>()
    );
    let mut binding = f["bindings"][0]["input"].clone();
    binding["resource_scope"] = raw["resource_scope"].clone();
    p = PreparedObservation::prepare(
        &serde_json::to_vec(&raw)?,
        p.profile,
        HistoryBinding::parse(&serde_json::to_vec(&binding)?)?,
        p.admission,
    )?;
    let result = store.append(p, ctx()).await;
    assert!(
        matches!(result, Err(CoverageError::OutcomeUnknown)),
        "{result:?}"
    );
    let _ = store.shutdown(ctx()).await;
    let reopened = CoverageStore::open(cfg).await?;
    assert_eq!(reopened.metrics().committed_sequence, 1);
    assert_eq!(
        reopened
            .load(receipt.record_id, ctx())
            .await?
            .ok_or("old ack")?
            .receipt,
        receipt
    );
    reopened.shutdown(ctx()).await?;
    Ok(())
}

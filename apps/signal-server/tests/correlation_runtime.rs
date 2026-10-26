#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "../../../crates/signal-rules/tests/support/correlation_d14.rs"]
#[allow(dead_code)]
mod support;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_collector_sdk::runtime_metadata as sdk;
use signal_event::Source;
use signal_rules::correlation::d14::*;
use std::path::PathBuf;
use support::*;
use uuid::Uuid;

#[test]
#[ignore = "requires reviewed owned native capture report and exact retained source/binaries"]
fn owned_native_metadata_composes_sdk_core_and_independent_historical_classification() -> Result {
    let directory = PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR")?);
    let report: Value = serde_json::from_slice(&std::fs::read(directory.join("report.json"))?)?;
    assert_eq!(report["passed"], true);
    assert_eq!(report["source_unchanged"], true);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, digest) in report["source_sha256"].as_object().ok_or("source map")? {
        let actual: String = Sha256::digest(std::fs::read(root.join(path))?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, digest.as_str().ok_or("digest")?);
    }
    for (path, digest) in report["executable_sha256"].as_object().ok_or("ELF map")? {
        let actual: String = Sha256::digest(std::fs::read(path)?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, digest.as_str().ok_or("ELF digest")?);
    }
    let mut matched = Vec::new();
    let mut negative = Vec::new();
    let mut decoded = 0;
    let mut gaps = 0;
    for case in report["cases"].as_array().ok_or("cases")? {
        let name = case["case"].as_str().ok_or("case")?;
        let raw = std::fs::read(directory.join(format!("{name}.raw.jsonl")))?;
        let first: Value =
            serde_json::from_slice(raw.split(|b| *b == b'\n').next().ok_or("line")?)?;
        let mut digest = [0; 32];
        let hex = first["config_sha256"].as_str().ok_or("config")?;
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
        }
        let host = first["host"].as_str().ok_or("host")?;
        let profile = sdk::Profile::new(
            host,
            first["boot_id"].as_str().ok_or("boot")?.parse()?,
            first["capture_id"].as_str().ok_or("capture")?.parse()?,
            digest,
            first["audit_arch"].as_u64().ok_or("ABI")? as u32,
        )?;
        let mut cfg = config();
        cfg.sources[0].host = host.into();
        cfg.sources[0].metadata_config_sha256 = digest;
        let c = context();
        let binding = RuntimeBinding::new(cfg, &c)?;
        let last: Value = serde_json::from_slice(
            raw.split(|b| *b == b'\n')
                .rfind(|s| !s.is_empty())
                .ok_or("terminal")?,
        )?;
        let from = ns(first["timestamp_ns"].as_u64().ok_or("first timestamp")?);
        let frontier = ns(last["timestamp_ns"].as_u64().ok_or("last timestamp")?);
        let checked = frontier + chrono::TimeDelta::seconds(2);
        // Independent host-fixture verdicts from the qualified supervisor report;
        // these are simulated authority, never a producer coverage flag.
        let complete = case["exit_code"] == 0;
        let s = &binding.config().sources[0];
        let source = RuntimeVerification {
            source: signal_rules::correlation::Verification {
                stream: s.stream,
                position: case["records"].as_u64().ok_or("records")?,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: binding.config().authority_keys_sha256,
                verification_reference: format!("fixture://qualified-supervisor/{name}"),
                verified_at: checked,
                verified_until: checked + chrono::TimeDelta::seconds(30),
                now: checked,
                coverage_from: from,
                frontier,
                complete,
                authenticated: true,
            },
            capture: CaptureEvidence {
                enrollment_sha256: binding.enrollment_sha256(),
                metadata_only: true,
                execution_continuity: true,
                clock_continuity: true,
            },
        };
        let policies = binding
            .config()
            .policy_authorities
            .iter()
            .map(|a| PolicyCoverageVerification {
                enrollment_sha256: binding.enrollment_sha256(),
                authority: a.id,
                authority_binding: a.binding,
                config_revision: a.config_revision.clone(),
                authority_keys_sha256: a.authority_keys_sha256,
                policy_revision: a.policy_revision.clone(),
                policy_config_sha256: a.policy_config_sha256,
                reference: format!("fixture://independent-policy-coverage/{name}"),
                verified_at: checked,
                verified_until: checked + chrono::TimeDelta::seconds(30),
                now: checked,
                coverage_from: from,
                frontier,
                complete: true,
                authenticated: true,
            })
            .collect();
        let epoch = RuntimeEpoch::new(&binding, vec![source], policies, &c)?;
        assert_eq!(epoch.has_coverage_gap(&binding, &c)?, !complete);
        let mut continuity = sdk::Continuity::new();
        let mut reads = Vec::new();
        let mut connects = Vec::new();
        for (ordinal, line) in raw.split_inclusive(|b| *b == b'\n').enumerate() {
            let native = continuity.admit(line, &profile)?;
            let event = sdk::normalize(
                line,
                &profile,
                Source {
                    source_type: "runtime".into(),
                    name: Some("owned-source".into()),
                },
                Uuid::new_v4(),
                ns(native.observed_ns + 1_000_000_000),
            )?;
            let input = Input::new(&binding, Uuid::from_u128(1), &event, &c)?;
            epoch.verify_input(&binding, &input, ordinal as u64 + 1, &c)?;
            assert_eq!(
                serde_json::to_value(input.process())?,
                serde_json::to_value(&native.process)?
            );
            assert_eq!(
                serde_json::to_value(input.operation())?,
                serde_json::to_value(&native.operation)?
            );
            decoded += 1;
            let role = match input.operation() {
                Operation::Read {
                    object,
                    result,
                    error: false,
                    ..
                } if object.object_type == 0o100000 && *result > 0 => Some(Role::Asset),
                Operation::Connect {
                    object,
                    result: 0,
                    error: false,
                    ..
                } if object.object_type == 0o140000 => Some(Role::Destination),
                Operation::Gap { .. } => {
                    gaps += 1;
                    None
                }
                _ => None,
            };
            if let Some(role) = role {
                let authority = binding
                    .config()
                    .policy_authorities
                    .iter()
                    .find(|a| a.role == role)
                    .ok_or("authority")?;
                let interval = input.operation().interval().ok_or("interval")?;
                // Synthetic private fixture policy, independently supplied by
                // the host test. The alternate FD-reuse file is not protected.
                // No classification flag is read from native/normalized data.
                let yes = role == Role::Destination || name != "reuse";
                let now = ns(native.observed_ns + 1_000_000_000);
                let proof = Verification {
                    claim: input.claim(&c)?,
                    authority: authority.id,
                    authority_binding: authority.binding,
                    config_revision: authority.config_revision.clone(),
                    authority_keys_sha256: authority.authority_keys_sha256,
                    policy_revision: authority.policy_revision.clone(),
                    policy_config_sha256: authority.policy_config_sha256,
                    decision: if role == Role::Asset {
                        Decision::Asset {
                            protected_credential: yes,
                        }
                    } else {
                        Decision::Destination { suspicious: yes }
                    },
                    covered_from: ns(interval.entry_ns),
                    covered_through: ns(interval.exit_ns),
                    reference: format!("fixture://private-policy/{name}/{role:?}"),
                    verified_at: now,
                    verified_until: now + chrono::TimeDelta::seconds(30),
                    now,
                    authenticated: true,
                };
                let evidence = CurrentDecision::new(&binding, &input, proof, &c)?
                    .retained(&binding, &input, &c)?;
                if role == Role::Asset {
                    reads.push((input, evidence));
                } else {
                    connects.push((input, evidence));
                }
            } else {
                assert!(input.claim(&c).is_err());
            }
        }
        if let (Some((read, asset)), Some((connect, destination))) =
            (reads.first(), connects.last())
        {
            let outcome = relation(&binding, read, asset, connect, destination, &c)?;
            if name == "exec" || name == "reuse" {
                assert_eq!(outcome, Relation::NotApplicable, "{name}");
                negative.push(name.to_owned());
            } else {
                assert_eq!(outcome, Relation::Match, "{name}");
                matched.push(name.to_owned());
            }
        }
    }
    matched.sort();
    negative.sort();
    assert_eq!(matched, ["execfail", "output", "read", "rename"]);
    assert_eq!(negative, ["exec", "reuse"]);
    assert_eq!(gaps, 8);
    assert_eq!(
        decoded,
        report["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["records"].as_u64().unwrap())
            .sum::<u64>()
    );
    Ok(())
}

#[path = "support/runtime_lifecycle.rs"]
#[allow(dead_code)]
mod lifecycle;

async fn qualify_native_lifecycle(
    case: &lifecycle::NativeCase,
    directory: &std::path::Path,
    missing_destination: bool,
) -> Result<Value> {
    use signal_rules::correlation::{
        Admission, Status,
        history::{self, Answer, Lookup, Query},
        journal::{self, Applied, RuntimeAction},
    };
    let c = context();
    let b = &case.binding;
    let db = lifecycle::open(b, &directory.join("runtime.sqlite")).await?;
    let record = lifecycle::ingest(case, &db, missing_destination).await?;
    let state = journal::recover_runtime(b, &record, &c)?;
    let expected = if missing_destination {
        Some(Status::Indeterminate)
    } else {
        match case.name.as_str() {
            "read" | "rename" | "execfail" | "output" => Some(Status::Match),
            "eof" | "error" | "fault" | "open" | "reuse" | "exec" | "socket" | "ipv6" => {
                Some(Status::NoMatch)
            }
            "clone" | "pread" | "mmap" | "signal" | "hang" | "cancel" | "dynamic" | "compat" => {
                Some(Status::Indeterminate)
            }
            "badconnect" => None,
            _ => return Err("unexpected native case".into()),
        }
    };
    assert_eq!(
        state.episodes().len(),
        usize::from(expected.is_some()),
        "{}",
        case.name
    );
    if let Some(status) = expected {
        assert_eq!(state.episodes()[0].status, status, "{}", case.name);
    }
    let originals = record.outbox.clone();
    let mut allowed = Vec::new();
    for e in state.episodes() {
        for scope in &e.contributors {
            if !allowed.contains(scope) {
                allowed.push(scope.clone());
            }
        }
    }
    if !originals.is_empty() {
        assert!(
            lifecycle::publish_effects(directory, &record, &allowed[..allowed.len() - 1]).is_err()
        );
    }
    lifecycle::publish_effects(directory, &record, &allowed)?;
    let record = if originals.is_empty() {
        record
    } else {
        db.retire(record.revision, record.outbox.len(), context())
            .await?
    };
    let record = lifecycle::seal(case, b, &db, &record, 2000).await?;
    let mut host = lifecycle::Host::new(directory);
    let (a, index) = host.publish(b, &record)?;
    host = lifecycle::Host::reload(directory)?;
    host.prove_partial_refusal(index)?;
    let state = journal::recover_runtime(b, &record, &c)?;
    let receipt = host.receipt(
        b,
        &state,
        a,
        index,
        case.terminal + chrono::TimeDelta::seconds(4),
        &c,
    )?;
    let pruned = history::prune_runtime(
        b,
        &record,
        host.archives.get(&a).ok_or("archive")?,
        &receipt,
        &case.epoch(b, record.checkpoint, 2000, &c)?,
        &c,
    )?
    .commit(&db)
    .await?;
    assert_eq!(
        journal::recover_runtime(b, &pruned, &c)?
            .metrics(b)?
            .retained_events,
        0
    );
    let selected_id = state
        .episodes()
        .first()
        .and_then(|e| e.originals.last())
        .map_or(case.events[0].id, |e| e.id);
    let selected = case
        .events
        .iter()
        .find(|e| e.id == selected_id)
        .ok_or("selected input")?;
    let input = Input::new(b, b.config().sources[0].stream, selected, &c)?;
    let ep = case.epoch(b, record.checkpoint, 2000, &c)?;
    let query = Query::new_runtime(b, &input, &ep, &c)?;
    // Missing index is an unavailable custody result, never an Absent answer.
    let index_path = directory.join("complete-index-0.json");
    let withheld = directory.join("withheld-index.json");
    std::fs::rename(&index_path, &withheld)?;
    let missing = lifecycle::Host::reload(directory)
        .and_then(|h| h.answers(&journal::recover_runtime(b, &pruned, &c)?, &query));
    std::fs::rename(&withheld, &index_path)?;
    assert!(missing.is_err());
    host = lifecycle::Host::reload(directory)?;
    let (a2, index2) = host.publish(b, &pruned)?;
    host = lifecycle::Host::reload(directory)?;
    let new = case.next_binding(&c)?;
    let old_state = journal::recover_runtime(b, &pruned, &c)?;
    let receipt = host.receipt(
        &new,
        &old_state,
        a2,
        index2,
        case.terminal + chrono::TimeDelta::seconds(4),
        &c,
    )?;
    let p = history::carry_runtime(
        b,
        &db,
        &pruned,
        host.archives.get(&a2).ok_or("carry archive")?,
        &receipt,
        &new,
        &case.epoch(&new, pruned.checkpoint, 2000, &c)?,
        &c,
    )
    .await?;
    let target_path = directory.join("new.sqlite");
    let target = lifecycle::open(&new, &target_path).await?;
    let carried = p.commit(&target).await?;
    let mut alias = selected.clone();
    alias.id = Uuid::new_v5(&new.config().partition, b"cold-native-alias");
    alias.observed_at += chrono::TimeDelta::seconds(2);
    let input = Input::new(&new, new.config().sources[0].stream, &alias, &c)?;
    let ep = case.epoch(&new, carried.checkpoint + 1, 2000, &c)?;
    let query = Query::new_runtime(&new, &input, &ep, &c)?;
    let state = journal::recover_runtime(&new, &carried, &c)?;
    let (canonical, native) = host.answers(&state, &query)?;
    assert!(canonical.is_none());
    let native = native.ok_or("complete native witness")?;
    let ca = Answer::Absent;
    let na = Answer::Known(&native);
    let anchor = state.archive_anchor().ok_or("carried root")?.clone();
    let claim = history::Claim::lookup(&query, &anchor, &ca, &na, &c)?;
    let authority = lifecycle::authority(
        &new,
        claim,
        case.terminal + chrono::TimeDelta::seconds(4),
        &c,
    )?;
    let lookup = Lookup::new(query, anchor, ca, na, authority, &c)?;
    let opposite = case.decision(&new, &input, true, false, &c)?;
    let p = journal::prepare_runtime_checked(
        &new,
        Some(&carried),
        carried.checkpoint + 1,
        RuntimeAction::Admit {
            input: &input,
            position: carried.checkpoint + 1,
            decision: opposite.as_ref(),
        },
        &ep,
        Some(&lookup),
        &c,
    )?;
    assert!(matches!(
        p.applied(),
        Applied::Admission(Admission::Duplicate)
    ));
    let after = p.commit(&target).await?;
    assert!(after.outbox.is_empty());
    assert!(
        journal::recover_runtime(&new, &after, &c)?
            .episodes()
            .is_empty()
    );
    for original in &originals {
        let reference = native.effect().ok_or("original outcome ref")?;
        assert_eq!(host.effect(reference)?, *original);
        assert_eq!(
            std::fs::read(directory.join(format!("published-{}.json", original.id)))?,
            original.bytes
        );
        let episode: signal_rules::correlation::Episode = serde_json::from_slice(&original.bytes)?;
        assert!(
            episode
                .contributors
                .iter()
                .any(|s| s.account.as_deref() == Some("fixture-old-policy-account"))
        );
        assert!(
            !episode
                .contributors
                .iter()
                .any(|s| s.account.as_deref() == Some("fixture-new-policy-account"))
        );
    }
    target.shutdown(context()).await?;
    let target = lifecycle::open(&new, &target_path).await?;
    assert_eq!(target.load(context()).await?, Some(after));
    target.shutdown(context()).await?;
    db.shutdown(context()).await?;
    Ok(
        serde_json::json!({"case":case.name,"missing_destination":missing_destination,"raw_sha256":lifecycle::hex(&case.raw_sha),"records":case.events.len(),"episodes":originals.len(),"status":expected,"capture_complete_synthetic_verdict":case.complete,"filesystem_index_reopened":true,"unavailable_index_refused":true,"partial_index_refused":true,"original_scope_publication_required":!originals.is_empty(),"retirement_and_scope_key_carry":true,"cold_alias_preserved_original":true,"second_reopen_exact":true}),
    )
}
#[tokio::test]
#[ignore = "requires reviewed native corpus and explicit owned lifecycle output"]
async fn owned_native_metadata_composes_runtime_journal_history_and_carry() -> Result {
    let native = PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR")?);
    let output = lifecycle::output_directory("SIGNAL_RUNTIME_LIFECYCLE_OUTPUT")?;
    let report = lifecycle::qualified_report(&native)?;
    let mut outcomes = Vec::new();
    let mut native_records = 0;
    let mut extra = None;
    for row in report["cases"].as_array().ok_or("cases")? {
        let name = row["case"].as_str().ok_or("case")?;
        let case = lifecycle::NativeCase::load(&native, name, name)?;
        let directory = output.join(name);
        lifecycle::owned_directory(&directory)?;
        native_records += case.events.len();
        outcomes.push(qualify_native_lifecycle(&case, &directory, false).await?);
        if name == "read" {
            let case = lifecycle::NativeCase::load(&native, name, "read-missing-destination")?;
            let directory = output.join("read-missing-destination");
            lifecycle::owned_directory(&directory)?;
            extra = Some(qualify_native_lifecycle(&case, &directory, true).await?);
        }
    }
    assert_eq!(outcomes.len(), 21);
    assert_eq!(native_records, 66);
    assert_eq!(
        outcomes
            .iter()
            .map(|v| v["episodes"].as_u64().unwrap())
            .sum::<u64>(),
        20
    );
    let count = |status: Value| outcomes.iter().filter(|v| v["status"] == status).count();
    assert_eq!(count(serde_json::json!("match")), 4);
    assert_eq!(count(serde_json::json!("no_match")), 8);
    assert_eq!(count(serde_json::json!("indeterminate")), 8);
    assert_eq!(count(Value::Null), 1);
    lifecycle::write_new(
        &output.join("lifecycle-report.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version":1,"status":"passed_local_retained_native_composition","native_report_sha256":lifecycle::hex(&lifecycle::sha(&std::fs::read(native.join("report.json"))?)),"native_cases":21,"native_records":66,"episodes":20,"source_policy_custody_and_supervised_preexec_authority":"synthetic current host verdicts, not producer flags or live capture authority","native_capture":"retained previously qualified owned LinuxAMD64 metadata","cases":outcomes,"extra_missing_classification_scenario":extra}),
        )?,
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "owned native lifecycle crash child only"]
async fn native_runtime_custody_crash_child() -> Result {
    use signal_rules::correlation::{history, journal};
    let native = PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR")?);
    let directory = PathBuf::from(std::env::var("SIGNAL_RUNTIME_CUSTODY_CHILD")?);
    let phase = std::env::var("SIGNAL_RUNTIME_CUSTODY_PHASE")?;
    assert!(["indexed", "pruned", "carried"].contains(&phase.as_str()));
    let case = lifecycle::NativeCase::load(&native, "read", "read")?;
    let c = context();
    let b = &case.binding;
    let db = lifecycle::open(b, &directory.join("runtime.sqlite")).await?;
    let r = lifecycle::ingest(&case, &db, false).await?;
    assert_eq!(r.outbox.len(), 1);
    let original = r.outbox[0].clone();
    let state = journal::recover_runtime(b, &r, &c)?;
    lifecycle::publish_effects(&directory, &r, &state.episodes()[0].contributors)?;
    lifecycle::write_new(
        &directory.join("original.json"),
        &serde_json::to_vec(&original)?,
    )?;
    let r = db.retire(r.revision, 1, context()).await?;
    let r = lifecycle::seal(&case, b, &db, &r, 2000).await?;
    lifecycle::write_new(
        &directory.join("source-baseline.json"),
        &serde_json::to_vec(&r)?,
    )?;
    let mut host = lifecycle::Host::new(&directory);
    let (a, index) = host.publish(b, &r)?;
    let state = journal::recover_runtime(b, &r, &c)?;
    let receipt = host.receipt(
        b,
        &state,
        a,
        index,
        case.terminal + chrono::TimeDelta::seconds(4),
        &c,
    )?;
    let p = history::prune_runtime(
        b,
        &r,
        host.archives.get(&a).ok_or("archive")?,
        &receipt,
        &case.epoch(b, r.checkpoint, 2000, &c)?,
        &c,
    )?;
    lifecycle::write_new(
        &directory.join("prune-intent.json"),
        &serde_json::to_vec(p.record())?,
    )?;
    if phase != "indexed" {
        let r = p.commit(&db).await?;
        if phase == "carried" {
            let (a, index) = host.publish(b, &r)?;
            let new = case.next_binding(&c)?;
            let state = journal::recover_runtime(b, &r, &c)?;
            let receipt = host.receipt(
                &new,
                &state,
                a,
                index,
                case.terminal + chrono::TimeDelta::seconds(4),
                &c,
            )?;
            let p = history::carry_runtime(
                b,
                &db,
                &r,
                host.archives.get(&a).ok_or("archive")?,
                &receipt,
                &new,
                &case.epoch(&new, r.checkpoint, 2000, &c)?,
                &c,
            )
            .await?;
            lifecycle::write_new(
                &directory.join("carry-intent.json"),
                &serde_json::to_vec(p.record())?,
            )?;
            let target = lifecycle::open(&new, &directory.join("new.sqlite")).await?;
            p.commit(&target).await?;
            // Keep both generations' leases until the owner kills this child;
            // no generation activation/source ACK occurs in this fixture.
            lifecycle::write_new(&directory.join("ready"), phase.as_bytes())?;
            std::future::pending::<()>().await;
            drop(target);
        }
    }
    lifecycle::write_new(&directory.join("ready"), phase.as_bytes())?;
    std::future::pending::<()>().await;
    println!("NATIVE-D14-ACTIVATED-OR-ACKNOWLEDGED");
    Ok(())
}
struct OwnedNativeCustodyChild(std::process::Child);
impl Drop for OwnedNativeCustodyChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[tokio::test]
#[ignore = "requires reviewed native corpus and owned custody process output"]
async fn owned_native_runtime_custody_process_crash() -> Result {
    use signal_rules::{
        correlation::{
            Admission, Status,
            history::{self, Answer, Lookup, Query},
            journal::{self, Applied, RuntimeAction},
        },
        state_journal::{Output, Record},
    };
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let native = PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR")?).canonicalize()?;
    let output = lifecycle::output_directory("SIGNAL_RUNTIME_CUSTODY_OUTPUT")?;
    let mut cases = Vec::new();
    for phase in ["indexed", "pruned", "carried"] {
        let directory = output.join(phase);
        lifecycle::owned_directory(&directory)?;
        let log = std::fs::File::create_new(directory.join("child.log"))?;
        let mut child = OwnedNativeCustodyChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--ignored",
                    "--exact",
                    "native_runtime_custody_crash_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("SIGNAL_RUNTIME_NATIVE_DIR", &native)
                .env("SIGNAL_RUNTIME_CUSTODY_CHILD", &directory)
                .env("SIGNAL_RUNTIME_CUSTODY_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let pid = child.0.id();
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if std::fs::read(directory.join("ready")).ok().as_deref() == Some(phase.as_bytes()) {
                break;
            }
            if child.0.try_wait()?.is_some() {
                return Err(format!("native custody child exited before {phase} witness").into());
            }
            if Instant::now() >= deadline {
                return Err("native custody witness timeout".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(child.0.try_wait()?.is_none());
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        assert!(std::fs::metadata(directory.join("child.log"))?.len() < 16384);
        assert!(
            !std::fs::read_to_string(directory.join("child.log"))?
                .contains("NATIVE-D14-ACTIVATED-OR-ACKNOWLEDGED")
        );
        let case = lifecycle::NativeCase::load(&native, "read", "read")?;
        let c = context();
        let b = &case.binding;
        let db = lifecycle::open(b, &directory.join("runtime.sqlite")).await?;
        let baseline: Record =
            serde_json::from_slice(&std::fs::read(directory.join("source-baseline.json"))?)?;
        let intent: Record =
            serde_json::from_slice(&std::fs::read(directory.join("prune-intent.json"))?)?;
        let original: Output =
            serde_json::from_slice(&std::fs::read(directory.join("original.json"))?)?;
        let loaded = db.load(context()).await?.ok_or("source")?;
        let mut host = lifecycle::Host::reload(&directory)?;
        let r = if phase == "indexed" {
            assert_eq!(loaded, baseline);
            let archive = history::export_runtime(b, &baseline, &c)?;
            let a = archive.sha256();
            let index = host_index_for_archive(&directory)?;
            let state = journal::recover_runtime(b, &baseline, &c)?;
            let receipt = host.receipt(
                b,
                &state,
                a,
                index,
                case.terminal + chrono::TimeDelta::seconds(4),
                &c,
            )?;
            let p = history::prune_runtime(
                b,
                &baseline,
                host.archives.get(&a).ok_or("original archive")?,
                &receipt,
                &case.epoch(b, baseline.checkpoint, 2000, &c)?,
                &c,
            )?;
            assert_eq!(p.record(), &intent);
            p.commit(&db).await?
        } else {
            assert_eq!(loaded, intent);
            loaded
        };
        let new = case.next_binding(&c)?;
        let (a, index) = if phase == "carried" {
            let archive = history::export_runtime(b, &r, &c)?;
            (archive.sha256(), host_index_for_archive(&directory)?)
        } else {
            host.publish(b, &r)?
        };
        host = lifecycle::Host::reload(&directory)?;
        let state = journal::recover_runtime(b, &r, &c)?;
        let receipt = host.receipt(
            &new,
            &state,
            a,
            index,
            case.terminal + chrono::TimeDelta::seconds(4),
            &c,
        )?;
        let p = history::carry_runtime(
            b,
            &db,
            &r,
            host.archives.get(&a).ok_or("carry archive")?,
            &receipt,
            &new,
            &case.epoch(&new, r.checkpoint, 2000, &c)?,
            &c,
        )
        .await?;
        let target_path = directory.join("new.sqlite");
        let target = lifecycle::open(&new, &target_path).await?;
        let carried = if phase == "carried" {
            let intent: Record =
                serde_json::from_slice(&std::fs::read(directory.join("carry-intent.json"))?)?;
            assert_eq!(p.record(), &intent);
            p.reconcile(&target, context()).await?
        } else {
            assert_eq!(target.load(context()).await?, None);
            p.commit(&target).await?
        };
        // A distinct actual retained EOF operation interposes before old native
        // replay. This is a host delivery ordinal, not native producer sequence.
        let eof = lifecycle::NativeCase::load(&native, "eof", "eof")?;
        let event = eof
            .events
            .iter()
            .find(|e| e.attributes["runtime_metadata"]["operation"]["kind"] == "read")
            .ok_or("native EOF")?;
        let input = Input::new(&new, new.config().sources[0].stream, event, &c)?;
        assert!(input.claim(&c).is_err());
        let ep = eof.epoch(&new, carried.checkpoint + 1, 2000, &c)?;
        let state = journal::recover_runtime(&new, &carried, &c)?;
        let query = Query::new_runtime(&new, &input, &ep, &c)?;
        let (ca, na) = host.answers(&state, &query)?;
        assert!(ca.is_none() && na.is_none());
        let anchor = state.archive_anchor().ok_or("anchor")?.clone();
        let ca = Answer::Absent;
        let na = Answer::Absent;
        let claim = history::Claim::lookup(&query, &anchor, &ca, &na, &c)?;
        let lookup = Lookup::new(
            query,
            anchor,
            ca,
            na,
            lifecycle::authority(
                &new,
                claim,
                eof.terminal + chrono::TimeDelta::seconds(4),
                &c,
            )?,
            &c,
        )?;
        let advanced = journal::prepare_runtime_checked(
            &new,
            Some(&carried),
            carried.checkpoint + 1,
            RuntimeAction::Admit {
                input: &input,
                position: carried.checkpoint + 1,
                decision: None,
            },
            &ep,
            Some(&lookup),
            &c,
        )?
        .commit(&target)
        .await?;
        let selected = case
            .events
            .iter()
            .find(|e| e.attributes["runtime_metadata"]["operation"]["kind"] == "connect")
            .ok_or("native connect")?;
        let mut alias = selected.clone();
        alias.id = Uuid::new_v5(&new.config().partition, b"crash-native-alias");
        alias.observed_at += chrono::TimeDelta::seconds(2);
        let input = Input::new(&new, new.config().sources[0].stream, &alias, &c)?;
        let ep = eof.epoch(&new, advanced.checkpoint + 1, 2000, &c)?;
        let state = journal::recover_runtime(&new, &advanced, &c)?;
        let query = Query::new_runtime(&new, &input, &ep, &c)?;
        let (ca, na) = host.answers(&state, &query)?;
        assert!(ca.is_none());
        let witness = na.ok_or("original witness")?;
        let anchor = state.archive_anchor().ok_or("anchor")?.clone();
        let ca = Answer::Absent;
        let na = Answer::Known(&witness);
        let claim = history::Claim::lookup(&query, &anchor, &ca, &na, &c)?;
        let lookup = Lookup::new(
            query,
            anchor,
            ca,
            na,
            lifecycle::authority(
                &new,
                claim,
                eof.terminal + chrono::TimeDelta::seconds(4),
                &c,
            )?,
            &c,
        )?;
        let replacement = context();
        let opposite = case
            .decision(&new, &input, true, false, &replacement)?
            .ok_or("opposite destination decision")?;
        replacement.cancellation.cancel();
        let p = journal::prepare_runtime_checked(
            &new,
            Some(&advanced),
            advanced.checkpoint + 1,
            RuntimeAction::Admit {
                input: &input,
                position: advanced.checkpoint + 1,
                decision: Some(&opposite),
            },
            &ep,
            Some(&lookup),
            &c,
        )?;
        assert!(matches!(
            p.applied(),
            Applied::Admission(Admission::Duplicate)
        ));
        let after = p.commit(&target).await?;
        assert!(after.outbox.is_empty());
        assert_eq!(after.checkpoint, 6);
        assert_eq!(
            host.effect(witness.effect().ok_or("original effect")?)?,
            original
        );
        assert_eq!(
            std::fs::read(directory.join(format!("published-{}.json", original.id)))?,
            original.bytes
        );
        let mut counterfactual = RuntimeState::new(&new);
        for (i, event) in case.events.iter().enumerate() {
            let input = Input::new(&new, new.config().sources[0].stream, event, &c)?;
            let decision = case.decision(&new, &input, true, false, &c)?;
            counterfactual.admit(
                &new,
                &input,
                i as u64 + 1,
                &case.epoch(&new, case.events.len() as u64, 25, &c)?,
                decision.as_ref(),
                &c,
            )?;
        }
        counterfactual.seal(
            &new,
            &case.epoch(&new, case.events.len() as u64, 25, &c)?,
            &c,
        )?;
        assert_eq!(counterfactual.episodes()[0].status, Status::NoMatch);
        let original_episode: signal_rules::correlation::Episode =
            serde_json::from_slice(&original.bytes)?;
        assert_eq!(original_episode.status, Status::Match);
        target.shutdown(context()).await?;
        let target = lifecycle::open(&new, &target_path).await?;
        assert_eq!(target.load(context()).await?, Some(after));
        target.shutdown(context()).await?;
        db.shutdown(context()).await?;
        cases.push(serde_json::json!({"phase":phase,"pid":pid,"actual_sigkill_signal":9,"before_activation_and_source_ack":true,"retained_actual_native_read_and_eof":true,"exact_intent_and_original_bytes":true,"indexes_reopened":true,"intervening_actual_input":true,"cancelled_replacement_decision_ignored":true,"scope_key_carry_preserved_original":"match","counterfactual_changed_policy":"no_match","second_reopen_exact":true}));
    }
    lifecycle::write_new(
        &output.join("custody-process-report.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version":1,"status":"passed_local_retained_native_custody_process","actual_sigkill":3,"owned_process_cleanup":true,"source_policy_custody_authority":"synthetic current fixture verification","capture":"actual retained owned LinuxAMD64 metadata, not fresh live authorization","cases":cases}),
        )?,
    )?;
    Ok(())
}
fn host_index_for_archive(directory: &std::path::Path) -> Result<[u8; 32]> {
    let mut files = std::fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(|e| e.file_name());
    let file = files
        .into_iter()
        .rev()
        .find(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("complete-index-"))
        })
        .ok_or("complete index file")?;
    Ok(lifecycle::sha(&std::fs::read(file.path())?))
}

#[test]
#[ignore = "requires reviewed actual retained native corpus for catalog augmentation"]
fn original_d14_catalog_envelopes_map_to_actual_native_evidence_without_using_state_flags() -> Result
{
    let directory = PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR")?);
    let catalog: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/security-requirements/catalog.json"
    ))?;
    let mapping: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/correlation/runtime-contract.json"
    ))?;
    assert_eq!(mapping["schema_version"], 2);
    assert_eq!(mapping["rule"], "SIG-D14");
    let rule = catalog["detections"]
        .as_array()
        .ok_or("detections")?
        .iter()
        .find(|d| d["id"] == "SIG-D14")
        .ok_or("D14")?;
    let mut checked = Vec::new();
    for map in mapping["cases"].as_array().ok_or("mapped cases")? {
        let id = map["catalog_fixture"].as_str().ok_or("fixture id")?;
        let fixture = rule["fixtures"]
            .as_array()
            .ok_or("fixtures")?
            .iter()
            .find(|f| f["id"] == id)
            .ok_or("original fixture")?;
        let original: signal_event::SignalEvent =
            serde_json::from_value(fixture["events"][0].clone())?;
        let original_json = serde_json::to_value(&original)?;
        assert_eq!(original_json, fixture["events"][0]);
        let verified = map["identity_link"] == "verified_for_fixture";
        if !verified {
            assert!(original.attributes["security"].get("process_key").is_none());
        }
        let native_name = map["native_case"].as_str().ok_or("native case")?;
        let mut case = lifecycle::NativeCase::load(&directory, native_name, id)?;
        let mut cfg = case.binding.config().clone();
        cfg.correlation_ms = fixture["parameters"]["correlation_seconds"]
            .as_i64()
            .ok_or("C")?
            * 1000;
        cfg.ttl_ms = cfg.correlation_ms * 2;
        case.binding = RuntimeBinding::new(cfg, &context())?;
        for event in &mut case.events {
            let timestamp = event.timestamp;
            let native = event.attributes["runtime_metadata"].clone();
            event
                .attributes
                .insert("catalog_original_envelope".into(), original_json.clone());
            assert_eq!(event.timestamp, timestamp);
            assert_eq!(event.attributes["runtime_metadata"], native);
            assert_eq!(event.attributes["catalog_original_envelope"], original_json);
        }
        let c = context();
        let b = &case.binding;
        let ep = case.epoch_with_identity(b, case.events.len() as u64, 25, &c, verified)?;
        let mut state = RuntimeState::new(b);
        for (i, event) in case.events.iter().enumerate() {
            let input = Input::new(b, b.config().sources[0].stream, event, &c)?;
            let decision = case.decision(b, &input, false, false, &c)?;
            state.admit(b, &input, i as u64 + 1, &ep, decision.as_ref(), &c)?;
        }
        state.seal(b, &ep, &c)?;
        assert_eq!(state.episodes().len(), 1, "{id}");
        let episode = &state.episodes()[0];
        assert_eq!(
            serde_json::to_value(episode.status)?,
            fixture["expected_assessment"]
        );
        assert_eq!(serde_json::to_value(episode.status)?, map["expected"]);
        for event in &episode.originals {
            assert_eq!(event.attributes["catalog_original_envelope"], original_json);
        }
        if !verified {
            assert!(episode.coverage_gap);
            assert!(episode.finding.is_none());
            assert!(episode.verification.iter().all(
                |p| serde_json::to_value(p).unwrap()["runtime"]["execution_continuity"] == false
            ));
        }
        checked.push(id.to_owned());
    }
    checked.sort();
    assert_eq!(
        checked,
        [
            "SIG-D14-missing_data",
            "SIG-D14-negative",
            "SIG-D14-positive"
        ]
    );
    Ok(())
}

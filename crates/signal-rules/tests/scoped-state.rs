#[path = "support/scoped_state.rs"]
mod support;
use serde_json::json;
use signal_rules::{
    baseline::Status,
    scoped_state::{
        replay::{self, Recovery},
        *,
    },
    state_journal::Journal,
};
use support::*;
use uuid::Uuid;

#[test]
fn fifteen_supported_catalog_outcomes_and_explicit_deferred_database_rule() -> Result {
    let contract: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scoped-state/contract.json"
    ))?;
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["cases"].as_array().ok_or("cases")?.len(), 15);
    assert!(contract["deferred"].get("SIG-D12").is_some());
    for rule in [
        Detection::D04,
        Detection::D06,
        Detection::D08,
        Detection::D09,
        Detection::D13,
    ] {
        for case in 0..3 {
            let f = fixture(rule, case)?;
            let input = Input::new(&f.event, &context())?;
            let out = assess(&input, rule, f.state.as_ref(), &f.host, &context())?;
            assert_eq!(
                out.status,
                [Status::Match, Status::NoMatch, Status::Indeterminate][case],
                "{rule:?}/{case}"
            );
            assert_eq!(out.coverage_gap, case == 2);
            assert_eq!(out.finding.is_some(), case == 0);
            if let Some(finding) = out.finding {
                assert_eq!(finding.event_ids, [f.event.id]);
                assert_eq!(finding.rule_id, rule.id());
            }
        }
    }
    let f = fixture(Detection::D04, 0)?;
    let i = Input::new(&f.event, &context())?;
    let out = assess(&i, Detection::D12, None, &f.host, &context())?;
    assert_eq!(out.gap, Some(Gap::DeferredDatabaseSource));
    Ok(())
}
#[test]
fn approval_absence_requires_complete_fresh_exact_policy_scope_and_history() -> Result {
    let mut f = fixture(Detection::D04, 0)?;
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_mut().ok_or("state")?;
    s.complete = false;
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::IncompleteInventory)
    );
    s.complete = true;
    s.policy_revision = "old-policy".into();
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMismatch)
    );
    s.policy_revision = f.host.policy_revision.clone();
    s.source_config_revision = "old-config".into();
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMismatch)
    );
    s.source_config_revision = f.host.source_config_revision.clone();
    s.validity.from = f.event.timestamp + chrono::TimeDelta::seconds(1);
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateStale)
    );
    s.validity = interval();
    s.expires_at = f.host.now;
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateStale)
    );
    s.expires_at = time("2026-10-07T00:30:00Z");
    f.host.ready = false;
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::HostUnverified)
    );
    Ok(())
}
#[test]
fn iam_literal_delta_uses_approvals_case_insensitive_actions_and_explicit_semantic_limits() -> Result
{
    let mut f = fixture(Detection::D06, 0)?;
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_mut().ok_or("state")?;
    if let Data::Iam {
        before,
        after,
        approved: _,
    } = &mut s.data
    {
        before.grants = after.grants.clone();
        if let Permission::Iam { action, .. } = &mut before.grants[0] {
            *action = "S3:getobject".into();
        }
        assert_eq!(
            assess(&i, Detection::D06, Some(s), &f.host, &context())?.status,
            Status::NoMatch
        );
        if let Data::Iam {
            before,
            after,
            approved,
        } = &mut s.data
        {
            before.grants.clear();
            approved.clone_from(&after.grants);
        }
    }
    assert_eq!(
        assess(&i, Detection::D06, Some(s), &f.host, &context())?.status,
        Status::NoMatch
    );
    if let Data::Iam { after, .. } = &mut s.data {
        after.unsupported.push(Unsupported::Conditions);
    }
    assert_eq!(
        assess(&i, Detection::D06, Some(s), &f.host, &context())?.gap,
        Some(Gap::UnsupportedSemantics)
    );
    Ok(())
}
#[test]
fn rbac_name_scope_narrowing_is_not_escalation_but_broadening_is() -> Result {
    let mut f = fixture(Detection::D08, 0)?;
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_mut().ok_or("state")?;
    if let Data::Rbac { before, after, .. } = &mut s.data {
        before.roles[0].grants = after.roles[0].grants.clone();
        after.roles[0].grants[0].resource_name = Some("one-pod".into());
    }
    assert_eq!(
        assess(&i, Detection::D08, Some(s), &f.host, &context())?.status,
        Status::NoMatch
    );
    if let Data::Rbac { before, after, .. } = &mut s.data {
        before.roles[0].grants[0].resource_name = Some("one-pod".into());
        after.roles[0].grants[0].resource_name = None;
    }
    assert_eq!(
        assess(&i, Detection::D08, Some(s), &f.host, &context())?.status,
        Status::Match
    );
    if let Data::Rbac { after, .. } = &mut s.data {
        after.roles[0].grants[0].resource_name = Some("one-pod".into());
        after.roles[0].grants[0].verb = "create".into();
    }
    assert_eq!(
        assess(&i, Detection::D08, Some(s), &f.host, &context())?.gap,
        Some(Gap::UnsupportedSemantics)
    );
    Ok(())
}
#[test]
fn rbac_must_resolve_references_and_bind_one_actual_object_transition() -> Result {
    let mut f = fixture(Detection::D08, 0)?;
    f.event.attributes["kubernetes"]["verb"] = "create".into();
    let i = Input::new(&f.event, &context())?;
    let q = query(&i, Detection::D08, &f.host).map_err(|g| format!("{g:?}"))?;
    let s = f.state.as_mut().ok_or("state")?;
    s.input_sha256 = i.sha256();
    s.change = q.change;
    assert_eq!(
        assess(&i, Detection::D08, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMismatch)
    );
    if let Data::Rbac { before, after, .. } = &mut s.data {
        before.roles.clear();
        before.bindings.clear();
        after.bindings[0].role_name = "unknown-role".into();
    }
    assert_eq!(
        assess(&i, Detection::D08, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMismatch)
    );
    // A source-bound Role creation must not smuggle in an unrelated binding change.
    Ok(())
}
#[test]
fn historical_workload_and_process_reuse_never_borrow_current_names_or_pids() -> Result {
    let mut f = fixture(Detection::D09, 0)?;
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_mut().ok_or("state")?;
    if let Data::Workload { history, .. } = &mut s.data {
        history[0].uid = "new-pod-uid".into();
    }
    assert_eq!(
        assess(&i, Detection::D09, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMissing)
    );
    let mut f = fixture(Detection::D13, 0)?;
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_mut().ok_or("state")?;
    if let Data::Process { history } = &mut s.data {
        history[0].start_epoch_ns += 1;
    }
    assert_eq!(
        assess(&i, Detection::D13, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMissing)
    );
    if let Data::Process { history } = &mut s.data {
        history[0].start_epoch_ns -= 1;
        history.push(history[0].clone());
    }
    assert_eq!(
        assess(&i, Detection::D13, Some(s), &f.host, &context())?.gap,
        Some(Gap::AmbiguousHistory)
    );
    Ok(())
}
#[test]
fn missing_native_uid_requires_unique_authoritative_event_time_resolution() -> Result {
    let mut f = fixture(Detection::D09, 0)?;
    f.event.attributes["kubernetes"]["object"]
        .as_object_mut()
        .ok_or("object")?
        .remove("uid");
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_mut().ok_or("state")?;
    s.input_sha256 = i.sha256();
    assert_eq!(
        assess(&i, Detection::D09, Some(s), &f.host, &context())?.status,
        Status::Match
    );
    if let Data::Workload { history, .. } = &mut s.data {
        let mut duplicate = history[0].clone();
        duplicate.uid = "reused-name-uid".into();
        history.push(duplicate);
    }
    assert_eq!(
        assess(&i, Detection::D09, Some(s), &f.host, &context())?.gap,
        Some(Gap::AmbiguousHistory)
    );
    Ok(())
}
#[test]
fn source_claims_cannot_override_host_and_input_state_output_work_is_bounded() -> Result {
    let mut f = fixture(Detection::D04, 0)?;
    f.event.attributes.insert("ready".into(), json!(true));
    let i = Input::new(&f.event, &context())?;
    f.host.ready = false;
    assert_eq!(
        assess(&i, Detection::D04, None, &f.host, &context())?.gap,
        Some(Gap::HostUnverified)
    );
    f.event.tags = vec!["tag".into(); 257];
    assert!(Input::new(&f.event, &context()).is_err());
    f.event.tags.clear();
    f.event.message = Some(" ".repeat(MAX_INPUT_BYTES + 1));
    assert!(Input::new(&f.event, &context()).is_err());
    let f = fixture(Detection::D04, 0)?;
    let i = Input::new(&f.event, &context())?;
    let mut s = f.state.ok_or("state")?;
    if let Data::Credentials { approvals } = &mut s.data {
        approvals.resize(
            129,
            approval(
                &query(&i, Detection::D04, &f.host).map_err(|g| format!("{g:?}"))?,
                "principal-uid",
            ),
        );
    }
    assert!(matches!(
        assess(&i, Detection::D04, Some(&s), &f.host, &context()),
        Err(Error::Capacity)
    ));
    Ok(())
}
#[tokio::test]
async fn original_journal_effect_survives_new_policy_and_explicit_outbox_retirement() -> Result {
    let mut f = fixture(Detection::D04, 0)?;
    let i = Input::new(&f.event, &context())?;
    let s = f.state.as_ref().ok_or("state")?;
    let original = assess(&i, Detection::D04, Some(s), &f.host, &context())?;
    let binding = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    let proposal = replay::prepare(&binding, &i, Some(s), &original, 1, 7, &context())?;
    let dir = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = dir.path().join("state.sqlite");
    let (journal, ready) = Journal::begin_open(path.clone(), binding.journal_config(), context())?;
    ready.wait().await?;
    let committed = proposal.commit(&journal, 0).await?;
    assert_eq!(proposal.reconcile(&journal, context()).await?, committed);
    journal.shutdown(context()).await?;
    let (journal, ready) = Journal::begin_open(path, binding.journal_config(), context())?;
    ready.wait().await?;
    let loaded = journal.load(context()).await?.ok_or("loaded")?;
    f.host.policy_revision = "policy-2".into();
    assert_eq!(
        assess(&i, Detection::D04, Some(s), &f.host, &context())?.gap,
        Some(Gap::StateMismatch)
    );
    let bytes = match replay::recover(&binding, Some(&loaded), &i, 7, &context())? {
        Recovery::Pending { output } => output.bytes,
        _ => return Err("pending".into()),
    };
    assert_eq!(bytes, committed.outbox[0].bytes);
    let retired = journal.retire(loaded.revision, 1, context()).await?;
    match replay::recover(&binding, Some(&retired), &i, 7, &context())? {
        Recovery::Published { original_output } => assert_eq!(original_output, bytes),
        _ => return Err("published".into()),
    };
    // Ingest is at least once: identical event pins can occupy a NEW WAL
    // position. A current policy/state must not reassess that old logical input.
    let later = replay::recover(&binding, Some(&retired), &i, 8, &context())?;
    assert!(
        !matches!(later, Recovery::NewInput { .. }),
        "same event ID at a later WAL position must recover its original effect"
    );
    journal.shutdown(context()).await?;
    Ok(())
}
#[test]
fn sealed_decision_and_exact_state_cannot_be_replaced_or_budget_renewed() -> Result {
    let f = fixture(Detection::D04, 0)?;
    let i = Input::new(&f.event, &context())?;
    let mut s = f.state.ok_or("state")?;
    let operation = context();
    let mut decision = assess(&i, Detection::D04, Some(&s), &f.host, &operation)?;
    let binding = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    decision.status = Status::NoMatch;
    assert!(replay::prepare(&binding, &i, Some(&s), &decision, 1, 1, &context()).is_err());
    decision.status = Status::Match;
    s.revision = "new-state".into();
    assert!(replay::prepare(&binding, &i, Some(&s), &decision, 1, 1, &context()).is_err());
    s.revision = "state-1".into();
    operation.cancellation.cancel();
    assert!(replay::prepare(&binding, &i, Some(&s), &decision, 1, 1, &context()).is_err());
    Ok(())
}

fn policy_after_arrival(f: &Fixture, rule: Detection) -> Result<(HostContext, Snapshot)> {
    let mut fresh = host(&f.event, f.host.scope.clone());
    fresh.policy_revision = "policy-2".into();
    fresh.policy_config_sha256 = [4; 32];
    fresh.verification_reference = "fixture://proof/2".into();
    let input = Input::new(&f.event, &context())?;
    let q = query(&input, rule, &fresh).map_err(|g| format!("{g:?}"))?;
    let mut state = f.state.clone().ok_or("state")?;
    state.policy_revision = fresh.policy_revision.clone();
    state.policy_config_sha256 = fresh.policy_config_sha256;
    state.revision = "state-2".into();
    let old = assess(&input, rule, f.state.as_ref(), &f.host, &context())?;
    match &mut state.data {
        Data::Credentials { approvals: entries }
        | Data::Workload {
            approvals: entries, ..
        } => entries.push(approval(&q, &state.resolved_target)),
        Data::Iam { approved, .. } | Data::Rbac { approved, .. } => {
            approved.clone_from(&old.added_permissions)
        }
        Data::Process { history } => history[0].approved = true,
    }
    Ok((fresh, state))
}
struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[tokio::test]
#[ignore = "only invoked by the owned process crash matrix"]
async fn scoped_state_child() -> Result {
    use std::io::Write;
    let dir = std::path::PathBuf::from(
        std::env::var_os("SCOPED_STATE_CHILD_DIR").ok_or("owned child directory")?,
    );
    let name = std::env::var("SCOPED_STATE_CHILD_RULE")?;
    let rule = [
        Detection::D04,
        Detection::D06,
        Detection::D08,
        Detection::D09,
        Detection::D13,
    ]
    .into_iter()
    .find(|r| r.id() == name)
    .ok_or("rule")?;
    let f = fixture(rule, 0)?;
    let input = Input::new(&f.event, &context())?;
    let decision = assess(&input, rule, f.state.as_ref(), &f.host, &context())?;
    assert_eq!(decision.status, Status::Match);
    let binding = replay::Binding::new(
        rule,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    let proposal = replay::prepare(
        &binding,
        &input,
        f.state.as_ref(),
        &decision,
        1,
        7,
        &context(),
    )?;
    let (journal, ready) = Journal::begin_open(
        dir.join("state.sqlite"),
        binding.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    // Source-client reply/ACK is deliberately withheld after actual durable COMMIT.
    proposal.commit(&journal, 0).await?;
    let mut witness = std::fs::File::create_new(dir.join("ready.tmp"))?;
    witness.write_all(b"committed")?;
    witness.sync_all()?;
    std::fs::rename(dir.join("ready.tmp"), dir.join("ready"))?;
    std::fs::File::open(&dir)?.sync_all()?;
    std::future::pending::<()>().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires an explicitly owned target evidence directory"]
async fn process_crash_matrix() -> Result {
    use std::{
        fs,
        io::Write,
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let output = std::path::PathBuf::from(
        std::env::var_os("SCOPED_STATE_OUTPUT").ok_or("owned output required")?,
    )
    .canonicalize()?;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("root")?
        .join("target")
        .canonicalize()?;
    if !output.starts_with(root) || fs::metadata(&output)?.permissions().mode() & 0o777 != 0o700 {
        return Err("owned protected target directory required".into());
    }
    let began = Instant::now();
    let mut cases = vec![];
    for rule in [
        Detection::D04,
        Detection::D06,
        Detection::D08,
        Detection::D09,
        Detection::D13,
    ] {
        let dir = output.join(rule.id());
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let f = fixture(rule, 0)?;
        let input = Input::new(&f.event, &context())?;
        let original = assess(&input, rule, f.state.as_ref(), &f.host, &context())?;
        let binding = replay::Binding::new(
            rule,
            Uuid::from_u128(1),
            &f.host,
            [2; 32],
            [3; 32],
            &context(),
        )?;
        let proposed = replay::prepare(
            &binding,
            &input,
            f.state.as_ref(),
            &original,
            1,
            7,
            &context(),
        )?;
        let log = fs::File::create_new(dir.join("child.log"))?;
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args(["--ignored", "--exact", "scoped_state_child", "--nocapture"])
                .env_clear()
                .env("SCOPED_STATE_CHILD_DIR", &dir)
                .env("SCOPED_STATE_CHILD_RULE", rule.id())
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let pid = child.0.id();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if fs::read(dir.join("ready")).ok().as_deref() == Some(b"committed") {
                break;
            }
            if child.0.try_wait()?.is_some() {
                return Err("owned child exited before COMMIT witness".into());
            }
            if Instant::now() >= deadline {
                return Err("owned COMMIT witness deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(child.0.try_wait()?.is_none());
        child.0.kill()?;
        let status = child.0.wait()?;
        assert_eq!(status.signal(), Some(9));
        assert!(fs::metadata(dir.join("child.log"))?.len() < 16384);
        assert!(!fs::read_to_string(dir.join("child.log"))?.contains("STATE-SOURCE-ACK"));
        let (journal, ready) = Journal::begin_open(
            dir.join("state.sqlite"),
            binding.journal_config(),
            context(),
        )?;
        ready.wait().await?;
        let loaded = journal
            .load(context())
            .await?
            .ok_or("original committed state")?;
        assert_eq!(&loaded, proposed.record());
        let (fresh, state) = policy_after_arrival(&f, rule)?;
        assert_eq!(
            assess(&input, rule, Some(&state), &fresh, &context())?.status,
            Status::NoMatch
        );
        let new_binding = replay::Binding::new(
            rule,
            Uuid::from_u128(1),
            &fresh,
            [4; 32],
            [3; 32],
            &context(),
        )?;
        assert!(replay::recover(&new_binding, Some(&loaded), &input, 7, &context()).is_err());
        let original_output = match replay::recover(&binding, Some(&loaded), &input, 7, &context())?
        {
            Recovery::Pending { output } => output,
            _ => return Err("pending original".into()),
        };
        assert_eq!(original_output.bytes, loaded.outbox[0].bytes);
        let observed: serde_json::Value = serde_json::from_slice(&original_output.bytes)?;
        assert_eq!(observed["status"], "match");
        let mut sink = fs::File::create_new(dir.join(format!("published-{}", original_output.id)))?;
        sink.write_all(&original_output.bytes)?;
        sink.sync_all()?;
        fs::File::open(&dir)?.sync_all()?;
        let retired = journal.retire(loaded.revision, 1, context()).await?;
        assert_eq!(retired.checkpoint, 7);
        match replay::recover(&binding, Some(&retired), &input, 7, &context())? {
            Recovery::Published {
                original_output: bytes,
            } => assert_eq!(bytes, original_output.bytes),
            _ => return Err("original published effect".into()),
        }
        // A different logical event advances the durable source frontier.
        let mut intervening = f.event.clone();
        intervening.id = Uuid::new_v5(&f.event.id, b"intervening");
        let other_input = Input::new(&intervening, &context())?;
        let other_decision = assess(&other_input, rule, None, &f.host, &context())?;
        let second = replay::prepare_after(
            &binding,
            Some(&retired),
            &other_input,
            None,
            &other_decision,
            8,
            None,
            &context(),
        )?
        .commit(&journal, retired.revision)
        .await?;
        let drained = journal.retire(second.revision, 1, context()).await?;
        let duplicate = replay::advance_duplicate(&binding, &drained, &input, 9, &context())?
            .commit(&journal, drained.revision)
            .await?;
        match replay::recover(&binding, Some(&duplicate), &input, 10, &context())? {
            Recovery::Published {
                original_output: bytes,
            } => assert_eq!(bytes, original_output.bytes),
            _ => return Err("old effect lost across intervening input".into()),
        }
        let carried =
            replay::carry_generation(&binding, &journal, &duplicate, &new_binding, &context())
                .await?;
        let (generation, ready) = Journal::begin_open(
            dir.join("generation-2.sqlite"),
            new_binding.journal_config(),
            context(),
        )?;
        ready.wait().await?;
        let migrated = carried.commit(&generation, 0).await?;
        assert_eq!(migrated.checkpoint, 9);
        generation.shutdown(context()).await?;
        let (generation, ready) = Journal::begin_open(
            dir.join("generation-2.sqlite"),
            new_binding.journal_config(),
            context(),
        )?;
        ready.wait().await?;
        let migrated = generation
            .load(context())
            .await?
            .ok_or("carried generation")?;
        match replay::recover(&new_binding, Some(&migrated), &input, 10, &context())? {
            Recovery::Published {
                original_output: bytes,
            } => assert_eq!(bytes, original_output.bytes),
            _ => return Err("old effect lost after generation reopen".into()),
        }
        generation.shutdown(context()).await?;
        journal.shutdown(context()).await?;
        let (wrong, ready) = Journal::begin_open(
            dir.join("state.sqlite"),
            new_binding.journal_config(),
            context(),
        )?;
        assert!(ready.wait().await.is_err());
        drop(wrong);
        cases.push(json!({"rule":rule,"child_pid":pid,"actual_sigkill_signal":9,"source_ack_withheld":true,"original_commit_recovered":true,"new_policy_would_be":"no_match","original_output_returned":"match","checkpoint":7,"published_before_retirement":true,"original_published_bytes_survive":true,"changed_enrollment_refused":true,"intervening_event_preserves_original":true,"duplicate_checkpoint":9,"generation_carry_reopen_preserves_original":true}));
    }
    fs::write(
        output.join("process-report.json"),
        serde_json::to_vec_pretty(
            &json!({"schema_version":1,"status":"passed_local","scope":"production Rust state_journal through actual owned test processes; synthetic source and private state","cases":cases,"actual_sigkill":5,"owned_process_cleanup":true,"elapsed_seconds":began.elapsed().as_secs_f64()}),
        )?,
    )?;
    Ok(())
}

#[tokio::test]
async fn prepared_commit_refuses_an_actual_different_journal_generation_before_writing() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture(Detection::D04, 0)?;
    let input = Input::new(&f.event, &context())?;
    let decision = assess(
        &input,
        Detection::D04,
        f.state.as_ref(),
        &f.host,
        &context(),
    )?;
    let a = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    let proposed = replay::prepare(&a, &input, f.state.as_ref(), &decision, 1, 7, &context())?;
    let mut foreign = host(&f.event, f.host.scope.clone());
    foreign.source_binding = [9; 32];
    let b = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(2),
        &foreign,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let (journal, ready) = Journal::begin_open(
        dir.path().join("foreign.sqlite"),
        b.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    assert!(matches!(
        proposed.commit(&journal, 0).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        proposed.reconcile(&journal, context()).await,
        Err(Error::Conflict)
    ));
    assert!(journal.load(context()).await?.is_none());
    journal.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn logical_effects_survive_intervening_inputs_and_policy_generation() -> Result {
    let f = fixture(Detection::D04, 0)?;
    let input = Input::new(&f.event, &context())?;
    let binding = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    let decision = assess(
        &input,
        Detection::D04,
        f.state.as_ref(),
        &f.host,
        &context(),
    )?;
    let dir = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let (journal, ready) = Journal::begin_open(
        dir.path().join("old.sqlite"),
        binding.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let first = replay::prepare(
        &binding,
        &input,
        f.state.as_ref(),
        &decision,
        1,
        7,
        &context(),
    )?
    .commit(&journal, 0)
    .await?;
    let bytes = first.outbox[0].bytes.clone();
    assert!(replay::advance_duplicate(&binding, &first, &input, 8, &context()).is_err());
    let drained = journal.retire(first.revision, 1, context()).await?;
    let mut b = f.event.clone();
    b.id = Uuid::from_u128(765);
    let bi = Input::new(&b, &context())?;
    let bd = assess(&bi, Detection::D04, None, &f.host, &context())?;
    let mut forged = drained.clone();
    let mut body: serde_json::Value = serde_json::from_slice(&forged.state)?;
    body["effects"] = json!([]);
    forged.state = serde_json::to_vec(&body)?;
    let forged_proposal =
        replay::prepare_after(&binding, Some(&forged), &bi, None, &bd, 8, None, &context())?;
    assert!(matches!(
        forged_proposal.commit(&journal, forged.revision).await,
        Err(Error::Conflict)
    ));
    assert_eq!(journal.load(context()).await?, Some(drained.clone()));
    let second = replay::prepare_after(
        &binding,
        Some(&drained),
        &bi,
        None,
        &bd,
        8,
        None,
        &context(),
    )?
    .commit(&journal, drained.revision)
    .await?;
    assert!(matches!(
        replay::recover(&binding, Some(&second), &input, 9, &context())?,
        Recovery::DrainPrior { .. }
    ));
    let second = journal.retire(second.revision, 1, context()).await?;
    match replay::recover(&binding, Some(&second), &input, 9, &context())? {
        Recovery::Published { original_output } => assert_eq!(original_output, bytes),
        _ => return Err("intervening event erased original effect".into()),
    }
    let advanced = replay::advance_duplicate(&binding, &second, &input, 9, &context())?
        .commit(&journal, second.revision)
        .await?;
    assert_eq!(advanced.checkpoint, 9);
    assert_eq!(advanced.state, second.state);
    let mut conflict = f.event.clone();
    conflict.message = Some("changed canonical input".into());
    assert!(matches!(
        replay::recover(
            &binding,
            Some(&advanced),
            &Input::new(&conflict, &context())?,
            10,
            &context()
        ),
        Err(Error::Conflict)
    ));
    let (fresh, state) = policy_after_arrival(&f, Detection::D04)?;
    assert_eq!(
        assess(&input, Detection::D04, Some(&state), &fresh, &context())?.status,
        Status::NoMatch
    );
    let new = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &fresh,
        [4; 32],
        [3; 32],
        &context(),
    )?;
    let carried = replay::carry_generation(&binding, &journal, &advanced, &new, &context()).await?;
    let (new_journal, ready) = Journal::begin_open(
        dir.path().join("new.sqlite"),
        new.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let migrated = carried.commit(&new_journal, 0).await?;
    assert_eq!(migrated.checkpoint, 9);
    match replay::recover(&new, Some(&migrated), &input, 10, &context())? {
        Recovery::Published { original_output } => assert_eq!(original_output, bytes),
        _ => return Err("generation carry reassessed original effect".into()),
    }
    assert!(replay::recover(&binding, Some(&migrated), &input, 10, &context()).is_err());
    new_journal.shutdown(context()).await?;
    journal.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn archive_pruning_requires_fresh_complete_index_and_preserves_originals() -> Result {
    let f = fixture(Detection::D04, 0)?;
    let input = Input::new(&f.event, &context())?;
    let binding = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    let decision = assess(
        &input,
        Detection::D04,
        f.state.as_ref(),
        &f.host,
        &context(),
    )?;
    let dir = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let (journal, ready) = Journal::begin_open(
        dir.path().join("state.sqlite"),
        binding.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let first = replay::prepare(
        &binding,
        &input,
        f.state.as_ref(),
        &decision,
        1,
        7,
        &context(),
    )?
    .commit(&journal, 0)
    .await?;
    let original = first.outbox[0].bytes.clone();
    assert!(replay::export_history(&binding, &first, &context()).is_err());
    let drained = journal.retire(first.revision, 1, context()).await?;
    let archive = replay::export_history(&binding, &drained, &context())?;
    // Host custody: publish original bytes durably before supplying a receipt.
    let path = dir.path().join("immutable-archive.json");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    std::io::Write::write_all(&mut file, archive.bytes())?;
    file.sync_all()?;
    std::fs::File::open(dir.path())?.sync_all()?;
    let decoded = replay::Archive::from_bytes(
        &binding,
        &std::fs::read(path)?,
        archive.sha256(),
        &context(),
    )?;
    let effect = decoded.effect(f.event.id).ok_or("archived effect")?;
    let mut invalid_host = host(&f.event, f.host.scope.clone());
    invalid_host.ready = false;
    assert!(
        replay::ArchiveAuthority::new(
            &binding,
            &invalid_host,
            "fixture://invalid".into(),
            true,
            &context()
        )
        .is_err()
    );
    invalid_host.ready = true;
    invalid_host.verified_at = invalid_host.now + chrono::TimeDelta::seconds(1);
    assert!(
        replay::ArchiveAuthority::new(
            &binding,
            &invalid_host,
            "fixture://future".into(),
            true,
            &context()
        )
        .is_err()
    );
    let mut other_host = host(&f.event, f.host.scope.clone());
    other_host.source_binding = [9; 32];
    let other_binding = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &other_host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    assert!(
        replay::ArchiveAuthority::new(
            &binding,
            &other_host,
            "fixture://wrong-source".into(),
            true,
            &context()
        )
        .is_err()
    );
    let mut receipt = replay::ArchiveReceipt {
        namespace: binding.archive_namespace(&context())?,
        archive_sha256: archive.sha256(),
        previous_root: [0; 32],
        index_sha256: [8; 32],
        authority: replay::ArchiveAuthority::new(
            &binding,
            &f.host,
            "fixture://durable-index/1".into(),
            false,
            &context(),
        )?,
    };
    assert!(replay::prune_archived(&binding, &drained, &archive, &receipt, &context()).is_err());
    receipt.authority = replay::ArchiveAuthority::new(
        &binding,
        &f.host,
        "fixture://durable-index/1".into(),
        true,
        &context(),
    )?;
    let pruned = replay::prune_archived(&binding, &drained, &archive, &receipt, &context())?
        .commit(&journal, drained.revision)
        .await?;
    let anchor = match replay::recover(&binding, Some(&pruned), &input, 8, &context())? {
        Recovery::ArchiveRequired { anchor } => anchor,
        _ => return Err("pruned history must require complete lookup".into()),
    };
    let mut proof = replay::ArchiveCheck {
        anchor: anchor.clone(),
        namespace: receipt.namespace,
        event_id: f.event.id,
        input_sha256: input.sha256(),
        authority: receipt.authority.clone(),
        answer: replay::ArchiveAnswer::Unknown,
    };
    assert!(matches!(
        replay::recover_checked(&binding, Some(&pruned), &input, 8, Some(&proof), &context())?,
        Recovery::ArchiveRequired { .. }
    ));
    proof.answer = replay::ArchiveAnswer::Known(&effect);
    let mut short = host(&f.event, f.host.scope.clone());
    short.verified_until = short.now + chrono::TimeDelta::milliseconds(80);
    proof.authority = replay::ArchiveAuthority::new(
        &binding,
        &short,
        "fixture://lookup/short".into(),
        true,
        &context(),
    )?;
    let expiring_restore =
        replay::restore_archived(&binding, &pruned, &input, 8, &proof, &context())?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        expiring_restore
            .commit(&journal, pruned.revision)
            .await
            .is_err()
    );
    assert_eq!(journal.load(context()).await?, Some(pruned.clone()));
    assert!(matches!(
        replay::recover_checked(&binding, Some(&pruned), &input, 8, Some(&proof), &context())?,
        Recovery::ArchiveRequired { .. }
    ));
    proof.authority = replay::ArchiveAuthority::new(
        &other_binding,
        &other_host,
        "fixture://other-source".into(),
        true,
        &context(),
    )?;
    assert!(matches!(
        replay::recover_checked(&binding, Some(&pruned), &input, 8, Some(&proof), &context())?,
        Recovery::ArchiveRequired { .. }
    ));
    let cancellation = context();
    proof.authority = replay::ArchiveAuthority::new(
        &binding,
        &f.host,
        "fixture://cancelled-lookup".into(),
        true,
        &cancellation,
    )?;
    let cancelled = replay::restore_archived(&binding, &pruned, &input, 8, &proof, &context())?;
    cancellation.cancellation.cancel();
    assert!(cancelled.commit(&journal, pruned.revision).await.is_err());
    assert_eq!(journal.load(context()).await?, Some(pruned.clone()));
    proof.authority = receipt.authority.clone();
    match replay::recover_checked(&binding, Some(&pruned), &input, 8, Some(&proof), &context())? {
        Recovery::Published { original_output } => assert_eq!(original_output, original),
        _ => return Err("archive must return original output".into()),
    }
    let restored = replay::restore_archived(&binding, &pruned, &input, 8, &proof, &context())?
        .commit(&journal, pruned.revision)
        .await?;
    assert_eq!(restored.checkpoint, 8);
    assert!(matches!(
        replay::recover(&binding, Some(&restored), &input, 9, &context())?,
        Recovery::Published { .. }
    ));
    let mut other = f.event.clone();
    other.id = Uuid::from_u128(987);
    let oi = Input::new(&other, &context())?;
    proof.event_id = other.id;
    proof.input_sha256 = oi.sha256();
    proof.answer = replay::ArchiveAnswer::Absent;
    proof.authority = replay::ArchiveAuthority::new(
        &binding,
        &f.host,
        "fixture://lookup/incomplete".into(),
        false,
        &context(),
    )?;
    assert!(matches!(
        replay::recover_checked(&binding, Some(&restored), &oi, 9, Some(&proof), &context())?,
        Recovery::ArchiveRequired { .. }
    ));
    proof.authority = receipt.authority.clone();
    assert!(matches!(
        replay::recover_checked(&binding, Some(&restored), &oi, 9, Some(&proof), &context())?,
        Recovery::NewInput { .. }
    ));
    let od = assess(&oi, Detection::D04, None, &f.host, &context())?;
    let admitted = replay::prepare_after(
        &binding,
        Some(&restored),
        &oi,
        None,
        &od,
        9,
        Some(&proof),
        &context(),
    )?
    .commit(&journal, restored.revision)
    .await?;
    assert_eq!(admitted.checkpoint, 9);
    let mut changed = f.event.clone();
    changed.message = Some("changed canonical input".into());
    let ci = Input::new(&changed, &context())?;
    proof.event_id = changed.id;
    proof.input_sha256 = ci.sha256();
    proof.answer = replay::ArchiveAnswer::Known(&effect);
    assert!(matches!(
        replay::recover_checked(&binding, Some(&pruned), &ci, 10, Some(&proof), &context()),
        Err(Error::Conflict)
    ));
    let (fresh, _) = policy_after_arrival(&f, Detection::D04)?;
    let new = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &fresh,
        [4; 32],
        [3; 32],
        &context(),
    )?;
    assert!(
        replay::carry_generation(&binding, &journal, &pruned, &new, &context())
            .await
            .is_err()
    );
    let admitted = journal.retire(admitted.revision, 1, context()).await?;
    let carry = replay::carry_generation(&binding, &journal, &admitted, &new, &context())
        .await
        .map_err(|e| format!("carry error: {e:?}"))?;
    proof.input_sha256 = input.sha256();
    proof.authority = replay::ArchiveAuthority::new(
        &new,
        &fresh,
        "fixture://fresh-generation-lookup".into(),
        true,
        &context(),
    )?;
    match replay::recover_checked(
        &new,
        Some(carry.record()),
        &input,
        10,
        Some(&proof),
        &context(),
    )? {
        Recovery::Published { original_output } => assert_eq!(original_output, original),
        _ => return Err("archive anchor lost during generation carry".into()),
    }
    journal.shutdown(context()).await?;
    Ok(())
}

#[test]
fn bounded_effect_history_refuses_count_and_encoded_byte_overflow_atomically() -> Result {
    let f = fixture(Detection::D04, 0)?;
    let binding = replay::Binding::new(
        Detection::D04,
        Uuid::from_u128(1),
        &f.host,
        [2; 32],
        [3; 32],
        &context(),
    )?;
    for large in [false, true] {
        let mut previous = None;
        let mut refused = false;
        for n in 0..129_u64 {
            let mut event = f.event.clone();
            event.id = Uuid::from_u128(2000 + n as u128);
            if large {
                event.message = Some("x".repeat(700_000));
            }
            let input = Input::new(&event, &context())?;
            let decision = assess(&input, Detection::D04, None, &f.host, &context())?;
            let before = previous.clone();
            match replay::prepare_after(
                &binding,
                previous.as_ref(),
                &input,
                None,
                &decision,
                n + 1,
                None,
                &context(),
            ) {
                Ok(prepared) => {
                    let mut record = prepared.record().clone();
                    record.outbox.clear(); // Model completed publication; no history removal.
                    previous = Some(record);
                }
                Err(Error::Capacity) => {
                    assert_eq!(previous, before);
                    if large {
                        assert!(n > 0 && n < 128);
                    } else {
                        assert_eq!(n, 128);
                    }
                    refused = true;
                    break;
                }
                Err(error) => return Err(format!("unexpected capacity outcome: {error:?}").into()),
            }
        }
        assert!(
            refused,
            "history must refuse before exceeding count or wire-byte cap"
        );
    }
    Ok(())
}

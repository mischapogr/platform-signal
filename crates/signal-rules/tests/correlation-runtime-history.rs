#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
#[path = "support/correlation_d14.rs"]
mod support;
use signal_rules::{
    RuleContext,
    correlation::{
        Admission, Error, Status,
        d14::*,
        history::{self, Answer, Archive, Authority, Claim, Lookup, Query, Receipt},
        journal::{self, Applied, RuntimeAction},
    },
    state_journal::{Journal, Record},
};
use std::{os::unix::fs::PermissionsExt, path::Path};
use support::*;
use uuid::Uuid;
fn epoch(b: &RuntimeBinding, position: u64, ms: u64, c: &RuleContext) -> Result<RuntimeEpoch> {
    epoch_limits(b, position, ms, ms, c)
}
fn epoch_limits(
    b: &RuntimeBinding,
    position: u64,
    ms: u64,
    policy_ms: u64,
    c: &RuleContext,
) -> Result<RuntimeEpoch> {
    let frontier = ns(BASE + (ms + b.config().lateness_ms as u64) * 1_000_000);
    let now = frontier + chrono::TimeDelta::milliseconds(100);
    let sources = b
        .config()
        .sources
        .iter()
        .map(|s| RuntimeVerification {
            source: signal_rules::correlation::Verification {
                stream: s.stream,
                position,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: b.config().authority_keys_sha256,
                verification_reference: "fixture://history-prefix".into(),
                verified_at: now,
                verified_until: now + chrono::TimeDelta::seconds(60),
                now,
                coverage_from: ns(BASE - 10_000_000),
                frontier,
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
            reference: "fixture://history-policy".into(),
            verified_at: now,
            verified_until: now + chrono::TimeDelta::seconds(60),
            now,
            coverage_from: ns(BASE - 10_000_000),
            frontier: ns(BASE + (policy_ms + b.config().lateness_ms as u64) * 1_000_000),
            complete: true,
            authenticated: true,
        })
        .collect();
    Ok(RuntimeEpoch::new(b, sources, policies, c)?)
}
fn authority(b: &RuntimeBinding, claim: Claim, c: &RuleContext) -> Result<Authority> {
    Ok(Authority::new_runtime(
        b,
        history::Verification {
            claim,
            reference: "fixture://protected-cumulative-index".into(),
            verified_at: ns(BASE + 10_000_000_000),
            verified_until: ns(BASE + 70_000_000_000),
            now: ns(BASE + 10_000_000_000),
            durable_originals: true,
            complete_cumulative_indexes: true,
        },
        c,
    )?)
}
fn receipt(b: &RuntimeBinding, archive: &Archive, r: &Record, c: &RuleContext) -> Result<Receipt> {
    let old = journal::recover_runtime(b, r, c)?
        .archive_anchor()
        .map_or([0; 32], |a| a.root_sha256);
    let index = [42; 32];
    let claim = Claim::publication(archive, old, index, c)?;
    Ok(Receipt {
        archive_sha256: archive.sha256(),
        previous_root: old,
        index_sha256: index,
        authority: authority(b, claim, c)?,
    })
}
fn lookup<'a>(
    b: &RuntimeBinding,
    q: Query,
    anchor: &history::Anchor,
    canonical: Answer<'a>,
    native: Answer<'a>,
    c: &RuleContext,
) -> Result<Lookup<'a>> {
    let claim = Claim::lookup(&q, anchor, &canonical, &native, c)?;
    Ok(Lookup::new(
        q,
        anchor.clone(),
        canonical,
        native,
        authority(b, claim, c)?,
        c,
    )?)
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
    r: Option<&Record>,
    e: &signal_event::SignalEvent,
    position: u64,
    classified: Option<bool>,
    ms: u64,
) -> Result<Record> {
    let c = context();
    let i = input(b, e, &c)?;
    let decision = classified
        .map(|yes| -> Result<CurrentDecision> {
            let mut p = verification(b, &i, yes, &c)?;
            p.now = e.observed_at.max(e.timestamp) + chrono::TimeDelta::milliseconds(100);
            p.verified_at = p.now;
            p.verified_until = p.now + chrono::TimeDelta::seconds(60);
            p.covered_through = ns(BASE + 10_000_000_000);
            Ok(CurrentDecision::new(b, &i, p, &c)?)
        })
        .transpose()?;
    Ok(journal::prepare_runtime(
        b,
        r,
        r.map_or(1, |r| r.checkpoint + 1),
        RuntimeAction::Admit {
            input: &i,
            position,
            decision: decision.as_ref(),
        },
        &epoch(b, position, ms, &c)?,
        &c,
    )?
    .commit(db)
    .await?)
}
async fn seal(db: &Journal, b: &RuntimeBinding, r: &Record, pos: u64, ms: u64) -> Result<Record> {
    Ok(journal::prepare_runtime(
        b,
        Some(r),
        r.checkpoint,
        RuntimeAction::Seal,
        &epoch(b, pos, ms, &context())?,
        &context(),
    )?
    .commit(db)
    .await?)
}
async fn pair(db: &Journal, b: &RuntimeBinding, classified: Option<bool>) -> Result<Record> {
    let r = admit(db, b, None, &event(true)?, 1, Some(true), 50).await?;
    let r = admit(db, b, Some(&r), &event(false)?, 2, classified, 50).await?;
    let r = seal(db, b, &r, 2, 50).await?;
    Ok(db.retire(r.revision, r.outbox.len(), context()).await?)
}
#[tokio::test]
async fn runtime_archive_cold_replay_and_key_scope_carry_preserve_original_outcomes() -> Result {
    for classified in [None, Some(false), Some(true)] {
        let c = context();
        let b = RuntimeBinding::new(
            {
                let mut cfg = config();
                cfg.policy_authorities[1].account = Some("old-scope".into());
                cfg
            },
            &c,
        )?;
        let d = directory()?;
        let db = open(&b, &d.path().join("old.sqlite")).await?;
        let r = pair(&db, &b, classified).await?;
        let original = journal::recover_runtime(&b, &r, &c)?.episodes()[0].clone();
        let expected = match classified {
            None => Status::Indeterminate,
            Some(false) => Status::NoMatch,
            Some(true) => Status::Match,
        };
        assert_eq!(original.status, expected);
        let r = seal(&db, &b, &r, 2, 2000).await?;
        let archive = history::export_runtime(&b, &r, &c)?;
        let restored = Archive::from_bytes(archive.bytes(), archive.sha256(), &c)?;
        assert_eq!(restored.bytes(), archive.bytes());
        assert_eq!(restored.identities().len(), 2);
        let con = event(false)?;
        let witness = archive.canonical(con.id).ok_or("canonical")?;
        let original_ref = witness.effect().ok_or("effect")?.clone();
        let output = archive.effect(&original_ref)?;
        assert_eq!(
            serde_json::from_slice::<signal_rules::correlation::Episode>(&output.bytes)?.status,
            expected
        );
        let receipt = receipt(&b, &archive, &r, &c)?;
        let pruned =
            history::prune_runtime(&b, &r, &archive, &receipt, &epoch(&b, 2, 2000, &c)?, &c)?
                .commit(&db)
                .await?;
        assert_eq!(
            journal::recover_runtime(&b, &pruned, &c)?
                .metrics(&b)?
                .retained_events,
            0
        );
        let mut cfg = config();
        cfg.revision = "new-rule".into();
        cfg.authority_keys_sha256 = [88; 32];
        cfg.policy_authorities[1].account = Some("new-scope".into());
        cfg.policy_authorities[1].policy_revision = "new-policy".into();
        let new = RuntimeBinding::new(cfg, &c)?;
        let carried_archive = history::export_runtime(&b, &pruned, &c)?;
        let current = journal::recover_runtime(&b, &pruned, &c)?
            .archive_anchor()
            .unwrap()
            .clone();
        let index = [99; 32];
        let claim = Claim::publication(&carried_archive, current.root_sha256, index, &c)?;
        let publication = Receipt {
            archive_sha256: carried_archive.sha256(),
            previous_root: current.root_sha256,
            index_sha256: index,
            authority: authority(&new, claim, &c)?,
        };
        let prepared = history::carry_runtime(
            &b,
            &db,
            &pruned,
            &carried_archive,
            &publication,
            &new,
            &epoch(&new, 2, 2000, &c)?,
            &c,
        )
        .await?;
        let target = open(&new, &d.path().join("new.sqlite")).await?;
        let carried = prepared.commit(&target).await?;
        let state = journal::recover_runtime(&new, &carried, &c)?;
        let anchor = state.archive_anchor().unwrap();
        let mut alias = con.clone();
        alias.id = Uuid::from_u128(999);
        let i = input(&new, &alias, &c)?;
        let ep = epoch(&new, 3, 2000, &c)?;
        let q = Query::new_runtime(&new, &i, &ep, &c)?;
        let l = lookup(&new, q, anchor, Answer::Absent, Answer::Known(&witness), &c)?;
        let replacement = CurrentDecision::new(&new, &i, verification(&new, &i, true, &c)?, &c)?;
        let p = journal::prepare_runtime_checked(
            &new,
            Some(&carried),
            3,
            RuntimeAction::Admit {
                input: &i,
                position: 3,
                decision: Some(&replacement),
            },
            &ep,
            Some(&l),
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
        assert_eq!(archive.effect(&original_ref)?, output);
        let data: serde_json::Value = serde_json::from_slice(&after.state)?;
        assert_eq!(data["observations"].as_array().unwrap().len(), 0);
        assert_eq!(
            data["aliases"][0]["effect"]["id"],
            serde_json::json!(original_ref.id)
        );
        target.shutdown(context()).await?;
        let target = open(&new, &d.path().join("new.sqlite")).await?;
        assert_eq!(target.load(context()).await?, Some(after));
        target.shutdown(context()).await?;
        db.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn runtime_pruning_keeps_long_pending_connect_lookback_and_refuses_unsealed_carry() -> Result
{
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("pending.sqlite")).await?;
    let r = admit(&db, &b, None, &event(true)?, 1, Some(true), 50).await?;
    let mut con = event(false)?;
    con.attributes["runtime_metadata"]["operation"]["interval"]["exit_ns"] =
        serde_json::json!(BASE + 3_000_000_000);
    con.attributes["runtime_metadata"]["observed_ns"] = serde_json::json!(BASE + 3_000_000_001);
    con.timestamp = ns(BASE + 3_000_000_001);
    con.observed_at = ns(BASE + 3_100_000_000);
    let r = admit(&db, &b, Some(&r), &con, 2, Some(true), 4000).await?;
    let r = seal(&db, &b, &r, 2, 2000).await?;
    assert!(r.outbox.is_empty());
    let archive = history::export_runtime(&b, &r, &c)?;
    let pubr = receipt(&b, &archive, &r, &c)?;
    let p = history::prune_runtime(&b, &r, &archive, &pubr, &epoch(&b, 2, 4000, &c)?, &c)?;
    let retained = journal::recover_runtime(&b, p.record(), &c)?;
    assert_eq!(retained.metrics(&b)?.retained_events, 2);
    let r = p.commit(&db).await?;
    let mut cfg = config();
    cfg.revision = "next-policy".into();
    let new = RuntimeBinding::new(cfg, &c)?;
    let a = history::export_runtime(&b, &r, &c)?;
    let anchor = journal::recover_runtime(&b, &r, &c)?
        .archive_anchor()
        .unwrap()
        .clone();
    let claim = Claim::publication(&a, anchor.root_sha256, [1; 32], &c)?;
    let pubr = Receipt {
        archive_sha256: a.sha256(),
        previous_root: anchor.root_sha256,
        index_sha256: [1; 32],
        authority: authority(&new, claim, &c)?,
    };
    assert!(matches!(
        history::carry_runtime(&b, &db, &r, &a, &pubr, &new, &epoch(&new, 2, 4000, &c)?, &c).await,
        Err(Error::Pending)
    ));
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn runtime_retired_facts_degrade_later_long_operation_by_entry_time() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("floor.sqlite")).await?;
    let r = admit(&db, &b, None, &event(true)?, 1, Some(true), 50).await?;
    let r = seal(&db, &b, &r, 1, 2000).await?;
    let archive = history::export_runtime(&b, &r, &c)?;
    let pubr = receipt(&b, &archive, &r, &c)?;
    let r = history::prune_runtime(&b, &r, &archive, &pubr, &epoch(&b, 1, 2000, &c)?, &c)?
        .commit(&db)
        .await?;
    assert_eq!(
        journal::recover_runtime(&b, &r, &c)?
            .metrics(&b)?
            .retained_events,
        0
    );
    let mut con = event(false)?;
    con.attributes["runtime_metadata"]["operation"]["interval"]["exit_ns"] =
        serde_json::json!(BASE + 3_000_000_000);
    con.attributes["runtime_metadata"]["observed_ns"] = serde_json::json!(BASE + 3_000_000_001);
    con.timestamp = ns(BASE + 3_000_000_001);
    con.observed_at = ns(BASE + 3_100_000_000);
    let i = input(&b, &con, &c)?;
    let ep = epoch(&b, 2, 4000, &c)?;
    let q = Query::new_runtime(&b, &i, &ep, &c)?;
    let state = journal::recover_runtime(&b, &r, &c)?;
    let l = lookup(
        &b,
        q,
        state.archive_anchor().unwrap(),
        Answer::Absent,
        Answer::Absent,
        &c,
    )?;
    let mut v = verification(&b, &i, true, &c)?;
    v.now = ns(BASE + 4_100_000_000);
    v.verified_at = v.now;
    v.verified_until = ns(BASE + 60_000_000_000);
    v.covered_through = ns(BASE + 4_100_000_000);
    let permit = CurrentDecision::new(&b, &i, v, &c)?;
    let r = journal::prepare_runtime_checked(
        &b,
        Some(&r),
        2,
        RuntimeAction::Admit {
            input: &i,
            position: 2,
            decision: Some(&permit),
        },
        &ep,
        Some(&l),
        &c,
    )?
    .commit(&db)
    .await?;
    let r = seal(&db, &b, &r, 2, 4000).await?;
    assert_eq!(
        journal::recover_runtime(&b, &r, &c)?.episodes()[0].status,
        Status::Indeterminate
    );
    db.shutdown(context()).await?;
    Ok(())
}

fn archive_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
#[tokio::test]
async fn runtime_archive_requires_exact_schema_enrollment_and_hash_domain() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("domain.sqlite")).await?;
    let r = pair(&db, &b, Some(true)).await?;
    let a = history::export_runtime(&b, &r, &c)?;
    assert!(
        Archive::from_bytes(
            a.bytes(),
            archive_hash(b"PLATFORM::SIGNAL/correlation/archive/v1\0", a.bytes()),
            &c
        )
        .is_err()
    );
    for edit in 0..3 {
        let mut value: serde_json::Value = serde_json::from_slice(a.bytes())?;
        match edit {
            0 => value["schema_version"] = serde_json::json!(1),
            1 => value["config"]["schema_version"] = serde_json::json!(1),
            _ => value["config"]["threshold"] = serde_json::json!(3),
        }
        let bytes = serde_json::to_vec(&value)?;
        assert!(
            Archive::from_bytes(
                &bytes,
                archive_hash(b"PLATFORM::SIGNAL/correlation/D14-archive/v2\0", &bytes),
                &c
            )
            .is_err()
        );
    }
    // Reusing a real archive in a detector with changed capture configuration
    // cannot inherit the old native-identity namespace.
    let mut cfg = config();
    cfg.revision = "new".into();
    cfg.sources[0].metadata_config_sha256 = [6; 32];
    let new = RuntimeBinding::new(cfg, &c)?;
    let claim = Claim::publication(&a, [0; 32], [42; 32], &c)?;
    let publication = Receipt {
        archive_sha256: a.sha256(),
        previous_root: [0; 32],
        index_sha256: [42; 32],
        authority: authority(&new, claim, &c)?,
    };
    assert!(matches!(
        history::carry_runtime(
            &b,
            &db,
            &r,
            &a,
            &publication,
            &new,
            &epoch(&new, 2, 50, &c)?,
            &c
        )
        .await,
        Err(Error::Conflict)
    ));
    db.shutdown(context()).await?;
    Ok(())
}
fn rollover_receipt(
    new: &RuntimeBinding,
    a: &Archive,
    r: &Record,
    old: &RuntimeBinding,
    c: &RuleContext,
) -> Result<Receipt> {
    let previous = journal::recover_runtime(old, r, c)?
        .archive_anchor()
        .map_or([0; 32], |x| x.root_sha256);
    let index = [77; 32];
    let claim = Claim::publication(a, previous, index, c)?;
    Ok(Receipt {
        archive_sha256: a.sha256(),
        previous_root: previous,
        index_sha256: index,
        authority: authority(new, claim, c)?,
    })
}
#[tokio::test]
async fn runtime_carry_rechecks_source_after_prepare_and_leaves_destination_empty() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("source.sqlite")).await?;
    let r = pair(&db, &b, Some(true)).await?;
    let a = history::export_runtime(&b, &r, &c)?;
    let mut cfg = config();
    cfg.revision = "next".into();
    let new = RuntimeBinding::new(cfg, &c)?;
    let receipt = rollover_receipt(&new, &a, &r, &b, &c)?;
    let p = history::carry_runtime(
        &b,
        &db,
        &r,
        &a,
        &receipt,
        &new,
        &epoch(&new, 2, 50, &c)?,
        &c,
    )
    .await?;
    let mut e = event(true)?;
    e.id = Uuid::from_u128(44);
    e.attributes["runtime_metadata"]["native"]["sequence"] = serde_json::json!(4);
    let advanced = admit(&db, &b, Some(&r), &e, 3, None, 50).await?;
    let target = open(&new, &d.path().join("destination.sqlite")).await?;
    assert_eq!(p.commit(&target).await, Err(Error::Conflict));
    assert_eq!(target.load(context()).await?, None);
    assert_eq!(db.load(context()).await?, Some(advanced));
    db.shutdown(context()).await?;
    target.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn runtime_custody_cancellation_interrupts_blocked_carry_source_and_destination() -> Result {
    use std::future::Future;
    use std::time::Duration;
    for source_blocked in [true, false] {
        let c = context();
        let custody = context();
        let b = RuntimeBinding::new(config(), &c)?;
        let d = directory()?;
        let source_path = d.path().join("source.sqlite");
        let db = open(&b, &source_path).await?;
        let r = pair(&db, &b, Some(true)).await?;
        let a = history::export_runtime(&b, &r, &c)?;
        let mut cfg = config();
        cfg.revision = "next".into();
        let new = RuntimeBinding::new(cfg, &c)?;
        let target_path = d.path().join("target.sqlite");
        let target = open(&new, &target_path).await?;
        let receipt = rollover_receipt(&new, &a, &r, &b, &custody)?;
        let ep = epoch(&new, 2, 50, &c)?;
        if source_blocked {
            let blocker = rusqlite::Connection::open(&source_path)?;
            blocker.execute_batch("BEGIN EXCLUSIVE")?;
            let mut future = Box::pin(history::carry_runtime(
                &b, &db, &r, &a, &receipt, &new, &ep, &c,
            ));
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            assert_eq!(db.metrics().0, 1);
            custody.cancellation.cancel();
            assert!(matches!(future.await, Err(Error::Cancelled)));
            blocker.execute_batch("ROLLBACK")?;
        } else {
            let p = history::carry_runtime(&b, &db, &r, &a, &receipt, &new, &ep, &c).await?;
            let blocker = rusqlite::Connection::open(&target_path)?;
            blocker.execute_batch("BEGIN EXCLUSIVE")?;
            let mut future = Box::pin(p.commit(&target));
            tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|cx| {
                    if let std::task::Poll::Ready(result) = future.as_mut().poll(cx) {
                        panic!("commit finished before target barrier: {result:?}");
                    }
                    if target.metrics().0 == 1 {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                }),
            )
            .await?;
            custody.cancellation.cancel();
            assert_eq!(future.await, Err(Error::Cancelled));
            blocker.execute_batch("ROLLBACK")?;
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while db.metrics().0 != 0 || target.metrics().0 != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(target.load(context()).await?, None);
        assert_eq!(db.load(context()).await?, Some(r));
        db.shutdown(context()).await?;
        target.shutdown(context()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn runtime_carry_degradation_covers_processed_reads_ahead_of_policy_watermark() -> Result {
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let db = open(&b, &d.path().join("ahead.sqlite")).await?;
    let mut read = event(true)?;
    read.attributes["runtime_metadata"]["operation"]["interval"] =
        serde_json::json!({"entry_ns":BASE+2_999_000_000,"exit_ns":BASE+3_000_000_000});
    read.attributes["runtime_metadata"]["observed_ns"] = serde_json::json!(BASE + 3_000_000_001);
    read.timestamp = ns(BASE + 3_000_000_001);
    read.observed_at = ns(BASE + 3_100_000_000);
    let r = admit(&db, &b, None, &read, 1, Some(true), 4000).await?;
    let old_epoch = epoch_limits(&b, 1, 4000, 50, &c)?;
    let r = journal::prepare_runtime(&b, Some(&r), 1, RuntimeAction::Seal, &old_epoch, &c)?
        .commit(&db)
        .await?;
    assert_eq!(
        journal::recover_runtime(&b, &r, &c)?.watermark(),
        Some(ns(BASE + 50_000_000))
    );
    let a = history::export_runtime(&b, &r, &c)?;
    let mut cfg = config();
    cfg.revision = "next".into();
    let new = RuntimeBinding::new(cfg, &c)?;
    let receipt = rollover_receipt(&new, &a, &r, &b, &c)?;
    let ep = epoch_limits(&new, 1, 4000, 50, &c)?;
    let p = history::carry_runtime(&b, &db, &r, &a, &receipt, &new, &ep, &c).await?;
    let target = open(&new, &d.path().join("next.sqlite")).await?;
    let carried = p.commit(&target).await?;
    let data: serde_json::Value = serde_json::from_slice(&carried.state)?;
    assert_eq!(
        data["degraded_through"],
        serde_json::json!(ns(BASE + 3_020_000_000))
    );
    let mut con = event(false)?;
    con.attributes["runtime_metadata"]["operation"]["interval"] =
        serde_json::json!({"entry_ns":BASE+3_010_000_000,"exit_ns":BASE+3_011_000_000});
    con.attributes["runtime_metadata"]["observed_ns"] = serde_json::json!(BASE + 3_011_000_001);
    con.timestamp = ns(BASE + 3_011_000_001);
    con.observed_at = ns(BASE + 3_100_000_000);
    let i = input(&new, &con, &c)?;
    let ep = epoch(&new, 2, 4000, &c)?;
    let q = Query::new_runtime(&new, &i, &ep, &c)?;
    let state = journal::recover_runtime(&new, &carried, &c)?;
    let l = lookup(
        &new,
        q,
        state.archive_anchor().unwrap(),
        Answer::Absent,
        Answer::Absent,
        &c,
    )?;
    let mut v = verification(&new, &i, true, &c)?;
    v.now = ns(BASE + 4_100_000_000);
    v.verified_at = v.now;
    v.verified_until = ns(BASE + 60_000_000_000);
    v.covered_through = v.now;
    let permit = CurrentDecision::new(&new, &i, v, &c)?;
    let r = journal::prepare_runtime_checked(
        &new,
        Some(&carried),
        2,
        RuntimeAction::Admit {
            input: &i,
            position: 2,
            decision: Some(&permit),
        },
        &ep,
        Some(&l),
        &c,
    )?
    .commit(&target)
    .await?;
    let r = seal(&target, &new, &r, 2, 4000).await?;
    assert_eq!(
        journal::recover_runtime(&new, &r, &c)?.episodes()[0].status,
        Status::Indeterminate
    );
    db.shutdown(context()).await?;
    target.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn runtime_custody_original_deadline_bounds_blocked_carry_source_io() -> Result {
    use std::{future::Future, time::Duration};
    let c = context();
    let b = RuntimeBinding::new(config(), &c)?;
    let d = directory()?;
    let path = d.path().join("deadline.sqlite");
    let db = open(&b, &path).await?;
    let r = pair(&db, &b, Some(true)).await?;
    let a = history::export_runtime(&b, &r, &c)?;
    let mut cfg = config();
    cfg.revision = "next".into();
    let new = RuntimeBinding::new(cfg, &c)?;
    let ep = epoch(&new, 2, 50, &c)?;
    // Validate/export/claim under the ordinary setup budget. The short custody
    // lifetime begins only at permit construction, immediately before blocked I/O.
    let claim = Claim::publication(&a, [0; 32], [77; 32], &c)?;
    let blocker = rusqlite::Connection::open(&path)?;
    blocker.execute_batch("BEGIN EXCLUSIVE")?;
    let mut custody = context();
    custody.deadline = tokio::time::Instant::now() + Duration::from_millis(60);
    let receipt = Receipt {
        archive_sha256: a.sha256(),
        previous_root: [0; 32],
        index_sha256: [77; 32],
        authority: authority(&new, claim, &custody)?,
    };
    let mut future = Box::pin(history::carry_runtime(
        &b, &db, &r, &a, &receipt, &new, &ep, &c,
    ));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let result =
        tokio::time::timeout_at(custody.deadline + Duration::from_millis(20), future).await?;
    assert!(matches!(
        result,
        Err(Error::Journal) | Err(Error::Cancelled)
    ));
    blocker.execute_batch("ROLLBACK")?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while db.metrics().0 != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(db.load(context()).await?, Some(r));
    db.shutdown(context()).await?;
    Ok(())
}

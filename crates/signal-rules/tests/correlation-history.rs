#[path = "support/correlation.rs"]
#[allow(dead_code)]
mod support;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_rules::{
    correlation::{
        history::{self, Answer, Archive, ArchivedIdentity, Authority, Lookup, Query, Receipt},
        journal::{self, Action},
        *,
    },
    state_journal::{Journal, Output, Record},
};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use support::*;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
struct Locator {
    archive: [u8; 32],
    canonical: Uuid,
}
#[derive(Clone, Default)]
struct Index {
    canonical: BTreeMap<Uuid, Locator>,
    native: BTreeMap<NativeId, Locator>,
}
/// Synthetic private host with actual durable archive AND both immutable indexes.
struct Host {
    directory: PathBuf,
    archives: BTreeMap<[u8; 32], Archive>,
    indexes: BTreeMap<[u8; 32], Index>,
    publications: usize,
}
fn write_new(path: &Path, bytes: &[u8]) -> Result {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(path.parent().ok_or("parent")?)?.sync_all()?;
    Ok(())
}
impl Host {
    fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
            archives: BTreeMap::new(),
            indexes: BTreeMap::new(),
            publications: 0,
        }
    }
    fn witness(&self, locator: &Locator) -> Result<ArchivedIdentity> {
        self.archives
            .get(&locator.archive)
            .ok_or("archive")?
            .canonical(locator.canonical)
            .ok_or("identity".into())
    }
    fn publish(&mut self, b: &Binding, record: &Record) -> Result<([u8; 32], [u8; 32])> {
        let state = journal::recover(b, record, &context())?;
        let archive = history::export(b, record, &context())?;
        let sha = archive.sha256();
        let file = self
            .directory
            .join(format!("archive-{}.json", self.publications));
        write_new(&file, archive.bytes())?;
        let archive = Archive::from_bytes(&std::fs::read(file)?, sha, &context())?;
        let mut index = match state.archive_anchor() {
            Some(a) => self
                .indexes
                .get(&a.index_sha256)
                .ok_or("complete prior index")?
                .clone(),
            None => Index::default(),
        };
        for witness in archive.identities() {
            let locator = Locator {
                archive: sha,
                canonical: witness.canonical_id(),
            };
            if let Some(old) = index.canonical.get(&witness.canonical_id()) {
                let old = self.witness(old)?;
                assert_eq!(old.canonical_sha256(), witness.canonical_sha256());
                assert_eq!(old.native_id(), witness.native_id());
                assert_eq!(old.first_canonical_id(), witness.first_canonical_id());
            }
            index
                .canonical
                .insert(witness.canonical_id(), locator.clone());
            if let Some(native) = witness.native_id() {
                if let Some(old) = index.native.get(native) {
                    let old = self.witness(old)?;
                    assert_eq!(old.content_sha256(), witness.content_sha256());
                    assert_eq!(old.first_canonical_id(), witness.first_canonical_id());
                }
                index.native.insert(native.clone(), locator);
            }
        }
        self.archives.insert(sha, archive);
        let canonical: Vec<_> = index.canonical.iter().collect();
        let native: Vec<_> = index.native.iter().collect();
        let bytes =
            serde_json::to_vec(&serde_json::json!({"canonical":canonical,"native":native}))?;
        let index_sha: [u8; 32] = Sha256::digest(&bytes).into();
        write_new(
            &self
                .directory
                .join(format!("complete-index-{}.json", self.publications)),
            &bytes,
        )?;
        self.indexes.insert(index_sha, index);
        self.publications += 1;
        Ok((sha, index_sha))
    }
    fn receipt(
        &self,
        b: &Binding,
        state: &State,
        archive_sha: [u8; 32],
        index_sha: [u8; 32],
    ) -> Result<Receipt> {
        assert!(self.archives.contains_key(&archive_sha) && self.indexes.contains_key(&index_sha));
        Ok(Receipt {
            archive_sha256: archive_sha,
            previous_root: state.archive_anchor().map_or([0; 32], |a| a.root_sha256),
            index_sha256: index_sha,
            authority: authority(
                b,
                history::Claim::publication(
                    self.archives.get(&archive_sha).ok_or("archive")?,
                    state.archive_anchor().map_or([0; 32], |a| a.root_sha256),
                    index_sha,
                    &context(),
                )?,
            )?,
        })
    }
    fn answers(
        &self,
        state: &State,
        query: &Query,
    ) -> Result<(Option<ArchivedIdentity>, Option<ArchivedIdentity>)> {
        let index = self
            .indexes
            .get(&state.archive_anchor().ok_or("anchor")?.index_sha256)
            .ok_or("exact complete cumulative index")?;
        Ok((
            index
                .canonical
                .get(&query.canonical_id())
                .map(|l| self.witness(l))
                .transpose()?,
            query
                .native_id()
                .and_then(|n| index.native.get(n))
                .map(|l| self.witness(l))
                .transpose()?,
        ))
    }
    fn effect(&self, reference: &history::EffectRef) -> Result<Output> {
        Ok(self
            .archives
            .get(&reference.archive_sha256)
            .ok_or("original protected archive")?
            .effect(reference)?)
    }
}
fn authority(b: &Binding, claim: history::Claim) -> Result<Authority> {
    Ok(Authority::new(
        b,
        history::Verification {
            claim,
            reference: "fixture://fresh-protected-originals-and-dual-index".into(),
            verified_at: time(1990),
            verified_until: time(2300),
            now: time(2000),
            durable_originals: true,
            complete_cumulative_indexes: true,
        },
        &context(),
    )?)
}
fn lookup<'a>(
    b: &Binding,
    state: &State,
    q: Query,
    canonical: &'a Option<ArchivedIdentity>,
    native: &'a Option<ArchivedIdentity>,
) -> Result<Lookup<'a>> {
    let ca = canonical.as_ref().map_or(Answer::Absent, Answer::Known);
    let na = if q.native_id().is_none() {
        Answer::NotApplicable
    } else {
        native.as_ref().map_or(Answer::Absent, Answer::Known)
    };
    let auth = authority(
        b,
        history::Claim::lookup(
            &q,
            state.archive_anchor().ok_or("anchor")?,
            &ca,
            &na,
            &context(),
        )?,
    )?;
    Ok(Lookup::new(
        q,
        state.archive_anchor().ok_or("anchor")?.clone(),
        ca,
        na,
        auth,
        &context(),
    )?)
}
fn source_epoch(
    b: &Binding,
    record: Option<&Record>,
    frontier: i64,
    recent: bool,
) -> Result<Epoch> {
    let state = record
        .map(|r| journal::recover(b, r, &context()))
        .transpose()?
        .unwrap_or_else(|| State::new(b));
    let proofs = b
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(frontier), true);
            p.position = state
                .source_positions()
                .iter()
                .find(|(stream, _)| *stream == s.stream)
                .map_or(0, |(_, n)| *n);
            p.authority_keys_sha256 = b.config().authority_keys_sha256;
            p.now = time(2000);
            p.verified_at = time(1990);
            p.verified_until = time(2300);
            if recent {
                p.coverage_from = time(400);
            }
            p
        })
        .collect();
    Ok(Epoch::new(b, proofs, &context())?)
}
fn admission_epoch(b: &Binding, recent: bool) -> Result<Epoch> {
    let proofs = b
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(600), true);
            p.authority_keys_sha256 = b.config().authority_keys_sha256;
            p.now = time(2000);
            p.verified_at = time(1990);
            p.verified_until = time(2300);
            if recent {
                p.coverage_from = time(400);
            }
            p
        })
        .collect();
    Ok(Epoch::new(b, proofs, &context())?)
}
async fn initial_in(
    directory: &Path,
    expire: bool,
) -> Result<(
    Binding,
    Journal,
    Record,
    Vec<signal_event::SignalEvent>,
    Output,
)> {
    let b = Binding::new(config(), &context())?;
    let (db, ready) =
        Journal::begin_open(directory.join("old.sqlite"), b.journal_config(), context())?;
    ready.wait().await?;
    let events = inputs()?;
    let mut previous = None;
    for (i, event) in events.iter().enumerate() {
        let source = if i < 3 { 0 } else { 1 };
        let position = if i < 3 { i as u64 + 1 } else { 1 };
        previous = Some(
            journal::prepare(
                &b,
                previous.as_ref(),
                i as u64 + 1,
                Action::Admit {
                    stream: b.config().sources[source].stream,
                    position,
                    event,
                },
                &epoch(&b, time(100), true)?,
                &context(),
            )?
            .commit(&db)
            .await?,
        );
    }
    let record = journal::prepare(
        &b,
        previous.as_ref(),
        4,
        Action::Seal,
        &source_epoch(&b, previous.as_ref(), 50, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let effect = record.outbox[0].clone();
    write_new(
        &directory.join(format!("published-{}", effect.id)),
        &effect.bytes,
    )?;
    let mut record = db.retire(record.revision, 1, context()).await?;
    if expire {
        record = journal::prepare(
            &b,
            Some(&record),
            4,
            Action::Seal,
            &source_epoch(&b, Some(&record), 500, false)?,
            &context(),
        )?
        .commit(&db)
        .await?;
    }
    Ok((b, db, record, events, effect))
}
async fn initial(
    expire: bool,
) -> Result<(
    Binding,
    tempfile::TempDir,
    Journal,
    Record,
    Vec<signal_event::SignalEvent>,
    Output,
)> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    let (b, db, record, events, effect) = initial_in(dir.path(), expire).await?;
    Ok((b, dir, db, record, events, effect))
}

#[tokio::test]
async fn active_completion_marker_prevents_resealing_and_inactive_retirement_frees_custody()
-> Result {
    let (b, dir, db, record, _events, original) = initial(false).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let pruned = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 50, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let after = journal::recover(&b, &pruned, &context())?;
    assert!(after.episodes().is_empty());
    assert_eq!(after.metrics(&b)?.retained_events, 4);
    let sealed = journal::prepare(
        &b,
        Some(&pruned),
        4,
        Action::Seal,
        &source_epoch(&b, Some(&pruned), 100, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    assert!(sealed.outbox.is_empty());
    let archived = host
        .archives
        .get(&sha)
        .ok_or("archive")?
        .native(
            &Query::new(
                &b,
                b.config().sources[1].stream,
                &inputs()?[3],
                &admission_epoch(&b, false)?,
                &context(),
            )?
            .native_id()
            .ok_or("native")?
            .clone(),
        )
        .ok_or("identity")?;
    assert_eq!(
        host.effect(archived.effect().ok_or("effect reference")?)?,
        original
    );
    let expired = journal::prepare(
        &b,
        Some(&sealed),
        4,
        Action::Seal,
        &source_epoch(&b, Some(&sealed), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha2, index2) = host.publish(&b, &expired)?;
    let receipt = host.receipt(
        &b,
        &journal::recover(&b, &expired, &context())?,
        sha2,
        index2,
    )?;
    let retired = history::prune(
        &b,
        &expired,
        host.archives.get(&sha2).ok_or("archive2")?,
        &receipt,
        &source_epoch(&b, Some(&expired), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let retained = journal::recover(&b, &retired, &context())?;
    assert_eq!(retained.metrics(&b)?.retained_events, 0);
    assert_eq!(retained.metrics(&b)?.retained_aliases, 0);
    assert_eq!(retained.archive_anchor().ok_or("anchor")?.generation, 2);
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn prune_cold_native_alias_intervening_restart_reexport_and_key_rollover_preserve_original()
-> Result {
    let (b, dir, db, record, events, original) = initial(true).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let mut record = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let mut duplicate = events[3].clone();
    duplicate.id = Uuid::from_u128(99991);
    duplicate.observed_at = time(550);
    assert!(matches!(
        journal::prepare(
            &b,
            Some(&record),
            5,
            Action::Admit {
                stream: b.config().sources[1].stream,
                position: 2,
                event: &duplicate
            },
            &admission_epoch(&b, true)?,
            &context()
        ),
        Err(Error::ArchiveRequired)
    ));
    let state = journal::recover(&b, &record, &context())?;
    let ep = admission_epoch(&b, true)?;
    let query = Query::new(
        &b,
        b.config().sources[1].stream,
        &duplicate,
        &ep,
        &context(),
    )?;
    let (ca, na) = host.answers(&state, &query)?;
    assert!(ca.is_none());
    let check = lookup(&b, &state, query, &ca, &na)?;
    let proposed = journal::prepare_checked(
        &b,
        Some(&record),
        5,
        Action::Admit {
            stream: b.config().sources[1].stream,
            position: 2,
            event: &duplicate,
        },
        &ep,
        Some(&check),
        &context(),
    )?;
    assert!(matches!(
        proposed.applied(),
        journal::Applied::Admission(Admission::Duplicate)
    ));
    record = proposed.commit(&db).await?;
    assert!(record.outbox.is_empty());
    assert_eq!(
        journal::recover(&b, &record, &context())?
            .metrics(&b)?
            .retained_events,
        0
    );
    assert_eq!(
        na.as_ref().ok_or("native")?.first_canonical_id(),
        events[3].id
    );
    assert_eq!(
        host.effect(
            na.as_ref()
                .and_then(|n| n.effect())
                .ok_or("original effect")?
        )?,
        original
    );
    let new_event = event(0, 99, 520, false)?;
    let state = journal::recover(&b, &record, &context())?;
    let q = Query::new(
        &b,
        b.config().sources[0].stream,
        &new_event,
        &ep,
        &context(),
    )?;
    let (ca, na) = host.answers(&state, &q)?;
    let check = lookup(&b, &state, q, &ca, &na)?;
    record = journal::prepare_checked(
        &b,
        Some(&record),
        6,
        Action::Admit {
            stream: b.config().sources[0].stream,
            position: 4,
            event: &new_event,
        },
        &ep,
        Some(&check),
        &context(),
    )?
    .commit(&db)
    .await?;
    db.shutdown(context()).await?;
    let (db, ready) =
        Journal::begin_open(dir.path().join("old.sqlite"), b.journal_config(), context())?;
    ready.wait().await?;
    assert_eq!(db.load(context()).await?, Some(record.clone()));
    record = journal::prepare(
        &b,
        Some(&record),
        6,
        Action::Seal,
        &source_epoch(&b, Some(&record), 590, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha2, index2) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha2, index2)?;
    record = history::prune(
        &b,
        &record,
        host.archives.get(&sha2).ok_or("archive2")?,
        &receipt,
        &source_epoch(&b, Some(&record), 590, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let state = journal::recover(&b, &record, &context())?;
    let q = Query::new(
        &b,
        b.config().sources[1].stream,
        &duplicate,
        &ep,
        &context(),
    )?;
    let (ca, na) = host.answers(&state, &q)?;
    assert_eq!(
        ca.as_ref()
            .ok_or("canonical alias indexed")?
            .first_canonical_id(),
        events[3].id
    );
    assert_eq!(
        host.effect(
            ca.as_ref()
                .and_then(|a| a.effect())
                .ok_or("alias original effect")?
        )?,
        original
    );
    let check = lookup(&b, &state, q, &ca, &na)?;
    record = journal::prepare_checked(
        &b,
        Some(&record),
        7,
        Action::Admit {
            stream: b.config().sources[1].stream,
            position: 3,
            event: &duplicate,
        },
        &ep,
        Some(&check),
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha3, index3) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let mut cfg = config();
    cfg.revision = "new-policy-and-keys".into();
    cfg.threshold = 4;
    cfg.authority_keys_sha256 = [4; 32];
    let new = Binding::new(cfg, &context())?;
    let receipt = host.receipt(&new, &state, sha3, index3)?;
    // New host verifies the SAME committed old cursor, never a zero/fresh prefix.
    let proofs = new
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(600), true);
            p.position = state
                .source_positions()
                .iter()
                .find(|(stream, _)| *stream == s.stream)
                .map_or(0, |(_, n)| *n);
            p.authority_keys_sha256 = [4; 32];
            p.now = time(2000);
            p.verified_at = time(1990);
            p.verified_until = time(2300);
            p.coverage_from = time(400);
            p
        })
        .collect();
    let fresh = Epoch::new(&new, proofs, &context())?;
    let carried = history::carry(
        &b,
        &db,
        &record,
        host.archives.get(&sha3).ok_or("archive3")?,
        &receipt,
        &new,
        &fresh,
        &context(),
    )
    .await?;
    let (destination, ready) = Journal::begin_open(
        dir.path().join("new.sqlite"),
        new.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let mut migrated = carried.commit(&destination).await?;
    assert_eq!(migrated.checkpoint, 7);
    let state = journal::recover(&new, &migrated, &context())?;
    assert_eq!(state.metrics(&new)?.retained_events, 0);
    assert_eq!(
        state.source_positions(),
        journal::recover(&b, &record, &context())?.source_positions()
    );
    for old in [&events[3], &duplicate] {
        let state = journal::recover(&new, &migrated, &context())?;
        let ep = admission_epoch(&new, true)?;
        let q = Query::new(&new, new.config().sources[1].stream, old, &ep, &context())?;
        let (ca, na) = host.answers(&state, &q)?;
        assert_eq!(
            host.effect(
                ca.as_ref()
                    .and_then(|a| a.effect())
                    .ok_or("rolled original effect")?
            )?,
            original
        );
        let check = lookup(&new, &state, q, &ca, &na)?;
        let prepared = journal::prepare_checked(
            &new,
            Some(&migrated),
            migrated.checkpoint + 1,
            Action::Admit {
                stream: new.config().sources[1].stream,
                position: state
                    .source_positions()
                    .iter()
                    .find(|(s, _)| *s == new.config().sources[1].stream)
                    .ok_or("position")?
                    .1
                    + 1,
                event: old,
            },
            &ep,
            Some(&check),
            &context(),
        )?;
        assert!(matches!(
            prepared.applied(),
            journal::Applied::Admission(Admission::Duplicate)
        ));
        assert!(prepared.record().outbox.is_empty());
        migrated = prepared.commit(&destination).await?;
    }
    assert_eq!(migrated.checkpoint, 9);
    destination.shutdown(context()).await?;
    db.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn unsealed_success_effect_appears_in_second_archive_without_changing_input_origin() -> Result
{
    let (b, dir, db, record, _events, _original) = initial(false).await?;
    let mut host = Host::new(dir.path());
    let success = event(1, 2, 80, true)?;
    let record = journal::prepare(
        &b,
        Some(&record),
        5,
        Action::Admit {
            stream: b.config().sources[1].stream,
            position: 2,
            event: &success,
        },
        &admission_epoch(&b, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let q = Query::new(
        &b,
        b.config().sources[1].stream,
        &success,
        &admission_epoch(&b, false)?,
        &context(),
    )?;
    assert!(
        host.archives
            .get(&sha)
            .and_then(|a| a.native(q.native_id()?))
            .ok_or("unsealed native")?
            .effect()
            .is_none()
    );
    let receipt = host.receipt(&b, &state, sha, index)?;
    let pruned = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 50, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let sealed = journal::prepare(
        &b,
        Some(&pruned),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&pruned), 100, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    assert_eq!(sealed.outbox.len(), 1);
    let original = sealed.outbox[0].clone();
    let decoded: Episode = serde_json::from_slice(&original.bytes)?;
    assert_eq!(decoded.status, Status::Match);
    assert_eq!(decoded.originals.last(), Some(&success));
    let published = db.retire(sealed.revision, 1, context()).await?;
    assert_eq!(
        journal::recover(&b, &published, &context())?.original_effect(original.id),
        Some(original.clone())
    );
    let (sha2, index2) = host.publish(&b, &published)?;
    let state = journal::recover(&b, &published, &context())?;
    let receipt = host.receipt(&b, &state, sha2, index2)?;
    let pruned = history::prune(
        &b,
        &published,
        host.archives.get(&sha2).ok_or("archive2")?,
        &receipt,
        &source_epoch(&b, Some(&published), 100, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let state = journal::recover(&b, &pruned, &context())?;
    let (ca, na) = host.answers(&state, &q)?;
    for witness in [
        ca.as_ref().ok_or("canonical")?,
        na.as_ref().ok_or("native")?,
    ] {
        assert_eq!(witness.origin_archive(), sha);
        assert_eq!(witness.first_canonical_id(), success.id);
        let effect = witness.effect().ok_or("second archive effect")?;
        assert_eq!(effect.archive_sha256, sha2);
        assert_eq!(host.effect(effect)?, original);
    }
    let again = journal::prepare(
        &b,
        Some(&pruned),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&pruned), 150, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    assert!(again.outbox.is_empty());
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn cold_unknown_conflicts_incomplete_and_expired_lookup_never_advance_the_record() -> Result {
    let (b, dir, db, record, events, _original) = initial(true).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let pruned = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let state = journal::recover(&b, &pruned, &context())?;
    let ep = admission_epoch(&b, true)?;
    let source = b.config().sources[1].stream;
    let query = Query::new(&b, source, &events[3], &ep, &context())?;
    let (ca, na) = host.answers(&state, &query)?;
    let canonical = ca.as_ref().ok_or("canonical")?;
    let native = na.as_ref().ok_or("native")?;
    for (canonical_answer, native_answer, expected_conflict) in [
        (Answer::Known(canonical), Answer::Absent, true),
        (Answer::Unavailable, Answer::Known(native), false),
        (Answer::Known(canonical), Answer::Unavailable, false),
    ] {
        let auth = authority(
            &b,
            history::Claim::lookup(
                &query,
                state.archive_anchor().ok_or("anchor")?,
                &canonical_answer,
                &native_answer,
                &context(),
            )?,
        )?;
        let check = Lookup::new(
            query.clone(),
            state.archive_anchor().ok_or("anchor")?.clone(),
            canonical_answer,
            native_answer,
            auth,
            &context(),
        )?;
        let result = journal::prepare_checked(
            &b,
            Some(&pruned),
            5,
            Action::Admit {
                stream: source,
                position: 2,
                event: &events[3],
            },
            &ep,
            Some(&check),
            &context(),
        );
        if expected_conflict {
            assert!(matches!(result, Err(Error::Conflict)));
        } else {
            assert!(matches!(result, Err(Error::ArchiveRequired)));
        }
    }
    let mut changed = events[3].clone();
    changed.message = Some("different original content".into());
    let changed_query = Query::new(&b, source, &changed, &ep, &context())?;
    let auth = authority(
        &b,
        history::Claim::lookup(
            &changed_query,
            state.archive_anchor().ok_or("anchor")?,
            &Answer::Known(canonical),
            &Answer::Known(native),
            &context(),
        )?,
    )?;
    let check = Lookup::new(
        changed_query,
        state.archive_anchor().ok_or("anchor")?.clone(),
        Answer::Known(canonical),
        Answer::Known(native),
        auth,
        &context(),
    )?;
    assert!(matches!(
        journal::prepare_checked(
            &b,
            Some(&pruned),
            5,
            Action::Admit {
                stream: source,
                position: 2,
                event: &changed
            },
            &ep,
            Some(&check),
            &context()
        ),
        Err(Error::Conflict)
    ));
    assert!(
        Authority::new(
            &b,
            history::Verification {
                claim: history::Claim::lookup(
                    &query,
                    state.archive_anchor().ok_or("anchor")?,
                    &Answer::Known(canonical),
                    &Answer::Known(native),
                    &context()
                )?,
                reference: "fixture://incomplete".into(),
                verified_at: time(1990),
                verified_until: time(2300),
                now: time(2000),
                durable_originals: true,
                complete_cumulative_indexes: false
            },
            &context()
        )
        .is_err()
    );
    let short = Authority::new(
        &b,
        history::Verification {
            claim: history::Claim::lookup(
                &query,
                state.archive_anchor().ok_or("anchor")?,
                &Answer::Known(canonical),
                &Answer::Known(native),
                &context(),
            )?,
            reference: "fixture://short".into(),
            verified_at: time(1990),
            verified_until: time(2000) + chrono::TimeDelta::milliseconds(100),
            now: time(2000),
            durable_originals: true,
            complete_cumulative_indexes: true,
        },
        &context(),
    )?;
    let check = Lookup::new(
        query,
        state.archive_anchor().ok_or("anchor")?.clone(),
        Answer::Known(canonical),
        Answer::Known(native),
        short,
        &context(),
    )?;
    let prepared = journal::prepare_checked(
        &b,
        Some(&pruned),
        5,
        Action::Admit {
            stream: source,
            position: 2,
            event: &events[3],
        },
        &ep,
        Some(&check),
        &context(),
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    assert!(matches!(prepared.commit(&db).await, Err(Error::Cancelled)));
    assert_eq!(db.load(context()).await?, Some(pruned));
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn changed_predecessor_and_unsealed_generation_refuse_without_destination_writes() -> Result {
    let (b, dir, db, record, _events, _original) = initial(false).await?;
    let mut host = Host::new(dir.path());
    let future = event(1, 2, 80, true)?;
    let pending = journal::prepare(
        &b,
        Some(&record),
        5,
        Action::Admit {
            stream: b.config().sources[1].stream,
            position: 2,
            event: &future,
        },
        &admission_epoch(&b, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha, index) = host.publish(&b, &pending)?;
    let old_state = journal::recover(&b, &pending, &context())?;
    let mut cfg = config();
    cfg.revision = "next-policy".into();
    cfg.threshold = 4;
    let new = Binding::new(cfg, &context())?;
    let receipt = host.receipt(&new, &old_state, sha, index)?;
    let proofs = new
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(100), true);
            p.position = old_state
                .source_positions()
                .iter()
                .find(|(stream, _)| *stream == s.stream)
                .map_or(0, |(_, p)| *p);
            p
        })
        .collect();
    let fresh = Epoch::new(&new, proofs, &context())?;
    assert!(matches!(
        history::carry(
            &b,
            &db,
            &pending,
            host.archives.get(&sha).ok_or("archive")?,
            &receipt,
            &new,
            &fresh,
            &context()
        )
        .await,
        Err(Error::Pending)
    ));
    let sealed = journal::prepare(
        &b,
        Some(&pending),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&pending), 100, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    assert!(matches!(
        history::export(&b, &sealed, &context()),
        Err(Error::Pending)
    ));
    let published = db.retire(sealed.revision, 1, context()).await?;
    let (sha2, index2) = host.publish(&b, &published)?;
    let state = journal::recover(&b, &published, &context())?;
    let receipt = host.receipt(&new, &state, sha2, index2)?;
    let proofs = new
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(100), true);
            p.position = state
                .source_positions()
                .iter()
                .find(|(stream, _)| *stream == s.stream)
                .map_or(0, |(_, p)| *p);
            p
        })
        .collect();
    let fresh = Epoch::new(&new, proofs, &context())?;
    let carried = history::carry(
        &b,
        &db,
        &published,
        host.archives.get(&sha2).ok_or("archive2")?,
        &receipt,
        &new,
        &fresh,
        &context(),
    )
    .await?;
    let (destination, ready) = Journal::begin_open(
        dir.path().join("new.sqlite"),
        new.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let changed = journal::prepare(
        &b,
        Some(&published),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&published), 150, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    assert!(matches!(
        carried.commit(&destination).await,
        Err(Error::Conflict)
    ));
    assert_eq!(destination.load(context()).await?, None);
    assert_eq!(db.load(context()).await?, Some(changed));
    destination.shutdown(context()).await?;
    db.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn verifier_targets_cannot_be_swapped_between_publications_queries_or_answers() -> Result {
    let (b, dir, db, record, events, _) = initial(true).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let mut receipt = host.receipt(&b, &state, sha, index)?;
    receipt.index_sha256 = [77; 32];
    assert!(matches!(
        history::prune(
            &b,
            &record,
            host.archives.get(&sha).ok_or("archive")?,
            &receipt,
            &source_epoch(&b, Some(&record), 500, false)?,
            &context()
        ),
        Err(Error::Conflict)
    ));
    receipt.index_sha256 = index;
    let pruned = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let state = journal::recover(&b, &pruned, &context())?;
    let ep = admission_epoch(&b, true)?;
    let query = Query::new(
        &b,
        b.config().sources[1].stream,
        &events[3],
        &ep,
        &context(),
    )?;
    let (ca, na) = host.answers(&state, &query)?;
    let ca = ca.as_ref().ok_or("canonical")?;
    let na = na.as_ref().ok_or("native")?;
    let root = state.archive_anchor().ok_or("root")?;
    let claim = history::Claim::lookup(
        &query,
        root,
        &Answer::Known(ca),
        &Answer::Known(na),
        &context(),
    )?;
    assert!(matches!(
        Lookup::new(
            query.clone(),
            root.clone(),
            Answer::Absent,
            Answer::Known(na),
            authority(&b, claim.clone())?,
            &context()
        ),
        Err(Error::Unverified)
    ));
    let mut other = events[3].clone();
    other.id = Uuid::from_u128(888881);
    let other_query = Query::new(&b, b.config().sources[1].stream, &other, &ep, &context())?;
    assert!(matches!(
        Lookup::new(
            other_query,
            root.clone(),
            Answer::Known(ca),
            Answer::Known(na),
            authority(&b, claim)?,
            &context()
        ),
        Err(Error::Unverified)
    ));
    // A separately asserted impossible dual-index result also conflicts semantically.
    let bad_claim = history::Claim::lookup(
        &query,
        root,
        &Answer::Absent,
        &Answer::Known(na),
        &context(),
    )?;
    let check = Lookup::new(
        query,
        root.clone(),
        Answer::Absent,
        Answer::Known(na),
        authority(&b, bad_claim)?,
        &context(),
    )?;
    assert!(matches!(
        journal::prepare_checked(
            &b,
            Some(&pruned),
            5,
            Action::Admit {
                stream: b.config().sources[1].stream,
                position: 2,
                event: &events[3]
            },
            &ep,
            Some(&check),
            &context()
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(db.load(context()).await?, Some(pruned));
    db.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn malformed_canonical_only_identity_replays_original_gap_after_inactive_prune() -> Result {
    let (b, dir, db, record, _events, _) = initial(true).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let record = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let mut malformed = event(0, 99, 520, false)?;
    malformed.attributes["producer"]
        .as_object_mut()
        .ok_or("producer")?
        .remove("sequence");
    let ep = admission_epoch(&b, true)?;
    let state = journal::recover(&b, &record, &context())?;
    let q = Query::new(
        &b,
        b.config().sources[0].stream,
        &malformed,
        &ep,
        &context(),
    )?;
    assert!(q.native_id().is_none());
    let (ca, na) = host.answers(&state, &q)?;
    let check = lookup(&b, &state, q, &ca, &na)?;
    let admitted = journal::prepare_checked(
        &b,
        Some(&record),
        5,
        Action::Admit {
            stream: b.config().sources[0].stream,
            position: 4,
            event: &malformed,
        },
        &ep,
        Some(&check),
        &context(),
    )?
    .commit(&db)
    .await?;
    let sealed = journal::prepare(
        &b,
        Some(&admitted),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&admitted), 590, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let original = sealed.outbox[0].clone();
    assert_eq!(
        serde_json::from_slice::<Episode>(&original.bytes)?.status,
        Status::Indeterminate
    );
    let record = db.retire(sealed.revision, 1, context()).await?;
    let expired = journal::prepare(
        &b,
        Some(&record),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&record), 900, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha, index) = host.publish(&b, &expired)?;
    let state = journal::recover(&b, &expired, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let pruned = history::prune(
        &b,
        &expired,
        host.archives.get(&sha).ok_or("archive2")?,
        &receipt,
        &source_epoch(&b, Some(&expired), 900, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let state = journal::recover(&b, &pruned, &context())?;
    assert_eq!(state.metrics(&b)?.retained_events, 0);
    let proofs = b
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(1200), true);
            p.now = time(2000);
            p.verified_at = time(1990);
            p.verified_until = time(2300);
            p.coverage_from = time(1000);
            p
        })
        .collect();
    let ep = Epoch::new(&b, proofs, &context())?;
    let q = Query::new(
        &b,
        b.config().sources[0].stream,
        &malformed,
        &ep,
        &context(),
    )?;
    let (ca, na) = host.answers(&state, &q)?;
    assert!(na.is_none());
    let effect = ca
        .as_ref()
        .and_then(|w| w.effect())
        .ok_or("canonical gap effect")?;
    assert_eq!(host.effect(effect)?, original);
    let check = lookup(&b, &state, q, &ca, &na)?;
    let duplicate = journal::prepare_checked(
        &b,
        Some(&pruned),
        6,
        Action::Admit {
            stream: b.config().sources[0].stream,
            position: 5,
            event: &malformed,
        },
        &ep,
        Some(&check),
        &context(),
    )?;
    assert!(matches!(
        duplicate.applied(),
        journal::Applied::Admission(Admission::Duplicate)
    ));
    let committed = duplicate.commit(&db).await?;
    assert!(committed.outbox.is_empty());
    assert_eq!(
        journal::recover(&b, &committed, &context())?
            .metrics(&b)?
            .retained_events,
        0
    );
    db.shutdown(context()).await?;
    Ok(())
}

#[derive(Deserialize)]
struct IndexWire {
    canonical: Vec<(Uuid, Locator)>,
    native: Vec<(NativeId, Locator)>,
}
impl Host {
    fn reload(directory: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let mut host = Self::new(directory);
        let mut entries = std::fs::read_dir(directory)?
            .take(65)
            .collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() > 64 {
            return Err("bounded history fixture inventory".into());
        }
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().ok_or("fixture name")?;
            if !name.starts_with("archive-") && !name.starts_with("complete-index-") {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            assert!(metadata.is_file() && !metadata.file_type().is_symlink());
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert!(metadata.len() <= 32 * 1024 * 1024);
            let bytes = std::fs::read(entry.path())?;
            if name.starts_with("archive-") {
                let mut sha = Sha256::new();
                sha.update(b"PLATFORM::SIGNAL/correlation/archive/v1\0");
                sha.update(&bytes);
                let hash: [u8; 32] = sha.finalize().into();
                host.archives
                    .insert(hash, Archive::from_bytes(&bytes, hash, &context())?);
            } else {
                let wire: IndexWire = serde_json::from_slice(&bytes)?;
                assert!(wire.canonical.len() <= 1024 && wire.native.len() <= 1024);
                let canonical: BTreeMap<_, _> = wire.canonical.into_iter().collect();
                let native: BTreeMap<_, _> = wire.native.into_iter().collect();
                host.indexes
                    .insert(Sha256::digest(&bytes).into(), Index { canonical, native });
            }
        }
        Ok(host)
    }
}
fn fresh_generation_epoch(new: &Binding, prior: &State, frontier: i64) -> Result<Epoch> {
    let proofs = new
        .config()
        .sources
        .iter()
        .map(|s| {
            let mut p = verification(s, time(frontier), true);
            p.authority_keys_sha256 = new.config().authority_keys_sha256;
            p.position = prior
                .source_positions()
                .iter()
                .find(|(stream, _)| *stream == s.stream)
                .map_or(0, |(_, n)| *n);
            p.now = time(2000);
            p.verified_at = time(1990);
            p.verified_until = time(2300);
            p.coverage_from = time(400);
            p
        })
        .collect();
    Ok(Epoch::new(new, proofs, &context())?)
}
fn next_binding() -> Result<Binding> {
    let mut cfg = config();
    cfg.revision = "process-policy-and-key-rollover".into();
    cfg.threshold = 4;
    cfg.authority_keys_sha256 = [4; 32];
    Ok(Binding::new(cfg, &context())?)
}
struct BuiltHistory {
    binding: Binding,
    db: Journal,
    record: Record,
    original: Output,
    old: Option<(Binding, Journal, Record)>,
}
async fn build_history_phase(directory: &Path, phase: &str) -> Result<BuiltHistory> {
    let (b, db, record, events, original) = initial_in(directory, true).await?;
    let mut host = Host::new(directory);
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let mut record = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    if phase == "pruned" {
        return Ok(BuiltHistory {
            binding: b,
            db,
            record,
            original,
            old: None,
        });
    }
    let mut duplicate = events[3].clone();
    duplicate.id = Uuid::from_u128(987654);
    duplicate.observed_at = time(550);
    let state = journal::recover(&b, &record, &context())?;
    let ep = admission_epoch(&b, true)?;
    let q = Query::new(
        &b,
        b.config().sources[1].stream,
        &duplicate,
        &ep,
        &context(),
    )?;
    let (ca, na) = host.answers(&state, &q)?;
    let check = lookup(&b, &state, q, &ca, &na)?;
    record = journal::prepare_checked(
        &b,
        Some(&record),
        5,
        Action::Admit {
            stream: b.config().sources[1].stream,
            position: 2,
            event: &duplicate,
        },
        &ep,
        Some(&check),
        &context(),
    )?
    .commit(&db)
    .await?;
    if phase == "alias" {
        return Ok(BuiltHistory {
            binding: b,
            db,
            record,
            original,
            old: None,
        });
    }
    assert_eq!(phase, "carry");
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let new = next_binding()?;
    let receipt = host.receipt(&new, &state, sha, index)?;
    let ep = fresh_generation_epoch(&new, &state, 600)?;
    let prepared = history::carry(
        &b,
        &db,
        &record,
        host.archives.get(&sha).ok_or("archive2")?,
        &receipt,
        &new,
        &ep,
        &context(),
    )
    .await?;
    // Protected intent precedes destination COMMIT; activation selection is absent
    // at the kill seam and must be resolved explicitly by the fresh host.
    write_new(
        &directory.join("handoff-intent.json"),
        &serde_json::to_vec(&(record.clone(), prepared.record().clone()))?,
    )?;
    let (destination, ready) = Journal::begin_open(
        directory.join("new.sqlite"),
        new.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let migrated = prepared.commit(&destination).await?;
    Ok(BuiltHistory {
        binding: new,
        db: destination,
        record: migrated,
        original,
        old: Some((b, db, record)),
    })
}
#[tokio::test]
#[ignore = "owned history crash child only"]
async fn history_crash_child() -> Result {
    let directory = PathBuf::from(
        std::env::var_os("CORRELATION_HISTORY_CHILD_DIR").ok_or("owned child directory")?,
    );
    let phase = std::env::var("CORRELATION_HISTORY_CHILD_PHASE")?;
    let built = build_history_phase(&directory, &phase).await?;
    assert!(built.record.outbox.is_empty());
    assert_eq!(built.db.config(), &built.binding.journal_config());
    write_new(
        &directory.join("ready.tmp"),
        b"history-committed-source-ack-withheld",
    )?;
    std::fs::rename(directory.join("ready.tmp"), directory.join("ready"))?;
    std::fs::File::open(&directory)?.sync_all()?;
    std::future::pending::<()>().await;
    println!("CORRELATION-HISTORY-SOURCE-ACK");
    built.db.shutdown(context()).await?;
    Ok(())
}
struct OwnedHistoryChild(std::process::Child);
impl Drop for OwnedHistoryChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[tokio::test]
#[ignore = "requires an explicitly owned target history evidence directory"]
async fn history_process_crash() -> Result {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let output =
        PathBuf::from(std::env::var_os("CORRELATION_HISTORY_OUTPUT").ok_or("owned output")?)
            .canonicalize()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("root")?
        .join("target")
        .canonicalize()?;
    assert!(output.starts_with(root));
    assert_eq!(
        std::fs::metadata(&output)?.permissions().mode() & 0o777,
        0o700
    );
    let began = Instant::now();
    let mut cases = Vec::new();
    for phase in ["pruned", "alias", "carry"] {
        let directory = output.join(phase);
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let expected_dir = directory.join("expected");
        std::fs::create_dir(&expected_dir)?;
        std::fs::set_permissions(&expected_dir, std::fs::Permissions::from_mode(0o700))?;
        let expected = build_history_phase(&expected_dir, phase).await?;
        let expected_record = expected.record.clone();
        let original = expected.original.clone();
        expected.db.shutdown(context()).await?;
        if let Some((_, db, _)) = expected.old {
            db.shutdown(context()).await?;
        }
        let log = std::fs::File::create_new(directory.join("child.log"))?;
        let mut child = OwnedHistoryChild(
            Command::new(std::env::current_exe()?)
                .args(["--ignored", "--exact", "history_crash_child", "--nocapture"])
                .env_clear()
                .env("CORRELATION_HISTORY_CHILD_DIR", &directory)
                .env("CORRELATION_HISTORY_CHILD_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let pid = child.0.id();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if std::fs::read(directory.join("ready")).ok().as_deref()
                == Some(b"history-committed-source-ack-withheld")
            {
                break;
            }
            if child.0.try_wait()?.is_some() {
                return Err("child exited before history witness".into());
            }
            if Instant::now() >= deadline {
                return Err("history witness deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(child.0.try_wait()?.is_none());
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        assert!(std::fs::metadata(directory.join("child.log"))?.len() < 16384);
        assert!(
            !std::fs::read_to_string(directory.join("child.log"))?
                .contains("CORRELATION-HISTORY-SOURCE-ACK")
        );
        let binding = if phase == "carry" {
            next_binding()?
        } else {
            Binding::new(config(), &context())?
        };
        let path = directory.join(if phase == "carry" {
            "new.sqlite"
        } else {
            "old.sqlite"
        });
        let (db, ready) = Journal::begin_open(path.clone(), binding.journal_config(), context())?;
        ready.wait().await?;
        let loaded = db.load(context()).await?.ok_or("committed history")?;
        assert_eq!(loaded, expected_record);
        if phase == "carry" {
            assert!(!directory.join("active-generation").exists());
            let intent = directory.join("handoff-intent.json");
            assert!(std::fs::metadata(&intent)?.len() <= 32 * 1024 * 1024);
            let (old, proposed): (Record, Record) =
                serde_json::from_slice(&std::fs::read(intent)?)?;
            assert_eq!(loaded, proposed);
            let prior = Binding::new(config(), &context())?;
            let (source, ready) = Journal::begin_open(
                directory.join("old.sqlite"),
                prior.journal_config(),
                context(),
            )?;
            ready.wait().await?;
            assert_eq!(source.load(context()).await?, Some(old));
            source.shutdown(context()).await?;
            write_new(
                &directory.join("active-generation"),
                b"new-exact-intent-reconciled",
            )?;
        }
        assert_eq!(
            std::fs::read(directory.join(format!("published-{}", original.id)))?,
            original.bytes
        );
        let host = Host::reload(&directory)?;
        let state = journal::recover(&binding, &loaded, &context())?;
        assert_eq!(state.metrics(&binding)?.retained_events, 0);
        let events = inputs()?;
        let mut duplicate = events[3].clone();
        duplicate.id = Uuid::from_u128(987654);
        duplicate.observed_at = time(550);
        let ep = admission_epoch(&binding, true)?;
        let query = Query::new(
            &binding,
            binding.config().sources[1].stream,
            &duplicate,
            &ep,
            &context(),
        )?;
        let (ca, na) = host.answers(&state, &query)?;
        assert_eq!(
            host.effect(
                na.as_ref()
                    .and_then(|w| w.effect())
                    .ok_or("original protected effect")?
            )?,
            original
        );
        assert_eq!(
            na.as_ref().ok_or("native")?.first_canonical_id(),
            events[3].id
        );
        let check = lookup(&binding, &state, query, &ca, &na)?;
        let position = state
            .source_positions()
            .iter()
            .find(|(s, _)| *s == binding.config().sources[1].stream)
            .ok_or("position")?
            .1
            + 1;
        let replay = journal::prepare_checked(
            &binding,
            Some(&loaded),
            loaded.checkpoint + 1,
            Action::Admit {
                stream: binding.config().sources[1].stream,
                position,
                event: &duplicate,
            },
            &ep,
            Some(&check),
            &context(),
        )?;
        assert!(matches!(
            replay.applied(),
            journal::Applied::Admission(Admission::Duplicate)
        ));
        let committed = replay.commit(&db).await?;
        assert!(committed.outbox.is_empty());
        assert_eq!(
            journal::recover(&binding, &committed, &context())?
                .metrics(&binding)?
                .retained_events,
            0
        );
        db.shutdown(context()).await?;
        let (db, ready) = Journal::begin_open(path, binding.journal_config(), context())?;
        ready.wait().await?;
        assert_eq!(db.load(context()).await?, Some(committed));
        db.shutdown(context()).await?;
        cases.push(serde_json::json!({"phase":phase,"pid":pid,"actual_sigkill_signal":9,"source_ack_withheld":true,"exact_history_record_recovered":true,"native_duplicate_new_uuid_progress_only":true,"first_canonical_preserved":true,"exact_original_effect":true,"published_before_retirement":true,"durable_dual_indexes_reloaded":true,"no_expired_event_reinserted":true,"second_reopen_exact":true,"uncertain_carry_resolved_before_activation":phase=="carry"}));
    }
    std::fs::write(
        output.join("process-report.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version":1,"status":"passed_local","rule":"SIG-D11-history","actual_sigkill":3,"owned_process_cleanup":true,"cases":cases,"elapsed_seconds":began.elapsed().as_secs_f64()}),
        )?,
    )?;
    Ok(())
}

#[tokio::test]
async fn retired_late_input_counter_survives_hot_history_reclamation() -> Result {
    let (b, dir, db, record, _events, _) = initial(true).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let record = history::prune(
        &b,
        &record,
        host.archives.get(&sha).ok_or("archive")?,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let late = event(0, 99, 480, false)?;
    let state = journal::recover(&b, &record, &context())?;
    let ep = admission_epoch(&b, true)?;
    let q = Query::new(&b, b.config().sources[0].stream, &late, &ep, &context())?;
    let (ca, na) = host.answers(&state, &q)?;
    let check = lookup(&b, &state, q, &ca, &na)?;
    let staged = journal::prepare_checked(
        &b,
        Some(&record),
        5,
        Action::Admit {
            stream: b.config().sources[0].stream,
            position: 4,
            event: &late,
        },
        &ep,
        Some(&check),
        &context(),
    )?;
    assert!(matches!(
        staged.applied(),
        journal::Applied::Admission(Admission::Late)
    ));
    let record = staged.commit(&db).await?;
    assert_eq!(
        journal::recover(&b, &record, &context())?
            .metrics(&b)?
            .late_inputs,
        1
    );
    let sealed = journal::prepare(
        &b,
        Some(&record),
        5,
        Action::Seal,
        &source_epoch(&b, Some(&record), 900, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let (sha, index) = host.publish(&b, &sealed)?;
    let state = journal::recover(&b, &sealed, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let pruned = history::prune(
        &b,
        &sealed,
        host.archives.get(&sha).ok_or("archive2")?,
        &receipt,
        &source_epoch(&b, Some(&sealed), 900, true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let metrics = journal::recover(&b, &pruned, &context())?.metrics(&b)?;
    assert_eq!(metrics.retained_events, 0);
    assert_eq!(metrics.late_inputs, 1);
    db.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn archive_summary_keeps_original_enrollment_and_prior_anchor_without_renewing_authority()
-> Result {
    let (b, dir, db, record, _, _) = initial(true).await?;
    let mut host = Host::new(dir.path());
    let (sha, index) = host.publish(&b, &record)?;
    let archive = host.archives.get(&sha).ok_or("archive")?;
    let original_bytes = archive.bytes().to_vec();
    let summary = archive.historical_summary(&context())?;
    let configured = b.journal_config();
    assert_eq!(summary.schema_version(), 1);
    assert_eq!(summary.detector_partition(), configured.source_stream);
    assert_eq!(summary.journal_source_binding(), configured.source_binding);
    assert_eq!(summary.enrollment_binding(), configured.enrollment_binding);
    assert_eq!(
        summary.authority_keys_sha256(),
        b.config().authority_keys_sha256
    );
    assert_eq!(summary.revision(), record.revision);
    assert_eq!(summary.checkpoint(), record.checkpoint);
    assert!(summary.prior_anchor().is_none());
    let state = journal::recover(&b, &record, &context())?;
    let receipt = host.receipt(&b, &state, sha, index)?;
    let pruned = history::prune(
        &b,
        &record,
        archive,
        &receipt,
        &source_epoch(&b, Some(&record), 500, false)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let after = history::export(&b, &pruned, &context())?;
    let after = Archive::from_bytes(after.bytes(), after.sha256(), &context())?;
    let anchored = after.historical_summary(&context())?;
    assert_eq!(
        anchored.prior_anchor(),
        journal::recover(&b, &pruned, &context())?.archive_anchor()
    );
    assert_eq!(anchored.namespace(), summary.namespace());
    assert_eq!(anchored.revision(), pruned.revision);
    let current = next_binding()?;
    let old = Archive::from_bytes(&original_bytes, sha, &context())?;
    let old_summary = old.historical_summary(&context())?;
    assert_eq!(
        old_summary.enrollment_binding(),
        configured.enrollment_binding
    );
    assert_ne!(
        old_summary.enrollment_binding(),
        current.journal_config().enrollment_binding
    );
    assert_ne!(
        old_summary.authority_keys_sha256(),
        current.config().authority_keys_sha256
    );
    assert_eq!(old.bytes(), original_bytes);
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        old.historical_summary(&cancelled),
        Err(Error::Cancelled)
    ));
    db.shutdown(context()).await?;
    Ok(())
}

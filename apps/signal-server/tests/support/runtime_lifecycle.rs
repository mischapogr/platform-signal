//! Synthetic private verifier/custody host over actual retained native metadata.
//! Files and SQLite are real; these facts are not live capture authorization.
use super::support::{Result, config, context};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_collector_sdk::runtime_metadata as sdk;
use signal_event::{SignalEvent, Source};
use signal_rules::{
    RuleContext,
    correlation::{
        self, Contributor, NativeId,
        d14::*,
        history::{self, Archive, ArchivedIdentity, Authority, Query, Receipt},
        journal::{self, RuntimeAction},
    },
    state_journal::{Journal, Record},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn ns(value: u64) -> DateTime<Utc> {
    DateTime::from_timestamp_nanos(value as i64)
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result {
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
pub fn owned_directory(path: &Path) -> Result {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn output_directory(variable: &str) -> Result<PathBuf> {
    let p = PathBuf::from(std::env::var(variable)?).canonicalize()?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()?;
    assert!(p.starts_with(root));
    assert_eq!(std::fs::metadata(&p)?.permissions().mode() & 0o777, 0o700);
    Ok(p)
}
pub fn qualified_report(directory: &Path) -> Result<Value> {
    let report: Value = serde_json::from_slice(&std::fs::read(directory.join("report.json"))?)?;
    assert_eq!(report["passed"], true);
    assert_eq!(report["source_unchanged"], true);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, digest) in report["source_sha256"].as_object().ok_or("source map")? {
        assert_eq!(
            hex(&sha(&std::fs::read(root.join(path))?)),
            digest.as_str().ok_or("source hash")?
        );
    }
    for (path, digest) in report["executable_sha256"].as_object().ok_or("ELF map")? {
        assert_eq!(
            hex(&sha(&std::fs::read(path)?)),
            digest.as_str().ok_or("ELF hash")?
        );
    }
    Ok(report)
}
pub struct NativeCase {
    pub name: String,
    pub binding: RuntimeBinding,
    pub events: Vec<SignalEvent>,
    pub first: DateTime<Utc>,
    pub terminal: DateTime<Utc>,
    pub complete: bool,
    pub raw_sha: [u8; 32],
}
impl NativeCase {
    pub fn load(directory: &Path, name: &str, scenario: &str) -> Result<Self> {
        let report = qualified_report(directory)?;
        let case = report["cases"]
            .as_array()
            .ok_or("cases")?
            .iter()
            .find(|v| v["case"] == name)
            .ok_or("case")?;
        assert_eq!(case["passed"], true);
        let raw = std::fs::read(directory.join(format!("{name}.raw.jsonl")))?;
        let lines = raw.split_inclusive(|b| *b == b'\n').collect::<Vec<_>>();
        assert_eq!(
            lines.len() as u64,
            case["records"].as_u64().ok_or("records")?
        );
        let first: Value = serde_json::from_slice(lines.first().ok_or("first")?)?;
        let last: Value = serde_json::from_slice(lines.last().ok_or("last")?)?;
        let complete = case["exit_code"] == 0;
        assert_eq!(last["kind"], if complete { "end" } else { "gap" });
        let mut digest = [0; 32];
        let encoded = first["config_sha256"].as_str().ok_or("config")?;
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16)?;
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
        cfg.partition = Uuid::new_v5(&Uuid::from_u128(20261026), scenario.as_bytes());
        cfg.sources[0].stream = Uuid::new_v5(&cfg.partition, b"runtime-source");
        cfg.sources[0].host = host.into();
        cfg.sources[0].metadata_config_sha256 = digest;
        cfg.revision = format!("owned-native-{scenario}-v1");
        for a in &mut cfg.policy_authorities {
            a.account = Some("fixture-old-policy-account".into());
            a.resource = Some(format!("fixture-{:?}-policy", a.role));
        }
        let binding = RuntimeBinding::new(cfg, &context())?;
        let mut continuity = sdk::Continuity::new();
        let mut events = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let native = continuity.admit(line, &profile)?;
            events.push(sdk::normalize(
                line,
                &profile,
                Source {
                    source_type: "runtime".into(),
                    name: Some("owned-source".into()),
                },
                Uuid::new_v5(&binding.config().partition, &(i as u64).to_le_bytes()),
                ns(native.observed_ns + 1_000_000_000),
            )?);
        }
        Ok(Self {
            name: name.into(),
            binding,
            events,
            first: ns(first["timestamp_ns"].as_u64().ok_or("first time")?),
            terminal: ns(last["timestamp_ns"].as_u64().ok_or("last time")?),
            complete,
            raw_sha: sha(&raw),
        })
    }
    pub fn epoch(
        &self,
        b: &RuntimeBinding,
        position: u64,
        advance_ms: i64,
        c: &RuleContext,
    ) -> Result<RuntimeEpoch> {
        self.epoch_with_identity(b, position, advance_ms, c, true)
    }
    pub fn epoch_with_identity(
        &self,
        b: &RuntimeBinding,
        position: u64,
        advance_ms: i64,
        c: &RuleContext,
        identity_link_verified: bool,
    ) -> Result<RuntimeEpoch> {
        let frontier = self.terminal + TimeDelta::milliseconds(advance_ms + b.config().lateness_ms);
        let now = frontier + TimeDelta::seconds(2);
        // Explicit SYNTHETIC supervisor proof: owned initial-exec absence before
        // capture and quiescence after reported terminal. Never producer flags.
        let from = self.first
            - TimeDelta::milliseconds(b.config().correlation_ms + b.config().lateness_ms);
        let s = &b.config().sources[0];
        let source = RuntimeVerification {
            source: correlation::Verification {
                stream: s.stream,
                position,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: b.config().authority_keys_sha256,
                verification_reference: format!(
                    "fixture://supervised-preexec-absence-and-closed-capture/{}",
                    self.name
                ),
                verified_at: now,
                verified_until: now + TimeDelta::seconds(60),
                now,
                coverage_from: from,
                frontier,
                complete: self.complete,
                authenticated: true,
            },
            capture: CaptureEvidence {
                enrollment_sha256: b.enrollment_sha256(),
                metadata_only: true,
                execution_continuity: identity_link_verified,
                clock_continuity: true,
            },
        };
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
                reference: format!("fixture://independent-historical-policy/{}", self.name),
                verified_at: now,
                verified_until: now + TimeDelta::seconds(60),
                now,
                coverage_from: from,
                frontier,
                complete: true,
                authenticated: true,
            })
            .collect();
        Ok(RuntimeEpoch::new(b, vec![source], policies, c)?)
    }
    pub fn decision(
        &self,
        b: &RuntimeBinding,
        input: &Input,
        invert: bool,
        missing_destination: bool,
        c: &RuleContext,
    ) -> Result<Option<CurrentDecision>> {
        let role = match input.operation() {
            Operation::Read {
                object,
                result,
                error: false,
                ..
            } if object.object_type == 0o100000 && *result > 0 => Role::Asset,
            Operation::Connect {
                object,
                result: 0,
                error: false,
                ..
            } if object.object_type == 0o140000 => Role::Destination,
            _ => return Ok(None),
        };
        if role == Role::Destination && missing_destination {
            return Ok(None);
        }
        let authority = b
            .config()
            .policy_authorities
            .iter()
            .find(|a| a.role == role)
            .ok_or("policy")?;
        let interval = input.operation().interval().ok_or("interval")?;
        let now = input.event().observed_at;
        // Synthetic versioned private classification; no flags from the event.
        let yes = (role == Role::Destination || self.name != "reuse") ^ invert;
        let proof = Verification {
            claim: input.claim(c)?,
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
            reference: format!("fixture://private-policy/{}/{role:?}", self.name),
            verified_at: now,
            verified_until: now + TimeDelta::seconds(60),
            now,
            authenticated: true,
        };
        Ok(Some(CurrentDecision::new(b, input, proof, c)?))
    }
    pub fn next_binding(&self, c: &RuleContext) -> Result<RuntimeBinding> {
        let mut cfg = self.binding.config().clone();
        cfg.revision.push_str("-scope-key-v2");
        cfg.authority_keys_sha256 = [9; 32];
        for a in &mut cfg.policy_authorities {
            a.account = Some("fixture-new-policy-account".into());
            a.policy_revision.push_str("-v2");
            a.authority_keys_sha256 = [55; 32];
        }
        Ok(RuntimeBinding::new(cfg, c)?)
    }
}
pub async fn open(b: &RuntimeBinding, path: &Path) -> Result<Journal> {
    let (db, ready) = Journal::begin_open(path.to_owned(), b.journal_config(), context())?;
    ready.wait().await?;
    Ok(db)
}
pub async fn ingest(case: &NativeCase, db: &Journal, missing_destination: bool) -> Result<Record> {
    let b = &case.binding;
    let mut prior = None;
    for (i, event) in case.events.iter().enumerate() {
        let c = context();
        let input = Input::new(b, b.config().sources[0].stream, event, &c)?;
        let ep = case.epoch(b, case.events.len() as u64, 25, &c)?;
        let decision = case.decision(b, &input, false, missing_destination, &c)?;
        let p = journal::prepare_runtime(
            b,
            prior.as_ref(),
            i as u64 + 1,
            RuntimeAction::Admit {
                input: &input,
                position: i as u64 + 1,
                decision: decision.as_ref(),
            },
            &ep,
            &c,
        )?;
        prior = Some(p.commit(db).await?);
    }
    let prior = prior.ok_or("inputs")?;
    seal(case, b, db, &prior, 25).await
}
pub async fn seal(
    case: &NativeCase,
    b: &RuntimeBinding,
    db: &Journal,
    prior: &Record,
    advance_ms: i64,
) -> Result<Record> {
    let c = context();
    Ok(journal::prepare_runtime(
        b,
        Some(prior),
        prior.checkpoint,
        RuntimeAction::Seal,
        &case.epoch(b, prior.checkpoint, advance_ms, &c)?,
        &c,
    )?
    .commit(db)
    .await?)
}
pub fn publish_effects(directory: &Path, record: &Record, allowed: &[Contributor]) -> Result {
    for output in &record.outbox {
        let e: correlation::Episode = serde_json::from_slice(&output.bytes)?;
        if e.contributors.iter().any(|scope| !allowed.contains(scope)) {
            return Err("whole original contributor inventory must be authorized".into());
        }
        write_new(
            &directory.join(format!("published-{}.json", output.id)),
            &output.bytes,
        )?;
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Locator {
    archive: [u8; 32],
    canonical: Uuid,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Index {
    canonical: BTreeMap<Uuid, Locator>,
    native: BTreeMap<NativeId, Locator>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexWire {
    canonical: Vec<(Uuid, Locator)>,
    native: Vec<(NativeId, Locator)>,
}
impl Index {
    fn bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&IndexWire {
            canonical: self
                .canonical
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            native: self
                .native
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })?)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let v: IndexWire = serde_json::from_slice(bytes)?;
        if v.canonical.len() > 1024 || v.native.len() > 1024 {
            return Err("bounded fixture index".into());
        }
        let nc = v.canonical.len();
        let nn = v.native.len();
        let result = Self {
            canonical: v.canonical.into_iter().collect(),
            native: v.native.into_iter().collect(),
        };
        if nc != result.canonical.len() || nn != result.native.len() {
            return Err("duplicate index keys".into());
        }
        Ok(result)
    }
}
pub struct Host {
    pub directory: PathBuf,
    pub archives: BTreeMap<[u8; 32], Archive>,
    indexes: BTreeMap<[u8; 32], Index>,
    publications: usize,
}
impl Host {
    pub fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
            archives: BTreeMap::new(),
            indexes: BTreeMap::new(),
            publications: 0,
        }
    }
    fn witness(&self, l: &Locator) -> Result<ArchivedIdentity> {
        self.archives
            .get(&l.archive)
            .ok_or("archive unavailable")?
            .canonical(l.canonical)
            .ok_or("identity unavailable".into())
    }
    fn validate(&self, index: &Index) -> Result {
        let mut canonical = BTreeSet::new();
        let mut native = BTreeSet::new();
        for archive in self.archives.values() {
            for w in archive.identities() {
                canonical.insert(w.canonical_id());
                let target = self.witness(
                    index
                        .canonical
                        .get(&w.canonical_id())
                        .ok_or("partial canonical index")?,
                )?;
                if target.canonical_sha256() != w.canonical_sha256()
                    || target.native_id() != w.native_id()
                    || target.first_canonical_id() != w.first_canonical_id()
                    || target.content_sha256() != w.content_sha256()
                    || target.origin_archive() != w.origin_archive()
                {
                    return Err("canonical index conflict".into());
                }
                if let Some(effect) = w.effect() {
                    if target.effect() != Some(effect) {
                        return Err("original effect lost".into());
                    }
                    self.effect(effect)?;
                }
                if let Some(id) = w.native_id() {
                    native.insert(id.clone());
                    let target =
                        self.witness(index.native.get(id).ok_or("partial native index")?)?;
                    if target.native_id() != Some(id)
                        || target.first_canonical_id() != w.first_canonical_id()
                        || target.content_sha256() != w.content_sha256()
                        || target.origin_archive() != w.origin_archive()
                    {
                        return Err("native index conflict".into());
                    }
                    if let Some(effect) = w.effect()
                        && target.effect() != Some(effect)
                    {
                        return Err("native original effect lost".into());
                    }
                }
            }
        }
        if canonical.len() != index.canonical.len() || native.len() != index.native.len() {
            return Err("extraneous index keys".into());
        }
        Ok(())
    }
    pub fn publish(&mut self, b: &RuntimeBinding, r: &Record) -> Result<([u8; 32], [u8; 32])> {
        let c = context();
        let state = journal::recover_runtime(b, r, &c)?;
        let archive = history::export_runtime(b, r, &c)?;
        let digest = archive.sha256();
        write_new(
            &self
                .directory
                .join(format!("archive-{}.json", self.publications)),
            archive.bytes(),
        )?;
        let mut index = match state.archive_anchor() {
            Some(a) => self
                .indexes
                .get(&a.index_sha256)
                .ok_or("complete prior index")?
                .clone(),
            None => Index::default(),
        };
        for w in archive.identities() {
            let l = Locator {
                archive: digest,
                canonical: w.canonical_id(),
            };
            index.canonical.insert(w.canonical_id(), l.clone());
            if let Some(id) = w.native_id() {
                index.native.insert(id.clone(), l);
            }
        }
        self.archives.insert(digest, archive);
        self.validate(&index)?;
        let bytes = index.bytes()?;
        let sha = sha(&bytes);
        write_new(
            &self
                .directory
                .join(format!("complete-index-{}.json", self.publications)),
            &bytes,
        )?;
        self.indexes.insert(sha, index);
        self.publications += 1;
        Ok((digest, sha))
    }
    pub fn reload(directory: &Path) -> Result<Self> {
        let mut h = Self::new(directory);
        let mut paths = std::fs::read_dir(directory)?
            .take(129)
            .collect::<std::io::Result<Vec<_>>>()?;
        if paths.len() > 128 {
            return Err("bounded custody fixture inventory".into());
        }
        paths.sort_by_key(|p| p.file_name());
        for p in paths {
            let name = p.file_name();
            let name = name.to_str().ok_or("file name")?;
            if !name.starts_with("archive-") && !name.starts_with("complete-index-") {
                continue;
            }
            let m = std::fs::symlink_metadata(p.path())?;
            if !m.is_file()
                || m.file_type().is_symlink()
                || m.nlink() != 1
                || m.permissions().mode() & 0o777 != 0o600
                || m.len() > 32 * 1024 * 1024
            {
                return Err("unsafe custody fixture file".into());
            }
            let bytes = std::fs::read(p.path())?;
            if name.starts_with("archive-") {
                let mut hash = Sha256::new();
                hash.update(b"PLATFORM::SIGNAL/correlation/D14-archive/v2\0");
                hash.update(&bytes);
                let sha = hash.finalize().into();
                h.archives
                    .insert(sha, Archive::from_bytes(&bytes, sha, &context())?);
                h.publications += 1;
            } else {
                h.indexes.insert(sha(&bytes), Index::decode(&bytes)?);
            }
        }
        Ok(h)
    }
    pub fn receipt(
        &self,
        b: &RuntimeBinding,
        state: &RuntimeState,
        archive: [u8; 32],
        index: [u8; 32],
        now: DateTime<Utc>,
        c: &RuleContext,
    ) -> Result<Receipt> {
        self.validate(self.indexes.get(&index).ok_or("index unavailable")?)?;
        let previous = state.archive_anchor().map_or([0; 32], |a| a.root_sha256);
        let claim = history::Claim::publication(
            self.archives.get(&archive).ok_or("archive unavailable")?,
            previous,
            index,
            c,
        )?;
        Ok(Receipt {
            archive_sha256: archive,
            previous_root: previous,
            index_sha256: index,
            authority: authority(b, claim, now, c)?,
        })
    }
    pub fn answers(
        &self,
        state: &RuntimeState,
        q: &Query,
    ) -> Result<(Option<ArchivedIdentity>, Option<ArchivedIdentity>)> {
        let index = self
            .indexes
            .get(&state.archive_anchor().ok_or("anchor")?.index_sha256)
            .ok_or("exact index unavailable")?;
        self.validate(index)?;
        Ok((
            index
                .canonical
                .get(&q.canonical_id())
                .map(|l| self.witness(l))
                .transpose()?,
            q.native_id()
                .and_then(|n| index.native.get(n))
                .map(|l| self.witness(l))
                .transpose()?,
        ))
    }
    pub fn effect(
        &self,
        reference: &history::EffectRef,
    ) -> Result<signal_rules::state_journal::Output> {
        Ok(self
            .archives
            .get(&reference.archive_sha256)
            .ok_or("original unavailable")?
            .effect(reference)?)
    }
    pub fn prove_partial_refusal(&self, index: [u8; 32]) -> Result {
        let mut partial = self.indexes.get(&index).ok_or("index")?.clone();
        partial.native.pop_first().ok_or("native key")?;
        let path = self.directory.join("partial-index.json");
        write_new(&path, &partial.bytes()?)?;
        assert!(
            self.validate(&Index::decode(&std::fs::read(path)?)?)
                .is_err()
        );
        Ok(())
    }
}
pub fn authority(
    b: &RuntimeBinding,
    claim: history::Claim,
    now: DateTime<Utc>,
    c: &RuleContext,
) -> Result<Authority> {
    Ok(Authority::new_runtime(
        b,
        history::Verification {
            claim,
            reference: "fixture://verified-fsynced-originals-and-complete-cumulative-index".into(),
            verified_at: now,
            verified_until: now + TimeDelta::seconds(60),
            now,
            durable_originals: true,
            complete_cumulative_indexes: true,
        },
        c,
    )?)
}

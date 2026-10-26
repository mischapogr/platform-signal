//! Real journal/export/index files with synthetic source/policy/observer authority.
use super::*;
use sha2::{Digest, Sha256};
use signal_rules::{
    RuleContext,
    correlation::{
        self,
        d14::*,
        history::{self, Anchor, Archive, Authority, Receipt},
        journal::{self, Action, RuntimeAction},
    },
    state_journal::{Journal, Output, Record},
};
use std::{collections::BTreeMap, io::Write, os::unix::fs::OpenOptionsExt, path::Path};
#[allow(dead_code)]
#[path = "../../../../../crates/signal-rules/tests/support/correlation.rs"]
mod auth;
#[allow(dead_code)]
#[path = "../../../../../crates/signal-rules/tests/support/correlation_d14.rs"]
mod runtime;
pub(super) enum Detector {
    D11,
    D14,
}
pub(super) struct Bundle {
    pub reference: FindingReference,
    pub episode: correlation::Episode,
    pub report: Value,
    pub configuration: Value,
    pub root: std::path::PathBuf,
    signer: Ed25519KeyPair,
}
fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(10))
}
fn replacement_runtime_binding() -> Result<RuntimeBinding, Box<dyn std::error::Error>> {
    let mut cfg = runtime::config();
    cfg.revision = "replacement-generation".into();
    cfg.authority_keys_sha256 = [88; 32];
    for authority in &mut cfg.policy_authorities {
        authority.account = Some("replacement-policy-scope".into());
        authority.resource = Some("replacement-policy".into());
        authority.policy_revision = "replacement-policy".into();
    }
    Ok(RuntimeBinding::new(cfg, &context())?)
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(hash: [u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}
fn write(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("parent")?)?.sync_all()?;
    Ok(())
}
fn index(
    archive: &Archive,
    edit: Option<&str>,
) -> Result<(Value, [u8; 32]), Box<dyn std::error::Error>> {
    let mut canonical = BTreeMap::new();
    let mut native = BTreeMap::new();
    for witness in archive.identities() {
        let locator = json!({"archive":archive.sha256(),"canonical":witness.canonical_id()});
        assert!(
            canonical
                .insert(witness.canonical_id(), locator.clone())
                .is_none()
        );
        if let Some(id) = witness.native_id() {
            assert!(native.insert(id.clone(), locator).is_none());
        }
    }
    let mut value = json!({"canonical":canonical.into_iter().collect::<Vec<_>>(),"native":native.into_iter().collect::<Vec<_>>()});
    match edit {
        Some("partial_canonical") => {
            value["canonical"].as_array_mut().ok_or("canonical")?.pop();
        }
        Some("partial_native") => {
            value["native"].as_array_mut().ok_or("native")?.pop();
        }
        Some("duplicate_native") => {
            let first = value["native"][0].clone();
            value["native"].as_array_mut().ok_or("native")?.push(first);
        }
        Some("conflicting_native") => {
            value["native"][0][1]["canonical"] = json!(Uuid::new_v4());
        }
        Some(_) => return Err("unknown index edit".into()),
        None => (),
    }
    let sha = digest(&serde_json::to_vec(&value)?);
    Ok((value, sha))
}
fn runtime_epoch(
    b: &RuntimeBinding,
    position: u64,
    ms: u64,
    c: &RuleContext,
) -> Result<RuntimeEpoch, Box<dyn std::error::Error>> {
    let frontier = runtime::ns(runtime::BASE + (ms + b.config().lateness_ms as u64) * 1_000_000);
    let now = frontier + chrono::TimeDelta::milliseconds(100);
    let sources = b
        .config()
        .sources
        .iter()
        .map(|s| RuntimeVerification {
            source: correlation::Verification {
                stream: s.stream,
                position,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: b.config().authority_keys_sha256,
                verification_reference: "fixture://episode-prefix".into(),
                verified_at: now,
                verified_until: now + chrono::TimeDelta::seconds(60),
                now,
                coverage_from: runtime::ns(runtime::BASE - 10_000_000),
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
            reference: "fixture://episode-policy-coverage".into(),
            verified_at: now,
            verified_until: now + chrono::TimeDelta::seconds(60),
            now,
            coverage_from: runtime::ns(runtime::BASE - 10_000_000),
            frontier,
            complete: true,
            authenticated: true,
        })
        .collect();
    Ok(RuntimeEpoch::new(b, sources, policies, c)?)
}
async fn d11(
    directory: &Path,
    edit: Option<&str>,
) -> Result<(Archive, Archive, Anchor, Output, Value), Box<dyn std::error::Error>> {
    let c = context();
    let b = correlation::Binding::new(auth::config(), &c)?;
    let (db, ready) = Journal::begin_open(
        directory.join("journal.sqlite"),
        b.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let events = auth::inputs()?;
    let mut record = None;
    let mut positions = [0; 2];
    for (i, event) in events.iter().enumerate() {
        let source = usize::from(i == 3);
        positions[source] += 1;
        record = Some(
            journal::prepare(
                &b,
                record.as_ref(),
                i as u64 + 1,
                Action::Admit {
                    stream: b.config().sources[source].stream,
                    position: positions[source],
                    event,
                },
                &auth::epoch(&b, auth::time(100), true)?,
                &context(),
            )?
            .commit(&db)
            .await?,
        );
    }
    let r = journal::prepare(
        &b,
        record.as_ref(),
        4,
        Action::Seal,
        &auth::journal_epoch(&b, record.as_ref(), auth::time(50), true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let output = r.outbox.first().ok_or("D11 finding output")?.clone();
    let r = db.retire(r.revision, r.outbox.len(), context()).await?;
    let r = journal::prepare(
        &b,
        Some(&r),
        4,
        Action::Seal,
        &auth::journal_epoch(&b, Some(&r), auth::time(500), true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let archive = history::export(&b, &r, &context())?;
    let (index, index_sha) = index(&archive, edit)?;
    let claim = history::Claim::publication(&archive, [0; 32], index_sha, &context())?;
    let authority = Authority::new(
        &b,
        history::Verification {
            claim,
            reference: "fixture://durable-complete-episode-index".into(),
            verified_at: auth::time(1990),
            verified_until: auth::time(2300),
            now: auth::time(2000),
            durable_originals: true,
            complete_cumulative_indexes: true,
        },
        &context(),
    )?;
    let receipt = Receipt {
        archive_sha256: archive.sha256(),
        previous_root: [0; 32],
        index_sha256: index_sha,
        authority,
    };
    let pruned = history::prune(
        &b,
        &r,
        &archive,
        &receipt,
        &auth::journal_epoch(&b, Some(&r), auth::time(500), true)?,
        &context(),
    )?
    .commit(&db)
    .await?;
    let root = journal::recover(&b, &pruned, &context())?
        .archive_anchor()
        .ok_or("root")?
        .clone();
    let witness = history::export(&b, &pruned, &context())?;
    db.shutdown(context()).await?;
    Ok((archive, witness, root, output, index))
}
async fn d14(
    directory: &Path,
    edit: Option<&str>,
) -> Result<(Archive, Archive, Anchor, Output, Value), Box<dyn std::error::Error>> {
    let c = context();
    let b = RuntimeBinding::new(runtime::config(), &c)?;
    let (db, ready) = Journal::begin_open(
        directory.join("journal.sqlite"),
        b.journal_config(),
        context(),
    )?;
    ready.wait().await?;
    let mut record: Option<Record> = None;
    for (i, read) in [true, false].into_iter().enumerate() {
        let event = runtime::event(read)?;
        let input = runtime::input(&b, &event, &c)?;
        let decision =
            CurrentDecision::new(&b, &input, runtime::verification(&b, &input, true, &c)?, &c)?;
        let position = i as u64 + 1;
        record = Some(
            journal::prepare_runtime(
                &b,
                record.as_ref(),
                position,
                RuntimeAction::Admit {
                    input: &input,
                    position,
                    decision: Some(&decision),
                },
                &runtime_epoch(&b, position, 50, &c)?,
                &c,
            )?
            .commit(&db)
            .await?,
        );
    }
    let r = journal::prepare_runtime(
        &b,
        record.as_ref(),
        2,
        RuntimeAction::Seal,
        &runtime_epoch(&b, 2, 50, &c)?,
        &c,
    )?
    .commit(&db)
    .await?;
    let output = r.outbox.first().ok_or("D14 finding output")?.clone();
    let r = db.retire(r.revision, r.outbox.len(), context()).await?;
    let r = journal::prepare_runtime(
        &b,
        Some(&r),
        2,
        RuntimeAction::Seal,
        &runtime_epoch(&b, 2, 2000, &c)?,
        &c,
    )?
    .commit(&db)
    .await?;
    let archive = history::export_runtime(&b, &r, &c)?;
    let (index, index_sha) = index(&archive, edit)?;
    let claim = history::Claim::publication(&archive, [0; 32], index_sha, &c)?;
    let authority = Authority::new_runtime(
        &b,
        history::Verification {
            claim,
            reference: "fixture://durable-runtime-complete-index".into(),
            verified_at: runtime::ns(runtime::BASE + 10_000_000_000),
            verified_until: runtime::ns(runtime::BASE + 70_000_000_000),
            now: runtime::ns(runtime::BASE + 10_000_000_000),
            durable_originals: true,
            complete_cumulative_indexes: true,
        },
        &c,
    )?;
    let receipt = Receipt {
        archive_sha256: archive.sha256(),
        previous_root: [0; 32],
        index_sha256: index_sha,
        authority,
    };
    let pruned = history::prune_runtime(
        &b,
        &r,
        &archive,
        &receipt,
        &runtime_epoch(&b, 2, 2000, &c)?,
        &c,
    )?
    .commit(&db)
    .await?;
    let root = journal::recover_runtime(&b, &pruned, &c)?
        .archive_anchor()
        .ok_or("root")?
        .clone();
    let witness = history::export_runtime(&b, &pruned, &c)?;
    db.shutdown(context()).await?;
    Ok((archive, witness, root, output, index))
}
impl Bundle {
    pub(super) async fn build(
        fixture: &Fixture,
        detector: Detector,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::build_index(fixture, detector, None).await
    }
    pub(super) async fn build_index(
        fixture: &Fixture,
        detector: Detector,
        edit: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = fixture
            .root
            .path()
            .join(format!("episode-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let (archive, witness, current_root, output, index) = match detector {
            Detector::D11 => d11(&root, edit).await?,
            Detector::D14 => d14(&root, edit).await?,
        };
        let episode: correlation::Episode = serde_json::from_slice(&output.bytes)?;
        let finding = episode.finding.clone().ok_or("published finding")?;
        let effect = archive
            .identities()
            .iter()
            .find_map(|w| w.effect().filter(|e| e.id == output.id).cloned())
            .ok_or("effect reference")?;
        assert_eq!(archive.effect(&effect)?.bytes, output.bytes);
        let reference = FindingReference {
            stream_id: Uuid::new_v4(),
            finding_id: finding.id,
        };
        let finding_bytes = serde_json::to_vec(&finding)?;
        let finding_sha = digest(&finding_bytes);
        let publication = super::super::episode::Publication {
            schema_version: 1,
            namespace: fixture.host.namespace,
            reference,
            finding_sha256: finding_sha,
            effect: effect.clone(),
        };
        let publication_bytes = serde_json::to_vec(&publication)?;
        let publication_sha = digest(&publication_bytes);
        write(
            &root.join(format!("finding-{}.json", hex(finding_sha))),
            &finding_bytes,
        )?;
        write(
            &root.join(format!("publication-{}.json", hex(publication_sha))),
            &publication_bytes,
        )?;
        for a in [&archive, &witness] {
            write(
                &root.join(format!("archive-{}.json", hex(a.sha256()))),
                a.bytes(),
            )?;
        }
        let index_bytes = serde_json::to_vec(&index)?;
        assert_eq!(digest(&index_bytes), current_root.index_sha256);
        write(
            &root.join(format!("index-{}.json", hex(current_root.index_sha256))),
            &index_bytes,
        )?;
        let summary = archive.historical_summary(&context())?;
        let signer =
            Ed25519KeyPair::from_seed_unchecked(&[53; 32]).map_err(|_| "episode signer")?;
        let enrollment = [39; 32];
        let now = crate::access::now().ok_or("clock")?;
        let report = json!({"schema_version":1,"namespace":fixture.host.namespace,"provider_enrollment_sha256":enrollment,
            "observer_issuer":"episode-observer-fixture","audience":"signal-soc-episodes","key_revision":"observer-v1","report_revision":"custody-1",
            "observed_at":now,"expires_at":now+30,"reference":reference,"finding_sha256":finding_sha,"publication_sha256":publication_sha,"effect":effect,
            "original_enrollment_sha256":summary.enrollment_binding(),"original_journal_binding":summary.journal_source_binding(),
            "original_authority_keys_sha256":summary.authority_keys_sha256(),"contributors_sha256":super::super::episode::contributors_digest(&episode).map_err(|_|"contributors")?,
            "current_root":current_root,"root_witness_archive_sha256":witness.sha256(),"index_format":"canonical-native-v1",
            "archives":[archive.sha256(),witness.sha256()],"protected_originals":true,"complete_cumulative_indexes":true});
        let configuration = json!({"stream_id":reference.stream_id,"root":root,"provider_enrollment_sha256":enrollment,"detector_partition":summary.detector_partition(),
            "archive_schema_version":summary.schema_version(),"allowed_original_enrollments":[summary.enrollment_binding()],"observer_issuer":"episode-observer-fixture",
            "audience":"signal-soc-episodes","key_revision":"observer-v1","public_key_base64":STANDARD.encode(signer.public_key().as_ref()),"max_age_seconds":30,
            "max_archives":8,"max_index_entries":256,"max_graph_bytes":8388608,"max_artifact_bytes":1048576,"max_work":8192});
        let mut configuration = configuration;
        if summary.schema_version() == 2 {
            configuration["allowed_original_enrollments"]
                .as_array_mut()
                .ok_or("allowlist")?
                .push(json!(
                    replacement_runtime_binding()?
                        .journal_config()
                        .enrollment_binding
                ));
        }
        let result = Self {
            reference,
            episode,
            report,
            configuration,
            root,
            signer,
        };
        result.write_report(&result.report)?;
        Ok(result)
    }
    pub(super) fn write_report(&self, report: &Value) -> TestResult {
        self.write_report_domain(report, super::super::episode::DOMAIN)
    }
    pub(super) fn write_report_domain(&self, report: &Value, domain: &[u8]) -> TestResult {
        let payload = serde_json::to_vec(report)?;
        let mut signed = domain.to_vec();
        signed.extend_from_slice(&payload);
        let path = self
            .root
            .join(format!("report-{}.json", self.reference.finding_id));
        let bytes = serde_json::to_vec(
            &json!({"schema_version":1,"payload_base64":STANDARD.encode(payload),"signature_base64":STANDARD.encode(self.signer.sign(&signed).as_ref())}),
        )?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        write(&path, &bytes)
    }
    pub(super) fn replace_publication_finding(
        &self,
        finding: &Finding,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let finding_bytes = serde_json::to_vec(finding)?;
        let finding_sha = digest(&finding_bytes);
        write(
            &self.root.join(format!("finding-{}.json", hex(finding_sha))),
            &finding_bytes,
        )?;
        let publication = super::super::episode::Publication {
            schema_version: 1,
            namespace: serde_json::from_value(self.report["namespace"].clone())?,
            reference: self.reference,
            finding_sha256: finding_sha,
            effect: serde_json::from_value(self.report["effect"].clone())?,
        };
        let publication_bytes = serde_json::to_vec(&publication)?;
        let publication_sha = digest(&publication_bytes);
        write(
            &self
                .root
                .join(format!("publication-{}.json", hex(publication_sha))),
            &publication_bytes,
        )?;
        let mut report = self.report.clone();
        report["finding_sha256"] = json!(finding_sha);
        report["publication_sha256"] = json!(publication_sha);
        Ok(report)
    }
    pub(super) async fn carry_runtime(&mut self) -> TestResult {
        let c = context();
        let old = RuntimeBinding::new(runtime::config(), &c)?;
        let new = replacement_runtime_binding()?;
        let (source, ready) = Journal::begin_open(
            self.root.join("journal.sqlite"),
            old.journal_config(),
            context(),
        )?;
        ready.wait().await?;
        let record = source.load(context()).await?.ok_or("source record")?;
        let old_hash: [u8; 32] =
            serde_json::from_value(self.report["root_witness_archive_sha256"].clone())?;
        let archive = Archive::from_bytes(
            &fs::read(self.root.join(format!("archive-{}.json", hex(old_hash))))?,
            old_hash,
            &c,
        )?;
        let prior: Anchor = serde_json::from_value(self.report["current_root"].clone())?;
        let claim =
            history::Claim::publication(&archive, prior.root_sha256, prior.index_sha256, &c)?;
        let authority = Authority::new_runtime(
            &new,
            history::Verification {
                claim,
                reference: "fixture://new-key-complete-original-index".into(),
                verified_at: runtime::ns(runtime::BASE + 10_000_000_000),
                verified_until: runtime::ns(runtime::BASE + 70_000_000_000),
                now: runtime::ns(runtime::BASE + 10_000_000_000),
                durable_originals: true,
                complete_cumulative_indexes: true,
            },
            &c,
        )?;
        let receipt = Receipt {
            archive_sha256: old_hash,
            previous_root: prior.root_sha256,
            index_sha256: prior.index_sha256,
            authority,
        };
        let prepared = history::carry_runtime(
            &old,
            &source,
            &record,
            &archive,
            &receipt,
            &new,
            &runtime_epoch(&new, 2, 2000, &c)?,
            &c,
        )
        .await?;
        let (destination, ready) = Journal::begin_open(
            self.root.join("replacement.sqlite"),
            new.journal_config(),
            context(),
        )?;
        ready.wait().await?;
        let carried = prepared.commit(&destination).await?;
        let state = journal::recover_runtime(&new, &carried, &c)?;
        let root = state.archive_anchor().ok_or("replacement root")?.clone();
        assert_eq!(root.previous_root, prior.root_sha256);
        assert_eq!(root.generation, prior.generation + 1);
        let exported = history::export_runtime(&new, &carried, &c)?;
        write(
            &self
                .root
                .join(format!("archive-{}.json", hex(exported.sha256()))),
            exported.bytes(),
        )?;
        source.shutdown(context()).await?;
        destination.shutdown(context()).await?;
        self.report["archives"]
            .as_array_mut()
            .ok_or("archives")?
            .push(json!(exported.sha256()));
        self.report["current_root"] = serde_json::to_value(root)?;
        self.report["root_witness_archive_sha256"] = json!(exported.sha256());
        self.report["report_revision"] = json!("custody-2");
        let now = crate::access::now().ok_or("clock")?;
        self.report["observed_at"] = json!(now);
        self.report["expires_at"] = json!(now + 30);
        self.write_report(&self.report)
    }
    pub(super) fn enroll(&self, fixture: &mut Fixture) -> TestResult {
        let config = serde_json::from_value::<super::super::episode::Configuration>(
            self.configuration.clone(),
        )?;
        let provider = super::super::episode::Provider::new(config, fixture.host.namespace)
            .map_err(|_| "provider configuration")?;
        Arc::get_mut(&mut fixture.host)
            .ok_or("shared host")?
            .registry
            .enroll_episode(provider)
            .map_err(|_| "provider enrollment")?;
        Ok(())
    }
}

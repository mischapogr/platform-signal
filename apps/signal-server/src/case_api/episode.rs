//! Explicit protected episode custody. Historical artifacts never grant access;
//! the independent observer authenticates current bounded publication/index custody.
use super::{Failure, reference::Scope};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_findings::{Finding, FindingContext, disposition::FindingReference};
use signal_rules::{
    RuleContext,
    correlation::{
        Episode, NativeId,
        history::{Anchor, Archive, ArchivedIdentity, EffectRef},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

pub(super) const DOMAIN: &[u8] = b"PLATFORM::SIGNAL/soc-episode-custody/v1\0";
const REPORT_BYTES: usize = 256 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    stream_id: Uuid,
    root: PathBuf,
    provider_enrollment_sha256: [u8; 32],
    detector_partition: Uuid,
    archive_schema_version: u16,
    allowed_original_enrollments: Vec<[u8; 32]>,
    observer_issuer: String,
    audience: String,
    key_revision: String,
    public_key_base64: String,
    max_age_seconds: u64,
    max_archives: usize,
    max_index_entries: usize,
    /// Aggregate raw encoded artifact bytes. This is not a decoded-RAM claim;
    /// typed archive state limits and finite index/work bounds also apply.
    max_graph_bytes: usize,
    max_artifact_bytes: usize,
    max_work: usize,
}
pub(super) struct Provider {
    configuration: Configuration,
    namespace: Uuid,
    key: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u16,
    payload_base64: String,
    signature_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u16,
    namespace: Uuid,
    provider_enrollment_sha256: [u8; 32],
    observer_issuer: String,
    audience: String,
    key_revision: String,
    report_revision: String,
    observed_at: u64,
    expires_at: u64,
    reference: FindingReference,
    finding_sha256: [u8; 32],
    publication_sha256: [u8; 32],
    effect: EffectRef,
    original_enrollment_sha256: [u8; 32],
    original_journal_binding: [u8; 32],
    original_authority_keys_sha256: [u8; 32],
    contributors_sha256: [u8; 32],
    current_root: Anchor,
    root_witness_archive_sha256: [u8; 32],
    index_format: String,
    archives: Vec<[u8; 32]>,
    protected_originals: bool,
    complete_cumulative_indexes: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Publication {
    pub(super) schema_version: u16,
    pub(super) namespace: Uuid,
    pub(super) reference: FindingReference,
    pub(super) finding_sha256: [u8; 32],
    pub(super) effect: EffectRef,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Locator {
    pub(super) archive: [u8; 32],
    pub(super) canonical: Uuid,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexWire {
    pub(super) canonical: Vec<(Uuid, Locator)>,
    pub(super) native: Vec<(NativeId, Locator)>,
}
struct Index {
    canonical: BTreeMap<Uuid, Locator>,
    native: BTreeMap<NativeId, Locator>,
}
pub(super) struct Resolved {
    pub(super) finding: Finding,
    pub(super) episode: Episode,
    pub(super) finding_sha256: [u8; 32],
    pub(super) original_binding: [u8; 32],
    pub(super) scopes: Vec<Scope>,
    pub(super) lease: CustodyLease,
}
#[derive(Clone)]
pub(super) struct CustodyLease {
    pub(super) not_before: u64,
    pub(super) expires_at: u64,
    pub(super) root_sha256: [u8; 32],
    pub(super) index_sha256: [u8; 32],
}
impl CustodyLease {
    pub(super) fn check(&self) -> Result<(), Failure> {
        let now = crate::access::now().ok_or(Failure::Unavailable)?;
        if now < self.not_before
            || now >= self.expires_at
            || self.root_sha256 == [0; 32]
            || self.index_sha256 == [0; 32]
        {
            Err(Failure::Unavailable)
        } else {
            Ok(())
        }
    }
}
fn identifier(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(super) fn contributors_digest(episode: &Episode) -> Result<[u8; 32], Failure> {
    let mut hash = Sha256::new();
    hash.update(b"PLATFORM::SIGNAL/soc-original-contributors/v1\0");
    hash.update(serde_json::to_vec(&episode.contributors).map_err(|_| Failure::Unavailable)?);
    Ok(hash.finalize().into())
}
fn hex(hash: [u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}
fn rule_context(context: &FindingContext) -> RuleContext {
    RuleContext {
        deadline: context.deadline,
        cancellation: context.cancellation.clone(),
    }
}
impl Provider {
    pub(super) fn new(configuration: Configuration, namespace: Uuid) -> Result<Arc<Self>, Failure> {
        let c = &configuration;
        if c.stream_id.is_nil()
            || namespace.is_nil()
            || c.detector_partition.is_nil()
            || !c.root.is_absolute()
            || c.root.as_os_str().len() > 4096
            || c.provider_enrollment_sha256 == [0; 32]
            || !matches!(c.archive_schema_version, 1 | 2)
            || c.allowed_original_enrollments.is_empty()
            || c.allowed_original_enrollments.len() > 16
            || c.allowed_original_enrollments.contains(&[0; 32])
            || c.allowed_original_enrollments
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != c.allowed_original_enrollments.len()
            || [&c.observer_issuer, &c.audience, &c.key_revision]
                .iter()
                .any(|s| !identifier(s))
            || !(1..=30).contains(&c.max_age_seconds)
            || !(1..=16).contains(&c.max_archives)
            || !(1..=8192).contains(&c.max_index_entries)
            || !(1024..=32 * 1024 * 1024).contains(&c.max_artifact_bytes)
            || !(c.max_artifact_bytes..=64 * 1024 * 1024).contains(&c.max_graph_bytes)
            || !(1..=262144).contains(&c.max_work)
        {
            return Err(Failure::Invalid);
        }
        let key = STANDARD
            .decode(&c.public_key_base64)
            .map_err(|_| Failure::Invalid)?
            .try_into()
            .map_err(|_| Failure::Invalid)?;
        Ok(Arc::new(Self {
            configuration,
            namespace,
            key,
        }))
    }
    pub(super) fn stream(&self) -> Uuid {
        self.configuration.stream_id
    }
    async fn read<T, F>(
        &self,
        name: String,
        limit: usize,
        context: &FindingContext,
        parse: F,
    ) -> Result<T, Failure>
    where
        T: Send + 'static,
        F: FnOnce(&str) -> Result<T, Failure> + Send + 'static,
    {
        super::check(context)?;
        crate::config::read_protected_artifact(
            self.configuration.root.clone(),
            name,
            limit,
            context.deadline,
            context.cancellation.clone(),
            move |text| {
                parse(text).map_err(|_| {
                    crate::config::ConfigError::Invalid("episode artifact unavailable")
                })
            },
        )
        .await
        .map_err(|_| Failure::Unavailable)
    }
    fn report(&self, text: &str, reference: FindingReference) -> Result<Report, Failure> {
        let wire: Envelope = serde_json::from_str(text).map_err(|_| Failure::Unavailable)?;
        if wire.schema_version != 1
            || wire.payload_base64.len() > REPORT_BYTES
            || wire.signature_base64.len() > 88
        {
            return Err(Failure::Unavailable);
        }
        let bytes = STANDARD
            .decode(wire.payload_base64)
            .map_err(|_| Failure::Unavailable)?;
        let signature = STANDARD
            .decode(wire.signature_base64)
            .map_err(|_| Failure::Unavailable)?;
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&bytes);
        signature::UnparsedPublicKey::new(&signature::ED25519, self.key)
            .verify(&signed, &signature)
            .map_err(|_| Failure::Unavailable)?;
        let report: Report = serde_json::from_slice(&bytes).map_err(|_| Failure::Unavailable)?;
        let c = &self.configuration;
        let now = crate::access::now().ok_or(Failure::Unavailable)?;
        if report.schema_version != 1
            || report.namespace != self.namespace
            || report.reference != reference
            || reference.stream_id != c.stream_id
            || report.provider_enrollment_sha256 != c.provider_enrollment_sha256
            || report.observer_issuer != c.observer_issuer
            || report.audience != c.audience
            || report.key_revision != c.key_revision
            || !identifier(&report.report_revision)
            || report.observed_at > now
            || report.expires_at <= now
            || report.expires_at <= report.observed_at
            || report.expires_at - report.observed_at > c.max_age_seconds
            || now - report.observed_at > c.max_age_seconds
            || !report.protected_originals
            || !report.complete_cumulative_indexes
            || report.index_format != "canonical-native-v1"
            || report.archives.is_empty()
            || report.archives.len() > c.max_archives
            || report.archives.contains(&[0; 32])
            || report.archives.iter().collect::<BTreeSet<_>>().len() != report.archives.len()
            || [
                report.finding_sha256,
                report.publication_sha256,
                report.effect.archive_sha256,
                report.effect.output_sha256,
                report.original_enrollment_sha256,
                report.original_journal_binding,
                report.original_authority_keys_sha256,
                report.contributors_sha256,
                report.root_witness_archive_sha256,
            ]
            .contains(&[0; 32])
            || report.effect.id.is_nil()
        {
            return Err(Failure::Unavailable);
        }
        Ok(report)
    }
    pub(super) async fn resolve(
        self: &Arc<Self>,
        reference: FindingReference,
        context: &FindingContext,
    ) -> Result<Resolved, Failure> {
        let provider = self.clone();
        let report = self
            .read(
                format!("report-{}.json", reference.finding_id),
                REPORT_BYTES,
                context,
                move |text| provider.report(text, reference),
            )
            .await?;
        let lease = CustodyLease {
            not_before: report.observed_at,
            expires_at: report.expires_at,
            root_sha256: report.current_root.root_sha256,
            index_sha256: report.current_root.index_sha256,
        };
        lease.check()?;
        let mut budget = Budget {
            bytes: 0,
            work: 0,
            max_bytes: self.configuration.max_graph_bytes,
            max_work: self.configuration.max_work,
        };
        let (finding, bytes) = self
            .read(
                format!("finding-{}.json", hex(report.finding_sha256)),
                budget.limit(self.configuration.max_artifact_bytes)?,
                context,
                move |text| {
                    if sha(text.as_bytes()) != report.finding_sha256 {
                        return Err(Failure::Unavailable);
                    }
                    let finding: Finding =
                        serde_json::from_str(text).map_err(|_| Failure::Unavailable)?;
                    finding.validate().map_err(|_| Failure::Unavailable)?;
                    Ok((finding, text.len()))
                },
            )
            .await?;
        budget.bytes(bytes)?;
        lease.check()?;
        let (publication, bytes) = self
            .read(
                format!("publication-{}.json", hex(report.publication_sha256)),
                budget.limit(REPORT_BYTES)?,
                context,
                move |text| {
                    if sha(text.as_bytes()) != report.publication_sha256 {
                        return Err(Failure::Unavailable);
                    }
                    Ok((
                        serde_json::from_str::<Publication>(text)
                            .map_err(|_| Failure::Unavailable)?,
                        text.len(),
                    ))
                },
            )
            .await?;
        budget.bytes(bytes)?;
        if publication.schema_version != 1
            || publication.namespace != self.namespace
            || publication.reference != reference
            || publication.finding_sha256 != report.finding_sha256
            || publication.effect != report.effect
            || finding.id != reference.finding_id
        {
            return Err(Failure::Unavailable);
        }
        let mut archives = BTreeMap::new();
        let mut anchors = BTreeMap::new();
        for digest in &report.archives {
            lease.check()?;
            let digest = *digest;
            let c = rule_context(context);
            let archive = self
                .read(
                    format!("archive-{}.json", hex(digest)),
                    budget.limit(self.configuration.max_artifact_bytes)?,
                    context,
                    move |text| {
                        Archive::from_bytes(text.as_bytes(), digest, &c)
                            .map_err(|_| Failure::Unavailable)
                    },
                )
                .await?;
            budget.bytes(archive.bytes().len())?;
            let summary = archive
                .historical_summary(&rule_context(context))
                .map_err(|_| Failure::Unavailable)?;
            if summary.schema_version() != self.configuration.archive_schema_version
                || summary.detector_partition() != self.configuration.detector_partition
                || !self
                    .configuration
                    .allowed_original_enrollments
                    .contains(&summary.enrollment_binding())
            {
                return Err(Failure::Unavailable);
            }
            if let Some(anchor) = summary.prior_anchor()
                && anchors
                    .insert(anchor.root_sha256, anchor.clone())
                    .is_some_and(|old| old != *anchor)
            {
                return Err(Failure::Unavailable);
            }
            archives.insert(digest, archive);
        }
        let witness = archives
            .get(&report.root_witness_archive_sha256)
            .ok_or(Failure::Unavailable)?
            .historical_summary(&rule_context(context))
            .map_err(|_| Failure::Unavailable)?;
        if witness.prior_anchor() != Some(&report.current_root) {
            return Err(Failure::Unavailable);
        }
        let mut cursor = report.current_root.clone();
        let mut visited = BTreeSet::new();
        let mut prefix = BTreeSet::new();
        let mut chain = Vec::new();
        loop {
            budget.work(context)?;
            lease.check()?;
            if !visited.insert(cursor.root_sha256)
                || cursor.namespace != report.current_root.namespace
                || cursor.generation == 0
                || cursor.root_sha256 == [0; 32]
                || cursor.archive_sha256 == [0; 32]
                || cursor.index_sha256 == [0; 32]
            {
                return Err(Failure::Unavailable);
            }
            let archived = archives
                .get(&cursor.archive_sha256)
                .ok_or(Failure::Unavailable)?;
            let summary = archived
                .historical_summary(&rule_context(context))
                .map_err(|_| Failure::Unavailable)?;
            if summary.namespace() != cursor.namespace
                || summary.prior_anchor().map_or([0; 32], |a| a.root_sha256) != cursor.previous_root
            {
                return Err(Failure::Unavailable);
            }
            chain.push(cursor.clone());
            if cursor.previous_root == [0; 32] {
                if cursor.generation != 1 {
                    return Err(Failure::Unavailable);
                }
                break;
            }
            let previous = anchors
                .get(&cursor.previous_root)
                .ok_or(Failure::Unavailable)?;
            if previous.generation.checked_add(1) != Some(cursor.generation) {
                return Err(Failure::Unavailable);
            }
            cursor = previous.clone();
        }
        if anchors.keys().any(|h| !visited.contains(h)) {
            return Err(Failure::Unavailable);
        }
        chain.reverse();
        let mut current_index = None;
        for anchor in chain {
            prefix.insert(anchor.archive_sha256);
            lease.check()?;
            let digest = anchor.index_sha256;
            let limit = self.configuration.max_index_entries;
            let (index, bytes) = self
                .read(
                    format!("index-{}.json", hex(digest)),
                    budget.limit(self.configuration.max_artifact_bytes)?,
                    context,
                    move |text| {
                        if sha(text.as_bytes()) != digest {
                            return Err(Failure::Unavailable);
                        }
                        Ok((Index::parse(text, limit)?, text.len()))
                    },
                )
                .await?;
            budget.bytes(bytes)?;
            validate_index(&archives, &prefix, &index, &mut budget, context)?;
            if anchor.root_sha256 == report.current_root.root_sha256 {
                current_index = Some(index);
            }
        }
        let all = archives.keys().copied().collect();
        validate_index(
            &archives,
            &all,
            &current_index.ok_or(Failure::Unavailable)?,
            &mut budget,
            context,
        )?;
        let original = archives
            .get(&report.effect.archive_sha256)
            .ok_or(Failure::Unavailable)?;
        let original_summary = original
            .historical_summary(&rule_context(context))
            .map_err(|_| Failure::Unavailable)?;
        if original_summary.enrollment_binding() != report.original_enrollment_sha256
            || original_summary.journal_source_binding() != report.original_journal_binding
            || original_summary.authority_keys_sha256() != report.original_authority_keys_sha256
        {
            return Err(Failure::Unavailable);
        }
        let output = original
            .effect(&report.effect)
            .map_err(|_| Failure::Unavailable)?;
        let episode: Episode =
            serde_json::from_slice(&output.bytes).map_err(|_| Failure::Unavailable)?;
        if output.id != episode.id
            || episode.finding.as_ref() != Some(&finding)
            || episode.event_ids != finding.event_ids
            || episode.contributors.is_empty()
            || episode.contributors.len() > 128
            || contributors_digest(&episode)? != report.contributors_sha256
        {
            return Err(Failure::Unavailable);
        }
        let mut scopes = Vec::with_capacity(episode.contributors.len());
        for contributor in &episode.contributors {
            budget.work(context)?;
            if contributor.stream.is_nil()
                || contributor.source_binding == [0; 32]
                || !identifier(&contributor.source_type)
                || contributor
                    .source_name
                    .as_ref()
                    .is_some_and(|s| !identifier(s))
                || contributor.account.as_ref().is_some_and(|s| !identifier(s))
                || contributor
                    .resource
                    .as_ref()
                    .is_some_and(|s| !identifier(s))
            {
                return Err(Failure::Unavailable);
            }
            scopes.push(Scope::from_facts(signal_protocol::access::ScopeFacts {
                source: Some(&contributor.source_type),
                account: contributor.account.as_deref(),
                resource: contributor.resource.as_deref(),
            }));
        }
        lease.check()?;
        super::check(context)?;
        let mut binding = Sha256::new();
        binding.update(b"PLATFORM::SIGNAL/soc-original-episode/v1\0");
        binding.update(report.finding_sha256);
        binding.update(report.publication_sha256);
        binding.update(report.effect.archive_sha256);
        binding.update(report.effect.id.as_bytes());
        binding.update(report.effect.output_sha256);
        binding.update(report.original_enrollment_sha256);
        binding.update(report.contributors_sha256);
        Ok(Resolved {
            finding,
            episode,
            finding_sha256: report.finding_sha256,
            original_binding: binding.finalize().into(),
            scopes,
            lease,
        })
    }
}
impl Index {
    fn parse(text: &str, limit: usize) -> Result<Self, Failure> {
        let wire: IndexWire = serde_json::from_str(text).map_err(|_| Failure::Unavailable)?;
        if wire.canonical.len() > limit || wire.native.len() > limit {
            return Err(Failure::Capacity);
        }
        let nc = wire.canonical.len();
        let nn = wire.native.len();
        let index = Self {
            canonical: wire.canonical.into_iter().collect(),
            native: wire.native.into_iter().collect(),
        };
        if index.canonical.len() != nc || index.native.len() != nn {
            return Err(Failure::Unavailable);
        }
        Ok(index)
    }
}
struct Budget {
    bytes: usize,
    work: usize,
    max_bytes: usize,
    max_work: usize,
}
impl Budget {
    fn limit(&self, cap: usize) -> Result<usize, Failure> {
        let remaining = self
            .max_bytes
            .checked_sub(self.bytes)
            .filter(|n| *n > 0)
            .ok_or(Failure::Capacity)?;
        Ok(cap.min(remaining))
    }
    fn bytes(&mut self, n: usize) -> Result<(), Failure> {
        self.bytes = self.bytes.checked_add(n).ok_or(Failure::Capacity)?;
        if self.bytes > self.max_bytes {
            Err(Failure::Capacity)
        } else {
            Ok(())
        }
    }
    fn work(&mut self, c: &FindingContext) -> Result<(), Failure> {
        super::check(c)?;
        self.work += 1;
        if self.work > self.max_work {
            Err(Failure::Capacity)
        } else {
            Ok(())
        }
    }
}
fn witness(
    archives: &BTreeMap<[u8; 32], Archive>,
    allowed: &BTreeSet<[u8; 32]>,
    locator: &Locator,
) -> Result<ArchivedIdentity, Failure> {
    if !allowed.contains(&locator.archive) {
        return Err(Failure::Unavailable);
    }
    archives
        .get(&locator.archive)
        .and_then(|a| a.canonical(locator.canonical))
        .ok_or(Failure::Unavailable)
}
fn validate_index(
    archives: &BTreeMap<[u8; 32], Archive>,
    allowed: &BTreeSet<[u8; 32]>,
    index: &Index,
    budget: &mut Budget,
    context: &FindingContext,
) -> Result<(), Failure> {
    let mut canonical = BTreeSet::new();
    let mut native = BTreeSet::new();
    for digest in allowed {
        for original in archives
            .get(digest)
            .ok_or(Failure::Unavailable)?
            .identities()
        {
            budget.work(context)?;
            canonical.insert(original.canonical_id());
            let target = witness(
                archives,
                allowed,
                index
                    .canonical
                    .get(&original.canonical_id())
                    .ok_or(Failure::Unavailable)?,
            )?;
            if target.canonical_sha256() != original.canonical_sha256()
                || target.native_id() != original.native_id()
                || target.first_canonical_id() != original.first_canonical_id()
                || target.content_sha256() != original.content_sha256()
                || target.origin_archive() != original.origin_archive()
            {
                return Err(Failure::Unavailable);
            }
            if let Some(effect) = original.effect() {
                if target.effect() != Some(effect) {
                    return Err(Failure::Unavailable);
                }
                archives
                    .get(&effect.archive_sha256)
                    .ok_or(Failure::Unavailable)?
                    .effect(effect)
                    .map_err(|_| Failure::Unavailable)?;
            }
            if let Some(id) = original.native_id() {
                native.insert(id.clone());
                let target = witness(
                    archives,
                    allowed,
                    index.native.get(id).ok_or(Failure::Unavailable)?,
                )?;
                if target.native_id() != Some(id)
                    || target.first_canonical_id() != original.first_canonical_id()
                    || target.content_sha256() != original.content_sha256()
                    || target.origin_archive() != original.origin_archive()
                    || original
                        .effect()
                        .is_some_and(|effect| target.effect() != Some(effect))
                {
                    return Err(Failure::Unavailable);
                }
            }
        }
    }
    if canonical.len() != index.canonical.len() || native.len() != index.native.len() {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn remaining_graph_allowance_rejects_the_next_artifact_before_parsing()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let _serial = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = root.path().join("archive.json");
        std::fs::write(&path, vec![b'x'; 925])?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let mut budget = Budget {
            bytes: 0,
            work: 0,
            max_bytes: 1024,
            max_work: 4,
        };
        budget.bytes(100).map_err(|_| "budget")?;
        let limit = budget.limit(8192).map_err(|_| "limit")?;
        assert_eq!(limit, 924);
        let result = crate::config::read_protected_artifact(
            root.path().into(),
            "archive.json".into(),
            limit,
            tokio::time::Instant::now() + std::time::Duration::from_secs(3),
            tokio_util::sync::CancellationToken::new(),
            |_| -> Result<(), crate::config::ConfigError> {
                panic!("over-budget artifact reached decoder")
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::config::ConfigError::Invalid(
                "protected artifact byte capacity"
            ))
        ));
        Ok(())
    }
}

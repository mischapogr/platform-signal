//! Protected custody and complete cumulative dual-index host boundary.
//! Historical archives/identity witnesses never construct a fresh Epoch.
use super::*;
use crate::state_journal::{Journal, Output, Record};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectRef {
    pub archive_sha256: [u8; 32],
    pub id: Uuid,
    pub output_sha256: [u8; 32],
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorityEvidence {
    binding: [u8; 32],
    keys_sha256: [u8; 32],
    reference: String,
    claim_sha256: [u8; 32],
    verified_at: DateTime<Utc>,
    verified_until: DateTime<Utc>,
    assessed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub namespace: [u8; 32],
    pub generation: u64,
    pub root_sha256: [u8; 32],
    pub previous_root: [u8; 32],
    pub archive_sha256: [u8; 32],
    pub index_sha256: [u8; 32],
    authority: AuthorityEvidence,
}
/// One independently verified current custody/index result, never archive JSON.
pub struct Verification {
    pub claim: Claim,
    pub reference: String,
    pub verified_at: DateTime<Utc>,
    pub verified_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub durable_originals: bool,
    pub complete_cumulative_indexes: bool,
}
/// Exact verification target. A commitment is data; only fresh private-host
/// Authority construction supplies a bounded lookup/publication permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    digest: [u8; 32],
}
impl Claim {
    pub fn publication(
        archive: &Archive,
        previous_root: [u8; 32],
        index_sha256: [u8; 32],
        c: &RuleContext,
    ) -> Result<Self, Error> {
        if index_sha256 == [0; 32] {
            return Err(Error::Invalid);
        }
        Ok(Self {
            digest: hash(
                b"PLATFORM::SIGNAL/correlation/publication-claim/v1\0",
                &codec::encode(
                    &(
                        archive.sha256,
                        archive.namespace,
                        previous_root,
                        index_sha256,
                    ),
                    1024,
                    c,
                )?,
            ),
        })
    }
    pub fn lookup(
        query: &Query,
        anchor: &Anchor,
        canonical: &Answer<'_>,
        native: &Answer<'_>,
        c: &RuleContext,
    ) -> Result<Self, Error> {
        fn answer(a: &Answer<'_>, c: &RuleContext) -> Result<[u8; 32], Error> {
            let bytes = match a {
                Answer::Known(w) => codec::encode(
                    &("known", w.namespace, &w.alias, w.origin_archive),
                    16384,
                    c,
                )?,
                Answer::Absent => codec::encode(&"absent", 128, c)?,
                Answer::Unavailable => codec::encode(&"unavailable", 128, c)?,
                Answer::NotApplicable => codec::encode(&"not_applicable", 128, c)?,
            };
            Ok(hash(
                b"PLATFORM::SIGNAL/correlation/index-answer/v1\0",
                &bytes,
            ))
        }
        Ok(Self {
            digest: hash(
                b"PLATFORM::SIGNAL/correlation/lookup-claim/v1\0",
                &codec::encode(
                    &(query, anchor, answer(canonical, c)?, answer(native, c)?),
                    8192,
                    c,
                )?,
            ),
        })
    }
}
pub struct Authority {
    binding: [u8; 32],
    namespace: [u8; 32],
    evidence: AuthorityEvidence,
    context: RuleContext,
}
impl Authority {
    pub fn new(b: &Binding, proof: Verification, c: &RuleContext) -> Result<Self, Error> {
        check(c)?;
        if !identity(&proof.reference)
            || proof.verified_at > proof.now
            || proof.now >= proof.verified_until
            || !proof.durable_originals
            || !proof.complete_cumulative_indexes
        {
            return Err(Error::Unverified);
        }
        let remaining = (proof.verified_until - proof.now)
            .to_std()
            .map_err(|_| Error::Unverified)?;
        let mut context = c.clone();
        context.deadline = context.deadline.min(
            tokio::time::Instant::now()
                .checked_add(remaining)
                .ok_or(Error::Invalid)?,
        );
        Ok(Self {
            binding: b.digest,
            namespace: namespace(b, c)?,
            evidence: AuthorityEvidence {
                binding: b.digest,
                keys_sha256: b.config.authority_keys_sha256,
                reference: proof.reference,
                claim_sha256: proof.claim.digest,
                verified_at: proof.verified_at,
                verified_until: proof.verified_until,
                assessed_at: proof.now,
            },
            context,
        })
    }
    fn valid(&self, b: &Binding, c: &RuleContext) -> Result<(), Error> {
        check(c)?;
        check(&self.context)?;
        if self.binding != b.digest || self.namespace != namespace(b, c)? {
            Err(Error::Unverified)
        } else {
            Ok(())
        }
    }
}
fn namespace(b: &Binding, c: &RuleContext) -> Result<[u8; 32], Error> {
    Ok(hash(
        b"PLATFORM::SIGNAL/correlation/history-namespace/v1\0",
        &codec::encode(
            &("SIG-D11", b.config.partition, &b.config.sources),
            16384,
            c,
        )?,
    ))
}
fn root(a: &Anchor, c: &RuleContext) -> Result<[u8; 32], Error> {
    Ok(hash(
        b"PLATFORM::SIGNAL/correlation/history-root/v1\0",
        &codec::encode(
            &(
                a.namespace,
                a.generation,
                a.previous_root,
                a.archive_sha256,
                a.index_sha256,
                &a.authority,
            ),
            4096,
            c,
        )?,
    ))
}
fn valid_effect(e: &EffectRef) -> bool {
    e.archive_sha256 != [0; 32] && !e.id.is_nil() && e.output_sha256 != [0; 32]
}
pub(super) fn validate_metadata(b: &Binding, s: &State, c: &RuleContext) -> Result<(), Error> {
    if let Some(a) = &s.archive {
        if a.namespace != namespace(b, c)?
            || a.generation == 0
            || a.archive_sha256 == [0; 32]
            || a.index_sha256 == [0; 32]
            || a.authority.binding == [0; 32]
            || a.authority.keys_sha256 == [0; 32]
            || a.authority.claim_sha256 == [0; 32]
            || !identity(&a.authority.reference)
            || a.authority.verified_at > a.authority.assessed_at
            || a.authority.assessed_at >= a.authority.verified_until
            || root(a, c)? != a.root_sha256
        {
            return Err(Error::Conflict);
        }
    } else if !s.completions.is_empty() {
        return Err(Error::Conflict);
    }
    let mut completions = BTreeSet::new();
    for m in &s.completions {
        if !completions.insert(m.canonical_id)
            || !valid_effect(&m.effect)
            || !s.observations.iter().any(|o| o.event.id == m.canonical_id)
            || s.episodes
                .iter()
                .any(|e| e.originals.last().is_some_and(|e| e.id == m.canonical_id))
        {
            return Err(Error::Conflict);
        }
    }
    s.retired_late_inputs
        .checked_add(
            s.observations
                .iter()
                .filter(|o| {
                    o.admission_watermark
                        .is_some_and(|w| o.event.timestamp <= w)
                })
                .count() as u64,
        )
        .ok_or(Error::Capacity)?;
    for a in &s.aliases {
        if let Some(p) = &a.lookup {
            let current = s.archive.as_ref().ok_or(Error::Conflict)?;
            let q = Query {
                binding: b.digest,
                namespace: namespace(b, c)?,
                stream: a.stream,
                canonical_id: a.id,
                canonical_sha256: a.canonical_sha256,
                native: a.native.clone(),
                content_sha256: a.content_sha256,
            };
            if p.anchor.namespace != current.namespace
                || p.anchor.generation > current.generation
                || root(&p.anchor, c)? != p.anchor.root_sha256
                || p.authority.binding != b.digest
                || p.authority.keys_sha256 != b.config.authority_keys_sha256
                || p.authority.claim_sha256 == [0; 32]
                || !identity(&p.authority.reference)
                || p.authority.verified_at > p.authority.assessed_at
                || p.authority.assessed_at >= p.authority.verified_until
                || p.query_sha256 != query_hash(&q, c)?
            {
                return Err(Error::Conflict);
            }
        } else if s.archive.is_some() && a.origin_archive.is_none() {
            return Err(Error::Conflict);
        }
        if a.id.is_nil()
            || a.original_id.is_nil()
            || a.canonical_sha256 == [0; 32]
            || a.content_sha256 == [0; 32]
            || !b.config.sources.iter().any(|s| s.stream == a.stream)
            || a.native
                .as_ref()
                .is_some_and(|n| n.stream != a.stream || !identity(&n.boot))
            || a.origin_archive
                .is_some_and(|sha| sha == [0; 32] || s.archive.is_none())
            || a.effect
                .as_ref()
                .is_some_and(|e| !valid_effect(e) || a.origin_archive.is_none())
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u16,
    config: Config,
    record: Record,
}
/// Exact bytes published by the private host before any hot-state retirement.
pub struct Archive {
    bytes: Vec<u8>,
    sha256: [u8; 32],
    envelope: Envelope,
    state: State,
    namespace: [u8; 32],
}
impl Archive {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn from_bytes(
        bytes: &[u8],
        expected_sha256: [u8; 32],
        c: &RuleContext,
    ) -> Result<Self, Error> {
        check(c)?;
        if bytes.len() > 32 * 1024 * 1024
            || hash(b"PLATFORM::SIGNAL/correlation/archive/v1\0", bytes) != expected_sha256
        {
            return Err(Error::Conflict);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if envelope.schema_version != 1 || !envelope.record.outbox.is_empty() {
            return Err(Error::Conflict);
        }
        // Pure historical config validation; this does not construct current source authority.
        let historical = Binding::new(envelope.config.clone(), c)?;
        let state = journal::recover(&historical, &envelope.record, c)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            sha256: expected_sha256,
            namespace: namespace(&historical, c)?,
            envelope,
            state,
        })
    }
    /// Bounded identities for building the host's cumulative protected indexes.
    pub fn identities(&self) -> Vec<ArchivedIdentity> {
        self.state
            .aliases
            .iter()
            .cloned()
            .map(|a| self.witness(a))
            .collect()
    }
    pub fn canonical(&self, id: Uuid) -> Option<ArchivedIdentity> {
        let alias = self.state.aliases.iter().find(|a| a.id == id)?.clone();
        Some(self.witness(alias))
    }
    pub fn native(&self, id: &NativeId) -> Option<ArchivedIdentity> {
        let alias = self
            .state
            .aliases
            .iter()
            .find(|a| a.native.as_ref() == Some(id) && a.id == a.original_id)
            .or_else(|| {
                self.state
                    .aliases
                    .iter()
                    .find(|a| a.native.as_ref() == Some(id))
            })?
            .clone();
        Some(self.witness(alias))
    }
    fn witness(&self, mut alias: Alias) -> ArchivedIdentity {
        let origin_archive = alias.origin_archive.unwrap_or(self.sha256);
        if alias.effect.is_none() {
            if let Some(episode) = self.state.episodes.iter().find(|e| {
                e.originals
                    .last()
                    .is_some_and(|e| e.id == alias.original_id)
            }) {
                if let Some(effect) = self.state.effects.iter().find(|e| e.id == episode.id) {
                    alias.effect = Some(EffectRef {
                        archive_sha256: self.sha256,
                        id: effect.id,
                        output_sha256: effect_hash(&effect.bytes),
                    });
                }
            } else if let Some(marker) = self
                .state
                .completions
                .iter()
                .find(|m| m.canonical_id == alias.original_id)
            {
                alias.effect = Some(marker.effect.clone());
            }
        }
        ArchivedIdentity {
            namespace: self.namespace,
            alias,
            origin_archive,
        }
    }
    pub fn effect(&self, reference: &EffectRef) -> Result<Output, Error> {
        if reference.archive_sha256 != self.sha256 {
            return Err(Error::Conflict);
        }
        let effect = self
            .state
            .effects
            .iter()
            .find(|e| e.id == reference.id)
            .ok_or(Error::Conflict)?;
        if effect_hash(&effect.bytes) != reference.output_sha256 {
            return Err(Error::Conflict);
        }
        Ok(Output {
            schema_version: 1,
            id: effect.id,
            bytes: effect.bytes.clone(),
        })
    }
}
fn effect_hash(bytes: &[u8]) -> [u8; 32] {
    hash(b"PLATFORM::SIGNAL/correlation/original-effect/v1\0", bytes)
}
/// Validated historical identity only. The host verifies its membership in the
/// current complete cumulative index before supplying a Known lookup result.
pub struct ArchivedIdentity {
    namespace: [u8; 32],
    alias: Alias,
    origin_archive: [u8; 32],
}
impl ArchivedIdentity {
    pub fn canonical_sha256(&self) -> [u8; 32] {
        self.alias.canonical_sha256
    }
    pub fn content_sha256(&self) -> [u8; 32] {
        self.alias.content_sha256
    }
    pub fn canonical_id(&self) -> Uuid {
        self.alias.id
    }
    pub fn first_canonical_id(&self) -> Uuid {
        self.alias.original_id
    }
    pub fn native_id(&self) -> Option<&NativeId> {
        self.alias.native.as_ref()
    }
    pub fn origin_archive(&self) -> [u8; 32] {
        self.origin_archive
    }
    pub fn effect(&self) -> Option<&EffectRef> {
        self.alias.effect.as_ref()
    }
}
pub fn export(b: &Binding, record: &Record, c: &RuleContext) -> Result<Archive, Error> {
    let state = journal::recover(b, record, c)?;
    if !record.outbox.is_empty() {
        return Err(Error::Pending);
    }
    let envelope = Envelope {
        schema_version: 1,
        config: b.config.clone(),
        record: record.clone(),
    };
    let bytes = codec::encode(&envelope, 32 * 1024 * 1024, c)?;
    let sha256 = hash(b"PLATFORM::SIGNAL/correlation/archive/v1\0", &bytes);
    Ok(Archive {
        bytes,
        sha256,
        envelope,
        state,
        namespace: namespace(b, c)?,
    })
}
pub struct Receipt {
    pub archive_sha256: [u8; 32],
    pub previous_root: [u8; 32],
    pub index_sha256: [u8; 32],
    pub authority: Authority,
}
fn anchor(
    b: &Binding,
    state: &State,
    archive: &Archive,
    receipt: &Receipt,
    c: &RuleContext,
) -> Result<Anchor, Error> {
    receipt.authority.valid(b, c)?;
    if archive.namespace != namespace(b, c)?
        || receipt.archive_sha256 != archive.sha256
        || receipt.index_sha256 == [0; 32]
        || receipt.authority.evidence.claim_sha256
            != Claim::publication(archive, receipt.previous_root, receipt.index_sha256, c)?.digest
        || receipt.previous_root != state.archive.as_ref().map_or([0; 32], |a| a.root_sha256)
    {
        return Err(Error::Conflict);
    }
    let generation = state.archive.as_ref().map_or(Ok(1), |a| {
        a.generation.checked_add(1).ok_or(Error::Capacity)
    })?;
    let mut a = Anchor {
        namespace: archive.namespace,
        generation,
        root_sha256: [0; 32],
        previous_root: receipt.previous_root,
        archive_sha256: archive.sha256,
        index_sha256: receipt.index_sha256,
        authority: receipt.authority.evidence.clone(),
    };
    a.root_sha256 = root(&a, c)?;
    Ok(a)
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Query {
    binding: [u8; 32],
    namespace: [u8; 32],
    stream: Uuid,
    canonical_id: Uuid,
    canonical_sha256: [u8; 32],
    native: Option<NativeId>,
    content_sha256: [u8; 32],
}
impl Query {
    pub fn new(
        b: &Binding,
        stream: Uuid,
        event: &SignalEvent,
        epoch: &Epoch,
        c: &RuleContext,
    ) -> Result<Self, Error> {
        epoch.valid(b, c)?;
        let source = b
            .config
            .sources
            .iter()
            .find(|s| s.stream == stream)
            .ok_or(Error::Unverified)?;
        let observation = d11::observation(source, event, epoch.proof(stream)?, c)?;
        Self::from_observation(b, &observation, c)
    }
    fn from_observation(b: &Binding, o: &Observation, c: &RuleContext) -> Result<Self, Error> {
        Ok(Self {
            binding: b.digest,
            namespace: namespace(b, c)?,
            stream: o.verification.stream,
            canonical_id: o.event.id,
            canonical_sha256: o.canonical_sha256,
            native: o.native.clone(),
            content_sha256: o.content_sha256,
        })
    }
    pub fn canonical_id(&self) -> Uuid {
        self.canonical_id
    }
    pub fn native_id(&self) -> Option<&NativeId> {
        self.native.as_ref()
    }
}
fn query_hash(query: &Query, c: &RuleContext) -> Result<[u8; 32], Error> {
    Ok(hash(
        b"PLATFORM::SIGNAL/correlation/history-query/v1\0",
        &codec::encode(query, 4096, c)?,
    ))
}
pub enum Answer<'a> {
    Known(&'a ArchivedIdentity),
    Absent,
    Unavailable,
    NotApplicable,
}
/// Non-deserializable result of fresh host verification of BOTH index keys,
/// complete across all previous publications/generations at this exact root.
pub struct Lookup<'a> {
    query: Query,
    anchor: Anchor,
    canonical: Answer<'a>,
    native: Answer<'a>,
    authority: Authority,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct LookupEvidence {
    anchor: Anchor,
    authority: AuthorityEvidence,
    query_sha256: [u8; 32],
}
impl<'a> Lookup<'a> {
    pub fn new(
        query: Query,
        anchor: Anchor,
        canonical: Answer<'a>,
        native: Answer<'a>,
        authority: Authority,
        c: &RuleContext,
    ) -> Result<Self, Error> {
        check(c)?;
        check(&authority.context)?;
        if authority.evidence.claim_sha256
            != Claim::lookup(&query, &anchor, &canonical, &native, c)?.digest
        {
            return Err(Error::Unverified);
        }
        if query.binding != authority.binding
            || query.namespace != authority.namespace
            || anchor.namespace != authority.namespace
        {
            return Err(Error::Unverified);
        }
        Ok(Self {
            query,
            anchor,
            canonical,
            native,
            authority,
        })
    }
    pub(super) fn valid(&self, b: &Binding, c: &RuleContext) -> Result<(), Error> {
        self.authority.valid(b, c)
    }
    pub(super) fn retained(&self, c: &RuleContext) -> Result<LookupEvidence, Error> {
        Ok(LookupEvidence {
            anchor: self.anchor.clone(),
            authority: self.authority.evidence.clone(),
            query_sha256: query_hash(&self.query, c)?,
        })
    }
    pub(super) fn authority_context(&self) -> &RuleContext {
        &self.authority.context
    }
}
pub(super) struct Known {
    pub original_id: Uuid,
    pub origin_archive: [u8; 32],
    pub native: Option<NativeId>,
    pub content_sha256: [u8; 32],
    pub stream: Uuid,
    pub effect: Option<EffectRef>,
}
fn known(w: &ArchivedIdentity) -> Known {
    Known {
        original_id: w.alias.original_id,
        origin_archive: w.origin_archive,
        native: w.alias.native.clone(),
        content_sha256: w.alias.content_sha256,
        stream: w.alias.stream,
        effect: w.alias.effect.clone(),
    }
}
fn same(a: &Known, b: &Known) -> bool {
    a.original_id == b.original_id
        && a.origin_archive == b.origin_archive
        && a.native == b.native
        && a.content_sha256 == b.content_sha256
        && a.stream == b.stream
        && a.effect == b.effect
}
pub(super) fn resolve(
    b: &Binding,
    state: &State,
    input: &Observation,
    lookup: Option<&Lookup<'_>>,
    c: &RuleContext,
) -> Result<Option<Known>, Error> {
    let Some(anchor) = &state.archive else {
        if lookup.is_some() {
            return Err(Error::Conflict);
        }
        return Ok(None);
    };
    let lookup = lookup.ok_or(Error::ArchiveRequired)?;
    lookup.valid(b, c)?;
    if lookup.anchor != *anchor || lookup.query != Query::from_observation(b, input, c)? {
        return Err(Error::Unverified);
    }
    let canonical = match &lookup.canonical {
        Answer::Known(w) => {
            if w.namespace != anchor.namespace
                || w.alias.id != input.event.id
                || w.alias.canonical_sha256 != input.canonical_sha256
                || w.alias.native != input.native
                || w.alias.content_sha256 != input.content_sha256
                || w.alias.stream != input.verification.stream
            {
                return Err(Error::Conflict);
            }
            Some(known(w))
        }
        Answer::Absent => None,
        Answer::Unavailable => return Err(Error::ArchiveRequired),
        Answer::NotApplicable => return Err(Error::Conflict),
    };
    let native = match (&input.native, &lookup.native) {
        (Some(id), Answer::Known(w)) => {
            if w.namespace != anchor.namespace
                || w.alias.native.as_ref() != Some(id)
                || w.alias.content_sha256 != input.content_sha256
                || w.alias.stream != input.verification.stream
            {
                return Err(Error::Conflict);
            }
            Some(known(w))
        }
        (Some(_), Answer::Absent) | (None, Answer::NotApplicable) => None,
        (_, Answer::Unavailable) => return Err(Error::ArchiveRequired),
        _ => return Err(Error::Conflict),
    };
    if canonical.is_none()
        && let Answer::Known(w) = &lookup.native
        && (w.alias.id == input.event.id || w.alias.original_id == input.event.id)
    {
        return Err(Error::Conflict);
    }
    if canonical
        .as_ref()
        .is_some_and(|a| input.native.is_some() && native.as_ref().is_none_or(|b| !same(a, b)))
    {
        return Err(Error::Conflict);
    }
    Ok(canonical.or(native))
}
pub(super) fn consistent_local(
    state: &State,
    input: &Observation,
    cold: Option<&Known>,
) -> Result<(), Error> {
    let alias = state
        .aliases
        .iter()
        .find(|a| a.id == input.event.id)
        .or_else(|| {
            input
                .native
                .as_ref()
                .and_then(|n| state.aliases.iter().find(|a| a.native.as_ref() == Some(n)))
        });
    if let Some(a) = alias {
        if let Some(cold) = cold {
            if a.origin_archive.is_none() {
                return Err(Error::Conflict);
            }
            if a.original_id != cold.original_id
                || a.native != cold.native
                || a.content_sha256 != cold.content_sha256
                || a.stream != cold.stream
                || a.origin_archive
                    .is_some_and(|sha| sha != cold.origin_archive)
                || a.effect
                    .as_ref()
                    .is_some_and(|e| Some(e) != cold.effect.as_ref())
            {
                return Err(Error::Conflict);
            }
        } else if a.origin_archive.is_some() {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
fn prefix(b: &Binding, state: &State, epoch: &Epoch, c: &RuleContext) -> Result<(), Error> {
    epoch.valid(b, c)?;
    let watermark = epoch.watermark(b).ok_or(Error::Unverified)?;
    if state.watermark.is_none_or(|old| watermark < old) {
        return Err(Error::Conflict);
    }
    for p in &epoch.evidence {
        if state
            .positions
            .iter()
            .find(|(s, _)| *s == p.stream)
            .is_none_or(|(_, n)| *n != p.position)
            || state
                .last_seal_evidence
                .iter()
                .find(|old| old.stream == p.stream)
                .is_some_and(|old| p.frontier < old.frontier || p.position < old.position)
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
fn proposal(
    b: &Binding,
    previous: Option<&Record>,
    state: State,
    checkpoint: u64,
    epoch: &Epoch,
    authority: &Authority,
    c: &RuleContext,
) -> Result<journal::Prepared, Error> {
    epoch.valid(b, c)?;
    authority.valid(b, c)?;
    let revision = previous.map_or(Ok(1), |r| {
        r.revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Capacity)
    })?;
    let record = Record {
        schema_version: 1,
        revision,
        checkpoint,
        state: state.encode(b, c)?,
        outbox: vec![],
    };
    codec::encode(&record, b.journal_config().max_record_bytes, c)?;
    epoch.valid(b, c)?;
    authority.valid(b, c)?;
    Ok(journal::Prepared {
        record,
        previous: previous.cloned(),
        config: b.journal_config(),
        original: c.clone(),
        authority: epoch.context.clone(),
        history_authority: Some(authority.context.clone()),
        source: None,
        applied: journal::Applied::History,
    })
}
/// Publish archive AND complete cumulative indexes first. Retire no identity
/// until both receipts and an exact fresh processed prefix are verified.
pub fn prune(
    b: &Binding,
    record: &Record,
    archive: &Archive,
    receipt: &Receipt,
    epoch: &Epoch,
    c: &RuleContext,
) -> Result<journal::Prepared, Error> {
    let mut state = journal::recover(b, record, c)?;
    if !record.outbox.is_empty() {
        return Err(Error::Pending);
    }
    if archive.envelope.config != b.config || archive.envelope.record != *record {
        return Err(Error::Conflict);
    }
    prefix(b, &state, epoch, c)?;
    let anchor = anchor(b, &state, archive, receipt, c)?;
    let cutoff = state
        .watermark
        .ok_or(Error::Conflict)?
        .checked_sub_signed(TimeDelta::milliseconds(b.config.ttl_ms))
        .ok_or(Error::Invalid)?;
    let retired = state
        .observations
        .iter()
        .filter(|o| {
            o.event.timestamp <= cutoff
                && o.admission_watermark
                    .is_some_and(|w| o.event.timestamp <= w)
        })
        .count() as u64;
    state.retired_late_inputs = state
        .retired_late_inputs
        .checked_add(retired)
        .ok_or(Error::Capacity)?;
    state.observations.retain(|o| o.event.timestamp > cutoff);
    state.completions.retain(|m| {
        state
            .observations
            .iter()
            .any(|o| o.event.id == m.canonical_id)
    });
    for (e, effect) in state.episodes.iter().zip(&state.effects) {
        let original = e.originals.last().ok_or(Error::Conflict)?.id;
        if state.observations.iter().any(|o| o.event.id == original) {
            state.completions.push(Completion {
                canonical_id: original,
                effect: EffectRef {
                    archive_sha256: archive.sha256,
                    id: effect.id,
                    output_sha256: effect_hash(&effect.bytes),
                },
            });
        }
    }
    state.aliases.retain(|a| {
        state
            .observations
            .iter()
            .any(|o| o.event.id == a.original_id)
    });
    for alias in &mut state.aliases {
        let witnessed = archive.canonical(alias.id).ok_or(Error::Conflict)?;
        alias.origin_archive = Some(witnessed.origin_archive);
        alias.effect = witnessed.alias.effect;
    }
    state.episodes.clear();
    state.effects.clear();
    state.archive = Some(anchor);
    proposal(
        b,
        Some(record),
        state,
        record.checkpoint,
        epoch,
        &receipt.authority,
        c,
    )
}
/// Single-writer handoff. The host keeps the old source quiescent through
/// destination commit and independently selects exactly one active generation.
#[allow(clippy::too_many_arguments)]
pub async fn carry(
    old: &Binding,
    source: &Journal,
    record: &Record,
    archive: &Archive,
    receipt: &Receipt,
    new: &Binding,
    epoch: &Epoch,
    c: &RuleContext,
) -> Result<journal::Prepared, Error> {
    epoch.valid(new, c)?;
    receipt.authority.valid(new, c)?;
    if source.config() != &old.journal_config() {
        return Err(Error::Conflict);
    }
    let mut operation = c.clone();
    operation.deadline = operation
        .deadline
        .min(epoch.context.deadline)
        .min(receipt.authority.context.deadline);
    let actual = tokio::select! {biased;
        _=epoch.context.cancellation.cancelled()=>return Err(Error::Cancelled),
        _=receipt.authority.context.cancellation.cancelled()=>return Err(Error::Cancelled),
        result=source.load(operation)=>result.map_err(|_|Error::Journal)?,
    };
    epoch.valid(new, c)?;
    receipt.authority.valid(new, c)?;
    if actual.as_ref() != Some(record) {
        return Err(Error::Conflict);
    }
    let prior = journal::recover(old, record, c)?;
    if !record.outbox.is_empty() {
        return Err(Error::Pending);
    }
    // A new policy must not strand any admitted old candidate without its original outcome.
    if prior.observations.iter().any(|o| {
        let needs = o.success != Some(false) || o.native.is_none() || o.key.is_none();
        needs
            && !prior
                .episodes
                .iter()
                .any(|e| e.originals.last().is_some_and(|e| e.id == o.event.id))
            && !prior
                .completions
                .iter()
                .any(|m| m.canonical_id == o.event.id)
    }) {
        return Err(Error::Pending);
    }

    if old.digest == new.digest
        || archive.envelope.config != old.config
        || archive.envelope.record != *record
        || namespace(old, c)? != namespace(new, c)?
    {
        return Err(Error::Conflict);
    }
    prefix(new, &prior, epoch, c)?;
    let mut state = State::new(new);
    state.positions = prior.positions.clone();
    state.watermark = epoch.watermark(new);
    state.last_seal_evidence = epoch.evidence.clone();
    let floor = state
        .watermark
        .ok_or(Error::Unverified)?
        .checked_add_signed(TimeDelta::milliseconds(
            new.config.window_ms + new.config.correlation_ms,
        ))
        .ok_or(Error::Invalid)?;
    state.degraded_through = Some(prior.degraded_through.map_or(floor, |t| t.max(floor)));
    state.retired_late_inputs = prior
        .retired_late_inputs
        .checked_add(
            prior
                .observations
                .iter()
                .filter(|o| {
                    o.admission_watermark
                        .is_some_and(|w| o.event.timestamp <= w)
                })
                .count() as u64,
        )
        .ok_or(Error::Capacity)?;
    state.archive = Some(anchor(new, &prior, archive, receipt, c)?);
    let mut prepared = proposal(
        new,
        None,
        state,
        record.checkpoint,
        epoch,
        &receipt.authority,
        c,
    )?;
    prepared.source = Some((source.clone(), record.clone()));
    prepared.applied = journal::Applied::Generation;
    Ok(prepared)
}
impl State {
    pub fn archive_anchor(&self) -> Option<&Anchor> {
        self.archive.as_ref()
    }
}

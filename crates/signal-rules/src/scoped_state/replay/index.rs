//! Durable bounded logical effects. Delivery checkpoints never erase identity.
use super::*;
use signal_event::SignalEvent;

const MAX_EFFECTS: usize = 128;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAnchor {
    pub generation: u64,
    pub namespace: [u8; 32],
    pub root_sha256: [u8; 32],
    pub index_sha256: [u8; 32],
    pub reference: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema_version: u16,
    binding: WireBinding,
    effects: Vec<Retained>,
    archive: Option<ArchiveAnchor>,
}

fn compatible(a: &WireBinding, b: &WireBinding) -> bool {
    a.schema_version == b.schema_version
        && a.rule == b.rule
        && a.source_stream == b.source_stream
        && a.source_binding == b.source_binding
        && a.scope == b.scope
        && a.source_type == b.source_type
        && a.source_name == b.source_name
        && a.source_config_revision == b.source_config_revision
}
fn namespace(binding: &WireBinding, context: &RuleContext) -> Result<[u8; 32], Error> {
    let fields = (
        &binding.rule,
        binding.source_stream,
        binding.source_binding,
        &binding.scope,
        &binding.source_type,
        &binding.source_name,
        &binding.source_config_revision,
    );
    Ok(digest(
        b"PLATFORM::SIGNAL/scoped-state/archive-namespace/v1\0",
        &input::encode(&fields, 16384, context)?,
    ))
}
#[derive(Deserialize)]
struct Header {
    schema_version: u16,
    detector_revision: String,
    rule: Detection,
    event_id: Uuid,
    input_sha256: [u8; 32],
    state_sha256: Option<[u8; 32]>,
    source_binding: [u8; 32],
    source_config_revision: String,
    policy_revision: String,
    policy_config_sha256: [u8; 32],
    authority_keys_sha256: [u8; 32],
    host_evidence: HostEvidence,
    finding: Option<signal_findings::Finding>,
}
fn validate_effect(
    current: &WireBinding,
    effect: &Retained,
    context: &RuleContext,
) -> Result<(), Error> {
    check(context)?;
    if effect.schema_version != 1
        || !compatible(current, &effect.binding)
        || effect.original_input.len() > MAX_INPUT_BYTES
        || effect.original_output.len() > MAX_OUTPUT_BYTES
        || effect.input_sha256
            != digest(
                b"PLATFORM::SIGNAL/scoped-state/input/v1\0",
                &effect.original_input,
            )
        || effect.output_sha256
            != digest(
                b"PLATFORM::SIGNAL/scoped-state/decision/v1\0",
                &effect.original_output,
            )
    {
        return Err(Error::Conflict);
    }
    let event: SignalEvent =
        serde_json::from_slice(&effect.original_input).map_err(|_| Error::Conflict)?;
    let input = Input::new(&event, context)?;
    if event.id != effect.event_id
        || input.sha256() != effect.input_sha256
        || input.original_bytes() != effect.original_input
    {
        return Err(Error::Conflict);
    }
    let h: Header = serde_json::from_slice(&effect.original_output).map_err(|_| Error::Conflict)?;
    let b = &effect.binding;
    if h.schema_version != 1
        || h.detector_revision != "scoped-state-v1"
        || h.rule != b.rule
        || h.event_id != effect.event_id
        || h.input_sha256 != effect.input_sha256
        || h.source_binding != b.source_binding
        || h.source_config_revision != b.source_config_revision
        || h.policy_revision != b.policy_revision
        || h.policy_config_sha256 != b.policy_config_sha256
        || h.authority_keys_sha256 != b.authority_keys_sha256
        || h.host_evidence.source_binding != b.source_binding
        || h.host_evidence.scope != b.scope
        || h.host_evidence.source_type != b.source_type
        || h.host_evidence.source_name != b.source_name
        || h.host_evidence.source_config_revision != b.source_config_revision
        || h.host_evidence.policy_revision != b.policy_revision
        || h.host_evidence.state_authority_revision != b.authority_revision
        || h.host_evidence.policy_config_sha256 != b.policy_config_sha256
        || h.host_evidence.authority_keys_sha256 != b.authority_keys_sha256
        || effect
            .original_state
            .as_ref()
            .map(|s| evaluate::state_digest(s, context))
            .transpose()?
            != h.state_sha256
    {
        return Err(Error::Conflict);
    }
    if let Some(proof) = &effect.archive_admission {
        validate_admission(b, proof, context)?;
    }
    if let Some(f) = h.finding {
        f.validate().map_err(|_| Error::Conflict)?;
        let expected =
            signal_findings::Finding::for_event(b.rule.id(), &event, f.severity, &f.title)
                .map_err(|_| Error::Conflict)?;
        if f != expected {
            return Err(Error::Conflict);
        }
    }
    check(context)
}
fn validate_ledger(binding: &Binding, ledger: &Ledger, context: &RuleContext) -> Result<(), Error> {
    check(context)?;
    if ledger.schema_version != 2
        || ledger.binding != binding.wire
        || ledger.effects.len() > MAX_EFFECTS
    {
        return Err(Error::Conflict);
    }
    let mut ids = std::collections::BTreeSet::new();
    for effect in &ledger.effects {
        if !ids.insert(effect.event_id) {
            return Err(Error::Conflict);
        }
        validate_effect(&binding.wire, effect, context)?;
    }
    if let Some(a) = &ledger.archive
        && (a.generation == 0
            || a.namespace != namespace(&binding.wire, context)?
            || a.root_sha256 == [0; 32]
            || a.index_sha256 == [0; 32]
            || !identity(&a.reference))
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn load(binding: &Binding, record: &Record, context: &RuleContext) -> Result<Ledger, Error> {
    check(context)?;
    if record.schema_version != 1
        || record.revision == 0
        || record.state.len() > 4 * MAX_STATE_BYTES
        || record.outbox.len() > 1
    {
        return Err(Error::Conflict);
    }
    let ledger: Ledger = serde_json::from_slice(&record.state).map_err(|_| Error::Conflict)?;
    validate_ledger(binding, &ledger, context)?;
    if let Some(output) = record.outbox.first()
        && (output.schema_version != 1
            || !ledger.effects.iter().any(|e| {
                output.id == output_id(e.binding.rule, e.event_id)
                    && output.bytes == e.original_output
            }))
    {
        return Err(Error::Conflict);
    }
    Ok(ledger)
}
fn proposal(
    binding: &Binding,
    ledger: Ledger,
    revision: u64,
    checkpoint: u64,
    outbox: Vec<Output>,
    original: RuleContext,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    check(context)?;
    if revision == 0 || ledger.effects.len() > MAX_EFFECTS {
        return Err(Error::Capacity);
    }
    validate_ledger(binding, &ledger, context)?;
    let state = input::encode(&ledger, 4 * MAX_STATE_BYTES, context)?;
    let record = Record {
        schema_version: 1,
        revision,
        checkpoint,
        state,
        outbox,
    };
    // Include JSON byte-array framing of the generic journal record, not just
    // the ledger's own encoding, before any disk admission.
    input::encode(&record, binding.journal_config().max_record_bytes, context)?;
    Ok(Prepared {
        record,
        original,
        preparation: context.clone(),
        expected_config: binding.journal_config(),
        authority: None,
        previous: None,
        source: None,
    })
}
fn next(record: &Record) -> Result<u64, Error> {
    record
        .revision
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::Capacity)
}
fn check_input(effect: &Retained, input: &Input<'_>) -> Result<(), Error> {
    if effect.input_sha256 != input.sha256 || effect.original_input != input.bytes {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Retained archive data. Decoding it never constructs current lookup authority.
pub struct ArchivedEffect {
    effect: Retained,
}
pub struct Archive {
    bytes: Vec<u8>,
    sha256: [u8; 32],
    ledger: Ledger,
}
impl Binding {
    /// Stable logical-source namespace used by the host's complete archive index.
    pub fn archive_namespace(&self, context: &RuleContext) -> Result<[u8; 32], Error> {
        namespace(&self.wire, context)
    }
}
impl Archive {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn effect(&self, event_id: Uuid) -> Option<ArchivedEffect> {
        self.ledger
            .effects
            .iter()
            .find(|e| e.event_id == event_id)
            .cloned()
            .map(|effect| ArchivedEffect { effect })
    }
    pub fn from_bytes(
        binding: &Binding,
        bytes: &[u8],
        expected_sha256: [u8; 32],
        context: &RuleContext,
    ) -> Result<Self, Error> {
        check(context)?;
        if bytes.len() > 4 * MAX_STATE_BYTES
            || digest(b"PLATFORM::SIGNAL/scoped-state/archive/v1\0", bytes) != expected_sha256
        {
            return Err(Error::Conflict);
        }
        let mut ledger: Ledger = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
        if !compatible(&binding.wire, &ledger.binding) {
            return Err(Error::Conflict);
        }
        // Historical archive enrollment is data; current lookup authority remains
        // separately supplied. Validate every original historical effect.
        ledger.binding = binding.wire.clone();
        validate_ledger(binding, &ledger, context)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            sha256: expected_sha256,
            ledger,
        })
    }
}
pub fn export_history(
    binding: &Binding,
    record: &Record,
    context: &RuleContext,
) -> Result<Archive, Error> {
    let ledger = load(binding, record, context)?;
    if !record.outbox.is_empty() {
        return Err(Error::Conflict);
    }
    let bytes = input::encode(&ledger, 4 * MAX_STATE_BYTES, context)?;
    let sha256 = digest(b"PLATFORM::SIGNAL/scoped-state/archive/v1\0", &bytes);
    Ok(Archive {
        bytes,
        sha256,
        ledger,
    })
}
/// Historical proof that the complete archived identity index was checked before
/// admitting this new logical event. This data never supplies fresh authority.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveAdmission {
    anchor: ArchiveAnchor,
    authority: HostEvidence,
    reference: String,
}
fn validate_admission(
    binding: &WireBinding,
    proof: &ArchiveAdmission,
    context: &RuleContext,
) -> Result<(), Error> {
    let h = &proof.authority;
    if proof.anchor.namespace != namespace(binding, context)?
        || proof.anchor.generation == 0
        || proof.anchor.root_sha256 == [0; 32]
        || proof.anchor.index_sha256 == [0; 32]
        || !identity(&proof.anchor.reference)
        || !identity(&proof.reference)
        || h.source_binding != binding.source_binding
        || h.scope != binding.scope
        || h.source_type != binding.source_type
        || h.source_name != binding.source_name
        || h.source_config_revision != binding.source_config_revision
        || h.policy_revision != binding.policy_revision
        || h.policy_config_sha256 != binding.policy_config_sha256
        || h.state_authority_revision != binding.authority_revision
        || h.authority_keys_sha256 != binding.authority_keys_sha256
        || !h.ready
        || h.verified_at > h.assessed_at
        || h.assessed_at >= h.verified_until
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Fresh host verification with a monotonic lifetime fixed at construction.
/// Cloning or consuming this evidence never renews its validity.
#[derive(Clone)]
pub struct ArchiveAuthority {
    binding: WireBinding,
    evidence: HostEvidence,
    authority_keys_sha256: [u8; 32],
    reference: String,
    complete: bool,
    context: RuleContext,
}
impl ArchiveAuthority {
    pub fn new(
        binding: &Binding,
        host: &HostContext,
        reference: String,
        complete: bool,
        context: &RuleContext,
    ) -> Result<Self, Error> {
        check(context)?;
        if !evaluate::host_valid(host)
            || !identity(&reference)
            || !host.ready
            || host.verified_at > host.now
            || host.now >= host.verified_until
            || Binding::new(
                binding.wire.rule,
                binding.wire.source_stream,
                host,
                host.policy_config_sha256,
                host.authority_keys_sha256,
                context,
            )?
            .wire
                != binding.wire
        {
            return Err(Error::Invalid);
        }
        let remaining = (host.verified_until - host.now)
            .to_std()
            .map_err(|_| Error::Invalid)?;
        let mut bounded = context.clone();
        bounded.deadline = bounded.deadline.min(
            tokio::time::Instant::now()
                .checked_add(remaining)
                .ok_or(Error::Invalid)?,
        );
        Ok(Self {
            binding: binding.wire.clone(),
            evidence: host.retained(),
            authority_keys_sha256: host.authority_keys_sha256,
            reference,
            complete,
            context: bounded,
        })
    }
}
/// Fresh host verification of durable archive publication AND complete index
/// publication covering all previous prunes. Never populate from archive JSON.
pub struct ArchiveReceipt {
    pub namespace: [u8; 32],
    pub archive_sha256: [u8; 32],
    pub previous_root: [u8; 32],
    pub index_sha256: [u8; 32],
    pub authority: ArchiveAuthority,
}
pub enum ArchiveAnswer<'a> {
    Known(&'a ArchivedEffect),
    Absent,
    Unknown,
}
/// Lookup is by UUID alone, then hash equality is checked. Fresh absence must
/// attest the complete index across ALL pruned generations at this exact anchor.
pub struct ArchiveCheck<'a> {
    pub anchor: ArchiveAnchor,
    pub namespace: [u8; 32],
    pub event_id: Uuid,
    pub input_sha256: [u8; 32],
    pub authority: ArchiveAuthority,
    pub answer: ArchiveAnswer<'a>,
}
fn archive_answer<'a>(
    binding: &Binding,
    anchor: &ArchiveAnchor,
    input: &Input<'_>,
    proof: Option<&'a ArchiveCheck<'_>>,
    context: &RuleContext,
) -> Result<Option<Option<&'a Retained>>, Error> {
    check(context)?;
    let Some(p) = proof else {
        return Ok(None);
    };
    if p.anchor != *anchor
        || p.namespace != namespace(&binding.wire, context)?
        || p.event_id != input.event.id
        || p.input_sha256 != input.sha256
        || p.authority.binding != binding.wire
        || p.authority.authority_keys_sha256 != binding.wire.authority_keys_sha256
        || !identity(&p.authority.reference)
        || !p.authority.complete
        || check(&p.authority.context).is_err()
    {
        return Ok(None);
    }
    match &p.answer {
        ArchiveAnswer::Unknown => Ok(None),
        ArchiveAnswer::Absent => Ok(Some(None)),
        ArchiveAnswer::Known(effect) => {
            validate_effect(&binding.wire, &effect.effect, context)?;
            if effect.effect.event_id != input.event.id {
                return Err(Error::Conflict);
            }
            check_input(&effect.effect, input)?;
            Ok(Some(Some(&effect.effect)))
        }
    }
}
pub fn prune_archived(
    binding: &Binding,
    record: &Record,
    archive: &Archive,
    receipt: &ArchiveReceipt,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    let mut ledger = load(binding, record, context)?;
    if !record.outbox.is_empty()
        || archive.bytes != input::encode(&ledger, 4 * MAX_STATE_BYTES, context)?
        || receipt.archive_sha256 != archive.sha256
        || receipt.namespace != namespace(&binding.wire, context)?
        || receipt.previous_root != ledger.archive.as_ref().map_or([0; 32], |a| a.root_sha256)
        || receipt.index_sha256 == [0; 32]
        || receipt.authority.binding != binding.wire
        || receipt.authority.authority_keys_sha256 != binding.wire.authority_keys_sha256
        || !identity(&receipt.authority.reference)
        || !receipt.authority.complete
        || check(&receipt.authority.context).is_err()
    {
        return Err(Error::Conflict);
    }
    let generation = ledger.archive.as_ref().map_or(Ok(1), |a| {
        a.generation.checked_add(1).ok_or(Error::Capacity)
    })?;
    let root_fields = (
        receipt.previous_root,
        receipt.index_sha256,
        archive.sha256,
        generation,
        receipt.namespace,
    );
    let root_sha256 = digest(
        b"PLATFORM::SIGNAL/scoped-state/archive-root/v1\0",
        &input::encode(&root_fields, 1024, context)?,
    );
    ledger.archive = Some(ArchiveAnchor {
        generation,
        namespace: receipt.namespace,
        root_sha256,
        index_sha256: receipt.index_sha256,
        reference: receipt.authority.reference.clone(),
    });
    ledger.effects.clear();
    proposal(
        binding,
        ledger,
        next(record)?,
        record.checkpoint,
        vec![],
        receipt.authority.context.clone(),
        context,
    )
    .map(|mut prepared| {
        prepared.previous = Some(record.clone());
        prepared
    })
}
pub fn recover_checked(
    binding: &Binding,
    record: Option<&Record>,
    input: &Input<'_>,
    source_checkpoint: u64,
    proof: Option<&ArchiveCheck<'_>>,
    context: &RuleContext,
) -> Result<Recovery, Error> {
    check(context)?;
    let Some(record) = record else {
        return Ok(Recovery::NewInput { next_revision: 1 });
    };
    let ledger = load(binding, record, context)?;
    let found = ledger.effects.iter().find(|e| e.event_id == input.event.id);
    if let Some(effect) = found {
        check_input(effect, input)?;
    }
    // Every identity/conflict check precedes checkpoint shortcuts.
    let effect = if let Some(effect) = found {
        Some(effect)
    } else if let Some(anchor) = &ledger.archive {
        match archive_answer(binding, anchor, input, proof, context)? {
            None => {
                return Ok(Recovery::ArchiveRequired {
                    anchor: anchor.clone(),
                });
            }
            Some(effect) => effect,
        }
    } else {
        None
    };
    if let Some(output) = record.outbox.first() {
        if effect.is_some_and(|e| output.id == output_id(e.binding.rule, e.event_id)) {
            return Ok(Recovery::Pending {
                output: output.clone(),
            });
        }
        return Ok(Recovery::DrainPrior {
            output: output.clone(),
        });
    }
    if let Some(effect) = effect {
        return Ok(Recovery::Published {
            original_output: effect.original_output.clone(),
        });
    }
    if source_checkpoint <= record.checkpoint {
        return Err(Error::Conflict);
    }
    Ok(Recovery::NewInput {
        next_revision: next(record)?,
    })
}

/// New logical input only. Recovery/absence authorization is rechecked against
/// the exact previous record; retirement never removes history membership.
#[allow(clippy::too_many_arguments)]
pub fn prepare_after(
    binding: &Binding,
    previous: Option<&Record>,
    input: &Input<'_>,
    state: Option<&Snapshot>,
    decision: &Decision,
    checkpoint: u64,
    proof: Option<&ArchiveCheck<'_>>,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    check(context)?;
    check(&decision.original_context)?;
    if decision.event_id != input.event.id
        || decision.input_sha256 != input.sha256
        || !binding.agrees(decision)
        || evaluate::decision_digest(decision, context)? != decision.seal
        || state
            .map(|s| evaluate::state_digest(s, context))
            .transpose()?
            != decision.state_sha256
    {
        return Err(Error::Conflict);
    }
    let Recovery::NewInput { next_revision } =
        recover_checked(binding, previous, input, checkpoint, proof, context)?
    else {
        return Err(Error::Conflict);
    };
    let mut ledger = previous
        .map(|r| load(binding, r, context))
        .transpose()?
        .unwrap_or(Ledger {
            schema_version: 2,
            binding: binding.wire.clone(),
            effects: vec![],
            archive: None,
        });
    if ledger.effects.len() >= MAX_EFFECTS {
        return Err(Error::Capacity);
    }
    let output = input::encode(decision, MAX_OUTPUT_BYTES, context)?;
    ledger.effects.push(Retained {
        schema_version: 1,
        binding: binding.wire.clone(),
        event_id: input.event.id,
        input_sha256: input.sha256,
        original_input: input.bytes.clone(),
        original_state: state.cloned(),
        original_output: output.clone(),
        output_sha256: decision.seal,
        archive_admission: if ledger.archive.is_some() {
            let p = proof.ok_or(Error::Conflict)?;
            Some(ArchiveAdmission {
                anchor: p.anchor.clone(),
                authority: p.authority.evidence.clone(),
                reference: p.authority.reference.clone(),
            })
        } else {
            None
        },
    });
    let mut original = decision.original_context.clone();
    if ledger.archive.is_some() {
        let verification = &proof.ok_or(Error::Conflict)?.authority.context;
        check(verification)?;
        original.deadline = original.deadline.min(verification.deadline);
        // Keep both cancellation tokens through Prepared::preparation below.
    }
    let mut prepared = proposal(
        binding,
        ledger,
        next_revision,
        checkpoint,
        vec![Output {
            schema_version: 1,
            id: output_id(decision.rule, input.event.id),
            bytes: output,
        }],
        original,
        context,
    )?;
    prepared.previous = previous.cloned();
    prepared.authority = proof.map(|p| p.authority.context.clone());
    Ok(prepared)
}
/// Advance only delivery progress for an existing immutable effect. A prior
/// undrained output must be published/retired first; no verdict is regenerated.
pub fn advance_duplicate(
    binding: &Binding,
    record: &Record,
    input: &Input<'_>,
    checkpoint: u64,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    let ledger = load(binding, record, context)?;
    let effect = ledger
        .effects
        .iter()
        .find(|e| e.event_id == input.event.id)
        .ok_or(Error::Conflict)?;
    check_input(effect, input)?;
    if checkpoint <= record.checkpoint || !record.outbox.is_empty() {
        return Err(Error::Conflict);
    }
    proposal(
        binding,
        ledger,
        next(record)?,
        checkpoint,
        vec![],
        context.clone(),
        context,
    )
    .map(|mut prepared| {
        prepared.previous = Some(record.clone());
        prepared
    })
}
pub fn restore_archived(
    binding: &Binding,
    record: &Record,
    input: &Input<'_>,
    checkpoint: u64,
    proof: &ArchiveCheck<'_>,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    let mut ledger = load(binding, record, context)?;
    if !record.outbox.is_empty()
        || checkpoint < record.checkpoint
        || ledger.effects.iter().any(|e| e.event_id == input.event.id)
    {
        return Err(Error::Conflict);
    }
    let anchor = ledger.archive.as_ref().ok_or(Error::Conflict)?;
    let Some(Some(effect)) = archive_answer(binding, anchor, input, Some(proof), context)? else {
        return Err(Error::Conflict);
    };
    if ledger.effects.len() >= MAX_EFFECTS {
        return Err(Error::Capacity);
    }
    ledger.effects.push(effect.clone());
    proposal(
        binding,
        ledger,
        next(record)?,
        checkpoint,
        vec![],
        proof.authority.context.clone(),
        context,
    )
    .map(|mut prepared| {
        prepared.previous = Some(record.clone());
        prepared
    })
}
/// Only drained generations can seed a new journal. Historical effects retain
/// old enrollment and complete archive root; current authority is never restored.
pub async fn carry_generation(
    old: &Binding,
    source: &Journal,
    record: &Record,
    new: &Binding,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    if source.config() != &old.journal_config()
        || source
            .load(context.clone())
            .await
            .map_err(|_| Error::Journal)?
            .as_ref()
            != Some(record)
    {
        return Err(Error::Conflict);
    }
    let mut ledger = load(old, record, context)?;
    if !record.outbox.is_empty()
        || !compatible(&old.wire, &new.wire)
        || old.enrollment == new.enrollment
    {
        return Err(Error::Conflict);
    }
    ledger.binding = new.wire.clone();
    proposal(
        new,
        ledger,
        1,
        record.checkpoint,
        vec![],
        context.clone(),
        context,
    )
    .map(|mut prepared| {
        prepared.source = Some((source.clone(), record.clone()));
        prepared
    })
}

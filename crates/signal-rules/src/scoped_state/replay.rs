//! Original input/state/output custody using the existing transactional journal.
use super::*;
use crate::{
    RuleContext,
    state_journal::{Config, Journal, Output, Record},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    schema_version: u16,
    rule: Detection,
    source_stream: Uuid,
    source_binding: [u8; 32],
    scope: Scope,
    source_type: String,
    source_name: Option<String>,
    source_config_revision: String,
    policy_revision: String,
    authority_revision: String,
    policy_config_sha256: [u8; 32],
    authority_keys_sha256: [u8; 32],
}
/// A host-selected journal generation, not reconstructed from historical data.
pub struct Binding {
    wire: WireBinding,
    enrollment: [u8; 32],
}
impl Binding {
    /// Private host hashes complete policy/configuration and authority enrollment.
    /// New generations drain the old journal; historical records grant no authority.
    pub fn new(
        rule: Detection,
        source_stream: Uuid,
        host: &HostContext,
        policy_config_sha256: [u8; 32],
        authority_keys_sha256: [u8; 32],
        context: &RuleContext,
    ) -> Result<Self, Error> {
        check(context)?;
        if !evaluate::host_valid(host)
            || source_stream.is_nil()
            || policy_config_sha256 == [0; 32]
            || policy_config_sha256 != host.policy_config_sha256
            || authority_keys_sha256 != host.authority_keys_sha256
            || authority_keys_sha256 == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let wire = WireBinding {
            schema_version: 1,
            rule,
            source_stream,
            source_binding: host.source_binding,
            scope: host.scope.clone(),
            source_type: host.source_type.clone(),
            source_name: host.source_name.clone(),
            source_config_revision: host.source_config_revision.clone(),
            policy_revision: host.policy_revision.clone(),
            authority_revision: host.state_authority_revision.clone(),
            policy_config_sha256,
            authority_keys_sha256,
        };
        let mut hash = Sha256::new();
        hash.update(b"PLATFORM::SIGNAL/scoped-state/enrollment/v1\0");
        hash.update(input::encode(&wire, 16384, context)?);
        Ok(Self {
            wire,
            enrollment: hash.finalize().into(),
        })
    }
    pub fn journal_config(&self) -> Config {
        Config {
            schema_version: 1,
            source_stream: self.wire.source_stream,
            source_binding: self.wire.source_binding,
            enrollment_binding: self.enrollment,
            max_record_bytes: 16 * 1024 * 1024,
            max_state_bytes: 4 * MAX_STATE_BYTES,
            max_outputs: 1,
            max_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
    fn agrees(&self, decision: &Decision) -> bool {
        let h = &decision.host_evidence;
        self.wire.rule == decision.rule
            && self.wire.source_binding == decision.source_binding
            && h.source_binding == decision.source_binding
            && self.wire.scope == h.scope
            && self.wire.source_type == h.source_type
            && self.wire.source_name == h.source_name
            && self.wire.policy_revision == decision.policy_revision
            && self.wire.policy_revision == h.policy_revision
            && self.wire.source_config_revision == decision.source_config_revision
            && self.wire.source_config_revision == h.source_config_revision
            && self.wire.authority_revision == h.state_authority_revision
            && self.wire.policy_config_sha256 == h.policy_config_sha256
            && self.wire.authority_keys_sha256 == h.authority_keys_sha256
    }
}
mod bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > MAX_INPUT_BYTES.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom("scoped state encoded byte budget"));
        }
        let bytes = STANDARD
            .decode(value.as_bytes())
            .map_err(|_| serde::de::Error::custom("scoped state binary encoding"))?;
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(serde::de::Error::custom("scoped state binary budget"));
        }
        Ok(bytes)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained {
    schema_version: u16,
    binding: WireBinding,
    event_id: Uuid,
    input_sha256: [u8; 32],
    #[serde(with = "bytes")]
    original_input: Vec<u8>,
    original_state: Option<Snapshot>,
    #[serde(with = "bytes")]
    original_output: Vec<u8>,
    output_sha256: [u8; 32],
    archive_admission: Option<index::ArchiveAdmission>,
}
/// Immutable proposal with original admission context. Recovery is read-only.
pub struct Prepared {
    record: Record,
    original: RuleContext,
    preparation: RuleContext,
    expected_config: Config,
    authority: Option<RuleContext>,
    previous: Option<Record>,
    source: Option<(Journal, Record)>,
}
impl Prepared {
    pub fn record(&self) -> &Record {
        &self.record
    }
    pub async fn commit(&self, journal: &Journal, expected_revision: u64) -> Result<Record, Error> {
        if journal.config() != &self.expected_config {
            return Err(Error::Conflict);
        }
        if let Some(authority) = &self.authority {
            check(authority)?;
        }
        check(&self.original)?;
        check(&self.preparation)?;
        let mut operation = self.original.clone();
        operation.deadline = operation.deadline.min(self.preparation.deadline);
        let execute = async {
            if let Some((source, expected)) = &self.source
                && source
                    .load(operation.clone())
                    .await
                    .map_err(|_| Error::Journal)?
                    .as_ref()
                    != Some(expected)
            {
                return Err(Error::Conflict);
            }
            if journal
                .load(operation.clone())
                .await
                .map_err(|_| Error::Journal)?
                != self.previous
            {
                return Err(Error::Conflict);
            }
            journal
                .commit(expected_revision, self.record.clone(), operation)
                .await
                .map_err(|_| Error::Journal)
        };
        tokio::select! {biased;
            _=self.preparation.cancellation.cancelled()=>Err(Error::Cancelled),
            _=async { match &self.authority { Some(a) => a.cancellation.cancelled().await, None => std::future::pending().await } }=>Err(Error::Cancelled),
            result=execute=>result,
        }
    }
    /// A fresh read budget may establish an uncertain exact effect, never admit
    /// a new assessment or replace its policy/state.
    pub async fn reconcile(
        &self,
        journal: &Journal,
        context: RuleContext,
    ) -> Result<Record, Error> {
        if journal.config() != &self.expected_config {
            return Err(Error::Conflict);
        }
        let loaded = journal
            .load(context)
            .await
            .map_err(|_| Error::Journal)?
            .ok_or(Error::Conflict)?;
        if loaded != self.record {
            return Err(Error::Conflict);
        }
        Ok(loaded)
    }
}
fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
fn output_id(rule: Detection, event: Uuid) -> Uuid {
    Uuid::new_v5(
        &Uuid::from_bytes(*b"SIGNAL-STATEOUT1"),
        &[rule.id().as_bytes(), event.as_bytes()].concat(),
    )
}
/// Publish original outbox before retirement/ACK. Exact state and decision seal
/// prevent caller-side mutation of the recorded assessment basis.
pub fn prepare(
    binding: &Binding,
    input: &Input<'_>,
    state: Option<&Snapshot>,
    decision: &Decision,
    revision: u64,
    checkpoint: u64,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    if revision != 1 {
        return Err(Error::Conflict);
    }
    index::prepare_after(
        binding, None, input, state, decision, checkpoint, None, context,
    )
}

#[derive(Debug)]
pub enum Recovery {
    ArchiveRequired {
        anchor: ArchiveAnchor,
    },
    NewInput {
        next_revision: u64,
    },
    /// Source positions come from the bound WAL, never event/HTTP claims. This
    /// does not verify the bytes of a supplied older payload.
    PriorCheckpoint {
        frontier: u64,
    },
    DrainPrior {
        output: Output,
    },
    Pending {
        output: Output,
    },
    Published {
        original_output: Vec<u8>,
    },
}
/// Recover logical effects before any new assessment, independently of delivery position.
pub fn recover(
    binding: &Binding,
    record: Option<&Record>,
    input: &Input<'_>,
    source_checkpoint: u64,
    context: &RuleContext,
) -> Result<Recovery, Error> {
    index::recover_checked(binding, record, input, source_checkpoint, None, context)
}
mod index;
pub use index::{
    Archive, ArchiveAnchor, ArchiveAnswer, ArchiveAuthority, ArchiveCheck, ArchiveReceipt,
    ArchivedEffect, advance_duplicate, carry_generation, export_history, prepare_after,
    prune_archived, recover_checked, restore_archived,
};

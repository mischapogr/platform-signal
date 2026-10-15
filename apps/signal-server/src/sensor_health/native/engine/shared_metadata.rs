//! Original canonical references for shared storage. Metadata grants no authority.
use super::*;
use serde_json::Value;
use signal_storage::StoredEvent;
use std::collections::BTreeMap;

const METADATA_BYTES: usize = signal_control::ITEM_BYTES;
const RETAINED_BYTES: usize = 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    schema_version: u16,
    id: Uuid,
    sha256: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u16,
    snapshot: Value,
    canonical_sha256: BTreeMap<Uuid, [u8; 32]>,
}
/// Bounded state metadata plus originals for protected canonical publication.
/// The Standard host must bind scope/generation/key/revision and install pins.
pub struct Detached {
    pub metadata: Value,
    pub canonical_sequences: BTreeMap<Uuid, u64>,
    pub retained: Vec<StoredEvent>,
}
fn array<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>, Error> {
    value
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .ok_or(Error::Configuration)
}
fn evidence<F>(value: &mut Value, visit: &mut F, context: &RuleContext) -> Result<(), Error>
where
    F: FnMut(u64, &mut Value) -> Result<(), Error>,
{
    for proof in array(value, "evidence")? {
        check(context)?;
        let sequence = proof
            .get("wal_sequence")
            .and_then(Value::as_u64)
            .ok_or(Error::Configuration)?;
        visit(
            sequence,
            proof.get_mut("event").ok_or(Error::Configuration)?,
        )?;
    }
    Ok(())
}
/// Visit only the versioned proof locations. An arbitrary private attribute named
/// "event" inside a canonical event is never interpreted as metadata.
fn walk<F>(snapshot: &mut Value, visit: &mut F, context: &RuleContext) -> Result<(), Error>
where
    F: FnMut(u64, &mut Value) -> Result<(), Error>,
{
    let record = snapshot.get_mut("record").ok_or(Error::Configuration)?;
    let state = record.get_mut("state").ok_or(Error::Configuration)?;
    for proof in array(state, "proofs")? {
        check(context)?;
        let sequence = proof
            .get("wal_sequence")
            .and_then(Value::as_u64)
            .ok_or(Error::Configuration)?;
        visit(
            sequence,
            proof.get_mut("event").ok_or(Error::Configuration)?,
        )?;
    }
    for pending in array(state, "known")? {
        evidence(pending, visit, context)?;
    }
    let history = state.get_mut("history").ok_or(Error::Configuration)?;
    for entry in array(history, "entries")? {
        evidence(entry, visit, context)?;
    }
    for output in array(record, "outbox")? {
        evidence(
            output.get_mut("bytes").ok_or(Error::Configuration)?,
            visit,
            context,
        )?;
    }
    Ok(())
}
impl Engine {
    /// Remove canonical bodies from typed state without discarding any current,
    /// historical, known-gap or pending-output reference. Capacity refuses all.
    pub fn detach(&self, snapshot: &Snapshot, context: &RuleContext) -> Result<Detached, Error> {
        let state = self.decoded(snapshot, context)?;
        if encode(&state, self.config.max_state_bytes)? != snapshot.record.state {
            return Err(Error::Conflict);
        }
        let mut value = serde_json::to_value(snapshot).map_err(|_| Error::Configuration)?;
        value["record"]["state"] =
            serde_json::from_slice(&snapshot.record.state).map_err(|_| Error::Configuration)?;
        let monitor = Monitor::restore(self.config.policy.clone(), &state.monitor)?;
        if monitor.snapshot()? != state.monitor {
            return Err(Error::Conflict);
        }
        let mut compact: Value =
            serde_json::from_slice(&state.monitor).map_err(|_| Error::Configuration)?;
        let object = compact.as_object_mut().ok_or(Error::Configuration)?;
        object.remove("policy").ok_or(Error::Configuration)?;
        object.insert(
            "policy_sha256".into(),
            serde_json::to_value(self.verifier.policy_sha256())
                .map_err(|_| Error::Configuration)?,
        );
        value["record"]["state"]["monitor"] = compact;
        for (output, original) in array(
            value.get_mut("record").ok_or(Error::Configuration)?,
            "outbox",
        )?
        .iter_mut()
        .zip(&snapshot.record.outbox)
        {
            let pending: Pending =
                serde_json::from_slice(&original.bytes).map_err(|_| Error::Configuration)?;
            if encode(&pending, self.config.max_output_bytes)? != original.bytes {
                return Err(Error::Conflict);
            }
            output["bytes"] =
                serde_json::from_slice(&original.bytes).map_err(|_| Error::Configuration)?;
        }
        let mut hashes = BTreeMap::new();
        let mut sequences = BTreeMap::new();
        let mut positions = BTreeMap::new();
        let mut retained = BTreeMap::new();
        let mut bytes = 0usize;
        walk(
            &mut value,
            &mut |sequence, event| {
                let original: SignalEvent =
                    serde_json::from_value(event.clone()).map_err(|_| Error::Configuration)?;
                let body = encode(&original, self.config.max_event_bytes)?;
                let sha256: [u8; 32] = Sha256::digest(&body).into();
                let id = original.id;
                if sequences.get(&id).is_some_and(|old| *old != sequence)
                    || hashes.get(&id).is_some_and(|old| *old != sha256)
                    || positions.get(&sequence).is_some_and(|old| *old != id)
                {
                    return Err(Error::Conflict);
                }
                if !retained.contains_key(&id) {
                    bytes = bytes.checked_add(body.len()).ok_or(Error::Capacity)?;
                    if retained.len() >= 4096 || bytes > RETAINED_BYTES {
                        return Err(Error::Capacity);
                    }
                    retained.insert(
                        id,
                        StoredEvent {
                            sequence,
                            event: original,
                        },
                    );
                }
                sequences.insert(id, sequence);
                positions.insert(sequence, id);
                hashes.insert(id, sha256);
                *event = serde_json::to_value(Reference {
                    schema_version: 1,
                    id,
                    sha256,
                })
                .map_err(|_| Error::Configuration)?;
                Ok(())
            },
            context,
        )?;
        let metadata = Metadata {
            schema_version: 1,
            snapshot: value,
            canonical_sha256: hashes,
        };
        encode(&metadata, METADATA_BYTES)?;
        check(context)?;
        Ok(Detached {
            metadata: serde_json::to_value(metadata).map_err(|_| Error::Configuration)?,
            canonical_sequences: sequences,
            retained: retained.into_values().collect(),
        })
    }

    /// Hydrate only from complete, independently protected canonical rows. This
    /// validates historical data and never adds a source to fresh authority.
    pub fn hydrate(
        &self,
        metadata: &Value,
        sequences: &BTreeMap<Uuid, u64>,
        rows: &[StoredEvent],
        context: &RuleContext,
    ) -> Result<Snapshot, Error> {
        check(context)?;
        if sequences.len() > 4096 || rows.len() > 4096 {
            return Err(Error::Capacity);
        }
        encode(metadata, METADATA_BYTES)?;
        let mut data: Metadata =
            serde_json::from_value(metadata.clone()).map_err(|_| Error::Configuration)?;
        if data.schema_version != 1 || data.canonical_sha256.len() != sequences.len() {
            return Err(Error::Conflict);
        }
        let mut inputs = BTreeMap::new();
        let mut positions = BTreeSet::new();
        for row in rows {
            check(context)?;
            if row.sequence == 0
                || !positions.insert(row.sequence)
                || inputs.insert(row.event.id, row).is_some()
            {
                return Err(Error::Conflict);
            }
        }
        if inputs.len() != sequences.len() {
            return Err(Error::Conflict);
        }
        let mut seen = BTreeSet::new();
        let mut bytes = 0usize;
        walk(
            &mut data.snapshot,
            &mut |sequence, event| {
                let reference: Reference =
                    serde_json::from_value(event.clone()).map_err(|_| Error::Configuration)?;
                if reference.schema_version != 1
                    || sequences.get(&reference.id) != Some(&sequence)
                    || data.canonical_sha256.get(&reference.id) != Some(&reference.sha256)
                {
                    return Err(Error::Conflict);
                }
                let row = inputs.get(&reference.id).ok_or(Error::Conflict)?;
                let body = encode(&row.event, self.config.max_event_bytes)?;
                if row.sequence != sequence
                    || <[u8; 32]>::from(Sha256::digest(&body)) != reference.sha256
                {
                    return Err(Error::Conflict);
                }
                if seen.insert(reference.id) {
                    bytes = bytes.checked_add(body.len()).ok_or(Error::Capacity)?;
                    if bytes > RETAINED_BYTES {
                        return Err(Error::Capacity);
                    }
                }
                *event = serde_json::to_value(&row.event).map_err(|_| Error::Configuration)?;
                Ok(())
            },
            context,
        )?;
        if seen.len() != sequences.len() {
            return Err(Error::Conflict);
        }
        let record = data
            .snapshot
            .get_mut("record")
            .ok_or(Error::Configuration)?;
        let compact = record
            .get_mut("state")
            .and_then(|s| s.get_mut("monitor"))
            .ok_or(Error::Configuration)?;
        let object = compact.as_object_mut().ok_or(Error::Configuration)?;
        let policy_hash = object.remove("policy_sha256").ok_or(Error::Configuration)?;
        if policy_hash
            != serde_json::to_value(self.verifier.policy_sha256())
                .map_err(|_| Error::Configuration)?
            || object.len() != 3
            || !object.contains_key("schema_version")
            || !object.contains_key("clock_ms")
            || !object.contains_key("slots")
        {
            return Err(Error::Conflict);
        }
        object.insert(
            "policy".into(),
            serde_json::to_value(&self.config.policy).map_err(|_| Error::Configuration)?,
        );
        let monitor = Monitor::restore(
            self.config.policy.clone(),
            &encode(compact, self.config.policy.max_state_bytes)?,
        )?;
        *compact = serde_json::to_value(monitor.snapshot()?).map_err(|_| Error::Configuration)?;
        let state: State =
            serde_json::from_value(record.get("state").ok_or(Error::Configuration)?.clone())
                .map_err(|_| Error::Configuration)?;
        let state = encode(&state, self.config.max_state_bytes)?;
        record["state"] = serde_json::to_value(state).map_err(|_| Error::Configuration)?;
        for output in array(record, "outbox")? {
            let pending: Pending =
                serde_json::from_value(output.get("bytes").ok_or(Error::Configuration)?.clone())
                    .map_err(|_| Error::Configuration)?;
            let payload = encode(&pending, self.config.max_output_bytes)?;
            output["bytes"] = serde_json::to_value(payload).map_err(|_| Error::Configuration)?;
        }
        let snapshot: Snapshot =
            serde_json::from_value(data.snapshot).map_err(|_| Error::Configuration)?;
        self.validate(&snapshot, context)?;
        check(context)?;
        Ok(snapshot)
    }
}

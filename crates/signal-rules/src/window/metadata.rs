//! Bounded control metadata; canonical payload custody stays in retained objects.
use super::{Error, Policy, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u16,
    state: Value,
    canonical_sha256: BTreeMap<Uuid, [u8; 32]>,
}
struct Size {
    bytes: usize,
    limit: usize,
}
impl std::io::Write for Size {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("window recovery byte capacity"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_digest(event: &SignalEvent) -> Result<[u8; 32], Error> {
    fn feed(value: &Value, hash: &mut Sha256) {
        match value {
            Value::Null => hash.update([0]),
            Value::Bool(value) => hash.update([1, u8::from(*value)]),
            Value::Number(value) => {
                hash.update([2]);
                let value = value.to_string();
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
            Value::String(value) => {
                hash.update([3]);
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
            Value::Array(values) => {
                hash.update([4]);
                hash.update((values.len() as u64).to_be_bytes());
                for value in values {
                    feed(value, hash);
                }
            }
            Value::Object(values) => {
                hash.update([5]);
                hash.update((values.len() as u64).to_be_bytes());
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort();
                for key in keys {
                    hash.update((key.len() as u64).to_be_bytes());
                    hash.update(key.as_bytes());
                    feed(&values[key], hash);
                }
            }
        }
    }
    let value = serde_json::to_value(event).map_err(|_| Error::Configuration)?;
    let mut hash = Sha256::new();
    hash.update(b"PLATFORM::SIGNAL/window-canonical-input/v1\0");
    feed(&value, &mut hash);
    Ok(hash.finalize().into())
}
fn wire(bytes: &[u8], policy: &Policy) -> Result<Envelope, Error> {
    policy.validate()?;
    if bytes.len() > 65536 {
        return Err(Error::Capacity);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    if envelope.schema_version != 1
        || serde_json::from_value::<Policy>(
            envelope
                .state
                .get("policy")
                .cloned()
                .ok_or(Error::Configuration)?,
        )
        .map_err(|_| Error::Configuration)?
            != *policy
    {
        return Err(Error::Conflict);
    }
    Ok(envelope)
}
fn references(envelope: &Envelope, policy: &Policy) -> Result<BTreeSet<Uuid>, Error> {
    let mut ids = BTreeSet::new();
    let attempts = envelope
        .state
        .get("attempts")
        .and_then(Value::as_array)
        .ok_or(Error::Configuration)?;
    let outputs = envelope
        .state
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or(Error::Configuration)?;
    if attempts.len() > policy.max_attempts || outputs.len() > policy.max_outputs {
        return Err(Error::Capacity);
    }
    for attempt in attempts {
        if attempt.get("event").is_some() {
            return Err(Error::Configuration);
        }
        let id: Uuid = serde_json::from_value(
            attempt
                .get("event_id")
                .cloned()
                .ok_or(Error::Configuration)?,
        )
        .map_err(|_| Error::Configuration)?;
        if id.is_nil() {
            return Err(Error::Configuration);
        }
        ids.insert(id);
    }
    for output in outputs {
        if output.get("evidence").is_some() {
            return Err(Error::Configuration);
        }
        let references: Vec<Uuid> = serde_json::from_value(
            output
                .get("event_ids")
                .cloned()
                .ok_or(Error::Configuration)?,
        )
        .map_err(|_| Error::Configuration)?;
        if references.len() > policy.max_attempts_per_key || references.iter().any(Uuid::is_nil) {
            return Err(Error::Configuration);
        }
        ids.extend(references);
    }
    if envelope
        .canonical_sha256
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != ids
    {
        return Err(Error::Conflict);
    }
    Ok(ids)
}
impl State {
    /// Metadata fits the control database's fixed64KiB item ceiling. The host
    /// retains/pins immutable object references for every required canonical ID.
    pub fn encode_metadata(&self, max_bytes: usize) -> Result<Vec<u8>, Error> {
        if !(256..=65536).contains(&max_bytes) {
            return Err(Error::Configuration);
        }
        self.validate(&self.policy)?;
        let mut canonical_sha256 = BTreeMap::new();
        for event in self
            .attempts
            .iter()
            .map(|a| &a.event)
            .chain(self.outputs.iter().flat_map(|a| a.canonical_events()))
        {
            let digest = canonical_digest(event)?;
            if canonical_sha256
                .insert(event.id, digest)
                .is_some_and(|old| old != digest)
            {
                return Err(Error::Conflict);
            }
        }
        let mut state = serde_json::to_value(self).map_err(|_| Error::Configuration)?;
        for attempt in state["attempts"]
            .as_array_mut()
            .ok_or(Error::Configuration)?
        {
            attempt
                .as_object_mut()
                .ok_or(Error::Configuration)?
                .remove("event");
        }
        for output in state["outputs"]
            .as_array_mut()
            .ok_or(Error::Configuration)?
        {
            output
                .as_object_mut()
                .ok_or(Error::Configuration)?
                .remove("evidence");
        }
        let bytes = serde_json::to_vec(&Envelope {
            schema_version: 1,
            state,
            canonical_sha256,
        })
        .map_err(|_| Error::Configuration)?;
        if bytes.len() > max_bytes {
            return Err(Error::Capacity);
        }
        Ok(bytes)
    }
    pub fn metadata_event_ids(bytes: &[u8], policy: &Policy) -> Result<Vec<Uuid>, Error> {
        Ok(references(&wire(bytes, policy)?, policy)?
            .into_iter()
            .collect())
    }
    /// Restore only with the exact complete retained canonical inputs. Missing
    /// evidence, conflicting IDs/content, changed policy or invalid state refuse.
    /// Metadata/checksums are not authentication or a publication permit.
    pub fn restore_metadata(
        bytes: &[u8],
        policy: &Policy,
        events: &[SignalEvent],
    ) -> Result<Self, Error> {
        let mut envelope = wire(bytes, policy)?;
        let ids = references(&envelope, policy)?;
        if events.len() != ids.len() {
            return Err(Error::Conflict);
        }
        let mut inputs = BTreeMap::new();
        let mut sizes = BTreeMap::new();
        for event in events {
            event.validate().map_err(|_| Error::Configuration)?;
            if !ids.contains(&event.id) || inputs.insert(event.id, event).is_some() {
                return Err(Error::Conflict);
            }
            let mut size = Size {
                bytes: 0,
                limit: policy.max_state_bytes,
            };
            serde_json::to_writer(&mut size, event).map_err(|_| Error::Capacity)?;
            if envelope.canonical_sha256.get(&event.id) != Some(&canonical_digest(event)?) {
                return Err(Error::Conflict);
            }
            sizes.insert(event.id, size.bytes);
        }
        // Charge every occurrence, including repeated assessment references,
        // before cloning canonical values into the hydrated state.
        let mut size = Size {
            bytes: 0,
            limit: policy.max_state_bytes,
        };
        serde_json::to_writer(&mut size, &envelope.state).map_err(|_| Error::Capacity)?;
        let mut budget = size.bytes;
        for attempt in envelope.state["attempts"]
            .as_array()
            .ok_or(Error::Configuration)?
        {
            let id: Uuid = serde_json::from_value(attempt["event_id"].clone())
                .map_err(|_| Error::Configuration)?;
            budget = budget
                .checked_add(*sizes.get(&id).ok_or(Error::Conflict)? + 9)
                .ok_or(Error::Capacity)?;
            if budget > policy.max_state_bytes {
                return Err(Error::Capacity);
            }
        }
        for output in envelope.state["outputs"]
            .as_array()
            .ok_or(Error::Configuration)?
        {
            let ids: Vec<Uuid> = serde_json::from_value(output["event_ids"].clone())
                .map_err(|_| Error::Configuration)?;
            budget = budget
                .checked_add(14 + ids.len().saturating_sub(1))
                .ok_or(Error::Capacity)?;
            if budget > policy.max_state_bytes {
                return Err(Error::Capacity);
            }
            for id in ids {
                budget = budget
                    .checked_add(*sizes.get(&id).ok_or(Error::Conflict)?)
                    .ok_or(Error::Capacity)?;
                if budget > policy.max_state_bytes {
                    return Err(Error::Capacity);
                }
            }
        }
        for attempt in envelope.state["attempts"]
            .as_array_mut()
            .ok_or(Error::Configuration)?
        {
            let id: Uuid = serde_json::from_value(attempt["event_id"].clone())
                .map_err(|_| Error::Configuration)?;
            let event = inputs.get(&id).ok_or(Error::Conflict)?;
            attempt["event"] = serde_json::to_value(event).map_err(|_| Error::Configuration)?;
        }
        for output in envelope.state["outputs"]
            .as_array_mut()
            .ok_or(Error::Configuration)?
        {
            let ids: Vec<Uuid> = serde_json::from_value(output["event_ids"].clone())
                .map_err(|_| Error::Configuration)?;
            let evidence = ids
                .iter()
                .map(|id| {
                    inputs.get(id).ok_or(Error::Conflict).and_then(|event| {
                        serde_json::to_value(event).map_err(|_| Error::Configuration)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            output["evidence"] = Value::Array(evidence);
        }
        let state: Self =
            serde_json::from_value(envelope.state).map_err(|_| Error::Configuration)?;
        state.validate(policy)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::window::durability_tests::{policy, state};
    #[test]
    fn metadata_omits_original_payload_and_restores_exact_state_with_retained_inputs() {
        let mut original = state();
        let mut event = original.attempts[0].event.clone();
        event.message = Some("retained-original-marker".repeat(100));
        event.attributes.insert(
            "private_payload_marker".into(),
            serde_json::json!({"nested":[1,true,"kept"]}),
        );
        original.attempts[0] = super::super::attempt(&event).unwrap();
        original.outputs[0].evidence[0] = event.clone();
        let bytes = original.encode_metadata(65536).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("retained-original-marker"));
        assert!(!text.contains("private_payload_marker"));
        assert!(bytes.len() < serde_json::to_vec(&original).unwrap().len());
        assert_eq!(
            State::metadata_event_ids(&bytes, &policy()).unwrap(),
            vec![event.id]
        );
        assert_eq!(
            State::restore_metadata(&bytes, &policy(), std::slice::from_ref(&event)).unwrap(),
            original
        );
        let later: chrono::DateTime<chrono::Utc> = "2026-10-14T12:00:02Z".parse().unwrap();
        original.seal(later, true).unwrap();
        assert!(original.attempts.is_empty());
        let bytes = original.encode_metadata(65536).unwrap();
        let mut changed = event.clone();
        changed.message = Some("substituted-after-ttl".into());
        assert!(matches!(
            State::restore_metadata(&bytes, &policy(), &[changed]),
            Err(Error::Conflict)
        ));
        assert_eq!(
            State::restore_metadata(&bytes, &policy(), &[event]).unwrap(),
            original
        );
    }
    #[test]
    fn metadata_recovery_refuses_missing_conflicting_embedded_revision_or_oversized_evidence() {
        let original = state();
        let bytes = original.encode_metadata(65536).unwrap();
        let event = original.attempts[0].event.clone();
        assert!(matches!(
            State::restore_metadata(&bytes, &policy(), &[]),
            Err(Error::Conflict)
        ));
        let mut changed = event.clone();
        changed.message = Some("changed".into());
        assert!(State::restore_metadata(&bytes, &policy(), &[changed]).is_err());
        let mut different = policy();
        different.revision = "other".into();
        assert!(State::restore_metadata(&bytes, &different, std::slice::from_ref(&event)).is_err());
        assert!(matches!(
            original.encode_metadata(256),
            Err(Error::Capacity)
        ));
        let mut embedded: Value = serde_json::from_slice(&bytes).unwrap();
        embedded["state"]["attempts"][0]["event"] = serde_json::to_value(&event).unwrap();
        assert!(
            State::restore_metadata(
                &serde_json::to_vec(&embedded).unwrap(),
                &policy(),
                std::slice::from_ref(&event)
            )
            .is_err()
        );
        let mut small = policy();
        small.max_state_bytes = 4096;
        let mut original = original;
        original.policy = small.clone();
        let metadata = original.encode_metadata(65536).unwrap();
        let mut large = event;
        large.message = Some("x".repeat(5000));
        assert!(matches!(
            State::restore_metadata(&metadata, &small, &[large]),
            Err(Error::Capacity)
        ));
    }
}

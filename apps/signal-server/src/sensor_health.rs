//! Verification seam for independently signed heartbeat observations.
//! The host enrolls keys and policy; neither signatures nor incoming telemetry
//! establish that the observer has independent failure visibility.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_rules::sensor_health::{Observation, Policy};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const DOMAIN: &[u8] = b"platform-signal/sensor-health-observer/v1\0";
pub const MAX_ENVELOPE_BYTES: usize = 8192;
pub const MAX_PAYLOAD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid sensor-health observer enrollment")]
    Configuration,
    #[error("sensor-health observer input capacity exceeded")]
    Capacity,
    #[error("invalid sensor-health observer envelope")]
    Envelope,
    #[error("sensor-health observer signature refused")]
    Signature,
    #[error("sensor-health observer policy or identity mismatch")]
    Scope,
    #[error("sensor-health observer evidence expired")]
    Expired,
    #[error(transparent)]
    Observation(#[from] signal_rules::sensor_health::Error),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverKey {
    pub schema_version: u16,
    pub observer_id: Uuid,
    pub public_key: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u16,
    observer_id: Uuid,
    payload_base64: String,
    signature_base64: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema_version: u16,
    policy_sha256: [u8; 32],
    observation: Observation,
}

/// Created only by successful verification. Original bytes must accompany the
/// assessment/state/outbox in the host's atomic commit. No Debug/Deserialize.
pub struct VerifiedObservation {
    observation: Observation,
    original_envelope: Vec<u8>,
    payload_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    enrollment_sha256: [u8; 32],
    valid_until_ms: i64,
}
impl VerifiedObservation {
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn original_envelope(&self) -> &[u8] {
        &self.original_envelope
    }
    pub fn payload_sha256(&self) -> [u8; 32] {
        self.payload_sha256
    }
    pub fn policy_sha256(&self) -> [u8; 32] {
        self.policy_sha256
    }
    pub fn enrollment_sha256(&self) -> [u8; 32] {
        self.enrollment_sha256
    }
    pub fn valid_until_ms(&self) -> i64 {
        self.valid_until_ms
    }
}

/// No worker, I/O, cached proof or refreshed verification clock. The embedding
/// host supplies a trusted current clock and uses this exact policy for Monitor.
pub struct Verifier {
    policy: Policy,
    fingerprint: [u8; 32],
    enrollment: [u8; 32],
    keys: BTreeMap<Uuid, [u8; 32]>,
}
impl Verifier {
    pub fn new(policy: Policy, keys: Vec<ObserverKey>) -> Result<Self, Error> {
        policy.validate()?;
        let observers: BTreeSet<_> = policy.expected.iter().map(|s| s.observer_id).collect();
        if keys.len() != observers.len() {
            return Err(Error::Configuration);
        }
        let mut pinned = BTreeMap::new();
        for key in keys {
            if key.schema_version != 1
                || key.public_key == [0; 32]
                || !observers.contains(&key.observer_id)
                || pinned.insert(key.observer_id, key.public_key).is_some()
            {
                return Err(Error::Configuration);
            }
        }
        // Policy is already structurally bounded to4096 finite-size sources.
        let bytes = serde_json::to_vec(&policy).map_err(|_| Error::Configuration)?;
        if bytes.len() > policy.max_state_bytes {
            return Err(Error::Capacity);
        }
        let fingerprint: [u8; 32] = Sha256::digest(bytes).into();
        let mut binding = Sha256::new();
        binding.update(b"platform-signal/sensor-health-enrollment/v1\0");
        binding.update(fingerprint);
        binding.update((pinned.len() as u64).to_be_bytes());
        for (id, key) in &pinned {
            binding.update(id.as_bytes());
            binding.update(key);
        }
        Ok(Self {
            policy,
            fingerprint,
            enrollment: binding.finalize().into(),
            keys: pinned,
        })
    }
    /// SHA256 of serde_json's compact Policy encoding, in validated source order.
    pub fn policy_sha256(&self) -> [u8; 32] {
        self.fingerprint
    }
    /// Pin this complete policy/key binding in durable state. Key rotation must
    /// not silently reauthorize snapshots admitted under an earlier enrollment.
    pub fn enrollment_sha256(&self) -> [u8; 32] {
        self.enrollment
    }
    pub fn verify(&self, bytes: &[u8], now_ms: i64) -> Result<VerifiedObservation, Error> {
        if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Capacity);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Envelope)?;
        if envelope.schema_version != 1
            || envelope.payload_base64.len() > MAX_PAYLOAD_BYTES.div_ceil(3) * 4
            || envelope.signature_base64.len() != 88
        {
            return Err(Error::Envelope);
        }
        let key = self.keys.get(&envelope.observer_id).ok_or(Error::Scope)?;
        let payload = STANDARD
            .decode(envelope.payload_base64)
            .map_err(|_| Error::Envelope)?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::Capacity);
        }
        let signature_bytes = STANDARD
            .decode(envelope.signature_base64)
            .map_err(|_| Error::Signature)?;
        if signature_bytes.len() != 64 {
            return Err(Error::Signature);
        }
        let mut signed = Vec::with_capacity(DOMAIN.len() + payload.len());
        signed.extend_from_slice(DOMAIN);
        signed.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(&signed, &signature_bytes)
            .map_err(|_| Error::Signature)?;
        let document: Payload = serde_json::from_slice(&payload).map_err(|_| Error::Envelope)?;
        if document.schema_version != 1
            || document.policy_sha256 != self.fingerprint
            || document.observation.observer_id != envelope.observer_id
        {
            return Err(Error::Scope);
        }
        let observation = document.observation;
        let index = self
            .policy
            .expected
            .binary_search_by_key(&observation.source_id, |s| s.source_id)
            .map_err(|_| Error::Scope)?;
        observation.validate(&self.policy.expected[index], now_ms)?;
        // Exactly the evaluator's half-open freshness interval. V1 has no
        // independent per-report expiry that could be lost during adaptation.
        let until = observation
            .observed_at_ms
            .checked_add(self.policy.observer_freshness_ms)
            .ok_or(Error::Configuration)?;
        if now_ms >= until {
            return Err(Error::Expired);
        }
        Ok(VerifiedObservation {
            observation,
            original_envelope: bytes.to_vec(),
            payload_sha256: Sha256::digest(&payload).into(),
            policy_sha256: self.fingerprint,
            enrollment_sha256: self.enrollment,
            valid_until_ms: until,
        })
    }
}

#[cfg(test)]
#[path = "sensor_health_tests.rs"]
mod tests;

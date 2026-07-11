//! Host-derived scope facts. Producer attributes never supply finding authority.
use crate::{Finding, FindingError};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;
use signal_protocol::{access::ScopeFacts, findings_feed::FindingsCursor};
use uuid::Uuid;

pub(crate) const KEY: &str = "signal.scope.v1";
pub(crate) const CONTROL_BYTES: usize = 144;
pub(crate) const CONTROL_INDEX_BYTES: usize = 256;
const FACT_BYTES: usize = 256;

/// Explicit host boundary: the host must prove native authenticated admission
/// before allowing a NEW row to carry scope. Replayed/unverified input uses false.
/// Fields are private; this type cannot deserialize caller-provided scope claims.
pub struct DerivedFinding {
    pub(crate) base: Finding,
    pub(crate) facts: Facts,
    pub(crate) authenticated_new: bool,
}
pub(crate) struct Facts {
    source: Option<Box<str>>,
    account: Option<Box<str>>,
    resource: Option<Box<str>>,
    digest: String,
}
impl DerivedFinding {
    pub fn from_event(
        base: Finding,
        event: &SignalEvent,
        authenticated_new: bool,
    ) -> Result<Self, FindingError> {
        // A derived finding has exactly the deterministic core for this event.
        // No arbitrary attributes/identity substitution reach the reserved key.
        let expected = Finding::for_event(&base.rule_id, event, base.severity, &base.title)?;
        if expected != base {
            return Err(FindingError::Invalid("derived finding/event binding"));
        }
        let facts = ScopeFacts::event(event);
        let values = [facts.source, facts.account, facts.resource];
        if values.iter().flatten().map(|s| s.len()).sum::<usize>() > 3 * 65_536 {
            return Err(FindingError::Invalid("canonical finding scope byte bound"));
        }
        // Full original identities still distinguish divergent replay when an
        // overlong selector fact is represented conservatively as unknown.
        let mut digest = Sha256::new();
        for value in values {
            digest.update([u8::from(value.is_some())]);
            let value = value.unwrap_or("");
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        fn bounded(value: Option<&str>) -> Option<Box<str>> {
            value.filter(|s| s.len() <= FACT_BYTES).map(Box::from)
        }
        Ok(Self {
            // Retain the bounded reconstruction, not caller spare allocation.
            base: expected,
            facts: Facts {
                source: bounded(facts.source),
                account: bounded(facts.account),
                resource: bounded(facts.resource),
                digest: digest
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            },
            authenticated_new,
        })
    }
    /// Worst-case encoded preview for the host's finite batching budget. This
    /// does not confer authority or contain the store's activation generation.
    pub fn budget_preview(&self) -> Finding {
        self.annotated(Uuid::nil())
    }
    pub(crate) fn annotated(&self, generation: Uuid) -> Finding {
        let mut finding = self.base.clone();
        let mut scope = Map::new();
        scope.insert("schema_version".into(), Value::from(1));
        scope.insert("generation".into(), Value::String(generation.to_string()));
        scope.insert(
            "binding_digest".into(),
            Value::String(self.facts.digest.clone()),
        );
        for (key, fact) in [
            ("source", &self.facts.source),
            ("account", &self.facts.account),
            ("resource", &self.facts.resource),
        ] {
            scope.insert(
                key.into(),
                fact.as_ref()
                    .map_or(Value::Null, |s| Value::String(s.to_string())),
            );
        }
        finding.attributes.insert(KEY.into(), Value::Object(scope));
        finding
    }
}

pub(crate) struct Boundary {
    pub generation: Uuid,
    pub cursor: FindingsCursor,
    pub bytes: u64,
    pub journal_digest: [u8; 32],
}
impl Boundary {
    pub fn encode(&self) -> [u8; CONTROL_BYTES] {
        let mut bytes = [0u8; CONTROL_BYTES];
        bytes[..8].copy_from_slice(b"SIGFSC01");
        bytes[8..24].copy_from_slice(self.generation.as_bytes());
        bytes[24..100].copy_from_slice(self.cursor.encode().as_bytes());
        bytes[100..108].copy_from_slice(&self.bytes.to_le_bytes());
        bytes[108..140].copy_from_slice(&self.journal_digest);
        let crc = crc32fast::hash(&bytes[..140]);
        bytes[140..].copy_from_slice(&crc.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, FindingError> {
        let invalid = || FindingError::Corrupt("finding scope control");
        if bytes.len() != CONTROL_BYTES
            || &bytes[..8] != b"SIGFSC01"
            || crc32fast::hash(&bytes[..140])
                != u32::from_le_bytes(bytes[140..].try_into().map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
        let generation = Uuid::from_slice(&bytes[8..24]).map_err(|_| invalid())?;
        if generation.is_nil() {
            return Err(invalid());
        }
        Ok(Self {
            generation,
            cursor: FindingsCursor::decode(
                std::str::from_utf8(&bytes[24..100]).map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?,
            bytes: u64::from_le_bytes(bytes[100..108].try_into().map_err(|_| invalid())?),
            journal_digest: bytes[108..140].try_into().map_err(|_| invalid())?,
        })
    }
    /// Only newly derived records in this verified generation have scope facts.
    /// Missing/malformed/old metadata cannot satisfy any restricted selector.
    pub fn facts<'a>(&self, finding: &'a Finding, offset: u64) -> ScopeFacts<'a> {
        let unknown = ScopeFacts {
            source: None,
            account: None,
            resource: None,
        };
        if offset <= self.bytes {
            return unknown;
        }
        let Some(Value::Object(scope)) = finding.attributes.get(KEY) else {
            return unknown;
        };
        if scope.len() != 6
            || scope.get("schema_version").and_then(Value::as_u64) != Some(1)
            || scope
                .get("generation")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                != Some(self.generation)
        {
            return unknown;
        }
        if scope
            .get("binding_digest")
            .and_then(Value::as_str)
            .is_none_or(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return unknown;
        }
        fn fact(value: Option<&Value>) -> Result<Option<&str>, ()> {
            match value {
                Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.trim().is_empty() && s.len() <= FACT_BYTES => {
                    Ok(Some(s))
                }
                _ => Err(()),
            }
        }
        match (
            fact(scope.get("source")),
            fact(scope.get("account")),
            fact(scope.get("resource")),
        ) {
            (Ok(source), Ok(account), Ok(resource)) => ScopeFacts {
                source,
                account,
                resource,
            },
            _ => unknown,
        }
    }
}

#[cfg(test)]
#[path = "scope/tests.rs"]
mod tests;

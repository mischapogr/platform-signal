//! Exact bounded metadata requests. Object verification/custody remain external.
use crate::{
    ControlError, FindingInput, ITEM_BYTES, ITEMS, MANIFEST_BYTES, REQUEST_BYTES, RevisionedState,
    Scope, WorkInput,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptInput {
    pub schema_version: u32,
    pub id: Uuid,
    pub prepared_count: u32,
    pub source_record_count: u32,
    /// Complete protected reference/disposition pins, never an ACK authorization.
    pub reference: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptProgress {
    pub id: Uuid,
    pub expected_prefix: u32,
    pub verified_prefix: u32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationInput {
    pub schema_version: u32,
    pub id: Uuid,
    pub previous: Option<Uuid>,
    pub first_sequence: u64,
    pub last_sequence: u64,
    /// Exact already-verified immutable QueryManifest bytes; this library does no uploads.
    pub manifest: Vec<u8>,
    pub rule_revision: [u8; 32],
    pub normalizer_revision: String,
    pub states: Vec<RevisionedState>,
    pub findings: Vec<FindingInput>,
    pub work: Vec<WorkInput>,
    pub receipts: Vec<ReceiptProgress>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationResult {
    pub schema_version: u32,
    pub id: Uuid,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub cursor: String,
    pub request_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptResult {
    pub schema_version: u32,
    pub id: Uuid,
    pub prepared_count: u32,
    pub source_record_count: u32,
    pub verified_prefix: u32,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}
struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > REQUEST_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("shared request capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(value: &impl Serialize) -> Result<Vec<u8>, ControlError> {
    let mut writer = BoundedWriter(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| ControlError::Full)?;
    Ok(writer.0.into_boxed_slice().into_vec())
}
impl ReceiptInput {
    pub(crate) fn wire(&self) -> Result<Vec<u8>, ControlError> {
        if self.schema_version != 1
            || self.id.is_nil()
            || self.prepared_count > 4096
            || self.source_record_count > 4096
            || self.reference.is_empty()
            || self.reference.len() > ITEM_BYTES
            || self.reference.capacity() > ITEM_BYTES
        {
            return Err(ControlError::Invalid);
        }
        encode(&serde_json::json!({"schema_version": 1, "id": self.id,
            "prepared_count": self.prepared_count, "source_record_count": self.source_record_count,
            "reference": hex(&self.reference)}))
    }
}
impl PublicationInput {
    /// Validate the complete bounded wire request without submitting a mutation.
    pub fn validate(&self, scope: &Scope) -> Result<(), ControlError> {
        self.wire(scope).map(drop)
    }
    pub(crate) fn wire(&self, scope: &Scope) -> Result<Vec<u8>, ControlError> {
        scope.validate()?;
        if self.schema_version != 1
            || self.id.is_nil()
            || self.previous.is_some_and(|id| id.is_nil())
            || self.first_sequence == 0
            || self.last_sequence < self.first_sequence
            || self.last_sequence > i64::MAX as u64
            || self.last_sequence - self.first_sequence >= 4096
            || self.manifest.is_empty()
            || self.manifest.len() > MANIFEST_BYTES
            || self.manifest.capacity() > MANIFEST_BYTES
            || self.normalizer_revision.is_empty()
            || self.normalizer_revision.len() > 128
            || self.normalizer_revision.capacity() > 128
            || self.normalizer_revision.chars().any(char::is_control)
            || self.states.len() > ITEMS
            || self.states.capacity() > ITEMS
            || self.findings.len() > ITEMS
            || self.findings.capacity() > ITEMS
            || self.work.len() > ITEMS
            || self.work.capacity() > ITEMS
            || self.receipts.len() > ITEMS
            || self.receipts.capacity() > ITEMS
        {
            return Err(ControlError::Invalid);
        }
        let manifest: signal_storage::object_manifest::QueryManifest =
            serde_json::from_slice(&self.manifest).map_err(|_| ControlError::Invalid)?;
        manifest
            .validate(
                signal_storage::object_manifest::ManifestLimits {
                    manifest_bytes: MANIFEST_BYTES,
                    events: 4096,
                    ..Default::default()
                },
                scope.stream,
            )
            .map_err(|_| ControlError::Invalid)?;
        if manifest.files.iter().any(|f| f.object.version.is_none())
            || manifest
                .previous
                .as_ref()
                .is_some_and(|p| p.object.version.is_none())
            || manifest.files.len() + usize::from(manifest.previous.is_some()) > ITEMS
        {
            return Err(ControlError::Invalid);
        }
        if manifest.first_sequence != self.first_sequence
            || manifest.last_sequence != self.last_sequence
            || manifest.events as u64 != self.last_sequence - self.first_sequence + 1
            || manifest.normalizer_revision != self.normalizer_revision
            || manifest.previous.is_some() != self.previous.is_some()
        {
            return Err(ControlError::Invalid);
        }
        let mut bytes = self.manifest.len();
        let mut keys = BTreeSet::new();
        for state in &self.states {
            state.validate()?;
            if !keys.insert(&state.key) || state.revision != self.rule_revision {
                return Err(ControlError::Invalid);
            }
            bytes += state.key.len() + state.bytes.len();
        }
        let mut ids = BTreeSet::new();
        for finding in &self.findings {
            finding.validate()?;
            if !ids.insert(finding.id) {
                return Err(ControlError::Invalid);
            }
            bytes += finding.bytes.len();
        }
        ids.clear();
        for work in &self.work {
            work.validate()?;
            if !ids.insert(work.id) {
                return Err(ControlError::Invalid);
            }
            bytes += work.bytes.len();
        }
        ids.clear();
        let mut advanced = 0_u64;
        for receipt in &self.receipts {
            if receipt.id.is_nil()
                || !ids.insert(receipt.id)
                || receipt.verified_prefix > 4096
                || receipt.verified_prefix <= receipt.expected_prefix
            {
                return Err(ControlError::Invalid);
            }
            advanced += u64::from(receipt.verified_prefix - receipt.expected_prefix);
        }
        if !self.receipts.is_empty() && advanced != self.last_sequence - self.first_sequence + 1 {
            return Err(ControlError::Invalid);
        }
        // Hex encoding doubles payload size; reject aggregate allocations before conversion.
        if bytes > REQUEST_BYTES / 2 {
            return Err(ControlError::Full);
        }
        encode(
            &serde_json::json!({"schema_version":1,"id":self.id,"previous":self.previous,
            "first_sequence":self.first_sequence,"last_sequence":self.last_sequence,"manifest":hex(&self.manifest),
            "rule_revision":hex(&self.rule_revision),"normalizer_revision":self.normalizer_revision,
            "states":self.states.iter().map(|s|serde_json::json!({"key":s.key,"revision":hex(&s.revision),"bytes":hex(&s.bytes)})).collect::<Vec<_>>(),
            "findings":self.findings.iter().map(|f|serde_json::json!({"id":f.id,"bytes":hex(&f.bytes)})).collect::<Vec<_>>(),
            "work":self.work.iter().map(|w|serde_json::json!({"id":w.id,"finding_id":w.finding_id,"bytes":hex(&w.bytes)})).collect::<Vec<_>>(),
            "receipts":self.receipts}),
        )
    }
}
pub(crate) fn request_digest(raw: &[u8]) -> String {
    hex(&Sha256::digest(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};

    fn fixture() -> Result<(Scope, PublicationInput), Box<dyn std::error::Error>> {
        let scope = Scope {
            schema_version: 1,
            store_id: Uuid::from_u128(1),
            generation: Uuid::from_u128(2),
            tenant: "synthetic".into(),
            stream: Uuid::from_u128(3),
            partition_id: Uuid::from_u128(4),
        };
        let manifest = QueryManifest {
            schema_version: 1,
            storage_schema_version: 1,
            stream_id: scope.stream,
            normalizer_revision: "synthetic-v1".into(),
            first_sequence: 1,
            last_sequence: 1,
            events: 1,
            previous: None,
            files: vec![QueryFile {
                date: "2026-10-10".into(),
                hour: 0,
                object: QueryObjectRef {
                    key: data_key(scope.stream, "2026-10-10", 0, [1; 32]),
                    version: Some("synthetic-v1".into()),
                    etag: None,
                    bytes: 128,
                    sha256: [1; 32],
                },
                rows: 1,
                decoded_bytes: 256,
            }],
        };
        let request = PublicationInput {
            schema_version: 1,
            id: Uuid::from_u128(10),
            previous: None,
            first_sequence: 1,
            last_sequence: 1,
            manifest: serde_json::to_vec(&manifest)?,
            rule_revision: [1; 32],
            normalizer_revision: "synthetic-v1".into(),
            states: vec![],
            findings: vec![],
            work: vec![],
            receipts: vec![],
        };
        Ok((scope, request))
    }
    fn scoped_fixture() -> Result<
        (crate::ProducerEnrollment, crate::ScopedPublicationInput),
        Box<dyn std::error::Error>,
    > {
        let (scope, base) = fixture()?;
        let producer = crate::ProducerEnrollment {
            scope,
            scope_generation: Uuid::from_u128(42),
            startup: Uuid::from_u128(43),
            wal_floor: 0,
        };
        let event = scoped_event()?;
        let finding = signal_findings::Finding::for_event(
            "fixture",
            &event,
            signal_findings::DetectionSeverity::High,
            "Fixture",
        )?;
        let sealed = signal_findings::DerivedFinding::from_event(finding, &event, true)?
            .into_scoped(producer.scope_generation)?;
        let input = crate::ScopedPublicationInput::from_host(base, &producer, vec![(1, sealed)])?;
        Ok((producer, input))
    }
    fn scoped_event() -> Result<signal_event::SignalEvent, serde_json::Error> {
        serde_json::from_value(
            serde_json::json!({"schema_version":1,"id":Uuid::from_u128(44),"timestamp":"2026-10-11T00:00:00Z","observed_at":"2026-10-11T00:00:00Z","source":{"type":"audit"},"message":"synthetic","severity":"info","attributes":{"account":"spoof"},"resource":{"kind":"host","id":"fixture","account_id":"canonical"},"tags":[]}),
        )
    }
    #[test]
    fn preupload_claims_preserve_original_startup_floor_and_exact_publication_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (producer, expected) = scoped_fixture()?;
        let event = scoped_event()?;
        let finding = signal_findings::Finding::for_event(
            "fixture",
            &event,
            signal_findings::DetectionSeverity::High,
            "Fixture",
        )?;
        let sealed = signal_findings::DerivedFinding::from_event(finding, &event, true)?
            .into_scoped(producer.scope_generation)?;
        let original = crate::ScopedFindingClaims::from_host(&producer, vec![(1, sealed)])?;
        let bytes = serde_json::to_vec(&original)?;
        let retained: crate::ScopedFindingClaims = serde_json::from_slice(&bytes)?;
        assert!(retained == original);
        let rows = vec![signal_storage::StoredEvent { sequence: 1, event }];
        retained.verify_rows(&rows)?;
        let (_, base) = fixture()?;
        let attached = retained.attach(base)?;
        assert_eq!(
            serde_json::to_vec(&attached)?,
            serde_json::to_vec(&expected)?
        );
        attached.verify_rows(&rows)?;
        // Idempotent attachment retains the exact already present payload.
        let duplicate = original.clone().attach(expected.publication().clone())?;
        assert_eq!(
            serde_json::to_vec(&duplicate)?,
            serde_json::to_vec(&expected)?
        );
        let mut divergent = expected.publication().clone();
        divergent.findings[0].bytes.push(b' ');
        assert!(matches!(
            original.attach(divergent),
            Err(ControlError::Conflict)
        ));
        Ok(())
    }
    #[test]
    fn retained_claims_reject_canonical_wal_substitution_without_renewing_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let (producer, input) = scoped_fixture()?;
        let before = serde_json::to_vec(&input)?;
        let row = signal_storage::StoredEvent {
            sequence: 1,
            event: scoped_event()?,
        };
        input.verify_rows(std::slice::from_ref(&row))?;
        for field in [
            "id",
            "sequence",
            "source",
            "account",
            "resource",
            "observed_at",
        ] {
            let mut changed = serde_json::to_value(&row.event)?;
            match field {
                "id" => changed["id"] = serde_json::json!(Uuid::from_u128(45)),
                "source" => changed["source"]["type"] = serde_json::json!("other"),
                "account" => changed["resource"]["account_id"] = serde_json::json!("other"),
                "resource" => changed["resource"]["id"] = serde_json::json!("other"),
                "observed_at" => changed["observed_at"] = serde_json::json!("2026-10-11T00:00:01Z"),
                _ => {}
            }
            let replaced = signal_storage::StoredEvent {
                sequence: if field == "sequence" { 2 } else { 1 },
                event: serde_json::from_value(changed)?,
            };
            assert!(
                matches!(input.verify_rows(&[replaced]), Err(ControlError::Corrupt)),
                "{field}"
            );
            assert_eq!(serde_json::to_vec(&input)?, before);
        }
        let mut foreign = producer.scope;
        foreign.generation = Uuid::from_u128(46);
        assert!(matches!(
            input.validate(&foreign),
            Err(ControlError::Fenced)
        ));
        assert_eq!(serde_json::to_vec(&input)?, before);
        Ok(())
    }
    #[test]
    fn scoped_original_claims_roundtrip_and_foreign_scope_fail_before_transport()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut producer, input) = scoped_fixture()?;
        let retained = serde_json::to_vec(&input)?;
        let decoded: crate::ScopedPublicationInput = serde_json::from_slice(&retained)?;
        assert!(decoded == input);
        assert_eq!(decoded.wire(&producer.scope)?, input.wire(&producer.scope)?);
        producer.scope.generation = Uuid::new_v4();
        assert!(matches!(
            decoded.wire(&producer.scope),
            Err(ControlError::Fenced)
        ));
        Ok(())
    }
    #[test]
    fn scoped_retained_claim_substitution_or_floor_replay_cannot_rebind_original_finding()
    -> Result<(), Box<dyn std::error::Error>> {
        let (producer, input) = scoped_fixture()?;
        for (key, value) in [
            ("account", serde_json::json!("spoof")),
            ("sequence", serde_json::json!(0)),
            ("binding_digest", serde_json::json!("0".repeat(64))),
        ] {
            let mut artifact = serde_json::to_value(&input)?;
            artifact["claims"]["findings"][0][key] = value;
            let corrupted: crate::ScopedPublicationInput = serde_json::from_value(artifact)?;
            assert!(matches!(
                corrupted.wire(&producer.scope),
                Err(ControlError::Invalid)
            ));
        }
        Ok(())
    }
    #[test]
    fn immutable_wire_preserves_bytes_and_rejects_foreign_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut scope, request) = fixture()?;
        let raw = request.wire(&scope)?;
        assert_eq!(raw, request.wire(&scope)?);
        let value: serde_json::Value = serde_json::from_slice(&raw)?;
        assert_eq!(value["manifest"], hex(&request.manifest));
        assert_eq!(request_digest(&raw), hex(&Sha256::digest(&raw)));
        scope.stream = Uuid::from_u128(8);
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        Ok(())
    }
    #[test]
    fn sparse_allocations_and_signed_sequence_overflow_fail_before_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let (scope, mut request) = fixture()?;
        request.states = Vec::with_capacity(ITEMS + 1);
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        request.states = vec![];
        request.last_sequence = i64::MAX as u64 + 1;
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        Ok(())
    }
    #[test]
    fn revision_and_duplicate_state_keys_fail_before_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let (scope, mut request) = fixture()?;
        let state = RevisionedState {
            key: "state".into(),
            revision: [2; 32],
            bytes: vec![1],
        };
        request.states.push(state);
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        request.states[0].revision = [1; 32];
        request.states.push(request.states[0].clone());
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        Ok(())
    }
    #[test]
    fn receipt_prefixes_must_account_for_exact_prepared_span()
    -> Result<(), Box<dyn std::error::Error>> {
        let (scope, mut request) = fixture()?;
        request.receipts.push(ReceiptProgress {
            id: Uuid::from_u128(20),
            expected_prefix: 0,
            verified_prefix: 2,
        });
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        request.receipts[0].verified_prefix = 1;
        assert!(request.wire(&scope).is_ok());
        request.receipts[0].expected_prefix = 1;
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        Ok(())
    }
    #[test]
    fn shared_publication_requires_exact_version_even_when_etag_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        let (scope, mut request) = fixture()?;
        let mut manifest: signal_storage::object_manifest::QueryManifest =
            serde_json::from_slice(&request.manifest)?;
        manifest.files[0].object.version = None;
        manifest.files[0].object.etag = Some("synthetic-conditional-etag".into());
        request.manifest = serde_json::to_vec(&manifest)?;
        assert!(matches!(request.wire(&scope), Err(ControlError::Invalid)));
        Ok(())
    }
    #[test]
    fn zero_prepared_receipt_requires_explicit_bounded_reference() {
        let mut receipt = ReceiptInput {
            schema_version: 1,
            id: Uuid::from_u128(20),
            prepared_count: 0,
            source_record_count: 1,
            reference: vec![],
        };
        assert!(matches!(receipt.wire(), Err(ControlError::Invalid)));
        receipt.reference = b"original-and-disposition-pins".to_vec();
        assert!(receipt.wire().is_ok());
        receipt.reference = Vec::with_capacity(ITEM_BYTES + 1);
        receipt.reference.push(1);
        assert!(matches!(receipt.wire(), Err(ControlError::Invalid)));
    }
    #[test]
    fn aggregate_encoding_cannot_overrun_queue_byte_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut writer = BoundedWriter(vec![0; REQUEST_BYTES - 1]);
        assert!(writer.write_all(&[1, 2]).is_err());
        assert_eq!(writer.0.len(), REQUEST_BYTES - 1);
        writer.write_all(&[1])?;
        assert_eq!(writer.0.len(), REQUEST_BYTES);
        Ok(())
    }
}

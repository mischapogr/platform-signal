//! Bounded private TLS material envelope; parsing is not certificate verification.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use thiserror::Error;

pub const TLS_DOCUMENT_BYTES: usize = 512 * 1024;

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
#[error("invalid bounded private TLS configuration")]
pub struct TlsMaterialError;

// No Debug/Serialize: this document contains a private key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u16,
    certificate_chain_der_base64: Vec<String>,
    private_key_der_base64: String,
    peer_roots_der_base64: Vec<String>,
    #[serde(default)]
    peer_crls_der_base64: Vec<String>,
}

/// Public mechanisms only. The operator supplies private roots, identity and CRLs.
/// Rustls must separately verify DER, key correspondence, signatures and peers.
pub struct TlsMaterial {
    pub certificate_chain_der: Vec<Vec<u8>>,
    pub private_key_der: Vec<u8>,
    pub peer_roots_der: Vec<Vec<u8>>,
    pub peer_crls_der: Vec<Vec<u8>>,
}
impl TlsMaterial {
    pub fn from_private_json(bytes: &[u8]) -> Result<Self, TlsMaterialError> {
        if bytes.is_empty()
            || bytes.len() > TLS_DOCUMENT_BYTES
            || bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
        {
            return Err(TlsMaterialError);
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| TlsMaterialError)?;
        if wire.schema_version != 1 {
            return Err(TlsMaterialError);
        }
        fn decode(value: String, capacity: usize) -> Result<Vec<u8>, TlsMaterialError> {
            if value.is_empty() || value.len() > capacity.div_ceil(3) * 4 {
                return Err(TlsMaterialError);
            }
            let bytes = STANDARD.decode(value).map_err(|_| TlsMaterialError)?;
            if bytes.is_empty() || bytes.len() > capacity {
                return Err(TlsMaterialError);
            }
            Ok(bytes)
        }
        fn many(
            values: Vec<String>,
            capacity: usize,
            total: usize,
            required: bool,
        ) -> Result<Vec<Vec<u8>>, TlsMaterialError> {
            if values.len() > 8 || (required && values.is_empty()) {
                return Err(TlsMaterialError);
            }
            let mut decoded = Vec::with_capacity(values.len());
            let mut used = 0usize;
            for value in values {
                let bytes = decode(value, capacity)?;
                used = used.checked_add(bytes.len()).ok_or(TlsMaterialError)?;
                if used > total || decoded.contains(&bytes) {
                    return Err(TlsMaterialError);
                }
                decoded.push(bytes);
            }
            Ok(decoded)
        }
        Ok(Self {
            certificate_chain_der: many(wire.certificate_chain_der_base64, 16_384, 65_536, true)?,
            private_key_der: decode(wire.private_key_der_base64, 16_384)?,
            peer_roots_der: many(wire.peer_roots_der_base64, 16_384, 65_536, true)?,
            peer_crls_der: many(wire.peer_crls_der_base64, 65_536, 131_072, false)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"certificate_chain_der_base64":["AQ=="],
            "private_key_der_base64":"Ag==","peer_roots_der_base64":["Aw=="]})
    }
    #[test]
    fn malformed_unknown_duplicate_null_empty_and_oversized_documents_deny() {
        let original = valid();
        assert!(TlsMaterial::from_private_json(original.to_string().as_bytes()).is_ok());
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("extra", serde_json::json!("synthetic-secret")),
            ("private_key_der_base64", serde_json::json!(null)),
            ("private_key_der_base64", serde_json::json!("?")),
            ("certificate_chain_der_base64", serde_json::json!([])),
            ("peer_roots_der_base64", serde_json::json!(["Aw==", "Aw=="])),
        ] {
            let mut wire = original.clone();
            wire[field] = value;
            assert!(
                TlsMaterial::from_private_json(wire.to_string().as_bytes()).is_err(),
                "{field}"
            );
        }
        assert!(
            TlsMaterial::from_private_json(br#"{"schema_version":1,"schema_version":1}"#).is_err()
        );
        assert!(TlsMaterial::from_private_json(&vec![b' '; TLS_DOCUMENT_BYTES + 1]).is_err());
        assert_eq!(
            TlsMaterialError.to_string(),
            "invalid bounded private TLS configuration"
        );
    }
}

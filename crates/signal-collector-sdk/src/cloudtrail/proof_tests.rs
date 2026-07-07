#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use flate2::{Compression, write::GzEncoder};
use ring::{rand::SystemRandom, rsa::KeyPair};
use serde_json::json;
use std::{io::Write, time::Duration};
use tokio_util::sync::CancellationToken;

const PRIVATE: &[u8] = include_bytes!("../../tests/proof-fixtures/synthetic-pkcs8.der");
const PUBLIC: &[u8] = include_bytes!("../../tests/proof-fixtures/synthetic-public.der");
const NATIVE: &[u8] = include_bytes!("../../tests/proof-fixtures/openssl-digest.json");
const GZIP: &[u8] = include_bytes!("../../tests/proof-fixtures/openssl-digest.json.gz");
const OPENSSL_SIGNATURE: &[u8] = include_bytes!("../../tests/proof-fixtures/openssl-signature.bin");
const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef";

fn context() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(30)).unwrap()
}
fn time(value: &str) -> DateTime<Utc> {
    native_time(value).unwrap()
}
fn scope() -> ProofScope {
    ProofScope::new(
        "synthetic-evidence",
        "444455556666",
        "111122223333",
        "eu-central-1",
        "eu-west-1",
        "synthetic_trail",
        "AWSLogs/111122223333",
    )
    .unwrap()
}
fn keys() -> Vec<TrustedRegionalKey> {
    vec![
        TrustedRegionalKey::new(
            "eu-central-1",
            FINGERPRINT,
            PUBLIC,
            time("2026-01-01T00:00:00Z"),
            time("2027-01-01T00:00:00Z"),
        )
        .unwrap(),
    ]
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(bytes).unwrap();
    gzip.finish().unwrap()
}
fn sign(bytes: &[u8]) -> String {
    let key = KeyPair::from_pkcs8(PRIVATE).unwrap();
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        bytes,
        &mut signature,
    )
    .unwrap();
    encode_hex(&signature)
}
fn digest_value() -> Value {
    serde_json::from_slice(NATIVE).unwrap()
}
fn signed(value: &Value, backfill: Option<DateTime<Utc>>) -> Result<ValidatedDigest, ProofError> {
    let raw = serde_json::to_vec(value).unwrap();
    signed_raw(value, &raw, backfill)
}
fn signed_raw(
    value: &Value,
    raw: &[u8],
    backfill: Option<DateTime<Utc>>,
) -> Result<ValidatedDigest, ProofError> {
    let previous = value["previousDigestSignature"].as_str().unwrap_or("null");
    let message = format!(
        "{}\n{}/{}\n{}\n{}",
        value["digestEndTime"].as_str().unwrap(),
        value["digestS3Bucket"].as_str().unwrap(),
        value["digestS3Object"].as_str().unwrap(),
        encode_hex(&Sha256::digest(raw)),
        previous
    );
    let signature = sign(message.as_bytes());
    let capture = CapturedObject::new(
        "synthetic-evidence",
        value["digestS3Object"].as_str().unwrap(),
        "version-1",
        "444455556666",
    )
    .unwrap();
    validate_digest(
        &scope(),
        &capture,
        &gzip(raw),
        &DigestMetadata {
            signature_hex: &signature,
            signature_algorithm: "SHA256withRSA",
            backfill_generated_at: backfill,
        },
        &keys(),
        &context(),
    )
}
fn delivery(value: &Value) -> ValidatedDelivery {
    validate_delivery(signed(value, None).unwrap(), &[], &context()).unwrap()
}
fn following(prior: &ValidatedDelivery, start: &str, end: &str) -> Value {
    let mut value = digest_value();
    value["digestStartTime"] = json!(start);
    value["digestEndTime"] = json!(end);
    value["digestS3Object"] = json!(scope().digest_key(time(end), false));
    value["previousDigestS3Bucket"] = json!(prior.digest.capture.bucket);
    value["previousDigestS3Object"] = json!(prior.digest.capture.key);
    value["previousDigestHashValue"] = json!(encode_hex(&prior.digest.hash));
    value["previousDigestHashAlgorithm"] = json!("SHA-256");
    value["previousDigestSignature"] = json!(prior.digest.signature);
    value
}
fn log_value(bytes: &[u8], key_suffix: &str) -> Value {
    json!({"s3Bucket":"synthetic-evidence", "s3Object":format!("AWSLogs/111122223333/CloudTrail/eu-central-1/2026/07/09/{key_suffix}.json.gz"), "hashValue":encode_hex(&Sha256::digest(bytes)), "hashAlgorithm":"SHA-256", "oldestEventTime":"2026-07-09T17:00:00Z", "newestEventTime":"2026-07-09T18:59:59Z"})
}
fn with_logs(logs: Vec<Value>) -> Value {
    let mut value = digest_value();
    value["logFiles"] = json!(logs);
    value["oldestEventTime"] = json!("2026-07-09T17:00:00Z");
    value["newestEventTime"] = json!("2026-07-09T18:59:59Z");
    value
}

#[test]
fn independent_openssl_native_signature_preserves_exact_bytes_and_distinct_hashes() {
    let value = digest_value();
    let capture = CapturedObject::new(
        "synthetic-evidence",
        value["digestS3Object"].as_str().unwrap(),
        "pinned-version",
        "444455556666",
    )
    .unwrap();
    let signature = encode_hex(OPENSSL_SIGNATURE);
    let metadata = DigestMetadata {
        signature_hex: &signature,
        signature_algorithm: "SHA256withRSA",
        backfill_generated_at: None,
    };
    let digest = validate_digest(&scope(), &capture, GZIP, &metadata, &keys(), &context()).unwrap();
    assert_eq!(
        digest.uncompressed_sha256(),
        &<[u8; 32]>::from(Sha256::digest(NATIVE))
    );
    assert_eq!(
        digest.compressed_sha256(),
        &<[u8; 32]>::from(Sha256::digest(GZIP))
    );
    assert_ne!(digest.uncompressed_sha256(), digest.compressed_sha256());
    assert_eq!(digest.capture().version(), "pinned-version");
    let projected = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            &gzip(&projected),
            &metadata,
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Signature)
    );
    let complete = validate_delivery(digest, &[], &context()).unwrap();
    assert_eq!(
        validate_chain(None, &[&complete], &context())
            .unwrap()
            .classification(),
        ChainClassification::Bootstrap
    );
}

#[test]
fn digest_signature_key_algorithm_location_and_owner_fail_closed() {
    let value = digest_value();
    let capture = CapturedObject::new(
        "synthetic-evidence",
        value["digestS3Object"].as_str().unwrap(),
        "version",
        "444455556666",
    )
    .unwrap();
    let signature = encode_hex(OPENSSL_SIGNATURE);
    let metadata = DigestMetadata {
        signature_hex: &signature,
        signature_algorithm: "SHA256withRSA",
        backfill_generated_at: None,
    };
    let wrong_owner =
        CapturedObject::new(capture.bucket(), capture.key(), "version", "777788889999").unwrap();
    assert_eq!(
        validate_digest(&scope(), &wrong_owner, GZIP, &metadata, &keys(), &context()).err(),
        Some(ProofError::Scope)
    );
    let wrong_location = CapturedObject::new(
        capture.bucket(),
        &capture.key().replace("synthetic_trail", "other-trail"),
        "version",
        capture.owner(),
    )
    .unwrap();
    assert_eq!(
        validate_digest(
            &scope(),
            &wrong_location,
            GZIP,
            &metadata,
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Scope)
    );
    let wrong_keys = vec![
        TrustedRegionalKey::new(
            "eu-west-1",
            FINGERPRINT,
            PUBLIC,
            time("2026-01-01T00:00:00Z"),
            time("2027-01-01T00:00:00Z"),
        )
        .unwrap(),
    ];
    assert_eq!(
        validate_digest(&scope(), &capture, GZIP, &metadata, &wrong_keys, &context()).err(),
        Some(ProofError::Key)
    );
    let expired_keys = vec![
        TrustedRegionalKey::new(
            "eu-central-1",
            FINGERPRINT,
            PUBLIC,
            time("2026-01-01T00:00:00Z"),
            time("2026-02-01T00:00:00Z"),
        )
        .unwrap(),
    ];
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            GZIP,
            &metadata,
            &expired_keys,
            &context()
        )
        .err(),
        Some(ProofError::Key)
    );
    let mut ambiguous = keys();
    ambiguous.extend(keys());
    assert_eq!(
        validate_digest(&scope(), &capture, GZIP, &metadata, &ambiguous, &context()).err(),
        Some(ProofError::Key)
    );
    let wrong_signature = "00".repeat(256);
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            GZIP,
            &DigestMetadata {
                signature_hex: &wrong_signature,
                ..metadata
            },
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Signature)
    );
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            GZIP,
            &DigestMetadata {
                signature_algorithm: "SHA1withRSA",
                ..metadata
            },
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Unsupported)
    );
}

#[test]
fn authenticated_native_body_shape_scope_and_algorithms_are_checked() {
    for (field, changed, expected) in [
        ("awsAccountId", json!("777788889999"), ProofError::Scope),
        (
            "digestSignatureAlgorithm",
            json!("SHA1withRSA"),
            ProofError::Unsupported,
        ),
        (
            "digestStartTime",
            json!("2026-07-09T20:00:00Z"),
            ProofError::Malformed,
        ),
        (
            "digestPublicKeyFingerprint",
            json!("not-a-fingerprint"),
            ProofError::Malformed,
        ),
        (
            "newestEventTime",
            json!("2026-07-09T18:00:00Z"),
            ProofError::Malformed,
        ),
        (
            "previousDigestSignature",
            json!("00".repeat(256)),
            ProofError::Malformed,
        ),
    ] {
        let mut value = digest_value();
        value[field] = changed;
        assert_eq!(signed(&value, None).err(), Some(expected), "{field}");
    }
    let value = digest_value();
    let mut raw = serde_json::to_vec(&value).unwrap();
    raw.pop();
    raw.extend_from_slice(b",\"logFiles\":[]}");
    assert_eq!(
        signed_raw(&value, &raw, None).err(),
        Some(ProofError::Malformed)
    );
    let mut value = digest_value();
    value
        .as_object_mut()
        .unwrap()
        .remove("previousDigestHashValue");
    assert_eq!(signed(&value, None).err(), Some(ProofError::Malformed));
}

#[test]
fn source_log_hashing_requires_every_exact_capture_but_not_json_projection() {
    // Authenticated vendor bytes can still fail a later normalization parser.
    let native = b"  deliberately not supported normalized JSON  ";
    let compressed = gzip(native);
    let row = log_value(native, "synthetic-log");
    let value = with_logs(vec![row.clone()]);
    let object = CapturedObject::new(
        "synthetic-evidence",
        row["s3Object"].as_str().unwrap(),
        "log-version",
        "444455556666",
    )
    .unwrap();
    let capture = LogCapture {
        object: &object,
        compressed: &compressed,
    };
    let complete =
        validate_delivery(signed(&value, None).unwrap(), &[capture], &context()).unwrap();
    assert_eq!(complete.logs()[0].capture().version(), "log-version");
    assert_eq!(
        complete.logs()[0].uncompressed_sha256(),
        &<[u8; 32]>::from(Sha256::digest(native))
    );
    assert_ne!(
        complete.logs()[0].compressed_sha256(),
        complete.logs()[0].uncompressed_sha256()
    );
    assert_eq!(
        validate_delivery(signed(&value, None).unwrap(), &[], &context()).err(),
        Some(ProofError::Content)
    );
    assert_eq!(
        validate_delivery(
            signed(&value, None).unwrap(),
            &[LogCapture {
                object: &object,
                compressed: &gzip(b"changed")
            }],
            &context()
        )
        .err(),
        Some(ProofError::Content)
    );
    let wrong = CapturedObject::new(
        object.bucket(),
        object.key(),
        object.version(),
        "777788889999",
    )
    .unwrap();
    assert_eq!(
        validate_delivery(
            signed(&value, None).unwrap(),
            &[LogCapture {
                object: &wrong,
                compressed: &compressed
            }],
            &context()
        )
        .err(),
        Some(ProofError::Scope)
    );
}

#[test]
fn duplicate_unscoped_and_unsupported_log_references_fail_before_publication() {
    let row = log_value(b"log", "synthetic-log");
    assert_eq!(
        signed(&with_logs(vec![row.clone(), row.clone()]), None).err(),
        Some(ProofError::Malformed)
    );
    let mut wrong = row.clone();
    wrong["s3Object"] = json!("AWSLogs/777788889999/CloudTrail/eu-central-1/log.json.gz");
    assert_eq!(
        signed(&with_logs(vec![wrong]), None).err(),
        Some(ProofError::Scope)
    );
    let mut wrong = row.clone();
    wrong["hashAlgorithm"] = json!("MD5");
    assert_eq!(
        signed(&with_logs(vec![wrong]), None).err(),
        Some(ProofError::Unsupported)
    );
    let rows = (0..MAX_LOG_FILES + 1)
        .map(|n| log_value(b"log", &format!("log-{n}")))
        .collect();
    assert_eq!(
        signed(&with_logs(rows), None).err(),
        Some(ProofError::Limit)
    );
    let row2 = log_value(b"log", "other-log");
    let value = with_logs(vec![row.clone(), row2]);
    let compressed = gzip(b"log");
    let object = CapturedObject::new(
        "synthetic-evidence",
        row["s3Object"].as_str().unwrap(),
        "version",
        "444455556666",
    )
    .unwrap();
    assert_eq!(
        validate_delivery(
            signed(&value, None).unwrap(),
            &[
                LogCapture {
                    object: &object,
                    compressed: &compressed
                },
                LogCapture {
                    object: &object,
                    compressed: &compressed
                }
            ],
            &context()
        )
        .err(),
        Some(ProofError::Scope)
    );
}

#[test]
fn authenticated_chain_requires_anchor_exact_links_and_contiguous_intervals() {
    let first = delivery(&digest_value());
    let second_value = following(&first, "2026-07-09T19:00:00Z", "2026-07-09T20:00:00Z");
    let second = delivery(&second_value);
    assert_eq!(
        validate_chain(None, &[&second], &context())
            .unwrap()
            .classification(),
        ChainClassification::Unanchored
    );
    let anchor = first.checkpoint();
    let bytes = anchor.to_bytes().unwrap();
    let restored = DeliveryCheckpoint::from_trusted_bytes(&bytes).unwrap();
    assert_eq!(anchor, restored);
    let evidence = validate_chain(Some(&restored), &[&second], &context()).unwrap();
    assert_eq!(
        evidence.classification(),
        ChainClassification::AnchoredContinuous
    );
    assert_eq!(
        evidence.interval(),
        (time("2026-07-09T19:00:00Z"), time("2026-07-09T20:00:00Z"))
    );
    assert_eq!(
        evidence.checkpoint().unwrap().end(),
        time("2026-07-09T20:00:00Z")
    );
    assert_eq!(
        validate_chain(None, &[&first, &second], &context())
            .unwrap()
            .classification(),
        ChainClassification::Bootstrap
    );
    assert_eq!(
        validate_chain(Some(&anchor), &[&first], &context()).err(),
        Some(ProofError::Link)
    );
    assert_eq!(
        validate_chain(None, &[&second, &first], &context()).err(),
        Some(ProofError::Link)
    );
    for field in [
        "previousDigestS3Object",
        "previousDigestHashValue",
        "previousDigestSignature",
    ] {
        let mut changed = second_value.clone();
        changed[field] = match field {
            "previousDigestS3Object" => json!("AWSLogs/111122223333/different.json.gz"),
            "previousDigestHashValue" => json!("00".repeat(32)),
            _ => json!("00".repeat(256)),
        };
        let bad = delivery(&changed);
        assert_eq!(
            validate_chain(Some(&anchor), &[&bad], &context()).err(),
            Some(ProofError::Link),
            "{field}"
        );
    }
    let skipped = delivery(&following(
        &second,
        "2026-07-09T20:00:00Z",
        "2026-07-09T21:00:00Z",
    ));
    assert_eq!(
        validate_chain(Some(&anchor), &[&skipped], &context()).err(),
        Some(ProofError::Link)
    );
}

#[test]
fn temporal_gap_and_backfill_never_establish_regular_continuity() {
    let first = delivery(&digest_value());
    let anchor = first.checkpoint();
    let gap = delivery(&following(
        &first,
        "2026-07-09T19:30:00Z",
        "2026-07-09T20:30:00Z",
    ));
    let third = delivery(&following(
        &gap,
        "2026-07-09T20:30:00Z",
        "2026-07-09T21:30:00Z",
    ));
    assert_eq!(
        validate_chain(Some(&anchor), &[&gap, &third], &context())
            .unwrap()
            .classification(),
        ChainClassification::TemporalGap
    );
    let mut backfill = digest_value();
    backfill["digestS3Object"] = json!(scope().digest_key(time("2026-07-09T19:00:00Z"), true));
    assert_eq!(signed(&backfill, None).err(), Some(ProofError::Scope));
    assert_eq!(
        signed(&backfill, Some(time("2026-07-09T18:00:00Z"))).err(),
        Some(ProofError::Malformed)
    );
    let proof = signed(&backfill, Some(time("2026-07-10T00:00:00Z"))).unwrap();
    let proof = validate_delivery(proof, &[], &context()).unwrap();
    let evidence = validate_chain(Some(&anchor), &[&proof], &context()).unwrap();
    assert_eq!(evidence.classification(), ChainClassification::BackfillOnly);
    assert!(evidence.checkpoint().is_none());
    assert_eq!(
        validate_chain(Some(&proof.checkpoint()), &[&gap], &context()).err(),
        Some(ProofError::Scope)
    );
    assert_eq!(
        validate_chain(None, &[&first, &proof], &context()).err(),
        Some(ProofError::Unsupported)
    );
}

#[test]
fn backfill_selects_key_by_generation_time_not_original_delivery_end() {
    let mut value = digest_value();
    value["digestS3Object"] = json!(scope().digest_key(time("2026-07-09T19:00:00Z"), true));
    let raw = serde_json::to_vec(&value).unwrap();
    let message = format!(
        "2026-07-09T19:00:00Z\nsynthetic-evidence/{}\n{}\nnull",
        value["digestS3Object"].as_str().unwrap(),
        encode_hex(&Sha256::digest(&raw))
    );
    let signature = sign(message.as_bytes());
    let object = CapturedObject::new(
        "synthetic-evidence",
        value["digestS3Object"].as_str().unwrap(),
        "version",
        "444455556666",
    )
    .unwrap();
    let generated = time("2026-07-10T00:00:00.125Z");
    let metadata = DigestMetadata {
        signature_hex: &signature,
        signature_algorithm: "SHA256withRSA",
        backfill_generated_at: Some(generated),
    };
    let applicable = vec![
        TrustedRegionalKey::new(
            "eu-central-1",
            FINGERPRINT,
            PUBLIC,
            time("2026-07-09T23:00:00Z"),
            time("2026-07-10T01:00:00Z"),
        )
        .unwrap(),
    ];
    assert!(
        validate_digest(
            &scope(),
            &object,
            &gzip(&raw),
            &metadata,
            &applicable,
            &context()
        )
        .is_ok()
    );
    let old = vec![
        TrustedRegionalKey::new(
            "eu-central-1",
            FINGERPRINT,
            PUBLIC,
            time("2026-07-09T18:00:00Z"),
            time("2026-07-09T20:00:00Z"),
        )
        .unwrap(),
    ];
    assert_eq!(
        validate_digest(&scope(), &object, &gzip(&raw), &metadata, &old, &context()).err(),
        Some(ProofError::Key)
    );
}

#[test]
fn trusted_regional_key_response_is_bounded_strict_and_never_truncated() {
    let response = json!({"PublicKeyList":[{"Fingerprint":FINGERPRINT,"Value":STANDARD.encode(PUBLIC),"ValidityStartTime":time("2026-01-01T00:00:00Z").timestamp(),"ValidityEndTime":time("2027-01-01T00:00:00Z").timestamp()}]});
    let bytes = serde_json::to_vec(&response).unwrap();
    let keys = trusted_keys_from_response("eu-central-1", &bytes, &context()).unwrap();
    assert_eq!(keys.len(), 1);
    let mut paged = response.clone();
    paged["NextToken"] = json!("unsupported-continuation");
    assert_eq!(
        trusted_keys_from_response(
            "eu-central-1",
            &serde_json::to_vec(&paged).unwrap(),
            &context()
        )
        .err(),
        Some(ProofError::Unsupported)
    );
    let mut duplicate = response.clone();
    duplicate["PublicKeyList"]
        .as_array_mut()
        .unwrap()
        .push(response["PublicKeyList"][0].clone());
    assert_eq!(
        trusted_keys_from_response(
            "eu-central-1",
            &serde_json::to_vec(&duplicate).unwrap(),
            &context()
        )
        .err(),
        Some(ProofError::Key)
    );
    let mut many = response.clone();
    many["PublicKeyList"] = json!(vec![response["PublicKeyList"][0].clone(); MAX_KEYS + 1]);
    assert_eq!(
        trusted_keys_from_response(
            "eu-central-1",
            &serde_json::to_vec(&many).unwrap(),
            &context()
        )
        .err(),
        Some(ProofError::Limit)
    );
    assert_eq!(
        trusted_keys_from_response(
            "eu-central-1",
            &vec![b' '; MAX_KEY_RESPONSE_BYTES + 1],
            &context()
        )
        .err(),
        Some(ProofError::Malformed)
    );
    assert_eq!(
        epoch(&serde_json::from_str("1700000000.125").unwrap())
            .unwrap()
            .timestamp_subsec_nanos(),
        125_000_000
    );
    assert_eq!(
        epoch(&serde_json::from_str("1700000000.0").unwrap())
            .unwrap()
            .timestamp_subsec_nanos(),
        0
    );
    assert_eq!(
        epoch(&serde_json::from_str("1700000000.0000000001").unwrap()).err(),
        Some(ProofError::Unsupported)
    );
    assert_eq!(
        trusted_keys_from_response(
            "eu-central-1",
            b"{\"PublicKeyList\":[],\"PublicKeyList\":[]}",
            &context()
        )
        .err(),
        Some(ProofError::Malformed)
    );
}

#[test]
fn malformed_compression_and_finite_resource_budgets_fail_closed() {
    let value = digest_value();
    let signature = encode_hex(OPENSSL_SIGNATURE);
    let capture = CapturedObject::new(
        "synthetic-evidence",
        value["digestS3Object"].as_str().unwrap(),
        "version",
        "444455556666",
    )
    .unwrap();
    let metadata = DigestMetadata {
        signature_hex: &signature,
        signature_algorithm: "SHA256withRSA",
        backfill_generated_at: None,
    };
    let mut corrupt = GZIP.to_vec();
    let n = corrupt.len();
    corrupt[n - 5] ^= 1;
    for bytes in [&GZIP[..GZIP.len() - 3], corrupt.as_slice(), b"not gzip"] {
        assert_eq!(
            validate_digest(&scope(), &capture, bytes, &metadata, &keys(), &context()).err(),
            Some(ProofError::Compression)
        );
    }
    let mut trailing = GZIP.to_vec();
    trailing.extend_from_slice(GZIP);
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            &trailing,
            &metadata,
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Compression)
    );
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            &vec![0; MAX_DIGEST_BYTES + 1],
            &metadata,
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Limit)
    );
    assert_eq!(
        validate_digest(
            &scope(),
            &capture,
            &gzip(&vec![b' '; MAX_DIGEST_BYTES + 1]),
            &metadata,
            &keys(),
            &context()
        )
        .err(),
        Some(ProofError::Limit)
    );
    let complete = delivery(&value);
    assert_eq!(
        validate_chain(None, &vec![&complete; MAX_CHAIN_LENGTH + 1], &context()).err(),
        Some(ProofError::Limit)
    );
    assert_eq!(
        DeliveryCheckpoint::from_trusted_bytes(&vec![b' '; 8193]).err(),
        Some(ProofError::Malformed)
    );
    assert_eq!(
        CapturedObject::new("synthetic-evidence", capture.key(), "null", "444455556666").err(),
        Some(ProofError::Configuration)
    );
}

#[test]
fn streaming_log_limits_include_complete_delivery_aggregate_budget() {
    let oversized = vec![b'x'; MAX_LOG_DECODED_BYTES + 1];
    let compressed = gzip(&oversized);
    let row = log_value(&oversized, "too-large");
    let value = with_logs(vec![row.clone()]);
    let object = CapturedObject::new(
        "synthetic-evidence",
        row["s3Object"].as_str().unwrap(),
        "version",
        "444455556666",
    )
    .unwrap();
    assert_eq!(
        validate_delivery(
            signed(&value, None).unwrap(),
            &[LogCapture {
                object: &object,
                compressed: &compressed
            }],
            &context()
        )
        .err(),
        Some(ProofError::Limit)
    );
    let native = &oversized[..MAX_LOG_DECODED_BYTES];
    let compressed = gzip(native);
    let first_row = log_value(native, "first");
    let second_row = log_value(native, "second");
    let first = CapturedObject::new(
        "synthetic-evidence",
        first_row["s3Object"].as_str().unwrap(),
        "one",
        "444455556666",
    )
    .unwrap();
    let second = CapturedObject::new(
        "synthetic-evidence",
        second_row["s3Object"].as_str().unwrap(),
        "two",
        "444455556666",
    )
    .unwrap();
    let value = with_logs(vec![first_row, second_row]);
    assert_eq!(
        validate_delivery(
            signed(&value, None).unwrap(),
            &[
                LogCapture {
                    object: &first,
                    compressed: &compressed
                },
                LogCapture {
                    object: &second,
                    compressed: &compressed
                }
            ],
            &context()
        )
        .err(),
        Some(ProofError::Limit)
    );
}

#[tokio::test]
async fn ready_cancel_and_expired_deadline_prevent_proof_work() {
    let ctx = context();
    ctx.cancellation().cancel();
    assert_eq!(
        trusted_keys_from_response("eu-central-1", b"malformed", &ctx).err(),
        Some(ProofError::Cancelled)
    );
    let value = digest_value();
    let signature = encode_hex(OPENSSL_SIGNATURE);
    let capture = CapturedObject::new(
        "synthetic-evidence",
        value["digestS3Object"].as_str().unwrap(),
        "version",
        "444455556666",
    )
    .unwrap();
    let metadata = DigestMetadata {
        signature_hex: &signature,
        signature_algorithm: "SHA256withRSA",
        backfill_generated_at: None,
    };
    assert_eq!(
        validate_digest(&scope(), &capture, GZIP, &metadata, &keys(), &ctx).err(),
        Some(ProofError::Cancelled)
    );
    let expired =
        ExtensionContext::new(CancellationToken::new(), Duration::from_millis(1)).unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(
        validate_digest(&scope(), &capture, GZIP, &metadata, &keys(), &expired).err(),
        Some(ProofError::Timeout)
    );
}

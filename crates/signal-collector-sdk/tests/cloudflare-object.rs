#![allow(clippy::unwrap_used, clippy::expect_used)]
use chrono::{DateTime, Utc};
use flate2::{Compression, write::GzEncoder};
use signal_collector_sdk::{ExtensionContext, cloudflare::*, source_object::DecodeError};
use std::{io::Write, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
fn ctx() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(10)).unwrap()
}
fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut g = GzEncoder::new(Vec::new(), Compression::fast());
    g.write_all(raw).unwrap();
    g.finish().unwrap()
}
fn profile() -> HttpRequestsProfile {
    HttpRequestsProfile::new("fixture", &"a".repeat(32), &"b".repeat(32), 500_000, true).unwrap()
}
fn row(status: u16) -> serde_json::Value {
    serde_json::json!({"RayID":"synthetic-ray", "EdgeStartTimestamp":"2026-10-14T12:00:00+02:00",
        "ClientIP":"2001:db8::1", "ClientRequestMethod":"GET", "EdgeResponseStatus":status})
}
fn time() -> DateTime<Utc> {
    "2026-10-14T12:30:00Z".parse().unwrap()
}
fn prepare(raw: &[u8]) -> Result<PreparedObject, Error> {
    prepare_object(&gzip(raw), &profile(), Uuid::from_u128(1), time(), &ctx())
}
#[test]
fn configured_scope_coverage_and_byte_identical_pinned_replay() {
    let raw = format!("{}\r\n{}", row(200), row(503));
    let original = gzip(raw.as_bytes());
    let first = prepare_object(&original, &profile(), Uuid::from_u128(1), time(), &ctx()).unwrap();
    let replay = prepare_object(&original, &profile(), Uuid::from_u128(1), time(), &ctx()).unwrap();
    assert_eq!(first.original().record_count(), 2);
    assert_eq!(
        first.original().record(0).unwrap(),
        row(200).to_string().as_bytes()
    );
    assert_eq!(
        serde_json::to_vec(first.events()).unwrap(),
        serde_json::to_vec(replay.events()).unwrap()
    );
    assert_ne!(first.events()[0].id, first.events()[1].id);
    let v = serde_json::to_value(&first.events()[0]).unwrap();
    assert_eq!(v["resource"]["account_id"], "a".repeat(32));
    assert_eq!(v["resource"]["id"], "b".repeat(32));
    assert_eq!(v["attributes"]["coverage"]["completeness"], "not_assessed");
    assert_eq!(v["attributes"]["coverage"]["sample_rate_ppm"], 500_000);
    assert_eq!(v["attributes"]["coverage"]["filtered"], true);
    assert_eq!(v["timestamp"], "2026-10-14T10:00:00Z");
    assert_eq!(v["severity"], "info");
    assert_eq!(
        serde_json::to_value(&first.events()[1]).unwrap()["severity"],
        "error"
    );
    let changed =
        prepare_object(&original, &profile(), Uuid::from_u128(2), time(), &ctx()).unwrap();
    assert_ne!(first.events()[0].id, changed.events()[0].id);
}
#[test]
fn selected_schema_refuses_extra_sensitive_or_scope_fields_and_bad_values() {
    for key in [
        "ZoneID",
        "AccountID",
        "ClientRequestURI",
        "Cookies",
        "RequestHeaders",
    ] {
        let mut v = row(200);
        v[key] = serde_json::json!("secret");
        assert!(prepare(v.to_string().as_bytes()).is_err());
    }
    for (key, value) in [
        ("ClientIP", serde_json::json!("bad")),
        ("ClientRequestMethod", serde_json::json!("GET\n")),
        ("EdgeResponseStatus", serde_json::json!(600)),
        ("EdgeResponseStatus", serde_json::json!(true)),
        ("EdgeStartTimestamp", serde_json::json!(123)),
        ("RayID", serde_json::json!("")),
    ] {
        let mut v = row(200);
        v[key] = value;
        assert!(prepare(v.to_string().as_bytes()).is_err());
    }
    assert!(prepare(row(0).to_string().as_bytes()).is_ok());
    assert!(prepare(row(401).to_string().as_bytes()).is_ok());
}
#[test]
fn late_malformed_or_semantically_invalid_rows_poison_whole_object() {
    for tail in ["{", "[]", "{\"x\":1,\"x\":2}", "{}", ""] {
        let raw = format!("{}\n{tail}\n", row(200));
        assert!(prepare(raw.as_bytes()).is_err());
    }
    assert!(prepare(b"").is_err());
    let raw = format!("{}\n", row(200)).repeat(MAX_RECORDS + 1);
    assert!(matches!(prepare(raw.as_bytes()), Err(Error::Limits)));
    assert!(matches!(
        prepare(&vec![b' '; MAX_RECORD_BYTES + 1]),
        Err(Error::Limits)
    ));
}
#[test]
fn complete_gzip_crc_trailing_members_and_original_deadline_are_required() {
    let compressed = gzip(row(200).to_string().as_bytes());
    for end in [1, compressed.len() - 1, compressed.len() - 8] {
        assert!(matches!(
            read_object(&compressed[..end], &ctx()),
            Err(Error::Decode(DecodeError::InvalidCompression))
        ));
    }
    let mut bad = compressed.clone();
    let i = bad.len() - 8;
    bad[i] ^= 1;
    assert!(read_object(&bad, &ctx()).is_err());
    let mut bad = compressed.clone();
    bad.extend_from_slice(&compressed);
    assert!(read_object(&bad, &ctx()).is_err());
    let token = CancellationToken::new();
    token.cancel();
    let cancelled = ExtensionContext::new(token, Duration::from_secs(1)).unwrap();
    assert!(matches!(
        read_object(&compressed, &cancelled),
        Err(Error::Decode(DecodeError::Cancelled))
    ));
    let expired =
        ExtensionContext::new(CancellationToken::new(), Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    assert!(matches!(
        read_object(&compressed, &expired),
        Err(Error::Decode(DecodeError::Timeout))
    ));
    assert!(matches!(
        read_object(&vec![0; 8 * 1024 * 1024 + 1], &ctx()),
        Err(Error::Decode(DecodeError::CaptureLimit))
    ));
    let bomb = gzip(&vec![b' '; 32 * 1024 * 1024 + 1]);
    assert!(matches!(
        read_object(&bomb, &ctx()),
        Err(Error::Decode(DecodeError::DecodedLimit))
    ));
}

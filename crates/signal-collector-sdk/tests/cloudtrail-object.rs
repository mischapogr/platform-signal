#![allow(clippy::unwrap_used, clippy::expect_used)]
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use signal_collector_sdk::{
    ExtensionContext,
    cloudtrail::{ObjectReadError as E, read_object},
};
use std::{io::Write, time::Duration};
use tokio_util::sync::CancellationToken;
fn ctx() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5)).unwrap()
}
fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut out = GzEncoder::new(Vec::new(), Compression::fast());
    out.write_all(raw).unwrap();
    out.finish().unwrap()
}
#[test]
fn exact_spans_original_hash_and_escaped_strings_survive_object_validation() {
    let raw=b" { \"Rec\\u006frds\" : [  {\"a\":\"comma, bracket] escape\\\" quote\",\"n\":1e-2} ,\n{\"k\":true} ] } \n";
    let compressed = gzip(raw);
    let object = read_object(&compressed, &ctx()).unwrap();
    assert_eq!(object.record_count(), 2);
    assert_eq!(object.decoded_length(), raw.len());
    assert_eq!(
        *object.original_sha256(),
        <[u8; 32]>::from(Sha256::digest(&compressed))
    );
    for i in 0..2 {
        assert_eq!(object.record(i).unwrap(), &raw[object.span(i).unwrap()]);
    }
    assert_eq!(object.record(1).unwrap(), b"{\"k\":true}");
    assert!(object.record(2).is_none());
    assert!(object.span(usize::MAX).is_none());
}
#[test]
fn all_native_fixture_records_are_validated_before_exposure() {
    let fixtures: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/cloudtrail-source/contract.json"
    ))
    .unwrap();
    let records = fixtures["native_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["raw_utf8"].as_str().unwrap())
        .collect::<Vec<_>>();
    let raw = format!("{{\"Records\":[{}]}}", records.join(","));
    let object = read_object(&gzip(raw.as_bytes()), &ctx()).unwrap();
    assert_eq!(object.record_count(), 41);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(object.record(i).unwrap(), r.as_bytes());
    }
}
#[test]
fn corrupt_truncated_concatenated_or_trailing_gzip_is_never_a_success() {
    let compressed = gzip(b"{\"Records\":[{}]}");
    for end in [1, 7, compressed.len() - 1, compressed.len() - 8] {
        assert!(matches!(
            read_object(&compressed[..end], &ctx()),
            Err(E::InvalidCompression)
        ));
    }
    for offset in [0, 2, compressed.len() - 8, compressed.len() - 4] {
        let mut changed = compressed.clone();
        changed[offset] ^= 1;
        assert!(matches!(
            read_object(&changed, &ctx()),
            Err(E::InvalidCompression)
        ));
    }
    let mut changed = compressed.clone();
    changed.extend_from_slice(b"garbage");
    assert!(matches!(
        read_object(&changed, &ctx()),
        Err(E::InvalidCompression)
    ));
    let mut changed = compressed.clone();
    changed.extend_from_slice(&compressed);
    assert!(matches!(
        read_object(&changed, &ctx()),
        Err(E::InvalidCompression)
    ));
}
#[test]
fn malformed_late_records_duplicate_keys_and_outer_inputs_never_expose_a_prefix() {
    for raw in [
        b"{\"Records\":[{}, {\"x\":1,\"x\":2}]}".as_slice(),
        b"{\"Records\":[{}, {\"x\":1,\"\\u0078\":2}]}",
        b"{\"Records\":[{},NaN]}",
        b"{\"Records\":[{},1e999]}",
        b"{\"Records\":[{},\"\\ud800\"]}",
        b"{\"Records\":[{},]}",
        b"{\"Records\":[{}],\"Records\":[{}]}",
        b"{\"Records\":[{}]}{}",
        b"{\"Records\":{}}",
        b"{\"Records\":[{]}",
        b"{\"Records\":[{},\"\xff\"]}",
    ] {
        assert!(read_object(&gzip(raw), &ctx()).is_err(), "{:?}", raw);
    }
    assert!(matches!(
        read_object(&gzip(b"{\"Records\":[]}"), &ctx()),
        Err(E::EmptyRecords)
    ));
    assert!(matches!(
        read_object(&gzip(b"{\"Message\":\"foreign notification\"}"), &ctx()),
        Err(E::UnsupportedObject)
    ));
}
#[test]
fn record_count_depth_nodes_and_byte_limits_are_finite() {
    for count in [1024, 1025] {
        let raw = format!("{{\"Records\":[{}]}}", vec!["{}"; count].join(","));
        let result = read_object(&gzip(raw.as_bytes()), &ctx());
        assert_eq!(result.is_ok(), count == 1024);
    }
    for depth in [14, 15] {
        let raw = format!(
            "{{\"Records\":[{}0{}]}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert_eq!(
            read_object(&gzip(raw.as_bytes()), &ctx()).is_ok(),
            depth == 14
        );
    }
    let raw = format!("{{\"Records\":[[{}]]}}", vec!["0"; 16384].join(","));
    assert!(matches!(
        read_object(&gzip(raw.as_bytes()), &ctx()),
        Err(E::ObjectLimitsExceeded)
    ));
    for bytes in [256 * 1024, 256 * 1024 + 1] {
        let record = format!("\"{}\"", "x".repeat(bytes - 2));
        let raw = format!("{{\"Records\":[{record}]}}");
        assert_eq!(
            read_object(&gzip(raw.as_bytes()), &ctx()).is_ok(),
            bytes == 256 * 1024
        );
    }
}
#[test]
fn compressed_and_decoded_bomb_limits_and_context_are_checked() {
    assert!(matches!(read_object(&[], &ctx()), Err(E::CaptureLimit)));
    assert!(matches!(
        read_object(&vec![0; 8 * 1024 * 1024 + 1], &ctx()),
        Err(E::CaptureLimit)
    ));
    let compressed = gzip(&vec![b' '; 32 * 1024 * 1024 + 1]);
    // This is a structural size assertion, not a debug-build throughput gate.
    // The adjacent exact-ceiling case uses the same finite 30-second budget;
    // cancellation and expired contexts remain independently asserted below.
    let structural =
        ExtensionContext::new(CancellationToken::new(), Duration::from_secs(30)).unwrap();
    let result = read_object(&compressed, &structural);
    assert!(
        matches!(result, Err(E::ObjectLimitsExceeded)),
        "unexpected structural-limit result: {:?}",
        result.err()
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ExtensionContext::new(cancellation, Duration::from_secs(5)).unwrap();
    assert!(matches!(
        read_object(&gzip(b"{\"Records\":[{}]}"), &cancelled),
        Err(E::Cancelled)
    ));
    let expired =
        ExtensionContext::new(CancellationToken::new(), Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    assert!(matches!(
        read_object(&gzip(b"{\"Records\":[{}]}"), &expired),
        Err(E::Timeout)
    ));
}

#[test]
fn exact_decoded_ceiling_and_valid_gzip_text_flag_are_accepted() {
    let mut raw = b"{\"Records\":[{}]}".to_vec();
    raw.resize(32 * 1024 * 1024, b' ');
    let compressed = gzip(&raw);
    let object = read_object(
        &compressed,
        &ExtensionContext::new(CancellationToken::new(), Duration::from_secs(30)).unwrap(),
    )
    .unwrap();
    assert_eq!(object.decoded_length(), 32 * 1024 * 1024);
    assert_eq!(object.record_count(), 1);
    let mut compressed = gzip(b"{\"Records\":[{}]}");
    compressed[3] |= 1;
    assert!(read_object(&compressed, &ctx()).is_ok());
    compressed[3] |= 0x80;
    assert!(matches!(
        read_object(&compressed, &ctx()),
        Err(E::InvalidCompression)
    ));
}

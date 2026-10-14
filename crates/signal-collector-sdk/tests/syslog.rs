#![allow(clippy::unwrap_used, clippy::expect_used)]
use signal_collector_sdk::syslog::*;
use signal_event::Source;
use uuid::Uuid;
fn source() -> Source {
    Source {
        source_type: "syslog".into(),
        name: Some("configured-site".into()),
    }
}
fn raw(level: &str) -> String {
    format!(
        "<134>devid=fixture-device eventtime=1791972000123456789 logid=0100032001 type=event subtype=system level={level} msg=\"quoted words\""
    )
}
#[test]
fn split_octet_counts_exact_utf8_embedded_newlines_and_coalesced_frames() {
    let body = "é\nmessage".as_bytes();
    let wire = format!("{} ", body.len())
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .chain(b"1 x".iter().copied())
        .collect::<Vec<_>>();
    for cut in 0..wire.len() - 3 {
        let mut decoder = OctetDecoder::default();
        let (n, first) = decoder.push(&wire[..cut]).unwrap();
        assert_eq!(n, cut);
        assert!(first.is_none());
        let (n, first) = decoder.push(&wire[cut..]).unwrap();
        assert_eq!(first.unwrap(), body);
        let (_, last) = decoder.push(&wire[cut + n..]).unwrap();
        assert_eq!(last.unwrap(), b"x");
        assert_eq!(decoder.buffered_bytes(), 0);
        decoder.finish().unwrap();
    }
}
#[test]
fn malformed_lengths_and_incomplete_eof_poison_stream_without_resync() {
    for bad in [
        b"0 ".as_slice(),
        b"01 x",
        b"65537 ",
        b"999999",
        b"<134>",
        b"1x",
        b"-1 ",
    ] {
        let mut d = OctetDecoder::default();
        assert!(d.push(bad).is_err());
        assert!(d.push(b"1 x").is_err());
        assert!(d.finish().is_err());
    }
    for truncated in [b"1".as_slice(), b"1 ", b"2 x"] {
        let mut d = OctetDecoder::default();
        assert!(d.push(truncated).unwrap().1.is_none());
        assert!(d.finish().is_err());
    }
    let mut d = OctetDecoder::default();
    let body = vec![b'x'; MAX_FRAME_BYTES];
    d.push(b"65536 ").unwrap();
    assert_eq!(d.push(&body).unwrap().1.unwrap().len(), MAX_FRAME_BYTES);
    assert_eq!(d.capacity_bytes(), MAX_FRAME_BYTES + 5);
}
#[test]
fn severity_source_time_and_native_assertion_are_distinct_from_authority() {
    let observed = "2026-10-14T12:30:00Z".parse().unwrap();
    let id = Uuid::from_u128(1);
    for (level, expected) in [
        ("emergency", "critical"),
        ("alert", "critical"),
        ("critical", "critical"),
        ("error", "error"),
        ("warning", "warn"),
        ("notice", "info"),
        ("information", "info"),
        ("debug", "debug"),
    ] {
        let event = normalize_fortigate_ns(raw(level).as_bytes(), source(), id, observed).unwrap();
        assert_eq!(event.id, id);
        assert_eq!(event.timestamp.timestamp_subsec_nanos(), 123456789);
        assert_eq!(event.observed_at, observed);
        assert_eq!(event.source.name.as_deref(), Some("configured-site"));
        let v = serde_json::to_value(event).unwrap();
        assert_eq!(v["severity"], expected);
        assert_eq!(v["attributes"]["fortigate"]["msg"], "quoted words");
        assert_eq!(
            v["attributes"]["syslog"]["identity_basis"],
            "native_assertion"
        );
        assert_eq!(v["attributes"]["coverage"]["completeness"], "not_assessed");
    }
}
#[test]
fn malformed_duplicate_sensitive_and_unsupported_records_are_refused() {
    let observed = "2026-10-14T12:30:00Z".parse().unwrap();
    for raw in [
        raw("bogus"),
        raw("notice") + " password=secret",
        raw("notice") + " devid=conflict",
        raw("notice") + " x=\"unclosed",
        raw("notice").replace("1791972000123456789", "-1"),
        raw("notice").replace("<134>", "<192>"),
        raw("notice") + " x=\"bad\\nescape\"",
    ] {
        assert!(
            normalize_fortigate_ns(raw.as_bytes(), source(), Uuid::from_u128(1), observed).is_err()
        );
    }
    assert!(
        normalize_fortigate_ns(raw("notice").as_bytes(), source(), Uuid::nil(), observed).is_err()
    );
    assert!(
        normalize_fortigate_ns(
            &vec![b'x'; MAX_FRAME_BYTES + 1],
            source(),
            Uuid::from_u128(1),
            observed
        )
        .is_err()
    );
}

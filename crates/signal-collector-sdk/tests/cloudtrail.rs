// Unwraps assert successes on owned synthetic inputs, never production paths.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_collector_sdk::cloudtrail::{
    CloudTrailProfile, Disposition, MAX_EVENT_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES,
    MAX_RECORD_BYTES, NormalizeError as E, PreparationIdentity, Reason, normalize_record,
};
use signal_event::SignalEvent;
use std::sync::OnceLock;
use uuid::Uuid;

fn fixtures() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/cloudtrail-source/contract.json"
        ))
        .unwrap()
    })
}
fn case(id: &str) -> &'static Value {
    fixtures()["native_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}
fn profile() -> CloudTrailProfile {
    CloudTrailProfile::new("cloudtrail-management", &["111122223333"], &["us-east-1"]).unwrap()
}
fn pin(ordinal: u32) -> PreparationIdentity {
    PreparationIdentity::new(
        Uuid::parse_str("20000000-0000-4000-8000-000000000001").unwrap(),
        Uuid::parse_str("30000000-0000-4000-8000-000000000001").unwrap(),
        "2026-10-07T12:00:01Z".parse::<DateTime<Utc>>().unwrap(),
        ordinal,
    )
    .unwrap()
}
fn root() -> Value {
    serde_json::from_str(case("root-activity")["raw_utf8"].as_str().unwrap()).unwrap()
}

#[test]
fn all_41_native_projection_and_quarantine_witnesses_execute_in_rust() {
    let cases = fixtures()["native_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 41);
    for c in cases {
        let raw = c["raw_utf8"].as_str().unwrap().as_bytes();
        let result = normalize_record(
            raw,
            &profile(),
            pin(c["record_ordinal"].as_u64().unwrap() as u32),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(result.disposition()).unwrap(),
            c["expected"]["disposition"],
            "{}",
            c["id"]
        );
        assert_eq!(
            serde_json::to_value(result.reason_codes()).unwrap(),
            c["expected"]["reason_codes"],
            "{}",
            c["id"]
        );
        assert_eq!(result.original(), raw);
        if let Some(event) = result.event() {
            event.validate().unwrap();
            assert_eq!(
                event.attributes["security"], c["expected"]["security"],
                "{}",
                c["id"]
            );
            assert_eq!(
                event.attributes["aws"]["cloudtrail"], c["expected"]["cloudtrail"],
                "{}",
                c["id"]
            );
            assert!(result.prepared_bytes().unwrap().len() <= MAX_EVENT_BYTES);
            let decoded: SignalEvent =
                serde_json::from_slice(result.prepared_bytes().unwrap()).unwrap();
            assert_eq!(*event, decoded);
        } else {
            assert!(result.prepared_bytes().is_none());
        }
    }
}
#[test]
fn two_prepared_pins_match_canonical_contract_and_replay_is_byte_stable() {
    for witness in fixtures()["prepared_cases"].as_array().unwrap() {
        let native = case(witness["native_case"].as_str().unwrap());
        let raw = native["raw_utf8"].as_str().unwrap().as_bytes();
        let context = PreparationIdentity::new(
            witness["prepared_uuid"].as_str().unwrap().parse().unwrap(),
            "30000000-0000-4000-8000-000000000001".parse().unwrap(),
            witness["prepared_observed_at"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            native["record_ordinal"].as_u64().unwrap() as u32,
        )
        .unwrap();
        let first = normalize_record(raw, &profile(), context).unwrap();
        let second = normalize_record(raw, &profile(), context).unwrap();
        let expected: Value = serde_json::from_str(witness["raw_utf8"].as_str().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(first.event().unwrap()).unwrap(),
            expected
        );
        assert_eq!(first.prepared_bytes(), second.prepared_bytes());
        assert_eq!(first.original_sha256(), second.original_sha256());
    }
}
#[test]
fn byte_limit_charges_whitespace_before_hash_parse_or_projection() {
    let mut bytes = case("root-activity")["raw_utf8"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes.resize(MAX_RECORD_BYTES, b' ');
    assert!(normalize_record(&bytes, &profile(), pin(0)).is_ok());
    bytes.push(b' ');
    assert_eq!(
        normalize_record(&bytes, &profile(), pin(0)).unwrap_err(),
        E::RecordBytesExceeded
    );
}
#[test]
fn escaped_duplicate_keys_reject_at_root_and_in_unknown_nested_extensions() {
    for raw in [
        r#"{"eventID":1,"event\u0049D":2}"#,
        r#"{"extension":{"secret":1,"\u0073ecret":2}}"#,
    ] {
        assert_eq!(
            normalize_record(raw.as_bytes(), &profile(), pin(0)).unwrap_err(),
            E::DuplicateKey
        );
    }
}
#[test]
fn invalid_json_and_exponent_overflow_never_become_empty_success() {
    for raw in [
        b"null trailing".as_slice(),
        b"{\"x\":NaN}",
        b"{\"x\":Infinity}",
        b"{\"x\":9e999}",
        b"{\"x\":-9e999}",
        b"[1,]",
        b"{\"x\":01}",
        b"{\"x\":truefalse}",
        b"\xff",
        b"{\"x\":\"\\uD800\"}",
        b"{\"x\":\"\\z\"}",
    ] {
        assert_eq!(
            normalize_record(raw, &profile(), pin(0)).unwrap_err(),
            E::InvalidJson,
            "{raw:?}"
        );
    }
}
#[test]
fn depth_boundary_is_checked_before_container_allocation() {
    let raw = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert_eq!(
        normalize_record(raw.as_bytes(), &profile(), pin(0))
            .unwrap()
            .disposition(),
        Disposition::QuarantineRecord
    );
    let raw = format!("[{}]", raw);
    assert_eq!(
        normalize_record(raw.as_bytes(), &profile(), pin(0)).unwrap_err(),
        E::JsonDepthExceeded
    );
    let raw = format!(
        "{}{}",
        "[".repeat(MAX_JSON_DEPTH + 1),
        "]".repeat(MAX_JSON_DEPTH + 1)
    );
    assert_eq!(
        normalize_record(raw.as_bytes(), &profile(), pin(0)).unwrap_err(),
        E::JsonDepthExceeded
    );
}
#[test]
fn node_limit_precedes_child_allocation_with_exact_primitive_boundary() {
    let raw = format!("[{}]", vec!["0"; MAX_JSON_NODES - 1].join(","));
    assert!(normalize_record(raw.as_bytes(), &profile(), pin(0)).is_ok());
    let raw = format!("[{}]", vec!["0"; MAX_JSON_NODES].join(","));
    assert_eq!(
        normalize_record(raw.as_bytes(), &profile(), pin(0)).unwrap_err(),
        E::JsonNodesExceeded
    );
}
#[test]
fn scalar_type_confusion_in_scope_mfa_and_disable_conditions_is_fail_closed() {
    let mut native = root();
    native["managementEvent"] = json!(1);
    let raw = serde_json::to_vec(&native).unwrap();
    assert_eq!(
        normalize_record(&raw, &profile(), pin(0))
            .unwrap()
            .disposition(),
        Disposition::QuarantineRecord
    );
    for enable in [json!(0), json!("false"), json!(null), json!([])] {
        let mut native: Value = serde_json::from_str(
            case("guardduty-update-disable")["raw_utf8"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        native["requestParameters"]["enable"] = enable;
        let raw = serde_json::to_vec(&native).unwrap();
        let result = normalize_record(&raw, &profile(), pin(0)).unwrap();
        assert!(
            result.event().unwrap().attributes["security"]
                .get("action")
                .is_none()
        );
    }
}
#[test]
fn oversized_projection_quarantines_without_partial_or_truncated_bytes() {
    let mut native = root();
    native["sourceIPAddress"] = json!("x".repeat(MAX_EVENT_BYTES));
    let raw = serde_json::to_vec(&native).unwrap();
    let result = normalize_record(&raw, &profile(), pin(0)).unwrap();
    assert_eq!(result.disposition(), Disposition::QuarantineRecord);
    assert_eq!(result.reason_codes(), &[Reason::PreparedEventBytesExceeded]);
    assert_eq!(result.original(), raw);
    assert!(result.event().is_none());
    assert!(result.prepared_bytes().is_none());
}
#[test]
fn unknown_extensions_remain_original_and_are_never_copied_as_credentials() {
    let mut native = root();
    native["futureField"] =
        json!({"token":"NATIVE_SECRET","big":123456789012345678901234567890_u128.to_string()});
    native["sourceIPAddress"] = json!("AWS Internal/example");
    let raw = serde_json::to_vec(&native).unwrap();
    let result = normalize_record(&raw, &profile(), pin(0)).unwrap();
    assert_eq!(result.original(), raw);
    let event = result.event().unwrap();
    assert_eq!(
        event.attributes["aws"]["cloudtrail"]["source_ip_address"],
        "AWS Internal/example"
    );
    assert!(
        !std::str::from_utf8(result.prepared_bytes().unwrap())
            .unwrap()
            .contains("NATIVE_SECRET")
    );
}
#[test]
fn native_identity_is_not_prepared_identity_or_a_global_deduplication_key() {
    let raw = case("root-activity")["raw_utf8"]
        .as_str()
        .unwrap()
        .as_bytes();
    let first = normalize_record(raw, &profile(), pin(0)).unwrap();
    assert_ne!(
        first.event().unwrap().id.to_string(),
        first.event().unwrap().attributes["aws"]["cloudtrail"]["event_id"]
    );
    let context = PreparationIdentity::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "2026-10-07T12:00:01Z".parse().unwrap(),
        0,
    )
    .unwrap();
    let other = normalize_record(raw, &profile(), context).unwrap();
    assert_ne!(first.event().unwrap().id, other.event().unwrap().id);
    assert_ne!(first.prepared_bytes(), other.prepared_bytes());
}
#[test]
fn invalid_configuration_and_context_return_static_errors() {
    for (name, accounts, regions) in [
        ("", vec!["111122223333"], vec!["us-east-1"]),
        ("source", vec!["not-an-account"], vec!["us-east-1"]),
        (
            "source",
            vec!["111122223333", "111122223333"],
            vec!["us-east-1"],
        ),
        ("source", vec!["111122223333"], vec!["us east 1"]),
    ] {
        assert_eq!(
            CloudTrailProfile::new(name, &accounts, &regions).unwrap_err(),
            E::InvalidConfiguration
        );
    }
    assert!(CloudTrailProfile::new("source", &vec!["111122223333"; 129], &["us-east-1"]).is_err());
    for (event, receipt, n) in [
        (Uuid::nil(), Uuid::new_v4(), 0),
        (Uuid::new_v4(), Uuid::nil(), 0),
        (Uuid::new_v4(), Uuid::new_v4(), 1024),
    ] {
        assert_eq!(
            PreparationIdentity::new(event, receipt, "2026-10-07T12:00:01Z".parse().unwrap(), n)
                .unwrap_err(),
            E::InvalidContext
        );
    }
    assert!(!E::InvalidJson.to_string().contains("NATIVE_SECRET"));
}
#[test]
fn uuid_time_and_version_lexical_constraints_do_not_guess_or_overflow() {
    for (key, value) in [
        ("eventID", "10000000000040008000000000000001"),
        ("eventID", "10000000-0000-4000-8000-00000000000A"),
        ("eventTime", "2026-10-07T12:00:00+00:00"),
        ("eventTime", "2026-10-07T12:00:60Z"),
        ("eventTime", "2026-02-30T12:00:00Z"),
        ("eventTime", "2026-10-07T12:00:00.1234567890Z"),
        (
            "eventVersion",
            "1.999999999999999999999999999999999999999999999",
        ),
    ] {
        let mut native = root();
        native[key] = json!(value);
        let raw = serde_json::to_vec(&native).unwrap();
        assert_eq!(
            normalize_record(&raw, &profile(), pin(0))
                .unwrap()
                .disposition(),
            Disposition::QuarantineRecord
        );
    }
}

#[test]
fn arbitrary_precision_internal_key_is_an_ordinary_native_extension_not_a_number() {
    let mut native = root();
    native["$serde_json::private::Number"] = json!("9e999");
    native["extension"] = json!({"$serde_json::private::Number":"not a number"});
    let raw = serde_json::to_vec(&native).unwrap();
    let result = normalize_record(&raw, &profile(), pin(0)).unwrap();
    assert_eq!(result.disposition(), Disposition::Emit);
    assert_eq!(result.original(), raw);
    assert_eq!(
        result.event().unwrap().attributes["security"]["outcome"],
        "success"
    );
}

#[test]
fn pinned_observation_time_rejects_unserializable_years_and_leap_seconds() {
    use chrono::TimeZone;
    for time in [
        Utc.with_ymd_and_hms(10000, 1, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(0, 1, 1, 0, 0, 0).unwrap(),
        "2016-12-31T23:59:60Z".parse().unwrap(),
    ] {
        assert_eq!(
            PreparationIdentity::new(Uuid::new_v4(), Uuid::new_v4(), time, 0).unwrap_err(),
            E::InvalidContext
        );
    }
}

#[test]
fn independent_json_grammar_models_preserve_known_projection_and_precise_originals() {
    let values = [
        json!(null),
        json!(true),
        json!(false),
        json!(-17),
        json!(1.25),
        json!("quote \" slash \\ newline \n emoji 🦀"),
        json!({"$serde_json::private::Number":"9e999","\u{0000}":1}),
        json!([1, 2, 3]),
    ];
    for (i, value) in values.iter().enumerate() {
        for depth in 0..8 {
            let mut extension = value.clone();
            for n in 0..depth {
                extension = if n % 2 == 0 {
                    json!([extension])
                } else {
                    json!({"nested":extension})
                };
            }
            let mut native = root();
            native["futureField"] = extension;
            let raw = if i % 2 == 0 {
                serde_json::to_vec(&native).unwrap()
            } else {
                serde_json::to_vec_pretty(&native).unwrap()
            };
            let result = normalize_record(&raw, &profile(), pin(0)).unwrap();
            assert_eq!(
                result.disposition(),
                Disposition::Emit,
                "model {i} depth {depth}"
            );
            assert_eq!(
                result.event().unwrap().attributes["security"],
                case("root-activity")["expected"]["security"]
            );
            assert_eq!(result.original(), raw);
        }
    }
    let raw = case("root-activity")["raw_utf8"].as_str().unwrap().replace(
        "\"responseElements\":null",
        "\"responseElements\":{\"Count\":12345678901234567890123456789012345678901234567890}",
    );
    assert!(raw.contains("78901234567890}"));
    let result = normalize_record(raw.as_bytes(), &profile(), pin(0)).unwrap();
    assert_eq!(result.disposition(), Disposition::Emit);
    assert_eq!(result.original(), raw.as_bytes());
}

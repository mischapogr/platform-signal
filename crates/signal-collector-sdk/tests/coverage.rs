// Assertions use unwrap only on owned laboratory fixtures and expected successes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use signal_collector_sdk::coverage::{
    CoverageContext, CoverageError as E, CoverageProfile, CoverageReason as R, CoverageStatus as S,
    MAX_RECORD_BYTES, ValidatedCoverage, assess_coverage,
};
use std::sync::OnceLock;

fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let bytes = include_bytes!("../../../tests/fixtures/source-coverage/contract.json");
        assert!(bytes.len() <= 4 * 1024 * 1024);
        serde_json::from_slice(bytes).expect("owned fixtures")
    })
}

fn case(group: &str, id: &str) -> &'static Value {
    fixtures()[group]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}

fn record(id: &str) -> Value {
    case("record_cases", id)["record"].clone()
}
fn context(id: &str) -> Value {
    case("assessment_cases", id)["context"].clone()
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn profile(record: &Value) -> Option<CoverageProfile> {
    fixtures()["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| {
            p["id"] == record["coverage_profile"]["id"]
                && p["revision"] == record["coverage_profile"]["revision"]
        })
        .map(|p| CoverageProfile::parse(&bytes(p)).unwrap())
}

fn validate(record: &Value) -> Result<ValidatedCoverage, E> {
    ValidatedCoverage::parse(&bytes(record), profile(record).as_ref())
}

fn assess(record: &Value, context: &Value) -> (S, Vec<R>) {
    let result = assess_coverage(
        &bytes(record),
        profile(record).as_ref(),
        &CoverageContext::parse(&bytes(context)).unwrap(),
    );
    (result.status(), result.reason_codes().to_vec())
}

fn check_assessment(case: &Value) {
    let record = record(case["record_fixture"].as_str().unwrap());
    let (status, reasons) = assess(&record, &case["context"]);
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        case["expected"]["status"],
        "{}",
        case["id"]
    );
    assert_eq!(
        serde_json::to_value(reasons).unwrap(),
        case["expected"]["reason_codes"],
        "{}",
        case["id"]
    );
}

#[test]
fn executes_all_60_record_requirements() {
    let cases = fixtures()["record_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 60);
    let mut counts = [0; 3];
    for case in cases {
        let result = validate(&case["record"]);
        match case["expected_semantics"].as_str().unwrap() {
            "valid" => {
                assert!(result.is_ok(), "{}: {result:?}", case["id"]);
                counts[0] += 1;
            }
            "reject" => {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    case["expected_semantic_error"].as_str().unwrap(),
                    "{}",
                    case["id"]
                );
                counts[1] += 1;
            }
            "not_evaluated" => {
                assert!(result.is_err(), "{}", case["id"]);
                counts[2] += 1;
            }
            other => panic!("unknown fixture expectation {other}"),
        }
    }
    assert_eq!(counts, [21, 21, 18]);
}

#[test]
fn executes_all_39_assessment_requirements() {
    let cases = fixtures()["assessment_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 39);
    for case in cases {
        check_assessment(case);
    }
}

#[test]
fn executes_seven_transition_sequences_without_mutating_history() {
    let before = fixtures().clone();
    let transitions = fixtures()["transition_cases"].as_array().unwrap();
    assert_eq!(transitions.len(), 7);
    for sequence in transitions {
        let retained: Vec<_> = sequence["retained_records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| record(id.as_str().unwrap()))
            .collect();
        for step in sequence["steps"].as_array().unwrap() {
            check_assessment(case("assessment_cases", step.as_str().unwrap()));
        }
        for historical in sequence["historical_assertions"].as_array().unwrap() {
            check_assessment(case("assessment_cases", historical.as_str().unwrap()));
        }
        for (id, snapshot) in sequence["retained_records"]
            .as_array()
            .unwrap()
            .iter()
            .zip(retained)
        {
            assert_eq!(snapshot, record(id.as_str().unwrap()));
        }
    }
    assert_eq!(before, *fixtures());
    // This exercises pure evaluation, not a persistent store or observer recovery.
}

#[test]
fn raw_whitespace_is_charged_before_decoding() {
    let r = record("quiet_verified");
    let p = profile(&r).unwrap();
    let mut wire = bytes(&r);
    wire.resize(MAX_RECORD_BYTES, b' ');
    assert!(ValidatedCoverage::parse(&wire, Some(&p)).is_ok());
    wire.push(b' ');
    assert_eq!(
        ValidatedCoverage::parse(&wire, Some(&p)).unwrap_err(),
        E::RecordBytesExceeded
    );
}

#[test]
fn invalid_utf8_nonfinite_and_trailing_content_are_rejected() {
    let r = record("quiet_verified");
    let p = profile(&r).unwrap();
    let mut invalid = bytes(&r);
    invalid.push(0xff);
    let mut trailing = bytes(&r);
    trailing.extend_from_slice(b" {}");
    let nonfinite = String::from_utf8(bytes(&r))
        .unwrap()
        .replace("\"total\":0", "\"total\":NaN");
    for wire in [invalid, trailing, nonfinite.into_bytes()] {
        assert_eq!(
            ValidatedCoverage::parse(&wire, Some(&p)).unwrap_err(),
            E::InvalidStructure
        );
    }
}

#[test]
fn duplicate_fields_and_escaped_attribute_keys_are_rejected() {
    let r = record("quiet_verified");
    let p = profile(&r).unwrap();
    let wire = String::from_utf8(bytes(&r)).unwrap();
    for candidate in [
        wire.replacen('{', "{\"schema_version\":1,", 1),
        wire.replace(
            "\"coverage_profile\":{",
            "\"coverage_profile\":{\"id\":\"ignored\",",
        ),
        wire.replace(
            "\"attributes\":{}",
            "\"attributes\":{\"a\":\"first\",\"\\u0061\":\"last\"}",
        ),
        wire.replace("\"checkpoint\":{", "\"checkpoint\":{\"value\":\"ignored\","),
    ] {
        assert_eq!(
            ValidatedCoverage::parse(candidate.as_bytes(), Some(&p)).unwrap_err(),
            E::InvalidStructure
        );
    }
}

#[test]
fn nullable_fields_must_be_present() {
    for field in ["last_observed_at", "checkpoint"] {
        let mut r = record("quiet_verified");
        r.as_object_mut().unwrap().remove(field);
        assert_eq!(validate(&r).unwrap_err(), E::InvalidStructure);
    }
    let mut r = record("source_gap");
    for field in ["end", "proof_ref"] {
        let saved = r["gaps"][0].clone();
        r["gaps"][0].as_object_mut().unwrap().remove(field);
        assert_eq!(validate(&r).unwrap_err(), E::InvalidStructure);
        r["gaps"][0] = saved;
    }
    let mut r = record("quiet_verified");
    r["gap_summary"].as_object_mut().unwrap().remove("total");
    assert_eq!(validate(&r).unwrap_err(), E::InvalidStructure);
}

#[test]
fn invalid_calendar_offsets_leap_seconds_and_fraction_formats_are_rejected() {
    for t in [
        "0000-10-07T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-10-07T00:00:60Z",
        "2026-10-07T00:00:00+00:00",
        "2026-10-07t00:00:00z",
        "2026-10-07T00:00:00.Z",
        "2026-10-07T00:00:00.1234567890Z",
        "10000-10-07T00:00:00Z",
    ] {
        let mut r = record("quiet_verified");
        r["coverage_start"] = json!(t);
        assert_eq!(validate(&r).unwrap_err(), E::InvalidTimestamp, "{t}");
    }
}

#[test]
fn nanosecond_intervals_and_far_calendar_years_keep_precision() {
    for year in ["0001", "2024", "9999"] {
        let mut r = record("quiet_verified");
        for (field, tail) in [
            ("coverage_start", "00:00:00.000000001Z"),
            ("coverage_end", "00:00:00.000000002Z"),
            ("last_verified_at", "00:00:00.000000002Z"),
            ("valid_until", "00:00:00.000000003Z"),
        ] {
            r[field] = json!(format!("{year}-02-28T{tail}"));
        }
        r["provenance"]["observed_at"] = r["last_verified_at"].clone();
        assert!(validate(&r).is_ok());
        let mut c = context("quiet_current");
        c["at"] = r["last_verified_at"].clone();
        c["interval"] = json!({"start":r["coverage_start"], "end":r["coverage_end"]});
        assert_eq!(assess(&r, &c), (S::Verified, vec![]));
        c["at"] = r["valid_until"].clone();
        assert_eq!(assess(&r, &c), (S::Unknown, vec![R::Expired]));
        r["coverage_start"] = r["coverage_end"].clone();
        assert_eq!(validate(&r).unwrap_err(), E::InvalidInterval);
    }
}

#[test]
fn interval_and_expiry_budget_limits_include_nanoseconds() {
    let mut r = record("quiet_verified");
    r["coverage_end"] = json!("2026-10-07T01:00:00Z");
    r["last_verified_at"] = r["coverage_end"].clone();
    r["provenance"]["observed_at"] = r["coverage_end"].clone();
    r["valid_until"] = json!("2026-10-07T01:01:00Z");
    assert!(validate(&r).is_ok());
    r["coverage_start"] = json!("2026-10-06T23:59:59.999999999Z");
    assert_eq!(validate(&r).unwrap_err(), E::IntervalBudgetExceeded);
    r["coverage_start"] = json!("2026-10-07T00:00:00Z");
    r["valid_until"] = json!("2026-10-07T01:01:00.000000001Z");
    assert_eq!(validate(&r).unwrap_err(), E::ExpiryBudgetExceeded);
}

#[test]
fn future_clock_guard_allows_exact_skew_but_not_one_extra_nanosecond() {
    let r = record("quiet_verified");
    let mut c = context("quiet_current");
    c["at"] = json!("2026-10-07T00:04:58Z");
    assert_eq!(assess(&r, &c), (S::Verified, vec![]));
    c["at"] = json!("2026-10-07T00:04:57.999999999Z");
    assert_eq!(assess(&r, &c), (S::Unknown, vec![R::VerificationInFuture]));
    let mut r = r;
    r["provenance"]["observed_at"] = json!("2026-10-07T00:05:00.000000001Z");
    c["at"] = json!("2026-10-07T00:04:58Z");
    assert_eq!(assess(&r, &c), (S::Unknown, vec![R::ObservationInFuture]));
}

#[test]
fn all_binding_fields_and_observer_identity_are_exact() {
    let r = record("quiet_verified");
    for pointer in [
        "/binding/source_id",
        "/binding/collector_id",
        "/binding/expected_stream",
        "/binding/collection_config_revision",
        "/binding/resource_scope/kind",
        "/binding/resource_scope/id",
        "/binding/coverage_profile/id",
        "/binding/coverage_profile/revision",
    ] {
        let mut c = context("quiet_current");
        *c.pointer_mut(pointer).unwrap() = json!("other");
        assert_eq!(
            assess(&r, &c),
            (S::Unknown, vec![R::BindingMismatch]),
            "{pointer}"
        );
    }
    let mut c = context("quiet_current");
    c["binding"]["resource_scope"]["attributes"] = json!({"team":"other"});
    assert_eq!(assess(&r, &c), (S::Unknown, vec![R::BindingMismatch]));
    c = context("quiet_current");
    c["observer_id"] = json!("other");
    assert_eq!(assess(&r, &c), (S::Unknown, vec![R::ObserverMismatch]));
}

#[test]
fn omitted_and_empty_scope_attributes_are_equal() {
    let r = record("quiet_verified");
    let mut c = context("quiet_current");
    c["binding"]["resource_scope"]
        .as_object_mut()
        .unwrap()
        .remove("attributes");
    assert_eq!(assess(&r, &c), (S::Verified, vec![]));
}

#[test]
fn unrecovered_gap_and_unreferenced_recovery_cannot_claim_verified() {
    let mut r = record("source_gap");
    r["validation"]["continuity"] = json!("verified");
    r["validation_status"] = json!("verified");
    assert_eq!(validate(&r).unwrap_err(), E::UnrecoveredGapVerified);
    r["gaps"][0]["recoverability"] = json!("recovered");
    r["gaps"][0]["proof_ref"] = Value::Null;
    assert_eq!(validate(&r).unwrap_err(), E::RecoveredGapMissingProof);
    r["gaps"][0]["proof_ref"] = json!("fixture://backfill");
    assert!(validate(&r).is_ok());
}

#[test]
fn gap_ids_counts_scope_and_interval_bounds_are_checked() {
    let original = record("source_gap");
    let mut r = original.clone();
    r["gaps"]
        .as_array_mut()
        .unwrap()
        .push(original["gaps"][0].clone());
    r["gap_summary"]["total"] = json!(2);
    assert_eq!(validate(&r).unwrap_err(), E::DuplicateGapId);
    r = original.clone();
    r["gaps"][0]["start"] = r["coverage_end"].clone();
    assert_eq!(validate(&r).unwrap_err(), E::GapOutsideInterval);
    r = original;
    r["gaps"][0]["end"] = r["gaps"][0]["start"].clone();
    assert_eq!(validate(&r).unwrap_err(), E::GapOutsideInterval);
}

#[test]
fn truncated_gap_totals_are_unknown_or_strictly_larger() {
    let mut r = record("quiet_verified");
    r["gap_summary"]["truncated"] = json!(true);
    r["validation_status"] = json!("partial");
    assert_eq!(validate(&r).unwrap_err(), E::GapSummaryMismatch);
    for total in [Value::Null, json!(1), json!(9_007_199_254_740_991_u64)] {
        r["gap_summary"]["total"] = total;
        assert!(validate(&r).is_ok());
    }
    r["gap_summary"]["total"] = json!(9_007_199_254_740_992_u64);
    assert_eq!(validate(&r).unwrap_err(), E::InvalidStructure);
}

#[test]
fn optional_unknown_does_not_reduce_but_optional_failure_does() {
    let mut r = record("quiet_verified");
    r["validation"]["source_integrity"] = json!("unknown");
    assert_eq!(assess(&r, &context("quiet_current")), (S::Verified, vec![]));
    r["validation"]["source_integrity"] = json!("failed");
    r["validation_status"] = json!("failed");
    assert_eq!(
        assess(&r, &context("quiet_current")),
        (S::Failed, vec![R::ComponentFailed])
    );
}

#[test]
fn invalid_profile_configuration_is_rejected() {
    let base = fixtures()["profiles"][0].clone();
    for (field, value) in [
        ("schema_version", json!(2)),
        ("max_interval_seconds", json!(0)),
        ("max_verification_age_seconds", json!(86_401)),
        ("max_clock_skew_seconds", json!(301)),
        (
            "required_components",
            json!(["configuration", "scope", "scope"]),
        ),
        (
            "required_components",
            json!(["scope", "continuity", "source_integrity"]),
        ),
    ] {
        let mut p = base.clone();
        p[field] = value;
        assert_eq!(
            CoverageProfile::parse(&bytes(&p)).unwrap_err(),
            E::InvalidProfile
        );
    }
}

#[test]
fn profiles_and_contexts_reject_duplicate_and_unknown_fields() {
    let p = String::from_utf8(bytes(&fixtures()["profiles"][0])).unwrap();
    assert_eq!(
        CoverageProfile::parse(p.replacen('{', "{\"id\":\"duplicate\",", 1).as_bytes())
            .unwrap_err(),
        E::InvalidStructure
    );
    let mut c = context("quiet_current");
    c["unrecognized"] = json!(true);
    assert_eq!(
        CoverageContext::parse(&bytes(&c)).unwrap_err(),
        E::InvalidStructure
    );
    c.as_object_mut().unwrap().remove("unrecognized");
    c["interval"]["end"] = c["interval"]["start"].clone();
    assert_eq!(
        CoverageContext::parse(&bytes(&c)).unwrap_err(),
        E::InvalidInterval
    );
}

#[test]
fn missing_profile_and_rejected_records_assess_unknown() {
    let r = record("quiet_verified");
    let c = CoverageContext::parse(&bytes(&context("quiet_current"))).unwrap();
    let rejected = ValidatedCoverage::parse(&bytes(&r), None);
    assert_eq!(rejected.unwrap_err(), E::ProfileUnavailable);
    let result = assess_coverage(&bytes(&r), None, &c);
    assert_eq!(result.reason_codes(), &[R::ProfileUnavailable]);
    assert_eq!(
        assess_coverage(b"malformed", profile(&r).as_ref(), &c).reason_codes(),
        &[R::InvalidRecord]
    );
    assert_eq!(
        assess_coverage(b"malformed", None, &c).reason_codes(),
        &[R::ProfileUnavailable]
    );
}

#[test]
fn record_id_is_canonical_and_non_nil() {
    for id in [
        "BCC77D04-395D-5803-B313-E58AC0C8ACBE",
        "bcc77d04395d5803b313e58ac0c8acbe",
        "not-a-uuid",
    ] {
        let mut r = record("quiet_verified");
        r["record_id"] = json!(id);
        assert_eq!(validate(&r).unwrap_err(), E::InvalidRecordId);
    }
}

#[test]
fn empty_and_overlong_attribute_keys_and_values_are_rejected() {
    for attributes in [json!({"":"value"}), json!({"key":""})] {
        let mut r = record("quiet_verified");
        r["resource_scope"]["attributes"] = attributes;
        assert_eq!(validate(&r).unwrap_err(), E::InvalidStructure);
    }
    let mut r = record("quiet_verified");
    r["resource_scope"]["attributes"] = json!({"key":"é".repeat(513)});
    assert_eq!(validate(&r).unwrap_err(), E::StringBytesExceeded);
}

#[test]
fn checkpoint_bytes_are_not_interpreted_or_rewritten() {
    let mut r = record("quiet_verified");
    r["checkpoint"]["value"] = json!("  opaque\tposition\n  ");
    let before = r.clone();
    let checked = validate(&r).unwrap();
    assert_eq!(checked.record_id(), r["record_id"].as_str().unwrap());
    assert_eq!(checked.status(), S::Verified);
    assert_eq!(before, r);
}

#[test]
fn assessment_serialization_is_versioned_with_bounded_reasons() {
    let c = CoverageContext::parse(&bytes(&context("quiet_current"))).unwrap();
    let r = record("quiet_verified");
    assert_eq!(
        serde_json::to_value(assess_coverage(&bytes(&r), profile(&r).as_ref(), &c)).unwrap(),
        json!({"schema_version":1,"status":"verified","reason_codes":[]})
    );
    assert_eq!(
        serde_json::to_value(assess_coverage(b"malformed", profile(&r).as_ref(), &c)).unwrap(),
        json!({"schema_version":1,"status":"unknown","reason_codes":["invalid_record"]})
    );
}

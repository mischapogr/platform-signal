// Existing generic predicates exercised against actual native Rust projection.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::Value;
use signal_collector_sdk::cloudtrail::{CloudTrailProfile, PreparationIdentity, normalize_record};
use signal_rules::{RuleLimits, RuleSet};
use uuid::Uuid;
fn fixtures() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/cloudtrail-source/contract.json"
    ))
    .unwrap()
}
fn rules() -> RuleSet {
    let catalog: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/security-requirements/catalog.json"
    ))
    .unwrap();
    let documents: Vec<_> = catalog["detections"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d.get("native_rule"))
        .map(|r| r.to_string())
        .collect();
    // JSON is a YAML subset accepted by the actual bounded loader.
    RuleSet::from_yaml_documents(documents, RuleLimits::default()).unwrap()
}
fn matches(id: &str) -> Vec<String> {
    let f = fixtures();
    let c = f["native_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap();
    let profile =
        CloudTrailProfile::new("cloudtrail-management", &["111122223333"], &["us-east-1"]).unwrap();
    let pin = PreparationIdentity::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "2026-10-07T12:00:01Z".parse().unwrap(),
        c["record_ordinal"].as_u64().unwrap() as u32,
    )
    .unwrap();
    let result =
        normalize_record(c["raw_utf8"].as_str().unwrap().as_bytes(), &profile, pin).unwrap();
    result
        .event()
        .map(|e| {
            rules()
                .evaluate(e)
                .unwrap()
                .iter()
                .map(|f| f.rule_id.clone())
                .collect()
        })
        .unwrap_or_default()
}
#[test]
fn all_native_cases_reach_selected_predicates_with_literal_expected_findings() {
    for case in fixtures()["native_cases"].as_array().unwrap() {
        let actual = matches(case["id"].as_str().unwrap());
        let expected: Vec<String> = case["expected"]["proposed_matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect();
        assert_eq!(actual, expected, "{}", case["id"]);
    }
}
#[test]
fn root_stopping_cloudtrail_produces_two_findings_without_action_filter() {
    assert_eq!(matches("root-stop-logging"), vec!["SIG-D01", "SIG-D02"]);
    assert_eq!(matches("console-root-no-mfa"), vec!["SIG-D01", "SIG-D03"]);
}
#[test]
fn failed_missing_and_federated_input_never_becomes_a_successful_no_mfa_finding() {
    for id in [
        "console-failed",
        "console-conflicting-error",
        "console-missing-mfa",
        "console-federated-no-mfa",
        "disable-failed",
        "stop-logging-failed",
        "recipient-scope-denied",
        "missing-event-id",
    ] {
        assert!(matches(id).is_empty(), "{id}");
    }
}

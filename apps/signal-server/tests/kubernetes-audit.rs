// Owned synthetic fixtures and the explicitly invoked local capture bridge only.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::{Value, json};
use signal_collector_sdk::kubernetes_audit::{MAX_RECORD_BYTES, Profile, normalize_record};
use signal_rules::{RuleLimits, RuleSet};
use std::{collections::HashSet, fs, io::Read, path::Path};
use uuid::Uuid;

fn rules() -> RuleSet {
    let catalog: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/security-requirements/catalog.json"
    ))
    .unwrap();
    let rule = catalog["detections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == "SIG-D07")
        .unwrap()["native_rule"]
        .to_string();
    RuleSet::from_yaml_documents([rule], RuleLimits::default()).unwrap()
}

fn project_cases(document: &Value, cluster: &str, revision: &str) -> Value {
    assert_eq!(document["schema_version"], 1);
    let profile = Profile::new(cluster, revision).unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert!(!cases.is_empty() && cases.len() <= 16);
    let rules = rules();
    let observed = "2026-10-24T12:00:00Z".parse().unwrap();
    let mut names = HashSet::new();
    let mut projected = vec![];
    for (index, case) in cases.iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        assert!(names.insert(name));
        let raw = case["raw_utf8"].as_str().unwrap().as_bytes();
        assert!(raw.len() <= MAX_RECORD_BYTES);
        // Gate-only pins are allocated once by position in this immutable capture
        // document, then retained in the output used for crash/redelivery checks.
        let id = Uuid::from_u128(0x53494700 + index as u128 + 1);
        let normalized = normalize_record(raw, &profile, id, observed).unwrap();
        assert_eq!(normalized.original(), raw);
        let event = normalized.event();
        let actual_privileged = event.attributes["security"].get("privileged");
        let expected_privileged = &case["expected_privileged"];
        if expected_privileged.is_null() {
            assert!(
                actual_privileged.is_none(),
                "{name}: must stay indeterminate"
            );
        } else {
            assert_eq!(actual_privileged, Some(expected_privileged), "{name}");
        }
        let findings = rules.evaluate(event).unwrap();
        assert_eq!(
            findings.len() as u64,
            case["expected_findings"].as_u64().unwrap(),
            "{name}"
        );
        let replay = normalize_record(raw, &profile, id, observed).unwrap();
        assert_eq!(
            serde_json::to_vec(event).unwrap(),
            serde_json::to_vec(replay.event()).unwrap()
        );
        assert_eq!(findings, rules.evaluate(replay.event()).unwrap());
        let original_sha256: String = normalized
            .original_sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        projected.push(json!({"name":name,"original_sha256":original_sha256,
            "event":event,"findings":findings}));
    }
    json!({"schema_version":1,"cases":projected})
}
#[test]
fn native_d07_positive_negative_and_indeterminate_cases_use_actual_engine() {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/kubernetes-audit/native.json"
    ))
    .unwrap();
    let result = project_cases(&fixture, "synthetic-cluster", "synthetic-policy");
    assert_eq!(result["cases"].as_array().unwrap().len(), 8);
}

#[test]
#[ignore = "requires an explicitly captured owned local Kubernetes audit document"]
fn captured_audit_records_use_actual_normalizer_and_engine() {
    let input = std::env::var_os("SIGNAL_K8S_AUDIT_CAPTURE").expect("capture input required");
    let output =
        std::env::var_os("SIGNAL_K8S_AUDIT_PROJECTION").expect("projection output required");
    let mut raw = vec![];
    fs::File::open(input)
        .unwrap()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(raw.len() <= 2 * 1024 * 1024);
    let document: Value = serde_json::from_slice(&raw).unwrap();
    let result = project_cases(
        &document,
        document["cluster"].as_str().unwrap(),
        document["policy_revision"].as_str().unwrap(),
    );
    // Never overwrite an earlier capture's projection or an arbitrary file.
    let mut destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&output))
        .unwrap();
    serde_json::to_writer(&mut destination, &result).unwrap();
    destination.sync_all().unwrap();
}

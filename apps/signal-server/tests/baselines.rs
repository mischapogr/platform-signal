use serde_json::Value;
use signal_collector_sdk::{cloudtrail, kubernetes_audit};
use signal_rules::{
    RuleContext, RuleLimits,
    baseline::{HostDecision, Pack, Status},
};
use std::time::Duration;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn pack() -> Result<Pack> {
    Ok(Pack::from_documents(
        include_str!("../../../rules/baselines/v1/manifest.json"),
        &[
            (
                "SIG-D01.yaml",
                include_str!("../../../rules/baselines/v1/SIG-D01.yaml"),
            ),
            (
                "SIG-D02.yaml",
                include_str!("../../../rules/baselines/v1/SIG-D02.yaml"),
            ),
            (
                "SIG-D03.yaml",
                include_str!("../../../rules/baselines/v1/SIG-D03.yaml"),
            ),
            (
                "SIG-D05.yaml",
                include_str!("../../../rules/baselines/v1/SIG-D05.yaml"),
            ),
            (
                "SIG-D07.yaml",
                include_str!("../../../rules/baselines/v1/SIG-D07.yaml"),
            ),
        ],
        RuleLimits::default(),
        &RuleContext::new(Duration::from_secs(5)),
    )?)
}
fn ready(pack: &Pack) -> Vec<HostDecision<'_>> {
    pack.manifest()
        .detections
        .iter()
        .map(|d| HostDecision {
            rule_id: &d.id,
            ready: true,
            normalization_profile: &d.normalization_profile,
        })
        .collect()
}

#[test]
fn native_cloudtrail_cases_use_packaged_predicates_and_missing_mfa_is_indeterminate() -> Result {
    let pack = pack()?;
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/cloudtrail-source/contract.json"
    ))?;
    let profile = cloudtrail::CloudTrailProfile::new(
        "cloudtrail-management",
        &["111122223333"],
        &["us-east-1"],
    )?;
    for (i, case) in fixtures["native_cases"]
        .as_array()
        .ok_or("native cases")?
        .iter()
        .enumerate()
    {
        let pin = cloudtrail::PreparationIdentity::new(
            Uuid::from_u128(1),
            Uuid::from_u128(i as u128 + 2),
            "2026-10-07T12:00:01Z".parse()?,
            case["record_ordinal"].as_u64().ok_or("ordinal")? as u32,
        )?;
        let normalized = cloudtrail::normalize_record(
            case["raw_utf8"].as_str().ok_or("raw")?.as_bytes(),
            &profile,
            pin,
        )?;
        let actual = if let Some(event) = normalized.event() {
            let rows = pack.assess(
                event,
                &ready(&pack),
                &RuleContext::new(Duration::from_secs(5)),
            )?;
            if case["id"] == "console-missing-mfa" {
                assert_eq!(rows[2].status, Status::Indeterminate);
                assert!(rows[2].coverage_gap);
            }
            rows.into_iter()
                .filter_map(|r| r.finding.map(|f| f.rule_id))
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let expected = case["expected"]["proposed_matches"]
            .as_array()
            .ok_or("expected")?
            .iter()
            .map(|v| v.as_str().ok_or("id").map(String::from))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(actual, expected, "{}", case["id"]);
    }
    Ok(())
}

#[test]
fn native_audit_admission_and_incomplete_evidence_have_distinct_assessments() -> Result {
    let pack = pack()?;
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/kubernetes-audit/native.json"
    ))?;
    let profile = kubernetes_audit::Profile::new("synthetic-cluster", "synthetic-policy")?;
    for (i, case) in fixtures["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .enumerate()
    {
        let normalized = kubernetes_audit::normalize_record(
            case["raw_utf8"].as_str().ok_or("raw")?.as_bytes(),
            &profile,
            Uuid::from_u128(i as u128 + 1),
            "2026-10-24T12:00:00Z".parse()?,
        )?;
        let rows = pack.assess(
            normalized.event(),
            &ready(&pack),
            &RuleContext::new(Duration::from_secs(5)),
        )?;
        assert_eq!(
            u64::from(rows[4].finding.is_some()),
            case["expected_findings"].as_u64().ok_or("findings")?,
            "{}",
            case["name"]
        );
        if ["metadata", "request-only", "dry-run", "missing-spec"]
            .contains(&case["name"].as_str().ok_or("name")?)
        {
            assert_eq!(rows[4].status, Status::Indeterminate, "{}", case["name"]);
            assert!(rows[4].coverage_gap);
        }
    }
    Ok(())
}

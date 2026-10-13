// Unwraps are limited to owned laboratory fixtures and expected test successes.
#![allow(clippy::unwrap_used)]

use serde_json::Value;
use signal_collector_sdk::coverage::{
    CoverageContext, CoverageProfile,
    onboarding::{
        self, BlockerCode as B, Detection, OnboardingError as E, Requirement,
        RequirementStatus as R, Stage,
    },
};

fn fixture() -> (Vec<u8>, CoverageProfile, Value) {
    let fixtures: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/source-coverage/contract.json"
    ))
    .unwrap();
    let record = fixtures["record_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "quiet_verified")
        .unwrap()["record"]
        .clone();
    let profile = fixtures["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| {
            profile["id"] == record["coverage_profile"]["id"]
                && profile["revision"] == record["coverage_profile"]["revision"]
        })
        .unwrap();
    let context = fixtures["assessment_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "quiet_current")
        .unwrap()["context"]
        .clone();
    (
        serde_json::to_vec(&record).unwrap(),
        CoverageProfile::parse(&serde_json::to_vec(profile).unwrap()).unwrap(),
        context,
    )
}

fn rule() -> Detection {
    Detection {
        id: "fixture-rule".into(),
        supported: true,
        loaded: true,
        permissions: vec![],
        categories: vec![],
        state: vec![],
    }
}

fn assess(
    connected: bool,
    context: &Value,
    detections: &[Detection],
) -> Result<onboarding::OnboardingReport, E> {
    let (record, profile, _) = fixture();
    onboarding::assess_onboarding(
        connected,
        &record,
        Some(&profile),
        &CoverageContext::parse(&serde_json::to_vec(context).unwrap()).unwrap(),
        detections,
    )
}

#[test]
fn current_verified_loaded_rule_can_be_active_but_empty_inventory_cannot() {
    let (_, _, context) = fixture();
    let report = assess(true, &context, &[rule()]).unwrap();
    assert_eq!(report.stage, Stage::DetectionsActive);
    assert!(report.detections[0].active);
    assert_eq!(
        assess(true, &context, &[]).unwrap().stage,
        Stage::CoverageVerified
    );
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["stage"], "detections_active");
}

#[test]
fn connection_is_independent_of_verified_coverage_and_loaded_rules() {
    let (_, _, context) = fixture();
    let report = assess(false, &context, &[rule()]).unwrap();
    assert_eq!(report.stage, Stage::Disconnected);
    assert!(!report.detections[0].active);
    assert_eq!(report.detections[0].blockers[0].code, B::Disconnected);
}

#[test]
fn historical_or_stale_or_unhealthy_or_mismatched_coverage_never_activates() {
    let (_, _, context) = fixture();
    for (field, value, expected) in [
        ("mode", "historical", B::HistoricalContext),
        ("at", "2026-10-08T00:05:30Z", B::CoverageNotVerified),
        ("observer_status", "unhealthy", B::CoverageNotVerified),
        ("observer_id", "other-observer", B::CoverageNotVerified),
    ] {
        let mut changed = context.clone();
        changed[field] = value.into();
        let report = assess(true, &changed, &[rule()]).unwrap();
        assert_eq!(report.stage, Stage::Connected);
        assert!(!report.detections[0].active);
        assert!(
            report.detections[0]
                .blockers
                .iter()
                .any(|b| b.code == expected)
        );
    }
    let mut changed = context.clone();
    changed["binding"]["source_id"] = "other-source".into();
    assert_eq!(
        assess(true, &changed, &[rule()]).unwrap().stage,
        Stage::Connected
    );
}

#[test]
fn missing_and_unknown_prerequisites_are_visible_per_rule() {
    let (_, _, context) = fixture();
    for (status, expected) in [
        (
            R::Missing,
            [B::MissingPermission, B::MissingCategory, B::MissingState],
        ),
        (
            R::Unknown,
            [B::UnknownPermission, B::UnknownCategory, B::UnknownState],
        ),
    ] {
        let mut blocked = rule();
        blocked.id = "blocked-rule".into();
        blocked.permissions.push(Requirement {
            id: "read-audit".into(),
            status,
        });
        blocked.categories.push(Requirement {
            id: "audit".into(),
            status,
        });
        blocked.state.push(Requirement {
            id: "baseline".into(),
            status,
        });
        let report = assess(true, &context, &[rule(), blocked]).unwrap();
        assert!(report.detections[0].active);
        assert!(!report.detections[1].active);
        assert_eq!(
            report.detections[1]
                .blockers
                .iter()
                .map(|b| b.code)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            report.detections[1]
                .blockers
                .iter()
                .all(|b| b.requirement.is_some())
        );
    }
    let mut met = rule();
    met.permissions.push(Requirement {
        id: "read-audit".into(),
        status: R::Met,
    });
    assert!(assess(true, &context, &[met]).unwrap().detections[0].active);
}

#[test]
fn unsupported_and_unloaded_rules_do_not_become_active() {
    let (_, _, context) = fixture();
    let mut unsupported = rule();
    unsupported.supported = false;
    let mut unloaded = rule();
    unloaded.id = "unloaded".into();
    unloaded.loaded = false;
    let report = assess(true, &context, &[unsupported, unloaded]).unwrap();
    assert_eq!(report.stage, Stage::CoverageVerified);
    assert_eq!(
        report.detections[0].blockers[0].code,
        B::UnsupportedDetection
    );
    assert_eq!(report.detections[1].blockers[0].code, B::RuleNotLoaded);
}

#[test]
fn malformed_and_unprofiled_coverage_cannot_activate() {
    let (record, profile, context) = fixture();
    let context = CoverageContext::parse(&serde_json::to_vec(&context).unwrap()).unwrap();
    for (record, profile) in [
        (b"invalid".as_slice(), Some(&profile)),
        (record.as_slice(), None),
    ] {
        let report =
            onboarding::assess_onboarding(true, record, profile, &context, &[rule()]).unwrap();
        assert_eq!(report.stage, Stage::Connected);
        assert!(!report.detections[0].active);
    }
}

#[test]
fn bounded_inventory_rejects_duplicates_bad_ids_and_excess_requirements() {
    let (_, _, context) = fixture();
    assert_eq!(
        assess(true, &context, &[rule(), rule()]),
        Err(E::DuplicateId)
    );
    assert_eq!(
        assess(
            true,
            &context,
            &vec![rule(); onboarding::MAX_DETECTIONS + 1]
        ),
        Err(E::BudgetExceeded)
    );
    for id in [
        "",
        "bad\nidentifier",
        "non-ascii-ß",
        &"x".repeat(onboarding::MAX_ID_BYTES + 1),
    ] {
        let mut bad = rule();
        bad.id = id.into();
        assert_eq!(assess(true, &context, &[bad]), Err(E::InvalidId));
    }
    let mut duplicate = rule();
    duplicate.state = vec![
        Requirement {
            id: "baseline".into(),
            status: R::Met
        };
        2
    ];
    assert_eq!(assess(true, &context, &[duplicate]), Err(E::DuplicateId));
    let mut excess = rule();
    excess.categories = vec![
        Requirement {
            id: "audit".into(),
            status: R::Met
        };
        onboarding::MAX_REQUIREMENTS + 1
    ];
    assert_eq!(assess(true, &context, &[excess]), Err(E::BudgetExceeded));
}

#[test]
fn maximum_inventory_remains_bounded_and_reports_every_blocker() {
    let (_, _, context) = fixture();
    let detections: Vec<_> = (0..onboarding::MAX_DETECTIONS)
        .map(|i| {
            let mut detection = rule();
            detection.id = format!("rule-{i}");
            let requirements: Vec<_> = (0..onboarding::MAX_REQUIREMENTS)
                .map(|j| Requirement {
                    id: format!("requirement-{j}"),
                    status: R::Unknown,
                })
                .collect();
            detection.permissions = requirements.clone();
            detection.categories = requirements.clone();
            detection.state = requirements;
            detection
        })
        .collect();
    let report = assess(true, &context, &detections).unwrap();
    assert_eq!(report.stage, Stage::CoverageVerified);
    assert_eq!(report.detections.len(), onboarding::MAX_DETECTIONS);
    for detection in report.detections {
        assert!(!detection.active);
        assert_eq!(detection.blockers.len(), 3 * onboarding::MAX_REQUIREMENTS);
    }
}

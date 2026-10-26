use serde_json::{Value, json};
use signal_event::SignalEvent;
use signal_rules::{
    RuleContext, RuleLimits,
    baseline::{HostDecision, Pack, Reason, Status},
};
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const MANIFEST: &str = include_str!("../../../rules/baselines/v1/manifest.json");
const DOCUMENTS: [(&str, &str); 5] = [
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
];
fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(5))
}
fn pack() -> Result<Pack> {
    Ok(Pack::from_documents(
        MANIFEST,
        &DOCUMENTS,
        RuleLimits::default(),
        &context(),
    )?)
}
fn decisions(pack: &Pack, ready: bool) -> Vec<HostDecision<'_>> {
    pack.manifest()
        .detections
        .iter()
        .map(|d| HostDecision {
            rule_id: &d.id,
            ready,
            normalization_profile: &d.normalization_profile,
        })
        .collect()
}
fn fixtures() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../tests/fixtures/security-requirements/catalog.json"
    ))?)
}
fn event(id: &str, case: usize) -> Result<SignalEvent> {
    let catalog = fixtures()?;
    let detection = catalog["detections"]
        .as_array()
        .ok_or("detections")?
        .iter()
        .find(|d| d["id"] == id)
        .ok_or("id")?;
    Ok(serde_json::from_value(
        detection["fixtures"][case]["events"][0].clone(),
    )?)
}

#[test]
fn all_fifteen_original_cases_have_explicit_assessments_and_original_finding_pins() -> Result {
    let pack = pack()?;
    let mut counts = [0; 3];
    for descriptor in &pack.manifest().detections {
        for case in 0..3 {
            let input = event(&descriptor.id, case)?;
            let ready = decisions(&pack, case != 2);
            let rows = pack.assess(&input, &ready, &context())?;
            let row = rows
                .iter()
                .find(|r| r.rule_id == descriptor.id)
                .ok_or("row")?;
            let expected = [Status::Match, Status::NoMatch, Status::Indeterminate][case];
            assert_eq!(row.status, expected, "{} case{case}", descriptor.id);
            assert_eq!(row.coverage_gap, case == 2);
            assert_eq!(row.event_id, input.id);
            assert_eq!(row.finding.is_some(), case == 0);
            if let Some(finding) = &row.finding {
                let original = pack.rules().evaluate(&input)?;
                assert!(original.contains(finding));
                assert_eq!(finding.event_ids, [input.id]);
            }
            counts[case] += 1;
        }
    }
    assert_eq!(counts, [5, 5, 5]);
    Ok(())
}

#[test]
fn fields_null_wrong_type_unknown_semantics_and_missing_are_explicit_gaps() -> Result {
    let pack = pack()?;
    let ready = decisions(&pack, true);
    for (id, name, invalid) in [
        ("SIG-D01", "actor_kind", json!("unknown-native-identity")),
        ("SIG-D01", "outcome", json!("unknown")),
        ("SIG-D03", "mfa_used", json!("false")),
        ("SIG-D07", "privileged", json!(null)),
        ("SIG-D05", "outcome", json!(false)),
        ("SIG-D02", "action", json!(7)),
    ] {
        let mut input = event(id, 0)?;
        input.attributes["security"][name] = invalid;
        let rows = pack.assess(&input, &ready, &context())?;
        let row = rows.iter().find(|r| r.rule_id == id).ok_or("row")?;
        assert_eq!(row.status, Status::Indeterminate, "{id}/{name}");
        assert!(row.coverage_gap && row.finding.is_none());
        assert_eq!(row.reason, Some(Reason::MissingOrInvalidField));
    }
    let mut input = event("SIG-D07", 0)?;
    input.attributes["security"]
        .as_object_mut()
        .ok_or("security")?
        .remove("privileged");
    assert_eq!(
        pack.assess(&input, &ready, &context())?[4].status,
        Status::Indeterminate
    );
    Ok(())
}

#[test]
fn trusted_host_gates_ignore_forged_event_readiness_and_profile_claims() -> Result {
    let pack = pack()?;
    let mut input = event("SIG-D07", 0)?;
    input.attributes.insert(
        "readiness".into(),
        json!({"ready":true,"coverage":"verified","profile":"kubernetes-audit-v1"}),
    );
    let blocked = decisions(&pack, false);
    let rows = pack.assess(&input, &blocked, &context())?;
    assert_eq!(rows[4].reason, Some(Reason::HostPrerequisitesUnverified));
    assert!(rows.iter().all(|r| r.finding.is_none()));
    let mut unsupported = decisions(&pack, true);
    unsupported[4].normalization_profile = "request-only-or-metadata";
    assert_eq!(
        pack.assess(&input, &unsupported, &context())?[4].reason,
        Some(Reason::UnsupportedNormalization)
    );
    let ready = decisions(&pack, true);
    assert!(pack.assess(&input, &ready[..4], &context()).is_err());
    let mut duplicate_full = decisions(&pack, true);
    duplicate_full[1].rule_id = "SIG-D01";
    assert!(pack.assess(&input, &duplicate_full, &context()).is_err());
    let mut foreign = decisions(&pack, true);
    foreign[1].rule_id = "private-unloaded-rule";
    assert!(pack.assess(&input, &foreign, &context()).is_err());
    let duplicate = [
        HostDecision {
            rule_id: "SIG-D07",
            ready: true,
            normalization_profile: "kubernetes-audit-v1",
        },
        HostDecision {
            rule_id: "SIG-D07",
            ready: true,
            normalization_profile: "kubernetes-audit-v1",
        },
    ];
    assert!(pack.assess(&input, &duplicate, &context()).is_err());
    Ok(())
}

#[test]
fn federated_and_unrelated_actions_are_outside_native_mfa_applicability() -> Result {
    let pack = pack()?;
    let ready = decisions(&pack, true);
    for actor in ["AssumedRole", "FederatedUser", "IdentityCenterUser"] {
        let mut input = event("SIG-D03", 0)?;
        input.attributes["security"]["actor_kind"] = json!(actor);
        input.attributes["security"]
            .as_object_mut()
            .ok_or("security")?
            .remove("mfa_used");
        let row = pack.assess(&input, &ready, &context())?.remove(2);
        assert_eq!(row.status, Status::NoMatch);
        assert!(!row.applicable && !row.coverage_gap && row.finding.is_none());
    }
    let mut unrelated = event("SIG-D03", 0)?;
    unrelated.attributes["security"] = json!({"action":"resource.activity"});
    let rows = pack.assess(&unrelated, &ready, &context())?;
    assert_eq!(rows[2].reason, Some(Reason::OutsideApplicability));
    Ok(())
}

#[test]
fn pack_refuses_inventory_version_hash_path_and_prerequisite_contract_drift() -> Result {
    let parsed: Value = serde_json::from_str(MANIFEST)?;
    for (field, value) in [
        ("schema_version", json!(2)),
        ("revision", json!("2.0.0")),
        ("activation", json!("automatic")),
        ("unknown", json!(true)),
    ] {
        let mut bad = parsed.clone();
        bad[field] = value;
        assert!(
            Pack::from_documents(
                &serde_json::to_string(&bad)?,
                &DOCUMENTS,
                RuleLimits::default(),
                &context()
            )
            .is_err()
        );
    }
    for (field, value) in [
        ("rule_file", json!("../foreign.yaml")),
        ("rule_sha256", json!("00")),
        ("required_fields", json!([])),
        ("actions", json!(["foreign"])),
        ("source_profiles", json!(["S03"])),
    ] {
        let mut bad = parsed.clone();
        bad["detections"][0][field] = value;
        assert!(
            Pack::from_documents(
                &serde_json::to_string(&bad)?,
                &DOCUMENTS,
                RuleLimits::default(),
                &context()
            )
            .is_err(),
            "{field}"
        );
    }
    let oversized_name = "S".repeat(100_000);
    let mut long_names = DOCUMENTS;
    long_names[0].0 = &oversized_name;
    assert!(
        Pack::from_documents(MANIFEST, &long_names, RuleLimits::default(), &context()).is_err()
    );
    let mut bad = DOCUMENTS;
    bad[1] = DOCUMENTS[0];
    assert!(Pack::from_documents(MANIFEST, &bad, RuleLimits::default(), &context()).is_err());
    assert!(
        Pack::from_documents(MANIFEST, &DOCUMENTS[..4], RuleLimits::default(), &context()).is_err()
    );
    assert!(
        Pack::from_documents(
            &"x".repeat(65_537),
            &DOCUMENTS,
            RuleLimits::default(),
            &context()
        )
        .is_err()
    );
    let edited = DOCUMENTS[0].1.replace("Root", "IAMUser");
    let mut edited_documents = DOCUMENTS;
    edited_documents[0].1 = &edited;
    let mut edited_manifest = parsed.clone();
    use sha2::{Digest, Sha256};
    edited_manifest["detections"][0]["rule_sha256"] = json!(
        Sha256::digest(edited.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert!(
        Pack::from_documents(
            &serde_json::to_string(&edited_manifest)?,
            &edited_documents,
            RuleLimits::default(),
            &context()
        )
        .is_err()
    );
    let duplicate = MANIFEST.replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1, \"schema_version\": 1",
        1,
    );
    assert!(
        Pack::from_documents(&duplicate, &DOCUMENTS, RuleLimits::default(), &context()).is_err()
    );
    Ok(())
}

#[test]
fn metadata_changes_commitment_and_cancelled_or_expired_work_refuses() -> Result {
    let original = pack()?;
    let mut metadata: Value = serde_json::from_str(MANIFEST)?;
    metadata["detections"][0]["investigation"] = json!("Inspect authorized synthetic context.");
    let changed = Pack::from_documents(
        &serde_json::to_string(&metadata)?,
        &DOCUMENTS,
        RuleLimits::default(),
        &context(),
    )?;
    assert_ne!(original.content_sha256(), changed.content_sha256());
    assert_eq!(original.content_sha256(), pack()?.content_sha256());
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(Pack::from_documents(MANIFEST, &DOCUMENTS, RuleLimits::default(), &cancelled).is_err());
    let expired = RuleContext::new(Duration::ZERO);
    assert!(
        original
            .assess(&event("SIG-D01", 0)?, &decisions(&original, true), &expired)
            .is_err()
    );
    Ok(())
}

#[test]
fn event_validation_work_is_bounded_before_trimming_or_tag_iteration() -> Result {
    let pack = pack()?;
    let ready = decisions(&pack, true);
    let mut input = event("SIG-D01", 0)?;
    input.source.source_type = " ".repeat(1024 * 1024 + 1);
    assert!(matches!(
        pack.assess(&input, &ready, &context()),
        Err(signal_rules::RuleError::Limit)
    ));
    input = event("SIG-D01", 0)?;
    input.tags = vec!["tag".into(); 257];
    assert!(matches!(
        pack.assess(&input, &ready, &context()),
        Err(signal_rules::RuleError::Limit)
    ));
    input = event("SIG-D01", 0)?;
    input.message = Some(" ".repeat(1024 * 1024));
    assert!(matches!(
        pack.assess(&input, &ready, &context()),
        Err(signal_rules::RuleError::Limit)
    ));
    input = event("SIG-D01", 0)?;
    let original = input.clone();
    input.attributes.insert(
        "private".into(),
        json!({"nested":{"opaque":"x".repeat(1024*1024+1)}}),
    );
    let before = input.attributes["private"].clone();
    let rows = pack.assess(&input, &ready, &context())?;
    assert_eq!(rows[0].status, Status::Match);
    assert_eq!(
        rows[0].finding,
        pack.assess(&original, &ready, &context())?[0].finding
    );
    assert_eq!(input.attributes["private"], before);
    Ok(())
}

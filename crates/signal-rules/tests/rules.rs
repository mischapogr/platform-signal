use signal_event::{IngestEvent, SignalEvent};
use signal_rules::{RuleContext, RuleError, RuleLimits, RuleSet};
use std::time::Duration;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn yaml(groups: &str) -> String {
    format!(
        "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: auth.failure\n  name: Login failure\nspec:\n  severity: medium\n  match:\n{groups}\n  finding:\n    title: Login failure detected\n"
    )
}
fn event() -> std::result::Result<SignalEvent, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str::<IngestEvent>(r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"application","name":"api"},"message":"login failed","resource":{"kind":"service","id":"api","account_id":"acct"},"attributes":{"user":{"name":"alice"},"vendor.owner":{"name":"exact"},"large":18446744073709551615,"number":1,"nil":null,"flag":true,"items":[1,"a"]}}"#)?.normalize("2026-10-06T12:01:00Z".parse()?)?)
}
fn matched(groups: &str) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    Ok(
        !RuleSet::from_yaml_documents([yaml(groups)], RuleLimits::default())?
            .evaluate(&event()?)?
            .is_empty(),
    )
}
#[test]
fn all_any_and_both_groups() -> Result {
    assert!(matched(
        "    all:\n      - field: source.type\n        eq: application\n      - field: message\n        contains: login failed"
    )?);
    assert!(!matched(
        "    all:\n      - field: message\n        contains: Login"
    )?);
    assert!(matched(
        "    any:\n      - field: missing\n        eq: x\n      - field: message\n        contains: failed"
    )?);
    assert!(!matched(
        "    all:\n      - field: source.type\n        eq: wrong\n    any:\n      - field: message\n        contains: failed"
    )?);
    assert!(!matched(
        "    all:\n      - field: source.type\n        eq: application\n    any:\n      - field: message\n        contains: wrong"
    )?);
    assert!(matched(
        "    all:\n      - field: source.type\n        eq: application\n    any:\n      - field: message\n        contains: failed"
    )?);
    Ok(())
}
#[test]
fn missing_and_null_are_distinct() -> Result {
    for predicate in ["eq: null", "neq: null", "eq: x", "neq: x", "exists: true"] {
        assert!(!matched(&format!(
            "    all:\n      - field: attributes.absent\n        {predicate}"
        ))?);
    }
    assert!(matched(
        "    all:\n      - field: attributes.absent\n        exists: false"
    )?);
    assert!(matched(
        "    all:\n      - field: attributes.nil\n        eq: null\n      - field: attributes.nil\n        exists: true"
    )?);
    assert!(!matched(
        "    all:\n      - field: attributes.nil\n        neq: null"
    )?);
    Ok(())
}
#[test]
fn typed_nested_values_and_namespaces() -> Result {
    for (field, value) in [
        ("attributes.user.name", "alice"),
        ("attributes.vendor.owner.name", "exact"),
        ("attributes.large", "18446744073709551615"),
        ("attributes.user", "{name: alice}"),
        ("attributes.items", "[1, a]"),
        ("resource.account_id", "acct"),
        ("attributes.flag", "true"),
    ] {
        assert!(
            matched(&format!(
                "    all:\n      - field: {field}\n        eq: {value}"
            ))?,
            "{field}"
        );
    }
    assert!(!matched(
        "    all:\n      - field: attributes.number\n        eq: '1'"
    )?);
    assert!(!matched(
        "    all:\n      - field: attributes.number\n        eq: 1.0"
    )?);
    assert!(!matched(
        "    all:\n      - field: attributes.number\n        contains: '1'"
    )?);
    Ok(())
}
#[test]
fn replay_findings_and_sorted_multiple_rules() -> Result {
    let a = yaml("    all:\n      - field: message\n        exists: true");
    let b = a.replace("id: auth.failure", "id: b.failure");
    let rules = RuleSet::from_yaml_documents([b, a], RuleLimits::default())?;
    let event = event()?;
    let findings = rules.evaluate(&event)?;
    assert_eq!(findings, rules.evaluate(&event)?);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].rule_id, "auth.failure");
    assert_eq!(findings[0].created_at, event.observed_at);
    assert_ne!(findings[0].id, findings[1].id);
    Ok(())
}

#[test]
fn readiness_suppresses_matching_rules_and_preserves_enabled_finding_identity() -> Result {
    let a = yaml("    all:\n      - field: message\n        exists: true");
    let b = a.replace("id: auth.failure", "id: b.failure");
    let rules = RuleSet::from_yaml_documents([b, a], RuleLimits::default())?;
    assert_eq!(
        rules.rule_ids().collect::<Vec<_>>(),
        ["auth.failure", "b.failure"]
    );
    let event = event()?;
    let ordinary = rules.evaluate(&event)?;
    let context = RuleContext::new(Duration::from_secs(5));
    let selected = rules.evaluate_ready_with_context(
        &event,
        &context,
        &[("b.failure", false), ("auth.failure", true)],
    )?;
    assert_eq!(selected, vec![ordinary[0].clone()]);
    assert!(
        rules
            .evaluate_ready_with_context(
                &event,
                &context,
                &[("auth.failure", false), ("b.failure", false)]
            )?
            .is_empty()
    );
    assert_eq!(
        rules.evaluate_ready_with_context(
            &event,
            &context,
            &[("auth.failure", true), ("b.failure", true)]
        )?,
        ordinary
    );
    // A new blocked decision is applied immediately; the engine caches no permit.
    assert!(
        rules
            .evaluate_ready_with_context(
                &event,
                &context,
                &[("auth.failure", false), ("b.failure", false)]
            )?
            .is_empty()
    );
    Ok(())
}

#[test]
fn incomplete_duplicate_foreign_and_oversized_readiness_fail_closed() -> Result {
    let a = yaml("    all:\n      - field: message\n        exists: true");
    let b = a.replace("id: auth.failure", "id: b.failure");
    let rules = RuleSet::from_yaml_documents([a, b], RuleLimits::default())?;
    let event = event()?;
    let context = RuleContext::new(Duration::from_secs(5));
    let oversized = "x".repeat(257);
    for readiness in [
        vec![],
        vec![("auth.failure", true)],
        vec![("auth.failure", true), ("foreign", true)],
        vec![("auth.failure", true), ("auth.failure", true)],
        vec![("auth.failure", true), ("", true)],
        vec![("auth.failure", true), (oversized.as_str(), true)],
        vec![
            ("auth.failure", true),
            ("b.failure", true),
            ("foreign", true),
        ],
    ] {
        assert!(matches!(
            rules.evaluate_ready_with_context(&event, &context, &readiness),
            Err(RuleError::Invalid("rule readiness inventory"))
        ));
    }
    Ok(())
}

#[test]
fn readiness_keeps_cancellation_and_deadline_checks_even_when_all_rules_blocked() -> Result {
    let rules = RuleSet::from_yaml_documents(
        [yaml(
            "    all:\n      - field: message\n        exists: true",
        )],
        RuleLimits::default(),
    )?;
    let event = event()?;
    let context = RuleContext::new(Duration::from_secs(5));
    context.cancellation.cancel();
    assert!(matches!(
        rules.evaluate_ready_with_context(&event, &context, &[("auth.failure", false)]),
        Err(RuleError::Cancelled)
    ));
    let expired = RuleContext::new(Duration::ZERO);
    assert!(matches!(
        rules.evaluate_ready_with_context(&event, &expired, &[("auth.failure", false)]),
        Err(RuleError::Timeout)
    ));
    Ok(())
}

#[test]
fn empty_loaded_inventory_requires_empty_readiness_and_still_validates_events() -> Result {
    let rules = RuleSet::from_yaml_documents(Vec::<String>::new(), RuleLimits::default())?;
    let mut event = event()?;
    let context = RuleContext::new(Duration::from_secs(5));
    assert!(
        rules
            .evaluate_ready_with_context(&event, &context, &[])?
            .is_empty()
    );
    assert!(
        rules
            .evaluate_ready_with_context(&event, &context, &[("foreign", false)])
            .is_err()
    );
    event.schema_version = 999;
    assert!(matches!(
        rules.evaluate_ready_with_context(&event, &context, &[]),
        Err(RuleError::Invalid("event"))
    ));
    Ok(())
}
#[test]
fn invalid_documents_fail_without_echoing_yaml() -> Result {
    let good = yaml("    all:\n      - field: message\n        exists: true");
    let invalid = [
        good.replace("signal.dev/v1", "signal.dev/v2"),
        good.replace("kind: Rule", "kind: Other"),
        good.replace("medium", "info"),
        good.replace("exists: true", "exists: 'true'"),
        good.replace("exists: true", "contains: 42"),
        good.replace("exists: true", "eq: x\n        neq: y"),
        good.replace("exists: true", "unknown: x"),
        good.replace(
            "name: Login failure",
            "name: Login failure\n  secret: TOKEN_SECRET",
        ),
        format!("{good}\n---\n{good}"),
        good.replace("exists: true", "exists: true\n        exists: false"),
        good.replace("exists: true", "eq: &secret TOKEN_SECRET"),
        good.replace("exists: true", "eq: !secret TOKEN_SECRET"),
        yaml("    all: []"),
        yaml("    all: null"),
        yaml("    any: []"),
        yaml("    all:\n      - field: attributes..x\n        exists: true"),
        yaml(
            "    all:\n      - field: message\n        eq: [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
        ),
    ];
    for text in invalid {
        let Err(error) = RuleSet::from_yaml_documents([text], RuleLimits::default()) else {
            return Err("invalid rule accepted".into());
        };
        assert!(!error.to_string().contains("TOKEN_SECRET"));
    }
    assert!(matches!(
        RuleSet::from_yaml_documents([&good, &good], RuleLimits::default()),
        Err(RuleError::DuplicateId)
    ));
    Ok(())
}
#[test]
fn resource_bounds() -> Result {
    let good = yaml("    all:\n      - field: message\n        exists: true");
    let limits = RuleLimits {
        max_document_bytes: 8,
        ..Default::default()
    };
    assert!(matches!(
        RuleSet::from_yaml_documents([&good], limits),
        Err(RuleError::Limit)
    ));
    let limits = RuleLimits {
        max_rules: 1,
        ..Default::default()
    };
    assert!(matches!(
        RuleSet::from_yaml_documents([&good, &good], limits),
        Err(RuleError::Limit)
    ));
    let limits = RuleLimits {
        max_predicates: 1,
        ..Default::default()
    };
    assert!(matches!(
        RuleSet::from_yaml_documents(
            [yaml(
                "    all:\n      - field: message\n        exists: true\n      - field: message\n        exists: true"
            )],
            limits
        ),
        Err(RuleError::Limit)
    ));
    Ok(())
}
#[tokio::test]
async fn real_directory_load_bounds_and_cancellation() -> Result {
    let dir = tempfile::tempdir()?;
    let good = yaml("    all:\n      - field: message\n        exists: true");
    std::fs::write(dir.path().join("a.yaml"), &good)?;
    std::fs::write(dir.path().join("ignored.txt"), "not yaml")?;
    let paths = vec![dir.path().to_path_buf()];
    let rules = RuleSet::load(
        &paths,
        RuleLimits::default(),
        RuleContext::new(Duration::from_secs(5)),
    )
    .await?;
    assert_eq!(rules.len(), 1);
    let cancelled = RuleContext::new(Duration::from_secs(5));
    cancelled.cancellation.cancel();
    assert!(matches!(
        RuleSet::load(&paths, RuleLimits::default(), cancelled).await,
        Err(RuleError::Cancelled)
    ));
    assert!(matches!(
        RuleSet::load(
            &paths,
            RuleLimits::default(),
            RuleContext::new(Duration::ZERO)
        )
        .await,
        Err(RuleError::Timeout)
    ));
    let limits = RuleLimits {
        max_directory_entries: 1,
        ..Default::default()
    };
    assert!(matches!(
        RuleSet::load(&paths, limits, RuleContext::new(Duration::from_secs(5))).await,
        Err(RuleError::Limit)
    ));
    std::fs::write(dir.path().join("b.yml"), &good)?;
    assert!(matches!(
        RuleSet::load(
            &paths,
            RuleLimits::default(),
            RuleContext::new(Duration::from_secs(5))
        )
        .await,
        Err(RuleError::DuplicateId)
    ));
    #[cfg(unix)]
    {
        std::fs::remove_file(dir.path().join("b.yml"))?;
        std::os::unix::fs::symlink(dir.path().join("a.yaml"), dir.path().join("link.yaml"))?;
        assert!(matches!(
            RuleSet::load(
                &paths,
                RuleLimits::default(),
                RuleContext::new(Duration::from_secs(5))
            )
            .await,
            Err(RuleError::Invalid("symlink"))
        ));
    }
    Ok(())
}

#[test]
fn exact_integer_boundaries_and_canonical_timestamps() -> Result {
    let rule = yaml(
        "    all:\n      - field: timestamp\n        eq: '2026-10-06T12:00:00Z'\n      - field: observed_at\n        eq: '2026-10-06T12:01:00Z'",
    );
    assert_eq!(
        RuleSet::from_yaml_documents([rule], RuleLimits::default())?
            .evaluate(&event()?)?
            .len(),
        1
    );
    for value in [
        "18446744073709551616",
        "-9223372036854775809",
        "0x10000000000000000",
    ] {
        assert!(
            RuleSet::from_yaml_documents(
                [yaml(&format!(
                    "    all:\n      - field: attributes.large\n        eq: {value}"
                ))],
                RuleLimits::default()
            )
            .is_err()
        );
    }
    assert!(matched(
        "    all:\n      - field: attributes.large\n        eq: 18446744073709551615"
    )?);
    Ok(())
}
#[test]
fn evaluation_honors_deadline_and_cancellation() -> Result {
    let rules = RuleSet::from_yaml_documents(
        [yaml(
            "    all:\n      - field: message\n        exists: true",
        )],
        RuleLimits::default(),
    )?;
    let context = RuleContext::new(Duration::from_secs(5));
    context.cancellation.cancel();
    assert!(matches!(
        rules.evaluate_with_context(&event()?, &context),
        Err(RuleError::Cancelled)
    ));
    assert!(matches!(
        rules.evaluate_with_context(&event()?, &RuleContext::new(Duration::ZERO)),
        Err(RuleError::Timeout)
    ));
    Ok(())
}

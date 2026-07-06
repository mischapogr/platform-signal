//! Independent boolean truth model; seed 0x51a10e03, 512 rule/event pairs.
use signal_event::{IngestEvent, SignalEvent};
use signal_rules::{RuleError, RuleLimits, RuleSet};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn yaml(groups: &str) -> String {
    format!(
        "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: property.check\n  name: Property\nspec:\n  severity: medium\n  match:\n{groups}  finding:\n    title: Match\n"
    )
}
fn event(flag: bool) -> std::result::Result<SignalEvent, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value::<IngestEvent>(
        serde_json::json!({"timestamp":"2026-10-06T12:00:00Z",
        "source":{"type":"test"},"attributes":{"flag":flag,"null":null}}),
    )?
    .normalize("2026-10-06T12:00:01Z".parse()?)?)
}
fn predicate(index: usize, flag: bool) -> (&'static str, bool) {
    match index {
        0 => ("field: attributes.flag\n        eq: true", flag),
        1 => ("field: attributes.flag\n        neq: true", !flag),
        2 => ("field: attributes.flag\n        exists: true", true),
        3 => ("field: attributes.absent\n        exists: false", true),
        4 => ("field: attributes.absent\n        neq: true", false),
        5 => ("field: attributes.absent\n        exists: true", false),
        _ => ("field: attributes.null\n        eq: null", true),
    }
}

#[test]
fn seeded_predicates_match_independent_truth_model() -> Result {
    let mut seed = 0x51a10e03;
    for iteration in 0..512 {
        let flag = next(&mut seed) & 1 == 0;
        let predicates = (0..4)
            .map(|_| predicate((next(&mut seed) % 7) as usize, flag))
            .collect::<Vec<_>>();
        let all = predicates[0].1 && predicates[1].1;
        let any = predicates[2].1 || predicates[3].1;
        let mut groups = String::new();
        if iteration % 3 != 1 {
            groups.push_str(&format!(
                "    all:\n      - {}\n      - {}\n",
                predicates[0].0, predicates[1].0
            ));
        }
        if iteration % 3 != 0 {
            groups.push_str(&format!(
                "    any:\n      - {}\n      - {}\n",
                predicates[2].0, predicates[3].0
            ));
        }
        let expected = match iteration % 3 {
            0 => all,
            1 => any,
            _ => all && any,
        };
        let rules = RuleSet::from_yaml_documents([yaml(&groups)], RuleLimits::default())?;
        let event = event(flag)?;
        let findings = rules.evaluate(&event)?;
        assert_eq!(!findings.is_empty(), expected, "iteration {iteration}");
        assert_eq!(findings, rules.evaluate(&event)?);
        assert!(findings.len() <= 1);
    }
    Ok(())
}

#[test]
fn yaml_dictionary_limits_duplicates_and_schema_are_safe() -> Result {
    let limits = RuleLimits {
        max_document_bytes: 2048,
        max_total_bytes: 4096,
        max_value_nodes: 128,
        max_depth: 8,
        ..RuleLimits::default()
    };
    let valid = yaml("    all:\n      - field: attributes.flag\n        eq: true\n");
    let sentinel = "SENTINEL_PRIVATE_VALUE";
    for depth in [1, 4, 8, 32, 128] {
        for value in [
            format!("&a {sentinel}"),
            format!("!custom {sentinel}"),
            format!("{}{}{}", "[".repeat(depth), sentinel, "]".repeat(depth)),
        ] {
            // Depth >8 must reject; anchors and unknown tags must reject at every depth.
            if depth <= 8 && value.starts_with('[') {
                continue;
            }
            let text = valid.replace("eq: true", &format!("eq: {value}"));
            assert!(text.len() <= 65536);
            let error = RuleSet::from_yaml_documents([text], limits.clone())
                .err()
                .ok_or("unsafe rule accepted")?;
            assert!(!error.to_string().contains(sentinel));
        }
    }
    // An alias expansion dictionary stays small; aliases are prohibited before expansion.
    for aliases in [1, 16, 128] {
        let value = format!("&a [{sentinel},{}]", vec!["*a"; aliases].join(","));
        let error = RuleSet::from_yaml_documents(
            [valid.replace("eq: true", &format!("eq: {value}"))],
            limits.clone(),
        )
        .err()
        .ok_or("alias accepted")?;
        assert!(!error.to_string().contains(sentinel));
    }
    for size in [2049, 4096, 65536] {
        let error = RuleSet::from_yaml_documents(["x".repeat(size)], limits.clone())
            .err()
            .ok_or("oversized rule accepted")?;
        assert!(matches!(error, RuleError::Limit));
    }
    assert!(matches!(
        RuleSet::from_yaml_documents([&valid, &valid], limits.clone()),
        Err(RuleError::DuplicateId)
    ));
    for replacement in [
        valid.replace("signal.dev/v1", "signal.dev/v99"),
        valid.replace("kind: Rule", "kind: Unknown"),
        valid.replace("eq: true", "eq: true\n        eq: false"),
        valid.replace("attributes.flag", "attributes..flag"),
    ] {
        assert!(RuleSet::from_yaml_documents([replacement], limits.clone()).is_err());
    }
    let end = valid.find("spec:").ok_or("missing spec")?;
    for cut in 0..end {
        assert!(RuleSet::from_yaml_documents([&valid[..cut]], limits.clone()).is_err());
    }
    Ok(())
}

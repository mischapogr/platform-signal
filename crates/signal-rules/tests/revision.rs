use signal_event::IngestEvent;
use signal_rules::{RuleContext, RuleError, RuleLimits, RuleSet};
use std::{
    io::{self, Write},
    time::Duration,
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn document(condition: &str) -> String {
    format!(
        "apiVersion: signal.dev/v1\nkind: Rule\nmetadata: {{id: login, name: Login}}\nspec:\n  severity: medium\n  match:\n    all:\n      - field: attributes.value\n        {condition}\n  finding: {{title: Login found}}\n"
    )
}
fn rules(document: &str) -> std::result::Result<RuleSet, RuleError> {
    RuleSet::from_yaml_documents([document], RuleLimits::default())
}
fn projection(rules: &RuleSet) -> std::result::Result<Vec<u8>, RuleError> {
    let mut bytes = Vec::new();
    rules.write_revision(
        &mut bytes,
        1_048_576,
        &RuleContext::new(Duration::from_secs(5)),
    )?;
    Ok(bytes)
}
#[test]
fn revision_is_stable_for_document_order_format_and_nested_object_keys() -> Result {
    let a = document("eq: {z: [1, {b: false, a: null}], a: 2}");
    let reordered = document("eq: {a: 2, z: [1, {a: null, b: false}]}");
    let b = a.replace("id: login", "id: second");
    let first = RuleSet::from_yaml_documents([&a, &b], RuleLimits::default())?;
    let second = RuleSet::from_yaml_documents([&b, &reordered], RuleLimits::default())?;
    let expected = projection(&first)?;
    assert_eq!(expected, projection(&second)?);
    let comment = format!(
        "# private input formatting\n{}",
        a.replace("kind: Rule", "kind: 'Rule'")
    );
    assert_eq!(projection(&rules(&a)?)?, projection(&rules(&comment)?)?);
    assert!(expected.starts_with(b"platform-signal/rules-revision/v1\0["));
    Ok(())
}
#[test]
fn revision_captures_metadata_output_severity_and_group_semantics() -> Result {
    let a = document("eq: null");
    let base = projection(&rules(&a)?)?;
    for changed in [
        a.replace("id: login", "id: other"),
        a.replace("name: Login", "name: Changed"),
        a.replace("medium", "critical"),
        a.replace("title: Login found", "title: Changed"),
        a.replace("all:", "any:"),
        a.replace("attributes.value", "attributes.other"),
    ] {
        assert_ne!(base, projection(&rules(&changed)?)?);
    }
    let both = a.replace(
        "  finding:",
        "    any:\n      - field: message\n        exists: true\n  finding:",
    );
    assert_ne!(base, projection(&rules(&both)?)?);
    Ok(())
}
#[test]
fn revision_distinguishes_operators_null_types_and_array_order() -> Result {
    let mut projections = Vec::new();
    for condition in [
        "eq: null",
        "neq: null",
        "exists: false",
        "exists: true",
        "eq: 'true'",
        "eq: true",
        "eq: 1",
        "eq: 1.0",
        "eq: '1'",
        "contains: '1'",
        "eq: [1, 'x']",
        "eq: ['x', 1]",
        "eq: {a: 1}",
    ] {
        let bytes = projection(&rules(&document(condition))?)?;
        assert!(!projections.contains(&bytes));
        projections.push(bytes);
    }
    Ok(())
}
#[test]
fn revision_has_exact_byte_bounds_and_an_empty_domain() -> Result {
    let empty = RuleSet::default();
    let expected = projection(&empty)?;
    assert_eq!(expected, b"platform-signal/rules-revision/v1\0[]");
    for limit in [0, 64 * 1024 * 1024 + 1] {
        let mut bytes = Vec::new();
        assert!(matches!(
            empty.write_revision(&mut bytes, limit, &RuleContext::new(Duration::from_secs(5))),
            Err(RuleError::Invalid(_))
        ));
        assert!(bytes.is_empty());
    }
    let rules = rules(&document(r#"eq: 'unicode € "quoted"'"#))?;
    let expected = projection(&rules)?;
    let mut bytes = Vec::new();
    rules.write_revision(
        &mut bytes,
        expected.len(),
        &RuleContext::new(Duration::from_secs(5)),
    )?;
    assert_eq!(bytes, expected);
    let mut short = Vec::new();
    assert!(matches!(
        rules.write_revision(
            &mut short,
            expected.len() - 1,
            &RuleContext::new(Duration::from_secs(5))
        ),
        Err(RuleError::Limit)
    ));
    assert!(short.len() < expected.len());
    Ok(())
}
struct Partial(Vec<u8>);
impl Write for Partial {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let size = bytes.len().min(1);
        self.0.extend_from_slice(&bytes[..size]);
        Ok(size)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn revision_handles_partial_and_failed_sinks_without_echoing_content() -> Result {
    let rules = rules(&document("eq: 'PRIVATE_RULE_CANARY'"))?;
    let mut partial = Partial(Vec::new());
    rules.write_revision(
        &mut partial,
        1_048_576,
        &RuleContext::new(Duration::from_secs(5)),
    )?;
    assert_eq!(partial.0, projection(&rules)?);
    struct Failed;
    impl Write for Failed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("PRIVATE_SINK_CANARY"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = rules
        .write_revision(
            &mut Failed,
            1_048_576,
            &RuleContext::new(Duration::from_secs(5)),
        )
        .err()
        .ok_or("missing I/O rejection")?;
    assert!(matches!(error, RuleError::Io));
    assert!(!format!("{error:?} {error}").contains("PRIVATE_"));
    Ok(())
}
#[test]
fn revision_rechecks_original_clock_and_cancellation_after_sink_handoff() -> Result {
    struct Cancel<'a>(&'a RuleContext, Vec<u8>);
    impl Write for Cancel<'_> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.1.extend_from_slice(b);
            self.0.cancellation.cancel();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let rules = rules(&document("eq: null"))?;
    let context = RuleContext::new(Duration::from_secs(5));
    let mut writer = Cancel(&context, Vec::new());
    assert!(matches!(
        rules.write_revision(&mut writer, 1_048_576, &context),
        Err(RuleError::Cancelled)
    ));
    assert!(!writer.1.is_empty());
    let mut untouched = Vec::new();
    assert!(matches!(
        rules.write_revision(&mut untouched, 1_048_576, &context),
        Err(RuleError::Cancelled)
    ));
    assert!(untouched.is_empty());
    struct Late<'a>(&'a RuleContext, usize);
    impl Write for Late<'_> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.1 += b.len();
            while tokio::time::Instant::now() < self.0.deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let context = RuleContext::new(Duration::from_millis(20));
    let mut writer = Late(&context, 0);
    assert!(matches!(
        rules.write_revision(&mut writer, 1_048_576, &context),
        Err(RuleError::Timeout)
    ));
    assert!(writer.1 > 0);
    Ok(())
}
#[tokio::test]
async fn revision_keeps_loaded_definitions_after_source_rewrite_and_removal() -> Result {
    let root = tempfile::tempdir()?;
    let path = root.path().join("rule.yaml");
    let original = document("eq: null");
    std::fs::write(&path, &original)?;
    let loaded = RuleSet::load(
        &[root.path().into()],
        RuleLimits::default(),
        RuleContext::new(Duration::from_secs(5)),
    )
    .await?;
    let before = projection(&loaded)?;
    assert_eq!(before, projection(&rules(&original)?)?);
    let event=serde_json::from_str::<IngestEvent>(r#"{"timestamp":"2026-10-09T08:00:00Z","source":{"type":"application"},"attributes":{"value":null}}"#)?.normalize("2026-10-09T08:01:00Z".parse()?)?;
    let findings = loaded.evaluate(&event)?;
    assert_eq!(findings.len(), 1);
    std::fs::write(&path, document("eq: 'changed'"))?;
    assert_eq!(before, projection(&loaded)?);
    assert_eq!(findings, loaded.evaluate(&event)?);
    std::fs::remove_file(&path)?;
    assert_eq!(before, projection(&loaded)?);
    assert_eq!(findings, loaded.evaluate(&event)?);
    Ok(())
}

#[test]
fn revision_bounds_large_deep_values_without_retaining_a_second_projection() -> Result {
    let mut value = serde_json::Value::String("\\\"€".repeat(4096));
    for _ in 0..16 {
        value = serde_json::Value::Array(vec![value]);
    }
    let document = document(&format!("eq: {}", serde_json::to_string(&value)?));
    let rules = rules(&document)?;
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    assert!(matches!(
        rules.write_revision(&mut count, 1024, &RuleContext::new(Duration::from_secs(5))),
        Err(RuleError::Limit)
    ));
    assert!(count.0 > 0 && count.0 <= 1024);
    let mut count = Count(0);
    rules.write_revision(
        &mut count,
        1_048_576,
        &RuleContext::new(Duration::from_secs(5)),
    )?;
    assert!(count.0 > 1024);
    Ok(())
}

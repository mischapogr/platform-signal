use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_event::{IngestEvent, Severity, SignalEvent, ValidationError};
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn now() -> Result<DateTime<Utc>> {
    Ok("2026-10-06T12:00:01Z".parse()?)
}
fn minimal() -> Value {
    json!({"timestamp":"2026-10-06T12:00:00Z", "source":{"type":"application"}, "message":"hello"})
}
fn normalize(value: Value) -> Result<SignalEvent> {
    Ok(serde_json::from_value::<IngestEvent>(value)?.normalize(now()?)?)
}

#[test]
fn minimal_event_normalizes_defaults_and_generates_unique_ids() -> Result {
    let first = normalize(minimal())?;
    let second = normalize(minimal())?;
    assert_eq!(first.schema_version, 1);
    assert_eq!(first.severity, Severity::Info);
    assert_eq!(first.observed_at, now()?);
    assert_eq!(first.id.get_version_num(), 4);
    assert_ne!(first.id, second.id);
    assert!(first.attributes.is_empty());
    let serialized = serde_json::to_value(first)?;
    assert!(serialized.get("resource").is_none());
    assert!(
        serialized
            .get("source")
            .and_then(|s| s.get("name"))
            .is_none()
    );
    Ok(())
}

#[test]
fn full_event_roundtrips_nested_and_namespaced_attributes() -> Result {
    let id = Uuid::new_v4();
    let event = normalize(json!({
        "schema_version":1, "id":id, "timestamp":"2026-10-06T14:00:00.123456789+02:00",
        "observed_at":"2026-10-06T12:00:02Z", "source":{"type":"application","name":"checkout"},
        "severity":"warn", "message":"hello", "attributes":{"tenant.owner":"team", "user":{"name":"alice","roles":["reader",null]}, "ok":true, "size":42},
        "resource":{"kind":"host","id":"host-1","account_id":"example-account","region":"example-region"},
        "trace_id":"abcdef0123456789abcdef0123456789", "span_id":"abcdef0123456789", "tags":["sample"]
    }))?;
    let wire = serde_json::to_value(&event)?;
    assert_eq!(wire["timestamp"], "2026-10-06T12:00:00.123456789Z");
    assert_eq!(wire["source"]["type"], "application");
    assert_eq!(wire["attributes"]["user"]["roles"][1], Value::Null);
    assert_eq!(wire["attributes"]["tenant.owner"], "team");
    assert_eq!(event.id, id);
    let restored: SignalEvent = serde_json::from_value(wire)?;
    restored.validate()?;
    assert_eq!(restored, event);
    Ok(())
}

#[test]
fn attributes_can_supply_content_without_a_message() -> Result {
    let mut value = minimal();
    value
        .as_object_mut()
        .ok_or("object expected")?
        .remove("message");
    value["attributes"] = json!({"structured":{"value":null}});
    assert!(normalize(value)?.message.is_none());
    Ok(())
}

#[test]
fn timestamps_required_fields_and_unknown_envelope_fields_are_rejected() -> Result {
    for replacement in [
        json!(null),
        json!("yesterday"),
        json!(123),
        json!("2026-10-06T12:00:00"),
    ] {
        let mut value = minimal();
        value["timestamp"] = replacement;
        assert!(serde_json::from_value::<IngestEvent>(value).is_err());
    }
    for field in ["timestamp", "source"] {
        let mut value = minimal();
        value
            .as_object_mut()
            .ok_or("object expected")?
            .remove(field);
        assert!(serde_json::from_value::<IngestEvent>(value).is_err());
    }
    let mut value = minimal();
    value["unknown"] = json!("must not vanish");
    assert!(serde_json::from_value::<IngestEvent>(value).is_err());
    let mut value = minimal();
    value["source"] = json!({"name":"app"});
    assert!(serde_json::from_value::<IngestEvent>(value).is_err());
    Ok(())
}

#[test]
fn semantic_validation_rejects_empty_content_version_nil_id_and_blank_fields() -> Result {
    let valid = normalize(minimal())?;
    let mut event = valid.clone();
    event.schema_version = 2;
    assert_eq!(event.validate(), Err(ValidationError::UnsupportedVersion));
    let mut event = valid.clone();
    event.id = Uuid::nil();
    assert_eq!(event.validate(), Err(ValidationError::NilId));
    let mut event = valid.clone();
    event.message = Some("  ".into());
    assert_eq!(event.validate(), Err(ValidationError::MissingContent));
    let mut event = valid.clone();
    event.source.source_type = " ".into();
    assert_eq!(
        event.validate(),
        Err(ValidationError::BlankField("source.type"))
    );
    let mut event = valid.clone();
    event.source.name = Some("".into());
    assert_eq!(
        event.validate(),
        Err(ValidationError::BlankField("source.name"))
    );
    let mut event = valid;
    event.tags = vec!["".into()];
    assert_eq!(event.validate(), Err(ValidationError::BlankField("tags")));
    Ok(())
}

#[test]
fn correlation_ids_validate_without_echoing_supplied_values() -> Result {
    let mut event = normalize(minimal())?;
    event.span_id = Some("abcdef0123456789".into());
    assert_eq!(event.validate(), Err(ValidationError::SpanWithoutTrace));
    event.trace_id = Some("super-secret-not-a-trace".into());
    let error = event
        .validate()
        .err()
        .ok_or("expected validation failure")?;
    assert_eq!(error, ValidationError::InvalidCorrelationId("trace_id"));
    assert!(!error.to_string().contains("super-secret"));
    event.trace_id = Some("0".repeat(32));
    assert_eq!(
        event.validate(),
        Err(ValidationError::InvalidCorrelationId("trace_id"))
    );
    Ok(())
}

#[test]
fn all_event_severities_have_stable_lowercase_serialization() -> Result {
    for (severity, name) in [
        (Severity::Trace, "trace"),
        (Severity::Debug, "debug"),
        (Severity::Info, "info"),
        (Severity::Warn, "warn"),
        (Severity::Error, "error"),
        (Severity::Critical, "critical"),
    ] {
        assert_eq!(serde_json::to_value(severity)?, json!(name));
        assert_eq!(serde_json::from_value::<Severity>(json!(name))?, severity);
    }
    assert!(serde_json::from_value::<Severity>(json!("medium")).is_err());
    Ok(())
}

#[test]
fn timestamps_reject_extended_years_and_attributes_preserve_large_numbers() -> Result {
    let mut value = minimal();
    value["timestamp"] = json!("+10000-10-06T12:00:00Z");
    assert!(serde_json::from_value::<IngestEvent>(value).is_err());
    let mut value = minimal();
    value["observed_at"] = json!("not-a-time");
    assert!(serde_json::from_value::<IngestEvent>(value).is_err());
    let number: Value = serde_json::from_str("184467440737095516160000")?;
    let mut value = minimal();
    value["attributes"] = json!({"large":number});
    let normalized = normalize(value)?;
    let wire = serde_json::to_string(&normalized)?;
    assert!(wire.contains("184467440737095516160000"));
    let restored: SignalEvent = serde_json::from_str(&wire)?;
    assert_eq!(restored.attributes, normalized.attributes);
    Ok(())
}

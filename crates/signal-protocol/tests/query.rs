use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_protocol::{EventQuery, QueryOrder, QueryValidationError, parse_event_query};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn defaults_and_every_named_filter() -> TestResult {
    let defaults = parse_event_query("", 1000)?;
    assert_eq!(defaults, EventQuery::default());
    assert_eq!(parse_event_query("", 10)?.limit, 10);
    let query = parse_event_query(
        "contains=a%2Bb+c&severity=critical&source_type=app&source_name=api&resource_kind=host&resource_id=host-1&account=acct&limit=999&order=desc",
        1000,
    )?;
    assert_eq!(query.contains.as_deref(), Some("a+b c"));
    assert_eq!(query.source_type_filter(), Some("app"));
    assert_eq!(query.source_name.as_deref(), Some("api"));
    assert_eq!(query.resource_kind.as_deref(), Some("host"));
    assert_eq!(query.resource_id_filter(), Some("host-1"));
    assert_eq!(query.account.as_deref(), Some("acct"));
    assert_eq!(query.limit, 999);
    assert_eq!(query.order, QueryOrder::Desc);
    Ok(())
}

#[test]
fn utc_offsets_and_fractional_bounds_are_exact() -> TestResult {
    let query = parse_event_query(
        "from=2026-10-06T13%3A02%3A03.123456789%2B02%3A00&to=2026-10-06T11%3A02%3A04Z",
        1000,
    )?;
    let expected =
        DateTime::parse_from_rfc3339("2026-10-06T11:02:03.123456789Z")?.with_timezone(&Utc);
    assert_eq!(query.from, Some(expected));
    assert_eq!(
        parse_event_query("from=2026-10-06T11:00:00Z&to=2026-10-06T11:00:00Z", 1000),
        Err(QueryValidationError::InvalidTimeRange)
    );
    assert_eq!(
        parse_event_query("from=2026-10-06T12:00:00Z&to=2026-10-06T11:00:00Z", 1000),
        Err(QueryValidationError::InvalidTimeRange)
    );
    assert!(
        parse_event_query(
            "from=0000-01-01T00:00:00Z&to=9999-12-31T23:59:59.999999999Z",
            1000
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn only_full_rfc3339_is_accepted() {
    for timestamp in [
        "2026-10-06",
        "2026-10-06T11:00:00",
        "2026-10-06 11:00:00Z",
        "2026-10-06T11:00:00.1234567890Z",
        "+10000-01-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "0000-01-01T00:00:00%2B01:00",
    ] {
        assert_eq!(
            parse_event_query(&format!("from={timestamp}"), 1000),
            Err(QueryValidationError::InvalidTimestamp),
            "{timestamp}"
        );
    }
}

#[test]
fn aliases_preserve_compatibility_and_reject_conflicts() -> TestResult {
    let query = parse_event_query("source=app&resource=host-1", 1000)?;
    assert_eq!(query.source_type_filter(), Some("app"));
    assert_eq!(query.resource_id_filter(), Some("host-1"));
    assert!(
        parse_event_query(
            "source=app&source_type=app&resource=id&resource_id=id",
            1000
        )
        .is_ok()
    );
    assert_eq!(
        parse_event_query("source=app&source_type=other", 1000),
        Err(QueryValidationError::ConflictingAlias)
    );
    assert_eq!(
        parse_event_query("resource=id&resource_id=other", 1000),
        Err(QueryValidationError::ConflictingAlias)
    );
    Ok(())
}

#[test]
fn attribute_values_preserve_json_types_and_large_numbers() -> TestResult {
    let query = parse_event_query(
        "attribute.user.name=alice&attribute.owner=123456789012345678901234567890&attribute.enabled=true&attribute.missing=null&attribute.object=%7B%22a%22%3A%5B1%2Cfalse%5D%7D&attribute.string=%22123%22&attribute.array=%5B1%2C2%5D",
        1000,
    )?;
    let values: Vec<&Value> = query.attributes.iter().map(|a| &a.value).collect();
    assert_eq!(values[0], &json!("alice"));
    assert_eq!(values[1].to_string(), "123456789012345678901234567890");
    assert_eq!(values[2], &json!(true));
    assert_eq!(values[3], &Value::Null);
    assert_eq!(values[4], &json!({"a": [1, false]}));
    assert_eq!(values[5], &json!("123"));
    assert_eq!(values[6], &json!([1, 2]));
    assert_eq!(query.attributes[0].path, "user.name");
    Ok(())
}

#[test]
fn invalid_parameters_and_encoded_duplicates_fail_closed() {
    for (raw, expected) in [
        ("sql=SELECT+secret", QueryValidationError::UnknownParameter),
        (
            "limit=1&%6cimit=2",
            QueryValidationError::DuplicateParameter,
        ),
        (
            "attribute.x=1&attribute.x=2",
            QueryValidationError::DuplicateParameter,
        ),
        ("attribute.=1", QueryValidationError::InvalidAttributePath),
        (
            "attribute.x..y=1",
            QueryValidationError::InvalidAttributePath,
        ),
        ("order=DESC", QueryValidationError::InvalidOrder),
        ("severity=fatal", QueryValidationError::InvalidSeverity),
        ("limit=0", QueryValidationError::InvalidLimit),
        ("limit=1001", QueryValidationError::InvalidLimit),
        ("limit=%2B1", QueryValidationError::InvalidLimit),
        ("limit=1.0", QueryValidationError::InvalidLimit),
        (
            "limit=999999999999999999999999999999",
            QueryValidationError::InvalidLimit,
        ),
        ("contains=%", QueryValidationError::InvalidEncoding),
        ("contains=%G0", QueryValidationError::InvalidEncoding),
        ("contains=%FF", QueryValidationError::InvalidEncoding),
    ] {
        assert_eq!(parse_event_query(raw, 1000), Err(expected), "{raw}");
    }
    assert_eq!(
        parse_event_query("", 0),
        Err(QueryValidationError::InvalidLimit)
    );
}

#[test]
fn programmatic_queries_and_safe_errors_use_same_validation() {
    let query = EventQuery {
        schema_version: 2,
        ..EventQuery::default()
    };
    assert_eq!(
        query.validate(1000),
        Err(QueryValidationError::UnsupportedVersion)
    );
    let query = EventQuery {
        limit: 0,
        ..EventQuery::default()
    };
    assert_eq!(
        query.validate(1000),
        Err(QueryValidationError::InvalidLimit)
    );
    let Err(error) = parse_event_query("secret_token=secret-value", 1000) else {
        panic!("unknown parameter must fail")
    };
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn raw_query_and_filter_strings_have_finite_limits() {
    assert_eq!(
        parse_event_query(&format!("contains={}", "a".repeat(16 * 1024)), 1000),
        Err(QueryValidationError::TooComplex)
    );
    assert_eq!(
        parse_event_query(&format!("contains={}", "a".repeat(4097)), 1000),
        Err(QueryValidationError::InvalidFilter)
    );
    let query = EventQuery {
        source_name: Some("a".repeat(4097)),
        ..EventQuery::default()
    };
    assert_eq!(
        query.validate(1000),
        Err(QueryValidationError::InvalidFilter)
    );
    let query = EventQuery {
        source: Some("a".repeat(4096)),
        source_name: Some("b".repeat(4096)),
        resource: Some("c".repeat(4096)),
        account: Some("d".repeat(4096)),
        contains: Some("e".into()),
        ..EventQuery::default()
    };
    assert_eq!(query.validate(1000), Err(QueryValidationError::TooComplex));
}

#[test]
fn attribute_count_and_paths_are_bounded_before_query_planning() {
    let raw = (0..33)
        .map(|i| format!("attribute.key{i}=true"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(
        parse_event_query(&raw, 1000),
        Err(QueryValidationError::TooComplex)
    );
    for path in ["a".repeat(513), vec!["a"; 17].join(".")] {
        assert_eq!(
            parse_event_query(&format!("attribute.{path}=1"), 1000),
            Err(QueryValidationError::TooComplex)
        );
        let query = EventQuery {
            attributes: vec![signal_protocol::AttributeFilter {
                path,
                value: json!(1),
            }],
            ..EventQuery::default()
        };
        assert_eq!(query.validate(1000), Err(QueryValidationError::TooComplex));
    }
    let query = EventQuery {
        attributes: (0..33)
            .map(|i| signal_protocol::AttributeFilter {
                path: format!("key{i}"),
                value: json!(true),
            })
            .collect(),
        ..EventQuery::default()
    };
    assert_eq!(query.validate(1000), Err(QueryValidationError::TooComplex));
}

#[test]
fn direct_attribute_serialization_and_total_size_are_bounded() {
    let query = EventQuery {
        attributes: vec![signal_protocol::AttributeFilter {
            path: "key".into(),
            value: json!("a".repeat(4095)),
        }],
        ..EventQuery::default()
    };
    assert_eq!(
        query.validate(1000),
        Err(QueryValidationError::InvalidFilter)
    );
    let query = EventQuery {
        attributes: (0..5)
            .map(|i| signal_protocol::AttributeFilter {
                path: format!("key{i}"),
                value: json!("a".repeat(4090)),
            })
            .collect(),
        ..EventQuery::default()
    };
    assert_eq!(query.validate(1000), Err(QueryValidationError::TooComplex));
    let mut value = json!(0);
    for _ in 0..33 {
        value = json!([value]);
    }
    let query = EventQuery {
        attributes: vec![signal_protocol::AttributeFilter {
            path: "key".into(),
            value,
        }],
        ..EventQuery::default()
    };
    assert_eq!(query.validate(1000), Err(QueryValidationError::TooComplex));
}

#[test]
fn bounded_normal_quoted_nested_and_large_number_values_work() -> TestResult {
    let raw = format!(
        "attribute.quoted=%22{}%22&attribute.nested=%7B%22owner%22%3A%7B%22id%22%3A{}%7D%7D",
        "a".repeat(2000),
        "9".repeat(100)
    );
    let query = parse_event_query(&raw, 1000)?;
    assert_eq!(query.attributes[0].value, json!("a".repeat(2000)));
    assert_eq!(
        query.attributes[1].value["owner"]["id"].to_string(),
        "9".repeat(100)
    );
    let raw = (0..32)
        .map(|i| format!("attribute.key{i}=true"))
        .collect::<Vec<_>>()
        .join("&");
    assert!(parse_event_query(&raw, 1000).is_ok());
    assert!(parse_event_query(&format!("attribute.{}=1", vec!["a"; 16].join(".")), 1000).is_ok());
    assert!(parse_event_query(&format!("attribute.{}=1", "a".repeat(512)), 1000).is_ok());
    Ok(())
}

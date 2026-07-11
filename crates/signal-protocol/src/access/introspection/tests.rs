#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::access::{AccessPolicy, Operation, ScopeFacts};
use serde_json::{Value, json};

const ISSUER: &str = "https://identity.example.test";
const AUDIENCE: &str = "synthetic-signal";

fn profile() -> IntrospectionProfile {
    IntrospectionProfile::new(ISSUER.into(), AUDIENCE.into(), 60).unwrap()
}
fn response() -> Value {
    json!({"active":true,"iss":ISSUER,"aud":AUDIENCE,"sub":"reader","exp":500,"token_type":"Bearer"})
}
fn parse(
    profile: &IntrospectionProfile,
    value: &Value,
    now: u64,
) -> Result<AuthenticatedIdentity, IntrospectionError> {
    profile.from_authenticated_response(&serde_json::to_vec(value).unwrap(), now)
}
fn read_policy() -> std::sync::Arc<crate::access::CompiledPolicy> {
    let document = json!({
        "schema_version":1,
        "roles":[{"id":"read","permissions":[{"operation":"query_events","scope":{
            "sources":{"mode":"all"},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"all"}
        }}]}],
        "bindings":[{"issuer":ISSUER,"subject":"reader","roles":["read"]}]
    });
    AccessPolicy::from_json(&serde_json::to_vec(&document).unwrap())
        .unwrap()
        .compile()
        .unwrap()
}
fn facts(account: &'static str) -> ScopeFacts<'static> {
    ScopeFacts {
        source: None,
        account: Some(account),
        resource: None,
    }
}

#[test]
fn validated_response_binds_exact_identity_and_finite_lease() {
    for audience in [json!(AUDIENCE), json!(["other-resource", AUDIENCE])] {
        let mut input = response();
        input["aud"] = audience;
        let identity = parse(&profile(), &input, 100).unwrap();
        let grant = read_policy().grant(identity, 100).unwrap();
        assert!(grant.allows(Operation::QueryEvents, facts("a"), 100));
        assert!(grant.allows(Operation::QueryEvents, facts("a"), 159));
        assert!(!grant.allows(Operation::QueryEvents, facts("a"), 160));
        assert!(!grant.allows(Operation::QueryEvents, facts("b"), 100));
    }
    let mut input = response();
    input["exp"] = json!(130);
    let grant = read_policy()
        .grant(parse(&profile(), &input, 100).unwrap(), 100)
        .unwrap();
    assert!(grant.allows(Operation::QueryEvents, facts("a"), 129));
    assert!(!grant.allows(Operation::QueryEvents, facts("a"), 130));
    let mut input = response();
    input["sub"] = json!("other");
    let identity = parse(&profile(), &input, 100).unwrap();
    assert!(matches!(
        read_policy().grant(identity, 100),
        Err(crate::access::AccessError::Denied)
    ));
}

#[test]
fn provider_role_scope_and_identity_extensions_never_assign_permissions() {
    let mut input = response();
    input["roles"] = json!(["admin"]);
    input["scope"] = json!("configure read_evidence query_events:*");
    input["username"] = json!("administrator");
    input["groups"] = json!(["everyone"]);
    input["attributes"] = json!({"account":"b","subject":"administrator"});
    let grant = read_policy()
        .grant(parse(&profile(), &input, 100).unwrap(), 100)
        .unwrap();
    assert!(grant.allows(Operation::QueryEvents, facts("a"), 100));
    assert!(!grant.allows(Operation::QueryEvents, facts("b"), 100));
    for operation in [
        Operation::Configure,
        Operation::ReadEvidence,
        Operation::IngestEvents,
    ] {
        assert!(!grant.allows(operation, facts("a"), 100));
    }
}

#[test]
fn inactive_missing_claims_wrong_issuer_audience_and_type_deny() {
    let mut cases = vec![json!({"active":false})];
    for field in ["iss", "aud", "sub", "exp", "token_type"] {
        let mut missing = response();
        missing.as_object_mut().unwrap().remove(field);
        cases.push(missing);
    }
    for (field, value) in [
        ("active", json!(false)),
        ("iss", json!("https://other.example.test")),
        ("iss", json!(format!("{ISSUER}/"))),
        ("aud", json!("other-resource")),
        ("aud", json!([])),
        ("aud", json!([AUDIENCE, AUDIENCE])),
        ("aud", json!([AUDIENCE, " "])),
        ("sub", json!("reader\n")),
        ("sub", json!("")),
        ("token_type", json!("ID")),
        ("token_type", json!("Bearer ")),
    ] {
        let mut invalid = response();
        invalid[field] = value;
        cases.push(invalid);
    }
    for case in cases {
        assert!(matches!(
            parse(&profile(), &case, 100),
            Err(IntrospectionError::Denied)
        ));
    }
    let mut input = response();
    input["token_type"] = json!("bEaReR");
    assert!(parse(&profile(), &input, 100).is_ok());
}

#[test]
fn expiry_and_not_before_or_issued_in_future_fail_closed() {
    for (field, value) in [
        ("exp", 99_u64),
        ("exp", 100),
        ("exp", 253_402_300_800),
        ("nbf", 101),
        ("iat", 101),
        ("nbf", 500),
        ("iat", 500),
    ] {
        let mut input = response();
        input[field] = json!(value);
        assert!(matches!(
            parse(&profile(), &input, 100),
            Err(IntrospectionError::Denied)
        ));
    }
    let mut input = response();
    input["nbf"] = json!(100);
    input["iat"] = json!(99);
    assert!(parse(&profile(), &input, 100).is_ok());
    assert!(matches!(
        parse(&profile(), &response(), u64::MAX),
        Err(IntrospectionError::Denied)
    ));
}

#[test]
fn malformed_and_duplicate_security_fields_cannot_be_interpreted_as_valid() {
    for bytes in [
        b"".as_slice(),
        b"[]",
        b"null",
        b"{}",
        b"[true,\"https://identity.example.test\",\"reader\",\"synthetic-signal\",500,\"Bearer\",null,null]",
        b"{\"active\":true,\"active\":false}",
        b"{\"active\":\"true\"}",
    ] {
        assert!(matches!(
            profile().from_authenticated_response(bytes, 100),
            Err(IntrospectionError::InvalidResponse)
        ));
    }
    for (field, value) in [
        ("exp", json!(-1)),
        ("exp", json!(100.5)),
        ("nbf", json!(false)),
        ("iat", json!("100")),
        ("aud", json!(1)),
        ("aud", json!([AUDIENCE, 1])),
        ("sub", json!({"role":"admin"})),
    ] {
        let mut input = response();
        input[field] = value;
        assert!(matches!(
            parse(&profile(), &input, 100),
            Err(IntrospectionError::InvalidResponse)
        ));
    }
    let base = serde_json::to_string(&response()).unwrap();
    for field in ["iss", "aud", "sub", "exp", "token_type", "nbf", "iat"] {
        let mut input = base[..base.len() - 1].to_owned();
        // nbf/iat aren't present in the baseline, so create both copies here.
        if matches!(field, "nbf" | "iat") {
            input.push_str(&format!(",\"{field}\":null"));
        }
        input.push_str(&format!(",\"{field}\":null}}"));
        assert!(matches!(
            profile().from_authenticated_response(input.as_bytes(), 100),
            Err(IntrospectionError::InvalidResponse)
        ));
    }
}

#[test]
fn response_profile_cardinality_and_strings_have_finite_bounds_and_safe_errors() {
    assert!(matches!(
        profile().from_authenticated_response(&vec![b' '; RESPONSE_BYTES + 1], 100),
        Err(IntrospectionError::InvalidResponse)
    ));
    let mut input = response();
    input["sub"] = json!("x".repeat(257));
    assert!(matches!(
        parse(&profile(), &input, 100),
        Err(IntrospectionError::Denied)
    ));
    input = response();
    input["aud"] = json!(["x".repeat(257), AUDIENCE]);
    assert!(matches!(
        parse(&profile(), &input, 100),
        Err(IntrospectionError::Denied)
    ));
    input = response();
    input["aud"] = json!(
        (0..MAX_AUDIENCES)
            .map(|i| format!("other-{i}"))
            .chain([AUDIENCE.into()])
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        parse(&profile(), &input, 100),
        Err(IntrospectionError::Denied)
    ));
    for (issuer, audience, lease) in [
        ("".into(), AUDIENCE.into(), 60),
        (ISSUER.into(), "\nsecret-sentinel".into(), 60),
        ("x".repeat(2049), AUDIENCE.into(), 60),
        (ISSUER.into(), "x".repeat(257), 60),
        (ISSUER.into(), AUDIENCE.into(), 0),
        (ISSUER.into(), AUDIENCE.into(), 301),
    ] {
        let error = IntrospectionProfile::new(issuer, audience, lease)
            .err()
            .expect("invalid profile");
        assert_eq!(error, IntrospectionError::Configuration);
        assert!(!error.to_string().contains("secret-sentinel"));
    }
    let mut input = response();
    input["sub"] = json!("secret-sentinel\n");
    let error = parse(&profile(), &input, 100)
        .err()
        .expect("invalid response");
    assert!(!error.to_string().contains("secret-sentinel"));
    assert!(!format!("{error:?}").contains("secret-sentinel"));
}

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use serde_json::{Value, json};
use signal_event::IngestEvent;

const ISSUER: &str = "https://identity.example.test";

fn permission(operation: Operation, scope: ResourceScope) -> Permission {
    Permission { operation, scope }
}

fn scope(account: &str) -> ResourceScope {
    ResourceScope {
        sources: Selection::All,
        accounts: Selection::Only(vec![account.into()]),
        resources: Selection::All,
    }
}

fn policy(roles: Vec<Role>) -> AccessPolicy {
    let assigned = roles.iter().map(|role| role.id.clone()).collect();
    AccessPolicy {
        schema_version: 1,
        roles,
        bindings: vec![SubjectBinding {
            issuer: ISSUER.into(),
            subject: "reader".into(),
            roles: assigned,
        }],
    }
}

fn identity(issuer: &str, subject: &str, start: u64, end: u64) -> AuthenticatedIdentity {
    AuthenticatedIdentity::from_verified_backend(issuer.into(), subject.into(), start, end).unwrap()
}

fn grant(policy: AccessPolicy) -> RequestGrant {
    policy
        .compile()
        .unwrap()
        .grant(identity(ISSUER, "reader", 100, 200), 110)
        .unwrap()
}

#[test]
fn roles_do_not_cross_combine_operations_and_account_scopes() {
    let grant = grant(policy(vec![
        Role {
            id: "read-a".into(),
            permissions: vec![permission(Operation::QueryEvents, scope("a"))],
        },
        Role {
            id: "ingest-b".into(),
            permissions: vec![permission(Operation::IngestEvents, scope("b"))],
        },
    ]));
    for (operation, allowed_account) in [
        (Operation::QueryEvents, "a"),
        (Operation::IngestEvents, "b"),
    ] {
        for account in [Some("a"), Some("b"), Some("c"), None] {
            let facts = ScopeFacts {
                source: None,
                account,
                resource: None,
            };
            assert_eq!(
                grant.allows(operation, facts, 120),
                account == Some(allowed_account)
            );
        }
        let selectors: Vec<_> = grant.scopes(operation, 120).collect();
        assert_eq!(selectors.len(), 1);
        assert!(selectors[0].accounts == Selection::Only(vec![allowed_account.into()]));
    }
    assert!(!grant.allows(
        Operation::ReadEvidence,
        ScopeFacts {
            source: None,
            account: Some("a"),
            resource: None
        },
        120
    ));
}

#[test]
fn dimensions_are_conjoined_and_permissions_are_disjoined_without_wildcards() {
    let grant = grant(policy(vec![
        Role {
            id: "first".into(),
            permissions: vec![permission(
                Operation::QueryEvents,
                ResourceScope {
                    sources: Selection::Only(vec!["control".into()]),
                    accounts: Selection::Only(vec!["a".into()]),
                    resources: Selection::Only(vec!["r1".into()]),
                },
            )],
        },
        Role {
            id: "second".into(),
            permissions: vec![permission(
                Operation::QueryEvents,
                ResourceScope {
                    sources: Selection::Only(vec!["auth".into()]),
                    accounts: Selection::Only(vec!["b".into()]),
                    resources: Selection::Only(vec!["*".into()]),
                },
            )],
        },
    ]));
    // Independent truth table: only these two exact triples are authorized.
    for source in [None, Some("control"), Some("auth"), Some("Control")] {
        for account in [None, Some("a"), Some("b"), Some("a-child")] {
            for resource in [None, Some("r1"), Some("*"), Some("anything")] {
                let expected = (source == Some("control")
                    && account == Some("a")
                    && resource == Some("r1"))
                    || (source == Some("auth") && account == Some("b") && resource == Some("*"));
                assert_eq!(
                    grant.allows(
                        Operation::QueryEvents,
                        ScopeFacts {
                            source,
                            account,
                            resource
                        },
                        120
                    ),
                    expected
                );
            }
        }
    }
}

#[test]
fn issuer_subject_are_exact_and_event_attributes_cannot_supply_authority() {
    let compiled = policy(vec![Role {
        id: "read".into(),
        permissions: vec![permission(Operation::QueryEvents, scope("a"))],
    }])
    .compile()
    .unwrap();
    for (issuer, subject) in [
        ("https://other.example.test", "reader"),
        (ISSUER, "Reader"),
        (ISSUER, "unknown"),
    ] {
        assert!(matches!(
            compiled.grant(identity(issuer, subject, 100, 200), 110),
            Err(AccessError::Denied)
        ));
    }
    let grant = compiled
        .grant(identity(ISSUER, "reader", 100, 200), 110)
        .unwrap();
    let mut value = json!({
        "timestamp": "2026-01-01T00:00:00Z", "source": {"type":"control"}, "message":"synthetic",
        "attributes":{"account_id":"a", "resource":{"account_id":"a"}, "roles":["admin"], "subject":"reader"},
        "resource":{"kind":"test", "id":"r", "account_id":"b"}
    });
    for account in [Some("b"), None, Some("a")] {
        if let Some(account) = account {
            value["resource"]["account_id"] = json!(account);
        } else {
            value["resource"]
                .as_object_mut()
                .unwrap()
                .remove("account_id");
        }
        let event = serde_json::from_value::<IngestEvent>(value.clone())
            .unwrap()
            .normalize(chrono::Utc::now())
            .unwrap();
        assert_eq!(
            grant.allows(Operation::QueryEvents, ScopeFacts::event(&event), 120),
            account == Some("a")
        );
    }
    value.as_object_mut().unwrap().remove("resource");
    let event = serde_json::from_value::<IngestEvent>(value)
        .unwrap()
        .normalize(chrono::Utc::now())
        .unwrap();
    assert!(!grant.allows(Operation::QueryEvents, ScopeFacts::event(&event), 120));
}

#[test]
fn expiry_future_verification_and_clock_rollback_fail_closed() {
    let compiled = policy(vec![Role {
        id: "read".into(),
        permissions: vec![permission(Operation::QueryEvents, ResourceScope::all())],
    }])
    .compile()
    .unwrap();
    for now in [99, 200, 201] {
        assert!(matches!(
            compiled.grant(identity(ISSUER, "reader", 100, 200), now),
            Err(AccessError::Expired)
        ));
    }
    let grant = compiled
        .grant(identity(ISSUER, "reader", 100, 200), 110)
        .unwrap();
    for now in [100, 109, 110, 199, 200, 201] {
        let expected = (110..200).contains(&now);
        assert_eq!(
            grant.allows(
                Operation::QueryEvents,
                ScopeFacts {
                    source: None,
                    account: None,
                    resource: None
                },
                now
            ),
            expected
        );
        assert_eq!(
            grant.scopes(Operation::QueryEvents, now).count(),
            usize::from(expected)
        );
    }
    for (start, end) in [(100, 100), (101, 100), (0, 253_402_300_800)] {
        assert!(matches!(
            AuthenticatedIdentity::from_verified_backend(
                ISSUER.into(),
                "reader".into(),
                start,
                end
            ),
            Err(AccessError::InvalidIdentity)
        ));
    }
}

#[test]
fn global_capabilities_are_explicit_and_never_inferred_from_role_names() {
    for operation in [
        Operation::ReadFindingsFeed,
        Operation::Configure,
        Operation::ManageRules,
        Operation::ReadAudit,
    ] {
        assert!(matches!(
            policy(vec![Role {
                id: "admin".into(),
                permissions: vec![permission(operation, scope("a"))]
            }])
            .compile(),
            Err(AccessError::InvalidPolicy(_))
        ));
        let grant = grant(policy(vec![Role {
            id: "admin".into(),
            permissions: vec![permission(operation, ResourceScope::all())],
        }]));
        let facts = ScopeFacts {
            source: None,
            account: None,
            resource: None,
        };
        assert!(grant.allows(operation, facts, 120));
        for denied in [
            Operation::QueryEvents,
            Operation::IngestEvents,
            Operation::ReadEvidence,
        ] {
            assert!(!grant.allows(denied, facts, 120));
        }
    }
    let compiled = AccessPolicy {
        schema_version: 1,
        roles: vec![],
        bindings: vec![],
    }
    .compile()
    .unwrap();
    assert!(matches!(
        compiled.grant(identity(ISSUER, "reader", 100, 200), 110),
        Err(AccessError::Denied)
    ));
}

fn document() -> Value {
    serde_json::to_value(policy(vec![Role {
        id: "read".into(),
        permissions: vec![permission(Operation::QueryEvents, scope("a"))],
    }]))
    .unwrap()
}

#[test]
fn malformed_policies_have_redacted_errors_and_never_compile() {
    let base = document();
    let mut cases = vec![json!([1, base["roles"], base["bindings"]])];
    for path in ["schema_version", "roles", "bindings"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(path);
        cases.push(missing);
    }
    let mut wrong = base.clone();
    wrong["schema_version"] = json!(2);
    cases.push(wrong);
    let mut unknown = base.clone();
    unknown["secret-sentinel"] = json!("secret-sentinel");
    cases.push(unknown);
    let mut reference = base.clone();
    reference["bindings"][0]["roles"] = json!(["secret-sentinel"]);
    cases.push(reference);
    let mut duplicate = base.clone();
    duplicate["roles"]
        .as_array_mut()
        .unwrap()
        .push(base["roles"][0].clone());
    cases.push(duplicate);
    let mut duplicate = base.clone();
    duplicate["bindings"]
        .as_array_mut()
        .unwrap()
        .push(base["bindings"][0].clone());
    cases.push(duplicate);
    let mut duplicate = base.clone();
    duplicate["bindings"][0]["roles"] = json!(["read", "read"]);
    cases.push(duplicate);
    let mut duplicate = base.clone();
    duplicate["roles"][0]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(base["roles"][0]["permissions"][0].clone());
    cases.push(duplicate);
    for selector in [
        json!({"mode":"only", "values":[]}),
        json!({"mode":"only", "values":["a", "a"]}),
        json!({"mode":"only", "values":[" secret-sentinel"]}),
        json!({"mode":"all", "extra":true}),
    ] {
        let mut invalid = base.clone();
        invalid["roles"][0]["permissions"][0]["scope"]["accounts"] = selector;
        cases.push(invalid);
    }
    for value in cases {
        let error = AccessPolicy::from_json(&serde_json::to_vec(&value).unwrap())
            .and_then(AccessPolicy::compile)
            .err()
            .expect("invalid policy rejected");
        assert!(!error.to_string().contains("secret-sentinel"));
        assert!(!format!("{error:?}").contains("secret-sentinel"));
    }
    assert!(
        AccessPolicy::from_json(
            br#"{"schema_version":1,"schema_version":1,"roles":[],"bindings":[]}"#
        )
        .is_err()
    );
}

#[test]
fn parsed_and_programmatic_policies_both_enforce_byte_and_collection_bounds() {
    assert!(AccessPolicy::from_json(&vec![b' '; POLICY_BYTES + 1]).is_err());
    let mut too_many = document();
    too_many["roles"] = json!((0..=MAX_ROLES).map(|i|json!({"id":format!("r{i}"),"permissions":[{"operation":"query_events","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]})).collect::<Vec<_>>());
    too_many["bindings"] = json!([]);
    assert!(
        AccessPolicy::from_json(&serde_json::to_vec(&too_many).unwrap())
            .unwrap()
            .compile()
            .is_err()
    );
    let mut too_many = document();
    too_many["bindings"] = json!(
        (0..=MAX_BINDINGS)
            .map(|i| json!({"issuer":ISSUER,"subject":format!("s{i}"),"roles":["read"]}))
            .collect::<Vec<_>>()
    );
    assert!(
        AccessPolicy::from_json(&serde_json::to_vec(&too_many).unwrap())
            .unwrap()
            .compile()
            .is_err()
    );
    let oversized = AccessPolicy {
        schema_version: 1,
        roles: vec![Role {
            id: "read".into(),
            permissions: vec![permission(Operation::QueryEvents, ResourceScope::all())],
        }],
        bindings: (0..MAX_BINDINGS)
            .map(|i| SubjectBinding {
                issuer: format!("https://{}.example.test/{i}", "x".repeat(1800)),
                subject: format!("s{i}"),
                roles: vec!["read".into()],
            })
            .collect(),
    };
    assert!(matches!(
        oversized.compile(),
        Err(AccessError::InvalidPolicy("encoded document byte bound"))
    ));
}

#[test]
fn compiled_grants_discard_programmatic_spare_capacity() {
    fn oversized_string(value: &str) -> String {
        let mut input = String::with_capacity(100_000);
        input.push_str(value);
        input
    }
    let mut roles = Vec::with_capacity(100_000);
    let empty = AccessPolicy {
        schema_version: 1,
        roles,
        bindings: vec![],
    }
    .compile()
    .unwrap();
    assert_eq!(empty.roles.capacity(), 0);
    roles = Vec::with_capacity(100_000);
    let mut permissions = Vec::with_capacity(100_000);
    let mut selectors = Vec::with_capacity(100_000);
    selectors.push(oversized_string("a"));
    permissions.push(permission(
        Operation::QueryEvents,
        ResourceScope {
            sources: Selection::All,
            accounts: Selection::Only(selectors),
            resources: Selection::All,
        },
    ));
    roles.push(Role {
        id: oversized_string("read"),
        permissions,
    });
    let mut input = policy(roles);
    input.bindings[0].issuer = oversized_string(ISSUER);
    input.bindings[0].subject = oversized_string("reader");
    let compiled = input.compile().unwrap();
    assert_eq!(compiled.roles.capacity(), compiled.roles.len());
    let role = &compiled.roles[0];
    assert_eq!(role.id.capacity(), role.id.len());
    assert_eq!(role.permissions.capacity(), role.permissions.len());
    let Selection::Only(values) = &role.permissions[0].scope.accounts else {
        panic!("restricted selector preserved");
    };
    assert_eq!(values.capacity(), values.len());
    assert_eq!(values[0].capacity(), values[0].len());
    for (issuer, subjects) in &compiled.subjects {
        assert_eq!(issuer.capacity(), issuer.len());
        for (subject, assigned) in subjects {
            assert_eq!(subject.capacity(), subject.len());
            assert_eq!(assigned.capacity(), assigned.len());
        }
    }
    let identity = AuthenticatedIdentity::from_verified_backend(
        oversized_string(ISSUER),
        oversized_string("reader"),
        100,
        200,
    )
    .unwrap();
    assert_eq!(identity.issuer.capacity(), identity.issuer.len());
    assert_eq!(identity.subject.capacity(), identity.subject.len());
    let grant = compiled.grant(identity, 110).unwrap();
    assert!(grant.allows(
        Operation::QueryEvents,
        ScopeFacts {
            source: None,
            account: Some("a"),
            resource: None
        },
        120
    ));
}

#[test]
fn structural_preflight_rejects_oversized_strings_before_encoded_size_work() {
    // These otherwise-small policies exceed the encoded byte limit too. Their
    // structural error proves rejection precedes scanning/serializing content.
    let mut input = policy(vec![Role {
        id: "x".repeat(POLICY_BYTES + 1),
        permissions: vec![permission(Operation::QueryEvents, ResourceScope::all())],
    }]);
    assert!(matches!(
        input.compile(),
        Err(AccessError::InvalidPolicy("role identity or permissions"))
    ));
    input = policy(vec![Role {
        id: "read".into(),
        permissions: vec![permission(
            Operation::QueryEvents,
            scope(&"x".repeat(POLICY_BYTES + 1)),
        )],
    }]);
    assert!(matches!(
        input.compile(),
        Err(AccessError::InvalidPolicy("selector identity"))
    ));
    for field in ["issuer", "subject", "assigned_role"] {
        let mut input = policy(vec![Role {
            id: "read".into(),
            permissions: vec![permission(Operation::QueryEvents, ResourceScope::all())],
        }]);
        let value = "x".repeat(POLICY_BYTES + 1);
        match field {
            "issuer" => input.bindings[0].issuer = value,
            "subject" => input.bindings[0].subject = value,
            _ => input.bindings[0].roles[0] = value,
        }
        assert!(matches!(
            input.compile(),
            Err(AccessError::InvalidPolicy("subject identity or roles"))
        ));
    }
}

#[test]
fn exact_subject_matching_and_lease_bounds_do_not_confer_capabilities() {
    let grant = grant(policy(vec![Role {
        id: "read".into(),
        permissions: vec![permission(Operation::ReadCoverage, scope("a"))],
    }]));
    assert_eq!(grant.lease_bounds(), (110, 200));
    assert!(grant.subject_matches(ISSUER, "reader", 110));
    for (issuer, subject, at) in [
        (ISSUER, "Reader", 110),
        ("https://other.example.test", "reader", 110),
        (ISSUER, "reader", 109),
        (ISSUER, "reader", 200),
    ] {
        assert!(!grant.subject_matches(issuer, subject, at));
    }
    assert!(!grant.allows(
        Operation::WriteCoverage,
        ScopeFacts {
            source: None,
            account: Some("a"),
            resource: None
        },
        120
    ));
}

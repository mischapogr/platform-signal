use super::*;
use crate::access::{
    AccessPolicy, AuthenticatedIdentity, Permission, ResourceScope, Role, ScopeFacts,
    SubjectBinding,
};
use serde_json::{Value, json};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn health() -> AuditReceiverHealth {
    AuditReceiverHealth {
        schema_version: 1,
        held: false,
        records: 1,
        bytes: 400,
        record_capacity: 8,
        byte_capacity: 65_536,
        physical_depth: 0,
        physical_capacity: 1,
        physical_rejected: 0,
        rejected: 0,
        uncertain: 0,
        append_http_depth: 0,
        append_http_capacity: 1,
        append_http_rejected: 0,
        health_http_rejected: 0,
    }
}
#[test]
fn health_wire_preserves_aggregate_and_rejects_shapes_fields_and_impossible_bounds() -> Result {
    let h = health();
    let bytes = h.to_json()?;
    assert_eq!(AuditReceiverHealth::from_json(&bytes)?, h);
    assert!(bytes.len() <= HEALTH_BYTES);
    let original: Value = serde_json::from_slice(&bytes)?;
    let mut bad = vec![
        "null".to_owned(),
        "[]".to_owned(),
        String::from_utf8(bytes.clone())?.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        ),
    ];
    for (key, value) in [
        ("schema_version", json!(2)),
        ("held", json!(null)),
        ("records", json!(-1)),
        ("records", json!(9)),
        ("bytes", json!(65_537)),
        ("record_capacity", json!(0)),
        ("byte_capacity", json!(1)),
        ("physical_depth", json!(2)),
        ("physical_capacity", json!(2)),
        ("append_http_depth", json!(2)),
        ("append_http_capacity", json!(0)),
        ("actor", json!("private-canary")),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        bad.push(changed.to_string());
    }
    for bytes in bad {
        let error = match AuditReceiverHealth::from_json(bytes.as_bytes()) {
            Err(error) => error,
            Ok(_) => return Err("malformed health accepted".into()),
        };
        assert!(!format!("{error:?} {error}").contains("private-canary"));
    }
    assert!(AuditReceiverHealth::from_json(&vec![b' '; HEALTH_BYTES + 1]).is_err());
    let mut invalid = h;
    invalid.records = usize::MAX;
    assert!(invalid.to_json().is_err());
    let mut held = h;
    held.held = true;
    held.physical_depth = 1;
    held.append_http_depth = 1;
    assert_eq!(AuditReceiverHealth::from_json(&held.to_json()?)?, held);
    // Independent atomic loads need not form a transactional record/byte pair.
    held.bytes = 0;
    assert!(held.to_json().is_ok());
    Ok(())
}
fn record() -> Result<AuditRecord> {
    Ok(AuditRecord {
        schema_version: 1,
        record_id: Uuid::new_v4(),
        producer_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: "2026-10-09T00:00:00Z".parse()?,
        actor: Actor::Unattributed {},
        action: Action::AccessDecision {
            operation: Operation::QueryEvents,
            operation_id: Uuid::new_v4(),
            decision: Decision::Denied,
        },
    })
}
#[test]
fn strict_record_semantics_no_free_data_and_static_errors() -> Result {
    let prepared = record()?.prepare()?;
    let original: Value = serde_json::from_slice(prepared.body())?;
    let mut invalid = vec![
        "".into(),
        "null".into(),
        "[]".into(),
        String::from_utf8(prepared.body().to_vec())?.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        ),
    ];
    for (field, value) in [
        ("schema_version", json!(2)),
        ("schema_version", json!(null)),
        ("record_id", json!(Uuid::nil())),
        ("producer_id", json!(Uuid::nil())),
        ("sequence", json!(0)),
        ("sequence", json!(-1)),
        ("sequence", json!(null)),
        ("timestamp", json!("1969-12-31T23:59:59Z")),
        ("timestamp", json!("2016-12-31T23:59:60Z")),
        ("timestamp", json!("+10000-01-01T00:00:00Z")),
        ("raw", json!("synthetic-secret-canary")),
        (
            "actor",
            json!({"kind":"bootstrap","credential":"synthetic-secret-canary"}),
        ),
        (
            "actor",
            json!({"kind":"verified_subject","key":"a".repeat(63)}),
        ),
        (
            "actor",
            json!({"kind":"verified_subject","key":"A".repeat(64)}),
        ),
        (
            "actor",
            json!({"kind":"verified_subject","key":"a".repeat(64),"header":"forged"}),
        ),
        (
            "action",
            json!({"kind":"configuration_activation","configuration":"rules","revision_sha256":"bad"}),
        ),
        (
            "action",
            json!({"kind":"access_decision","operation":"query_events","operation_id":Uuid::nil(),"decision":"granted"}),
        ),
        (
            "action",
            json!({"kind":"operation_completion","operation":"query_events","operation_id":Uuid::new_v4(),"completion":"uncertain","raw":"synthetic-secret-canary"}),
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        invalid.push(changed.to_string());
    }
    for kind in ["bootstrap", "anonymous", "unattributed", "system"] {
        let mut changed = original.clone();
        changed["actor"] = json!({"kind": kind, "credential": "synthetic-secret-canary"});
        invalid.push(changed.to_string());
    }
    invalid.push(String::from_utf8(prepared.body().to_vec())?.replace(
        "\"kind\":\"unattributed\"",
        "\"kind\":\"unattributed\",\"kind\":\"anonymous\"",
    ));
    for (index, body) in invalid.into_iter().enumerate() {
        let error = match PreparedAudit::from_original(body.as_bytes()) {
            Err(e) => e,
            Ok(_) => return Err(format!("accepted malformed audit record case {index}").into()),
        };
        assert!(!format!("{error} {error:?}").contains("synthetic-secret-canary"));
    }
    assert!(matches!(
        PreparedAudit::from_original(&vec![b' '; RECORD_BYTES + 1]),
        Err(AuditError::TooLarge)
    ));
    let mut bad = record()?;
    bad.actor = Actor::VerifiedSubject {
        key: "synthetic-secret-canary".repeat(4096),
    };
    assert!(matches!(bad.prepare(), Err(AuditError::InvalidRecord)));
    Ok(())
}
#[test]
fn exact_original_bytes_survive_decode_and_ack_binds_full_identity_and_hash() -> Result {
    let canonical = record()?.prepare()?;
    let mut original = b" \n".to_vec();
    original.extend_from_slice(canonical.body());
    original.resize(RECORD_BYTES, b' ');
    let received = PreparedAudit::from_original(&original)?;
    assert!(received.record() == canonical.record());
    assert_eq!(received.body(), original);
    assert_ne!(received.sha256(), canonical.sha256());
    let ack = AuditAcknowledgement::for_prepared(&received).to_json()?;
    received.verify_acknowledgement(&ack)?;
    assert!(matches!(
        canonical.verify_acknowledgement(&ack),
        Err(AuditError::InvalidAcknowledgement)
    ));
    let canonical_ack = AuditAcknowledgement::for_prepared(&canonical).to_json()?;
    canonical.verify_acknowledgement(&canonical_ack)?;
    let original: Value = serde_json::from_slice(&canonical_ack)?;
    for (field, value) in [
        ("schema_version", json!(2)),
        ("record_id", json!(Uuid::new_v4())),
        ("producer_id", json!(Uuid::new_v4())),
        ("sequence", json!(2)),
        ("body_sha256", json!("b".repeat(64))),
        ("body_sha256", json!("A".repeat(64))),
        ("durable", json!(true)),
        ("sequence", json!(null)),
    ] {
        let mut altered = original.clone();
        altered[field] = value;
        assert!(matches!(
            canonical.verify_acknowledgement(altered.to_string().as_bytes()),
            Err(AuditError::InvalidAcknowledgement)
        ));
    }
    let duplicate = String::from_utf8(canonical_ack)?.replacen(
        "\"sequence\":1",
        "\"sequence\":1,\"sequence\":1",
        1,
    );
    assert!(matches!(
        canonical.verify_acknowledgement(duplicate.as_bytes()),
        Err(AuditError::InvalidAcknowledgement)
    ));
    assert!(matches!(
        canonical.verify_acknowledgement(&vec![b' '; ACK_BYTES + 1]),
        Err(AuditError::TooLarge)
    ));
    let mut claim = AuditAcknowledgement::for_prepared(&canonical);
    claim.body_sha256 = "canary".into();
    assert!(matches!(
        claim.to_json(),
        Err(AuditError::InvalidAcknowledgement)
    ));
    Ok(())
}
#[test]
fn decisions_completions_and_activation_are_distinct_non_authorizing_records() -> Result {
    let operation_id = Uuid::new_v4();
    let actions = [
        Action::AccessDecision {
            operation: Operation::IngestEvents,
            operation_id,
            decision: Decision::Granted,
        },
        Action::OperationCompletion {
            operation: Operation::IngestEvents,
            operation_id,
            completion: Completion::Uncertain,
        },
        Action::ConfigurationActivation {
            configuration: ConfigurationKind::Rules,
            revision_sha256: "a".repeat(64),
        },
        Action::ConfigurationActivation {
            configuration: ConfigurationKind::Runtime,
            revision_sha256: "b".repeat(64),
        },
    ];
    for action in actions {
        for actor in [
            Actor::System {},
            Actor::Bootstrap {},
            Actor::Anonymous {},
            Actor::Unattributed {},
            Actor::VerifiedSubject {
                key: "a".repeat(64),
            },
        ] {
            let mut event = record()?;
            event.action = action.clone();
            event.actor = actor;
            let body = event.clone().prepare()?;
            let decoded = PreparedAudit::from_original(body.body())?;
            assert!(decoded.record() == &event);
            assert!(body.body().len() < RECORD_BYTES);
        }
    }
    Ok(())
}
fn grant(issuer: &str, subject: &str, issued: u64) -> Result<crate::access::RequestGrant> {
    let policy = AccessPolicy {
        schema_version: 1,
        roles: vec![Role {
            id: "reader".into(),
            permissions: vec![Permission {
                operation: Operation::QueryEvents,
                scope: ResourceScope::all(),
            }],
        }],
        bindings: vec![SubjectBinding {
            issuer: issuer.into(),
            subject: subject.into(),
            roles: vec!["reader".into()],
        }],
    }
    .compile()?;
    Ok(policy.grant(
        AuthenticatedIdentity::from_verified_backend(issuer.into(), subject.into(), 100, 200)?,
        issued,
    )?)
}
#[test]
fn verified_subject_reference_is_live_framed_stable_and_does_not_add_permissions() -> Result {
    let first = grant("https://issuer.example.test/a", "bc", 110)?;
    let second = grant("https://issuer.example.test/ab", "c", 110)?;
    let refreshed = grant("https://issuer.example.test/a", "bc", 120)?;
    let key = first
        .audit_subject_key(120)
        .ok_or("missing live audit actor")?;
    assert!(digest_text(&key));
    assert_ne!(Some(key.clone()), second.audit_subject_key(120));
    assert_eq!(Some(key.clone()), refreshed.audit_subject_key(120));
    assert_eq!(Some(key), first.audit_subject_key(199));
    assert!(first.audit_subject_key(109).is_none());
    assert!(first.audit_subject_key(200).is_none());
    assert!(first.audit_subject_key(201).is_none());
    assert!(!first.allows(
        Operation::ReadAudit,
        ScopeFacts {
            source: None,
            account: None,
            resource: None
        },
        120
    ));
    assert!(first.scopes(Operation::ReadAudit, 120).next().is_none());
    assert!(first.subject_matches("https://issuer.example.test/a", "bc", 120));
    Ok(())
}
#[test]
fn complete_positional_arrays_are_not_named_field_wire_objects() -> Result {
    let prepared = record()?.prepare()?;
    let r = prepared.record();
    let positional = json!([
        r.schema_version,
        r.record_id,
        r.producer_id,
        r.sequence,
        r.timestamp,
        r.actor,
        r.action
    ]);
    // Valid field values: this failure must be the wire shape, not a bad fixture.
    let deserialized: AuditRecord = serde_json::from_value(positional.clone())?;
    deserialized.validate()?;
    assert!(matches!(
        PreparedAudit::from_original(positional.to_string().as_bytes()),
        Err(AuditError::InvalidRecord)
    ));
    let ack = AuditAcknowledgement::for_prepared(&prepared);
    let positional = json!([
        ack.schema_version,
        ack.record_id,
        ack.producer_id,
        ack.sequence,
        ack.body_sha256
    ]);
    let _deserialized: AuditAcknowledgement = serde_json::from_value(positional.clone())?;
    assert!(matches!(
        prepared.verify_acknowledgement(positional.to_string().as_bytes()),
        Err(AuditError::InvalidAcknowledgement)
    ));
    Ok(())
}
#[test]
fn prepared_metadata_cannot_retain_callers_large_spare_string_capacity() -> Result {
    let mut key = String::with_capacity(1024 * 1024);
    key.push_str(&"a".repeat(64));
    let mut revision = String::with_capacity(2 * 1024 * 1024);
    revision.push_str(&"b".repeat(64));
    let mut event = record()?;
    event.actor = Actor::VerifiedSubject { key };
    event.action = Action::ConfigurationActivation {
        configuration: ConfigurationKind::Runtime,
        revision_sha256: revision,
    };
    let prepared = event.prepare()?;
    if let Actor::VerifiedSubject { key } = &prepared.record().actor {
        assert!(key.capacity() <= 64);
    } else {
        return Err("missing actor".into());
    }
    if let Action::ConfigurationActivation {
        revision_sha256, ..
    } = &prepared.record().action
    {
        assert!(revision_sha256.capacity() <= 64);
    } else {
        return Err("missing revision".into());
    }
    assert!(prepared.body.capacity() <= RECORD_BYTES);
    Ok(())
}

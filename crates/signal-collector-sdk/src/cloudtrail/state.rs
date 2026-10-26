//! Opt-in state projection; the legacy profile and its pinned bytes are unchanged.
use super::*;

fn selected<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    field(value, path).and_then(Value::as_str).filter(|text| {
        !text.is_empty() && text.len() <= 1024 && !text.chars().any(char::is_control)
    })
}

/// Selected IAM native facts only. A target name is a locator, not a principal
/// UID or approval. The trusted host resolves missing immutable IDs historically.
/// No request/response body, access key or credential material is copied.
pub fn normalize_state_record<'a>(
    raw: &'a [u8],
    profile: &CloudTrailProfile,
    pin: PreparationIdentity,
) -> Result<NormalizedRecord<'a>, NormalizeError> {
    let mut result = normalize_record(raw, profile, pin)?;
    if result.event.is_none() {
        return Ok(result);
    }
    let native = decode_json(raw, MAX_RECORD_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES)?;
    let service = selected(&native, &["eventSource"]);
    let operation = selected(&native, &["eventName"]);
    if service != Some("iam.amazonaws.com")
        || selected(&native, &["eventType"]) != Some("AwsApiCall")
    {
        return Ok(result);
    }
    let (action, kind, target_key) = match operation {
        Some("CreateUser" | "CreateAccessKey") => ("credential.create", "user", "userName"),
        Some("AttachUserPolicy" | "DetachUserPolicy" | "PutUserPolicy" | "DeleteUserPolicy") => {
            ("iam.permissions.change", "user", "userName")
        }
        Some("AttachRolePolicy" | "DetachRolePolicy" | "PutRolePolicy" | "DeleteRolePolicy") => {
            ("iam.permissions.change", "role", "roleName")
        }
        _ => return Ok(result),
    };
    let request_target = selected(&native, &["requestParameters", target_key]);
    let response_target = match operation {
        Some("CreateUser") => selected(&native, &["responseElements", "user", "userName"]),
        Some("CreateAccessKey") => {
            selected(&native, &["responseElements", "accessKey", "userName"])
        }
        _ => None,
    };
    // A malformed or conflicting explicit request never falls back to another
    // identity. Missing optional input can be supplied by the native response.
    let request_present = field(&native, &["requestParameters", target_key]).is_some();
    let response_path: &[&str] = if operation == Some("CreateUser") {
        &["responseElements", "user", "userName"]
    } else {
        &["responseElements", "accessKey", "userName"]
    };
    let response_present = action == "credential.create" && field(&native, response_path).is_some();
    let invalid_target = native
        .get("requestParameters")
        .is_some_and(|v| !v.is_null() && !v.is_object())
        || request_present && request_target.is_none()
        || response_present && response_target.is_none()
        || request_target
            .zip(response_target)
            .is_some_and(|(a, b)| a != b);
    let target = if invalid_target {
        None
    } else {
        request_target.or(response_target)
    };
    let actor_id = selected(&native, &["userIdentity", "principalId"]);
    let mut iam = serde_json::json!({"schema_version":1,"target_kind":kind,
        "identity_complete":target.is_some() && actor_id.is_some()});
    if let Some(target) = target {
        iam["target_name"] = target.into();
    }
    if let Some(actor) = actor_id {
        iam["actor_principal_id"] = actor.into();
    }
    if let Some(arn) = selected(&native, &["userIdentity", "arn"]) {
        iam["actor_arn"] = arn.into();
    }
    if operation == Some("CreateUser") && target.is_some() {
        for (name, key) in [("target_id", "userId"), ("target_arn", "arn")] {
            if let Some(value) = selected(&native, &["responseElements", "user", key]) {
                iam[name] = value.into();
            }
        }
    }
    // Policy identity is context for the mutation, never an effective grant set.
    for (name, key) in [("policy_arn", "policyArn"), ("policy_name", "policyName")] {
        if let Some(value) = selected(&native, &["requestParameters", key]) {
            iam[name] = value.into();
        }
    }
    result
        .reasons
        .retain(|reason| *reason != Reason::UnsupportedOperation);
    if target.is_none() || actor_id.is_none() {
        result.reasons.push(Reason::MissingRequiredNative);
    }
    let outcome = outcome(&native, false);
    if outcome.is_none() {
        result.reasons.push(Reason::UnknownOperationOutcome);
    }
    if let Some(event) = &mut result.event {
        event.attributes["aws"]["cloudtrail"]["iam"] = iam;
        event.attributes["normalizer"] =
            serde_json::json!({"id":"cloudtrail-state-management","revision":"v1"});
        event.attributes["security"]["action"] = action.into();
        if let Some(outcome) = outcome {
            event.attributes["security"]["outcome"] = outcome.into();
        }
        let mut writer = EventWriter(Vec::new());
        if serde_json::to_writer(&mut writer, event).is_err() {
            result.event = None;
            result.bytes = None;
            result.reasons = vec![Reason::PreparedEventBytesExceeded];
            result.disposition = Disposition::QuarantineRecord;
            return Ok(result);
        }
        result.bytes = Some(writer.0);
    }
    result.disposition = if result.reasons.is_empty() {
        Disposition::Emit
    } else {
        Disposition::EmitIndeterminate
    };
    Ok(result)
}

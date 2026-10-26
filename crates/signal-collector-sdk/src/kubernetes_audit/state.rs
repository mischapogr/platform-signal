//! Opt-in selected RBAC/exec facts, separate from legacy admitted-Pod projection.
use super::*;

fn segment(value: &str) -> bool {
    identity(value) && !value.contains(['/', '%', '?', '#']) && value != "." && value != ".."
}

/// Classify supported resource endpoints only. HTTP acceptance of an exec stream
/// is not command success, privilege, operator approval or source coverage.
pub fn normalize_state_record<'a>(
    raw: &'a [u8],
    profile: &Profile,
    id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<NormalizedRecord<'a>, Error> {
    let mut result = normalize_record(raw, profile, id, observed_at)?;
    let native =
        crate::cloudtrail::decode_json(raw, MAX_RECORD_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES)
            .map_err(|_| Error::Decode)?;
    let uri = native["requestURI"].as_str().ok_or(Error::Record)?;
    let path = uri.split_once('?').map_or(uri, |(path, _)| path);
    let metadata = &mut result.event.attributes["kubernetes"];
    metadata["state_profile_revision"] = "v1".into();
    let object = &metadata["object"];
    let resource = object["resource"].as_str().unwrap_or("");
    let namespace = object["namespace"].as_str().unwrap_or("");
    let name = object["name"].as_str().unwrap_or("");
    let group = object["apiGroup"].as_str().unwrap_or("");
    let subresource = object["subresource"].as_str().unwrap_or("");
    let verb = metadata["verb"].as_str().unwrap_or("");
    let stage = metadata["stage"].as_str().unwrap_or("");
    let code = metadata["response_code"].as_u64();
    let dry_run = metadata["dry_run"].as_bool() != Some(false);
    let exec = group.is_empty()
        && resource == "pods"
        && subresource == "exec"
        && ["create", "get"].contains(&verb)
        && segment(namespace)
        && segment(name)
        && path == format!("/api/v1/namespaces/{namespace}/pods/{name}/exec");
    let namespaced = ["roles", "rolebindings"].contains(&resource);
    let cluster = ["clusterroles", "clusterrolebindings"].contains(&resource);
    let collection = if namespaced {
        format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/{resource}")
    } else {
        format!("/apis/rbac.authorization.k8s.io/v1/{resource}")
    };
    let rbac = group == "rbac.authorization.k8s.io"
        && subresource.is_empty()
        && (namespaced && segment(namespace) || cluster && namespace.is_empty())
        && segment(name)
        && ["create", "update", "patch", "delete"].contains(&verb)
        && (path == format!("{collection}/{name}") || verb == "create" && path == collection);
    let terminal = ["ResponseStarted", "ResponseComplete"].contains(&stage);
    let outcome = if exec {
        if terminal && !dry_run && matches!(code, Some(101 | 200)) {
            "success"
        } else if terminal && matches!(code, Some(400..=599)) {
            "failure"
        } else {
            "unknown"
        }
    } else if dry_run {
        "unknown"
    } else {
        result.event.attributes["security"]["outcome"]
            .as_str()
            .unwrap_or("unknown")
    };
    let outcome = outcome.to_owned();
    if exec || rbac {
        result.event.attributes["security"]["action"] =
            if exec { "k8s.exec" } else { "k8s.rbac.change" }.into();
        result.event.attributes["security"]["outcome"] = outcome.clone().into();
        if exec && outcome != "unknown" {
            result.event.attributes["kubernetes"]["exec_session_accepted"] =
                (outcome == "success").into();
        }
    }
    // Selected additional fields are finite; never clone a response body/URI.
    if serde_json::to_vec(&result.event)
        .map_err(|_| Error::Record)?
        .len()
        > 65536
    {
        return Err(Error::Record);
    }
    Ok(result)
}

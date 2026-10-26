use super::{Error, Kind, Profile, size, string, text};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Versioned selected metadata. No annotations, command/env/volume or arbitrary
/// native spec/status body is retained. This is a snapshot, not effective RBAC.
#[derive(Clone, Debug, Serialize)]
pub struct MetadataObject {
    schema_version: u16,
    uid: String,
    name: String,
    namespace: Option<String>,
    resource_version: String,
    labels: BTreeMap<String, String>,
    owners: Vec<Value>,
    properties: Value,
    observed_at: DateTime<Utc>,
}
impl MetadataObject {
    pub fn uid(&self) -> &str {
        &self.uid
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    pub fn resource_version(&self) -> &str {
        &self.resource_version
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
    pub fn owners(&self) -> &[Value] {
        &self.owners
    }
    pub fn properties(&self) -> &Value {
        &self.properties
    }
    pub(super) fn name_key(&self) -> (Option<&str>, &str) {
        (self.namespace(), self.name())
    }
    pub(super) fn same_content(&self, other: &Self) -> bool {
        self.uid == other.uid
            && self.name == other.name
            && self.namespace == other.namespace
            && self.resource_version == other.resource_version
            && self.labels == other.labels
            && self.owners == other.owners
            && self.properties == other.properties
    }
}
fn optional_text(value: &Value, key: &str) -> Result<Option<String>, Error> {
    value
        .get(key)
        .map(|_| string(value, key).map(str::to_owned))
        .transpose()
}
fn string_array(value: &Value, empty: bool) -> Result<(), Error> {
    let values = value
        .as_array()
        .filter(|a| a.len() <= 64)
        .ok_or(Error::Record)?;
    if values.iter().any(|v| {
        v.as_str()
            .is_none_or(|s| !(text(s) || empty && s.is_empty()))
    }) {
        return Err(Error::Record);
    }
    Ok(())
}
fn rules(native: &Value) -> Result<Value, Error> {
    let Some(rules) = native.get("rules").filter(|v| !v.is_null()) else {
        return Ok(json!([]));
    };
    let array = rules
        .as_array()
        .filter(|a| a.len() <= 64)
        .ok_or(Error::Record)?;
    for rule in array {
        let object = rule.as_object().ok_or(Error::Record)?;
        if object.keys().any(|k| {
            ![
                "verbs",
                "apiGroups",
                "resources",
                "resourceNames",
                "nonResourceURLs",
            ]
            .contains(&k.as_str())
        }) || !object.contains_key("verbs")
        {
            return Err(Error::Record);
        }
        for (key, value) in object {
            string_array(value, key == "apiGroups")?;
        }
    }
    size(rules, 64 * 1024)?;
    Ok(rules.clone())
}
fn aggregation(native: &Value) -> Result<Value, Error> {
    let Some(value) = native.get("aggregationRule") else {
        return Ok(Value::Null);
    };
    let map = value.as_object().ok_or(Error::Record)?;
    if map.len() != 1 || !map.contains_key("clusterRoleSelectors") {
        return Err(Error::Record);
    }
    let selectors = value["clusterRoleSelectors"]
        .as_array()
        .filter(|a| a.len() <= 32)
        .ok_or(Error::Record)?;
    for selector in selectors {
        let selector = selector.as_object().ok_or(Error::Record)?;
        if selector
            .keys()
            .any(|k| !["matchLabels", "matchExpressions"].contains(&k.as_str()))
        {
            return Err(Error::Record);
        }
        if let Some(labels) = selector.get("matchLabels") {
            label_map(labels)?;
        }
        if let Some(expressions) = selector.get("matchExpressions") {
            let array = expressions
                .as_array()
                .filter(|a| a.len() <= 32)
                .ok_or(Error::Record)?;
            for expression in array {
                let map = expression.as_object().ok_or(Error::Record)?;
                if map
                    .keys()
                    .any(|k| !["key", "operator", "values"].contains(&k.as_str()))
                {
                    return Err(Error::Record);
                }
                string(expression, "key")?;
                string(expression, "operator")?;
                if let Some(values) = map.get("values") {
                    string_array(values, true)?;
                }
            }
        }
    }
    size(value, 16 * 1024)?;
    Ok(value.clone())
}
fn label_map(value: &Value) -> Result<BTreeMap<String, String>, Error> {
    let values = value
        .as_object()
        .filter(|v| v.len() <= 64)
        .ok_or(Error::Record)?;
    let mut result = BTreeMap::new();
    for (key, value) in values {
        let value = value.as_str().ok_or(Error::Record)?;
        if !text(key) || !(text(value) || value.is_empty()) {
            return Err(Error::Record);
        }
        result.insert(key.clone(), value.into());
    }
    Ok(result)
}
fn properties(native: &Value, profile: &Profile) -> Result<Value, Error> {
    match profile.kind {
        Kind::Pod => {
            let spec = native
                .get("spec")
                .and_then(Value::as_object)
                .ok_or(Error::Record)?;
            let node = optional_text(&native["spec"], "nodeName")?;
            if profile
                .node
                .as_ref()
                .is_some_and(|expected| node.as_ref() != Some(expected))
            {
                return Err(Error::Scope);
            }
            let service_account = optional_text(&native["spec"], "serviceAccountName")?;
            let mut containers = Vec::new();
            let mut names = std::collections::BTreeSet::new();
            for key in ["containers", "initContainers", "ephemeralContainers"] {
                let array = match spec.get(key) {
                    None if key != "containers" => continue,
                    Some(v) => v
                        .as_array()
                        .filter(|a| a.len() <= 128)
                        .ok_or(Error::Record)?,
                    _ => return Err(Error::Record),
                };
                if key == "containers" && array.is_empty() {
                    return Err(Error::Record);
                }
                for container in array {
                    let name = string(container, "name")?;
                    if !names.insert(name.to_owned()) {
                        return Err(Error::Record);
                    }
                    containers.push(json!({"name":name,"class":key}));
                }
            }
            Ok(
                json!({"node_name":node,"service_account_name":service_account,"containers":containers}),
            )
        }
        Kind::Role | Kind::ClusterRole => Ok(json!({"rules":rules(native)?,
            "aggregation_rule":if profile.kind==Kind::ClusterRole {aggregation(native)?} else {Value::Null}})),
        Kind::RoleBinding | Kind::ClusterRoleBinding => {
            let role = native.get("roleRef").ok_or(Error::Record)?;
            let role_kind = string(role, "kind")?;
            if string(role, "apiGroup")? != "rbac.authorization.k8s.io"
                || !["Role", "ClusterRole"].contains(&role_kind)
                || profile.kind == Kind::ClusterRoleBinding && role_kind != "ClusterRole"
            {
                return Err(Error::Record);
            }
            let subjects = match native.get("subjects") {
                None | Some(Value::Null) => &[][..],
                Some(v) => v
                    .as_array()
                    .filter(|a| a.len() <= 128)
                    .ok_or(Error::Record)?
                    .as_slice(),
            };
            let mut projected = Vec::new();
            for subject in subjects {
                projected.push(json!({"kind":string(subject,"kind")?,"name":string(subject,"name")?,
                    "namespace":optional_text(subject,"namespace")?,
                    "api_group":match subject.get("apiGroup") {None=>None,Some(Value::String(s)) if s.is_empty()=>Some("".to_owned()),Some(_)=>Some(string(subject,"apiGroup")?.to_owned())}}));
            }
            Ok(
                json!({"role_ref":{"api_group":"rbac.authorization.k8s.io","kind":role_kind,"name":string(role,"name")?},"subjects":projected}),
            )
        }
        Kind::Node | Kind::Namespace => Ok(json!({})),
    }
}
pub(super) fn project(
    native: &Value,
    profile: &Profile,
    observed_at: DateTime<Utc>,
    typed_list_item: bool,
) -> Result<MetadataObject, Error> {
    // Native typed lists omit item TypeMeta. Only their already validated
    // outer API version/kind can supply it; watch objects remain explicit.
    for (key, expected) in [
        ("apiVersion", profile.kind.api_version()),
        ("kind", profile.kind.name()),
    ] {
        match native.get(key) {
            None if typed_list_item => {}
            Some(Value::String(value)) if value == expected => {}
            _ => return Err(Error::Scope),
        }
    }
    let metadata = native.get("metadata").ok_or(Error::Record)?;
    let uid = string(metadata, "uid")?.to_owned();
    let name = string(metadata, "name")?.to_owned();
    let resource_version = string(metadata, "resourceVersion")?.to_owned();
    let namespace = optional_text(metadata, "namespace")?;
    if profile.kind.namespaced() && namespace.is_none()
        || !profile.kind.namespaced() && namespace.is_some()
        || profile
            .namespace
            .as_ref()
            .is_some_and(|expected| namespace.as_ref() != Some(expected))
    {
        return Err(Error::Scope);
    }
    let labels = metadata
        .get("labels")
        .map(label_map)
        .transpose()?
        .unwrap_or_default();
    let mut owners = Vec::new();
    if let Some(value) = metadata.get("ownerReferences") {
        let values = value
            .as_array()
            .filter(|v| v.len() <= 16)
            .ok_or(Error::Record)?;
        for value in values {
            let controller = match value.get("controller") {
                None => false,
                Some(v) => v.as_bool().ok_or(Error::Record)?,
            };
            owners.push(json!({"uid":string(value,"uid")?,"name":string(value,"name")?,"kind":string(value,"kind")?,"api_version":string(value,"apiVersion")?,"controller":controller}));
        }
    }
    Ok(MetadataObject {
        schema_version: 1,
        uid,
        name,
        namespace,
        resource_version,
        labels,
        owners,
        properties: properties(native, profile)?,
        observed_at,
    })
}

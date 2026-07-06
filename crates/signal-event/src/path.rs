//! Generic attribute lookup shared by queries and predicate evaluation.

use serde_json::{Map, Value};

/// Look up a relative attribute path while preserving namespaced map keys.
///
/// An exact key wins at every level. Otherwise the longest existing dotted prefix
/// wins, and its object is traversed recursively. A scalar prefix blocks shorter
/// alternatives; arrays are values rather than an indexed path syntax.
pub fn lookup_attribute_path<'a>(
    attributes: &'a Map<String, Value>,
    path: &str,
) -> Option<&'a Value> {
    let mut object = attributes;
    let mut remaining = path;
    loop {
        if let Some(value) = object.get(remaining) {
            return Some(value);
        }
        let (prefix, suffix, value) =
            remaining.match_indices('.').rev().find_map(|(index, _)| {
                let prefix = &remaining[..index];
                object
                    .get(prefix)
                    .map(|value| (prefix, &remaining[index + 1..], value))
            })?;
        let _ = prefix;
        object = value.as_object()?;
        remaining = suffix;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_namespaced_and_nested_keys_have_deterministic_precedence() {
        let value = json!({
            "user.name": "exact",
            "user": {"name": "nested"},
            "vendor.owner": {"name": "namespaced", "name.first": "direct"},
            "vendor": {"owner": {"name": "shorter"}}
        });
        let Some(attributes) = value.as_object() else {
            panic!("fixture must be object")
        };
        assert_eq!(
            lookup_attribute_path(attributes, "user.name"),
            Some(&json!("exact"))
        );
        assert_eq!(
            lookup_attribute_path(attributes, "vendor.owner.name"),
            Some(&json!("namespaced"))
        );
        assert_eq!(
            lookup_attribute_path(attributes, "vendor.owner.name.first"),
            Some(&json!("direct"))
        );
        assert_eq!(lookup_attribute_path(attributes, "absent.name"), None);
    }

    #[test]
    fn scalar_prefix_does_not_fall_back_or_index_arrays() {
        let value = json!({"a.b": 1, "a": {"b": {"c": 2}}, "items": [1]});
        let Some(attributes) = value.as_object() else {
            panic!("fixture must be object")
        };
        assert_eq!(lookup_attribute_path(attributes, "a.b.c"), None);
        assert_eq!(lookup_attribute_path(attributes, "items.0"), None);
    }
}

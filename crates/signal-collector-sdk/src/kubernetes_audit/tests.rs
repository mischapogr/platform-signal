// Unwraps assert successful construction of owned synthetic fixtures only.
#![allow(clippy::unwrap_used)]
use super::*;

fn native() -> Value {
    json!({
        "apiVersion":"audit.k8s.io/v1", "kind":"Event", "level":"RequestResponse",
        "auditID":"audit-1", "stage":"ResponseComplete", "verb":"create",
        "requestURI":"/api/v1/namespaces/example/pods?secret=never-project",
        "requestReceivedTimestamp":"2026-10-24T10:00:00Z",
        "stageTimestamp":"2026-10-24T10:00:01Z",
        "user":{"username":"synthetic-user","uid":"user-1","extra":{"token":"never-project"}},
        "objectRef":{"apiGroup":"","resource":"pods","namespace":"example","name":"pod-1","uid":"pod-uid"},
        "responseStatus":{"code":201,"message":"never-project"},
        "responseObject":{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"example","name":"pod-1","uid":"pod-uid"},
            "spec":{"containers":[{"name":"main","securityContext":{"privileged":true}}]}}
    })
}
fn projection(v: &Value) -> SignalEvent {
    let raw = serde_json::to_vec(v).unwrap();
    normalize_record(
        &raw,
        &Profile::new("cluster-1", "policy-1").unwrap(),
        Uuid::from_u128(1),
        "2026-10-24T10:02:00Z".parse().unwrap(),
    )
    .unwrap()
    .event()
    .clone()
}
fn privileged(v: &Value) -> Option<bool> {
    projection(v).attributes["security"]
        .get("privileged")
        .and_then(Value::as_bool)
}
#[test]
fn admitted_pod_metadata_and_original_are_exact() {
    let raw = serde_json::to_vec_pretty(&native()).unwrap();
    let profile = Profile::new("cluster-1", "policy-1").unwrap();
    let pin = Uuid::from_u128(1);
    let observed = "2026-10-24T10:02:00Z".parse().unwrap();
    let record = normalize_record(&raw, &profile, pin, observed).unwrap();
    assert_eq!(record.original(), raw);
    assert_eq!(
        *record.original_sha256(),
        <[u8; 32]>::from(Sha256::digest(&raw))
    );
    let event = record.event();
    assert_eq!(event.id, pin);
    assert_eq!(event.observed_at, observed);
    assert_eq!(event.timestamp.to_rfc3339(), "2026-10-24T10:00:01+00:00");
    assert_eq!(event.source.source_type, "kubernetes.audit");
    assert_eq!(event.attributes["kubernetes"]["object"]["uid"], "pod-uid");
    assert_eq!(
        event.attributes["security"],
        json!({"action":"k8s.workload.write","outcome":"success","privileged":true})
    );
    let bytes = serde_json::to_vec(event).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("never-project"));
    assert_eq!(
        bytes,
        serde_json::to_vec(
            normalize_record(&raw, &profile, pin, observed)
                .unwrap()
                .event()
        )
        .unwrap()
    );
}
#[test]
fn request_only_metadata_and_denied_cannot_prove_admission() {
    for level in ["Metadata", "Request"] {
        let mut v = native();
        v["level"] = json!(level);
        assert_eq!(privileged(&v), None);
    }
    for stage in ["RequestReceived", "ResponseStarted", "Panic"] {
        let mut v = native();
        v["stage"] = json!(stage);
        assert_eq!(projection(&v).attributes["security"]["outcome"], "unknown");
        assert_eq!(privileged(&v), None);
    }
    for code in [101, 302, 403, 500] {
        let mut v = native();
        v["responseStatus"]["code"] = json!(code);
        assert_eq!(privileged(&v), None);
        assert_eq!(
            projection(&v).attributes["security"]["outcome"],
            if code >= 400 { "failure" } else { "unknown" }
        );
    }
    let mut v = native();
    v.as_object_mut().unwrap().remove("responseStatus");
    assert_eq!(privileged(&v), None);
    v["requestObject"] = v["responseObject"].clone();
    v.as_object_mut().unwrap().remove("responseObject");
    assert_eq!(privileged(&v), None);
}
#[test]
fn admission_mutation_uses_returned_spec_only() {
    let mut v = native();
    v["requestObject"] = v["responseObject"].clone();
    v["responseObject"]["spec"]["containers"][0]["securityContext"]["privileged"] = json!(false);
    assert_eq!(privileged(&v), Some(false));
    v["responseObject"]["spec"]["containers"][0]
        .as_object_mut()
        .unwrap()
        .remove("securityContext");
    assert_eq!(privileged(&v), Some(false));
}
#[test]
fn all_container_types_are_checked_and_malformed_specs_stay_unknown() {
    for key in ["containers", "initContainers", "ephemeralContainers"] {
        let mut v = native();
        v["responseObject"]["spec"]["containers"] = json!([{"name":"main"}]);
        v["responseObject"]["spec"][key] =
            json!([{"name":"selected","securityContext":{"privileged":true}}]);
        assert_eq!(privileged(&v), Some(true));
        for invalid in [json!("true"), Value::Null, json!(1)] {
            v["responseObject"]["spec"][key][0]["securityContext"]["privileged"] = invalid;
            assert_eq!(privileged(&v), None);
        }
    }
    for invalid in [
        json!([]),
        json!({}),
        json!([null]),
        json!([{"name":"x"},{"name":"x"}]),
        json!([{"name":"x","securityContext":null}]),
    ] {
        let mut v = native();
        v["responseObject"]["spec"]["containers"] = invalid;
        assert_eq!(privileged(&v), None);
    }
}
#[test]
fn mismatched_or_unversioned_response_is_not_admitted_evidence() {
    for key in ["uid", "name", "namespace"] {
        let mut v = native();
        v["responseObject"]["metadata"][key] = json!("other");
        assert_eq!(privileged(&v), None);
        v["responseObject"]["metadata"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert_eq!(privileged(&v), None);
    }
    for key in ["apiVersion", "kind"] {
        let mut v = native();
        v["responseObject"][key] = json!("other");
        assert_eq!(privileged(&v), None);
    }
    let mut v = native();
    v["objectRef"].as_object_mut().unwrap().remove("uid");
    assert_eq!(privileged(&v), Some(true));
}
#[test]
fn subresources_and_other_groups_never_become_workload_writes() {
    for (key, value) in [
        ("resource", "deployments"),
        ("subresource", "exec"),
        ("apiGroup", "example.invalid"),
    ] {
        let mut v = native();
        v["objectRef"][key] = json!(value);
        assert!(
            projection(&v).attributes["security"]
                .get("action")
                .is_none()
        );
        assert_eq!(privileged(&v), None);
    }
    let mut v = native();
    v["verb"] = json!("get");
    assert!(
        projection(&v).attributes["security"]
            .get("action")
            .is_none()
    );
}
#[test]
fn actors_stages_and_trusted_binding_remain_separate() {
    let mut v = native();
    v["impersonatedUser"] = json!({"username":"impersonated"});
    v["annotations"] = json!({"cluster":"forged","policy_revision":"forged"});
    let e = projection(&v);
    assert_eq!(e.attributes["kubernetes"]["cluster"], "cluster-1");
    assert_eq!(e.attributes["kubernetes"]["policy_revision"], "policy-1");
    assert_eq!(
        e.attributes["kubernetes"]["user"]["username"],
        "synthetic-user"
    );
    assert_eq!(
        e.attributes["kubernetes"]["impersonated_user"]["username"],
        "impersonated"
    );
    v["stage"] = json!("RequestReceived");
    let early = projection(&v);
    assert_ne!(
        e.attributes["kubernetes"]["stage"],
        early.attributes["kubernetes"]["stage"]
    );
    assert_eq!(
        e.attributes["kubernetes"]["audit_id"],
        early.attributes["kubernetes"]["audit_id"]
    );
}
#[test]
fn invalid_native_fields_and_pins_refuse_with_static_errors() {
    let p = Profile::new("cluster", "policy").unwrap();
    let observed = "2026-10-24T10:02:00Z".parse().unwrap();
    for (key, value) in [
        ("stage", json!("future")),
        ("level", json!("None")),
        ("apiVersion", json!("v2")),
        ("auditID", json!("")),
        ("verb", json!("x".repeat(257))),
        ("user", json!({})),
        ("objectRef", Value::Null),
        ("responseStatus", json!({"code":"201"})),
        ("stageTimestamp", json!("2026-10-24T09:00:00Z")),
    ] {
        let mut v = native();
        v[key] = value;
        let raw = serde_json::to_vec(&v).unwrap();
        assert!(
            matches!(
                normalize_record(&raw, &p, Uuid::from_u128(1), observed),
                Err(Error::Record)
            ),
            "{key}"
        );
    }
    assert!(matches!(
        normalize_record(b"{}", &p, Uuid::nil(), observed),
        Err(Error::Record)
    ));
    assert!(Profile::new("", "policy").is_err());
    assert!(Profile::new("cluster", "p\n").is_err());
}
#[test]
fn strict_decoder_refuses_duplicate_trailing_deep_large_and_excess_nodes() {
    let p = Profile::new("cluster", "policy").unwrap();
    let observed = "2026-10-24T10:02:00Z".parse().unwrap();
    let inputs = [
        br#"{"auditID":"x","auditID":"y"}"#.to_vec(),
        br#"{"nested":{"x":1,"\u0078":2}}"#.to_vec(),
        b"{} {}".to_vec(),
        vec![b' '; MAX_RECORD_BYTES + 1],
        format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        )
        .into_bytes(),
        format!("[{}]", vec!["0"; MAX_JSON_NODES + 1].join(",")).into_bytes(),
    ];
    for raw in inputs {
        assert!(matches!(
            normalize_record(&raw, &p, Uuid::from_u128(1), observed),
            Err(Error::Decode)
        ));
    }
}

#[test]
fn dry_run_responses_never_claim_persisted_privileged_workloads() {
    for query in [
        "dryRun=All",
        "%64ryRun=All",
        "fieldManager=test&dryRun=All",
        "dryRun=",
        "dryRun=All&dryRun=All",
    ] {
        let mut v = native();
        v["requestURI"] = json!(format!("/api/v1/namespaces/example/pods?{query}"));
        assert_eq!(privileged(&v), None);
        assert_eq!(projection(&v).attributes["kubernetes"]["dry_run"], true);
    }
    let mut v = native();
    v["requestURI"] = json!("/api/v1/namespaces/example/pods?fieldManager=test");
    assert_eq!(privileged(&v), Some(true));
}

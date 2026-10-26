// All unchecked constructions below assert owned synthetic fixtures, never a
// production source, transport or identity grant.
#![allow(clippy::unwrap_used)]
use super::*;
use serde_json::json;
fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap()
}
fn profile(limits: Limits) -> Profile {
    Profile::new(
        "synthetic-cluster",
        Kind::Pod,
        Some("team"),
        Some("node-a"),
        limits,
    )
    .unwrap()
}
fn pod(uid: &str, name: &str, rv: &str) -> Value {
    json!({"apiVersion":"v1","kind":"Pod","metadata":{
    "uid":uid,"name":name,"namespace":"team","resourceVersion":rv,"labels":{"app":"fixture"},
    "annotations":{"token":"do-not-copy"},"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"replica","uid":"owner-uid","controller":true}]},
    "spec":{"nodeName":"node-a","serviceAccountName":"fixture-sa","containers":[{"name":"main","env":[{"name":"TOKEN","value":"do-not-copy"}],"command":["do-not-copy"]}]}})
}
fn page(items: Vec<Value>, rv: &str, token: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":rv,"continue":token},"items":items})).unwrap()
}
fn watch(action: &str, object: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"type":action,"object":object})).unwrap()
}
fn listed(limits: Limits) -> Reconciler {
    let mut r = Reconciler::new(profile(limits));
    let epoch = r.begin_list(at(0)).unwrap();
    assert!(
        r.list_page(
            epoch,
            None,
            &page(vec![pod("uid-a", "pod-a", "a")], "list-z", ""),
            at(1)
        )
        .unwrap()
    );
    r
}
#[test]
fn complete_pages_publish_atomically_and_keep_trusted_scope_original_times() {
    let mut r = Reconciler::new(profile(Limits::default()));
    let epoch = r.begin_list(at(0)).unwrap();
    assert!(
        !r.list_page(
            epoch,
            None,
            &page(
                vec![pod("uid-a", "pod-a", "rv-a")],
                "opaque+revision",
                "next"
            ),
            at(1)
        )
        .unwrap()
    );
    assert!(r.lookup("uid-a", at(1)).is_none());
    assert_eq!(r.metrics().staged_objects, 1);
    assert!(
        r.list_page(
            epoch,
            Some("next"),
            &page(vec![pod("uid-b", "pod-b", "rv-b")], "opaque+revision", ""),
            at(2)
        )
        .unwrap()
    );
    let object = r.lookup("uid-a", at(3)).unwrap();
    assert_eq!(object.observed_at(), at(0));
    assert_eq!(object.owners()[0]["uid"], "owner-uid");
    assert_eq!(object.properties()["service_account_name"], "fixture-sa");
    let snapshot = serde_json::to_value(r.snapshot(at(4))).unwrap();
    assert_eq!(snapshot["schema_version"], 1);
    assert_eq!(snapshot["cluster"], "synthetic-cluster");
    assert_eq!(snapshot["objects"].as_array().unwrap().len(), 2);
    assert!(!snapshot.to_string().contains("do-not-copy"));
    assert_eq!(snapshot["expires_at"], json!(at(300)));
    assert!(snapshot["authoritative"].as_bool().unwrap());
}
#[test]
fn partial_replacement_or_failed_pagination_never_establishes_absence() {
    for mode in ["revision", "token", "repeat", "duplicate"] {
        let mut r = listed(Limits::default());
        let epoch = r.begin_list(at(3)).unwrap();
        assert!(
            !r.list_page(
                epoch,
                None,
                &page(vec![pod("uid-b", "pod-b", "b")], "new", "continue"),
                at(4)
            )
            .unwrap()
        );
        let (token, rv, next, items) = match mode {
            "revision" => (Some("continue"), "other", "", vec![]),
            "token" => (Some("foreign"), "new", "", vec![]),
            "repeat" => (Some("continue"), "new", "continue", vec![]),
            _ => (
                Some("continue"),
                "new",
                "",
                vec![pod("uid-b", "pod-b", "b")],
            ),
        };
        assert!(
            r.list_page(epoch, token, &page(items, rv, next), at(5))
                .is_err()
        );
        assert!(!r.authoritative(at(6)));
        let snapshot = r.snapshot(at(6));
        assert_eq!(snapshot.generation, epoch - 1);
        assert_eq!(snapshot.objects.len(), 1);
        assert_eq!(snapshot.objects[0].uid(), "uid-a");
        assert_eq!(r.metrics().staged_objects, 0);
        assert_eq!(r.metrics().retained_objects, 1);
    }
}
#[test]
fn revisions_are_opaque_and_order_is_stream_epoch_sequence() {
    let mut r = listed(Limits::default());
    let epoch = r.epoch();
    r.watch_frame(
        epoch,
        1,
        &watch("MODIFIED", pod("uid-a", "pod-a", "0-not-a-number")),
        at(2),
    )
    .unwrap();
    assert_eq!(r.resource_version(), Some("0-not-a-number"));
    assert_eq!(r.lookup("uid-a", at(2)).unwrap().observed_at(), at(2));
    r.watch_frame(
        epoch,
        2,
        &watch("MODIFIED", pod("uid-a", "pod-a", "-earlier-looking")),
        at(3),
    )
    .unwrap();
    assert_eq!(r.resource_version(), Some("-earlier-looking"));
    assert!(
        r.watch_frame(
            epoch,
            4,
            &watch("MODIFIED", pod("uid-a", "pod-a", "next")),
            at(4)
        )
        .is_err()
    );
    assert!(!r.authoritative(at(4)));
    assert_eq!(r.metrics().retained_objects, 1);
}
#[test]
fn exact_last_frame_replay_is_idempotent_but_conflicting_or_older_epoch_refuses() {
    let mut r = listed(Limits::default());
    let epoch = r.epoch();
    let raw = watch("MODIFIED", pod("uid-a", "pod-a", "changed"));
    r.watch_frame(epoch, 1, &raw, at(2)).unwrap();
    let before = r.metrics().watch_bytes;
    r.watch_frame(epoch, 1, &raw, at(5)).unwrap();
    assert_eq!(r.lookup("uid-a", at(5)).unwrap().observed_at(), at(2));
    assert_eq!(r.metrics().watch_bytes, before);
    assert!(
        r.watch_frame(
            epoch,
            1,
            &watch("MODIFIED", pod("uid-a", "pod-a", "conflict")),
            at(6)
        )
        .is_err()
    );
    let new = r.begin_list(at(7)).unwrap();
    assert!(
        r.list_page(new, None, &page(vec![], "fresh", ""), at(7))
            .unwrap()
    );
    assert!(r.watch_frame(epoch, 1, &raw, at(8)).is_err());
    assert!(!r.authoritative(at(8)));
}
#[test]
fn bookmark_and_duplicate_object_never_renew_collection_or_object_age() {
    let mut r = listed(Limits {
        max_age_seconds: 10,
        ..Limits::default()
    });
    let epoch = r.epoch();
    r.watch_frame(epoch, 1, &watch("ADDED", pod("uid-a", "pod-a", "a")), at(4))
        .unwrap();
    assert_eq!(r.lookup("uid-a", at(4)).unwrap().observed_at(), at(0));
    r.watch_frame(
        epoch,
        2,
        &watch(
            "BOOKMARK",
            json!({"metadata":{"resourceVersion":"bookmark"}}),
        ),
        at(8),
    )
    .unwrap();
    assert_eq!(r.lookup("uid-a", at(9)).unwrap().observed_at(), at(0));
    assert!(r.lookup("uid-a", at(10)).is_none());
    assert!(!r.authoritative(at(9)));
    assert_eq!(r.snapshot(at(11)).observed_at, Some(at(0)));
}
#[test]
fn delayed_old_uid_delete_preserves_recreated_name() {
    let mut r = listed(Limits::default());
    let epoch = r.epoch();
    r.watch_frame(
        epoch,
        1,
        &watch("DELETED", pod("uid-a", "pod-a", "delete-old")),
        at(2),
    )
    .unwrap();
    r.watch_frame(
        epoch,
        2,
        &watch("ADDED", pod("uid-new", "pod-a", "new")),
        at(3),
    )
    .unwrap();
    r.watch_frame(
        epoch,
        3,
        &watch("DELETED", pod("uid-a", "pod-a", "late-old")),
        at(4),
    )
    .unwrap();
    assert!(r.lookup("uid-a", at(4)).is_none());
    assert_eq!(r.lookup("uid-new", at(4)).unwrap().name(), "pod-a");
    assert_eq!(r.metrics().retained_objects, 1);
}
#[test]
fn conflicting_same_revision_or_impossible_lifecycle_refuses_without_replacement() {
    for action in ["MODIFIED", "ADDED"] {
        let mut r = listed(Limits::default());
        let epoch = r.epoch();
        let mut changed = pod("uid-a", "pod-a", "a");
        changed["metadata"]["labels"]["app"] = json!("conflicting");
        assert!(
            r.watch_frame(epoch, 1, &watch(action, changed), at(2))
                .is_err()
        );
        assert_eq!(r.snapshot(at(3)).objects[0].labels()["app"], "fixture");
    }
    let mut r = listed(Limits::default());
    let epoch = r.epoch();
    assert!(
        r.watch_frame(
            epoch,
            1,
            &watch("MODIFIED", pod("absent", "pod-b", "x")),
            at(2)
        )
        .is_err()
    );
}
#[test]
fn capacities_refuse_without_evicting_retained_inventory() {
    let mut r = listed(Limits {
        max_objects: 1,
        ..Limits::default()
    });
    let epoch = r.epoch();
    assert_eq!(
        r.watch_frame(epoch, 1, &watch("ADDED", pod("uid-b", "pod-b", "b")), at(2)),
        Err(Error::Limit)
    );
    assert_eq!(r.metrics().retained_objects, 1);
    assert!(!r.authoritative(at(2)));
    let mut r = listed(Limits {
        max_watch_frames: 1,
        ..Limits::default()
    });
    let epoch = r.epoch();
    r.watch_frame(
        epoch,
        1,
        &watch("BOOKMARK", json!({"metadata":{"resourceVersion":"b"}})),
        at(2),
    )
    .unwrap();
    assert!(
        r.watch_frame(
            epoch,
            2,
            &watch("BOOKMARK", json!({"metadata":{"resourceVersion":"c"}})),
            at(3)
        )
        .is_err()
    );
    let mut r = Reconciler::new(profile(Limits {
        max_pages: 1,
        ..Limits::default()
    }));
    let epoch = r.begin_list(at(0)).unwrap();
    assert!(
        !r.list_page(epoch, None, &page(vec![], "list", "next"), at(0))
            .unwrap()
    );
    assert!(
        r.list_page(epoch, Some("next"), &page(vec![], "list", ""), at(1))
            .is_err()
    );
}
#[test]
fn failed_clock_scope_decode_and_expired_list_cannot_make_current_state() {
    let mut r = listed(Limits::default());
    let epoch = r.epoch();
    assert!(
        r.watch_frame(
            epoch,
            1,
            &watch("BOOKMARK", json!({"metadata":{"resourceVersion":"x"}})),
            at(0)
        )
        .is_err()
    );
    for invalid in [
        b"{} {}".as_slice(),
        br#"{"type":"ADDED","type":"BOOKMARK"}"#.as_slice(),
    ] {
        let mut r = listed(Limits::default());
        let epoch = r.epoch();
        assert!(r.watch_frame(epoch, 1, invalid, at(2)).is_err());
    }
    let mut bad = pod("uid", "pod", "rv");
    bad["metadata"]["namespace"] = json!("foreign");
    let mut r = Reconciler::new(profile(Limits::default()));
    let epoch = r.begin_list(at(0)).unwrap();
    assert!(
        r.list_page(epoch, None, &page(vec![bad], "list", ""), at(1))
            .is_err()
    );
    let mut r = Reconciler::new(profile(Limits {
        max_age_seconds: 2,
        ..Limits::default()
    }));
    let epoch = r.begin_list(at(0)).unwrap();
    assert!(
        r.list_page(epoch, None, &page(vec![], "list", ""), at(2))
            .is_err()
    );
}
#[test]
fn rbac_projection_retains_permissions_subjects_and_unsupported_aggregation_inputs() {
    let mut r = Reconciler::new(
        Profile::new("cluster", Kind::ClusterRole, None, None, Limits::default()).unwrap(),
    );
    let object = json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole",
        "metadata":{"name":"role","uid":"role-uid","resourceVersion":"role-rv"},
        "rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}],
        "aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"app":"fixture"}}]}});
    let raw=serde_json::to_vec(&json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleList","metadata":{"resourceVersion":"list"},"items":[object]})).unwrap();
    let epoch = r.begin_list(at(0)).unwrap();
    r.list_page(epoch, None, &raw, at(0)).unwrap();
    assert_eq!(
        r.lookup("role-uid", at(1)).unwrap().properties()["rules"][0]["verbs"],
        json!(["get", "list"])
    );
    assert!(r.lookup("role-uid", at(1)).unwrap().properties()["aggregation_rule"].is_object());
    let mut r = Reconciler::new(
        Profile::new(
            "cluster",
            Kind::RoleBinding,
            Some("team"),
            None,
            Limits::default(),
        )
        .unwrap(),
    );
    let object = json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"binding-uid","name":"binding","namespace":"team","resourceVersion":"rv"},
        "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"role"},"subjects":[{"kind":"ServiceAccount","name":"sa","namespace":"team"}]});
    let raw=serde_json::to_vec(&json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","metadata":{"resourceVersion":"list"},"items":[object]})).unwrap();
    let epoch = r.begin_list(at(0)).unwrap();
    r.list_page(epoch, None, &raw, at(0)).unwrap();
    assert_eq!(
        r.lookup("binding-uid", at(1)).unwrap().properties()["subjects"][0]["name"],
        "sa"
    );
}
#[test]
fn error_events_and_interruption_keep_history_stale_until_complete_relist() {
    let mut r = listed(Limits::default());
    let epoch = r.epoch();
    assert!(
        r.watch_frame(
            epoch,
            1,
            &watch("ERROR", json!({"kind":"Status","code":410})),
            at(2)
        )
        .is_err()
    );
    assert_eq!(r.snapshot(at(3)).objects.len(), 1);
    let epoch = r.begin_list(at(4)).unwrap();
    assert!(
        r.list_page(epoch, None, &page(vec![], "replacement", ""), at(4))
            .unwrap()
    );
    assert!(r.authoritative(at(5)));
    assert_eq!(r.metrics().retained_objects, 0);
    r.invalidate();
    assert!(!r.authoritative(at(6)));
    assert_eq!(r.metrics().staged_objects, 0);
}
#[test]
fn profile_binding_pins_scope_kind_selector_and_limits() {
    let p = profile(Limits::default());
    assert_eq!(p.binding(), profile(Limits::default()).binding());
    assert_ne!(
        p.binding(),
        Profile::new(
            "other",
            Kind::Pod,
            Some("team"),
            Some("node-a"),
            Limits::default()
        )
        .unwrap()
        .binding()
    );
    assert_ne!(
        p.binding(),
        profile(Limits {
            max_objects: 4,
            ..Limits::default()
        })
        .binding()
    );
    assert!(Profile::new("cluster", Kind::Node, Some("team"), None, Limits::default()).is_err());
    assert!(Profile::new("cluster", Kind::Role, None, Some("node"), Limits::default()).is_err());
}

#[test]
fn native_empty_rbac_arrays_accept_omitted_null_and_empty_but_refuse_wrong_types() {
    for kind in [
        Kind::Role,
        Kind::ClusterRole,
        Kind::RoleBinding,
        Kind::ClusterRoleBinding,
    ] {
        for value in [
            None,
            Some(Value::Null),
            Some(json!([])),
            Some(json!({})),
            Some(json!("malformed")),
        ] {
            let namespace = kind.namespaced().then_some("team");
            let mut object = json!({"kind":kind.name(),"apiVersion":kind.api_version(),"metadata":{"uid":"uid","name":"name","resourceVersion":"rv"}});
            if let Some(namespace) = namespace {
                object["metadata"]["namespace"] = json!(namespace);
            }
            let field = if matches!(kind, Kind::Role | Kind::ClusterRole) {
                "rules"
            } else {
                "subjects"
            };
            if matches!(kind, Kind::RoleBinding | Kind::ClusterRoleBinding) {
                object["roleRef"] = json!({"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"role"});
            }
            if let Some(value) = &value {
                object[field] = value.clone();
            }
            let raw=serde_json::to_vec(&json!({"kind":format!("{}List",kind.name()),"apiVersion":kind.api_version(),"metadata":{"resourceVersion":"list"},"items":[object]})).unwrap();
            let mut r = Reconciler::new(
                Profile::new("cluster", kind, namespace, None, Limits::default()).unwrap(),
            );
            let epoch = r.begin_list(at(0)).unwrap();
            let result = r.list_page(epoch, None, &raw, at(0));
            assert_eq!(
                result.is_ok(),
                value.is_none() || value.as_ref().is_some_and(|v| v.is_null() || v.is_array()),
                "{kind:?} {value:?}"
            );
        }
    }
}
#[test]
fn projected_inventory_input_and_stream_byte_caps_refuse_without_silent_eviction() {
    let mut r = Reconciler::new(profile(Limits {
        max_object_bytes: 256,
        ..Limits::default()
    }));
    let epoch = r.begin_list(at(0)).unwrap();
    assert_eq!(
        r.list_page(
            epoch,
            None,
            &page(vec![pod("uid", "name", "rv")], "list", ""),
            at(0)
        ),
        Err(Error::Limit)
    );
    let mut r = listed(Limits {
        max_inventory_bytes: 1024,
        max_object_bytes: 1024,
        ..Limits::default()
    });
    let epoch = r.begin_list(at(2)).unwrap();
    let objects = (0..10)
        .map(|i| pod(&format!("uid-{i}"), &format!("pod-{i}"), "rv"))
        .collect();
    assert_eq!(
        r.list_page(epoch, None, &page(objects, "list", ""), at(2)),
        Err(Error::Limit)
    );
    assert_eq!(r.metrics().retained_objects, 1);
    let mut r = listed(Limits {
        max_watch_bytes: 256,
        ..Limits::default()
    });
    let epoch = r.epoch();
    let mut refused = false;
    for sequence in 1..=8 {
        let raw = watch(
            "BOOKMARK",
            json!({"metadata":{"resourceVersion":format!("bookmark-{sequence}")}}),
        );
        if r.watch_frame(epoch, sequence, &raw, at(sequence as i64 + 1))
            .is_err()
        {
            refused = true;
            break;
        }
    }
    assert!(refused);
    assert_eq!(r.metrics().retained_objects, 1);
    assert!(r.metrics().watch_bytes <= 256);
    let mut r = Reconciler::new(profile(Limits {
        max_page_bytes: 256,
        ..Limits::default()
    }));
    let epoch = r.begin_list(at(0)).unwrap();
    assert_eq!(
        r.list_page(epoch, None, &vec![b' '; 257], at(0)),
        Err(Error::Limit)
    );
}
#[test]
fn strict_native_depth_and_node_budgets_apply_even_to_discarded_fields() {
    for raw in [
        format!("{{\"discarded\":{}0{}}}", "[".repeat(40), "]".repeat(40)).into_bytes(),
        format!("[{}]", vec!["0"; 65_537].join(",")).into_bytes(),
    ] {
        let mut r = listed(Limits::default());
        let epoch = r.epoch();
        assert_eq!(r.watch_frame(epoch, 1, &raw, at(2)), Err(Error::Limit));
        assert!(!r.authoritative(at(2)));
    }
}

#[test]
fn native_typed_list_items_inherit_only_missing_types_and_watch_does_not() {
    for missing in [vec!["apiVersion"], vec!["kind"], vec!["apiVersion", "kind"]] {
        let mut object = pod("uid-a", "pod-a", "rv-a");
        for key in missing {
            object.as_object_mut().unwrap().remove(key);
        }
        let mut r = Reconciler::new(profile(Limits::default()));
        let epoch = r.begin_list(at(0)).unwrap();
        assert!(
            r.list_page(epoch, None, &page(vec![object.clone()], "list", ""), at(1))
                .unwrap()
        );
        assert_eq!(r.snapshot(at(1)).objects[0].uid(), "uid-a");
        assert!(matches!(
            r.watch_frame(epoch, 1, &watch("MODIFIED", object), at(2)),
            Err(Error::Scope)
        ));
        assert!(!r.authoritative(at(2)));
    }
    for (key, value) in [
        ("apiVersion", json!("apps/v1")),
        ("kind", json!("Node")),
        ("apiVersion", Value::Null),
        ("kind", Value::Null),
    ] {
        let mut object = pod("uid-a", "pod-a", "rv-a");
        object[key] = value;
        let mut r = Reconciler::new(profile(Limits::default()));
        let epoch = r.begin_list(at(0)).unwrap();
        assert!(matches!(
            r.list_page(epoch, None, &page(vec![object], "list", ""), at(1)),
            Err(Error::Scope)
        ));
        assert!(!r.authoritative(at(1)));
    }
    let mut raw: Value =
        serde_json::from_slice(&page(vec![pod("uid-a", "pod-a", "rv-a")], "list", "")).unwrap();
    raw["kind"] = json!("NodeList");
    let mut r = Reconciler::new(profile(Limits::default()));
    let epoch = r.begin_list(at(0)).unwrap();
    assert!(
        r.list_page(epoch, None, &serde_json::to_vec(&raw).unwrap(), at(1))
            .is_err()
    );
}

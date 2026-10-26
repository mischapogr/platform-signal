#![allow(clippy::expect_used)]
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_event::SignalEvent;
use signal_rules::{RuleContext, scoped_state::*};
use std::time::Duration;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn context() -> RuleContext {
    RuleContext::new(Duration::from_secs(10))
}
pub fn time(text: &str) -> DateTime<Utc> {
    text.parse().expect("constant fixture time")
}
pub fn interval() -> Interval {
    Interval {
        from: time("2026-10-07T00:00:00Z"),
        until: time("2026-10-07T01:00:00Z"),
    }
}
pub struct Fixture {
    pub event: SignalEvent,
    pub host: HostContext,
    pub state: Option<Snapshot>,
}
pub fn host(event: &SignalEvent, scope: Scope) -> HostContext {
    HostContext {
        source_binding: [1; 32],
        source_type: event.source.source_type.clone(),
        source_name: event.source.name.clone(),
        scope,
        source_config_revision: "config-1".into(),
        policy_revision: "policy-1".into(),
        policy_config_sha256: [2; 32],
        authority_keys_sha256: [3; 32],
        state_authority_revision: "authority-1".into(),
        verification_reference: "fixture://proof/1".into(),
        verified_at: time("2026-10-07T00:01:00Z"),
        verified_until: time("2026-10-07T00:30:00Z"),
        now: time("2026-10-07T00:02:00Z"),
        ready: true,
        impersonation: Impersonation::Reject,
    }
}
pub fn catalog(rule: Detection, case: usize) -> Result<(SignalEvent, Value)> {
    let catalog: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/security-requirements/catalog.json"
    ))?;
    let d = catalog["detections"]
        .as_array()
        .ok_or("detections")?
        .iter()
        .find(|d| d["id"] == rule.id())
        .ok_or("rule")?;
    Ok((
        serde_json::from_value(d["fixtures"][case]["events"][0].clone())?,
        d["fixtures"][case]["state"].clone(),
    ))
}
pub fn approval(q: &Query, target: &str) -> Approval {
    Approval {
        id: "approval-1".into(),
        actor: q.actor.clone(),
        target: target.into(),
        action: q.action.clone(),
        change: String::new(),
        validity: interval(),
    }
}
pub fn iam_permission() -> Permission {
    Permission::Iam {
        principal: "principal-uid".into(),
        action: "s3:GetObject".into(),
        resource: "arn:aws:s3:::fixture/object".into(),
    }
}
pub fn template() -> ResourceGrant {
    ResourceGrant {
        api_group: String::new(),
        resource: "pods".into(),
        namespaced: true,
        resource_name: None,
        verb: "get".into(),
    }
}
pub fn rbac_views(add: bool) -> (RbacView, RbacView) {
    let before = RbacView {
        revision: "rbac-1".into(),
        complete: true,
        unsupported: vec![],
        namespaces: vec!["fixture".into()],
        roles: vec![Role {
            uid: "role-uid".into(),
            revision: "role-1".into(),
            name: "fixture-role".into(),
            namespace: Some("fixture".into()),
            grants: vec![],
        }],
        bindings: vec![Binding {
            uid: "binding-uid".into(),
            revision: "binding-1".into(),
            name: "fixture-binding".into(),
            namespace: Some("fixture".into()),
            cluster_role: false,
            role_name: "fixture-role".into(),
            subjects: vec![Subject::User {
                name: "fixture-subject".into(),
            }],
        }],
    };
    let mut after = before.clone();
    after.revision = "rbac-2".into();
    after.roles[0].revision = "role-2".into();
    if add {
        after.roles[0].grants.push(template());
    }
    (before, after)
}
pub fn snapshot(
    input: &Input<'_>,
    rule: Detection,
    host: &HostContext,
    target: &str,
    data: Data,
) -> Result<Snapshot> {
    let q = query(input, rule, host).map_err(|g| format!("fixture query {g:?}"))?;
    Ok(Snapshot {
        schema_version: 1,
        rule,
        source_binding: host.source_binding,
        input_sha256: input.sha256(),
        scope: host.scope.clone(),
        authority_revision: host.state_authority_revision.clone(),
        policy_revision: host.policy_revision.clone(),
        policy_config_sha256: host.policy_config_sha256,
        authority_keys_sha256: host.authority_keys_sha256,
        source_config_revision: host.source_config_revision.clone(),
        revision: "state-1".into(),
        validity: interval(),
        observed_at: time("2026-10-07T00:01:00Z"),
        expires_at: time("2026-10-07T00:30:00Z"),
        complete: true,
        actor: q.actor,
        locator: q.locator,
        change: q.change,
        resolved_target: target.into(),
        data,
    })
}
pub fn fixture(rule: Detection, case: usize) -> Result<Fixture> {
    let (mut event, original_state) = catalog(rule, case)?;
    let missing = case == 2;
    let scope = match rule {
        Detection::D04 | Detection::D06 => {
            event.attributes.insert(
                "normalizer".into(),
                json!({"id":"cloudtrail-state-management","revision":"v1"}),
            );
            let mut iam = json!({"schema_version":1,"identity_complete":!missing,"actor_principal_id":"actor-uid","target_kind":"user"});
            if !missing {
                iam["target_name"] = "fixture-principal".into();
            }
            event.attributes.insert("aws".into(),json!({"cloudtrail":{"recipient_account_id":"111122223333","event_id":"change-1","iam":iam}}));
            event.attributes["security"]["action"] = if rule == Detection::D04 {
                "credential.create"
            } else {
                "iam.permissions.change"
            }
            .into();
            Scope::Aws {
                account: "111122223333".into(),
            }
        }
        Detection::D08 | Detection::D09 => {
            event.attributes["security"]["action"] = if rule == Detection::D08 {
                "k8s.rbac.change"
            } else {
                "k8s.exec"
            }
            .into();
            let mut k = json!({"cluster":"cluster-fixture","state_profile_revision":"v1","audit_id":"audit-1","stage":"ResponseComplete","verb":if rule==Detection::D08{"patch"}else{"create"},"user":{"username":"fixture-actor","uid":"actor-uid"},
                "object":{"resource":if rule==Detection::D08{"roles"}else{"pods"},"namespace":"fixture","name":if rule==Detection::D08{"fixture-role"}else{"fixture-pod"},"uid":if rule==Detection::D08{"role-uid"}else{"pod-uid"}}});
            if rule == Detection::D09 {
                k["exec_session_accepted"] = true.into();
                if missing {
                    k["user"] = json!({});
                }
            }
            event.attributes.insert("kubernetes".into(), k);
            Scope::Kubernetes {
                cluster: "cluster-fixture".into(),
            }
        }
        Detection::D13 => {
            let start = (event.timestamp.timestamp() as u64 - 1) * 1_000_000_000;
            event.attributes.insert(
                "runtime".into(),
                json!({"kind":"execution","syscall":"execve","outcome":"success"}),
            );
            let mut p = json!({"host_id":"host-fixture","boot_id":"00000000-0000-0000-0000-000000000001","pid":42,"executable":"/fixture/program"});
            if !missing {
                p["start_epoch_ns"] = start.into();
            }
            event.attributes.insert("process".into(), p);
            event
                .attributes
                .insert("producer".into(), json!({"sequence":1}));
            event.attributes.insert(
                "evidence".into(),
                json!({"profile":"falco-syscall-metadata-v1"}),
            );
            Scope::Host {
                host: "host-fixture".into(),
                boot: "00000000-0000-0000-0000-000000000001".into(),
            }
        }
        Detection::D12 => return Err("use supported fixture rule".into()),
    };
    let host = host(&event, scope);
    let input = Input::new(&event, &context())?;
    if missing && rule != Detection::D08 {
        return Ok(Fixture {
            event,
            host,
            state: None,
        });
    }
    let q = query(&input, rule, &host).map_err(|g| format!("fixture query {g:?}"))?;
    let (target, data) = match rule {
        Detection::D04 => {
            let target = "principal-uid";
            let rows = if original_state["approval"] == "valid" {
                vec![approval(&q, target)]
            } else {
                vec![]
            };
            (target.into(), Data::Credentials { approvals: rows })
        }
        Detection::D06 => {
            let before = IamView {
                revision: "iam-1".into(),
                principal_id: "principal-uid".into(),
                complete: true,
                unsupported: vec![],
                grants: vec![],
            };
            let mut after = before.clone();
            after.revision = "iam-2".into();
            if case == 0 {
                after.grants.push(iam_permission());
            }
            (
                "principal-uid".into(),
                Data::Iam {
                    before,
                    after,
                    approved: vec![],
                },
            )
        }
        Detection::D08 => {
            let (before, after) = rbac_views(case == 0);
            (
                "role-uid".into(),
                Data::Rbac {
                    before,
                    after,
                    approved: vec![],
                },
            )
        }
        Detection::D09 => {
            let target = "pod-uid";
            let a = if original_state["operator_authorized"] == true {
                vec![approval(&q, target)]
            } else {
                vec![]
            };
            (
                target.into(),
                Data::Workload {
                    history: vec![WorkloadVersion {
                        uid: target.into(),
                        namespace: "fixture".into(),
                        name: "fixture-pod".into(),
                        revision: "pod-1".into(),
                        validity: interval(),
                        sensitive: true,
                    }],
                    approvals: a,
                },
            )
        }
        Detection::D13 => {
            let key = q.process.as_ref().ok_or("process")?;
            (
                "07".repeat(32),
                Data::Process {
                    history: vec![ProcessVersion {
                        host: key.host.clone(),
                        boot: key.boot.clone(),
                        pid: key.pid,
                        start_epoch_ns: key.start_epoch_ns,
                        execution_sequence: key.execution_sequence,
                        executable_sha256: [7; 32],
                        revision: "process-1".into(),
                        validity: interval(),
                        privileged: true,
                        provenance_verified: true,
                        approved: original_state["approved"] == true,
                    }],
                },
            )
        }
        Detection::D12 => return Err("deferred".into()),
    };
    let mut state = snapshot(&input, rule, &host, &target, data)?;
    if missing {
        state.complete = false;
    }
    Ok(Fixture {
        event,
        host,
        state: Some(state),
    })
}

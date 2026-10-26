#[path = "../../../crates/signal-rules/tests/support/scoped_state.rs"]
mod support;
use serde_json::{Value, json};
use signal_collector_sdk::{cloudtrail, falco, kubernetes_audit};
use signal_rules::{baseline::Status, scoped_state::*};
use support::*;
use uuid::Uuid;

fn cloud_raw(event: &signal_event::SignalEvent, operation: &str) -> Value {
    json!({"eventVersion":"1.11","eventID":"00000000-0000-0000-0000-000000000001","eventTime":event.timestamp,
        "eventSource":"iam.amazonaws.com","eventName":operation,"awsRegion":"us-east-1","eventType":"AwsApiCall","recipientAccountId":"111122223333","managementEvent":true,"eventCategory":"Management",
        "userIdentity":{"type":"IAMUser","accountId":"111122223333","principalId":"actor-uid","arn":"arn:aws:iam::111122223333:user/fixture-actor"},
        "requestParameters":{"userName":"fixture-principal","policyArn":"arn:aws:iam::111122223333:policy/fixture","policyDocument":"DO_NOT_COPY_POLICY"},
        "responseElements":{"user":{"userName":"fixture-principal","userId":"principal-uid","arn":"arn:aws:iam::111122223333:user/fixture-principal"},"accessKey":{"userName":"fixture-principal","secretAccessKey":"DO_NOT_COPY_SECRET"}}})
}
fn kube_raw(event: &signal_event::SignalEvent, exec: bool) -> Value {
    json!({"apiVersion":"audit.k8s.io/v1","kind":"Event","level":"Metadata","auditID":"native-audit-1","stage":if exec{"ResponseStarted"}else{"ResponseComplete"},"verb":if exec{"create"}else{"patch"},
        "requestURI":if exec{"/api/v1/namespaces/fixture/pods/fixture-pod/exec?command=DO_NOT_COPY_COMMAND"}else{"/apis/rbac.authorization.k8s.io/v1/namespaces/fixture/roles/fixture-role"},
        "requestReceivedTimestamp":event.timestamp-chrono::TimeDelta::seconds(1),"stageTimestamp":event.timestamp,
        "user":{"username":"fixture-actor","uid":"actor-uid"},"objectRef":{"apiGroup":if exec{""}else{"rbac.authorization.k8s.io"},"apiVersion":"v1","resource":if exec{"pods"}else{"roles"},"subresource":if exec{"exec"}else{""},
            "namespace":"fixture","name":if exec{"fixture-pod"}else{"fixture-role"},"uid":if exec{"pod-uid"}else{"role-uid"}},"responseStatus":{"code":if exec{101}else{200}}})
}
fn native_fixture(rule: Detection, case: usize) -> Result<Fixture> {
    let f = fixture(rule, case)?;
    let event = match rule {
        Detection::D04 | Detection::D06 => {
            let raw = serde_json::to_vec(&cloud_raw(
                &f.event,
                if rule == Detection::D04 {
                    "CreateUser"
                } else {
                    "AttachUserPolicy"
                },
            ))?;
            let profile = cloudtrail::CloudTrailProfile::new(
                "requirement-fixture",
                &["111122223333"],
                &["us-east-1"],
            )?;
            let pin = cloudtrail::PreparationIdentity::new(
                f.event.id,
                Uuid::from_u128(1),
                f.event.observed_at,
                0,
            )?;
            let old = cloudtrail::normalize_record(&raw, &profile, pin)?;
            assert!(
                old.event().ok_or("legacy")?.attributes["aws"]["cloudtrail"]
                    .get("iam")
                    .is_none()
            );
            let state = cloudtrail::normalize_state_record(&raw, &profile, pin)?;
            assert_eq!(
                old.prepared_bytes(),
                cloudtrail::normalize_record(&raw, &profile, pin)?.prepared_bytes()
            );
            let canonical = state.prepared_bytes().ok_or("prepared")?;
            assert!(!String::from_utf8_lossy(canonical).contains("DO_NOT_COPY"));
            state.event().ok_or("state event")?.clone()
        }
        Detection::D08 | Detection::D09 => {
            let raw = serde_json::to_vec(&kube_raw(&f.event, rule == Detection::D09))?;
            let profile = kubernetes_audit::Profile::new("cluster-fixture", "logging-policy-1")?;
            let old = kubernetes_audit::normalize_record(
                &raw,
                &profile,
                f.event.id,
                f.event.observed_at,
            )?;
            let state = kubernetes_audit::normalize_state_record(
                &raw,
                &profile,
                f.event.id,
                f.event.observed_at,
            )?;
            if rule == Detection::D09 {
                assert_eq!(old.event().attributes["security"]["outcome"], "unknown");
                assert_eq!(state.event().attributes["security"]["outcome"], "success");
            }
            assert!(!serde_json::to_string(state.event())?.contains("DO_NOT_COPY"));
            state.event().clone()
        }
        Detection::D13 => {
            let at = f.event.timestamp.timestamp_nanos_opt().ok_or("time")? as u64;
            let raw = serde_json::to_vec(
                &json!({"source":"syscall","time":f.event.timestamp,"output_fields":{"evt.num":1,"evt.rawtime":at,"evt.type":"execve","evt.rawres":0,"proc.pid":42,"proc.pid.ts":at-1_000_000_000,"proc.ppid":1,"proc.ppid.ts":at-2_000_000_000,"proc.exepath":"/fixture/program"}}),
            )?;
            let profile = falco::Profile::new("host-fixture", Uuid::from_u128(1))?;
            falco::normalize_syscall(
                &raw,
                &profile,
                f.event.source.clone(),
                f.event.id,
                f.event.observed_at,
            )?
        }
        Detection::D12 => return Err("deferred".into()),
    };
    let host = host(&event, f.host.scope.clone());
    let input = Input::new(&event, &context())?;
    let prior = f.state.ok_or("fixture state")?;
    let state = snapshot(&input, rule, &host, &prior.resolved_target, prior.data)?;
    Ok(Fixture {
        event,
        host,
        state: Some(state),
    })
}
#[test]
fn all_five_native_profile_compositions_match_and_authorized_controls_do_not() -> Result {
    for rule in [
        Detection::D04,
        Detection::D06,
        Detection::D08,
        Detection::D09,
        Detection::D13,
    ] {
        for case in 0..2 {
            let f = native_fixture(rule, case)?;
            let i = Input::new(&f.event, &context())?;
            assert_eq!(
                assess(&i, rule, f.state.as_ref(), &f.host, &context())?.status,
                if case == 0 {
                    Status::Match
                } else {
                    Status::NoMatch
                },
                "{rule:?}/{case}"
            );
        }
    }
    Ok(())
}
#[test]
fn iam_opt_in_projection_refuses_conflicts_and_never_copies_secrets_or_policy_bodies() -> Result {
    let f = fixture(Detection::D04, 0)?;
    let profile = cloudtrail::CloudTrailProfile::new(
        "requirement-fixture",
        &["111122223333"],
        &["us-east-1"],
    )?;
    let pin = cloudtrail::PreparationIdentity::new(
        f.event.id,
        Uuid::from_u128(1),
        f.event.observed_at,
        0,
    )?;
    for operation in [
        "CreateUser",
        "CreateAccessKey",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
    ] {
        let mut raw = cloud_raw(&f.event, operation);
        if operation.contains("Role") {
            raw["requestParameters"]["roleName"] = "fixture-role".into();
        }
        let bytes = serde_json::to_vec(&raw)?;
        let out = cloudtrail::normalize_state_record(&bytes, &profile, pin)?;
        let e = out.event().ok_or("event")?;
        assert_eq!(
            e.attributes["aws"]["cloudtrail"]["iam"]["identity_complete"], true,
            "{operation}"
        );
        assert!(!serde_json::to_string(e)?.contains("DO_NOT_COPY"));
    }
    let mut raw = cloud_raw(&f.event, "CreateUser");
    raw["responseElements"]["user"]["userName"] = "other-user".into();
    let bytes = serde_json::to_vec(&raw)?;
    let out = cloudtrail::normalize_state_record(&bytes, &profile, pin)?;
    let input = Input::new(out.event().ok_or("event")?, &context())?;
    assert_eq!(
        assess(&input, Detection::D04, None, &f.host, &context())?.gap,
        Some(Gap::MissingSourceField)
    );
    Ok(())
}
#[test]
fn exec_acceptance_is_endpoint_stage_status_and_dryrun_specific() -> Result {
    let f = fixture(Detection::D09, 0)?;
    let profile = kubernetes_audit::Profile::new("cluster-fixture", "logging-policy-1")?;
    for (stage, code, uri, accepted) in [
        (
            "ResponseStarted",
            101,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec",
            true,
        ),
        (
            "ResponseStarted",
            200,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec",
            true,
        ),
        (
            "ResponseComplete",
            200,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec",
            true,
        ),
        (
            "ResponseStarted",
            201,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec",
            false,
        ),
        (
            "RequestReceived",
            200,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec",
            false,
        ),
        (
            "ResponseComplete",
            403,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec",
            false,
        ),
        (
            "ResponseStarted",
            101,
            "/api/v1/namespaces/fixture/pods/fixture-pod/log",
            false,
        ),
        (
            "ResponseStarted",
            101,
            "/api/v1/namespaces/other/../fixture/pods/fixture-pod/exec",
            false,
        ),
        (
            "ResponseStarted",
            101,
            "/api/v1/namespaces/fixture/pods/fixture-pod/exec?dryRun=All",
            false,
        ),
    ] {
        let mut raw = kube_raw(&f.event, true);
        raw["stage"] = stage.into();
        raw["responseStatus"]["code"] = code.into();
        raw["requestURI"] = uri.into();
        let bytes = serde_json::to_vec(&raw)?;
        let out = kubernetes_audit::normalize_state_record(
            &bytes,
            &profile,
            f.event.id,
            f.event.observed_at,
        )?;
        assert_eq!(
            out.event().attributes["kubernetes"]["exec_session_accepted"] == true,
            accepted,
            "{stage}/{code}/{uri}"
        );
    }
    Ok(())
}

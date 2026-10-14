#![allow(clippy::unwrap_used, clippy::expect_used)]
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_collector_sdk::falco::*;
use signal_event::Source;
use uuid::Uuid;
fn time() -> DateTime<Utc> {
    "2026-10-14T12:00:00Z".parse().unwrap()
}
fn syscall() -> Value {
    let n = time().timestamp_nanos_opt().unwrap() as u64;
    json!({"source":"syscall","time":time(),"rule":"fixture execution","priority":"Notice","output_fields":{"evt.num":20,"evt.rawtime":n,"evt.type":"execve","evt.rawres":0,"proc.pid":100,"proc.pid.ts":n-10000,"proc.ppid":99,"proc.ppid.ts":n-20000,"proc.exepath":"/usr/bin/fixture"}})
}
fn normalize(v: &Value, boot: u128) -> Result<signal_event::SignalEvent, Error> {
    normalize_syscall(
        &serde_json::to_vec(v).unwrap(),
        &Profile::new("configured-host", Uuid::from_u128(boot)).unwrap(),
        Source {
            source_type: "runtime".into(),
            name: Some("configured-source".into()),
        },
        Uuid::from_u128(1),
        time() + chrono::Duration::seconds(1),
    )
}
#[test]
fn execution_file_access_and_egress_keep_process_start_scope_and_outcomes() {
    for kind in ["execve", "openat", "connect"] {
        let mut v = syscall();
        v["output_fields"]["evt.type"] = json!(kind);
        match kind {
            "openat" => {
                v["output_fields"]["fd.name"] = json!("/synthetic/protected-fixture");
                v["output_fields"]["evt.is_open_read"] = json!(true);
            }
            "connect" => {
                v["output_fields"]["fd.sip"] = json!("198.51.100.10");
                v["output_fields"]["fd.sport"] = json!(443);
            }
            _ => {}
        }
        for result in [0, -13] {
            v["output_fields"]["evt.rawres"] = json!(result);
            let event = normalize(&v, 10).unwrap();
            assert_eq!(event.attributes["process"]["host_id"], "configured-host");
            assert_eq!(
                event.attributes["runtime"]["outcome"],
                if result >= 0 { "success" } else { "failure" }
            );
            assert_eq!(
                event.attributes["evidence"]["runtime_sensor_coverage"],
                "not_assessed"
            );
            assert_eq!(
                event.attributes["producer"]["dropped_events"],
                "requires_metrics_stream"
            );
            if kind == "openat" {
                assert_eq!(
                    event.attributes["runtime"]["detail"]["actual_read"],
                    "not_assessed"
                );
            }
        }
    }
    let first = normalize(&syscall(), 10).unwrap();
    let mut reused = syscall();
    reused["output_fields"]["proc.pid.ts"] =
        json!(time().timestamp_nanos_opt().unwrap() as u64 - 1);
    assert_ne!(
        first.attributes["process"],
        normalize(&reused, 10).unwrap().attributes["process"]
    );
    assert_ne!(
        first.attributes["process"],
        normalize(&syscall(), 11).unwrap().attributes["process"]
    );
}
#[test]
fn malformed_identity_credentials_output_unknown_hook_and_missing_fields_refuse() {
    for field in [
        "proc.pid",
        "proc.pid.ts",
        "proc.ppid.ts",
        "evt.num",
        "evt.rawtime",
    ] {
        let mut v = syscall();
        v["output_fields"].as_object_mut().unwrap().remove(field);
        assert!(normalize(&v, 10).is_err());
    }
    for (key, value) in [
        ("proc.cmdline", json!("credential-argument")),
        ("evt.type", json!("read")),
        ("proc.pid.ts", json!(0)),
        ("evt.dir", json!("<")),
        ("proc.pid", json!(-1)),
        ("evt.rawtime", json!(1)),
    ] {
        let mut v = syscall();
        v["output_fields"][key] = value;
        assert!(normalize(&v, 10).is_err());
    }
    let mut v = syscall();
    v["output"] = json!("freeform secret");
    assert!(normalize(&v, 10).is_err());
    let mut v = syscall();
    v["source"] = json!("plugin");
    assert!(normalize(&v, 10).is_err());
    let mut v = syscall();
    v["output_fields"]["proc.exepath"] = json!("x".repeat(MAX_RECORD_BYTES));
    assert!(normalize(&v, 10).is_err());
    let mut bytes = serde_json::to_string(&syscall()).unwrap();
    bytes = bytes.replacen("\"proc.pid\":100", "\"proc.pid\":1,\"proc.pid\":100", 1);
    assert!(
        normalize_syscall(
            bytes.as_bytes(),
            &Profile::new("host", Uuid::from_u128(1)).unwrap(),
            Source {
                source_type: "runtime".into(),
                name: None
            },
            Uuid::from_u128(1),
            time()
        )
        .is_err()
    );
}
fn metrics() -> Value {
    let n = time().timestamp_nanos_opt().unwrap() as u64;
    json!({"source":"internal","time":time(),"rule":"Falco internal: metrics snapshot","output_fields":{"evt.source":"syscall","evt.time":n,"falco.start_ts":n-1000,"falco.reload_ts":n-1000,"falco.host_boot_ts":n-2000,"scap.n_evts":100,"scap.n_drops":2,"falco.outputs_queue_num_drops":3,"scap.engine_name":"modern_bpf","falco.version":"0.44.1","falco.n_failed_fd_lookups":0,"falco.n_failed_thread_lookups":1,"falco.n_drops_full_threadtable":0,"falco.n_store_evts_drops":0,"falco.n_retrieve_evts_drops":0}})
}
#[test]
fn internal_metrics_keep_actual_drop_and_identity_counters_without_defaults() {
    let v = metrics();
    let m = parse_metrics(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(m.kernel_drops, 2);
    assert_eq!(m.output_queue_drops, 3);
    assert_eq!(m.failed_thread_lookups, 1);
    for key in [
        "scap.n_drops",
        "scap.n_evts",
        "falco.outputs_queue_num_drops",
        "falco.n_failed_fd_lookups",
        "falco.n_failed_thread_lookups",
        "falco.n_store_evts_drops",
        "falco.n_retrieve_evts_drops",
    ] {
        let mut bad = v.clone();
        bad["output_fields"].as_object_mut().unwrap().remove(key);
        assert!(parse_metrics(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = v.clone();
    bad["output_fields"]["scap.engine_name"] = json!("unverified");
    assert!(parse_metrics(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = v.clone();
    bad["output_fields"]["falco.reload_ts"] = json!(1);
    assert!(parse_metrics(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut extended = v;
    for i in 0..100 {
        extended["output_fields"][format!("native.counter.{i}")] = json!(i);
    }
    assert_eq!(
        parse_metrics(&serde_json::to_vec(&extended).unwrap()).unwrap(),
        m
    );
}

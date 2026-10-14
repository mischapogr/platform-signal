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

/// This gate deliberately fails without a real owned native capture manifest.
#[test]
#[ignore = "requires isolated native Falco capture fixture"]
fn native_capture_projects_all_owned_hooks_and_explicit_health_counters() {
    use sha2::{Digest, Sha256};
    let directory = std::path::PathBuf::from(
        std::env::var("SIGNAL_OWNED_FALCO_CAPTURE").expect("owned capture directory"),
    );
    let directory = directory.canonicalize().unwrap();
    assert!(directory.starts_with(std::env::current_dir().unwrap().join("target")));
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory.join("NATIVE-CAPTURE.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["status"], "passed_native_capture");
    assert!(manifest.get("simulation").is_none());
    assert_eq!(manifest["cleanup"], true);
    assert_eq!(
        manifest["source_sha"],
        std::env::var("GITHUB_SHA").expect("CI source binding")
    );
    assert_eq!(manifest["observer"]["capture_interval_verified"], true);
    let boot: Uuid = manifest["boot_id"].as_str().unwrap().parse().unwrap();
    let profile = Profile::new("owned-runtime-host", boot).unwrap();
    let path = directory.join("native.jsonl");
    assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
    assert!(std::fs::metadata(&path).unwrap().len() <= 2 * 1024 * 1024);
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(
        Sha256::digest(&raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        manifest["raw_sha256"].as_str().unwrap()
    );
    let mut kinds = std::collections::BTreeSet::new();
    let mut identity = None;
    let mut metrics = Vec::new();
    let mut events = Vec::new();
    for (index, line) in raw
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        assert!(index < 512 && line.len() <= MAX_RECORD_BYTES);
        let value: Value = serde_json::from_slice(line).unwrap();
        let source = Source {
            source_type: "runtime".into(),
            name: Some("owned-runtime-host".into()),
        };
        let observed: DateTime<Utc> = value["time"].as_str().unwrap().parse().unwrap();
        let id = Uuid::from_u128(index as u128 + 1);
        let event = if value["source"] == "syscall" {
            let event = normalize_syscall(line, &profile, source, id, observed).unwrap();
            let process = &event.attributes["process"];
            assert_eq!(process["pid"], manifest["observer"]["owned_pid"]);
            assert_eq!(process["parent_pid"], manifest["observer"]["owned_parent"]);
            let current = (
                process["pid"].clone(),
                process["start_epoch_ns"].clone(),
                process["boot_id"].clone(),
            );
            if let Some(previous) = &identity {
                assert_eq!(&current, previous);
            } else {
                identity = Some(current);
            }
            kinds.insert(
                event.attributes["runtime"]["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
            event
        } else {
            assert_eq!(value["source"], "internal");
            metrics.push(parse_metrics(line).unwrap());
            normalize_metrics(line, &profile, source, id, observed).unwrap()
        };
        assert_eq!(
            event.attributes["evidence"]["runtime_sensor_coverage"],
            "not_assessed"
        );
        events.push(event);
    }
    for kind in ["execution", "file_open", "connection"] {
        assert!(kinds.contains(kind));
    }
    assert!(metrics.len() >= 2);
    for pair in metrics.windows(2) {
        assert!(pair[1].timestamp >= pair[0].timestamp);
        assert_eq!(pair[1].sensor_start_epoch_ns, pair[0].sensor_start_epoch_ns);
        assert_eq!(pair[1].host_boot_epoch_ns, pair[0].host_boot_epoch_ns);
        assert!(pair[1].captured_events >= pair[0].captured_events);
        assert!(pair[1].kernel_drops >= pair[0].kernel_drops);
    }
    std::fs::write(directory.join("NATIVE-PROJECTION.json"),serde_json::to_vec_pretty(&json!({"status":"passed_native_projection","source_sha":manifest["source_sha"],"events":events.len(),"metrics":metrics.len(),"kinds":kinds,"kernel_capture_manifest":"NATIVE-CAPTURE.json","production_coverage":"not_assessed"})).unwrap()).unwrap();
}

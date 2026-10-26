#![allow(clippy::unwrap_used, clippy::expect_used)]
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_collector_sdk::runtime_metadata::*;
use signal_event::Source;
use uuid::Uuid;
fn base(kind: &str) -> Value {
    json!({"schema_version":1,"profile":PROFILE,"capture_id":Uuid::from_u128(2),"config_sha256":"ab".repeat(32),
        "host":"synthetic-host","boot_id":Uuid::from_u128(1),"sequence":2,"timestamp_ns":1792987443600357722u64,
        "pid":123,"tid":123,"start_ticks":100,"clock_ticks":100,"mount_ns":1,"audit_arch":AUDIT_X86_64,
        "execution_generation":1,"kind":kind})
}
fn read() -> Value {
    let mut r = base("read");
    for (k, v) in json!({"fd":3,"object_type":REGULAR_FILE,"dev_major":8,"dev_minor":1,"inode":10,"mount_id":30,
        "ctime_sec":1792987443,"ctime_nsec":561209218,"result":47,"error":false,"requested":64,
        "syscall_entry_ns":1792987443599264629u64,"syscall_exit_ns":1792987443600354620u64}).as_object().unwrap()
    { r[k] = v.clone(); }
    r
}
fn connect() -> Value {
    let mut r = read();
    r["kind"] = json!("connect");
    r.as_object_mut().unwrap().remove("requested");
    r["object_type"] = json!(SOCKET);
    r["result"] = json!(0);
    r["family"] = json!(4);
    r["address"] = json!("198.51.100.10");
    r["port"] = json!(443);
    r["scope_id"] = json!(0);
    r
}
fn profile() -> Profile {
    Profile::new(
        "synthetic-host",
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        [0xab; 32],
        AUDIT_X86_64,
    )
    .unwrap()
}
fn parse_value(v: &Value) -> Result<Metadata, Error> {
    parse(&serde_json::to_vec(v).unwrap(), &profile())
}
fn source() -> Source {
    Source {
        source_type: "runtime".into(),
        name: Some("owned-metadata".into()),
    }
}
fn time() -> DateTime<Utc> {
    "2026-10-26T06:00:00Z".parse().unwrap()
}

#[test]
fn successful_regular_read_is_distinct_from_eof_errors_sockets_and_connections() {
    assert!(
        parse_value(&read())
            .unwrap()
            .operation
            .positive_regular_read()
    );
    for (result, error, object_type) in [
        (0, false, REGULAR_FILE),
        (-14, true, REGULAR_FILE),
        (47, false, SOCKET),
    ] {
        let mut r = read();
        r["result"] = json!(result);
        r["error"] = json!(error);
        r["object_type"] = json!(object_type);
        let m = parse_value(&r).unwrap();
        assert!(!m.operation.positive_regular_read());
        assert!(!m.operation.successful_connect());
    }
    let mut r = read();
    r["result"] = json!(-9);
    r["error"] = json!(true);
    r["fd"] = json!(-1);
    for key in [
        "object_type",
        "dev_major",
        "dev_minor",
        "inode",
        "mount_id",
        "ctime_sec",
        "ctime_nsec",
    ] {
        r[key] = json!(0);
    }
    assert!(!parse_value(&r).unwrap().operation.positive_regular_read());
    let m = parse_value(&connect()).unwrap();
    assert!(m.operation.successful_connect());
    assert!(!m.operation.positive_regular_read());
    let mut r = connect();
    r["result"] = json!(-111);
    r["error"] = json!(true);
    assert!(!parse_value(&r).unwrap().operation.successful_connect());
}

#[test]
fn strict_shapes_and_payload_or_policy_fields_refuse_including_null_and_duplicate() {
    for key in [
        "buffer",
        "read_buffer_address",
        "argv",
        "environment",
        "protected_read",
        "suspicious",
        "contents_captured",
    ] {
        let mut r = read();
        r[key] = json!("synthetic-payload");
        assert_eq!(parse_value(&r), Err(Error::Record));
        r[key] = Value::Null;
        assert_eq!(parse_value(&r), Err(Error::Record));
    }
    for key in read().as_object().unwrap().keys() {
        let mut r = read();
        r.as_object_mut().unwrap().remove(key);
        assert!(parse_value(&r).is_err(), "{key}");
    }
    let raw = serde_json::to_string(&read()).unwrap();
    let duplicated = raw.replacen("\"fd\":3", "\"fd\":4,\"fd\":3", 1);
    assert_eq!(parse(duplicated.as_bytes(), &profile()), Err(Error::Record));
    assert_eq!(
        parse(format!("{raw}{{}}").as_bytes(), &profile()),
        Err(Error::Record)
    );
    assert_eq!(
        parse(&vec![b' '; MAX_RECORD_BYTES + 1], &profile()),
        Err(Error::Limit)
    );
    let mut r = read();
    r["fd"] = json!({"nested":"not scalar"});
    assert_eq!(parse_value(&r), Err(Error::Record));
    let mut r = base("exec");
    r["requested"] = json!(0);
    assert_eq!(parse_value(&r), Err(Error::Record));
}

#[test]
fn native_binding_abi_process_and_operation_inconsistencies_refuse() {
    for (key, value) in [
        ("host", json!("other")),
        ("capture_id", json!(Uuid::from_u128(3))),
        ("boot_id", json!(Uuid::from_u128(3))),
        ("config_sha256", json!("cd".repeat(32))),
        ("audit_arch", json!(0x40000003u32)),
        ("pid", json!(0)),
        ("tid", json!(124)),
        ("start_ticks", json!(0)),
        ("execution_generation", json!(0)),
        ("sequence", json!(0)),
        ("timestamp_ns", json!(u64::MAX)),
        ("result", json!(65)),
        ("result", json!(-512)),
        ("result", json!(-4096)),
        ("error", json!(true)),
        ("requested", json!(-1)),
        ("ctime_nsec", json!(1_000_000_000)),
        ("inode", json!(0)),
        ("mount_id", json!(0)),
        ("object_type", json!(99)),
        ("syscall_entry_ns", json!(1792987443600354621u64)),
        ("syscall_exit_ns", json!(1792987443600357723u64)),
    ] {
        let mut r = read();
        r[key] = value;
        assert!(parse_value(&r).is_err(), "{key}: {r}");
    }
    for (key, value) in [
        ("port", json!(65536)),
        ("family", json!(6)),
        ("address", json!("invalid")),
        ("scope_id", json!(1)),
        ("result", json!(1)),
        ("object_type", json!(REGULAR_FILE)),
    ] {
        let mut r = connect();
        r[key] = value;
        assert!(parse_value(&r).is_err(), "{key}");
    }
    assert!(
        Profile::new(
            "bad host",
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            [1; 32],
            AUDIT_X86_64
        )
        .is_err()
    );
    assert!(
        Profile::new(
            "host",
            Uuid::nil(),
            Uuid::from_u128(2),
            [1; 32],
            AUDIT_X86_64
        )
        .is_err()
    );
    for arch in [AUDIT_X86_64, AUDIT_ARM64] {
        let p = Profile::new(
            "synthetic-host",
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            [0xab; 32],
            arch,
        )
        .unwrap();
        let mut r = read();
        r["audit_arch"] = json!(arch);
        assert!(parse(&serde_json::to_vec(&r).unwrap(), &p).is_ok());
    }
}

#[test]
fn normalized_metadata_keeps_exact_original_process_native_and_intervals_without_authority() {
    let raw = serde_json::to_vec(&read()).unwrap();
    let first = normalize(&raw, &profile(), source(), Uuid::from_u128(10), time()).unwrap();
    let second = normalize(
        &raw,
        &profile(),
        source(),
        Uuid::from_u128(11),
        time() + chrono::TimeDelta::seconds(1),
    )
    .unwrap();
    assert_eq!(first.attributes, second.attributes);
    assert_ne!(first.id, second.id);
    assert_eq!(
        first.attributes["evidence"]["runtime_sensor_coverage"],
        "not_assessed"
    );
    let m: Metadata = serde_json::from_value(first.attributes["runtime_metadata"].clone()).unwrap();
    assert_eq!(m, parse_value(&read()).unwrap());
    assert_eq!(m.native.capture, Uuid::from_u128(2));
    assert_eq!(m.process.start_ticks, 100);
    assert_eq!(
        m.operation.interval().unwrap().entry_ns,
        1792987443599264629
    );
    assert!(normalize(&raw, &profile(), source(), Uuid::nil(), time()).is_err());
}

#[test]
fn continuity_requires_prefix_exec_generation_clock_and_terminal_and_is_transactional() {
    let p = profile();
    let mut continuity = Continuity::new();
    let mut exec = base("exec");
    exec["sequence"] = json!(1);
    exec["timestamp_ns"] = json!(1792987443500000000u64);
    continuity
        .admit(&serde_json::to_vec(&exec).unwrap(), &p)
        .unwrap();
    let other = Profile::new(
        "synthetic-host",
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        [0xcd; 32],
        AUDIT_X86_64,
    )
    .unwrap();
    let mut swapped = read();
    swapped["config_sha256"] = json!("cd".repeat(32));
    assert_eq!(
        continuity.admit(&serde_json::to_vec(&swapped).unwrap(), &other),
        Err(Error::Continuity)
    );
    for (key, value) in [
        ("sequence", json!(3)),
        ("execution_generation", json!(2)),
        ("pid", json!(124)),
        ("mount_ns", json!(2)),
        ("timestamp_ns", json!(1792987443499999999u64)),
    ] {
        let mut r = read();
        r[key] = value;
        if key == "pid" {
            r["tid"] = r["pid"].clone();
        }
        assert!(
            continuity
                .admit(&serde_json::to_vec(&r).unwrap(), &p)
                .is_err(),
            "{key}"
        );
    }
    continuity
        .admit(&serde_json::to_vec(&read()).unwrap(), &p)
        .unwrap();
    let mut next_exec = base("exec");
    next_exec["sequence"] = json!(3);
    next_exec["execution_generation"] = json!(2);
    next_exec["timestamp_ns"] = json!(1792987443700000000u64);
    continuity
        .admit(&serde_json::to_vec(&next_exec).unwrap(), &p)
        .unwrap();
    let mut end = base("end");
    end["sequence"] = json!(4);
    end["execution_generation"] = json!(2);
    end["timestamp_ns"] = json!(1792987443800000000u64);
    end["reason"] = json!("exited");
    end["stops"] = json!(100);
    continuity
        .admit(&serde_json::to_vec(&end).unwrap(), &p)
        .unwrap();
    assert_eq!(
        continuity.admit(&serde_json::to_vec(&end).unwrap(), &p),
        Err(Error::Continuity)
    );
}

#[test]
fn normalization_refuses_unbounded_source_and_unserializable_observation_before_copy() {
    let raw = serde_json::to_vec(&read()).unwrap();
    for s in [
        " ".to_owned(),
        "x".repeat(1024 * 1024),
        " leading".into(),
        "control\n".into(),
    ] {
        assert_eq!(
            normalize(
                &raw,
                &profile(),
                Source {
                    source_type: s.clone(),
                    name: None
                },
                Uuid::from_u128(1),
                time()
            ),
            Err(Error::Record)
        );
        assert_eq!(
            normalize(
                &raw,
                &profile(),
                Source {
                    source_type: "runtime".into(),
                    name: Some(s)
                },
                Uuid::from_u128(1),
                time()
            ),
            Err(Error::Record)
        );
    }
    let invalid = DateTime::from_timestamp(253402300800, 0).unwrap();
    assert_eq!(
        normalize(&raw, &profile(), source(), Uuid::from_u128(1), invalid),
        Err(Error::Record)
    );
    let leap = DateTime::from_timestamp(1792987439, 1_000_000_000).unwrap();
    assert_eq!(
        normalize(&raw, &profile(), source(), Uuid::from_u128(1), leap),
        Err(Error::Record)
    );
}

#[test]
fn stop_limit_terminal_gap_preserves_collectors_overflow_count() {
    let mut gap = base("gap");
    gap["reason"] = json!("stop_limit");
    gap["stops"] = json!(100001);
    assert!(parse_value(&gap).is_ok());
    gap["stops"] = json!(100002);
    assert_eq!(parse_value(&gap), Err(Error::Record));
    gap["stops"] = json!(100001);
    gap["kind"] = json!("end");
    gap["reason"] = json!("exited");
    assert_eq!(parse_value(&gap), Err(Error::Record));
    gap["kind"] = json!("gap");
    gap["reason"] = json!("cancelled");
    assert_eq!(parse_value(&gap), Err(Error::Record));
}

#[test]
#[ignore = "requires reviewed native report and original owned capture artifacts"]
fn retained_native_capture_composes_through_strict_normalizer_and_continuity() {
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;
    let directory =
        PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR").expect("native report directory"));
    let report: Value =
        serde_json::from_slice(&std::fs::read(directory.join("report.json")).unwrap()).unwrap();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, digest) in report["source_sha256"].as_object().unwrap() {
        let actual: String = Sha256::digest(std::fs::read(root.join(path)).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, digest.as_str().unwrap());
    }
    assert_eq!(report["passed"], true);
    assert_eq!(report["source_unchanged"], true);
    let cases = report["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    let mut positive_reads = 0;
    let mut gaps = 0;
    for case in cases {
        let name = case["case"].as_str().unwrap();
        let raw = std::fs::read(directory.join(format!("{name}.raw.jsonl"))).unwrap();
        let first: Value =
            serde_json::from_slice(raw.split(|b| *b == b'\n').next().unwrap()).unwrap();
        let digest = first["config_sha256"].as_str().unwrap();
        let mut config = [0; 32];
        for (i, byte) in config.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).unwrap();
        }
        // Synthetic test enrollment only; original native authority is reviewed
        // separately. Record fields cannot authenticate a production profile.
        let p = Profile::new(
            first["host"].as_str().unwrap(),
            first["boot_id"].as_str().unwrap().parse().unwrap(),
            first["capture_id"].as_str().unwrap().parse().unwrap(),
            config,
            first["audit_arch"].as_u64().unwrap() as u32,
        )
        .unwrap();
        let mut continuity = Continuity::new();
        let mut count = 0;
        for line in raw.split_inclusive(|b| *b == b'\n') {
            let m = continuity.admit(line, &p).unwrap();
            let event = normalize(line, &p, source(), Uuid::new_v4(), time()).unwrap();
            assert_eq!(
                serde_json::to_value(&m).unwrap(),
                event.attributes["runtime_metadata"]
            );
            positive_reads += usize::from(m.operation.positive_regular_read());
            gaps += usize::from(matches!(m.operation, Operation::Gap { .. }));
            count += 1;
        }
        assert_eq!(count, case["records"].as_u64().unwrap());
    }
    assert_eq!(positive_reads, 6);
    assert_eq!(gaps, 8);
}

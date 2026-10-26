#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "../../../crates/signal-rules/tests/support/correlation_d14.rs"]
#[allow(dead_code)]
mod support;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_collector_sdk::runtime_metadata as sdk;
use signal_event::Source;
use signal_rules::correlation::d14::*;
use std::path::PathBuf;
use support::*;
use uuid::Uuid;

#[test]
#[ignore = "requires reviewed owned native capture report and exact retained source/binaries"]
fn owned_native_metadata_composes_sdk_core_and_independent_historical_classification() -> Result {
    let directory = PathBuf::from(std::env::var("SIGNAL_RUNTIME_NATIVE_DIR")?);
    let report: Value = serde_json::from_slice(&std::fs::read(directory.join("report.json"))?)?;
    assert_eq!(report["passed"], true);
    assert_eq!(report["source_unchanged"], true);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (path, digest) in report["source_sha256"].as_object().ok_or("source map")? {
        let actual: String = Sha256::digest(std::fs::read(root.join(path))?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, digest.as_str().ok_or("digest")?);
    }
    for (path, digest) in report["executable_sha256"].as_object().ok_or("ELF map")? {
        let actual: String = Sha256::digest(std::fs::read(path)?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, digest.as_str().ok_or("ELF digest")?);
    }
    let mut matched = Vec::new();
    let mut negative = Vec::new();
    let mut decoded = 0;
    let mut gaps = 0;
    for case in report["cases"].as_array().ok_or("cases")? {
        let name = case["case"].as_str().ok_or("case")?;
        let raw = std::fs::read(directory.join(format!("{name}.raw.jsonl")))?;
        let first: Value =
            serde_json::from_slice(raw.split(|b| *b == b'\n').next().ok_or("line")?)?;
        let mut digest = [0; 32];
        let hex = first["config_sha256"].as_str().ok_or("config")?;
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
        }
        let host = first["host"].as_str().ok_or("host")?;
        let profile = sdk::Profile::new(
            host,
            first["boot_id"].as_str().ok_or("boot")?.parse()?,
            first["capture_id"].as_str().ok_or("capture")?.parse()?,
            digest,
            first["audit_arch"].as_u64().ok_or("ABI")? as u32,
        )?;
        let mut cfg = config();
        cfg.sources[0].host = host.into();
        cfg.sources[0].metadata_config_sha256 = digest;
        let c = context();
        let binding = RuntimeBinding::new(cfg, &c)?;
        let last: Value = serde_json::from_slice(
            raw.split(|b| *b == b'\n')
                .rfind(|s| !s.is_empty())
                .ok_or("terminal")?,
        )?;
        let from = ns(first["timestamp_ns"].as_u64().ok_or("first timestamp")?);
        let frontier = ns(last["timestamp_ns"].as_u64().ok_or("last timestamp")?);
        let checked = frontier + chrono::TimeDelta::seconds(2);
        // Independent host-fixture verdicts from the qualified supervisor report;
        // these are simulated authority, never a producer coverage flag.
        let complete = case["exit_code"] == 0;
        let s = &binding.config().sources[0];
        let source = RuntimeVerification {
            source: signal_rules::correlation::Verification {
                stream: s.stream,
                position: case["records"].as_u64().ok_or("records")?,
                source_binding: s.binding,
                source_config_revision: s.config_revision.clone(),
                authority_keys_sha256: binding.config().authority_keys_sha256,
                verification_reference: format!("fixture://qualified-supervisor/{name}"),
                verified_at: checked,
                verified_until: checked + chrono::TimeDelta::seconds(30),
                now: checked,
                coverage_from: from,
                frontier,
                complete,
                authenticated: true,
            },
            capture: CaptureEvidence {
                enrollment_sha256: binding.enrollment_sha256(),
                metadata_only: true,
                execution_continuity: true,
                clock_continuity: true,
            },
        };
        let policies = binding
            .config()
            .policy_authorities
            .iter()
            .map(|a| PolicyCoverageVerification {
                enrollment_sha256: binding.enrollment_sha256(),
                authority: a.id,
                authority_binding: a.binding,
                config_revision: a.config_revision.clone(),
                authority_keys_sha256: a.authority_keys_sha256,
                policy_revision: a.policy_revision.clone(),
                policy_config_sha256: a.policy_config_sha256,
                reference: format!("fixture://independent-policy-coverage/{name}"),
                verified_at: checked,
                verified_until: checked + chrono::TimeDelta::seconds(30),
                now: checked,
                coverage_from: from,
                frontier,
                complete: true,
                authenticated: true,
            })
            .collect();
        let epoch = RuntimeEpoch::new(&binding, vec![source], policies, &c)?;
        assert_eq!(epoch.has_coverage_gap(&binding, &c)?, !complete);
        let mut continuity = sdk::Continuity::new();
        let mut reads = Vec::new();
        let mut connects = Vec::new();
        for (ordinal, line) in raw.split_inclusive(|b| *b == b'\n').enumerate() {
            let native = continuity.admit(line, &profile)?;
            let event = sdk::normalize(
                line,
                &profile,
                Source {
                    source_type: "runtime".into(),
                    name: Some("owned-source".into()),
                },
                Uuid::new_v4(),
                ns(native.observed_ns + 1_000_000_000),
            )?;
            let input = Input::new(&binding, Uuid::from_u128(1), &event, &c)?;
            epoch.verify_input(&binding, &input, ordinal as u64 + 1, &c)?;
            assert_eq!(
                serde_json::to_value(input.process())?,
                serde_json::to_value(&native.process)?
            );
            assert_eq!(
                serde_json::to_value(input.operation())?,
                serde_json::to_value(&native.operation)?
            );
            decoded += 1;
            let role = match input.operation() {
                Operation::Read {
                    object,
                    result,
                    error: false,
                    ..
                } if object.object_type == 0o100000 && *result > 0 => Some(Role::Asset),
                Operation::Connect {
                    object,
                    result: 0,
                    error: false,
                    ..
                } if object.object_type == 0o140000 => Some(Role::Destination),
                Operation::Gap { .. } => {
                    gaps += 1;
                    None
                }
                _ => None,
            };
            if let Some(role) = role {
                let authority = binding
                    .config()
                    .policy_authorities
                    .iter()
                    .find(|a| a.role == role)
                    .ok_or("authority")?;
                let interval = input.operation().interval().ok_or("interval")?;
                // Synthetic private fixture policy, independently supplied by
                // the host test. The alternate FD-reuse file is not protected.
                // No classification flag is read from native/normalized data.
                let yes = role == Role::Destination || name != "reuse";
                let now = ns(native.observed_ns + 1_000_000_000);
                let proof = Verification {
                    claim: input.claim(&c)?,
                    authority: authority.id,
                    authority_binding: authority.binding,
                    config_revision: authority.config_revision.clone(),
                    authority_keys_sha256: authority.authority_keys_sha256,
                    policy_revision: authority.policy_revision.clone(),
                    policy_config_sha256: authority.policy_config_sha256,
                    decision: if role == Role::Asset {
                        Decision::Asset {
                            protected_credential: yes,
                        }
                    } else {
                        Decision::Destination { suspicious: yes }
                    },
                    covered_from: ns(interval.entry_ns),
                    covered_through: ns(interval.exit_ns),
                    reference: format!("fixture://private-policy/{name}/{role:?}"),
                    verified_at: now,
                    verified_until: now + chrono::TimeDelta::seconds(30),
                    now,
                    authenticated: true,
                };
                let evidence = CurrentDecision::new(&binding, &input, proof, &c)?
                    .retained(&binding, &input, &c)?;
                if role == Role::Asset {
                    reads.push((input, evidence));
                } else {
                    connects.push((input, evidence));
                }
            } else {
                assert!(input.claim(&c).is_err());
            }
        }
        if let (Some((read, asset)), Some((connect, destination))) =
            (reads.first(), connects.last())
        {
            let outcome = relation(&binding, read, asset, connect, destination, &c)?;
            if name == "exec" || name == "reuse" {
                assert_eq!(outcome, Relation::NotApplicable, "{name}");
                negative.push(name.to_owned());
            } else {
                assert_eq!(outcome, Relation::Match, "{name}");
                matched.push(name.to_owned());
            }
        }
    }
    matched.sort();
    negative.sort();
    assert_eq!(matched, ["execfail", "output", "read", "rename"]);
    assert_eq!(negative, ["exec", "reuse"]);
    assert_eq!(gaps, 8);
    assert_eq!(
        decoded,
        report["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["records"].as_u64().unwrap())
            .sum::<u64>()
    );
    Ok(())
}

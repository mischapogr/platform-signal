//! Private host evidence, verified afresh. No collector claims or cached grants.
use crate::config::{self, ConfigError, Settings};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ring::signature;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use signal_collector_sdk::coverage::{
    CoverageContext, CoverageProfile,
    onboarding::{self, Detection, OnboardingReport, Requirement, RequirementStatus},
};
use signal_event::SignalEvent;
use signal_protocol::access::ScopeFacts;
use signal_rules::{RuleContext, RuleError, RuleSet};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const DOMAIN: &[u8] = b"PLATFORM::SIGNAL/onboarding/v1\0";
const MAX_DOCUMENT: usize = 262_144;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u32,
    scope_id: String,
    public_key_base64: String,
    report_path: PathBuf,
    coverage_profile_json: String,
    coverage_context_json: String,
    event_scope: EventScope,
    detections: Vec<PolicyDetection>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn fixture(at: DateTime<Utc>) -> Result<(Value, Value, Value)> {
        let fixtures: Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/source-coverage/contract.json"
        ))?;
        let find = |group: &str, id: &str| -> std::result::Result<Value, ConfigError> {
            fixtures[group]
                .as_array()
                .and_then(|rows| rows.iter().find(|r| r["id"] == id))
                .cloned()
                .ok_or_else(invalid)
        };
        let mut record = find("record_cases", "quiet_verified")?["record"].clone();
        let mut context = find("assessment_cases", "quiet_current")?["context"].clone();
        let base = DateTime::parse_from_rfc3339("2026-10-07T00:05:30Z")?.with_timezone(&Utc);
        fn shift(value: &mut Value, delta: chrono::TimeDelta) {
            match value {
                Value::String(text) => {
                    if let Ok(time) = DateTime::parse_from_rfc3339(text) {
                        *text = (time + delta)
                            .with_timezone(&Utc)
                            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        shift(value, delta);
                    }
                }
                Value::Object(values) => {
                    for value in values.values_mut() {
                        shift(value, delta);
                    }
                }
                _ => {}
            }
        }
        shift(&mut record, at - base);
        shift(&mut context, at - base);
        let profile = fixtures["profiles"]
            .as_array()
            .and_then(|rows| rows.iter().find(|p| p["id"] == "fixture-basic"))
            .cloned()
            .ok_or_else(invalid)?;
        Ok((record, context, profile))
    }
    fn signer() -> std::result::Result<Ed25519KeyPair, ConfigError> {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).map_err(|_| invalid())
    }
    fn envelope(payload: &Value) -> Result<String> {
        let body = serde_json::to_vec(payload)?;
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&body);
        Ok(serde_json::to_string(
            &json!({"schema_version":1,"payload_base64":STANDARD.encode(body),"signature_base64":STANDARD.encode(signer()?.sign(&signed).as_ref())}),
        )?)
    }
    fn setup(path: &std::path::Path, at: DateTime<Utc>) -> Result<(Arc<Host>, Value, RuleSet)> {
        let (record, context, profile) = fixture(at)?;
        let rules = RuleSet::from_yaml_documents(
            [
                "apiVersion: signal.dev/v1\nkind: Rule\nmetadata: {id: fixture-rule, name: fixture}\nspec:\n  severity: medium\n  match: {all: [{field: message, exists: true}]}\n  finding: {title: Fixture}",
            ],
            signal_rules::RuleLimits::default(),
        )?;
        let policy = json!({"schema_version":1,"scope_id":"fixture-scope","public_key_base64":STANDARD.encode(signer()?.public_key().as_ref()),"report_path":path,"coverage_profile_json":serde_json::to_string(&profile)?,"coverage_context_json":serde_json::to_string(&context)?,"event_scope":{"source":"application","account":"acct","resource":"api"},"detections":[{"id":"fixture-rule","supported":true,"permissions":["read-audit"],"categories":["audit"],"state":["baseline"]}]});
        let host = Arc::new(Host::parse(
            &serde_json::to_string(&policy)?,
            &["fixture-rule".into()],
        )?);
        std::fs::write(
            path.with_file_name("policy.json"),
            serde_json::to_string(&policy)?,
        )?;
        let payload = json!({"schema_version":1,"scope_id":"fixture-scope","observed_at":at,"expires_at":at+chrono::TimeDelta::seconds(20),"connected":true,"observer_status":"healthy","coverage_record":record,"interval":context["interval"],"permissions":{"read-audit":"met"},"categories":{"audit":"met"},"state":{"baseline":"met"}});
        Ok((host, payload, rules))
    }

    #[test]
    fn onboarding_signature_scope_time_and_payload_refusals() -> Result {
        let dir = tempfile::tempdir()?;
        let at = Utc::now();
        let (host, payload, _) = setup(&dir.path().join("report.json"), at)?;
        let evidence = host.verify(&envelope(&payload)?, at)?;
        assert_eq!(
            host.assess(Some(&evidence), at)?.stage,
            onboarding::Stage::DetectionsActive
        );
        for (field, value) in [
            ("scope_id", json!("other-scope")),
            ("expires_at", json!(at)),
            ("observed_at", json!(at + chrono::TimeDelta::seconds(1))),
            ("expires_at", json!(at + chrono::TimeDelta::seconds(31))),
        ] {
            let mut bad = payload.clone();
            bad[field] = value;
            assert!(host.verify(&envelope(&bad)?, at).is_err());
        }
        let mut unsigned: Value = serde_json::from_str(&envelope(&payload)?)?;
        unsigned["signature_base64"] = STANDARD.encode([0; 64]).into();
        assert!(host.verify(&serde_json::to_string(&unsigned)?, at).is_err());
        unsigned["signature_base64"] = "".into();
        assert!(host.verify(&serde_json::to_string(&unsigned)?, at).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn stateless_evaluation_keeps_separate_window_inventory_and_live_coverage() -> Result {
        let _worker_fixture = config::FILE_WORKER_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("report.json");
        let at = Utc::now();
        let (mut host, payload, rules) = setup(&path, at)?;
        Arc::get_mut(&mut host)
            .ok_or_else(invalid)?
            .policy
            .detections
            .push(PolicyDetection {
                id: "fixture-window".into(),
                supported: true,
                permissions: vec!["read-audit".into()],
                categories: vec!["audit".into()],
                state: vec!["baseline".into()],
            });
        let event: signal_event::IngestEvent = serde_json::from_value(json!({
            "timestamp":at,"source":{"type":"application"},"message":"fixture",
            "resource":{"kind":"service","id":"api","account_id":"acct"}
        }))?;
        let event = event.normalize(at)?;
        assert!(
            host.evaluate(
                &rules,
                &event,
                &RuleContext::new(Duration::from_secs(5)),
                true
            )
            .await?
            .is_empty()
        );
        std::fs::write(&path, envelope(&payload)?)?;
        let snapshot = host
            .snapshot(&RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(snapshot.report.detections.len(), 2);
        assert!(snapshot.report.detections.iter().all(|d| d.active));
        assert_eq!(
            host.evaluate(
                &rules,
                &event,
                &RuleContext::new(Duration::from_secs(5)),
                true
            )
            .await?
            .len(),
            1
        );
        assert!(
            host.evaluate(
                &rules,
                &event,
                &RuleContext::new(Duration::from_secs(5)),
                false
            )
            .await?
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn onboarding_startup_refuses_wrong_inventory_historical_context_and_unknown_options() -> Result
    {
        let dir = tempfile::tempdir()?;
        let at = Utc::now();
        let path = dir.path().join("report.json");
        let _ = setup(&path, at)?;
        let policy: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("policy.json"))?)?;
        assert!(Host::parse(&serde_json::to_string(&policy)?, &["other-rule".into()]).is_err());
        let mut historical = policy.clone();
        let mut context: Value = serde_json::from_str(
            historical["coverage_context_json"]
                .as_str()
                .ok_or_else(invalid)?,
        )?;
        context["mode"] = "historical".into();
        historical["coverage_context_json"] = serde_json::to_string(&context)?.into();
        assert!(
            Host::parse(
                &serde_json::to_string(&historical)?,
                &["fixture-rule".into()]
            )
            .is_err()
        );
        let mut unknown = policy;
        unknown["connected"] = true.into();
        assert!(Host::parse(&serde_json::to_string(&unknown)?, &["fixture-rule".into()]).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn onboarding_validity_is_capped_by_source_coverage_not_only_host_expiry() -> Result {
        let _worker_fixture = config::FILE_WORKER_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir()?;
        let at = Utc::now();
        let path = dir.path().join("report.json");
        let (host, mut payload, _) = setup(&path, at)?;
        let source_end = at + chrono::TimeDelta::seconds(10);
        payload["coverage_record"]["valid_until"] = source_end
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            .into();
        std::fs::write(&path, envelope(&payload)?)?;
        let snapshot = host
            .snapshot(&RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(snapshot.valid_until, Some(source_end));
        assert!(snapshot.report.detections[0].active);
        Ok(())
    }

    #[tokio::test]
    async fn onboarding_account_restricted_coverage_must_match_event_account() -> Result {
        let _worker_fixture = config::FILE_WORKER_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir()?;
        let (host, _, _) = setup(&dir.path().join("report.json"), Utc::now())?;
        let mut binding = host.template["binding"].clone();
        binding["observer_id"] = host.template["observer_id"].clone();
        let budgets = signal_coverage::CoverageConfig::default();
        let limits = json!({"max_payloads":budgets.max_payloads,"max_identities":budgets.max_identities,
            "max_bindings":budgets.max_bindings,"max_ledger_bytes":budgets.max_ledger_bytes,
            "max_database_pages":budgets.max_database_pages,"max_journal_bytes":budgets.max_journal_bytes,
            "operation_capacity":budgets.operation_capacity,"transient_memory_bytes":budgets.transient_memory_bytes,
            "worker_memory_bytes":budgets.worker_memory_bytes,"max_vm_steps":budgets.max_vm_steps,"operation_timeout_ms":1000});
        let path = dir.path().join("coverage.json");
        let configured = path.to_str().ok_or_else(invalid)?;
        let settings = Settings::for_test(
            "schema_version: 1\n",
            &[
                ("SIGNAL_COVERAGE_CONFIG", configured),
                ("SIGNAL_ACCESS_CONFIG", "fixture-native-mode"),
            ],
        )?;
        for account in [Some("acct"), Some("different-account"), None] {
            let config = json!({"schema_version":1,"directory":dir.path().join("coverage"),"limits":limits,
                "scopes":[{"binding_json":serde_json::to_string(&binding)?,"profile_json":host.policy.coverage_profile_json,
                    "authority_revision":"fixture-v1","identity":{"scope_id":"fixture-scope","account_id":account,
                        "writer_issuer":"https://identity.fixture.test","writer_subject":"fixture"},
                    "max_report_age_seconds":60,"max_clock_skew_seconds":2,"payload_retention_seconds":300,"identity_retention_seconds":600}]});
            std::fs::write(&path, serde_json::to_vec(&config)?)?;
            let config = crate::coverage_api::Configuration::load(&settings)
                .await?
                .ok_or_else(invalid)?;
            let result = config.validate_onboarding(&host);
            if account == Some("different-account") {
                assert!(matches!(
                    result,
                    Err(ConfigError::Invalid(
                        "onboarding coverage/event account mismatch"
                    ))
                ));
            } else {
                result?;
            }
        }
        assert!(
            !dir.path().join("coverage").exists(),
            "validation must not open persistence"
        );
        Ok(())
    }

    #[test]
    fn onboarding_valid_signature_does_not_override_missing_prerequisites_or_coverage() -> Result {
        let dir = tempfile::tempdir()?;
        let at = Utc::now();
        let (host, payload, _) = setup(&dir.path().join("report.json"), at)?;
        for (field, value) in [
            ("connected", json!(false)),
            ("observer_status", json!("unhealthy")),
            ("permissions", json!({})),
            ("categories", json!({"audit":"missing"})),
            ("state", json!({"baseline":"unknown"})),
            ("coverage_record", json!({})),
        ] {
            let mut blocked = payload.clone();
            blocked[field] = value;
            let evidence = host.verify(&envelope(&blocked)?, at)?;
            assert!(!host.assess(Some(&evidence), at)?.detections[0].active);
        }
        assert!(!host.assess(None, at)?.detections[0].active);
        Ok(())
    }

    #[tokio::test]
    async fn onboarding_actual_file_evaluation_is_fresh_scoped_and_authentication_bound() -> Result
    {
        let _worker_fixture = config::FILE_WORKER_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("report.json");
        let at = Utc::now();
        let (host, payload, rules) = setup(&path, at)?;
        std::fs::write(&path, envelope(&payload)?)?;
        let event: SignalEvent=serde_json::from_str::<signal_event::IngestEvent>(r#"{"timestamp":"2026-10-14T00:00:00Z","source":{"type":"application","name":"fixture"},"message":"fixture","resource":{"kind":"service","id":"api","account_id":"acct"}}"#)?.normalize("2026-10-14T00:01:00Z".parse()?)?;
        let context = RuleContext::new(Duration::from_secs(5));
        assert_eq!(
            host.evaluate(&rules, &event, &context, true).await?.len(),
            1
        );
        assert!(
            host.evaluate(&rules, &event, &context, false)
                .await?
                .is_empty()
        );
        let mut other = event.clone();
        other.source.source_type = "other".into();
        assert!(
            host.evaluate(&rules, &other, &context, true)
                .await?
                .is_empty()
        );
        let mut blocked = payload.clone();
        blocked["permissions"] = json!({"read-audit":"missing"});
        std::fs::write(&path, envelope(&blocked)?)?;
        assert!(
            host.evaluate(&rules, &event, &context, true)
                .await?
                .is_empty()
        );
        std::fs::write(&path, "invalid")?;
        assert!(
            host.evaluate(&rules, &event, &context, true)
                .await?
                .is_empty()
        );
        let mut malformed_interval = payload.clone();
        malformed_interval["interval"] = json!({"start":"bad", "end":"bad"});
        std::fs::write(&path, envelope(&malformed_interval)?)?;
        assert!(
            host.evaluate(&rules, &event, &context, true)
                .await?
                .is_empty()
        );
        std::fs::remove_file(&path)?;
        assert!(
            host.evaluate(&rules, &event, &context, true)
                .await?
                .is_empty()
        );
        context.cancellation.cancel();
        assert!(matches!(
            host.evaluate(&rules, &event, &context, true).await,
            Err(RuleError::Cancelled)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn window_actual_signed_coverage_atomic_outbox_publication_and_replay() -> Result {
        use signal_buffer::{BufferMetrics, SequencedEvent};
        use signal_findings::{FindingConfig, FindingContext, FindingStore};
        use std::os::unix::fs::PermissionsExt;
        let _worker_fixture = config::FILE_WORKER_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let at = Utc::now();
        let report_path = dir.path().join("report.json");
        let (host, payload, _) = setup(&report_path, at)?;
        std::fs::write(&report_path, envelope(&payload)?)?;
        let window_path = dir.path().join("window.json");
        let stream = uuid::Uuid::from_u128(20);
        let policy = json!({"schema_version":1,"database":dir.path().join("window.sqlite"),"policy":{
            "schema_version":1,"partition":uuid::Uuid::from_u128(10),"rule_id":"fixture-rule","revision":"fixture-v1",
            "title":"fixture window","severity":"medium","threshold":3,"window_ms":10000,"lateness_ms":0,"ttl_ms":20000,
            "max_keys":4,"max_attempts_per_key":8,"max_attempts":16,"max_outputs":16,"max_state_bytes":65536,"max_history_assessments":64,"max_history_bytes":262144,"history_retention_ms":60000}});
        std::fs::write(&window_path, serde_json::to_vec(&policy)?)?;
        let settings = Settings::for_test(
            "schema_version: 1\n",
            &[(
                "SIGNAL_WINDOW_CONFIG",
                window_path.to_str().ok_or_else(invalid)?,
            )],
        )?;
        let wal = BufferMetrics {
            stream_id: stream,
            last_sequence: 3,
            ..Default::default()
        };
        let detector = crate::window::Configuration::load(&settings)
            .await?
            .ok_or_else(invalid)?
            .open(wal, host.clone())
            .await?;
        let end: DateTime<Utc> = payload["interval"]["end"]
            .as_str()
            .ok_or_else(invalid)?
            .parse()?;
        let mut batch = Vec::new();
        for (sequence, seconds) in [(1, 8), (2, 5), (3, 2)] {
            let time = end - chrono::TimeDelta::seconds(seconds);
            let input: signal_event::IngestEvent = serde_json::from_value(
                json!({"timestamp":time,
                "source":{"type":"application","name":"fixture"},"message":"authentication fixture",
                "resource":{"kind":"service","id":"api","account_id":"acct"},
                "attributes":{"authentication":{"identity_authority":"fixture","principal_id":"user","target_id":"target","outcome":"failure","method":"password","session_id":"fixture"},
                    "producer":{"boot_id":"fixture-boot","sequence":sequence}}}),
            )?;
            batch.push(SequencedEvent {
                sequence,
                event: input.normalize(at)?,
            });
        }
        assert!(detector.metrics().coverage_gap);
        let outputs = detector
            .complete(&batch, 0, 3, RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(outputs.findings.len(), 1);
        let health = detector.metrics();
        assert_eq!((health.operations, health.operation_capacity), (0, 1));
        assert_eq!((health.attempts, health.attempt_capacity), (3, 16));
        assert_eq!((health.assessments, health.assessment_capacity), (3, 16));
        assert!(health.bytes > 0 && health.bytes <= health.byte_capacity);
        assert!(!health.coverage_gap);
        let failed = RuleContext::new(Duration::from_secs(5));
        failed.cancellation.cancel();
        assert!(detector.complete(&batch, 0, 3, failed).await.is_err());
        assert!(detector.metrics().coverage_gap);
        let expected_id = outputs.findings[0].budget_preview().id;
        let store = FindingStore::open(
            FindingConfig {
                directory: dir.path().join("findings"),
                ..Default::default()
            },
            stream,
        )
        .await?;
        store
            .enable_scopes(FindingContext::new(Duration::from_secs(5)))
            .await?;
        let receipt = store
            .append_derived(
                outputs.findings,
                FindingContext::new(Duration::from_secs(5)),
            )
            .await?;
        assert_eq!((receipt.inserted, receipt.duplicates), (1, 0));
        let saved = detector
            .journal
            .load(RuleContext::new(Duration::from_secs(5)))
            .await?
            .ok_or_else(invalid)?;
        assert_eq!(saved.checkpoint, 3);
        assert_eq!(
            saved.findings[0].event_ids,
            batch.iter().map(|r| r.event.id).collect::<Vec<_>>()
        );
        detector
            .journal
            .shutdown(RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert!(detector.metrics().closed);
        assert!(detector.metrics().coverage_gap);
        let restarted = crate::window::Configuration::load(&settings)
            .await?
            .ok_or_else(invalid)?
            .open(wal, host.clone())
            .await?;
        std::fs::remove_file(&report_path)?;
        let replay = restarted
            .complete(&batch, 3, 3, RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(replay.findings.len(), 1);
        assert_eq!(replay.findings[0].budget_preview().id, expected_id);
        let receipt = store
            .append_derived(replay.findings, FindingContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!((receipt.inserted, receipt.duplicates), (0, 1));
        restarted
            .acknowledge(
                replay.revision,
                replay.assessments,
                RuleContext::new(Duration::from_secs(5)),
            )
            .await?;
        let retired = restarted
            .journal
            .load(RuleContext::new(Duration::from_secs(5)))
            .await?
            .ok_or_else(invalid)?;
        assert_eq!(retired.checkpoint, 3);
        assert!(retired.state.assessments().is_empty());
        assert!(retired.findings.is_empty());
        assert_eq!(restarted.metrics().assessments, 0);
        assert_eq!(restarted.metrics().history_assessments, 3);
        assert_eq!(restarted.metrics().history_assessment_capacity, 64);
        assert!(restarted.metrics().history_bytes > 0);
        assert!(
            restarted
                .acknowledge(
                    replay.revision,
                    replay.assessments,
                    RuleContext::new(Duration::from_secs(5))
                )
                .await
                .is_err()
        );
        restarted
            .journal
            .shutdown(RuleContext::new(Duration::from_secs(5)))
            .await?;
        // Retained WAL admitted before this identity generation cannot create a
        // new scoped detector result, even with a currently valid signed report.
        std::fs::write(&report_path, envelope(&payload)?)?;
        let mut unknown_policy = policy.clone();
        unknown_policy["database"] = json!(dir.path().join("unverified.sqlite"));
        std::fs::write(&window_path, serde_json::to_vec(&unknown_policy)?)?;
        let unknown = crate::window::Configuration::load(&settings)
            .await?
            .ok_or_else(invalid)?
            .open(wal, host.clone())
            .await?;
        assert!(
            unknown
                .complete(&batch, 3, 3, RuleContext::new(Duration::from_secs(5)))
                .await?
                .findings
                .is_empty()
        );
        let unknown_state = unknown
            .journal
            .load(RuleContext::new(Duration::from_secs(5)))
            .await?
            .ok_or_else(invalid)?;
        assert_eq!(unknown_state.checkpoint, 3);
        assert_eq!(
            unknown_state
                .state
                .coverage_gap()
                .ok_or_else(invalid)?
                .rejected_inputs,
            3
        );
        assert!(unknown_state.findings.is_empty());
        unknown
            .journal
            .shutdown(RuleContext::new(Duration::from_secs(5)))
            .await?;
        std::fs::write(&window_path, serde_json::to_vec(&policy)?)?;
        let mut changed_scope: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("policy.json"))?)?;
        changed_scope["event_scope"]["account"] = json!("other-account");
        let other_host = Arc::new(Host::parse(
            &serde_json::to_string(&changed_scope)?,
            &["fixture-rule".into()],
        )?);
        assert!(matches!(
            crate::window::Configuration::load(&settings)
                .await?
                .ok_or_else(invalid)?
                .open(wal, other_host)
                .await,
            Err(signal_rules::window::Error::Conflict)
        ));
        let mut split_policy = policy.clone();
        split_policy["database"] = json!(dir.path().join("split.sqlite"));
        std::fs::write(&window_path, serde_json::to_vec(&split_policy)?)?;
        let split = crate::window::Configuration::load(&settings)
            .await?
            .ok_or_else(invalid)?
            .open(wal, host.clone())
            .await?;
        let prefix = split
            .complete(&batch[..2], 0, 3, RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert!(prefix.findings.is_empty());
        let intermediate = split
            .journal
            .load(RuleContext::new(Duration::from_secs(5)))
            .await?
            .ok_or_else(invalid)?;
        assert_eq!(intermediate.state.watermark(), None);
        split
            .acknowledge(
                prefix.revision,
                prefix.assessments,
                RuleContext::new(Duration::from_secs(5)),
            )
            .await?;
        let suffix = split
            .complete(&batch[2..], 0, 3, RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert_eq!(suffix.findings.len(), 1);
        assert_eq!(suffix.findings[0].budget_preview().id, expected_id);
        split
            .journal
            .shutdown(RuleContext::new(Duration::from_secs(5)))
            .await?;
        std::fs::write(&window_path, serde_json::to_vec(&policy)?)?;
        let changed = BufferMetrics {
            stream_id: uuid::Uuid::from_u128(99),
            ..wal
        };
        assert!(matches!(
            crate::window::Configuration::load(&settings)
                .await?
                .ok_or_else(invalid)?
                .open(changed, host)
                .await,
            Err(signal_rules::window::Error::Conflict)
        ));
        store
            .shutdown(FindingContext::new(Duration::from_secs(5)))
            .await?;
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventScope {
    source: String,
    account: String,
    resource: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDetection {
    id: String,
    supported: bool,
    permissions: Vec<String>,
    categories: Vec<String>,
    state: Vec<String>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Check {
    Met,
    Missing,
    Unknown,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    payload_base64: String,
    signature_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema_version: u32,
    scope_id: String,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    connected: bool,
    observer_status: String,
    coverage_record: Box<serde_json::value::RawValue>,
    interval: Value,
    permissions: BTreeMap<String, Check>,
    categories: BTreeMap<String, Check>,
    state: BTreeMap<String, Check>,
}

pub(crate) struct Host {
    policy: Policy,
    key: [u8; 32],
    profile: CoverageProfile,
    template: Value,
    binding: signal_coverage::format::HistoryBinding,
}

#[derive(Serialize)]
pub(crate) struct Snapshot {
    #[serde(flatten)]
    pub report: OnboardingReport,
    pub assessed_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub source_interval: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

fn invalid() -> ConfigError {
    ConfigError::Invalid("onboarding host evidence")
}
fn bytes(value: &Value) -> Result<Vec<u8>, ConfigError> {
    serde_json::to_vec(value).map_err(|_| invalid())
}

impl Host {
    pub(crate) async fn load(
        settings: &Settings,
        rules: &RuleSet,
    ) -> Result<Option<Arc<Self>>, ConfigError> {
        Self::load_with_detection(settings, rules, None).await
    }
    pub(crate) async fn load_with_detection(
        settings: &Settings,
        rules: &RuleSet,
        additional: Option<&str>,
    ) -> Result<Option<Arc<Self>>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_ONBOARDING_CONFIG")? else {
            return Ok(None);
        };
        if path.is_empty() || path.len() > 4096 {
            return Err(invalid());
        }
        let mut ids: Vec<String> = rules.rule_ids().map(str::to_owned).collect();
        if let Some(id) = additional {
            if ids.iter().any(|existing| existing == id) {
                return Err(invalid());
            }
            ids.push(id.to_owned());
        }
        let host = config::read_limited_document(
            path.into(),
            MAX_DOCUMENT,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            move |text| Self::parse(text, &ids),
        )
        .await?;
        Ok(Some(Arc::new(host)))
    }

    fn parse(text: &str, ids: &[String]) -> Result<Self, ConfigError> {
        let policy: Policy = serde_json::from_str(text).map_err(|_| invalid())?;
        if policy.schema_version != 1
            || policy.scope_id.is_empty()
            || policy.scope_id.len() > 128
            || policy.detections.len() != ids.len()
            || ids.len() > onboarding::MAX_DETECTIONS
            || !policy.report_path.is_absolute()
            || policy.report_path.as_os_str().len() > 4096
            || [
                &policy.event_scope.source,
                &policy.event_scope.account,
                &policy.event_scope.resource,
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        let key: [u8; 32] = STANDARD
            .decode(&policy.public_key_base64)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        let profile = CoverageProfile::parse(policy.coverage_profile_json.as_bytes())
            .map_err(|_| invalid())?;
        let template: Value =
            serde_json::from_str(&policy.coverage_context_json).map_err(|_| invalid())?;
        let context = CoverageContext::parse(&bytes(&template)?).map_err(|_| invalid())?;
        if !context.is_current() {
            return Err(invalid());
        }
        let mut binding = template["binding"].clone();
        binding["observer_id"] = template["observer_id"].clone();
        let binding = signal_coverage::format::HistoryBinding::parse(&bytes(&binding)?)
            .map_err(|_| invalid())?;
        let host = Self {
            policy,
            key,
            profile,
            template,
            binding,
        };
        let detections = host.detections(None);
        // Exercise the SDK's identifier/count/duplicate validation at startup.
        let unavailable = onboarding::assess_onboarding(
            false,
            b"invalid",
            Some(&host.profile),
            &context,
            &detections,
        )
        .map_err(|_| invalid())?;
        // All unknown prerequisites must fit the authorized HTTP response budget.
        if serde_json::to_vec(&unavailable)
            .map_err(|_| invalid())?
            .len()
            > 500_000
        {
            return Err(invalid());
        }
        let configured: std::collections::BTreeSet<_> = host
            .policy
            .detections
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        if configured.len() != ids.len() || ids.iter().any(|id| !configured.contains(id.as_str())) {
            return Err(invalid());
        }
        Ok(host)
    }

    pub(crate) fn scope_id(&self) -> &str {
        &self.policy.scope_id
    }
    pub(crate) fn binding(&self) -> &signal_coverage::format::HistoryBinding {
        &self.binding
    }
    pub(crate) fn profile(&self) -> &CoverageProfile {
        &self.profile
    }
    pub(crate) fn event_account(&self) -> &str {
        &self.policy.event_scope.account
    }

    fn detections(&self, evidence: Option<&Evidence>) -> Vec<Detection> {
        let requirements = |ids: &[String], values: Option<&BTreeMap<String, Check>>| {
            ids.iter()
                .map(|id| Requirement {
                    id: id.clone(),
                    status: match values.and_then(|v| v.get(id)) {
                        Some(Check::Met) => RequirementStatus::Met,
                        Some(Check::Missing) => RequirementStatus::Missing,
                        _ => RequirementStatus::Unknown,
                    },
                })
                .collect()
        };
        self.policy
            .detections
            .iter()
            .map(|d| Detection {
                id: d.id.clone(),
                supported: d.supported,
                loaded: true,
                permissions: requirements(&d.permissions, evidence.map(|e| &e.permissions)),
                categories: requirements(&d.categories, evidence.map(|e| &e.categories)),
                state: requirements(&d.state, evidence.map(|e| &e.state)),
            })
            .collect()
    }

    fn verify(&self, text: &str, at: DateTime<Utc>) -> Result<Evidence, ConfigError> {
        let envelope: Envelope = serde_json::from_str(text).map_err(|_| invalid())?;
        if envelope.schema_version != 1
            || envelope.payload_base64.len() > MAX_DOCUMENT
            || envelope.signature_base64.len() > 88
        {
            return Err(invalid());
        }
        let payload = STANDARD
            .decode(envelope.payload_base64)
            .map_err(|_| invalid())?;
        let signature = STANDARD
            .decode(envelope.signature_base64)
            .map_err(|_| invalid())?;
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, self.key)
            .verify(&signed, &signature)
            .map_err(|_| invalid())?;
        let evidence: Evidence = serde_json::from_slice(&payload).map_err(|_| invalid())?;
        if evidence.schema_version != 1
            || evidence.scope_id != self.policy.scope_id
            || evidence.observed_at > at
            || evidence.expires_at <= at
            || evidence.expires_at <= evidence.observed_at
            || evidence
                .expires_at
                .signed_duration_since(evidence.observed_at)
                > chrono::TimeDelta::seconds(30)
            || !matches!(
                evidence.observer_status.as_str(),
                "healthy" | "unhealthy" | "unknown"
            )
            || [&evidence.permissions, &evidence.categories, &evidence.state]
                .iter()
                .any(|values| {
                    values.len() > 2048
                        || values
                            .keys()
                            .any(|id| id.is_empty() || id.len() > onboarding::MAX_ID_BYTES)
                })
        {
            return Err(invalid());
        }
        Ok(evidence)
    }

    fn assess(
        &self,
        evidence: Option<&Evidence>,
        at: DateTime<Utc>,
    ) -> Result<OnboardingReport, ConfigError> {
        let mut context = self.template.clone();
        context["at"] = at
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            .into();
        context["observer_status"] = evidence
            .map_or("unknown", |e| e.observer_status.as_str())
            .into();
        if let Some(evidence) = evidence {
            context["interval"] = evidence.interval.clone();
        }
        let context = CoverageContext::parse(&bytes(&context)?).map_err(|_| invalid())?;
        onboarding::assess_onboarding(
            evidence.is_some_and(|e| e.connected && e.expires_at > at && e.observed_at <= at),
            evidence.map_or(b"invalid".as_slice(), |e| {
                e.coverage_record.get().as_bytes()
            }),
            Some(&self.profile),
            &context,
            &self.detections(evidence),
        )
        .map_err(|_| invalid())
    }

    pub(crate) async fn snapshot(
        self: &Arc<Self>,
        context: &RuleContext,
    ) -> Result<Snapshot, ConfigError> {
        let host = self.clone();
        let result = config::read_limited_document(
            self.policy.report_path.clone(),
            MAX_DOCUMENT,
            context.deadline,
            context.cancellation.child_token(),
            move |text| host.verify(text, Utc::now()),
        )
        .await;
        // Unavailable/invalid evidence is an explicit unverified snapshot. A
        // cancelled/late caller still cannot receive a successful assessment.
        if context.cancellation.is_cancelled() || Instant::now() >= context.deadline {
            return Err(invalid());
        }
        let at = Utc::now();
        let evidence = result.as_ref().ok();
        let mut report = self
            .assess(evidence, at)
            .or_else(|_| self.assess(None, at))?;
        let valid_until = evidence
            .and_then(|e| {
                if report.coverage.status()
                    == signal_collector_sdk::coverage::CoverageStatus::Verified
                {
                    self.effective_until(e).ok()
                } else {
                    Some(e.expires_at)
                }
            })
            .filter(|end| *end > at);
        if evidence.is_some() && valid_until.is_none() {
            report = self.assess(None, at)?;
        }
        Ok(Snapshot {
            report,
            assessed_at: at,
            valid_until,
            source_interval: evidence.and_then(|e| {
                let parse = |field| {
                    e.interval
                        .get(field)?
                        .as_str()?
                        .parse::<DateTime<Utc>>()
                        .ok()
                };
                Some((parse("start")?, parse("end")?))
            }),
        })
    }

    fn effective_until(&self, evidence: &Evidence) -> Result<DateTime<Utc>, ConfigError> {
        let record: Value =
            serde_json::from_str(evidence.coverage_record.get()).map_err(|_| invalid())?;
        let time = |name: &str| -> Result<DateTime<Utc>, ConfigError> {
            DateTime::parse_from_rfc3339(record[name].as_str().ok_or_else(invalid)?)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| invalid())
        };
        let profile: Value =
            serde_json::from_str(&self.policy.coverage_profile_json).map_err(|_| invalid())?;
        let age = profile["max_verification_age_seconds"]
            .as_i64()
            .ok_or_else(invalid)?;
        let freshness = time("last_verified_at")?
            .checked_add_signed(chrono::TimeDelta::seconds(age))
            .ok_or_else(invalid)?;
        Ok(evidence.expires_at.min(time("valid_until")?).min(freshness))
    }

    pub(crate) async fn evaluate(
        self: &Arc<Self>,
        rules: &RuleSet,
        event: &SignalEvent,
        context: &RuleContext,
        authenticated: bool,
    ) -> Result<Vec<signal_findings::Finding>, RuleError> {
        let facts = ScopeFacts::event(event);
        let in_scope = authenticated
            && facts.source == Some(self.policy.event_scope.source.as_str())
            && facts.account == Some(self.policy.event_scope.account.as_str())
            && facts.resource == Some(self.policy.event_scope.resource.as_str());
        let snapshot = if in_scope {
            self.snapshot(context).await.map_err(|_| {
                if context.cancellation.is_cancelled() {
                    RuleError::Cancelled
                } else if Instant::now() >= context.deadline {
                    RuleError::Timeout
                } else {
                    RuleError::Invalid("onboarding evidence")
                }
            })?
        } else {
            Snapshot {
                report: self
                    .assess(None, Utc::now())
                    .map_err(|_| RuleError::Invalid("onboarding policy"))?,
                assessed_at: Utc::now(),
                valid_until: None,
                source_interval: None,
            }
        };
        let now = Utc::now();
        let live = snapshot.valid_until.is_some_and(|end| end > now);
        let decisions: Vec<_> = snapshot
            .report
            .detections
            .iter()
            // Window readiness belongs to its stateful evaluator. The strict
            // stateless inventory still requires one decision per loaded rule.
            .filter(|d| rules.rule_ids().any(|id| id == d.id))
            .map(|d| (d.id.as_str(), live && d.active))
            .collect();
        let deadline = if live {
            snapshot
                .valid_until
                .and_then(|end| (end - now).to_std().ok())
                .map(|ttl| (Instant::now() + ttl).min(context.deadline))
                .unwrap_or(context.deadline)
        } else {
            context.deadline
        };
        let result = rules.evaluate_ready_with_context(
            event,
            &RuleContext {
                deadline,
                cancellation: context.cancellation.clone(),
            },
            &decisions,
        )?;
        if context.cancellation.is_cancelled() {
            return Err(RuleError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(RuleError::Timeout);
        }
        Ok(result)
    }

    pub(crate) fn includes_event(&self, event: &SignalEvent) -> bool {
        let facts = ScopeFacts::event(event);
        facts.source == Some(self.policy.event_scope.source.as_str())
            && facts.account == Some(self.policy.event_scope.account.as_str())
            && facts.resource == Some(self.policy.event_scope.resource.as_str())
    }
    pub(crate) fn window_binding(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"PLATFORM::SIGNAL/window-source-binding/v1\0");
        for value in [
            &self.policy.scope_id,
            &self.policy.event_scope.source,
            &self.policy.event_scope.account,
            &self.policy.event_scope.resource,
            &self.policy.public_key_base64,
            &self.policy.coverage_profile_json,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.update((self.binding.encoded().len() as u64).to_be_bytes());
        digest.update(self.binding.encoded());
        digest.finalize().into()
    }
}

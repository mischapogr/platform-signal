#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use signal_findings::{
    DerivedFinding, Finding, FindingConfig, FindingStore, disposition::FindingReference,
};
use signal_ingest::identity::{IdentityBackend, IdentityConfig};
use signal_protocol::access::{AccessPolicy, introspection::IntrospectionProfile};
use std::{fs, os::unix::fs::PermissionsExt};
use tower::ServiceExt;
mod episode_fixture;
mod tls;
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct AbortTask(tokio::task::AbortHandle);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct AuditPause {
    sequence: u64,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
struct PauseDestination {
    inner: Arc<dyn signal_protocol::audit::AuditSink>,
    pause: Arc<AuditPause>,
}
impl signal_protocol::audit::AuditSink for PauseDestination {
    fn append<'a>(
        &'a self,
        record: &'a signal_protocol::audit::PreparedAudit,
        deadline: std::time::Instant,
    ) -> signal_protocol::audit::AppendFuture<'a> {
        Box::pin(async move {
            self.inner.append(record, deadline).await?;
            if record.record().sequence == self.pause.sequence {
                self.pause.entered.notify_one();
                tokio::time::timeout(Duration::from_secs(4), self.pause.release.notified())
                    .await
                    .map_err(|_| signal_protocol::audit::AppendError::Uncertain)?;
            }
            Ok(())
        })
    }
    fn metrics(&self) -> signal_protocol::audit::AuditMetrics {
        self.inner.metrics()
    }
}

fn scope(account: &str) -> Value {
    json!({"sources":{"mode":"only","values":["application"]},
        "accounts":{"mode":"only","values":[account]},"resources":{"mode":"only","values":["api"]}})
}
fn permissions(operations: &[&str], account: &str) -> Vec<Value> {
    operations
        .iter()
        .map(|op| json!({"operation":op,"scope":scope(account)}))
        .collect()
}
fn episode_permissions(source: Option<&str>) -> Vec<Value> {
    let sources = source.map_or_else(
        || json!({"mode":"all"}),
        |source| json!({"mode":"only","values":[source]}),
    );
    let scope = json!({"sources":sources,"accounts":{"mode":"all"},"resources":{"mode":"all"}});
    [
        "create_cases",
        "assign_cases",
        "read_cases",
        "read_findings",
        "read_evidence",
    ]
    .iter()
    .map(|op| json!({"operation":op,"scope":scope}))
    .collect()
}
fn replacement_policy_permissions() -> Vec<Value> {
    let scope = json!({"sources":{"mode":"only","values":["historical-policy"]},
        "accounts":{"mode":"only","values":["replacement-policy-scope"]},"resources":{"mode":"only","values":["replacement-policy"]}});
    [
        "create_cases",
        "assign_cases",
        "read_cases",
        "read_findings",
        "read_evidence",
    ]
    .iter()
    .map(|op| json!({"operation":op,"scope":scope}))
    .collect()
}
struct Fixture {
    root: tempfile::TempDir,
    provider: tls::Provider,
    host: Arc<Host>,
    findings: Arc<FindingStore>,
    reference: FindingReference,
    foreign: FindingReference,
    signer: Ed25519KeyPair,
    report: Value,
}
impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_pause(None).await
    }
    async fn with_pause(
        pause: Option<Arc<AuditPause>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let provider = tls::Provider::new()?;
        let policy = json!({"schema_version":1,"roles":[
            {"id":"writer","permissions":permissions(&["create_cases","assign_cases","read_findings"],"a")},
            {"id":"reader","permissions":permissions(&["read_cases","read_findings"],"a")},
            {"id":"evidence","permissions":permissions(&["read_cases","read_findings","read_evidence"],"a")},
            {"id":"foreign","permissions":permissions(&["create_cases","assign_cases","read_cases","read_findings"],"b")},
            {"id":"creator-b","permissions":permissions(&["create_cases","read_findings"],"b")},
            {"id":"reader-b","permissions":permissions(&["read_cases","read_findings"],"b")},
            {"id":"findings-b","permissions":permissions(&["read_findings"],"b")},
            {"id":"cases-b","permissions":permissions(&["read_cases"],"b")},
            {"id":"episode-admin","permissions":episode_permissions(None)},
            {"id":"episode-runtime-only","permissions":episode_permissions(Some("runtime"))},
            {"id":"episode-auth-only","permissions":episode_permissions(Some("authentication-1"))},
            {"id":"episode-new-policy","permissions":replacement_policy_permissions()}
        ],"bindings":[
            {"issuer":"https://soc-idp.example.test","subject":"writer","roles":["writer"]},
            {"issuer":"https://soc-idp.example.test","subject":"reader","roles":["reader"]},
            {"issuer":"https://soc-idp.example.test","subject":"evidence","roles":["evidence"]},
            {"issuer":"https://soc-idp.example.test","subject":"foreign","roles":["foreign"]},
            {"issuer":"https://soc-idp.example.test","subject":"creator-ab","roles":["writer","creator-b"]},
            {"issuer":"https://soc-idp.example.test","subject":"assigner-ab","roles":["writer","foreign"]},
            {"issuer":"https://soc-idp.example.test","subject":"evidence-ab","roles":["evidence","reader-b"]},
            {"issuer":"https://soc-idp.example.test","subject":"evidence-missing-case","roles":["evidence","findings-b"]},
            {"issuer":"https://soc-idp.example.test","subject":"evidence-missing-finding","roles":["evidence","cases-b"]},
            {"issuer":"https://soc-idp.example.test","subject":"episode-admin","roles":["episode-admin"]},
            {"issuer":"https://soc-idp.example.test","subject":"episode-runtime-only","roles":["episode-runtime-only"]},
            {"issuer":"https://soc-idp.example.test","subject":"episode-auth-only","roles":["episode-auth-only"]},
            {"issuer":"https://soc-idp.example.test","subject":"episode-new-policy","roles":["episode-runtime-only","episode-new-policy"]}
        ]});
        let identity = IdentityBackend::new(
            IdentityConfig {
                endpoint: format!("https://{}/introspect", provider.address),
                client_id: "synthetic-client".into(),
                client_secret: "synthetic-secret".into(),
                extra_roots: vec![provider.root.clone()],
                workers: 1,
                max_request_duration: Duration::from_secs(1),
            },
            IntrospectionProfile::new("https://soc-idp.example.test".into(), "signal".into(), 30)?,
            AccessPolicy::from_json(&serde_json::to_vec(&policy)?)?.compile()?,
            tokio::runtime::Handle::current(),
        )?;
        let stream = Uuid::new_v4();
        let findings = Arc::new(
            FindingStore::open(
                FindingConfig {
                    directory: root.path().join("findings"),
                    ..Default::default()
                },
                stream,
            )
            .await?,
        );
        findings
            .enable_scopes(FindingContext::new(Duration::from_secs(5)))
            .await?;
        let mut references = Vec::new();
        for account in ["a", "b"] {
            let event = serde_json::from_value::<signal_event::IngestEvent>(json!({"timestamp":"2026-10-27T00:00:00Z","source":{"type":"application"},"message":"synthetic finding","resource":{"kind":"service","id":"api","account_id":account}}))?.normalize("2026-10-27T00:01:00Z".parse()?)?;
            let finding = Finding::for_event(
                "fixture-rule",
                &event,
                signal_findings::DetectionSeverity::High,
                "private finding",
            )?;
            references.push(FindingReference {
                stream_id: stream,
                finding_id: finding.id,
            });
            findings
                .append_derived(
                    vec![DerivedFinding::from_event(finding, &event, true)?],
                    FindingContext::new(Duration::from_secs(5)),
                )
                .await?;
        }
        let outbox = root.path().join("audit");
        fs::create_dir(&outbox)?;
        fs::set_permissions(&outbox, fs::Permissions::from_mode(0o700))?;
        let destination = root.path().join("destination");
        fs::create_dir(&destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
        let ordinary = crate::audit::tests::destination(&destination, 0);
        let sink: Arc<dyn signal_protocol::audit::AuditSink> = match pause {
            Some(pause) => Arc::new(PauseDestination {
                inner: ordinary,
                pause,
            }),
            None => ordinary,
        };
        let audit = crate::audit::Control::test_open(
            &outbox,
            sink,
            vec![
                Operation::ReadCases,
                Operation::CreateCases,
                Operation::AssignCases,
                Operation::ReadEvidence,
            ],
            signal_collector_sdk::ExtensionContext::new(
                CancellationToken::new(),
                Duration::from_secs(5),
            )?,
        )
        .await?;
        let signer =
            Ed25519KeyPair::from_seed_unchecked(&[49; 32]).map_err(|_| "synthetic signer")?;
        let namespace = Uuid::new_v4();
        let configuration = json!({"schema_version":1,"namespace":namespace,"directory":root.path().join("cases"),
            "provider":"canonical_small","request_timeout_ms":5000,"max_response_bytes":1048576,
            "max_cases":100,"max_operations":1000,"max_disk_bytes":33554432,"max_state_bytes":67108864,"request_capacity":4,
            "directory_observer":{"issuer":"directory-fixture","audience":"signal-soc","key_revision":"key-v1","policy_revision":"policy-v1",
                "public_key_base64":STANDARD.encode(signer.public_key().as_ref()),"report_path":root.path().join("directory-report.json"),"max_age_seconds":30,
                "targets":[{"id":"recipient","issuer":"https://soc-idp.example.test","subject":"reader"}]}});
        let configuration = Configuration::parse(&configuration.to_string())?;
        let host = configuration
            .open(
                stream,
                findings.clone(),
                Some(identity),
                Some(audit),
                CancellationToken::new(),
            )
            .await?;
        let now = crate::access::now().ok_or("clock")?;
        let report = json!({"schema_version":1,"namespace":namespace,"issuer":"directory-fixture","audience":"signal-soc",
            "key_revision":"key-v1","policy_revision":"policy-v1","directory_revision":"directory-v1","observed_at":now,"expires_at":now+30,
            "subjects":[{"issuer":"https://soc-idp.example.test","subject":"reader","status":"active","permissions":permissions(&["read_cases","read_findings"],"a")}]});
        let result = Self {
            root,
            provider,
            host,
            findings,
            reference: references[0],
            foreign: references[1],
            signer,
            report,
        };
        result.write_report(&result.report)?;
        Ok(result)
    }
    fn subject(&self, name: Option<&str>) {
        *self.provider.subject.lock().unwrap() = name.map(str::to_owned);
    }
    fn write_report(&self, report: &Value) -> TestResult {
        let payload = serde_json::to_vec(report)?;
        let mut signed = eligibility::DOMAIN.to_vec();
        signed.extend_from_slice(&payload);
        fs::write(
            self.root.path().join("directory-report.json"),
            serde_json::to_vec(&json!({"schema_version":1,
            "payload_base64":STANDARD.encode(payload),"signature_base64":STANDARD.encode(self.signer.sign(&signed).as_ref())}))?,
        )?;
        Ok(())
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        value: Option<&Value>,
    ) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
        let body = value
            .map(|v| serde_json::to_vec(v).unwrap())
            .unwrap_or_default();
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer opaque")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))?;
        let response = self.host.router().oneshot(request).await?;
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }
    fn create(&self, case: Uuid) -> Value {
        json!({"schema_version":1,"operation_id":Uuid::new_v4(),"case_id":case,
        "expected_revision":0,"change":{"kind":"create","title":"private case title","references":[self.reference]},"note":"private create note"})
    }
    async fn finish(self) -> TestResult {
        self.host
            .stop(FindingContext::new(Duration::from_secs(5)))
            .await?;
        self.host
            .identity
            .shutdown(Instant::now() + Duration::from_secs(3))
            .await?;
        self.findings
            .shutdown(FindingContext::new(Duration::from_secs(3)))
            .await?;
        Ok(())
    }
    async fn reopen(self) -> Result<Self, Box<dyn std::error::Error>> {
        let Self {
            root,
            provider,
            host,
            findings,
            reference,
            foreign,
            signer,
            report,
        } = self;
        let namespace = host.namespace;
        let identity = host.identity.clone();
        let audit = host.audit.clone();
        let directory = host.directory.clone();
        let episodes = host.registry.episode_providers();
        host.stop(FindingContext::new(Duration::from_secs(5)))
            .await?;
        drop(host);
        findings
            .shutdown(FindingContext::new(Duration::from_secs(5)))
            .await?;
        drop(findings);
        let findings = Arc::new(
            FindingStore::open(
                FindingConfig {
                    directory: root.path().join("findings"),
                    ..Default::default()
                },
                reference.stream_id,
            )
            .await?,
        );
        // All router/request owners have retired; the actual file lock must be
        // reacquired and originals recovered by a newly opened production store.
        let store = Arc::new(
            CaseStore::open(
                signal_findings::cases::CaseConfig {
                    directory: root.path().join("cases"),
                    max_cases: 100,
                    max_operations: 1000,
                    ..Default::default()
                },
                namespace,
                FindingContext::new(Duration::from_secs(5)),
            )
            .await?,
        );
        let mut registry = reference::Registry::canonical(reference.stream_id, findings.clone())
            .map_err(|_| "registry")?;
        for provider in episodes {
            registry
                .enroll_episode(provider)
                .map_err(|_| "episode enrollment")?;
        }
        let host = Arc::new(Host {
            namespace,
            store,
            registry,
            directory,
            identity,
            audit,
            slots: Semaphore::new(4),
            capacity: 4,
            rejected: AtomicU64::new(0),
            timeout: Duration::from_secs(5),
            response_bytes: 1048576,
            stopping: CancellationToken::new(),
        });
        Ok(Self {
            root,
            provider,
            host,
            findings,
            reference,
            foreign,
            signer,
            report,
        })
    }
}

#[tokio::test]
async fn actual_identity_write_only_ack_retry_history_and_assignment_directory() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let create = fixture.create(id);
    let (status, ack) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    let mut keys = ack
        .as_object()
        .ok_or("ack object")?
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "case_id",
            "operation_id",
            "replayed",
            "result_revision",
            "schema_version"
        ]
    );
    assert_eq!(ack["result_revision"], 1);
    assert_eq!(ack["replayed"], false);
    assert_eq!(
        fixture
            .request("GET", &format!("/v1/cases/{id}"), None)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture.request("GET", "/v1/cases", None).await?.0,
        StatusCode::FORBIDDEN
    );
    let assignment = json!({"schema_version":1,"operation_id":Uuid::new_v4(),"case_id":id,"expected_revision":1,
        "change":{"kind":"assign","assignee":"recipient"},"note":"private assignment note"});
    let (status, assigned) = fixture
        .request(
            "POST",
            &format!("/v1/cases/{id}/assignment"),
            Some(&assignment),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{assigned}");
    assert_eq!(assigned["result_revision"], 2);
    assert!(!assigned.to_string().contains("private"));
    assert!(assigned.get("assignee").is_none());
    let (_, replay) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
    assert_eq!(replay["result_revision"], 1);
    assert_eq!(replay["replayed"], true);
    let mut conflict = assignment.clone();
    conflict["operation_id"] = json!(Uuid::new_v4());
    let (status, body) = fixture
        .request(
            "POST",
            &format!("/v1/cases/{id}/assignment"),
            Some(&conflict),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!body.to_string().contains("private"));
    assert!(body.get("head").is_none());
    fixture.subject(Some("reader"));
    let (status, head) = fixture
        .request("GET", &format!("/v1/cases/{id}"), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{head}");
    assert_eq!(head["revision"], 2);
    assert_eq!(head["assignee"], "recipient");
    let (_, history) = fixture
        .request("GET", &format!("/v1/cases/{id}/history?limit=1"), None)
        .await?;
    assert_eq!(history["records"].as_array().ok_or("records")?.len(), 1);
    assert_eq!(history["has_more"], true);
    assert_eq!(history["records"][0]["request"], create);
    let (_, list) = fixture.request("GET", "/v1/cases", None).await?;
    assert_eq!(list["cases"].as_array().ok_or("case list")?.len(), 1);
    assert!(list.get("total_count").is_none());
    assert_eq!(
        fixture
            .request("POST", "/v1/cases", Some(&fixture.create(Uuid::new_v4())))
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert!(
        fixture
            .provider
            .calls
            .load(std::sync::atomic::Ordering::Acquire)
            >= 18
    );
    fixture.finish().await
}

#[tokio::test]
async fn complete_reference_actor_and_target_denials_do_not_mutate_or_disclose() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let create = fixture.create(id);
    let mut mixed = create.clone();
    let mut refs = vec![fixture.reference, fixture.foreign];
    refs.sort_by_key(|r| (r.stream_id, r.finding_id));
    mixed["change"]["references"] = serde_json::to_value(refs)?;
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&mixed)).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(
            fixture.root.path().join("cases/cases.commit")
        )?)?["records"],
        0
    );
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
        StatusCode::OK
    );
    let assignment = json!({"schema_version":1,"operation_id":Uuid::new_v4(),"case_id":id,"expected_revision":1,
        "change":{"kind":"assign","assignee":"recipient"},"note":"sentinel private note"});
    let mut inactive = fixture.report.clone();
    inactive["subjects"][0]["status"] = json!("inactive");
    fixture.write_report(&inactive)?;
    assert!(
        !fixture
            .request(
                "POST",
                &format!("/v1/cases/{id}/assignment"),
                Some(&assignment)
            )
            .await?
            .0
            .is_success()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(
            fixture.root.path().join("cases/cases.commit")
        )?)?["records"],
        1
    );
    fixture.write_report(&fixture.report)?;
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/v1/cases/{id}/assignment"),
                Some(&assignment)
            )
            .await?
            .0,
        StatusCode::OK
    );
    fixture.write_report(&inactive)?;
    assert!(
        !fixture
            .request(
                "POST",
                &format!("/v1/cases/{id}/assignment"),
                Some(&assignment)
            )
            .await?
            .0
            .is_success()
    );
    fixture.subject(Some("foreign"));
    for method_path in [
        ("GET", format!("/v1/cases/{id}")),
        ("GET", format!("/v1/cases/{id}/history")),
    ] {
        let (status, body) = fixture.request(method_path.0, &method_path.1, None).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.to_string().contains("private"));
    }
    let (_, list) = fixture.request("GET", "/v1/cases", None).await?;
    assert_eq!(list["cases"], json!([]));
    fixture.subject(None);
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
        StatusCode::FORBIDDEN
    );
    fixture.finish().await
}

#[tokio::test]
async fn decision_and_completion_audit_barriers_recheck_identity_and_target() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    for (target_revocation, completion) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let pause = Arc::new(AuditPause {
            sequence: (if target_revocation { 3 } else { 1 }) + u64::from(completion),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let fixture = Fixture::with_pause(Some(pause.clone())).await?;
        let id = Uuid::new_v4();
        let create = fixture.create(id);
        let (path, intent) = if target_revocation {
            assert_eq!(
                fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
                StatusCode::OK
            );
            (
                format!("/v1/cases/{id}/assignment"),
                json!({"schema_version":1,"case_id":id,
                "operation_id":Uuid::new_v4(),"expected_revision":1,"change":{"kind":"assign","assignee":"recipient"},"note":"private note"}),
            )
        } else {
            ("/v1/cases".into(), create)
        };
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(&path)
            .header("authorization", "Bearer opaque")
            .body(axum::body::Body::from(serde_json::to_vec(&intent)?))?;
        // Only this owned task is submitted; cancellation/failed assertions abort it.
        let mut request = tokio::spawn(fixture.host.router().oneshot(request));
        let _abort = AbortTask(request.abort_handle());
        tokio::time::timeout(Duration::from_secs(3), pause.entered.notified()).await?;
        let witness: Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join("cases/cases.commit"))?)?;
        assert_eq!(
            witness["records"],
            u64::from(target_revocation) + u64::from(completion)
        );
        if target_revocation {
            let mut inactive = fixture.report.clone();
            inactive["subjects"][0]["status"] = json!("inactive");
            fixture.write_report(&inactive)?;
        } else {
            fixture.subject(None);
        }
        pause.release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(3), &mut request).await???;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 65536).await?;
        assert!(!String::from_utf8_lossy(&body).contains("private"));
        fixture.subject(Some("writer"));
        fixture.write_report(&fixture.report)?;
        let (status, replay) = fixture.request("POST", &path, Some(&intent)).await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], completion);
        assert_eq!(
            replay["result_revision"],
            if target_revocation { 2 } else { 1 }
        );
        fixture.finish().await?;
    }
    Ok(())
}

#[test]
fn startup_rejects_standard_and_missing_audit_without_disabling_canonical_publishers() -> TestResult
{
    let settings = crate::config::Settings::for_test(
        "schema_version: 1\ncases: {config: '/private/cases.json'}",
        &[],
    )?;
    Configuration::validate_runtime(&settings)?;
    assert!(Configuration::validate_audit(None).is_err());
    {
        let publisher = "SIGNAL_SHARED_CONFIG";
        let settings = crate::config::Settings::for_test(
            "schema_version: 1\ncases: {config: '/private/cases.json'}",
            &[(publisher, "/private/publisher.json")],
        )?;
        assert!(Configuration::validate_runtime(&settings).is_err());
    }
    for publisher in ["SIGNAL_WINDOW_CONFIG", "SIGNAL_SENSOR_HEALTH_CONFIG"] {
        let settings = crate::config::Settings::for_test(
            "schema_version: 1\ncases: {config: '/private/cases.json'}",
            &[(publisher, "/private/publisher.json")],
        )?;
        Configuration::validate_runtime(&settings)?;
    }
    Ok(())
}

#[tokio::test]
async fn signed_directory_rejects_wrong_bindings_status_time_scope_and_signature() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let create = fixture.create(id);
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
        StatusCode::OK
    );
    let assignment = json!({"schema_version":1,"operation_id":Uuid::new_v4(),"case_id":id,"expected_revision":1,
        "change":{"kind":"assign","assignee":"recipient"},"note":"private note sentinel"});
    let now = crate::access::now().ok_or("clock")?;
    let mut bad = Vec::new();
    for (key, value) in [
        ("schema_version", json!(2)),
        ("namespace", json!(Uuid::new_v4())),
        ("issuer", json!("foreign")),
        ("audience", json!("foreign")),
        ("key_revision", json!("key-v2")),
        ("policy_revision", json!("policy-v2")),
        ("directory_revision", json!("")),
        ("observed_at", json!(now + 30)),
        ("expires_at", json!(now)),
        ("expires_at", json!(now + 31)),
        ("subjects", json!([])),
    ] {
        let mut report = fixture.report.clone();
        report[key] = value;
        bad.push(report);
    }
    for (key, value) in [
        ("issuer", json!("foreign")),
        ("subject", json!("writer")),
        ("status", json!("inactive")),
        ("status", json!("unknown")),
        (
            "permissions",
            json!(permissions(&["read_cases", "read_findings"], "b")),
        ),
        (
            "permissions",
            json!(permissions(&["assign_cases", "read_findings"], "a")),
        ),
        ("permissions", json!(permissions(&["read_cases"], "a"))),
    ] {
        let mut report = fixture.report.clone();
        report["subjects"][0][key] = value;
        bad.push(report);
    }
    let mut duplicated = fixture.report.clone();
    duplicated["subjects"]
        .as_array_mut()
        .ok_or("subjects")?
        .push(fixture.report["subjects"][0].clone());
    bad.push(duplicated);
    for report in bad {
        fixture.write_report(&report)?;
        let (status, body) = fixture
            .request(
                "POST",
                &format!("/v1/cases/{id}/assignment"),
                Some(&assignment),
            )
            .await?;
        assert!(!status.is_success());
        assert!(!body.to_string().contains("private"));
        let witness: Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join("cases/cases.commit"))?)?;
        assert_eq!(witness["records"], 1);
    }
    fixture.write_report(&fixture.report)?;
    let path = fixture.root.path().join("directory-report.json");
    let mut wire: Value = serde_json::from_slice(&fs::read(&path)?)?;
    wire["signature_base64"] = json!(STANDARD.encode([0; 64]));
    fs::write(&path, serde_json::to_vec(&wire)?)?;
    assert!(
        !fixture
            .request(
                "POST",
                &format!("/v1/cases/{id}/assignment"),
                Some(&assignment)
            )
            .await?
            .0
            .is_success()
    );
    fixture.write_report(&fixture.report)?;
    let (status, ack) = fixture
        .request(
            "POST",
            &format!("/v1/cases/{id}/assignment"),
            Some(&assignment),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["result_revision"], 2);
    fixture.finish().await
}

#[tokio::test]
async fn native_store_reopen_preserves_http_original_intent_and_rejects_claim_fields() -> TestResult
{
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let create = fixture.create(id);
    for (key, value) in [
        ("actor", json!("forged")),
        ("authority", json!({})),
        ("scope", json!(scope("b"))),
    ] {
        let mut bad = create.clone();
        bad[key] = value;
        assert_eq!(
            fixture.request("POST", "/v1/cases", Some(&bad)).await?.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, original) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
    assert_eq!(original["replayed"], false);
    let fixture = fixture.reopen().await?;
    let (status, replay) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["result_revision"], 1);
    assert_eq!(replay["replayed"], true);
    fixture.subject(Some("reader"));
    let (_, history) = fixture
        .request("GET", &format!("/v1/cases/{id}/history"), None)
        .await?;
    assert_eq!(history["records"][0]["request"], create);
    assert_eq!(history["records"].as_array().ok_or("records")?.len(), 1);
    fixture.finish().await
}

#[tokio::test]
async fn retained_multi_event_canonical_provenance_survives_reopen_without_promoting_unknown_rows()
-> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let event = serde_json::from_value::<signal_event::IngestEvent>(json!({"timestamp":"2026-10-27T00:02:00Z",
        "source":{"type":"application"},"message":"canonical multi event","resource":{"kind":"service","id":"api","account_id":"a"}}))?
        .normalize("2026-10-27T00:03:00Z".parse()?)?;
    let mut second = event.clone();
    second.id = Uuid::new_v4();
    let mut derived = Finding::for_event(
        "synthetic-window",
        &event,
        signal_findings::DetectionSeverity::High,
        "canonical multi-event fixture",
    )?;
    derived.id = Uuid::new_v4();
    derived.event_ids = vec![event.id, second.id];
    fixture
        .findings
        .append_derived(
            vec![DerivedFinding::from_events(
                derived.clone(),
                &[&event, &second],
                true,
            )?],
            FindingContext::new(Duration::from_secs(5)),
        )
        .await?;
    let legacy = Finding::for_event(
        "legacy",
        &event,
        signal_findings::DetectionSeverity::High,
        "legacy unknown provenance",
    )?;
    fixture
        .findings
        .append(
            vec![legacy.clone()],
            FindingContext::new(Duration::from_secs(5)),
        )
        .await?;
    let fixture = fixture.reopen().await?;
    let mut create = fixture.create(Uuid::new_v4());
    create["change"]["references"][0]["finding_id"] = json!(derived.id);
    let (status, ack) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    let mut unknown = fixture.create(Uuid::new_v4());
    unknown["change"]["references"][0]["finding_id"] = json!(legacy.id);
    assert_eq!(
        fixture
            .request("POST", "/v1/cases", Some(&unknown))
            .await?
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    unknown["change"]["references"][0]["stream_id"] = json!(Uuid::new_v4());
    assert_eq!(
        fixture
            .request("POST", "/v1/cases", Some(&unknown))
            .await?
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.finish().await
}

#[tokio::test]
async fn evidence_navigation_needs_separate_grant_and_an_original_case_reference() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let create = fixture.create(id);
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
        StatusCode::OK
    );
    let path = format!(
        "/v1/cases/{id}/evidence/{}/{}",
        fixture.reference.stream_id, fixture.reference.finding_id
    );
    for subject in ["writer", "reader", "foreign"] {
        fixture.subject(Some(subject));
        let (status, body) = fixture.request("GET", &path, None).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.get("finding").is_none());
    }
    fixture.subject(Some("evidence"));
    let (status, body) = fixture.request("GET", &path, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["finding"]["id"], json!(fixture.reference.finding_id));
    let foreign = format!(
        "/v1/cases/{id}/evidence/{}/{}",
        fixture.foreign.stream_id, fixture.foreign.finding_id
    );
    assert_eq!(
        fixture.request("GET", &foreign, None).await?.0,
        StatusCode::FORBIDDEN
    );
    fixture.finish().await
}

#[tokio::test]
async fn admission_capacity_is_counted_and_shutdown_remains_visible() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let all = fixture.host.slots.acquire_many(4).await?;
    assert_eq!(fixture.host.metrics().request_depth, 4);
    let calls = fixture.provider.calls.load(Ordering::Acquire);
    assert_eq!(
        fixture
            .request("POST", "/v1/cases", Some(&fixture.create(Uuid::new_v4())))
            .await?
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(fixture.provider.calls.load(Ordering::Acquire), calls);
    assert_eq!(fixture.host.metrics().request_rejected, 1);
    drop(all);
    assert_eq!(fixture.host.metrics().request_depth, 0);
    assert_eq!(fixture.host.metrics().physical_capacity, 4);
    fixture.host.stop_admission();
    assert!(fixture.host.metrics().closed);
    fixture.finish().await
}

#[tokio::test]
async fn multi_reference_evidence_authorizes_selected_body_and_all_case_relationships() -> TestResult
{
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let mut create = fixture.create(id);
    let mut references = vec![fixture.reference, fixture.foreign];
    references.sort_by_key(|r| (r.stream_id, r.finding_id));
    create["change"]["references"] = serde_json::to_value(references)?;
    fixture.subject(Some("creator-ab"));
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
        StatusCode::OK
    );
    let a = format!(
        "/v1/cases/{id}/evidence/{}/{}",
        fixture.reference.stream_id, fixture.reference.finding_id
    );
    let b = format!(
        "/v1/cases/{id}/evidence/{}/{}",
        fixture.foreign.stream_id, fixture.foreign.finding_id
    );
    fixture.subject(Some("evidence-ab"));
    let (status, body) = fixture.request("GET", &a, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["finding"]["id"], json!(fixture.reference.finding_id));
    assert_eq!(
        fixture.request("GET", &b, None).await?.0,
        StatusCode::FORBIDDEN
    );
    for subject in ["evidence-missing-case", "evidence-missing-finding"] {
        fixture.subject(Some(subject));
        let (status, body) = fixture.request("GET", &a, None).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.get("finding").is_none());
    }
    fixture.finish().await
}

#[tokio::test]
async fn real_pipeline_exposes_case_capacity_and_refuses_readiness_after_case_shutdown()
-> TestResult {
    use signal_protocol::EventSink;
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let buffer = Arc::new(
        signal_buffer::DurableBuffer::open(signal_buffer::BufferConfig {
            directory: fixture.root.path().join("wal"),
            ..Default::default()
        })
        .await?,
    );
    let storage = Arc::new(crate::storage::Backend::local(
        signal_storage::ParquetStore::open(
            signal_storage::StorageConfig {
                directory: fixture.root.path().join("events"),
                ..Default::default()
            },
            buffer.snapshot().stream_id,
        )
        .await?,
    ));
    let pipeline = Arc::new(crate::pipeline::PipelineSink {
        cases: Some(fixture.host.clone()),
        audit: None,
        buffer: buffer.clone(),
        store: storage.clone(),
        query: None,
        detection: None,
        logging: None,
        coverage: None,
    });
    let service = signal_ingest::IngestService::new(IngestConfig::default(), pipeline.clone())?;
    let request = |path: &str| {
        axum::http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
    };
    assert_eq!(
        service
            .metrics_router()
            .oneshot(request("/readyz")?)
            .await?
            .status(),
        StatusCode::OK
    );
    let all = fixture.host.slots.acquire_many(4).await?;
    let response = service
        .metrics_router()
        .oneshot(request("/metrics")?)
        .await?;
    let text = String::from_utf8(to_bytes(response.into_body(), 1048576).await?.to_vec())?;
    assert!(text.contains("signal_cases_request_depth 4\n"));
    assert!(text.contains("signal_cases_request_capacity 4\n"));
    assert!(text.contains("signal_cases_physical_capacity 4\n"));
    assert!(text.contains("signal_cases_shared_file_capacity 1\n"));
    assert!(!text.contains(&fixture.host.namespace.to_string()));
    drop(all);
    fixture.host.stop_admission();
    assert_eq!(
        service
            .metrics_router()
            .oneshot(request("/readyz")?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(pipeline.metrics().closed);
    let event = serde_json::from_value::<signal_event::IngestEvent>(json!({"timestamp":"2026-10-27T00:00:00Z","source":{"type":"application"},"message":"stopped"}))?.normalize("2026-10-27T00:01:00Z".parse()?)?;
    assert!(matches!(
        pipeline.admit(event).await,
        Err(signal_protocol::AdmissionError::Closed)
    ));
    service.stop_admission();
    storage
        .shutdown(signal_storage::OperationContext::new(Duration::from_secs(
            5,
        )))
        .await?;
    buffer.shutdown().await?;
    fixture.finish().await
}

#[tokio::test]
async fn recipient_eligibility_independently_requires_every_original_scope() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let fixture = Fixture::new().await?;
    let id = Uuid::new_v4();
    let mut create = fixture.create(id);
    let mut references = vec![fixture.reference, fixture.foreign];
    references.sort_by_key(|r| (r.stream_id, r.finding_id));
    create["change"]["references"] = serde_json::to_value(references)?;
    fixture.subject(Some("creator-ab"));
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
        StatusCode::OK
    );
    let assignment = json!({"schema_version":1,"operation_id":Uuid::new_v4(),"case_id":id,"expected_revision":1,
        "change":{"kind":"assign","assignee":"recipient"},"note":null});
    let path = format!("/v1/cases/{id}/assignment");
    fixture.subject(Some("assigner-ab"));
    assert!(
        !fixture
            .request("POST", &path, Some(&assignment))
            .await?
            .0
            .is_success()
    );
    let mut full = fixture.report.clone();
    full["subjects"][0]["permissions"] = json!(
        [
            permissions(&["read_cases", "read_findings"], "a"),
            permissions(&["read_cases", "read_findings"], "b")
        ]
        .concat()
    );
    fixture.write_report(&full)?;
    let (status, ack) = fixture.request("POST", &path, Some(&assignment)).await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["result_revision"], 2);
    fixture.subject(Some("writer"));
    assert_eq!(
        fixture.request("POST", &path, Some(&assignment)).await?.0,
        StatusCode::FORBIDDEN
    );
    fixture.subject(Some("assigner-ab"));
    fixture.write_report(&fixture.report)?;
    assert!(
        !fixture
            .request("POST", &path, Some(&assignment))
            .await?
            .0
            .is_success()
    );
    fixture.finish().await
}

#[tokio::test]
async fn real_d11_d14_episode_originals_authorize_all_contributors_after_prune_and_reopen()
-> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    for detector in [
        episode_fixture::Detector::D11,
        episode_fixture::Detector::D14,
    ] {
        let mut fixture = Fixture::new().await?;
        let bundle = episode_fixture::Bundle::build(&fixture, detector).await?;
        bundle.enroll(&mut fixture)?;
        let id = Uuid::new_v4();
        let mut create = fixture.create(id);
        create["change"]["references"] = json!([bundle.reference]);
        fixture.subject(Some("episode-runtime-only"));
        assert_eq!(
            fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
            StatusCode::FORBIDDEN
        );
        fixture.subject(Some("episode-auth-only"));
        assert_eq!(
            fixture.request("POST", "/v1/cases", Some(&create)).await?.0,
            StatusCode::FORBIDDEN
        );
        fixture.subject(Some("episode-admin"));
        let (status, ack) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
        assert_eq!(status, StatusCode::OK, "{ack}");
        assert_eq!(ack["result_revision"], 1);
        let path = format!(
            "/v1/cases/{id}/evidence/{}/{}",
            bundle.reference.stream_id, bundle.reference.finding_id
        );
        let (status, evidence) = fixture.request("GET", &path, None).await?;
        assert_eq!(status, StatusCode::OK, "{evidence}");
        assert_eq!(
            evidence["finding"],
            serde_json::to_value(bundle.episode.finding.as_ref().ok_or("finding")?)?
        );
        assert_eq!(evidence["episode"], serde_json::to_value(&bundle.episode)?);
        let fixture = fixture.reopen().await?;
        let (status, replay) = fixture.request("POST", "/v1/cases", Some(&create)).await?;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay["replayed"], true);
        fixture.subject(Some("episode-runtime-only"));
        assert_eq!(
            fixture.request("GET", &path, None).await?.0,
            StatusCode::FORBIDDEN
        );
        fixture.subject(Some("episode-admin"));
        let assignment = json!({"schema_version":1,"case_id":id,"operation_id":Uuid::new_v4(),"expected_revision":1,
            "change":{"kind":"assign","assignee":"recipient"},"note":null});
        assert!(
            !fixture
                .request(
                    "POST",
                    &format!("/v1/cases/{id}/assignment"),
                    Some(&assignment)
                )
                .await?
                .0
                .is_success()
        );
        let mut recipient = fixture.report.clone();
        let all =
            json!({"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}});
        recipient["subjects"][0]["permissions"] = json!([{"operation":"read_cases","scope":all},{"operation":"read_findings","scope":all}]);
        fixture.write_report(&recipient)?;
        let (status, ack) = fixture
            .request(
                "POST",
                &format!("/v1/cases/{id}/assignment"),
                Some(&assignment),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{ack}");
        assert_eq!(ack["result_revision"], 2);
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn signed_complete_claim_cannot_hide_partial_duplicate_or_conflicting_dual_indexes()
-> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    for edit in [
        "partial_canonical",
        "partial_native",
        "duplicate_native",
        "conflicting_native",
    ] {
        let mut fixture = Fixture::new().await?;
        let bundle = episode_fixture::Bundle::build_index(
            &fixture,
            episode_fixture::Detector::D14,
            Some(edit),
        )
        .await?;
        bundle.enroll(&mut fixture)?;
        fixture.subject(Some("episode-admin"));
        let mut request = fixture.create(Uuid::new_v4());
        request["change"]["references"] = json!([bundle.reference]);
        let (status, body) = fixture.request("POST", "/v1/cases", Some(&request)).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{edit}: {body}");
        assert!(!body.to_string().contains("private"));
        let commit: Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join("cases/cases.commit"))?)?;
        assert_eq!(commit["records"], 0);
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn episode_observer_cannot_substitute_publication_originals_inventory_or_enrollment()
-> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await?;
    let bundle = episode_fixture::Bundle::build(&fixture, episode_fixture::Detector::D14).await?;
    bundle.enroll(&mut fixture)?;
    fixture.subject(Some("episode-admin"));
    let mut request = fixture.create(Uuid::new_v4());
    request["change"]["references"] = json!([bundle.reference]);
    let now = crate::access::now().ok_or("clock")?;
    let mut bad = Vec::new();
    for (key, value) in [
        ("schema_version", json!(2)),
        ("namespace", json!(Uuid::new_v4())),
        ("observer_issuer", json!("foreign")),
        ("audience", json!("foreign")),
        ("key_revision", json!("foreign")),
        ("provider_enrollment_sha256", json!(vec![77; 32])),
        ("observed_at", json!(now + 30)),
        ("expires_at", json!(now)),
        ("protected_originals", json!(false)),
        ("complete_cumulative_indexes", json!(false)),
        ("original_enrollment_sha256", json!(vec![77; 32])),
        ("original_journal_binding", json!(vec![77; 32])),
        ("original_authority_keys_sha256", json!(vec![77; 32])),
    ] {
        let mut report = bundle.report.clone();
        report[key] = value;
        bad.push(report);
    }
    let mut incomplete = bundle.episode.clone();
    incomplete
        .contributors
        .retain(|c| c.source_type == "runtime");
    let mut report = bundle.report.clone();
    report["contributors_sha256"] =
        json!(episode::contributors_digest(&incomplete).map_err(|_| "digest")?);
    bad.push(report);
    let mut effect = bundle.report.clone();
    effect["effect"]["id"] = json!(bundle.reference.finding_id);
    bad.push(effect);
    let mut finding = bundle.episode.finding.clone().ok_or("finding")?;
    finding.title = "forged original finding".into();
    bad.push(bundle.replace_publication_finding(&finding)?);
    for report in bad {
        bundle.write_report(&report)?;
        let (status, body) = fixture.request("POST", "/v1/cases", Some(&request)).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(body.get("finding").is_none());
        let commit: Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join("cases/cases.commit"))?)?;
        assert_eq!(commit["records"], 0);
    }
    bundle.write_report_domain(&bundle.report, eligibility::DOMAIN)?;
    assert_eq!(
        fixture
            .request("POST", "/v1/cases", Some(&request))
            .await?
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    bundle.write_report(&bundle.report)?;
    let (status, ack) = fixture.request("POST", "/v1/cases", Some(&request)).await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    fixture.finish().await
}

#[tokio::test]
async fn episode_custody_loss_during_decision_or_completion_audit_withholds_success() -> TestResult
{
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    for completion in [false, true] {
        let pause = Arc::new(AuditPause {
            sequence: if completion { 2 } else { 1 },
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let mut fixture = Fixture::with_pause(Some(pause.clone())).await?;
        let bundle =
            episode_fixture::Bundle::build(&fixture, episode_fixture::Detector::D14).await?;
        bundle.enroll(&mut fixture)?;
        fixture.subject(Some("episode-admin"));
        let mut intent = fixture.create(Uuid::new_v4());
        intent["change"]["references"] = json!([bundle.reference]);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/cases")
            .header("authorization", "Bearer opaque")
            .body(axum::body::Body::from(serde_json::to_vec(&intent)?))?;
        let mut request = tokio::spawn(fixture.host.router().oneshot(request));
        let _abort = AbortTask(request.abort_handle());
        tokio::time::timeout(Duration::from_secs(3), pause.entered.notified()).await?;
        let mut unavailable = bundle.report.clone();
        unavailable["complete_cumulative_indexes"] = json!(false);
        bundle.write_report(&unavailable)?;
        pause.release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(3), &mut request).await???;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let commit: Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join("cases/cases.commit"))?)?;
        assert_eq!(commit["records"], u64::from(completion));
        bundle.write_report(&bundle.report)?;
        let (status, ack) = fixture.request("POST", "/v1/cases", Some(&intent)).await?;
        assert_eq!(status, StatusCode::OK, "{ack}");
        assert_eq!(ack["replayed"], completion);
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn episode_key_policy_carry_keeps_original_scopes_and_exact_case_receipts() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await?;
    let mut bundle =
        episode_fixture::Bundle::build(&fixture, episode_fixture::Detector::D14).await?;
    bundle.enroll(&mut fixture)?;
    fixture.subject(Some("episode-admin"));
    let id = Uuid::new_v4();
    let mut intent = fixture.create(id);
    intent["change"]["references"] = json!([bundle.reference]);
    let (status, ack) = fixture.request("POST", "/v1/cases", Some(&intent)).await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    bundle.carry_runtime().await?;
    let fixture = fixture.reopen().await?;
    let (status, replay) = fixture.request("POST", "/v1/cases", Some(&intent)).await?;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["result_revision"], 1);
    assert_eq!(replay["replayed"], true);
    let path = format!(
        "/v1/cases/{id}/evidence/{}/{}",
        bundle.reference.stream_id, bundle.reference.finding_id
    );
    let (status, evidence) = fixture.request("GET", &path, None).await?;
    assert_eq!(status, StatusCode::OK, "{evidence}");
    assert_eq!(evidence["episode"], serde_json::to_value(&bundle.episode)?);
    fixture.subject(Some("episode-new-policy"));
    assert_eq!(
        fixture.request("GET", &path, None).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&intent)).await?.0,
        StatusCode::FORBIDDEN
    );
    fixture.subject(Some("episode-admin"));
    let mut missing_ancestor = bundle.report.clone();
    missing_ancestor["archives"]
        .as_array_mut()
        .ok_or("archives")?
        .remove(0);
    bundle.write_report(&missing_ancestor)?;
    assert_eq!(
        fixture.request("GET", &path, None).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    bundle.write_report(&bundle.report)?;
    assert_eq!(fixture.request("GET", &path, None).await?.0, StatusCode::OK);
    fixture.finish().await
}

#[tokio::test]
async fn refreshed_episode_report_cannot_renew_the_original_request_custody_lease() -> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let pause = Arc::new(AuditPause {
        sequence: 1,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let mut fixture = Fixture::with_pause(Some(pause.clone())).await?;
    let bundle = episode_fixture::Bundle::build(&fixture, episode_fixture::Detector::D14).await?;
    bundle.enroll(&mut fixture)?;
    fixture.subject(Some("episode-admin"));
    let mut intent = fixture.create(Uuid::new_v4());
    intent["change"]["references"] = json!([bundle.reference]);
    let observed = crate::access::now().ok_or("clock")?;
    let expires = observed + 2;
    let mut short = bundle.report.clone();
    short["observed_at"] = json!(observed);
    short["expires_at"] = json!(expires);
    bundle.write_report(&short)?;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/cases")
        .header("authorization", "Bearer opaque")
        .body(axum::body::Body::from(serde_json::to_vec(&intent)?))?;
    let mut request = tokio::spawn(fixture.host.router().oneshot(request));
    let _abort = AbortTask(request.abort_handle());
    tokio::time::timeout(Duration::from_secs(3), pause.entered.notified()).await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        while crate::access::now().is_some_and(|now| now < expires) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let now = crate::access::now().ok_or("clock")?;
    let mut renewed = bundle.report.clone();
    renewed["observed_at"] = json!(now);
    renewed["expires_at"] = json!(now + 30);
    bundle.write_report(&renewed)?;
    pause.release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(3), &mut request).await???;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let witness: Value =
        serde_json::from_slice(&fs::read(fixture.root.path().join("cases/cases.commit"))?)?;
    assert_eq!(witness["records"], 0);
    let (status, ack) = fixture.request("POST", "/v1/cases", Some(&intent)).await?;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["replayed"], false);
    fixture.finish().await
}

#[tokio::test]
async fn provider_kind_enrollment_refuses_shadowing_and_failed_custody_never_falls_back()
-> TestResult {
    let _audit = crate::audit::tests::SERIAL.lock().await;
    let _reader = crate::config::FILE_WORKER_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await?;
    let bundle = episode_fixture::Bundle::build(&fixture, episode_fixture::Detector::D14).await?;
    let mut shadow = bundle.configuration.clone();
    shadow["stream_id"] = json!(fixture.reference.stream_id);
    let provider = episode::Provider::new(serde_json::from_value(shadow)?, fixture.host.namespace)
        .map_err(|_| "provider")?;
    assert!(matches!(
        Arc::get_mut(&mut fixture.host)
            .ok_or("host")?
            .registry
            .enroll_episode(provider),
        Err(Failure::Invalid)
    ));
    bundle.enroll(&mut fixture)?;
    let canonical = bundle.episode.finding.clone().ok_or("finding")?;
    let originals = bundle.episode.originals.iter().collect::<Vec<_>>();
    fixture
        .findings
        .append_derived(
            vec![DerivedFinding::from_events(canonical, &originals, true)?],
            FindingContext::new(Duration::from_secs(5)),
        )
        .await?;
    let mut unavailable = bundle.report.clone();
    unavailable["complete_cumulative_indexes"] = json!(false);
    bundle.write_report(&unavailable)?;
    fixture.subject(Some("episode-admin"));
    let mut intent = fixture.create(Uuid::new_v4());
    intent["change"]["references"] = json!([bundle.reference]);
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&intent)).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    bundle.write_report(&bundle.report)?;
    assert_eq!(
        fixture.request("POST", "/v1/cases", Some(&intent)).await?.0,
        StatusCode::OK
    );
    fixture.finish().await
}

#![cfg(feature = "aws-source")]
use serde_json::{Value, json};
use signal_collector_sdk::{
    ExtensionContext,
    coverage::{CoverageProfile, CoverageReason, CoverageStatus, cloudtrail::*, observer::*},
    receipt::{AwsCredentialsProvider, SigningCredentials, SourceFailure},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;
#[path = "../../../tests/support/aws_signature.rs"]
mod signature;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ARN: &str = "arn:aws:cloudtrail:eu-central-1:111122223333:trail/laboratory";
const ACCESS_A: &str = "AKIASYNTHETIC0001";
const ACCESS_B: &str = "AKIASYNTHETIC0002";
const SECRET: &str = "synthetic-signing-secret-never-use-in-aws";
struct Credentials {
    calls: AtomicUsize,
    deny: bool,
}
#[signal_collector_sdk::extension]
impl AwsCredentialsProvider for Credentials {
    async fn credentials(&self, _: &ExtensionContext) -> Result<SigningCredentials, SourceFailure> {
        let n = self.calls.fetch_add(1, Ordering::AcqRel);
        if self.deny {
            return Err(SourceFailure::Denied);
        }
        SigningCredentials::new(
            if n == 0 { ACCESS_A } else { ACCESS_B },
            SECRET,
            Some("synthetic-session-token"),
            None,
        )
    }
}
fn credentials(deny: bool) -> Arc<Credentials> {
    Arc::new(Credentials {
        calls: AtomicUsize::new(0),
        deny,
    })
}
struct Wire {
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct Endpoint {
    url: String,
    task: Option<tokio::task::JoinHandle<Result<Vec<Wire>, &'static str>>>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Endpoint {
    async fn start(replies: Vec<Vec<u8>>, stall: bool) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let mut captured = Vec::new();
            for reply in replies {
                let (mut socket, _) = listener.accept().await.map_err(|_| "accept")?;
                let mut raw = Vec::new();
                let header_end = loop {
                    let mut byte = [0u8; 1];
                    socket.read_exact(&mut byte).await.map_err(|_| "header")?;
                    raw.push(byte[0]);
                    if raw.len() > 32768 {
                        return Err("header cap");
                    }
                    if raw.ends_with(b"\r\n\r\n") {
                        break raw.len();
                    }
                };
                let text = std::str::from_utf8(&raw[..header_end]).map_err(|_| "header utf8")?;
                let mut lines = text.lines();
                if lines.next() != Some("POST / HTTP/1.1") {
                    return Err("request line");
                }
                let headers: BTreeMap<_, _> = lines
                    .filter_map(|s| s.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().into()))
                    .collect();
                let n = headers
                    .get("content-length")
                    .and_then(|v: &String| v.parse::<usize>().ok())
                    .filter(|n| *n <= 32768)
                    .ok_or("body cap")?;
                let mut body = vec![0; n];
                socket.read_exact(&mut body).await.map_err(|_| "body")?;
                captured.push(Wire { headers, body });
                let _ = socket.write_all(&reply).await;
                if stall {
                    std::future::pending::<()>().await;
                }
                let _ = socket.shutdown().await;
            }
            Ok(captured)
        });
        Ok(Self {
            url,
            task: Some(task),
        })
    }
    async fn finish(mut self) -> TestResult<Vec<Wire>> {
        let mut task = self.task.take().ok_or("task")?;
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(v) => v?.map_err(Into::into),
            Err(error) => {
                task.abort();
                let _ = task.await;
                Err(error.into())
            }
        }
    }
}
fn reply(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}
fn native() -> [Value; 3] {
    [
        json!({"Trail":{"TrailARN":ARN,"HomeRegion":"eu-central-1","S3BucketName":"laboratory-evidence","S3KeyPrefix":"audit","IsMultiRegionTrail":true,"IncludeGlobalServiceEvents":true,"IsOrganizationTrail":true,"LogFileValidationEnabled":true}}),
        json!({"IsLogging":true,"LatestDeliveryTime":1791331470.0}),
        json!({"TrailARN":ARN,"EventSelectors":[{"IncludeManagementEvents":true,"ReadWriteType":"All","ExcludeManagementEventSources":[],"DataResources":[]}]}),
    ]
}
fn encode(v: &Value) -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(v)?)
}
fn replies(v: &[Value; 3]) -> TestResult<Vec<Vec<u8>>> {
    v.iter()
        .map(|v| encode(v).map(|b| reply(200, &b)))
        .collect()
}
fn setup(endpoint: &str) -> TestResult<(Value, Value, CoverageProfile)> {
    let f: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/source-coverage/contract.json"
    ))?;
    let mut context = f["assessment_cases"][0]["context"].clone();
    context["binding"]["resource_scope"] =
        json!({"kind":"aws.cloudtrail.trail","id":ARN,"attributes":{"region":"eu-central-1"}});
    context["binding"]["expected_stream"] = "aws.cloudtrail.management.all".into();
    let config = json!({"schema_version":1,"trail_arn":ARN,"observed_region":"eu-central-1","endpoint":endpoint,"allow_loopback_http":true,
        "expected_bucket":"laboratory-evidence","expected_prefix":"audit","management_read_write":"All","require_multi_region":true,
        "require_global_events":true,"require_organization":true,"require_digest_delivery":true});
    Ok((
        context,
        config,
        CoverageProfile::parse(&encode(&f["profiles"][0])?)?,
    ))
}
fn probe(
    config: &Value,
    context: &Value,
    c: Arc<Credentials>,
) -> TestResult<CloudTrailConfigurationProbe> {
    Ok(CloudTrailConfigurationProbe::new(
        CloudTrailProbeConfig::parse(&encode(config)?, &encode(context)?)?,
        c,
        Duration::from_secs(1),
    )?)
}
fn ctx() -> TestResult<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(5),
    )?)
}
fn verify(wires: &[Wire]) -> TestResult {
    for (i, wire) in wires.iter().enumerate() {
        assert!(signature::verify(
            "POST",
            "/",
            &wire.headers,
            &wire.body,
            if i == 0 { ACCESS_A } else { ACCESS_B },
            SECRET,
            "cloudtrail",
            "eu-central-1"
        ));
        assert_eq!(
            wire.headers.get("content-type").map(String::as_str),
            Some("application/x-amz-json-1.1")
        );
        let action = ["GetTrail", "GetTrailStatus", "GetEventSelectors"][i];
        assert_eq!(
            wire.headers.get("x-amz-target").map(String::as_str),
            Some(
                format!("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{action}").as_str()
            )
        );
        let body: Value = serde_json::from_slice(&wire.body)?;
        assert_eq!(body, json!({if i==2 {"TrailName"} else {"Name"}: ARN}));
    }
    Ok(())
}
#[tokio::test]
async fn signed_configuration_is_independent_but_quiet_continuity_remains_unknown() -> TestResult {
    let endpoint = Endpoint::start(replies(&native())?, false).await?;
    let (mut current, config, profile) = setup(&endpoint.url)?;
    let c = credentials(false);
    let probe = probe(&config, &current, c.clone())?;
    let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
    let result = observer.poll(&probe, &encode(&current)?, &ctx()?).await?;
    assert_eq!(result.assessment().status(), CoverageStatus::Unknown);
    assert_eq!(observer.health(), ObserverHealth::Healthy);
    let report: Value = serde_json::from_slice(observer.latest_bytes().ok_or("report")?)?;
    assert_eq!(
        report["validation"],
        json!({"configuration":"verified","scope":"verified","continuity":"unknown","source_integrity":"unknown"})
    );
    assert!(report["last_observed_at"].is_null());
    assert!(report["checkpoint"].is_null());
    assert_eq!(
        report["gap_summary"],
        json!({"total":null,"truncated":true})
    );
    assert_eq!(
        report["provenance"]["proof_refs"]
            .as_array()
            .ok_or("proofs")?
            .len(),
        3
    );
    current["at"] = "2026-10-07T00:06:30Z".into();
    assert_eq!(
        observer.assess(&encode(&current)?)?.reason_codes(),
        &[CoverageReason::Expired]
    );
    assert_eq!(c.calls.load(Ordering::Acquire), 3);
    verify(&endpoint.finish().await?)?;
    Ok(())
}
#[test]
fn trusted_config_scope_and_endpoint_fail_before_credentials() -> TestResult {
    let (current, config, _) = setup("http://127.0.0.1:1")?;
    for (key, value) in [
        ("schema_version", json!(2)),
        (
            "trail_arn",
            json!("arn:aws:cloudtrail:eu-central-1:111122223333:trail/../bad"),
        ),
        ("endpoint", json!("http://example.invalid/")),
        ("endpoint", json!("https://example.invalid/path")),
        ("management_read_write", json!("DataEvents")),
        ("expected_bucket", json!("bad/bucket")),
        ("unexpected", json!(true)),
    ] {
        let mut bad = config.clone();
        bad[key] = value;
        assert!(CloudTrailProbeConfig::parse(&encode(&bad)?, &encode(&current)?).is_err());
    }
    let mut bad = current.clone();
    bad["binding"]["resource_scope"]["attributes"]["region"] = "us-east-1".into();
    assert!(matches!(
        CloudTrailProbeConfig::parse(&encode(&config)?, &encode(&bad)?),
        Err(ProbeFailure::Denied)
    ));
    let mut bad = config;
    bad["allow_loopback_http"] = false.into();
    assert!(CloudTrailProbeConfig::parse(&encode(&bad)?, &encode(&current)?).is_err());
    Ok(())
}
#[tokio::test]
async fn disabled_destination_and_scope_changes_are_failed_checks() -> TestResult {
    for (index, key, value) in [
        (1, "IsLogging", json!(false)),
        (0, "S3BucketName", json!("foreign-evidence")),
        (0, "S3KeyPrefix", json!("other")),
        (0, "LogFileValidationEnabled", json!(false)),
        (0, "IsMultiRegionTrail", json!(false)),
        (0, "IncludeGlobalServiceEvents", json!(false)),
        (0, "IsOrganizationTrail", json!(false)),
    ] {
        let mut observations = native();
        let target = if index == 0 {
            &mut observations[0]["Trail"]
        } else {
            &mut observations[1]
        };
        target[key] = value;
        let endpoint = Endpoint::start(replies(&observations)?, false).await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let probe = probe(&config, &current, credentials(false))?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        assert_eq!(
            observer
                .poll(&probe, &encode(&current)?, &ctx()?)
                .await?
                .assessment()
                .status(),
            CoverageStatus::Failed
        );
        assert_eq!(observer.health(), ObserverHealth::Healthy);
        verify(&endpoint.finish().await?)?;
    }
    Ok(())
}
#[tokio::test]
async fn selectors_do_not_invent_management_or_advanced_coverage() -> TestResult {
    for (selection, expected) in [
        (json!({"EventSelectors":[{}]}), "verified"),
        (
            json!({"EventSelectors":[{"ReadWriteType":"ReadOnly"},{"ReadWriteType":"WriteOnly"}]}),
            "verified",
        ),
        (
            json!({"EventSelectors":[{"DataResources":[{}, {"Type":"AWS::S3::Object"}, {"Values":["arn:aws:s3"]}]}]}),
            "verified",
        ),
        (
            json!({"EventSelectors":[{"IncludeManagementEvents":false,"ReadWriteType":"All"}]}),
            "failed",
        ),
        (
            json!({"EventSelectors":[{"IncludeManagementEvents":true,"ReadWriteType":"ReadOnly"}]}),
            "failed",
        ),
        (
            json!({"EventSelectors":[{"IncludeManagementEvents":true,"ReadWriteType":"All","ExcludeManagementEventSources":["kms.amazonaws.com"]}]}),
            "failed",
        ),
        (
            json!({"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]}]}),
            "unsupported",
        ),
        (
            json!({"EventSelectors":[],"NextToken":"future-pagination"}),
            "unsupported",
        ),
        (
            json!({"EventSelectors":[{"IncludeManagementEvents":true,"ReadWriteType":"All","FutureFilter":true}]}),
            "unsupported",
        ),
    ] {
        let mut observations = native();
        observations[2] = selection;
        observations[2]["TrailARN"] = ARN.into();
        let endpoint = Endpoint::start(replies(&observations)?, false).await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let probe = probe(&config, &current, credentials(false))?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        observer.poll(&probe, &encode(&current)?, &ctx()?).await?;
        let report: Value = serde_json::from_slice(observer.latest_bytes().ok_or("report")?)?;
        assert_eq!(report["validation"]["scope"], expected);
        assert_ne!(report["validation_status"], "verified");
        verify(&endpoint.finish().await?)?;
    }
    Ok(())
}
#[tokio::test]
async fn malformed_optional_selector_fields_cannot_verify_scope() -> TestResult {
    for (key, bad) in [
        ("DataResources", Value::Null),
        ("DataResources", json!("bad")),
        ("DataResources", json!([{"Type":1,"Values":{}}])),
        (
            "DataResources",
            json!([{"Type":"AWS::S3::Object","Values":[null]}]),
        ),
        ("ExcludeManagementEventSources", json!([1])),
        ("ExcludeManagementEventSources", json!([null])),
    ] {
        let mut observations = native();
        observations[2]["EventSelectors"][0][key] = bad;
        let endpoint = Endpoint::start(replies(&observations)?, false).await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let probe = probe(&config, &current, credentials(false))?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        assert!(matches!(
            observer.poll(&probe, &encode(&current)?, &ctx()?).await,
            Err(ObserverError::Probe(ProbeFailure::Malformed))
        ));
        assert!(observer.latest_bytes().is_none());
        assert_eq!(observer.health(), ObserverHealth::Unhealthy);
        verify(&endpoint.finish().await?)?;
    }
    Ok(())
}
#[tokio::test]
async fn foreign_and_malformed_native_observations_do_not_become_reports() -> TestResult {
    for (index, key, value, denied) in [
        (
            0,
            "TrailARN",
            json!("arn:aws:cloudtrail:eu-central-1:999900001111:trail/foreign"),
            true,
        ),
        (0, "HomeRegion", Value::Null, false),
        (1, "IsLogging", json!("true"), false),
        (2, "TrailARN", json!("foreign"), true),
        (2, "EventSelectors", json!({}), false),
    ] {
        let mut observations = native();
        let target = if index == 0 {
            &mut observations[0]["Trail"]
        } else {
            &mut observations[index]
        };
        target[key] = value;
        let endpoint = Endpoint::start(replies(&observations)?, false).await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let probe = probe(&config, &current, credentials(false))?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        let error = observer
            .poll(&probe, &encode(&current)?, &ctx()?)
            .await
            .err()
            .ok_or("error")?;
        assert!(matches!(
            (denied, error),
            (true, ObserverError::Probe(ProbeFailure::Denied))
                | (false, ObserverError::Probe(ProbeFailure::Malformed))
        ));
        assert!(observer.latest_bytes().is_none());
        assert_eq!(observer.health(), ObserverHealth::Unhealthy);
        verify(&endpoint.finish().await?)?;
    }
    Ok(())
}
#[tokio::test]
async fn denied_throttled_outage_error_envelopes_and_duplicate_keys_are_not_success() -> TestResult
{
    for (status, body, expected) in [
        (403, b"{}".as_slice(), ProbeFailure::Denied),
        (429, b"{}", ProbeFailure::Throttled),
        (
            400,
            b"{\"__type\":\"ThrottlingException\"}",
            ProbeFailure::Throttled,
        ),
        (503, b"{}", ProbeFailure::Unavailable),
        (
            200,
            b"{\"__type\":\"AccessDeniedException\"}",
            ProbeFailure::Malformed,
        ),
        (200, b"{\"Trail\":{},\"Trail\":{}}", ProbeFailure::Malformed),
        (200, b"null", ProbeFailure::Malformed),
    ] {
        let endpoint = Endpoint::start(vec![reply(status, body)], false).await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let c = credentials(false);
        let probe = probe(&config, &current, c.clone())?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        assert!(
            matches!(observer.poll(&probe,&encode(&current)?,&ctx()?).await,Err(ObserverError::Probe(e)) if e==expected)
        );
        assert!(observer.latest_bytes().is_none());
        assert_eq!(c.calls.load(Ordering::Acquire), 1);
        verify(&endpoint.finish().await?)?;
    }
    Ok(())
}
#[tokio::test]
async fn actual_declared_and_chunked_response_caps_hold_before_report() -> TestResult {
    let body = vec![b' '; 65537];
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n"
            .to_vec();
    chunked.extend_from_slice(&body);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    for response in [reply(200, &body), chunked] {
        let endpoint = Endpoint::start(vec![response], false).await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let probe = probe(&config, &current, credentials(false))?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        assert!(matches!(
            observer.poll(&probe, &encode(&current)?, &ctx()?).await,
            Err(ObserverError::Probe(ProbeFailure::Malformed))
        ));
        assert!(observer.latest_bytes().is_none());
        verify(&endpoint.finish().await?)?;
    }
    Ok(())
}
#[tokio::test]
async fn stalled_body_cancellation_and_deadline_leave_no_coverage() -> TestResult {
    for cancel in [false, true] {
        let endpoint = Endpoint::start(
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n".to_vec()],
            true,
        )
        .await?;
        let (current, config, profile) = setup(&endpoint.url)?;
        let probe = probe(&config, &current, credentials(false))?;
        let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
        let operation = ExtensionContext::new(
            CancellationToken::new(),
            Duration::from_millis(if cancel { 5000 } else { 30 }),
        )?;
        let token = operation.cancellation().clone();
        let bytes = encode(&current)?;
        {
            let work = observer.poll(&probe, &bytes, &operation);
            tokio::pin!(work);
            if cancel {
                tokio::select! { result=&mut work=>return Err(format!("early result: {}",result.is_ok()).into()), _=tokio::time::sleep(Duration::from_millis(30))=>{} }
                token.cancel();
            }
            assert!(work.await.is_err());
        }
        assert!(observer.latest_bytes().is_none());
        assert_eq!(observer.health(), ObserverHealth::Unhealthy);
    }
    Ok(())
}
#[tokio::test]
async fn foreign_current_binding_is_denied_before_credentials_and_network() -> TestResult {
    let (current, config, profile) = setup("http://127.0.0.1:1")?;
    let c = credentials(false);
    let probe = probe(&config, &current, c.clone())?;
    let mut foreign = current;
    foreign["binding"]["collection_config_revision"] = "new-without-authorization".into();
    let mut observer = CoverageObserver::new(profile, &encode(&foreign)?)?;
    assert!(matches!(
        observer.poll(&probe, &encode(&foreign)?, &ctx()?).await,
        Err(ObserverError::Probe(ProbeFailure::Denied))
    ));
    assert_eq!(c.calls.load(Ordering::Acquire), 0);
    Ok(())
}
#[tokio::test]
async fn credential_denial_never_creates_configuration_evidence() -> TestResult {
    let (current, config, profile) = setup("http://127.0.0.1:1")?;
    let c = credentials(true);
    let probe = probe(&config, &current, c.clone())?;
    let mut observer = CoverageObserver::new(profile, &encode(&current)?)?;
    assert!(matches!(
        observer.poll(&probe, &encode(&current)?, &ctx()?).await,
        Err(ObserverError::Probe(ProbeFailure::Denied))
    ));
    assert_eq!(c.calls.load(Ordering::Acquire), 1);
    assert!(observer.latest_bytes().is_none());
    Ok(())
}

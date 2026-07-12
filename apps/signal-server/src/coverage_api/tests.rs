use super::*;
use axum::body::Body;
use serde_json::{Value, json};
use tower::ServiceExt;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TOKEN: &str = "fixture-observer-token-unique";
const OTHER: &str = "fixture-other-observer-token";
const ISSUER: &str = "https://identity.example.test";

fn native_wire(path: &std::path::Path) -> TestResult<Value> {
    let mut v = wire(path)?;
    let scope = v["scopes"][0].as_object_mut().ok_or("scope")?;
    scope.remove("token_env");
    scope.insert(
        "identity".into(),
        json!({"scope_id":"fixture-a", "account_id":"a",
        "writer_issuer":ISSUER,"writer_subject":"writer"}),
    );
    Ok(v)
}
fn native_configuration(v: &Value) -> TestResult<Configuration> {
    Ok(Configuration::validate_mode(
        serde_json::from_value(v.clone())?,
        |_| {
            Err(ConfigError::Invalid(
                "native mode must never read legacy secrets",
            ))
        },
        true,
    )?)
}
fn native_grant(subject: &str, permissions: Value) -> TestResult<RequestGrant> {
    use signal_protocol::access::{AccessPolicy, AuthenticatedIdentity};
    let policy = AccessPolicy::from_json(&serde_json::to_vec(&json!({"schema_version":1,
        "roles":[{"id":"fixture-role","permissions":permissions}],
        "bindings":[{"issuer":ISSUER,"subject":subject,"roles":["fixture-role"]}]}))?)?
    .compile()?;
    let at = crate::access::now().ok_or("clock")?;
    Ok(policy.grant(
        AuthenticatedIdentity::from_verified_backend(ISSUER.into(), subject.into(), at, at + 60)?,
        at,
    )?)
}
fn native_permission(operation: &str, account: &str) -> Value {
    json!({"operation":operation,"scope":{
        "sources":{"mode":"only","values":["fixture-source"]},
        "accounts":{"mode":"only","values":[account]},
        "resources":{"mode":"only","values":["fixture-resource"]}}})
}

#[test]
fn native_coverage_configuration_has_no_legacy_fallback_or_ambiguous_binding() -> TestResult {
    let base = native_wire(std::path::Path::new("data/coverage"))?;
    assert!(native_configuration(&base).is_ok());
    assert!(configuration(&base).is_err());
    assert!(native_configuration(&wire(std::path::Path::new("data/coverage"))?).is_err());
    for (field, value) in [
        ("scope_id", json!("bad space")),
        ("scope_id", json!("x".repeat(129))),
        ("writer_issuer", json!("")),
        ("writer_subject", json!("x".repeat(257))),
        ("account_id", json!("x".repeat(257))),
        ("unexpected", json!("private-value")),
    ] {
        let mut v = base.clone();
        v["scopes"][0]["identity"][field] = value;
        assert!(native_configuration(&v).is_err());
    }
    let mut v = base.clone();
    v["scopes"][0]["token_env"] = json!("FIXTURE_TOKEN");
    assert!(native_configuration(&v).is_err());
    let mut v = base.clone();
    v["scopes"][0]["identity"]
        .as_object_mut()
        .ok_or("identity")?
        .remove("account_id");
    assert!(native_configuration(&v).is_err());
    let mut v = base.clone();
    v["scopes"][0]["identity"]["account_id"] = Value::Null;
    assert!(native_configuration(&v).is_ok());
    let mut v = base.clone();
    let mut second = base["scopes"][0].clone();
    let mut b: Value = serde_json::from_str(second["binding_json"].as_str().ok_or("binding")?)?;
    b["observer_id"] = json!("another-observer");
    second["binding_json"] = serde_json::to_string(&b)?.into();
    v["scopes"].as_array_mut().ok_or("scopes")?.push(second);
    assert!(native_configuration(&v).is_err()); // Duplicate alias, even with distinct binding.
    v["scopes"][1]["identity"]["scope_id"] = json!("fixture-b");
    assert!(native_configuration(&v).is_ok());
    v["scopes"][1]["binding_json"] = base["scopes"][0]["binding_json"].clone();
    assert!(native_configuration(&v).is_err()); // Distinct aliases cannot duplicate a full binding.
    Ok(())
}

#[test]
fn native_coverage_operations_preserve_complete_pairs_verified_actor_and_unknown_account()
-> TestResult {
    let v = native_wire(std::path::Path::new("data/coverage"))?;
    let config = native_configuration(&v)?;
    let scope = &config.scopes[0];
    let writer = native_grant("writer", json!([native_permission("write_coverage", "a")]))?;
    assert!(native_allowed(
        scope,
        &writer,
        AccessOperation::WriteCoverage,
        false
    ));
    assert!(!native_allowed(
        scope,
        &writer,
        AccessOperation::ReadCoverage,
        false
    ));
    let impostor = native_grant(
        "impostor",
        json!([native_permission("write_coverage", "a")]),
    )?;
    assert!(!native_allowed(
        scope,
        &impostor,
        AccessOperation::WriteCoverage,
        false
    ));
    let reader = native_grant(
        "reader",
        json!([
            native_permission("read_coverage", "a"),
            native_permission("write_coverage", "b")
        ]),
    )?;
    assert!(native_allowed(
        scope,
        &reader,
        AccessOperation::ReadCoverage,
        false
    ));
    assert!(!native_allowed(
        scope,
        &reader,
        AccessOperation::WriteCoverage,
        false
    ));
    assert!(!native_allowed(
        scope,
        &reader,
        AccessOperation::ReadCoverage,
        true
    ));
    let global = native_grant(
        "reader",
        json!([{"operation":"read_coverage","scope":{
        "sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]),
    )?;
    assert!(native_allowed(
        scope,
        &global,
        AccessOperation::ReadCoverage,
        true
    ));
    let mut unknown = v;
    unknown["scopes"][0]["identity"]["account_id"] = Value::Null;
    let unknown = native_configuration(&unknown)?;
    assert!(!native_allowed(
        &unknown.scopes[0],
        &reader,
        AccessOperation::ReadCoverage,
        false
    ));
    assert!(native_allowed(
        &unknown.scopes[0],
        &global,
        AccessOperation::ReadCoverage,
        false
    ));
    Ok(())
}
fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/source-coverage/backend-vectors.json"
    ))?)
}
fn wire(path: &std::path::Path) -> TestResult<Value> {
    let f = fixture()?;
    let c = CoverageConfig::default();
    Ok(
        json!({"schema_version":1,"directory":path.to_str().ok_or("path")?,
        "limits":{"max_payloads":c.max_payloads,"max_identities":c.max_identities,"max_bindings":c.max_bindings,
            "max_ledger_bytes":c.max_ledger_bytes,"max_database_pages":c.max_database_pages,"max_journal_bytes":c.max_journal_bytes,
            "operation_capacity":c.operation_capacity,"transient_memory_bytes":c.transient_memory_bytes,"worker_memory_bytes":c.worker_memory_bytes,
            "max_vm_steps":c.max_vm_steps,"operation_timeout_ms":c.operation_timeout.as_millis()},
        "scopes":[{"binding_json":serde_json::to_string(&f["bindings"][0]["input"])?,
            "profile_json":serde_json::to_string(&f["profiles"][0]["input"])?,"authority_revision":"fixture-authority-v1","token_env":"FIXTURE_TOKEN",
            "max_report_age_seconds":60,"max_clock_skew_seconds":2,"payload_retention_seconds":300,"identity_retention_seconds":600}]}),
    )
}
fn configuration(v: &Value) -> TestResult<Configuration> {
    Ok(Configuration::validate(
        serde_json::from_value(v.clone())?,
        |name| Ok(if name == "OTHER_TOKEN" { OTHER } else { TOKEN }.into()),
    )?)
}
fn report() -> TestResult<Value> {
    let f = fixture()?;
    let mut v: Value = serde_json::from_str(
        f["chains"][0]["commits"][0]["input"]["raw_utf8"]
            .as_str()
            .ok_or("raw")?,
    )?;
    let at = chrono::Utc::now() - chrono::TimeDelta::seconds(2);
    let stamp = |delta: i64| {
        (at + chrono::TimeDelta::seconds(delta)).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    };
    v["coverage_start"] = stamp(-300).into();
    v["coverage_end"] = stamp(0).into();
    v["last_verified_at"] = stamp(0).into();
    v["valid_until"] = stamp(60).into();
    v["provenance"]["observed_at"] = stamp(0).into();
    v["record_id"] = Uuid::new_v4().to_string().into();
    Ok(v)
}
async fn open(v: &Value) -> TestResult<Arc<CoverageState>> {
    Ok(configuration(v)?
        .open(Duration::from_secs(1), CancellationToken::new())
        .await?)
}
async fn initialize(v: &Value) -> TestResult {
    configuration(v)?.initialize().await?;
    Ok(())
}
async fn stop(s: &CoverageState) -> TestResult {
    s.stopping.cancel();
    s.store
        .shutdown(OperationContext::new(Duration::from_secs(3)))
        .await?;
    Ok(())
}
async fn call(
    s: &Arc<CoverageState>,
    method: Method,
    url: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> TestResult<(StatusCode, Value)> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"))
    }
    let reply = s.router().oneshot(request.body(Body::from(body))?).await?;
    let status = reply.status();
    assert_eq!(
        reply
            .headers()
            .get("cache-control")
            .and_then(|h| h.to_str().ok()),
        Some("no-store")
    );
    let bytes = to_bytes(reply.into_body(), RESPONSE_BYTES).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}
fn path(r: &Value) -> TestResult<String> {
    Ok(format!(
        "/v1/coverage/records/{}",
        r["record_id"].as_str().ok_or("ID")?
    ))
}
#[test]
fn config_requires_closed_versioned_schema_explicit_retirement_and_finite_limits() -> TestResult {
    let base = wire(std::path::Path::new("data/coverage"))?;
    for (field, value) in [
        ("schema_version", json!(2)),
        ("scopes", json!([])),
        ("extra", json!(1)),
    ] {
        let mut v = base.clone();
        v[field] = value;
        assert!(configuration(&v).is_err());
    }
    let mut v = base.clone();
    v["scopes"][0]
        .as_object_mut()
        .ok_or("scope")?
        .remove("profile_json");
    assert!(configuration(&v).is_err());
    let mut v = base.clone();
    v["scopes"][0]["profile_json"] = Value::Null;
    assert!(configuration(&v).is_ok());
    let mut v = base.clone();
    v["limits"]["operation_capacity"] = json!(0);
    assert!(configuration(&v).is_err());
    let mut v = base.clone();
    v["limits"]["max_journal_bytes"] = json!(1);
    assert!(configuration(&v).is_err());
    let mut v = base.clone();
    let mut p: Value =
        serde_json::from_str(v["scopes"][0]["profile_json"].as_str().ok_or("profile")?)?;
    p["id"] = "foreign".into();
    v["scopes"][0]["profile_json"] = serde_json::to_string(&p)?.into();
    assert!(configuration(&v).is_err());
    Ok(())
}
#[test]
fn config_rejects_ambiguous_credentials_bindings_and_redacts_diagnostics() -> TestResult {
    let base = wire(std::path::Path::new("data/coverage"))?;
    let mut v = base.clone();
    let duplicate = v["scopes"][0].clone();
    v["scopes"].as_array_mut().ok_or("scopes")?.push(duplicate);
    assert!(configuration(&v).is_err());
    let mut v = base.clone();
    v["scopes"] = json!(vec![base["scopes"][0].clone(); 33]);
    assert!(configuration(&v).is_err());
    let error = Configuration::validate(serde_json::from_value(base)?, |_| {
        Ok("sensitive bad token".into())
    })
    .err()
    .ok_or("error")?;
    assert!(!error.to_string().contains("sensitive"));
    Ok(())
}
#[test]
fn coverage_url_identity_and_encoding_contract_is_strict() -> TestResult {
    assert_eq!(
        query(Some("correction_of=abc"), "correction_of")?,
        Some("abc".into())
    );
    for raw in [
        "cursor=%",
        "cursor=%FF",
        "cursor=",
        "cursor=one&cursor=two",
        "sql=select",
        "cursor=%GG",
    ] {
        assert!(query(Some(raw), "cursor").is_err());
    }
    assert!(uuid("00000000-0000-0000-0000-000000000000").is_err());
    assert!(uuid("BCC77D04-395D-5803-B313-E58AC0C8ACBE").is_err());
    Ok(())
}
#[tokio::test]
async fn bootstrap_is_explicit_and_never_recreates_existing_or_missing_history() -> TestResult {
    let temp = tempfile::tempdir()?;
    let v = wire(&temp.path().join("coverage"))?;
    assert!(open(&v).await.is_err());
    initialize(&v).await?;
    assert!(initialize(&v).await.is_err());
    let state = open(&v).await?;
    assert!(open(&v).await.is_err());
    stop(&state).await?;
    let state = open(&v).await?;
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn original_bytes_receipt_and_replay_survive_store_restart_without_healthy_silence()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let v = wire(&temp.path().join("coverage"))?;
    initialize(&v).await?;
    let state = open(&v).await?;
    let r = report()?;
    let raw = serde_json::to_string_pretty(&r)?.into_bytes();
    let url = path(&r)?;
    let (status, accepted) = call(&state, Method::POST, &url, Some(TOKEN), raw.clone()).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(accepted["current_health"], "unknown");
    let (status, replayed) = call(&state, Method::POST, &url, Some(TOKEN), raw.clone()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replayed["receipt"], accepted["receipt"]);
    let (_, read) = call(&state, Method::GET, &url, Some(TOKEN), vec![]).await?;
    assert_eq!(read["raw"].as_str().ok_or("raw")?.as_bytes(), raw);
    assert_eq!(read["current_health"], "unknown");
    let retained =
        ProfileDefinition::parse(read["profile_json"].as_str().ok_or("profile")?.as_bytes())?;
    assert_eq!(
        signal_coverage::format::hex(&retained.fingerprint()),
        accepted["receipt"]["profile_fingerprint"]
            .as_str()
            .ok_or("hash")?
    );
    stop(&state).await?;
    let state = open(&v).await?;
    let (_, read) = call(&state, Method::GET, &url, Some(TOKEN), vec![]).await?;
    assert_eq!(read["receipt"], accepted["receipt"]);
    assert_eq!(read["current_health"], "unknown");
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn authentication_precedes_input_and_full_binding_is_enforced_for_every_operation()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let mut v = wire(&temp.path().join("coverage"))?;
    let mut other = v["scopes"][0].clone();
    let mut binding: Value =
        serde_json::from_str(other["binding_json"].as_str().ok_or("binding")?)?;
    binding["observer_id"] = "other-observer".into();
    binding["source_id"] = "other-source".into();
    other["binding_json"] = serde_json::to_string(&binding)?.into();
    other["token_env"] = "OTHER_TOKEN".into();
    v["scopes"].as_array_mut().ok_or("scope")?.push(other);
    initialize(&v).await?;
    let state = open(&v).await?;
    let r = report()?;
    let url = path(&r)?;
    let raw = serde_json::to_vec(&r)?;
    for token in [None, Some("wrong-token"), Some("operator-shared-api-token")] {
        assert_eq!(
            call(
                &state,
                Method::POST,
                &url,
                token,
                vec![0; MAX_RAW_BYTES + 1]
            )
            .await?
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        call(&state, Method::POST, &url, Some(OTHER), raw.clone())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(state.store.metrics().committed_sequence, 0);
    assert_eq!(
        call(&state, Method::POST, &url, Some(TOKEN), raw).await?.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&state, Method::GET, &url, Some(OTHER), vec![])
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, page) = call(
        &state,
        Method::GET,
        "/v1/coverage/history",
        Some(OTHER),
        vec![],
    )
    .await?;
    assert_eq!(page["records"], json!([]));
    assert_eq!(page["current_health"], "unknown");
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn malformed_oversized_changed_id_and_correction_input_never_promote_health() -> TestResult {
    let temp = tempfile::tempdir()?;
    let v = wire(&temp.path().join("coverage"))?;
    initialize(&v).await?;
    let state = open(&v).await?;
    let mut r = report()?;
    let url = path(&r)?;
    for raw in [
        b"{\"secret\":\"sensitive-fixture\"}".to_vec(),
        vec![b' '; MAX_RAW_BYTES + 1],
        b"not json".to_vec(),
    ] {
        let (status, reply) = call(&state, Method::POST, &url, Some(TOKEN), raw).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!reply.to_string().contains("sensitive-fixture"));
    }
    assert_eq!(
        call(
            &state,
            Method::POST,
            &format!("{url}?correction_of=%FF"),
            Some(TOKEN),
            serde_json::to_vec(&r)?
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &state,
            Method::POST,
            &url,
            Some(TOKEN),
            serde_json::to_vec(&r)?
        )
        .await?
        .0,
        StatusCode::CREATED
    );
    r["provenance"]["method"] = "changed-method".into();
    assert_eq!(
        call(
            &state,
            Method::POST,
            &url,
            Some(TOKEN),
            serde_json::to_vec(&r)?
        )
        .await?
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(state.store.metrics().committed_sequence, 1);
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn retired_profile_replay_returns_original_pin_and_blocks_new_admission() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut v = wire(&temp.path().join("coverage"))?;
    initialize(&v).await?;
    let state = open(&v).await?;
    let mut r = report()?;
    let raw = serde_json::to_vec(&r)?;
    let url = path(&r)?;
    let (_, accepted) = call(&state, Method::POST, &url, Some(TOKEN), raw.clone()).await?;
    stop(&state).await?;
    v["scopes"][0]["profile_json"] = Value::Null;
    let state = open(&v).await?;
    let (status, replay) = call(&state, Method::POST, &url, Some(TOKEN), raw).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["receipt"], accepted["receipt"]);
    assert_eq!(replay["current_health"], "unknown");
    r["record_id"] = Uuid::new_v4().to_string().into();
    assert_eq!(
        call(
            &state,
            Method::POST,
            &path(&r)?,
            Some(TOKEN),
            serde_json::to_vec(&r)?
        )
        .await?
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(state.store.metrics().committed_sequence, 1);
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn history_pages_pin_frontier_and_never_interpret_exhaustion_as_health() -> TestResult {
    let temp = tempfile::tempdir()?;
    let v = wire(&temp.path().join("coverage"))?;
    initialize(&v).await?;
    let state = open(&v).await?;
    let mut r = report()?;
    for _ in 0..2 {
        r["record_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            call(
                &state,
                Method::POST,
                &path(&r)?,
                Some(TOKEN),
                serde_json::to_vec(&r)?
            )
            .await?
            .0,
            StatusCode::CREATED
        );
    }
    let (_, first) = call(
        &state,
        Method::GET,
        "/v1/coverage/history",
        Some(TOKEN),
        vec![],
    )
    .await?;
    assert_eq!(first["frontier"], "2");
    assert_eq!(first["records"].as_array().ok_or("rows")?.len(), 1);
    r["record_id"] = Uuid::new_v4().to_string().into();
    call(
        &state,
        Method::POST,
        &path(&r)?,
        Some(TOKEN),
        serde_json::to_vec(&r)?,
    )
    .await?;
    let cursor = first["continuation"].as_str().ok_or("cursor")?;
    let (_, second) = call(
        &state,
        Method::GET,
        &format!("/v1/coverage/history?cursor={cursor}"),
        Some(TOKEN),
        vec![],
    )
    .await?;
    assert_eq!(second["frontier"], "2");
    assert_eq!(second["records"][0]["receipt"]["sequence"], "2");
    assert!(second["continuation"].is_null());
    assert_eq!(second["current_health"], "unknown");
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn quotas_and_http_capacity_keep_exact_replay_and_expose_finite_metrics() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut v = wire(&temp.path().join("coverage"))?;
    v["limits"]["max_payloads"] = json!(1);
    v["limits"]["max_identities"] = json!(1);
    v["limits"]["max_bindings"] = json!(1);
    initialize(&v).await?;
    let state = open(&v).await?;
    let mut r = report()?;
    let raw = serde_json::to_vec(&r)?;
    let url = path(&r)?;
    assert_eq!(
        call(&state, Method::POST, &url, Some(TOKEN), raw.clone())
            .await?
            .0,
        StatusCode::CREATED
    );
    r["record_id"] = Uuid::new_v4().to_string().into();
    assert_eq!(
        call(
            &state,
            Method::POST,
            &path(&r)?,
            Some(TOKEN),
            serde_json::to_vec(&r)?
        )
        .await?
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        call(&state, Method::POST, &url, Some(TOKEN), raw.clone())
            .await?
            .0,
        StatusCode::OK
    );
    let permits = state.requests.acquire_many(REQUEST_CAPACITY as u32).await?;
    assert_eq!(
        call(&state, Method::POST, &url, Some(TOKEN), raw).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    drop(permits);
    let (_, metrics) = call(
        &state,
        Method::GET,
        "/v1/coverage/metrics",
        Some(TOKEN),
        vec![],
    )
    .await?;
    assert_eq!(metrics["operation_capacity"], 4);
    assert_eq!(metrics["payload_capacity"], 1);
    assert_eq!(metrics["accepted"], 1);
    assert_eq!(metrics["replayed"], 1);
    assert_eq!(metrics["current_health"], "unknown");
    stop(&state).await?;
    Ok(())
}
#[tokio::test]
async fn cancelled_requests_do_not_mutate_store_and_bounded_serialization_fails_closed()
-> TestResult {
    let temp = tempfile::tempdir()?;
    let v = wire(&temp.path().join("coverage"))?;
    initialize(&v).await?;
    let state = open(&v).await?;
    let r = report()?;
    state.stopping.cancel();
    assert_eq!(
        call(
            &state,
            Method::POST,
            &path(&r)?,
            Some(TOKEN),
            serde_json::to_vec(&r)?
        )
        .await?
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(state.store.metrics().committed_sequence, 0);
    let reply = response(StatusCode::OK, json!("x".repeat(RESPONSE_BYTES)));
    assert_eq!(reply.status(), StatusCode::PAYLOAD_TOO_LARGE);
    stop(&state).await?;
    Ok(())
}

async fn audit_control(
    spool: &std::path::Path,
    sink: Arc<crate::audit::tests::SyncedDestination>,
    operations: Vec<AccessOperation>,
) -> TestResult<Arc<crate::audit::Control>> {
    Ok(crate::audit::Control::test_open(
        spool,
        sink,
        operations,
        signal_collector_sdk::ExtensionContext::new(
            CancellationToken::new(),
            Duration::from_secs(10),
        )?,
    )
    .await?)
}
async fn audited(v: &Value, control: Arc<crate::audit::Control>) -> TestResult<Arc<CoverageState>> {
    Ok(configuration(v)?
        .open_with_identity(
            Duration::from_secs(10),
            CancellationToken::new(),
            None,
            Some(control),
        )
        .await?)
}
fn coverage_operations() -> Vec<AccessOperation> {
    vec![
        AccessOperation::ReadCoverage,
        AccessOperation::WriteCoverage,
    ]
}
fn audit_record(
    path: &std::path::Path,
    sequence: u64,
) -> TestResult<signal_protocol::audit::PreparedAudit> {
    Ok(signal_protocol::audit::PreparedAudit::from_original(
        &std::fs::read(path.join(sequence.to_string()))?,
    )?)
}
#[tokio::test]
async fn coverage_audit_writes_replays_reads_and_errors_emit_only_control_pairs() -> TestResult {
    use signal_protocol::audit::{Action, Actor, Completion, Decision};
    use std::sync::atomic::Ordering;
    let _serial = crate::audit::tests::SERIAL.lock().await;
    let spool = crate::audit::tests::root()?;
    let archive = crate::audit::tests::root()?;
    let data = tempfile::tempdir()?;
    let sink = crate::audit::tests::destination(archive.path(), 0);
    let control = audit_control(spool.path(), sink.clone(), coverage_operations()).await?;
    let v = wire(&data.path().join("store"))?;
    initialize(&v).await?;
    let state = audited(&v, control.clone()).await?;
    let report = report()?;
    let id = report["record_id"].as_str().ok_or("id")?;
    let url = format!("/v1/coverage/records/{id}");
    let raw = serde_json::to_vec(&report)?;
    let (_, accepted) = call(&state, Method::POST, &url, Some(TOKEN), raw.clone()).await?;
    assert_eq!(state.store.metrics().accepted, 1);
    let (_, replayed) = call(&state, Method::POST, &url, Some(TOKEN), raw).await?;
    assert_eq!(accepted["receipt"], replayed["receipt"]);
    for (method, url, token, expected) in [
        (Method::GET, url.as_str(), Some(TOKEN), StatusCode::OK),
        (
            Method::GET,
            "/v1/coverage/history",
            Some(TOKEN),
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/v1/coverage/metrics",
            Some(TOKEN),
            StatusCode::OK,
        ),
        (Method::GET, url.as_str(), None, StatusCode::UNAUTHORIZED),
        (
            Method::POST,
            "/v1/coverage/records/not-a-uuid",
            Some(TOKEN),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, _) = call(&state, method, url, token, Vec::new()).await?;
        assert_eq!(status, expected);
    }
    assert_eq!(sink.calls.load(Ordering::SeqCst), 14);
    for sequence in (1..=13).step_by(2) {
        let first = audit_record(archive.path(), sequence)?;
        let last = audit_record(archive.path(), sequence + 1)?;
        let Action::AccessDecision {
            operation,
            operation_id,
            decision,
        } = first.record().action
        else {
            return Err("decision".into());
        };
        let expected = if sequence <= 3 || sequence == 13 {
            AccessOperation::WriteCoverage
        } else {
            AccessOperation::ReadCoverage
        };
        assert_eq!(operation, expected);
        let completion = if sequence == 11 {
            Completion::Denied
        } else if sequence == 13 {
            Completion::Failed
        } else {
            Completion::Success
        };
        assert!(
            last.record().action
                == Action::OperationCompletion {
                    operation,
                    operation_id,
                    completion
                }
        );
        assert!(
            decision
                == if sequence == 11 {
                    Decision::Denied
                } else {
                    Decision::Granted
                }
        );
        assert!(matches!(first.record().actor, Actor::Bootstrap {}) || sequence == 11);
        for record in [first, last] {
            let text = String::from_utf8_lossy(record.body());
            for secret in [
                TOKEN,
                id,
                "fixture-source",
                "fixture-authority-v1",
                "profile_fingerprint",
            ] {
                assert!(!text.contains(secret));
            }
        }
    }
    assert!(!control.metrics().held);
    stop(&state).await
}
#[tokio::test]
async fn coverage_decision_loss_prevents_admission_but_completion_loss_keeps_exact_committed_receipt()
-> TestResult {
    use signal_protocol::audit::Action;
    let _serial = crate::audit::tests::SERIAL.lock().await;
    for lose_on in [1, 2] {
        let spool = crate::audit::tests::root()?;
        let archive = crate::audit::tests::root()?;
        let data = tempfile::tempdir()?;
        let sink = crate::audit::tests::destination(archive.path(), lose_on);
        let control = audit_control(spool.path(), sink.clone(), coverage_operations()).await?;
        let v = wire(&data.path().join("store"))?;
        initialize(&v).await?;
        let state = audited(&v, control.clone()).await?;
        let r = report()?;
        let id = r["record_id"].as_str().ok_or("id")?;
        let url = format!("/v1/coverage/records/{id}");
        let raw = serde_json::to_vec(&r)?;
        let (status, response) = call(&state, Method::POST, &url, Some(TOKEN), raw.clone()).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.get("receipt").is_none());
        assert_eq!(state.store.metrics().accepted, u64::from(lose_on == 2));
        assert!(control.metrics().held);
        let pending = std::fs::read(spool.path().join("pending"))?;
        assert_eq!(
            pending,
            std::fs::read(archive.path().join(lose_on.to_string()))?
        );
        let old = audit_record(archive.path(), lose_on)?;
        let operation_id = match old.record().action {
            Action::AccessDecision { operation_id, .. }
            | Action::OperationCompletion { operation_id, .. } => operation_id,
            _ => return Err("read action".into()),
        };
        stop(&state).await?;
        drop(state);
        drop(control);
        let control = audit_control(spool.path(), sink.clone(), coverage_operations()).await?;
        let state = audited(&v, control.clone()).await?;
        let (status, retry) = call(&state, Method::POST, &url, Some(TOKEN), raw).await?;
        assert_eq!(
            status,
            if lose_on == 1 {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            }
        );
        assert!(retry.get("receipt").is_some());
        assert_eq!(state.store.metrics().payloads, 1);
        assert_eq!(
            std::fs::read(archive.path().join(lose_on.to_string()))?,
            pending
        );
        let fresh = audit_record(archive.path(), lose_on + 1)?;
        let Action::AccessDecision {
            operation_id: fresh_id,
            ..
        } = fresh.record().action
        else {
            return Err("fresh decision".into());
        };
        assert_ne!(fresh_id, operation_id);
        let (status, read) = call(&state, Method::GET, &url, Some(TOKEN), Vec::new()).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read["receipt"], retry["receipt"]);
        stop(&state).await?;
    }
    Ok(())
}

#[tokio::test]
async fn coverage_read_ack_loss_withholds_originals_history_and_aggregate_metadata() -> TestResult {
    let _serial = crate::audit::tests::SERIAL.lock().await;
    for route in ["record", "history", "metrics"] {
        for lose_on in [1, 2] {
            let spool = crate::audit::tests::root()?;
            let archive = crate::audit::tests::root()?;
            let data = tempfile::tempdir()?;
            let sink = crate::audit::tests::destination(archive.path(), lose_on);
            let control = audit_control(
                spool.path(),
                sink.clone(),
                vec![AccessOperation::ReadCoverage],
            )
            .await?;
            let v = wire(&data.path().join("store"))?;
            initialize(&v).await?;
            let state = audited(&v, control.clone()).await?;
            let r = report()?;
            let id = r["record_id"].as_str().ok_or("id")?;
            let url = format!("/v1/coverage/records/{id}");
            let (status, _) = call(
                &state,
                Method::POST,
                &url,
                Some(TOKEN),
                serde_json::to_vec(&r)?,
            )
            .await?;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
            let uri = match route {
                "record" => url.as_str(),
                "history" => "/v1/coverage/history",
                _ => "/v1/coverage/metrics",
            };
            let (status, value) = call(&state, Method::GET, uri, Some(TOKEN), Vec::new()).await?;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                value.get("receipt").is_none()
                    && value.get("records").is_none()
                    && value.get("accepted").is_none()
            );
            assert!(!value.to_string().contains(id));
            assert_eq!(state.store.metrics().payloads, 1);
            assert!(control.metrics().held);
            let pending = std::fs::read(spool.path().join("pending"))?;
            assert_eq!(
                pending,
                std::fs::read(archive.path().join(lose_on.to_string()))?
            );
            stop(&state).await?;
            drop(state);
            drop(control);
            let control = audit_control(
                spool.path(),
                sink.clone(),
                vec![AccessOperation::ReadCoverage],
            )
            .await?;
            let state = audited(&v, control).await?;
            assert_eq!(
                std::fs::read(archive.path().join(lose_on.to_string()))?,
                pending
            );
            let (status, _) = call(&state, Method::GET, uri, Some(TOKEN), Vec::new()).await?;
            assert_eq!(status, StatusCode::OK);
            stop(&state).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn coverage_and_query_share_one_bounded_control_slot_before_mutation() -> TestResult {
    use signal_protocol::audit::{Actor, Completion, Decision};
    let _serial = crate::audit::tests::SERIAL.lock().await;
    let spool = crate::audit::tests::root()?;
    let archive = crate::audit::tests::root()?;
    let data = tempfile::tempdir()?;
    let sink = crate::audit::tests::destination(archive.path(), 0);
    let control = audit_control(
        spool.path(),
        sink.clone(),
        vec![
            AccessOperation::QueryEvents,
            AccessOperation::ReadFindings,
            AccessOperation::ReadFindingsFeed,
            AccessOperation::ReadCoverage,
            AccessOperation::WriteCoverage,
        ],
    )
    .await?;
    let v = wire(&data.path().join("store"))?;
    initialize(&v).await?;
    let state = audited(&v, control.clone()).await?;
    let r = report()?;
    let url = format!(
        "/v1/coverage/records/{}",
        r["record_id"].as_str().ok_or("id")?
    );
    let ctx = signal_collector_sdk::ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(10),
    )?;
    let session = control
        .begin(
            Actor::Anonymous {},
            Decision::Granted,
            AccessOperation::QueryEvents,
            ctx.deadline(),
            ctx.cancellation().clone(),
        )
        .await?;
    for (method, uri, body) in [
        (Method::POST, url.as_str(), serde_json::to_vec(&r)?),
        (Method::GET, "/v1/coverage/history", Vec::new()),
    ] {
        let (status, _) = call(&state, method, uri, Some(TOKEN), body).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(state.store.metrics().payloads, 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(control.metrics().rejected, 2);
    assert!(!control.metrics().held);
    session.finish(Completion::Success).await?;
    let (status, _) = call(
        &state,
        Method::POST,
        &url,
        Some(TOKEN),
        serde_json::to_vec(&r)?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(state.store.metrics().payloads, 1);
    stop(&state).await
}

#[tokio::test]
async fn uncertain_write_response_survives_late_authority_denial_after_audit() -> TestResult {
    let data = tempfile::tempdir()?;
    let v = wire(&data.path().join("store"))?;
    initialize(&v).await?;
    let state = open(&v).await?;
    let native = native_configuration(&native_wire(std::path::Path::new("fixture-native"))?)?;
    let scope = &native.scopes[0];
    let denied = native_grant(
        "impostor",
        json!([native_permission("write_coverage", "a")]),
    )?;
    let access = ScopeAccess {
        scope,
        request_grant: Some(denied),
        authority: grant_binding(scope)?,
        operation: AccessOperation::WriteCoverage,
        aggregate: false,
    };
    let context = OperationContext::new(Duration::from_secs(10));
    assert_eq!(
        access.finish(&context).map(|response| response.status()),
        Some(StatusCode::FORBIDDEN)
    );
    let response = post_audit_response(
        &access,
        &context,
        failure(CoverageError::OutcomeUnknown),
        &state,
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    stop(&state).await
}

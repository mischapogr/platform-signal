use super::*;
use axum::body::Body;
use serde_json::{Value, json};
use tower::ServiceExt;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TOKEN: &str = "fixture-observer-token-unique";
const OTHER: &str = "fixture-other-observer-token";
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
            "max_vm_steps":c.max_vm_steps,"operation_timeout_ms":1000},
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

//! Live HTTP/TLS/audit over the native admitted mixed-history database.
use super::*;
use signal_collector_sdk::ExtensionContext;
use signal_control::{ConnectionSettings, ControlClient, ControlContext, ScopedFindingsBinding};
use signal_ingest::identity::IdentityConfig;
use signal_protocol::access::{AccessPolicy, introspection::IntrospectionProfile};
use signal_server::{shared_feed::SharedFindingsFeed, shared_findings::SharedFindings};
use std::{fs, path::PathBuf, sync::atomic::Ordering};
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(serde::Deserialize)]
struct Fixture {
    port: u16,
    password: String,
    root_der: String,
}
async fn get(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    token: &str,
) -> Result<(u16, Vec<u8>)> {
    let mut request = client
        .get(format!("{base}{path}"))
        .header("x-forwarded-user", "reader")
        .header("x-forwarded-roles", "administrator");
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|h| h.to_str().ok()),
        Some("no-store")
    );
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;
    assert!(bytes.len() <= 65536);
    Ok((status, bytes.to_vec()))
}
fn ids(bytes: &[u8]) -> Result<Vec<Uuid>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    assert_eq!(value["schema_version"], 1);
    value["findings"]
        .as_array()
        .ok_or("missing findings")?
        .iter()
        .map(|v| Ok(v["id"].as_str().ok_or("missing id")?.parse()?))
        .collect()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "owned native admission/PostgreSQL/TLS fixture launched by check-shared-runtime.py"]
async fn authorized_shared_scoped_http_provider_audit() -> Result {
    let path = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?);
    assert!(fs::metadata(&path)?.len() <= 4096);
    let f: Fixture = serde_json::from_slice(&fs::read(path)?)?;
    let mut pg = tokio_postgres::Config::new();
    pg.host("127.0.0.1")
        .port(f.port)
        .user("postgres")
        .password(&f.password)
        .dbname("signal_native_admission");
    let (db, connection) =
        tokio::time::timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let driver = tokio::spawn(connection);
    let row=tokio::time::timeout(Duration::from_secs(2),db.query_one("SELECT c.store_id,c.generation,a.scope_generation FROM signal_control.store c CROSS JOIN signal_finding_scope.activation a",&[])).await??;
    let binding = ScopedFindingsBinding {
        store: row.try_get(0)?,
        generation: row.try_get(1)?,
        scope_generation: row.try_get(2)?,
        schema_owner: "signal_control_owner".into(),
    };
    let original = tokio::time::timeout(
        Duration::from_secs(2),
        db.query(
            "SELECT id FROM signal_control.findings ORDER BY position",
            &[],
        ),
    )
    .await??;
    assert_eq!(original.len(), 2);
    let legacy: Uuid = original[0].try_get(0)?;
    let native: Uuid = original[1].try_get(0)?;
    let reader = Arc::new(ControlClient::catalog(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            f.port,
            "signal_native_admission".into(),
            "signal_denied".into(),
            f.password.as_bytes().to_vec(),
        )?,
    )?);
    let list = Arc::new(SharedFindings::new(
        reader.clone(),
        binding.clone(),
        1,
        65536,
    )?);
    let feed = Arc::new(SharedFindingsFeed::new(
        reader.clone(),
        binding.store,
        binding.generation,
        1,
        65536,
    )?);
    let policy=AccessPolicy::from_json(br#"{"schema_version":1,"roles":[{"id":"restricted","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"only","values":["audit"]},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"only","values":["host-a"]}}}]},{"id":"all","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]},{"id":"one","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"only","values":["audit"]},"accounts":{"mode":"only","values":["b"]},"resources":{"mode":"all"}}}]},{"id":"two","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"all"},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"only","values":["host-b"]}}}]},{"id":"feed","permissions":[{"operation":"read_findings_feed","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]}],"bindings":[{"issuer":"https://identity.example.test","subject":"reader","roles":["restricted"]},{"issuer":"https://identity.example.test","subject":"all-reader","roles":["all"]},{"issuer":"https://identity.example.test","subject":"paired-reader","roles":["one","two"]},{"issuer":"https://identity.example.test","subject":"feed-reader","roles":["feed"]}]}"#)?.compile()?;
    let identity = IdentityBackend::new(
        IdentityConfig {
            endpoint: std::env::var("SIGNAL_SHARED_HTTP_PROVIDER")?,
            client_id: "synthetic-client".into(),
            client_secret: "synthetic-shared-feed-secret".into(),
            extra_roots: vec![fs::read(&f.root_der)?],
            workers: 1,
            max_request_duration: Duration::from_secs(1),
        },
        IntrospectionProfile::new("https://identity.example.test".into(), "signal".into(), 30)?,
        policy,
        tokio::runtime::Handle::current(),
    )?;
    let outbox = crate::audit::tests::root()?;
    let destination = crate::audit::tests::root()?;
    let sink = crate::audit::tests::destination(destination.path(), 0);
    let audit = crate::audit::Control::test_open(
        outbox.path(),
        sink.clone(),
        vec![Operation::ReadFindings, Operation::ReadFindingsFeed],
        ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?,
    )
    .await?;
    let stopping = CancellationToken::new();
    let security = Security {
        identity: Some(identity.clone()),
        audit: Some(audit),
    };
    let router = router_with_shared_findings(
        list.clone(),
        feed.clone(),
        IngestConfig::default(),
        2,
        Duration::from_secs(2),
        stopping.clone(),
        security.clone(),
    )?;
    let tiny = Arc::new(SharedFindings::new(reader.clone(), binding.clone(), 1, 64)?);
    let tiny_router = router_with_shared_findings(
        tiny,
        feed.clone(),
        IngestConfig::default(),
        2,
        Duration::from_secs(2),
        stopping.clone(),
        security.clone(),
    )?;
    let mut wrong = binding.clone();
    wrong.scope_generation = Uuid::new_v4();
    let wrong = Arc::new(SharedFindings::new(reader.clone(), wrong, 1, 65536)?);
    let wrong_router = router_with_shared_findings(
        wrong,
        feed.clone(),
        IngestConfig::default(),
        2,
        Duration::from_secs(2),
        stopping.clone(),
        security.clone(),
    )?;
    let other = Arc::new(SharedFindingsFeed::new(
        reader.clone(),
        Uuid::new_v4(),
        binding.generation,
        1,
        65536,
    )?);
    assert!(matches!(
        router_with_shared_findings(
            list.clone(),
            other,
            IngestConfig::default(),
            2,
            Duration::from_secs(2),
            stopping.clone(),
            security.clone()
        ),
        Err(signal_control::ControlError::Invalid)
    ));
    let failed_outbox = crate::audit::tests::root()?;
    let failed_destination = crate::audit::tests::root()?;
    let failed_sink = crate::audit::tests::destination(failed_destination.path(), 2);
    let failed = crate::audit::Control::test_open(
        failed_outbox.path(),
        failed_sink.clone(),
        vec![Operation::ReadFindings],
        ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?,
    )
    .await?;
    let failed_router = router_with_shared_findings(
        list.clone(),
        feed,
        IngestConfig::default(),
        2,
        Duration::from_secs(2),
        stopping.clone(),
        Security {
            identity: Some(identity.clone()),
            audit: Some(failed),
        },
    )?;
    // The selected durable audit profile has its own single operation seat.
    // Exercise the independent caller gate with a native-authenticated profile
    // whose audit is disabled, while the ordinary routes qualify durable audit.
    let capacity_router = router_with_shared_findings(
        list.clone(),
        Arc::new(SharedFindingsFeed::new(
            reader.clone(),
            binding.store,
            binding.generation,
            1,
            65536,
        )?),
        IngestConfig::default(),
        2,
        Duration::from_secs(2),
        stopping.clone(),
        Security {
            identity: Some(identity.clone()),
            audit: None,
        },
    )?;
    let router = router
        .nest("/capacity", capacity_router)
        .nest("/tiny", tiny_router)
        .nest("/wrong", wrong_router)
        .nest("/audit-fail", failed_router);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let shutdown = stopping.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    let test: Result = async {
        let (status, bytes) = get(&client, &base, "/v1/findings?limit=1", "reader").await?;
        assert_eq!(status, 200);
        assert_eq!(ids(&bytes)?, vec![native]);
        assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
        let completion: signal_protocol::audit::AuditRecord =
            serde_json::from_slice(&fs::read(destination.path().join("2"))?)?;
        assert!(matches!(
            completion.action,
            signal_protocol::audit::Action::OperationCompletion {
                operation: Operation::ReadFindings,
                completion: signal_protocol::audit::Completion::Success,
                ..
            }
        ));
        let (status, bytes) = get(&client, &base, "/v1/findings?limit=2", "all-reader").await?;
        assert_eq!(status, 200);
        assert_eq!(ids(&bytes)?, vec![legacy, native]);
        let (status, bytes) = get(
            &client,
            &base,
            "/v1/findings?from=0000-01-01T00%3A01%3A00Z&limit=1",
            "all-reader",
        )
        .await?;
        assert_eq!(status, 200);
        assert_eq!(ids(&bytes)?, vec![native]);
        let (status, bytes) = get(&client, &base, "/v1/findings?limit=1", "paired-reader").await?;
        assert_eq!(status, 200);
        assert!(ids(&bytes)?.is_empty());
        let (status, bytes) = get(&client, &base, "/v1/findings?severity=low", "reader").await?;
        assert_eq!(status, 200);
        assert!(ids(&bytes)?.is_empty());
        for token in ["", "expired", "producer", "impostor", "feed-reader"] {
            let (status, bytes) = get(&client, &base, "/v1/findings?limit=1", token).await?;
            assert!(matches!(status, 401 | 403));
            assert!(!String::from_utf8_lossy(&bytes).contains(&native.to_string()));
        }
        let (status, _) = get(&client, &base, "/v1/findings/feed?after=begin", "reader").await?;
        assert_eq!(status, 403);
        let (status, bytes) = get(
            &client,
            &base,
            "/v1/findings/feed?after=begin&limit=2",
            "feed-reader",
        )
        .await?;
        assert_eq!(status, 200);
        assert_eq!(ids(&bytes)?, vec![legacy, native]);
        for (path, want) in [
            ("/tiny/v1/findings?limit=1", 413),
            ("/wrong/v1/findings?limit=1", 503),
            ("/audit-fail/v1/findings?limit=1", 503),
            ("/v1/findings?limit=3", 400),
        ] {
            let (status, bytes) = get(&client, &base, path, "reader").await?;
            assert_eq!(status, want);
            assert!(!String::from_utf8_lossy(&bytes).contains(&native.to_string()));
        }
        assert_eq!(failed_sink.calls.load(Ordering::SeqCst), 2);
        assert!(failed_destination.path().join("2").is_file());
        tokio::time::timeout(
            Duration::from_secs(2),
            db.batch_execute("BEGIN; LOCK TABLE signal_control.findings IN ACCESS EXCLUSIVE MODE"),
        )
        .await??;
        let pending_client = client.clone();
        let pending_base = base.clone();
        let pending = tokio::spawn(async move {
            pending_client
                .get(format!("{pending_base}/capacity/v1/findings?limit=1"))
                .bearer_auth("reader")
                .send()
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while list.metrics().active_callers != 1 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        let (status, bytes) =
            get(&client, &base, "/capacity/v1/findings?limit=1", "reader").await?;
        assert_eq!(status, 429);
        assert!(!String::from_utf8_lossy(&bytes).contains(&native.to_string()));
        let response = tokio::time::timeout(Duration::from_secs(3), pending).await???;
        assert!(matches!(response.status().as_u16(), 408 | 503));
        let bytes = response.bytes().await?;
        assert!(!String::from_utf8_lossy(&bytes).contains(&native.to_string()));
        tokio::time::timeout(Duration::from_secs(2), db.batch_execute("ROLLBACK")).await??;
        assert_eq!(list.metrics().active_callers, 0);
        assert!(list.metrics().rejected >= 2);
        tokio::time::timeout(
            Duration::from_secs(2),
            db.batch_execute("BEGIN; LOCK TABLE signal_control.findings IN ACCESS EXCLUSIVE MODE"),
        )
        .await??;
        let pending_client = client.clone();
        let pending_base = base.clone();
        let pending = tokio::spawn(async move {
            pending_client
                .get(format!("{pending_base}/capacity/v1/findings?limit=1"))
                .bearer_auth("reader")
                .send()
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while list.metrics().active_callers != 1 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        stopping.cancel();
        let response = tokio::time::timeout(Duration::from_secs(3), pending).await???;
        assert_eq!(response.status().as_u16(), 503);
        let bytes = response.bytes().await?;
        assert!(!String::from_utf8_lossy(&bytes).contains(&native.to_string()));
        tokio::time::timeout(Duration::from_secs(2), db.batch_execute("ROLLBACK")).await??;
        assert_eq!(list.metrics().active_callers, 0);
        assert_eq!(list.metrics().caller_capacity, 1);
        Ok(())
    }
    .await;
    stopping.cancel();
    tokio::time::timeout(Duration::from_secs(3), server).await???;
    identity
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
        .await?;
    reader
        .shutdown(ControlContext::new(Duration::from_secs(2))?)
        .await?;
    drop(db);
    tokio::time::timeout(Duration::from_secs(2), driver).await???;
    test?;
    println!(
        "phase: actual-native-shared-scoped-http-TLS-paired-before-limit-unknown-history-durable-audit-qualified"
    );
    Ok(())
}

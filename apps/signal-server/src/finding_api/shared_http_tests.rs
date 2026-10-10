//! Owned native PostgreSQL + real TLS introspection + loopback HTTP qualification.
use super::*;
use signal_collector_sdk::ExtensionContext;
use signal_control::{ConnectionSettings, ControlClient, ControlContext};
use signal_ingest::identity::IdentityConfig;
use signal_protocol::access::{
    AccessPolicy, Permission, ResourceScope, Role, SubjectBinding,
    introspection::IntrospectionProfile,
};
use std::{fs, net::IpAddr, path::PathBuf};
use uuid::Uuid;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(serde::Deserialize)]
struct Fixture {
    port: u16,
    password: String,
    root_der: String,
}

async fn response(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    token: &str,
) -> Result<(u16, Vec<u8>)> {
    let mut request = client.get(format!("{base}{path}"));
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;
    assert!(bytes.len() <= 65536);
    Ok((status, bytes.to_vec()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "owned PostgreSQL/TLS provider fixture launched by check-shared-runtime.py"]
async fn authorized_shared_feed_http_provider_audit() -> Result {
    let path = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?);
    assert!(fs::metadata(&path)?.len() <= 4096);
    let fixture: Fixture = serde_json::from_slice(&fs::read(&path)?)?;
    let mut pg = tokio_postgres::Config::new();
    pg.host("127.0.0.1")
        .port(fixture.port)
        .user("postgres")
        .password(&fixture.password)
        .dbname("signal_global_feed");
    let (db, connection) =
        tokio::time::timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let driver = tokio::spawn(connection);
    let row = tokio::time::timeout(
        Duration::from_secs(2),
        db.query_one("SELECT store_id,generation FROM signal_control.store", &[]),
    )
    .await??;
    let store: Uuid = row.try_get(0)?;
    let generation: Uuid = row.try_get(1)?;
    let row = tokio::time::timeout(
        Duration::from_secs(2),
        db.query_one(
            "SELECT content FROM signal_control.findings ORDER BY position LIMIT 1",
            &[],
        ),
    )
    .await??;
    let original: Vec<u8> = row.try_get(0)?;
    let reader = Arc::new(ControlClient::catalog(
        ConnectionSettings::fixture_loopback(
            IpAddr::from([127, 0, 0, 1]),
            fixture.port,
            "signal_global_feed".into(),
            "signal_denied".into(),
            fixture.password.as_bytes().to_vec(),
        )?,
    )?);
    let shared = Arc::new(signal_server::shared_feed::SharedFindingsFeed::new(
        reader.clone(),
        store,
        generation,
        1,
        65536,
    )?);
    let policy = AccessPolicy {
        schema_version: 1,
        roles: vec![Role {
            id: "reader".into(),
            permissions: vec![Permission {
                operation: Operation::ReadFindingsFeed,
                scope: ResourceScope::all(),
            }],
        }],
        bindings: vec![SubjectBinding {
            issuer: "https://identity.example.test".into(),
            subject: "reader".into(),
            roles: vec!["reader".into()],
        }],
    }
    .compile()?;
    let identity = IdentityBackend::new(
        IdentityConfig {
            endpoint: std::env::var("SIGNAL_SHARED_HTTP_PROVIDER")?,
            client_id: "synthetic-client".into(),
            client_secret: "synthetic-shared-feed-secret".into(),
            extra_roots: vec![fs::read(&fixture.root_der)?],
            workers: 1,
            max_request_duration: Duration::from_secs(1),
        },
        IntrospectionProfile::new("https://identity.example.test".into(), "signal".into(), 30)?,
        policy,
        tokio::runtime::Handle::current(),
    )?;
    let outbox = crate::audit::tests::root()?;
    let destination_root = crate::audit::tests::root()?;
    let sink = crate::audit::tests::destination(destination_root.path(), 0);
    let audit = crate::audit::Control::test_open(
        outbox.path(),
        sink.clone(),
        vec![Operation::ReadFindingsFeed],
        ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?,
    )
    .await?;
    let stopping = CancellationToken::new();
    let router = router_with_shared_feed(
        shared.clone(),
        IngestConfig::default(),
        1,
        Duration::from_secs(2),
        stopping.clone(),
        Security {
            identity: Some(identity.clone()),
            audit: Some(audit.clone()),
        },
    )?;
    let failed_outbox = crate::audit::tests::root()?;
    let failed_destination = crate::audit::tests::root()?;
    // The destination syncs the completion but loses its acknowledgement. The
    // caller must receive unavailable, never the already computed finding page.
    let failed_sink = crate::audit::tests::destination(failed_destination.path(), 2);
    let failed_audit = crate::audit::Control::test_open(
        failed_outbox.path(),
        failed_sink.clone(),
        vec![Operation::ReadFindingsFeed],
        ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?,
    )
    .await?;
    let failed_router = router_with_shared_feed(
        shared.clone(),
        IngestConfig::default(),
        1,
        Duration::from_secs(2),
        stopping.clone(),
        Security {
            identity: Some(identity.clone()),
            audit: Some(failed_audit),
        },
    )?;
    let tiny = Arc::new(signal_server::shared_feed::SharedFindingsFeed::new(
        reader.clone(),
        store,
        generation,
        1,
        144,
    )?);
    let tiny_router = router_with_shared_feed(
        tiny,
        IngestConfig::default(),
        1,
        Duration::from_secs(2),
        stopping.clone(),
        Security {
            identity: Some(identity.clone()),
            audit: Some(audit.clone()),
        },
    )?;
    let router = router
        .nest("/audit-fail", failed_router)
        .nest("/tiny", tiny_router);
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
        let (status, bytes) =
            response(&client, &base, "/v1/findings/feed?after=begin", "reader").await?;
        assert_eq!(status, 200);
        assert!(
            bytes
                .windows(original.len())
                .any(|window| window == original)
        );
        let first: serde_json::Value = serde_json::from_slice(&bytes)?;
        let next = first["next_cursor"].as_str().ok_or("missing cursor")?;
        assert_eq!(
            next,
            signal_protocol::findings_feed::FindingsCursor::initial(store)?
                .advance(&original)?
                .encode()
        );
        assert_eq!(first["findings"].as_array().map(Vec::len), Some(1));
        assert_eq!(sink.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        let completion: signal_protocol::audit::AuditRecord =
            serde_json::from_slice(&fs::read(destination_root.path().join("2"))?)?;
        assert!(matches!(
            completion.action,
            signal_protocol::audit::Action::OperationCompletion {
                operation: Operation::ReadFindingsFeed,
                completion: signal_protocol::audit::Completion::Success,
                ..
            }
        ));
        let (status, _) = response(
            &client,
            &base,
            &format!("/v1/findings/feed?after={next}"),
            "reader",
        )
        .await?;
        assert_eq!(status, 200);
        for token in ["", "inactive", "expired", "impostor"] {
            let (status, bytes) =
                response(&client, &base, "/v1/findings/feed?after=begin", token).await?;
            assert!(matches!(status, 401 | 403));
            assert!(
                !bytes
                    .windows(original.len())
                    .any(|window| window == original)
            );
        }
        let (status, _) =
            response(&client, &base, "/v1/findings/feed?after=invalid", "reader").await?;
        assert_eq!(status, 400);
        let foreign =
            signal_protocol::findings_feed::FindingsCursor::initial(Uuid::new_v4())?.encode();
        let (status, bytes) = response(
            &client,
            &base,
            &format!("/v1/findings/feed?after={foreign}"),
            "reader",
        )
        .await?;
        assert_eq!(status, 409);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes)?["error"]["code"],
            "cursor_stream_mismatch"
        );
        let divergent = signal_protocol::findings_feed::FindingsCursor::initial(store)?
            .advance(b"different bytes")?
            .encode();
        let (status, bytes) = response(
            &client,
            &base,
            &format!("/v1/findings/feed?after={divergent}"),
            "reader",
        )
        .await?;
        assert_eq!(status, 409);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes)?["error"]["code"],
            "cursor_history_mismatch"
        );
        let (status, _) = response(
            &client,
            &base,
            "/tiny/v1/findings/feed?after=begin",
            "reader",
        )
        .await?;
        assert_eq!(status, 413);
        let (status, bytes) = response(
            &client,
            &base,
            "/audit-fail/v1/findings/feed?after=begin",
            "reader",
        )
        .await?;
        assert_eq!(status, 503);
        assert!(
            !bytes
                .windows(original.len())
                .any(|window| window == original)
        );
        assert_eq!(
            failed_sink.calls.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert!(failed_destination.path().join("2").is_file());
        assert_eq!(shared.metrics().active_callers, 0);
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
    println!("phase: actual-shared-feed-live-http-tls-provider-durable-audit-qualified");
    Ok(())
}

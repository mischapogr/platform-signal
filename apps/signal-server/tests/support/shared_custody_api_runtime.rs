//! Actual API + SDK on mandatory peer TLS and provider-authenticated authority.
use super::*;
use signal_collector_sdk::{
    ExtensionContext,
    object_custody::{CustodyError, ObjectCustodyClient},
};
use signal_ingest::{
    identity::{IdentityBackend, IdentityConfig},
    server::{ServerLimits, TransportState, serve_transport_router},
};
use signal_protocol::access::{AccessPolicy, introspection::IntrospectionProfile};
use signal_server::shared_custody_api::CustodyApi;

pub(super) async fn qualify(
    f: &super::super::super::Fixture,
    token: &LeaseToken,
    original: &ObjectCustodyDescription,
    objects: Arc<ObjectIo>,
    endpoint: &Endpoint,
    db: &tokio_postgres::Client,
) -> Result {
    let policy=AccessPolicy::from_json(br#"{"schema_version":1,"roles":[{"id":"custody","permissions":[{"operation":"confirm_object_custody","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]},{"id":"reader","permissions":[{"operation":"query_events","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]}],"bindings":[{"issuer":"https://identity.example.test","subject":"custodian","roles":["custody"]},{"issuer":"https://identity.example.test","subject":"reader","roles":["reader"]}]}"#)?.compile()?;
    let identity = IdentityBackend::new(
        IdentityConfig {
            endpoint: std::env::var("SIGNAL_SHARED_HTTP_PROVIDER")?,
            client_id: "synthetic-client".into(),
            client_secret: "synthetic-shared-feed-secret".into(),
            extra_roots: vec![std::fs::read(&f.root_der)?],
            workers: 2,
            max_request_duration: Duration::from_secs(3),
        },
        IntrospectionProfile::new("https://identity.example.test".into(), "signal".into(), 10)?,
        policy,
        tokio::runtime::Handle::current(),
    )?;
    let verifier = Arc::new(ConfiguredCustodyVerifier::new(
        CustodyBinding {
            scope: original.scope.clone(),
            backend: original.object.backend_id,
            key_prefix: "custody/original/".into(),
            authority_revision: [7; 32],
            required_until: original.retain_until,
        },
        objects,
    )?);
    let control = Arc::new(super::control(f)?);
    let stop = CancellationToken::new();
    let _stop = stop.clone().drop_guard();
    let api = CustodyApi::new(
        control.clone(),
        token.clone(),
        verifier,
        identity.clone(),
        stop.clone(),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://{}/v1/custody/confirm", listener.local_addr()?);
    let server_tls = signal_ingest::tls::ServerTls::from_private_json(&std::fs::read(
        std::env::var("SIGNAL_CUSTODY_SERVER_TLS")?,
    )?)?;
    let client_material = std::fs::read(std::env::var("SIGNAL_CUSTODY_CLIENT_TLS")?)?;
    let client_tls = || signal_collector_sdk::transport::tls::from_private_json(&client_material);
    let transport = TransportState::independent(stop.clone(), Duration::from_secs(2), false)?;
    let server_stop = stop.clone();
    let callback = stop.clone();
    let server = tokio::spawn(serve_transport_router(
        listener,
        transport,
        api.router(),
        ServerLimits {
            max_connections: 4,
            ..Default::default()
        },
        Arc::new(tokio::sync::Semaphore::new(4)),
        Some(server_tls),
        (move || callback.cancel(), async move {
            server_stop.cancelled().await
        }),
    ));
    let owner = tempfile::tempdir()?;
    let path = owner.path().join("original");
    tokio::fs::write(&path, b"body").await?;
    let context = || ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5));
    let mut d = original.clone();
    d.id = Uuid::from_u128(0xc120);
    let wire = signal_protocol::object_custody::Description::from(&d);
    for bearer in ["reader", "expired", "inactive"] {
        let producer = ObjectCustodyClient::new(
            &url,
            bearer,
            Duration::from_secs(1),
            Some(client_tls()?),
            false,
        )?;
        let before = state(db).await?;
        let reads = endpoint.calls.load(Ordering::SeqCst);
        assert!(matches!(
            producer.confirm(&wire, &context()?).await,
            Err(CustodyError::Unavailable)
        ));
        assert_eq!(state(db).await?, before);
        assert_eq!(endpoint.calls.load(Ordering::SeqCst), reads);
        assert_eq!(tokio::fs::read(&path).await?, b"body");
    }
    let producer = ObjectCustodyClient::new(
        &url,
        "custodian",
        Duration::from_secs(1),
        Some(client_tls()?),
        false,
    )?;
    let permit = producer.confirm(&wire, &context()?).await?;
    assert_eq!(permit.checked_confirmation()?.description, wire);
    assert_eq!(tokio::fs::read(&path).await?, b"body");
    let before = state(db).await?;
    let retry = producer.confirm(&wire, &context()?).await?;
    assert_ne!(
        permit.checked_confirmation()?.request_nonce,
        retry.checked_confirmation()?.request_nonce
    );
    assert_eq!(state(db).await?, before);
    let mut foreign = wire.clone();
    foreign.scope.tenant = "foreign".into();
    let reads = endpoint.calls.load(Ordering::SeqCst);
    assert!(producer.confirm(&foreign, &context()?).await.is_err());
    assert_eq!(state(db).await?, before);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), reads);
    endpoint.mode(1);
    let mut outage = d.clone();
    outage.id = Uuid::from_u128(0xc121);
    let outage = signal_protocol::object_custody::Description::from(&outage);
    assert!(producer.confirm(&outage, &context()?).await.is_err());
    assert_eq!(tokio::fs::read(&path).await?, b"body");
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM signal_control.receipts WHERE id=$1",
            &[&outage.id]
        )
        .await?
        .get::<_, i64>(0),
        1
    );
    endpoint.mode(0);
    let before = state(db).await?;
    producer
        .confirm(&outage, &context()?)
        .await?
        .checked_confirmation()?;
    assert_eq!(state(db).await?, before);
    endpoint.mode(3);
    let short = ObjectCustodyClient::new(
        &url,
        "short",
        Duration::from_secs(1),
        Some(client_tls()?),
        false,
    )?;
    let mut expired = d.clone();
    expired.id = Uuid::from_u128(0xc122);
    let expired = signal_protocol::object_custody::Description::from(&expired);
    assert!(short.confirm(&expired, &context()?).await.is_err());
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM signal_control.receipts WHERE id=$1",
            &[&expired.id]
        )
        .await?
        .get::<_, i64>(0),
        1
    );
    assert_eq!(tokio::fs::read(&path).await?, b"body");
    endpoint.mode(0);
    let restarted = ObjectCustodyClient::new(
        &url,
        "custodian",
        Duration::from_secs(1),
        Some(client_tls()?),
        false,
    )?;
    let release = restarted.confirm(&wire, &context()?).await?;
    release.checked_confirmation()?;
    tokio::fs::remove_file(&path).await?;
    assert!(api.metrics().confirmed >= 4);
    assert!(api.metrics().rejected >= 5);
    assert_eq!(api.metrics().depth, 0);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), server).await???;
    identity
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(3))
        .await?;
    control.shutdown(super::super::context()?).await?;
    assert_eq!(restarted.metrics().depth, 0);
    eprintln!(
        "phase: custody-authenticated-mTLS-API-producer-fresh-replay-denial-expiry-original-qualified"
    );
    Ok(())
}

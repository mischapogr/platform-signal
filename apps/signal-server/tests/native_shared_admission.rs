//! Actual owned owner enrollment, TLS provider authentication, HTTP and durable WAL.
//! Loopback laboratory only; emulated object versions, no AWS or Standard READY.
use signal_buffer::{BufferConfig, DurableBuffer, Policy};
use signal_control::{
    AdministrativeScope, ConnectionSettings, ControlAdministrator, ControlContext, ControlError,
    FindingScopeAdministrator, FindingScopeLimits, FindingScopeProfile, InitializeInput,
    MigrationInput, ProducerEnrollment, Scope, schema_identity,
};
use signal_event::IngestEvent;
use signal_ingest::{
    IngestConfig, IngestService,
    identity::{IdentityBackend, IdentityConfig, IdentityContext},
    server::{ServerLimits, serve},
};
use signal_protocol::{
    AdmissionError, EventSink, IngestResponse,
    access::{AccessPolicy, introspection::IntrospectionProfile},
};
use signal_server::{shared_admission::SharedAdmission, shared_recovery::RECOVERY_BYTES};
use std::{fs, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DB: &str = "signal_native_admission";
#[path = "support/native_scoped_publication.rs"]
mod publication;
#[path = "support/native_scoped_read.rs"]
mod scoped_read;
#[path = "support/versions.rs"]
mod versions;
#[derive(serde::Deserialize)]
struct Fixture {
    port: u16,
    password: String,
    root_der: String,
}
fn context() -> std::result::Result<ControlContext, ControlError> {
    ControlContext::new(Duration::from_secs(5))
}
fn settings(f: &Fixture) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        DB.into(),
        "signal_migrator".into(),
        f.password.as_bytes().to_vec(),
    )
}
fn input(id: u128, account: &str) -> serde_json::Value {
    serde_json::json!({"id":Uuid::from_u128(id),"timestamp":chrono::Utc::now().to_rfc3339(),
        "source":{"type":"audit"},"message":"native admission",
        "resource":{"kind":"host","id":"host-a","account_id":account},
        "attributes":{"account_id":"a","roles":["administrator"],"nested":{"keep":[true,7]}}})
}
async fn post(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    value: serde_json::Value,
) -> Result<(u16, IngestResponse)> {
    let mut request = client
        .post(format!("{base}/v1/events"))
        .header("x-forwarded-user", "producer")
        .header("x-forwarded-roles", "administrator")
        .json(&value);
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;
    assert!(bytes.len() <= 65536);
    Ok((status, serde_json::from_slice(&bytes)?))
}
async fn grant(
    identity: &IdentityBackend,
    token: &str,
) -> Result<signal_protocol::access::RequestGrant> {
    Ok(identity
        .authenticate(
            token,
            IdentityContext {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation: CancellationToken::new(),
            },
        )
        .await?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "owned PostgreSQL and finite TLS provider launched by check-shared-runtime.py"]
async fn native_owner_provider_http_wal_admission() -> Result {
    let path = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?);
    assert!(fs::metadata(&path)?.len() <= 4096);
    let f: Fixture = serde_json::from_slice(&fs::read(path)?)?;
    let mut pg = tokio_postgres::Config::new();
    pg.host("127.0.0.1")
        .port(f.port)
        .user("postgres")
        .password(&f.password);
    let (root_db, connection) =
        timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let root_driver = tokio::spawn(connection);
    timeout(
        Duration::from_secs(2),
        root_db.batch_execute(&format!("CREATE DATABASE {DB}")),
    )
    .await??;
    timeout(
        Duration::from_secs(2),
        root_db.batch_execute(&format!(
            "GRANT CREATE ON DATABASE {DB} TO signal_control_owner"
        )),
    )
    .await??;
    drop(root_db);
    timeout(Duration::from_secs(2), root_driver).await???;
    pg.dbname(DB);
    let (db, connection) =
        timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let driver = tokio::spawn(connection);
    let root = tempfile::tempdir()?;
    let cfg = BufferConfig {
        directory: root.path().join("wal"),
        max_events: 2,
        policy: Policy::BlockWithTimeout,
        operation_timeout: Duration::from_secs(5),
        block_timeout: Duration::from_secs(4),
        ..Default::default()
    };
    let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
    // An existing pre-enrollment row remains legacy; startup must capture it.
    let legacy: IngestEvent = serde_json::from_value(input(801, "legacy"))?;
    wal.admit(legacy.normalize("0000-01-01T00:00:60.999999999Z".parse()?)?)
        .await?;
    let producer = ProducerEnrollment {
        scope: Scope {
            schema_version: 1,
            store_id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            tenant: "synthetic-native-admission".into(),
            stream: wal.snapshot().stream_id,
            partition_id: Uuid::new_v4(),
        },
        scope_generation: Uuid::new_v4(),
        startup: Uuid::new_v4(),
        wal_floor: 1,
    };
    let authority = AdministrativeScope {
        schema_version: 1,
        store_id: producer.scope.store_id,
        generation: producer.scope.generation,
    };
    let installer = ControlAdministrator::new(settings(&f)?, "signal_control_owner".into())?;
    installer
        .initialize(
            InitializeInput {
                scope: authority.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    installer
        .migrate_catalog(
            MigrationInput {
                scope: authority.clone(),
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    installer.shutdown(context()?).await?;
    timeout(Duration::from_secs(2),db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",
        &[&producer.scope.partition_id,&producer.scope.tenant,&producer.scope.stream])).await??;
    timeout(
        Duration::from_secs(2),
        db.batch_execute("SET ROLE signal_control_owner"),
    )
    .await??;
    timeout(
        Duration::from_secs(2),
        db.batch_execute(include_str!(
            "../../../schemas/shared-control/007-finding-scope.sql"
        )),
    )
    .await??;
    timeout(
        Duration::from_secs(2),
        db.batch_execute(include_str!(
            "../../../schemas/shared-control/008-scoped-publication.sql"
        )),
    )
    .await??;
    timeout(Duration::from_secs(2), db.batch_execute("RESET ROLE")).await??;
    let owner = FindingScopeAdministrator::new(
        settings(&f)?,
        "signal_control_owner".into(),
        FindingScopeProfile::Catalog4Scoped,
    )?;
    let activation = owner
        .activate(
            authority,
            producer.scope_generation,
            FindingScopeLimits {
                producers: 1,
                rows: 128,
                bytes: 131072,
            },
            context()?,
        )
        .await?;
    assert!(matches!(
        SharedAdmission::new(wal.clone(), activation),
        Err(ControlError::Invalid)
    ));
    let pin = owner.enroll(producer.clone(), context()?).await?;
    let foreign = Arc::new(
        DurableBuffer::open_with_recovery(
            BufferConfig {
                directory: root.path().join("foreign"),
                ..Default::default()
            },
            RECOVERY_BYTES,
        )
        .await?,
    );
    assert!(matches!(
        SharedAdmission::new(foreign.clone(), pin),
        Err(ControlError::Fenced)
    ));
    foreign.shutdown().await?;
    let inspected = SharedAdmission::new(
        wal.clone(),
        owner
            .inspect(
                producer.scope.clone(),
                producer.scope_generation,
                context()?,
            )
            .await?,
    )?;
    assert_eq!(inspected.enrollment().startup, producer.startup);
    assert_eq!(inspected.enrollment().wal_floor, 1);
    drop(inspected);
    let canceled = context()?;
    let pin = owner.enroll(producer.clone(), canceled.clone()).await?;
    canceled.cancel();
    assert!(matches!(
        SharedAdmission::new(wal.clone(), pin),
        Err(ControlError::Cancelled)
    ));
    wal.shutdown().await?;
    let missing = Arc::new(DurableBuffer::open(cfg.clone()).await?);
    assert!(matches!(
        SharedAdmission::new(
            missing.clone(),
            owner.enroll(producer.clone(), context()?).await?
        ),
        Err(ControlError::Invalid)
    ));
    missing.shutdown().await?;
    let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
    let native = Arc::new(SharedAdmission::new(
        wal.clone(),
        owner.enroll(producer.clone(), context()?).await?,
    )?);
    assert_eq!(native.enrollment().wal_floor, 1);
    let policy = AccessPolicy::from_json(br#"{"schema_version":1,"roles":[{"id":"producer","permissions":[{"operation":"ingest_events","scope":{"sources":{"mode":"only","values":["audit"]},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"only","values":["host-a"]}}}]},{"id":"reader","permissions":[{"operation":"query_events","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}},{"operation":"read_findings","scope":{"sources":{"mode":"only","values":["audit"]},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"only","values":["host-a"]}}}]},{"id":"all-reader","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]},{"id":"paired-one","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"only","values":["audit"]},"accounts":{"mode":"only","values":["b"]},"resources":{"mode":"all"}}}]},{"id":"paired-two","permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"all"},"accounts":{"mode":"only","values":["a"]},"resources":{"mode":"only","values":["host-b"]}}}]}],"bindings":[{"issuer":"https://identity.example.test","subject":"producer","roles":["producer"]},{"issuer":"https://identity.example.test","subject":"reader","roles":["reader"]},{"issuer":"https://identity.example.test","subject":"all-reader","roles":["all-reader"]},{"issuer":"https://identity.example.test","subject":"paired-reader","roles":["paired-one","paired-two"]}]}"#)?.compile()?;
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
    let service = IngestService::new_with_identity(
        IngestConfig {
            request_timeout: Duration::from_millis(200),
            ..Default::default()
        },
        native.clone(),
        identity.clone(),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let stopping = CancellationToken::new();
    let shutdown = stopping.clone();
    let server = tokio::spawn(serve(
        listener,
        service,
        ServerLimits {
            max_connections: 4,
            connection_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(2),
        },
        shutdown.cancelled_owned(),
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?;
    let test: Result<Vec<(u64, Vec<u8>)>> = async {
        for token in ["", "inactive", "expired", "impostor", "reader"] {
            let (status, response) = post(&client, &base, token, input(802, "a")).await?;
            assert!(matches!(status, 401 | 403));
            assert_eq!(response.accepted, 0);
        }
        let (status, response) = post(&client, &base, "producer", input(802, "b")).await?;
        assert_eq!(status, 403);
        assert_eq!(response.accepted, 0);
        assert_eq!(wal.snapshot().last_sequence, 1);
        let raw: IngestEvent = serde_json::from_value(input(802, "a"))?;
        assert_eq!(
            native.admit(raw.normalize(chrono::Utc::now())?).await,
            Err(AdmissionError::Unavailable)
        );
        let bootstrap = IngestService::new(
            IngestConfig {
                api_token: Some("bootstrap".into()),
                ..Default::default()
            },
            native.clone(),
        )?;
        use tower::ServiceExt;
        let response = bootstrap
            .router()
            .oneshot(
                axum::http::Request::post("/v1/events")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer bootstrap")
                    .body(axum::body::Body::from(serde_json::to_vec(&input(
                        802, "a",
                    ))?))?,
            )
            .await?;
        assert_eq!(response.status().as_u16(), 503);
        assert_eq!(wal.snapshot().last_sequence, 1);
        let (status, response) = post(&client, &base, "producer", input(802, "a")).await?;
        assert_eq!(status, 202);
        assert_eq!(response.accepted, 1);
        assert_eq!(response.event_ids, vec![Uuid::from_u128(802)]);
        assert_eq!(wal.snapshot().checkpoint, 0);
        assert_eq!(wal.snapshot().last_sequence, 2);
        let original = wal
            .read_batch(2, 65536)
            .await?
            .into_iter()
            .map(|row| Ok((row.sequence, serde_json::to_vec(&row.event)?)))
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;
        assert_eq!(native.enrollment().wal_floor, 1);
        assert!(matches!(
            SharedAdmission::new(
                wal.clone(),
                owner.enroll(producer.clone(), context()?).await?
            ),
            Err(ControlError::Fenced)
        ));
        let allowed = grant(&identity, "producer").await?;
        let expired: IngestEvent = serde_json::from_value(input(803, "a"))?;
        assert_eq!(
            native
                .admit_with_grant(
                    expired.normalize(chrono::Utc::now())?,
                    &allowed,
                    std::time::Instant::now()
                )
                .await,
            Err(AdmissionError::Unavailable)
        );
        let started = Instant::now();
        let (status, response) = post(&client, &base, "producer", input(803, "a")).await?;
        assert!(matches!(status, 408 | 429));
        assert_eq!(response.accepted, 0);
        assert!(started.elapsed() < Duration::from_secs(1));
        let short = grant(&identity, "short").await?;
        let started = Instant::now();
        let expires: IngestEvent = serde_json::from_value(input(804, "a"))?;
        assert_eq!(
            native
                .admit_with_grant(
                    expires.normalize(chrono::Utc::now())?,
                    &short,
                    std::time::Instant::now() + Duration::from_secs(4)
                )
                .await,
            Err(AdmissionError::Full)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(native.admission_metrics().active, 0);
        assert_eq!(native.admission_metrics().accepted, 1);
        assert_eq!(wal.snapshot().last_sequence, 2);
        Ok(original)
    }
    .await;
    stopping.cancel();
    timeout(Duration::from_secs(3), server).await???;
    owner.shutdown(context()?).await?;
    wal.shutdown().await?;
    drop(db);
    timeout(Duration::from_secs(2), driver).await???;
    let original = test?;
    let replay = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
    let rows = replay.read_batch(2, 65536).await?;
    let replayed = rows
        .iter()
        .map(|row| Ok((row.sequence, serde_json::to_vec(&row.event)?)))
        .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;
    assert_eq!(replayed, original);
    assert_eq!(
        rows.iter()
            .map(|r| (r.sequence, r.event.id))
            .collect::<Vec<_>>(),
        vec![(1, Uuid::from_u128(801)), (2, Uuid::from_u128(802))]
    );
    assert_eq!(
        rows[1].event.attributes["nested"]["keep"],
        serde_json::json!([true, 7])
    );
    assert_eq!(
        rows[1].event.attributes["roles"],
        serde_json::json!(["administrator"])
    );
    assert_eq!(
        rows[0]
            .event
            .resource
            .as_ref()
            .and_then(|r| r.account_id.as_deref()),
        Some("legacy")
    );
    assert_eq!(replay.snapshot().checkpoint, 0);
    publication::qualify(&f, &producer, &identity, replay.clone(), cfg).await?;
    identity
        .shutdown(Instant::now() + Duration::from_secs(2))
        .await?;
    replay.shutdown().await?;
    println!("phase: actual-owner-native-provider-http-wal-floor-deadline-expiry-replay-qualified");
    Ok(())
}

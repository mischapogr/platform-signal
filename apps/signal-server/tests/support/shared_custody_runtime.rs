//! Composed actual PostgreSQL TLS + signed S3 protocol; provider retention simulated.
use super::*;
use signal_control::{
    AdministrativeScope, ControlAdministrator, InitializeInput, coordinate_object_custody,
};
use signal_storage::{
    OperationContext,
    object_manifest::sha256,
    object_s3::{S3Config, S3Credentials, build, build_custody_reader},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;
type FixtureResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct Endpoint {
    url: String,
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<FixtureResult>>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Endpoint {
    async fn start(directory: std::path::PathBuf, horizon: chrono::DateTime<Utc>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let mode = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let m = mode.clone();
        let c = calls.clone();
        let cancellation = stop.clone();
        let task: tokio::task::JoinHandle<FixtureResult> = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(60),async {
                for _ in 0..64 {
                    let (mut socket,_)=tokio::select! { _=cancellation.cancelled()=>return Ok(()), accepted=listener.accept()=>accepted? };
                    let mut head=Vec::new();
                    tokio::time::timeout(Duration::from_secs(3),async {
                        while !head.ends_with(b"\r\n\r\n") { if head.len()>=8192 {return Err("request headers full".into());} head.push(socket.read_u8().await?); }
                        Ok::<(),Box<dyn std::error::Error+Send+Sync>>(())
                    }).await??;
                    let text=std::str::from_utf8(&head)?;
                    let mut parts=text.lines().next().ok_or("request line")?.split_whitespace();
                    assert_eq!(parts.next(),Some("GET"));
                    let uri=reqwest::Url::parse(&format!("http://127.0.0.1{}",parts.next().ok_or("request target")?))?;
                    assert_eq!(uri.path(),"/synthetic-custody/custody/original/source");
                    let pairs=uri.query_pairs().collect::<Vec<_>>();assert_eq!(pairs.len(),1);assert_eq!(pairs[0].0,"versionId");
                    let version=pairs[0].1.as_ref();assert!(matches!(version,"v1"|"v2"));
                    let lower=text.to_ascii_lowercase();assert!(lower.contains("x-amz-expected-bucket-owner: 123456789012"));assert!(lower.contains("authorization: aws4-hmac-sha256"));
                    let call=c.fetch_add(1,Ordering::SeqCst);let mode=m.load(Ordering::SeqCst);
                    let denied=mode==1&&call==1;
                    let body=if denied {Vec::new()} else {tokio::fs::read(directory.join(version)).await?};assert!(body.len()<=16);
                    let lock=if mode==2 {"GOVERNANCE"}else{"COMPLIANCE"};
                    let reply=format!("HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nx-amz-version-id: {version}\r\nx-amz-object-lock-mode: {lock}\r\nx-amz-object-lock-retain-until-date: {}\r\nConnection: close\r\n\r\n",if denied {403}else{200},body.len(),horizon.to_rfc3339());
                    socket.write_all(reply.as_bytes()).await?;socket.write_all(&body).await?;socket.shutdown().await?;
                }
                Err("request fixture capacity exceeded".into())
            }).await?
        });
        Ok(Self {
            url,
            mode,
            calls,
            stop,
            task: Some(task),
        })
    }
    fn mode(&self, mode: usize) {
        self.calls.store(0, Ordering::SeqCst);
        self.mode.store(mode, Ordering::SeqCst);
    }
    async fn finish(&mut self) -> Result {
        self.stop.cancel();
        let task = self.task.take().ok_or("fixture task missing")?;
        tokio::time::timeout(Duration::from_secs(3), task)
            .await??
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }
}
fn control(f: &super::super::Fixture) -> Result<ControlClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(std::fs::read(
        &f.root_der,
    )?))?;
    Ok(ControlClient::new(ConnectionSettings::tls(
        "signal-control.invalid".into(),
        Some("127.0.0.1".parse()?),
        f.port,
        super::super::DATABASE.into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
        roots,
    )?)?)
}
async fn state(db: &tokio_postgres::Client) -> Result<serde_json::Value> {
    Ok(db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM signal_control.receipts r),'partitions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p))",&[]).await?.get(0))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "owned PostgreSQL TLS/S3 composed custody fixture only"]
async fn postgres_tls_s3_configured_custody() -> Result {
    let path = std::env::var("SIGNAL_CONTROL_FIXTURE")?;
    assert!(std::fs::metadata(&path)?.len() <= 4096);
    let f: super::super::Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert!(f.password.starts_with("synthetic-control-") && f.password.len() <= 64);
    let (root, driver) = super::super::database(&f, "postgres").await?;
    root.batch_execute(&format!("CREATE DATABASE {}", super::super::DATABASE))
        .await?;
    root.batch_execute(&format!(
        "GRANT CREATE ON DATABASE {} TO signal_control_owner",
        super::super::DATABASE
    ))
    .await?;
    drop(root);
    driver.await??;
    let b = binding();
    let scope = b.scope.clone();
    let horizon = b.required_until;
    let backend = b.backend;
    let administrator = ControlAdministrator::new(
        super::super::settings(&f, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    administrator
        .initialize(
            InitializeInput {
                scope: AdministrativeScope {
                    schema_version: 1,
                    store_id: scope.store_id,
                    generation: scope.generation,
                },
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    administrator.shutdown(context()?).await?;
    let (db, driver) = super::super::database(&f, super::super::DATABASE).await?;
    db.execute(
        "INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",
        &[&scope.partition_id, &scope.tenant, &scope.stream],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.principals VALUES('signal_runtime',$1,$2,$3)",
        &[&scope.tenant, &scope.stream, &scope.partition_id],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-custody-s3-fixture')",
        &[&backend],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,'custody/original/')",
        &[&scope.partition_id, &backend],
    )
    .await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let client = control(&f)?;
    let token = client
        .acquire(scope, Uuid::from_u128(0xc106), 60000, context()?)
        .await?;
    let archive = tempfile::tempdir()?;
    let producer = tempfile::tempdir()?;
    let original = producer.path().join("original");
    tokio::fs::write(&original, b"body").await?;
    tokio::fs::write(archive.path().join("v1"), b"body").await?;
    tokio::fs::write(archive.path().join("v2"), b"next").await?;
    let mut endpoint =
        Endpoint::start(archive.path().into(), horizon + ChronoDuration::hours(1)).await?;
    let cfg = S3Config {
        endpoint: endpoint.url.clone(),
        region: "eu-central-1".into(),
        bucket: "synthetic-custody".into(),
        max_object_bytes: 1024,
        allow_loopback_http: true,
    };
    let credentials = S3Credentials {
        access_key: "synthetic-access".into(),
        secret_key: "synthetic-secret".into(),
        session_token: None,
    };
    let (store, _) = build(&cfg, &credentials)?;
    let (reader, observer) = build_custody_reader(&cfg, &credentials, "123456789012")?;
    let objects = Arc::new(ObjectIo::remote_retained(
        Arc::new(store),
        reader,
        tokio::runtime::Handle::current(),
        ObjectIoLimits {
            bytes: 1024,
            ..Default::default()
        },
    )?);
    let verifier = ConfiguredCustodyVerifier::new(b, objects.clone())?;
    let d = description(horizon);
    coordinate_object_custody(
        &client,
        &verifier,
        token.clone(),
        d.clone(),
        verifier.authority_revision(),
        context()?,
    )
    .await?
    .checked_receipt()?
    .validate()?;
    assert_eq!(tokio::fs::read(&original).await?, b"body");
    let before = state(&db).await?;
    coordinate_object_custody(
        &client,
        &verifier,
        token.clone(),
        d.clone(),
        verifier.authority_revision(),
        context()?,
    )
    .await?
    .checked_receipt()?;
    assert_eq!(state(&db).await?, before);
    let mut conflict = d.clone();
    conflict.object.version = "v2".into();
    conflict.sha256 = sha256(b"next");
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            conflict,
            verifier.authority_revision(),
            context()?
        )
        .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(state(&db).await?, before);
    eprintln!("phase: composed-custody-real-PG-TLS-signed-S3-exact-replay-conflict-qualified");
    endpoint.mode(1);
    let mut outage = d.clone();
    outage.id = Uuid::from_u128(0xc107);
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            outage.clone(),
            verifier.authority_revision(),
            context()?
        )
        .await,
        Err(ControlError::Unavailable)
    ));
    assert_eq!(tokio::fs::read(&original).await?, b"body");
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
    let before = state(&db).await?;
    coordinate_object_custody(
        &client,
        &verifier,
        token.clone(),
        outage,
        verifier.authority_revision(),
        context()?,
    )
    .await?
    .checked_receipt()?;
    assert_eq!(state(&db).await?, before);
    endpoint.mode(2);
    let before = state(&db).await?;
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            d.clone(),
            verifier.authority_revision(),
            context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(state(&db).await?, before);
    endpoint.mode(0);
    db.batch_execute("UPDATE signal_control.store SET max_rows=used_rows")
        .await?;
    let mut full = d.clone();
    full.id = Uuid::from_u128(0xc108);
    let before = state(&db).await?;
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            full,
            verifier.authority_revision(),
            context()?
        )
        .await,
        Err(ControlError::Full)
    ));
    assert_eq!(state(&db).await?, before);
    db.batch_execute("UPDATE signal_control.store SET max_rows=65536")
        .await?;
    eprintln!(
        "phase: composed-custody-postcommit-denial-governance-quota-original-retained-qualified"
    );
    // Observe actual deferred COMMIT before cancellation, then physically drain
    // the control worker before inspecting or retrying that exact request.
    db.batch_execute("CREATE FUNCTION public.custody_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER custody_commit_delay AFTER INSERT ON signal_control.receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.custody_commit_delay()").await?;
    let mut uncertain = d.clone();
    uncertain.id = Uuid::from_u128(0xc110);
    let ctx = context()?;
    let (result, observed) = tokio::join!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            uncertain.clone(),
            verifier.authority_revision(),
            ctx.clone()
        ),
        async {
            let observed=tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                if db.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=$1 AND application_name='signal-control' AND state='active' AND query='COMMIT' AND wait_event='PgSleep'",&[&super::super::DATABASE]).await?.get::<_,i64>(0)==1 {return Ok::<(),tokio_postgres::Error>(());}
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
            ctx.cancel();
            observed??;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
    );
    observed?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    assert_eq!(tokio::fs::read(&original).await?, b"body");
    tokio::time::timeout(Duration::from_secs(3), async {
        while client.metrics().active != 0 || client.metrics().queue_depth != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM signal_control.receipts WHERE id=$1",
            &[&uncertain.id]
        )
        .await?
        .get::<_, i64>(0),
        1
    );
    db.batch_execute("DROP TRIGGER custody_commit_delay ON signal_control.receipts; DROP FUNCTION public.custody_commit_delay()").await?;
    let before = state(&db).await?;
    coordinate_object_custody(
        &client,
        &verifier,
        token.clone(),
        uncertain,
        verifier.authority_revision(),
        context()?,
    )
    .await?
    .checked_receipt()?;
    assert_eq!(state(&db).await?, before);
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            d.clone(),
            [8; 32],
            context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(state(&db).await?, before);
    eprintln!("phase: composed-custody-observed-COMMIT-physical-drain-same-id-authority-qualified");
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&d.scope.partition_id]).await?;
    let next = client
        .acquire(d.scope.clone(), Uuid::from_u128(0xc109), 60000, context()?)
        .await?;
    assert!(next.epoch > token.epoch);
    let before = state(&db).await?;
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token,
            d.clone(),
            verifier.authority_revision(),
            context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(state(&db).await?, before);
    assert_eq!(tokio::fs::read(&original).await?, b"body");
    client.shutdown(context()?).await?;
    let reopened = control(&f)?;
    let permit = coordinate_object_custody(
        &reopened,
        &verifier,
        next,
        d,
        verifier.authority_revision(),
        context()?,
    )
    .await?;
    assert_eq!(state(&db).await?, before);
    permit.checked_receipt()?.validate()?;
    tokio::fs::remove_file(&original).await?;
    assert_eq!(tokio::fs::read(archive.path().join("v1")).await?, b"body");
    reopened.shutdown(context()?).await?;
    objects
        .shutdown(OperationContext::new(Duration::from_secs(3)))
        .await?;
    assert_eq!(observer.metrics().depth, 0);
    assert_eq!(objects.metrics().running, 0);
    endpoint.finish().await?;
    drop(db);
    tokio::time::timeout(Duration::from_secs(3), driver).await???;
    eprintln!(
        "phase: composed-custody-current-owner-reopen-checked-permit-independent-original-qualified"
    );
    Ok(())
}

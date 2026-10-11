//! Real owned PostgreSQL TLS and immutable files; retention authority is simulated.
use chrono::Utc;
use sha2::{Digest, Sha256};
use signal_control::{
    CanonicalObjectRef, ConnectionSettings, ControlClient, ControlContext, ControlError,
    CustodyFuture, LeaseToken, ObjectCustodyDescription, ObjectCustodyVerifier,
    RetainedObjectObservation, coordinate_object_custody,
};
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;

fn runtime(f: &super::Fixture) -> Result<ControlClient, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(std::fs::read(
        &f.root_der,
    )?))?;
    Ok(ControlClient::new(ConnectionSettings::tls(
        "signal-control.invalid".into(),
        Some(IpAddr::from([127, 0, 0, 1])),
        f.port,
        "postgres".into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
        roots,
    )?)?)
}
struct Files<'a> {
    directory: PathBuf,
    horizon: chrono::DateTime<Utc>,
    db: &'a Client,
    runtime: &'a ControlClient,
    calls: AtomicUsize,
    mode: AtomicUsize,
    takeover: Mutex<Option<LeaseToken>>,
}
impl ObjectCustodyVerifier for Files<'_> {
    fn verify<'a>(
        &'a self,
        description: &'a ObjectCustodyDescription,
        context: ControlContext,
    ) -> CustodyFuture<'a, RetainedObjectObservation> {
        Box::pin(async move {
            context.check()?;
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.mode.load(Ordering::SeqCst) == 1 && call == 1 {
                return Err(ControlError::Unavailable);
            }
            if description.scope != super::scope()
                || description.object.backend_id != Uuid::from_u128(20)
                || description.object.key != "custody/synthetic/original"
                || !matches!(description.object.version.as_str(), "v1" | "v2")
            {
                return Err(ControlError::Fenced);
            }
            let path = self.directory.join(&description.object.version);
            let metadata = tokio::fs::symlink_metadata(&path)
                .await
                .map_err(|_| ControlError::Unavailable)?;
            if !metadata.is_file() || metadata.len() != description.bytes || metadata.len() > 128 {
                return Err(ControlError::Corrupt);
            }
            let bytes = tokio::fs::read(path)
                .await
                .map_err(|_| ControlError::Unavailable)?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != description.sha256 {
                return Err(ControlError::Corrupt);
            }
            if self.mode.load(Ordering::SeqCst) == 2 && call == 1 {
                self.db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",
                    &[&description.scope.partition_id]).await.map_err(|_| ControlError::Unavailable)?;
                let next = self
                    .runtime
                    .acquire(
                        description.scope.clone(),
                        Uuid::from_u128(11),
                        60000,
                        context.clone(),
                    )
                    .await?;
                *self.takeover.lock().map_err(|_| ControlError::Corrupt)? = Some(next);
            }
            context.check()?;
            // Explicit laboratory authority, not a filesystem/provider retention claim.
            Ok(RetainedObjectObservation {
                description_sha256: description.digest()?,
                authority_revision: [1; 32],
                observed_at: Utc::now(),
                retained_until: self.horizon,
            })
        })
    }
}
impl Files<'_> {
    fn mode(&self, mode: usize) {
        self.mode.store(mode, Ordering::SeqCst);
        self.calls.store(0, Ordering::SeqCst);
    }
}
async fn state(db: &Client) -> Result<serde_json::Value, Error> {
    Ok(db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM signal_control.receipts r),'partitions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p))",&[]).await?.get(0))
}
pub(super) async fn qualify(f: &super::Fixture) -> Result<(), Error> {
    let (db, driver) = super::admin(f).await?;
    let administrative = signal_control::ControlAdministrator::new(
        ConnectionSettings::fixture_loopback(
            IpAddr::from([127, 0, 0, 1]),
            f.port,
            "postgres".into(),
            "signal_migrator".into(),
            f.password.as_bytes().to_vec(),
        )?,
        "signal_control_owner".into(),
    )?;
    let scope = super::scope();
    administrative
        .migrate(
            signal_control::MigrationInput {
                scope: signal_control::AdministrativeScope {
                    schema_version: 1,
                    store_id: scope.store_id,
                    generation: scope.generation,
                },
                source_revision: 1,
                source_sha256: signal_control::legacy_identity(),
            },
            super::context()?,
        )
        .await?;
    administrative.shutdown(super::context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    let client = runtime(f)?;
    let token = client
        .acquire(scope.clone(), Uuid::from_u128(10), 60000, super::context()?)
        .await?;
    let archive = tempfile::tempdir()?;
    let producer = tempfile::tempdir()?;
    let original = producer.path().join("original");
    let bytes = b"exact independent custody payload";
    tokio::fs::write(&original, bytes).await?;
    tokio::fs::write(archive.path().join("v1"), bytes).await?;
    let horizon = Utc::now() + chrono::Duration::hours(1);
    let verifier = Files {
        directory: archive.path().into(),
        horizon,
        db: &db,
        runtime: &client,
        calls: AtomicUsize::new(0),
        mode: AtomicUsize::new(0),
        takeover: Mutex::new(None),
    };
    let description = ObjectCustodyDescription {
        schema_version: 1,
        id: Uuid::from_u128(0xc001),
        scope,
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id: Uuid::from_u128(20),
            key: "custody/synthetic/original".into(),
            version: "v1".into(),
        },
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        retain_until: horizon,
    };
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.receipts", &[])
            .await?
            .get::<_, i64>(0),
        0
    );
    let permit = coordinate_object_custody(
        &client,
        &verifier,
        token.clone(),
        description.clone(),
        [1; 32],
        super::context()?,
    )
    .await?;
    permit.checked_receipt()?.validate()?;
    let committed = state(&db).await?;
    assert_eq!(tokio::fs::read(&original).await?, bytes);
    coordinate_object_custody(
        &client,
        &verifier,
        token.clone(),
        description.clone(),
        [1; 32],
        super::context()?,
    )
    .await?
    .checked_receipt()?;
    assert_eq!(state(&db).await?, committed);
    let changed = b"different independently retained bytes";
    tokio::fs::write(archive.path().join("v2"), changed).await?;
    let mut conflict = description.clone();
    conflict.object.version = "v2".into();
    conflict.bytes = changed.len() as u64;
    conflict.sha256 = Sha256::digest(changed).into();
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            conflict,
            [1; 32],
            super::context()?
        )
        .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(state(&db).await?, committed);
    eprintln!("phase: custody-real-postgres-TLS-exact-replay-conflict-original-copy-qualified");

    // Observe actual deferred COMMIT before cancellation; retain original while
    // the physically owned control worker drains its unknown outcome.
    db.batch_execute("CREATE FUNCTION public.custody_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER custody_commit_delay AFTER INSERT ON signal_control.receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.custody_commit_delay()").await?;
    let mut uncertain = description.clone();
    uncertain.id = Uuid::from_u128(0xc002);
    let ctx = super::context()?;
    let (result, observed) = tokio::join!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            uncertain.clone(),
            [1; 32],
            ctx.clone()
        ),
        super::cancel_delayed_commit(&db, &ctx)
    );
    observed?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    assert_eq!(tokio::fs::read(&original).await?, bytes);
    super::idle(&client).await?;
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
        uncertain.clone(),
        [1; 32],
        super::context()?,
    )
    .await?
    .checked_receipt()?;
    assert_eq!(state(&db).await?, before);
    eprintln!("phase: custody-observed-COMMIT-cancel-physical-drain-same-request-qualified");

    verifier.mode(1);
    let mut outage = description.clone();
    outage.id = Uuid::from_u128(0xc003);
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            outage,
            [1; 32],
            super::context()?
        )
        .await,
        Err(ControlError::Unavailable)
    ));
    assert_eq!(tokio::fs::read(&original).await?, bytes);
    verifier.mode(0);
    db.batch_execute("UPDATE signal_control.store SET max_rows=used_rows")
        .await?;
    let quota_before = state(&db).await?;
    let mut full = description.clone();
    full.id = Uuid::from_u128(0xc004);
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            full,
            [1; 32],
            super::context()?
        )
        .await,
        Err(ControlError::Full)
    ));
    assert_eq!(state(&db).await?, quota_before);
    db.batch_execute("UPDATE signal_control.store SET max_rows=65536")
        .await?;
    verifier.mode(2);
    let mut fenced = description.clone();
    fenced.id = Uuid::from_u128(0xc005);
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token.clone(),
            fenced,
            [1; 32],
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    let next = verifier
        .takeover
        .lock()
        .map_err(|_| "takeover lock")?
        .clone()
        .ok_or("takeover missing")?;
    assert!(next.epoch > token.epoch);
    verifier.mode(0);
    let fenced_before = state(&db).await?;
    assert!(matches!(
        coordinate_object_custody(
            &client,
            &verifier,
            token,
            description.clone(),
            [1; 32],
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(state(&db).await?, fenced_before);
    assert_eq!(tokio::fs::read(&original).await?, bytes);
    eprintln!(
        "phase: custody-real-quota-postcommit-outage-competing-owner-original-retained-qualified"
    );

    client.shutdown(super::context()?).await?;
    let reopened = runtime(f)?;
    let before = state(&db).await?;
    coordinate_object_custody(
        &reopened,
        &verifier,
        next,
        description.clone(),
        [1; 32],
        super::context()?,
    )
    .await?
    .checked_receipt()?;
    assert_eq!(state(&db).await?, before);
    tokio::fs::remove_file(&original).await?;
    assert_eq!(tokio::fs::read(archive.path().join("v1")).await?, bytes);
    reopened.shutdown(super::context()?).await?;
    eprintln!("phase: custody-fresh-control-reopen-original-id-verified-archive-release-qualified");
    drop(db);
    tokio::time::timeout(std::time::Duration::from_secs(2), driver).await??;
    Ok(())
}

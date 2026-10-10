//! Owned producer processes and actual PostgreSQL failure boundaries.
use sha2::{Digest, Sha256};
use signal_control::*;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio_postgres::Client;
use uuid::Uuid;

type Error = Box<dyn std::error::Error>;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Work {
    token: LeaseToken,
    publication: PublicationInput,
    mode: String,
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Owned test process only. SIGKILL is followed by reaping on every path.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn stopped(db: &Client) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if db.query_one("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='signal-control' AND state='active')", &[]).await?.get::<_,bool>(0) {
                return Ok::<(),tokio_postgres::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}
async fn observed(db: &Client, commit: bool) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='signal-control' AND state='active' AND wait_event='PgSleep' AND (query='COMMIT')=$1)", &[&commit]).await?.get::<_,bool>(0) {
                return Ok::<(),tokio_postgres::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}
async fn marker(path: &Path, expected: &[u8]) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match fs::read(path) {
                Ok(bytes) if bytes == expected => return Ok::<(), std::io::Error>(()),
                Ok(_) => return Err(std::io::Error::other("invalid owned worker marker")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok(())
}
fn start(root: &Path, work: &Work) -> Result<OwnedChild, Error> {
    fs::write(root.join("work.json"), serde_json::to_vec(work)?)?;
    let log = fs::File::create(root.join("worker.log"))?;
    Ok(OwnedChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "postgres_matrix_crash_worker",
                "--nocapture",
            ])
            .env("SIGNAL_MATRIX_WORK", root)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            .spawn()?,
    ))
}
fn publish_marker(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    // Readers must never observe create/truncate before the complete marker.
    // Each path has one writer in a freshly owned fixture directory.
    let pending = path.with_extension("pending");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&pending, path)?;
    fs::File::open(path.parent().ok_or("marker parent")?)?.sync_all()?;
    Ok(())
}
pub async fn worker() -> Result<(), Error> {
    let root = PathBuf::from(std::env::var("SIGNAL_MATRIX_WORK")?);
    let encoded = fs::read(root.join("work.json"))?;
    assert!(encoded.len() <= 65536);
    let work: Work = serde_json::from_slice(&encoded)?;
    let f: super::Fixture =
        serde_json::from_slice(&fs::read(std::env::var("SIGNAL_CONTROL_FIXTURE")?)?)?;
    fs::write(
        root.join("immutable-object-v1"),
        b"exact synthetic uploaded object bytes",
    )?;
    fs::File::open(root.join("immutable-object-v1"))?.sync_all()?;
    fs::File::open(&root)?.sync_all()?;
    publish_marker(&root.join("uploaded"), b"uploaded")?;
    if work.mode == "upload" {
        std::future::pending::<()>().await;
    }
    if matches!(work.mode.as_str(), "expired" | "takeover") {
        marker(&root.join("release"), b"publish").await?;
    }
    assert!(matches!(
        work.mode.as_str(),
        "transaction" | "commit" | "stall" | "expired" | "takeover"
    ));
    let runtime = super::runtime(&f, "signal_runtime")?;
    let began = tokio::time::Instant::now();
    let result = runtime
        .publish(work.token, work.publication, super::context()?)
        .await;
    if work.mode == "stall" {
        assert!(matches!(
            result,
            Err(ControlError::Uncertain | ControlError::Timeout | ControlError::Unavailable)
        ));
        assert!(
            began.elapsed() >= Duration::from_millis(1500)
                && began.elapsed() < Duration::from_secs(3)
        );
    } else if matches!(work.mode.as_str(), "expired" | "takeover") {
        assert!(matches!(result, Err(ControlError::Fenced)));
    } else {
        return Err("producer survived the intended crash boundary".into());
    }
    runtime.shutdown(super::context()?).await?;
    publish_marker(&root.join("refused"), b"refused")?;
    Ok(())
}
pub async fn qualify(
    f: &super::Fixture,
    db: &Client,
    runtime: &ControlClient,
) -> Result<(), Error> {
    let root = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?)
        .parent()
        .ok_or("fixture parent")?
        .join("crash-workers");
    fs::create_dir(&root)?;
    // Exercise the visibility boundary deterministically: partial temporary
    // bytes cannot become a completed upload signal, and wrong final bytes
    // remain fatal rather than being treated as a retryable partial marker.
    let probe = root.join("marker-probe");
    fs::write(probe.with_extension("pending"), b"u")?;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), marker(&probe, b"uploaded"))
            .await
            .is_err()
    );
    fs::remove_file(probe.with_extension("pending"))?;
    publish_marker(&probe, b"uploaded")?;
    marker(&probe, b"uploaded").await?;
    assert!(marker(&probe, b"wrong").await.is_err());
    eprintln!("phase: crash-marker-atomic-publication-qualified");
    for (ordinal, mode) in [
        "upload",
        "transaction",
        "commit",
        "stall",
        "expired",
        "takeover",
    ]
    .into_iter()
    .enumerate()
    {
        let mut scope = super::scope();
        scope.partition_id = Uuid::from_u128(0xc00 + ordinal as u128);
        scope.stream = Uuid::from_u128(0xc10 + ordinal as u128);
        scope.tenant = "synthetic-matrix".into();
        db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')", &[&scope.partition_id,&scope.tenant,&scope.stream]).await?;
        db.execute("INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES('signal_runtime',$1,$2,$3)", &[&scope.tenant,&scope.stream,&scope.partition_id]).await?;
        db.execute("INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES($1,$2,$3)", &[&scope.partition_id,&Uuid::from_u128(0x20),&format!("query/{}/",scope.stream)]).await?;
        let token = runtime
            .acquire(scope, Uuid::new_v4(), 60000, super::context()?)
            .await?;
        let mut publication =
            super::publication::request(&token, 0xc20 + ordinal as u128, 1, None)?;
        let object = b"exact synthetic uploaded object bytes";
        let mut manifest: signal_storage::object_manifest::QueryManifest =
            serde_json::from_slice(&publication.manifest)?;
        manifest.files[0].object.sha256 = Sha256::digest(object).into();
        manifest.files[0].object.bytes = object.len() as u64;
        manifest.files[0].object.key = signal_storage::object_manifest::data_key(
            token.scope.stream,
            "2026-10-10",
            0,
            Sha256::digest(object).into(),
        );
        publication.manifest = serde_json::to_vec(&manifest)?;
        let directory = root.join(mode);
        fs::create_dir(&directory)?;
        if mode == "stall" {
            db.batch_execute("CREATE FUNCTION public.synthetic_matrix_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$; CREATE TRIGGER synthetic_matrix_pause BEFORE INSERT ON signal_control.commits FOR EACH ROW EXECUTE FUNCTION public.synthetic_matrix_pause()").await?;
            db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '500 milliseconds' WHERE id=$1", &[&token.scope.partition_id]).await?;
        } else if mode == "transaction" {
            db.batch_execute("CREATE FUNCTION public.synthetic_matrix_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.5); RETURN NEW; END $$; CREATE TRIGGER synthetic_matrix_pause BEFORE INSERT ON signal_control.commits FOR EACH ROW EXECUTE FUNCTION public.synthetic_matrix_pause()").await?;
        } else if mode == "commit" {
            db.batch_execute("CREATE FUNCTION public.synthetic_matrix_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_matrix_pause AFTER UPDATE ON signal_control.partitions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_matrix_pause()").await?;
        }
        let mut before = super::publication::witness(db).await?;
        let mut child = start(
            &directory,
            &Work {
                token: token.clone(),
                publication: publication.clone(),
                mode: mode.into(),
            },
        )?;
        marker(&directory.join("uploaded"), b"uploaded").await?;
        if matches!(mode, "expired" | "takeover") {
            db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", &[&token.scope.partition_id]).await?;
            if mode == "takeover" {
                let replacement = runtime
                    .acquire(
                        token.scope.clone(),
                        Uuid::new_v4(),
                        60000,
                        super::context()?,
                    )
                    .await?;
                assert_eq!(replacement.epoch, token.epoch + 1);
            }
            before = super::publication::witness(db).await?;
            publish_marker(&directory.join("release"), b"publish")?;
        } else if mode != "upload" {
            observed(db, mode == "commit").await?;
        }
        if matches!(mode, "stall" | "expired" | "takeover") {
            marker(&directory.join("refused"), b"refused").await?;
            let exit = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(exit) = child.0.try_wait()? {
                        return Ok::<_, std::io::Error>(exit);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await??;
            assert!(exit.success());
        } else {
            child.0.kill()?;
            let exit = child.0.wait()?;
            assert!(!exit.success());
        }
        stopped(db).await?;
        assert_eq!(fs::read(directory.join("immutable-object-v1"))?, object);
        if mode != "commit" {
            assert_eq!(super::publication::witness(db).await?, before);
        } else {
            let fresh = super::runtime(f, "signal_runtime")?;
            let result = fresh
                .resolve_publication(token.clone(), publication.clone(), super::context()?)
                .await?;
            assert_eq!(result.id, publication.id);
            assert_eq!(result.last_sequence, 1);
            let committed = super::publication::witness(db).await?;
            fresh
                .resolve_publication(token.clone(), publication.clone(), super::context()?)
                .await?;
            assert_eq!(super::publication::witness(db).await?, committed);
            fresh.shutdown(super::context()?).await?;
        }
        if mode == "transaction" || mode == "stall" {
            db.batch_execute("DROP TRIGGER synthetic_matrix_pause ON signal_control.commits; DROP FUNCTION public.synthetic_matrix_pause()").await?;
        } else if mode == "commit" {
            db.batch_execute("DROP TRIGGER synthetic_matrix_pause ON signal_control.partitions; DROP FUNCTION public.synthetic_matrix_pause()").await?;
        }
        if mode == "stall" {
            let fresh = runtime
                .acquire(
                    token.scope.clone(),
                    Uuid::new_v4(),
                    60000,
                    super::context()?,
                )
                .await?;
            assert_eq!(fresh.epoch, token.epoch + 1);
            let after_takeover = super::publication::witness(db).await?;
            assert!(matches!(
                runtime
                    .publish(token.clone(), publication.clone(), super::context()?)
                    .await,
                Err(ControlError::Fenced)
            ));
            assert_eq!(super::publication::witness(db).await?, after_takeover);
        }
        let case = match mode {
            "upload" => "upload_before_commit_crash",
            "transaction" => "transaction_before_commit_crash",
            "commit" => "commit_reply_lost",
            "stall" => "owner_stalls_after_lock",
            "expired" => "owner_expired_before_transaction",
            "takeover" => "owner_changes_after_upload",
            _ => return Err("unknown owned process mode".into()),
        };
        eprintln!("matrix-case:{case} passed");
        eprintln!("matrix-process: {mode} owned child observed and reaped");
    }
    eprintln!("phase: abrupt-process-crash-qualification-complete");
    Ok(())
}

/// Runs in a separate test process after an owned PostgreSQL/container restart.
/// The launcher has already compared complete database witnesses byte for byte.
pub async fn restart_probe() -> Result<(), Error> {
    let encoded = fs::read(std::env::var("SIGNAL_CONTROL_FIXTURE")?)?;
    assert!(encoded.len() <= 4096);
    let f: super::Fixture = serde_json::from_slice(&encoded)?;
    let (db, driver) = super::admin(&f).await?;
    let runtime = super::runtime(&f, "signal_runtime")?;
    let before = super::publication::witness(&db).await?;
    let mut foreign = super::scope();
    foreign.generation = Uuid::from_u128(0xfff);
    assert!(matches!(
        runtime
            .acquire(foreign, Uuid::new_v4(), 15000, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(super::publication::witness(&db).await?, before);
    let head: Uuid = db
        .query_one(
            "SELECT head FROM signal_control.partitions WHERE id=$1",
            &[&super::scope().partition_id],
        )
        .await?
        .get(0);
    let pin = runtime
        .read_snapshot(
            super::scope(),
            SnapshotInput {
                schema_version: 1,
                id: Uuid::from_u128(0xcf0),
                manifest_ids: vec![head],
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?;
    assert_eq!(pin.manifests()?.len(), 1);
    assert_eq!(
        db.query_one(
            "SELECT checkpoint FROM signal_control.partitions WHERE id=$1",
            &[&super::scope().partition_id]
        )
        .await?
        .get::<_, i64>(0),
        4
    );
    runtime.shutdown(super::context()?).await?;
    drop(db);
    driver.abort();
    let _ = driver.await;
    super::catalog::restart_probe(&f).await?;
    super::finding_scope::restart_probe(&f).await?;
    super::catalog_restore::restart_probe(&f).await?;
    eprintln!("phase: persistent-restart-fresh-client-qualified");
    Ok(())
}

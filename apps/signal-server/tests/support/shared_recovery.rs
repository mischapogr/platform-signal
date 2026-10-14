//! Owned native PostgreSQL/WAL abrupt process boundaries, not AWS custody proof.
use super::{Fixture, Result, context, database, draft, io, versions};
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_control::{ConnectionSettings, ControlClient, ControlError, LeaseToken, Scope};
use signal_protocol::EventSink;
use signal_server::{
    shared::SharedPublisher,
    shared_recovery::{RECOVERY_BYTES, RecoveryError, SharedRecovery},
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
const DB: &str = "signal_shared_server_recovery";
fn connection(f: &Fixture) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        DB.into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
    )
}
pub(super) fn publisher(
    control: Arc<ControlClient>,
    scope: &Scope,
    backend: Uuid,
    objects: &Arc<versions::Versions>,
) -> Result<Arc<SharedPublisher>> {
    Ok(Arc::new(SharedPublisher::new(
        control,
        scope.clone(),
        backend,
        io(objects.clone())?,
        signal_storage::StorageConfig::default(),
        signal_storage::object_manifest::ManifestLimits::default(),
    )?))
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    schema_version: u32,
    wal: PathBuf,
    marker: PathBuf,
    mode: String,
    token: LeaseToken,
}
pub(super) async fn kill_worker(root: &Path, mode: &str, wal: &Path, token: &LeaseToken) -> Result {
    let marker = root.join(format!("{mode}.marker"));
    let path = root.join(format!("{mode}.json"));
    std::fs::write(
        &path,
        serde_json::to_vec(&Job {
            schema_version: if mode.starts_with("multi-") {
                3
            } else if mode.starts_with("scoped-") {
                2
            } else {
                1
            },
            wal: wal.into(),
            marker: marker.clone(),
            mode: mode.into(),
            token: token.clone(),
        })?,
    )?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "postgres_shared_recovery_crash_worker",
            "--nocapture",
        ])
        .env("SIGNAL_SHARED_RECOVERY_JOB", path)
        .stdout(std::fs::File::create(root.join(format!("{mode}.out")))?)
        .stderr(std::fs::File::create(root.join(format!("{mode}.err")))?)
        .spawn()?;
    let observed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if marker.exists() {
                assert_eq!(std::fs::read(&marker)?, mode.as_bytes());
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            if let Some(status) = child.try_wait()? {
                return Err(format!("owned recovery worker exited: {status}").into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let killed = child.kill();
    let status = child.wait()?;
    killed?;
    observed??;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
    }
    eprintln!("recovery-process: {mode} owned child SIGKILL observed and reaped");
    Ok(())
}
pub(super) async fn worker() -> Result {
    let path =
        std::env::var_os("SIGNAL_SHARED_RECOVERY_JOB").ok_or("owned recovery job missing")?;
    let bytes = std::fs::read(path)?;
    if bytes.len() > 16384 {
        return Err("job bounds".into());
    }
    let job: Job = serde_json::from_slice(&bytes)?;
    let scoped = job.mode.starts_with("scoped-");
    let multi = job.mode.starts_with("multi-");
    let mode = job
        .mode
        .strip_prefix("multi-")
        .or_else(|| job.mode.strip_prefix("scoped-"))
        .unwrap_or(&job.mode);
    if job.schema_version
        != if multi {
            3
        } else if scoped {
            2
        } else {
            1
        }
        || !["draft", "before-commit", "after-commit", "after-ack"].contains(&mode)
    {
        return Err("job contract".into());
    }
    let fixture: Fixture =
        serde_json::from_slice(&std::fs::read(std::env::var("SIGNAL_CONTROL_FIXTURE")?)?)?;
    let wal = DurableBuffer::open_with_recovery(
        BufferConfig {
            directory: job.wal,
            ..Default::default()
        },
        RECOVERY_BYTES,
    )
    .await?;
    let record = wal
        .read_recovery(context()?.deadline())
        .await?
        .ok_or("retained slot missing")?;
    let entry: serde_json::Value = serde_json::from_slice(&record.bytes)?;
    assert_eq!(entry["scope"], serde_json::to_value(&job.token.scope)?);
    assert_eq!(entry["schema_version"], job.schema_version);
    if mode == "draft" {
        assert_eq!(
            entry["phase"]["state"],
            if multi {
                "multi_draft"
            } else if scoped {
                "scoped_draft"
            } else {
                "draft"
            }
        );
    } else {
        assert_eq!(
            entry["phase"]["state"],
            if multi {
                "multi_prepared"
            } else if scoped {
                "scoped_prepared"
            } else {
                "prepared"
            }
        );
        if mode != "before-commit" {
            let settings = if multi {
                super::multi_recovery_support::connection(&fixture)?
            } else if scoped {
                super::scoped_recovery_support::connection(&fixture)?
            } else {
                connection(&fixture)?
            };
            let control = ControlClient::catalog(settings)?;
            let result = if multi {
                let request: signal_control::MultiEventPublicationInput =
                    serde_json::from_value(entry["phase"]["request"].clone())?;
                control
                    .publish_multi_event(job.token, request, context()?)
                    .await?
            } else if scoped {
                let request: signal_control::ScopedPublicationInput =
                    serde_json::from_value(entry["phase"]["request"].clone())?;
                control
                    .publish_scoped(job.token, request, context()?)
                    .await?
            } else {
                let request: signal_control::PublicationInput =
                    serde_json::from_value(entry["phase"]["request"].clone())?;
                control.publish(job.token, request, context()?).await?
            };
            if mode == "after-ack" {
                wal.read_batch(4096, 8 * 1024 * 1024).await?;
                wal.ack(result.last_sequence).await?;
            }
            control.shutdown(context()?).await?;
        }
    }
    let temporary = job.marker.with_extension("pending");
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    marker.write_all(job.mode.as_bytes())?;
    marker.sync_all()?;
    std::fs::rename(temporary, &job.marker)?;
    std::fs::File::open(job.marker.parent().ok_or("marker root")?)?.sync_all()?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    Err("parent failed to kill recovery worker".into())
}
pub(super) async fn qualify(f: &Fixture) -> Result {
    use sha2::Digest;
    use signal_control::{
        AdministrativeScope, ControlAdministrator, FindingInput, InitializeInput, MigrationInput,
        schema_identity,
    };
    let root = tempfile::tempdir()?;
    let cfg = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let initial = DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?;
    let stream = initial.snapshot().stream_id;
    initial.shutdown().await?;
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xef00),
        generation: Uuid::from_u128(0xef01),
        tenant: "synthetic-shared-recovery".into(),
        stream,
        partition_id: Uuid::from_u128(0xef03),
    };
    let (admin, admin_driver) = database(f, "postgres").await?;
    admin
        .batch_execute(&format!("CREATE DATABASE {DB}"))
        .await?;
    admin
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {DB} TO signal_control_owner"
        ))
        .await?;
    drop(admin);
    admin_driver.await??;
    let migrator = ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        f.port,
        DB.into(),
        "signal_migrator".into(),
        f.password.as_bytes().to_vec(),
    )?;
    let installer = ControlAdministrator::new(migrator, "signal_control_owner".into())?;
    let authority = AdministrativeScope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
    };
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
                scope: authority,
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    installer.shutdown(context()?).await?;
    let (db, db_driver) = database(f, DB).await?;
    let backend = Uuid::from_u128(0xef04);
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
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-recovery-versions')",
        &[&backend],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[&scope.partition_id, &backend, &format!("query/{stream}/")],
    )
    .await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let control = ControlClient::catalog(connection(f)?)?;
    let mut token = control
        .acquire(scope.clone(), Uuid::new_v4(), 60000, context()?)
        .await?;
    control.shutdown(context()?).await?;
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"synthetic"},"message":"exact recovery","attributes":{}}),
    )?;
    let event = input.normalize(chrono::Utc::now())?;
    let rules = signal_rules::RuleSet::from_yaml_documents(
        [
            "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: synthetic.recovery\n  name: Recovery\nspec:\n  severity: high\n  match:\n    all:\n      - field: message\n        contains: exact recovery\n  finding:\n    title: Recovery finding\n",
        ],
        signal_rules::RuleLimits::default(),
    )?;
    let mut revision = Vec::new();
    rules.write_revision(
        &mut revision,
        65536,
        &signal_rules::RuleContext::new(Duration::from_secs(5)),
    )?;
    let rule_sha: [u8; 32] = sha2::Sha256::digest(revision).into();
    let finding = rules.evaluate(&event)?.remove(0);
    let finding_bytes = serde_json::to_vec(&finding)?;
    let objects = Arc::new(versions::Versions(object_store::memory::InMemory::new()));
    let mut previous = None;
    let mut original_cursor = None;
    for (offset, mode) in ["draft", "before-commit", "after-commit", "after-ack"]
        .into_iter()
        .enumerate()
    {
        let sequence = offset as u64 + 1;
        let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
        wal.admit(event.clone()).await?;
        let control = Arc::new(ControlClient::catalog(connection(f)?)?);
        let publish = publisher(control.clone(), &scope, backend, &objects)?;
        let recovery = SharedRecovery::new(publish.clone(), wal.clone())?;
        let mut plan = draft();
        plan.previous = previous;
        plan.rule_revision = rule_sha;
        plan.findings = vec![FindingInput {
            id: finding.id,
            bytes: finding_bytes.clone(),
        }];
        let id = plan.id;
        let budget = context()?;
        let mut prepared = if mode == "draft" {
            db.batch_execute("UPDATE signal_control.store SET ready=false")
                .await?;
            let denied = recovery
                .prepare(token.clone(), plan, 1, budget.clone())
                .await;
            assert!(matches!(
                denied,
                Err(RecoveryError::Shared(super::SharedError::Control(
                    ControlError::Fenced
                )))
            ));
            db.batch_execute("UPDATE signal_control.store SET ready=true")
                .await?;
            None
        } else {
            Some(
                recovery
                    .prepare(token.clone(), plan, 1, budget.clone())
                    .await?,
            )
        };
        if prepared.is_some() {
            assert!(matches!(
                recovery.resume(token.clone(), context()?).await,
                Err(RecoveryError::Control(ControlError::Full))
            ));
        }
        if mode == "before-commit" {
            budget.cancel();
            let original = prepared.take().ok_or("prepared request missing")?;
            assert!(matches!(
                recovery.commit(original).await,
                Err(RecoveryError::Shared(super::SharedError::Control(
                    ControlError::Cancelled
                )))
            ));
        }
        let retained = wal
            .read_recovery(context()?.deadline())
            .await?
            .ok_or("retained recovery")?;
        assert_eq!(wal.snapshot().checkpoint, sequence - 1);
        drop(prepared);
        drop(recovery);
        publish.shutdown(context()?).await?;
        control.shutdown(context()?).await?;
        wal.shutdown().await?;
        drop(publish);
        drop(control);
        drop(wal);
        kill_worker(root.path(), mode, &cfg.directory, &token).await?;
        let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
        assert_eq!(
            wal.read_recovery(context()?.deadline()).await?,
            Some(retained)
        );
        assert_eq!(
            wal.snapshot().checkpoint,
            if mode == "after-ack" {
                sequence
            } else {
                sequence - 1
            }
        );
        let count: i64 = db
            .query_one("SELECT count(*) FROM signal_control.commits", &[])
            .await?
            .get(0);
        assert_eq!(
            count,
            if mode == "after-commit" || mode == "after-ack" {
                sequence as i64
            } else {
                sequence as i64 - 1
            }
        );
        let control = Arc::new(ControlClient::catalog(connection(f)?)?);
        let publish = publisher(control.clone(), &scope, backend, &objects)?;
        let recovery = SharedRecovery::new(publish.clone(), wal.clone())?;
        let old = token.clone();
        db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", &[&scope.partition_id]).await?;
        token = control
            .acquire(scope.clone(), Uuid::new_v4(), 60000, context()?)
            .await?;
        assert!(token.epoch > old.epoch);
        if mode != "draft" {
            assert!(matches!(
                recovery.resume(old, context()?).await,
                Err(RecoveryError::Shared(super::SharedError::Control(
                    ControlError::Fenced
                )))
            ));
            assert_eq!(
                wal.snapshot().checkpoint,
                if mode == "after-ack" {
                    sequence
                } else {
                    sequence - 1
                }
            );
        }
        // Admission closes first during graceful shutdown; retained work can
        // still drain on the same physically live worker without reopening it.
        wal.close();
        let resolved = recovery
            .resume(token.clone(), context()?)
            .await?
            .ok_or("resolution missing")?;
        assert_eq!(resolved.id, id);
        assert_eq!(resolved.last_sequence, sequence);
        assert_eq!(wal.snapshot().checkpoint, sequence);
        if let Some(cursor) = &original_cursor {
            assert_eq!(&resolved.cursor, cursor);
        } else {
            original_cursor = Some(resolved.cursor.clone());
        }
        assert!(wal.read_recovery(context()?.deadline()).await?.is_none());
        assert!(recovery.resume(token.clone(), context()?).await?.is_none());
        assert_eq!(
            db.query_one("SELECT count(*) FROM signal_control.findings", &[])
                .await?
                .get::<_, i64>(0),
            1
        );
        previous = Some(id);
        drop(recovery);
        publish.shutdown(context()?).await?;
        control.shutdown(context()?).await?;
        wal.shutdown().await?;
    }
    // Observe the driver's own COMMIT reply loss, retaining its exact record
    // before any checkpoint. Resolution then advances the prefix exactly once.
    let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
    wal.admit(event.clone()).await?;
    let control = Arc::new(ControlClient::catalog(connection(f)?)?);
    let publish = publisher(control.clone(), &scope, backend, &objects)?;
    let recovery = SharedRecovery::new(publish.clone(), wal.clone())?;
    let mut plan = draft();
    plan.previous = previous;
    plan.rule_revision = rule_sha;
    plan.findings = vec![FindingInput {
        id: finding.id,
        bytes: finding_bytes.clone(),
    }];
    let budget = context()?;
    let prepared = recovery
        .prepare(token.clone(), plan, 1, budget.clone())
        .await?;
    let exact = prepared.request().clone();
    db.batch_execute("CREATE FUNCTION public.synthetic_recovery_commit_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(.5); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_recovery_commit_pause AFTER INSERT ON signal_control.commits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_recovery_commit_pause()").await?;
    let observed = async {
        tokio::time::timeout(Duration::from_secs(4),async {
        loop {
            let active:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND query='COMMIT' AND wait_event='PgSleep')", &[&DB]).await?.get(0);
            if active {budget.cancel();return Ok::<(),tokio_postgres::Error>(());}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await
    };
    let (uncertain, observed) = tokio::join!(recovery.commit(prepared), observed);
    observed??;
    assert!(matches!(
        uncertain,
        Err(RecoveryError::Shared(super::SharedError::Control(
            ControlError::Uncertain
        )))
    ));
    assert_eq!(wal.snapshot().checkpoint, 4);
    assert!(wal.read_recovery(context()?.deadline()).await?.is_some());
    db.batch_execute("DROP TRIGGER synthetic_recovery_commit_pause ON signal_control.commits; DROP FUNCTION public.synthetic_recovery_commit_pause()").await?;
    let confirmed = recovery
        .resume(token.clone(), context()?)
        .await?
        .ok_or("uncertain resolution missing")?;
    assert_eq!(confirmed.id, exact.id);
    assert_eq!(confirmed.last_sequence, 5);
    assert_eq!(wal.snapshot().checkpoint, 5);
    assert_eq!(Some(confirmed.cursor), original_cursor);
    previous = Some(exact.id);
    drop(recovery);
    publish.shutdown(context()?).await?;
    control.shutdown(context()?).await?;
    wal.shutdown().await?;
    drop(wal);
    // Exact retries cannot substitute changed provider bytes/versions. Leave
    // both the original request and WAL prefix held after the bounded rejection.
    let wal = Arc::new(DurableBuffer::open_with_recovery(cfg, RECOVERY_BYTES).await?);
    wal.admit(event).await?;
    let control = Arc::new(ControlClient::catalog(connection(f)?)?);
    let publish = publisher(control.clone(), &scope, backend, &objects)?;
    let recovery = SharedRecovery::new(publish.clone(), wal.clone())?;
    let mut plan = draft();
    plan.previous = previous;
    plan.rule_revision = rule_sha;
    plan.findings = vec![FindingInput {
        id: finding.id,
        bytes: finding_bytes,
    }];
    let prepared = recovery.prepare(token.clone(), plan, 1, context()?).await?;
    let manifest: signal_storage::object_manifest::QueryManifest =
        serde_json::from_slice(&prepared.request().manifest)?;
    let key = object_store::path::Path::from(manifest.files[0].object.key.clone());
    drop(prepared);
    let retained = wal.read_recovery(context()?.deadline()).await?;
    use object_store::ObjectStore;
    objects
        .0
        .put_opts(
            &key,
            object_store::PutPayload::from(b"corrupt-fixture-object".to_vec()),
            object_store::PutOptions::default(),
        )
        .await?;
    assert!(matches!(
        recovery.resume(token, context()?).await,
        Err(RecoveryError::Shared(super::SharedError::Object(_)))
    ));
    assert_eq!(wal.snapshot().checkpoint, 5);
    assert_eq!(wal.read_recovery(context()?.deadline()).await?, retained);
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.commits", &[])
            .await?
            .get::<_, i64>(0),
        5
    );
    drop(recovery);
    publish.shutdown(context()?).await?;
    control.shutdown(context()?).await?;
    wal.shutdown().await?;
    drop(db);
    db_driver.await??;
    eprintln!("phase: actual-server-durable-request-recovery-before-wal-checkpoint-qualified");
    Ok(())
}

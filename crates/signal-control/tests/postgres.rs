//! Owned local PostgreSQL only; never consumes ambient database credentials.
use signal_control::{
    ConnectionSettings, ControlClient, ControlContext, ControlError, Scope, schema_identity,
};
use std::{net::IpAddr, time::Duration};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

#[path = "support/administration.rs"]
mod administration;
#[path = "support/catalog.rs"]
mod catalog;
#[path = "support/catalog_query.rs"]
mod catalog_query;
#[path = "support/catalog_restore.rs"]
mod catalog_restore;
#[path = "support/custody.rs"]
mod custody;
#[path = "support/finding_scope.rs"]
mod finding_scope;
#[path = "support/global_feed.rs"]
mod global_feed;
#[path = "support/matrix.rs"]
mod matrix;
#[path = "support/multi_event_publication.rs"]
mod multi_event_publication;
#[path = "support/multi_event_restore.rs"]
mod multi_event_restore;
#[path = "support/notification.rs"]
mod notification;
#[path = "support/publication.rs"]
mod publication;
#[path = "support/restore.rs"]
mod restore;
#[path = "support/retention.rs"]
mod retention;
#[path = "support/scoped_publication.rs"]
mod scoped_publication;
#[path = "support/snapshot.rs"]
mod snapshot;
#[path = "support/state_read.rs"]
mod state_read;

fn context() -> Result<ControlContext, ControlError> {
    ControlContext::new(Duration::from_secs(5))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "owned PostgreSQL TLS fixture; check-shared-runtime.py --custody-only"]
async fn postgres_object_custody_coordinator() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var("SIGNAL_CONTROL_FIXTURE")?;
    assert!(std::fs::metadata(&path)?.len() <= 4096);
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert!(fixture.password.starts_with("synthetic-control-") && fixture.password.len() <= 64);
    custody::qualify(&fixture).await
}
fn scope() -> Scope {
    Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(1),
        generation: Uuid::from_u128(2),
        tenant: "synthetic".into(),
        stream: Uuid::from_u128(3),
        partition_id: Uuid::from_u128(4),
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    port: u16,
    password: String,
    root_der: String,
    wrong_der: String,
}
async fn admin(
    f: &Fixture,
) -> Result<(Client, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    admin_database(f, "postgres").await
}
async fn admin_database(
    f: &Fixture,
    database: &str,
) -> Result<(Client, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host("127.0.0.1").port(f.port).dbname(database).user("postgres").password(f.password.as_bytes())
 .connect_timeout(Duration::from_secs(2)).application_name("signal-control-fixture")
 .options("-c statement_timeout=2000 -c lock_timeout=500 -c idle_in_transaction_session_timeout=2000");
    let (client, driver) =
        tokio::time::timeout(Duration::from_secs(2), cfg.connect(NoTls)).await??;
    let task = tokio::spawn(async move {
        let _ = driver.await;
    });
    Ok((client, task))
}
fn runtime(f: &Fixture, user: &str) -> Result<ControlClient, ControlError> {
    ControlClient::new(ConnectionSettings::fixture_loopback(
        IpAddr::from([127, 0, 0, 1]),
        f.port,
        "postgres".into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )?)
}
async fn idle(client: &ControlClient) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let m = client.metrics();
            if m.active == 0 && m.queue_depth == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
// A lost-reply test must observe COMMIT, rather than assume a time budget
// was long enough for connection/admission. Only owned fixture sessions qualify.
async fn cancel_delayed_commit(
    db: &Client,
    context: &ControlContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed=tokio::time::timeout(Duration::from_secs(2),async {
        loop {
            let row=db.query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name='signal-control' AND state='active' AND query='COMMIT' AND wait_event='PgSleep'",&[]).await?;
            if row.get::<_,i64>(0)==1 {return Ok::<(),tokio_postgres::Error>(());}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    context.cancel();
    observed??;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned PostgreSQL fixture from check-shared-runtime.py"]
async fn postgres_lease_authority_and_cancellation() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var("SIGNAL_CONTROL_FIXTURE")?;
    let metadata = std::fs::metadata(&path)?;
    assert!(metadata.len() <= 4096);
    let f: Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert!(f.password.starts_with("synthetic-control-") && f.password.len() <= 64);
    let (db, driver) = admin(&f).await?;
    administration::qualify(&db, &f).await?;
    catalog::qualify(&db, &f).await?;
    catalog_restore::qualify(&db, &f).await?;
    global_feed::qualify(&db, &f).await?;
    finding_scope::qualify(&db, &f).await?;
    multi_event_publication::qualify_isolated_client(&db, &f).await?;
    multi_event_restore::qualify(&db, &f).await?;
    restore::qualify(&db, &f).await?;
    let runtime = runtime(&f, "signal_runtime")?;
    let scope = scope();
    let actor = Uuid::from_u128(10);
    let tls_settings =
        |host: &str, root_path: &str| -> Result<ConnectionSettings, Box<dyn std::error::Error>> {
            let certificate = std::fs::read(root_path)?;
            assert!(certificate.len() <= 65536);
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(certificate))?;
            Ok(ConnectionSettings::tls(
                host.into(),
                Some(IpAddr::from([127, 0, 0, 1])),
                f.port,
                "postgres".into(),
                "signal_runtime".into(),
                f.password.as_bytes().to_vec(),
                roots,
            )?)
        };
    for settings in [
        tls_settings("wrong-control.invalid", &f.root_der)?,
        tls_settings("signal-control.invalid", &f.wrong_der)?,
    ] {
        let denied = ControlClient::new(settings)?;
        assert!(matches!(
            denied
                .acquire(scope.clone(), actor, 15000, context()?)
                .await,
            Err(ControlError::Unavailable)
        ));
        denied.shutdown(context()?).await?;
    }
    let tls = ControlClient::new(tls_settings("signal-control.invalid", &f.root_der)?)?;
    let token = tls.acquire(scope.clone(), actor, 60000, context()?).await?;
    assert_eq!(tls.renew(token.clone(), 60000, context()?).await?, token);
    assert_eq!(tls.metrics().lease_acquired_results, 1);
    assert_eq!(tls.metrics().lease_renewed_results, 1);
    assert_eq!(tls.metrics().fenced_results, 0);
    tls.shutdown(context()?).await?;
    assert_eq!(token.epoch, 1);
    publication::qualify(&db, &runtime, &token).await?;
    state_read::qualify(&db, &runtime, &token).await?;
    snapshot::qualify(&db, &runtime, &token).await?;
    retention::qualify(&db, &runtime, &token).await?;
    notification::qualify(&db, &runtime, &token).await?;
    matrix::qualify(&f, &db, &runtime).await?;
    let row=db.query_one("SELECT epoch,owner,lease_until>clock_timestamp() FROM signal_control.partitions WHERE id=$1",&[&scope.partition_id]).await?;
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, Uuid>(1), actor);
    assert!(row.get::<_, bool>(2));
    assert_eq!(
        runtime.renew(token.clone(), 15000, context()?).await?,
        token
    );
    assert!(matches!(
        runtime
            .acquire(scope.clone(), Uuid::from_u128(11), 15000, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let foreign_before = publication::witness(&db).await?;
    for foreign in [
        Scope {
            tenant: "foreign".into(),
            ..scope.clone()
        },
        Scope {
            stream: Uuid::from_u128(999),
            ..scope.clone()
        },
    ] {
        assert!(matches!(
            runtime
                .acquire(foreign.clone(), actor, 15000, context()?)
                .await,
            Err(ControlError::Fenced)
        ));
        assert!(matches!(
            runtime
                .read_snapshot(
                    foreign,
                    signal_control::SnapshotInput {
                        schema_version: 1,
                        id: Uuid::new_v4(),
                        manifest_ids: vec![Uuid::from_u128(100)],
                        pin_ms: 5000
                    },
                    context()?
                )
                .await,
            Err(ControlError::Fenced)
        ));
        assert_eq!(publication::witness(&db).await?, foreign_before);
    }
    eprintln!("matrix-case:foreign_tenant_stream passed");
    assert!(runtime.metrics().fenced_results > 0);
    let mut stale = scope.clone();
    stale.generation = Uuid::from_u128(999);
    assert!(matches!(
        runtime.acquire(stale, actor, 15000, context()?).await,
        Err(ControlError::Fenced)
    ));
    // An independently authenticated role has EXECUTE but no partition grant.
    let denied = crate::runtime(&f, "signal_denied")?;
    assert!(matches!(
        denied.renew(token.clone(), 15000, context()?).await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        denied
            .read_snapshot(
                scope.clone(),
                signal_control::SnapshotInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    manifest_ids: vec![Uuid::from_u128(100)],
                    pin_ms: 5000,
                },
                context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    denied.shutdown(context()?).await?;
    db.batch_execute(
        "UPDATE signal_control.store SET routines_sha256=decode(repeat('ab',32),'hex')",
    )
    .await?;
    assert!(matches!(
        runtime.renew(token.clone(), 15000, context()?).await,
        Err(ControlError::Fenced)
    ));
    let (_, routines) = schema_identity();
    let routines = routines.as_slice();
    db.execute(
        "UPDATE signal_control.store SET routines_sha256=$1",
        &[&routines],
    )
    .await?;
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    assert!(matches!(
        runtime.renew(token.clone(), 15000, context()?).await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&scope.partition_id]).await?;
    assert!(matches!(
        runtime.renew(token.clone(), 15000, context()?).await,
        Err(ControlError::Fenced)
    ));
    eprintln!("phase: competing-takeover");
    // Two real concurrent contenders: row locks allow one epoch publication.
    let one = runtime.clone();
    let two = runtime.clone();
    let s1 = scope.clone();
    let s2 = scope.clone();
    let (a, b) = tokio::join!(
        one.acquire(s1, Uuid::from_u128(12), 15000, context()?),
        two.acquire(s2, Uuid::from_u128(13), 15000, context()?)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let next = if let Ok(value) = a {
        assert!(matches!(b, Err(ControlError::Fenced)));
        value
    } else {
        assert!(matches!(a, Err(ControlError::Fenced)));
        b?
    };
    assert_eq!(next.epoch, 2);
    assert!(matches!(
        runtime.renew(token, 15000, context()?).await,
        Err(ControlError::Fenced)
    ));
    idle(&runtime).await?;
    eprintln!("phase: blocked-statements");
    // A deadline after actual SQL lock admission must retain uncertainty and
    // physically roll back without granting a renewal or changing store facts.
    let before_timeout = runtime.metrics().transaction_timeouts;
    let before_renewal = runtime.metrics().lease_renewed_results;
    let before_facts = publication::witness(&db).await?;
    db.batch_execute("BEGIN; SELECT singleton FROM signal_control.store FOR UPDATE")
        .await?;
    let bounded = runtime.clone();
    let original = next.clone();
    let short = ControlContext::new(Duration::from_millis(400))?;
    let timed = tokio::spawn(async move { bounded.renew(original, 15000, short).await });
    tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            db.batch_execute("SELECT pg_stat_clear_snapshot()").await?;
            let row = db.query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name='signal-control' AND wait_event_type='Lock'", &[]).await?;
            if row.get::<_, i64>(0) == 1 { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<(), tokio_postgres::Error>(())
    }).await??;
    assert!(matches!(timed.await?, Err(ControlError::Uncertain)));
    db.batch_execute("ROLLBACK").await?;
    idle(&runtime).await?;
    assert_eq!(runtime.metrics().transaction_timeouts, before_timeout + 1);
    assert_eq!(runtime.metrics().lease_renewed_results, before_renewal);
    assert_eq!(publication::witness(&db).await?, before_facts);
    // PostgreSQL query-cancel responses retain a timeout class without parsing
    // localized error messages; existing uncertainty/rollback rules still apply.
    db.batch_execute("SET statement_timeout='5ms'").await?;
    let cancelled_statement = db.batch_execute("SELECT pg_sleep(0.1)").await;
    let cancelled_statement = match cancelled_statement {
        Err(error) => error,
        Ok(()) => return Err("statement timeout did not fire".into()),
    };
    assert_eq!(
        cancelled_statement
            .as_db_error()
            .map(|error| error.code().code()),
        Some("57014")
    );
    db.batch_execute("SET statement_timeout='2000ms'").await?;
    // Hold the actual store row: four cancelled statements must keep their seats
    // while ROLLBACK waits behind those statements. Queue admits only another32.
    db.batch_execute("BEGIN; SELECT singleton FROM signal_control.store FOR UPDATE")
        .await?;
    let mut contexts = Vec::new();
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let c = context()?;
        contexts.push(c.clone());
        let r = runtime.clone();
        let t = next.clone();
        jobs.push(tokio::spawn(async move { r.renew(t, 15000, c).await }));
    }
    tokio::time::timeout(Duration::from_secs(1),async {loop {
  db.batch_execute("SELECT pg_stat_clear_snapshot()").await?;
  let row=db.query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name='signal-control' AND wait_event_type='Lock'",&[]).await?;
  if row.get::<_,i64>(0)==4 {break;}tokio::time::sleep(Duration::from_millis(5)).await;
 }Ok::<(),tokio_postgres::Error>(())}).await??;
    eprintln!("phase: cancel-blocked");
    for c in contexts {
        c.cancel();
    }
    for job in jobs {
        assert!(matches!(job.await?, Err(ControlError::Uncertain)));
    }
    assert_eq!(runtime.metrics().active, 4);
    eprintln!("phase: fill-queue");
    let mut queued = Vec::new();
    for _ in 0..32 {
        let r = runtime.clone();
        let t = next.clone();
        queued.push(tokio::spawn(
            async move { r.renew(t, 15000, context()?).await },
        ));
    }
    tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if runtime.metrics().queue_depth == 32 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(matches!(
        runtime.renew(next.clone(), 15000, context()?).await,
        Err(ControlError::Full)
    ));
    assert_eq!(runtime.metrics().rejected, 1);
    let row = db
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name='signal-control'",
            &[],
        )
        .await?;
    assert_eq!(row.get::<_, i64>(0), 4);
    db.batch_execute("ROLLBACK").await?;
    eprintln!("phase: replay-queued");
    for job in queued {
        assert_eq!(job.await??, next);
    }
    idle(&runtime).await?;
    assert_eq!(runtime.metrics().quarantined, 0);
    eprintln!("phase: restricted-privileges");
    // The restricted role has neither table DML nor helper EXECUTE authority.
    let mut cfg = tokio_postgres::Config::new();
    cfg.host("127.0.0.1")
        .port(f.port)
        .dbname("postgres")
        .user("signal_runtime")
        .password(f.password.as_bytes());
    let (restricted, restricted_driver) = cfg.connect(NoTls).await?;
    let restricted_task = tokio::spawn(async move {
        let _ = restricted_driver.await;
    });
    assert!(
        restricted
            .batch_execute("UPDATE signal_control.store SET ready=true")
            .await
            .is_err()
    );
    assert!(
        restricted
            .query_one(
                "SELECT signal_control.check_token($1,$2,$3)",
                &[&serde_json::to_value(&next)?, &routines, &routines]
            )
            .await
            .is_err()
    );
    restricted_task.abort();
    let _ = restricted_task.await;
    runtime.shutdown(context()?).await?;
    eprintln!("phase: unconfirmed-rollback-quarantine");
    let broken = crate::runtime(&f, "signal_runtime")?;
    db.batch_execute("BEGIN; SELECT singleton FROM signal_control.store FOR UPDATE")
        .await?;
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let c = context()?;
        let r = broken.clone();
        let t = next.clone();
        jobs.push(tokio::spawn(async move { r.renew(t, 15000, c).await }));
    }
    tokio::time::timeout(Duration::from_secs(1),async {loop {
        db.batch_execute("SELECT pg_stat_clear_snapshot()").await?;
        let row=db.query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name='signal-control' AND wait_event_type='Lock'",&[]).await?;
        if row.get::<_,i64>(0)==4 {break;}tokio::time::sleep(Duration::from_millis(5)).await;
    }Ok::<(),tokio_postgres::Error>(())}).await??;
    // Fixture administrator terminates exactly this client's blocked sessions.
    let rows=db.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='signal-control'",&[]).await?;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|row| row.get::<_, bool>(0)));
    for job in jobs {
        assert!(matches!(job.await?, Err(ControlError::Uncertain)));
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if broken.metrics().quarantined == 4 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(broken.metrics().active, 4);
    let c = ControlContext::new(Duration::from_millis(30))?;
    assert!(matches!(
        broken.renew(next.clone(), 15000, c).await,
        Err(ControlError::Uncertain)
    ));
    assert_eq!(broken.metrics().queue_depth, 1);
    db.batch_execute("ROLLBACK").await?;
    assert!(matches!(
        broken.shutdown(context()?).await,
        Err(ControlError::Uncertain)
    ));
    assert_eq!(broken.metrics().queue_depth, 0);
    assert_eq!(broken.metrics().active, 0);
    assert!(matches!(
        broken.renew(next, 15000, context()?).await,
        Err(ControlError::Cancelled)
    ));
    eprintln!("matrix-case:cancelled_transaction_or_pool_full passed");
    drop(db);
    driver.abort();
    let _ = driver.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "owned subprocess worker; invoked only by matrix fixture"]
async fn postgres_matrix_crash_worker() -> Result<(), Box<dyn std::error::Error>> {
    matrix::worker().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned persistent database restart from matrix launcher"]
async fn postgres_matrix_restart_probe() -> Result<(), Box<dyn std::error::Error>> {
    matrix::restart_probe().await
}

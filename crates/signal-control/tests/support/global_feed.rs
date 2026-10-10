//! Actual PostgreSQL table-read authority, original prefixes and fixed snapshots.
use signal_control::*;
use signal_protocol::{
    access::{
        AccessPolicy, AuthenticatedIdentity, Operation, Permission, ResourceScope, Role,
        SubjectBinding,
    },
    findings_feed::{FindingsAfter, FindingsCursor, FindingsFeedQuery},
};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DATABASE: &str = "signal_global_feed";
pub fn grant(
    operation: Operation,
    seconds: u64,
) -> Result<Arc<signal_protocol::access::RequestGrant>> {
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let policy = AccessPolicy {
        schema_version: 1,
        roles: vec![Role {
            id: "synthetic-reader".into(),
            permissions: vec![Permission {
                operation,
                scope: ResourceScope::all(),
            }],
        }],
        bindings: vec![SubjectBinding {
            issuer: "synthetic-fixture".into(),
            subject: "reader".into(),
            roles: vec!["synthetic-reader".into()],
        }],
    }
    .compile()?;
    Ok(Arc::new(policy.grant(
        AuthenticatedIdentity::from_verified_backend(
            "synthetic-fixture".into(),
            "reader".into(),
            at,
            at + seconds,
        )?,
        at,
    )?))
}
fn settings(
    f: &super::Fixture,
    database: &str,
    user: &str,
) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        IpAddr::from([127, 0, 0, 1]),
        f.port,
        database.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
fn query(after: FindingsAfter) -> FindingsFeedQuery {
    FindingsFeedQuery { after, limit: 1 }
}
pub async fn qualify(root: &Client, f: &super::Fixture) -> Result {
    root.batch_execute("CREATE DATABASE signal_global_feed TEMPLATE signal_catalog_profile")
        .await?;
    let (db, driver) = super::admin_database(f, DATABASE).await?;
    let row = db
        .query_one("SELECT store_id,generation FROM signal_control.store", &[])
        .await?;
    let store: Uuid = row.try_get(0)?;
    let generation: Uuid = row.try_get(1)?;
    let producer = ControlClient::catalog(settings(f, DATABASE, "signal_runtime")?)?;
    assert!(matches!(
        producer
            .read_findings_feed(
                store,
                generation,
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    producer.shutdown(super::context()?).await?;
    let reader = ControlClient::catalog(settings(f, DATABASE, "signal_denied")?)?;
    assert!(matches!(
        reader
            .read_findings_feed(
                store,
                generation,
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    // Dedicated fixture role has no schema-owner membership or partition grant.
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_denied; GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings TO signal_denied").await?;
    assert!(matches!(
        reader
            .read_findings_feed(
                store,
                generation,
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindings, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        reader
            .read_findings_feed(
                store,
                Uuid::new_v4(),
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    let original = db
        .query(
            "SELECT id,position,content FROM signal_control.findings ORDER BY position LIMIT 129",
            &[],
        )
        .await?;
    assert!(!original.is_empty() && original.len() <= 128);
    let mut after = FindingsAfter::Begin;
    for (i, row) in original.iter().enumerate() {
        let page = reader
            .read_findings_feed(
                store,
                generation,
                query(after),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?,
            )
            .await?;
        assert_eq!(page.records()?.len(), 1);
        assert_eq!(page.records()?[0].id, row.try_get::<_, Uuid>(0)?);
        assert_eq!(page.records()?[0].bytes, row.try_get::<_, Vec<u8>>(2)?);
        assert_eq!(
            page.next_cursor()?.position(),
            row.try_get::<_, i64>(1)? as u64
        );
        assert_eq!(page.has_more()?, i + 1 < original.len());
        after = FindingsAfter::Cursor(page.next_cursor()?);
    }
    let empty = reader
        .read_findings_feed(
            store,
            generation,
            query(after),
            grant(Operation::ReadFindingsFeed, 60)?,
            super::context()?,
        )
        .await?;
    assert!(empty.records()?.is_empty());
    assert!(!empty.has_more()?);
    for invalid in [
        FindingsCursor::initial(Uuid::new_v4())?,
        FindingsCursor::initial(store)?.advance(b"divergent")?,
    ] {
        assert!(matches!(
            reader
                .read_findings_feed(
                    store,
                    generation,
                    query(FindingsAfter::Cursor(invalid)),
                    grant(Operation::ReadFindingsFeed, 60)?,
                    super::context()?
                )
                .await,
            Err(ControlError::Conflict)
        ));
    }
    if let FindingsAfter::Cursor(tail) = after {
        assert!(matches!(
            reader
                .read_findings_feed(
                    store,
                    generation,
                    query(FindingsAfter::Cursor(tail.advance(b"synthetic ahead")?)),
                    grant(Operation::ReadFindingsFeed, 60)?,
                    super::context()?
                )
                .await,
            Err(ControlError::CursorPositionUnavailable)
        ));
    }
    // Freeze row acquisition after the transaction snapshot/head are established.
    let (locker, lock_driver) = super::admin_database(f, DATABASE).await?;
    locker
        .batch_execute("BEGIN; LOCK TABLE signal_control.findings IN ACCESS EXCLUSIVE MODE")
        .await?;
    let pending = {
        let reader = reader.clone();
        let grant = grant(Operation::ReadFindingsFeed, 60)?;
        tokio::spawn(async move {
            reader
                .read_findings_feed(
                    store,
                    generation,
                    query(FindingsAfter::Begin),
                    grant,
                    super::context()?,
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_millis(750),async {
        loop {
            let n:i64=db.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname='signal_global_feed' AND usename='signal_denied' AND wait_event='relation'",&[]).await?.try_get(0)?;
            if n==1 {return Ok::<(),tokio_postgres::Error>(());}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    let id: Uuid = original[0].try_get(0)?;
    let bytes: Vec<u8> = original[0].try_get(2)?;
    let mut changed = bytes.clone();
    changed.push(b'\n');
    locker
        .execute(
            "UPDATE signal_control.findings SET content=$1 WHERE id=$2",
            &[&changed, &id],
        )
        .await?;
    locker.batch_execute("COMMIT").await?;
    let page = pending.await??;
    assert_eq!(page.records()?[0].bytes, bytes);
    assert!(matches!(
        reader
            .read_findings_feed(
                store,
                generation,
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute(
        "UPDATE signal_control.findings SET content=$1 WHERE id=$2",
        &[&bytes, &id],
    )
    .await?;
    drop(locker);
    lock_driver.await?;
    db.batch_execute("REVOKE SELECT ON signal_control.findings FROM signal_denied")
        .await?;
    assert!(matches!(
        reader
            .read_findings_feed(
                store,
                generation,
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("GRANT SELECT ON signal_control.findings TO signal_denied")
        .await?;
    let context = super::context()?;
    let page = reader
        .read_findings_feed(
            store,
            generation,
            query(FindingsAfter::Begin),
            grant(Operation::ReadFindingsFeed, 60)?,
            context.clone(),
        )
        .await?;
    context.cancel();
    assert!(matches!(page.records(), Err(ControlError::Cancelled)));
    let retained = reader
        .read_findings_feed(
            store,
            generation,
            query(FindingsAfter::Begin),
            grant(Operation::ReadFindingsFeed, 60)?,
            super::context()?,
        )
        .await?;
    reader.shutdown(super::context()?).await?;
    assert!(matches!(retained.records(), Err(ControlError::Cancelled)));
    assert!(matches!(
        retained.next_cursor(),
        Err(ControlError::Cancelled)
    ));
    drop(db);
    driver.await?;
    eprintln!("phase: globally-authorized-original-feed-qualified");
    Ok(())
}

/// Destination reader privileges are explicitly re-enrolled with currently
/// captured credentials; no source ACL or old-generation grant is imported.
pub async fn restored(
    f: &super::Fixture,
    database: &str,
    store: Uuid,
    generation: Uuid,
    old: Uuid,
    enroll: bool,
) -> Result {
    let (db, driver) = super::admin_database(f, database).await?;
    if enroll {
        assert!(
            !db.query_one(
                "SELECT has_table_privilege('signal_denied','signal_control.findings','SELECT')",
                &[]
            )
            .await?
            .try_get::<_, bool>(0)?
        );
        db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_denied; GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings TO signal_denied").await?;
    }

    let reader = ControlClient::restored_catalog(settings(f, database, "signal_denied")?)?;
    assert!(matches!(
        reader
            .read_findings_feed(
                store,
                old,
                query(FindingsAfter::Begin),
                grant(Operation::ReadFindingsFeed, 60)?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    let page = reader
        .read_findings_feed(
            store,
            generation,
            query(FindingsAfter::Begin),
            grant(Operation::ReadFindingsFeed, 60)?,
            super::context()?,
        )
        .await?;
    let original = db
        .query_one(
            "SELECT content FROM signal_control.findings ORDER BY position LIMIT 1",
            &[],
        )
        .await?;
    assert_eq!(page.records()?[0].bytes, original.try_get::<_, Vec<u8>>(0)?);
    assert_eq!(page.next_cursor()?.position(), 1);
    reader.shutdown(super::context()?).await?;
    drop(db);
    driver.await?;
    Ok(())
}

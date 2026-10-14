//! Actual low-privilege fenced recovery reads over the owned PostgreSQL fixture.
use signal_control::{ControlClient, ControlError, LeaseToken, StateReadInput};
use tokio_postgres::Client;
use uuid::Uuid;
pub async fn qualify(
    db: &Client,
    runtime: &ControlClient,
    token: &LeaseToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let row=db.query_one("SELECT head,checkpoint,(SELECT value FROM signal_control.state WHERE partition_id=$1 AND key='synthetic-state') FROM signal_control.partitions WHERE id=$1",&[&token.scope.partition_id]).await?;
    let head: Option<Uuid> = row.try_get(0)?;
    let checkpoint: i64 = row.try_get(1)?;
    let expected: Vec<u8> = row.try_get(2)?;
    let request = StateReadInput {
        key: "synthetic-state".into(),
        expected_head: head,
    };
    assert!(matches!(
        runtime
            .read_state(token.clone(), request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let owner: String = db
        .query_one(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control'",
            &[],
        )
        .await?
        .try_get(0)?;
    let quoted = format!("\"{}\"", owner.replace('"', "\"\""));
    db.batch_execute(&format!("SET ROLE {quoted}")).await?;
    let source = include_str!("../../../../schemas/shared-control/009-state-read.sql");
    assert!(db.batch_execute(source).await.is_err());
    db.batch_execute("ROLLBACK; UPDATE signal_control.store SET ready=false")
        .await?;
    db.batch_execute(source).await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_state_read TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_state_read.read_state(jsonb,text,uuid,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    db.batch_execute("RESET ROLE").await?;
    // The preceding publication fixture intentionally expires its lease. Restore
    // only its deadline for this bounded read test, then restore that deadline.
    let prior_lease: String = db
        .query_one(
            "SELECT lease_until::text FROM signal_control.partitions WHERE id=$1",
            &[&token.scope.partition_id],
        )
        .await?
        .try_get(0)?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '60 seconds' WHERE id=$1",&[&token.scope.partition_id]).await?;
    let result = runtime
        .read_state(token.clone(), request.clone(), super::context()?)
        .await?;
    assert_eq!(result.checkpoint, checkpoint as u64);
    assert_eq!(
        result.state.ok_or("missing qualified state")?.bytes,
        expected
    );
    assert!(
        runtime
            .read_state(
                token.clone(),
                StateReadInput {
                    key: "missing".into(),
                    expected_head: head
                },
                super::context()?
            )
            .await?
            .state
            .is_none()
    );
    let mut stale = token.clone();
    stale.epoch += 1;
    assert!(matches!(
        runtime
            .read_state(stale, request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut foreign = token.clone();
    foreign.scope.tenant = "foreign-fixture".into();
    assert!(matches!(
        runtime
            .read_state(foreign, request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        runtime
            .read_state(
                token.clone(),
                StateReadInput {
                    key: request.key.clone(),
                    expected_head: Some(Uuid::from_u128(9999))
                },
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    db.batch_execute("ALTER FUNCTION signal_state_read.read_state(jsonb,text,uuid,bytea,bytea) SET search_path=pg_catalog").await?;
    assert!(matches!(
        runtime
            .read_state(token.clone(), request, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("ALTER FUNCTION signal_state_read.read_state(jsonb,text,uuid,bytea,bytea) SET search_path=pg_catalog,signal_control,pg_temp").await?;
    db.execute(
        "UPDATE signal_control.partitions SET lease_until=$2::text::timestamptz WHERE id=$1",
        &[&token.scope.partition_id, &prior_lease],
    )
    .await?;
    eprintln!("phase: fenced-revisioned-state-recovery-read-qualified");
    Ok(())
}

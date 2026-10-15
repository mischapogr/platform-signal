//! Actual worker/SQL credential inspection in the owned isolated database.
use signal_control::{ConnectionSettings, ControlClient, ControlError, ProducerDetectors};
use tokio_postgres::Client;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
async fn inspect(client: &ControlClient, window: bool) -> std::result::Result<(), ControlError> {
    client
        .verify_detector_producer_credentials(
            "signal_control_owner".into(),
            false,
            false,
            ProducerDetectors {
                window,
                sensor_health: true,
            },
            super::context().map_err(|_| ControlError::Invalid)?,
        )
        .await
}
pub async fn qualify(db: &Client, fixture: &super::Fixture, database: &str) -> Result {
    assert!(
        fixture
            .password
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    );
    db.batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    for source in [
        include_str!("../../../../schemas/shared-control/019-sensor-replay-pin.sql"),
        include_str!("../../../../schemas/shared-control/017-window-replay-pin.sql"),
        include_str!("../../../../schemas/shared-control/020-sensor-maintenance.sql"),
        include_str!("../../../../schemas/shared-control/021-sensor-bootstrap.sql"),
    ] {
        db.batch_execute(source).await?;
    }
    db.batch_execute("RESET ROLE; UPDATE signal_control.store SET ready=true")
        .await?;
    db.batch_execute(&format!("CREATE ROLE signal_sensor_test_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{}'; CREATE ROLE signal_sensor_test_probe NOLOGIN; GRANT USAGE ON SCHEMA signal_control,signal_finding_scope,signal_sensor_pin,signal_multi_event,signal_sensor_maintenance,signal_sensor_bootstrap TO signal_sensor_test_runtime; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.renew(jsonb,integer,bytea,bytea),signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea),signal_control.check_token(jsonb,bytea,bytea),signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea),signal_sensor_pin.retain(jsonb,bytea,bytea,bytea),signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea),signal_sensor_bootstrap.initialize(jsonb,bytea,bytea,bytea) TO signal_sensor_test_runtime",fixture.password)).await?;
    let runtime = ControlClient::catalog(ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        fixture.port,
        database.into(),
        "signal_sensor_test_runtime".into(),
        fixture.password.as_bytes().to_vec(),
    )?)?;
    inspect(&runtime, false).await?;
    db.batch_execute("REVOKE EXECUTE ON FUNCTION signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea) FROM signal_sensor_test_runtime").await?;
    assert!(matches!(
        inspect(&runtime, false).await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("GRANT EXECUTE ON FUNCTION signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea) TO signal_sensor_test_runtime").await?;
    inspect(&runtime, false).await?;
    assert!(matches!(
        runtime
            .verify_producer_credentials("signal_control_owner".into(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        runtime
            .verify_window_producer_credentials(
                "signal_control_owner".into(),
                false,
                false,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    for (grant, revoke) in [
        (
            "GRANT EXECUTE ON FUNCTION signal_control.object_control(jsonb,bytea,bytea,bytea) TO signal_sensor_test_runtime",
            "REVOKE EXECUTE ON FUNCTION signal_control.object_control(jsonb,bytea,bytea,bytea) FROM signal_sensor_test_runtime",
        ),
        (
            "GRANT EXECUTE ON FUNCTION signal_control.object_control(jsonb,bytea,bytea,bytea) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION signal_control.object_control(jsonb,bytea,bytea,bytea) FROM PUBLIC",
        ),
        (
            "GRANT SELECT ON signal_control.state TO signal_sensor_test_runtime",
            "REVOKE SELECT ON signal_control.state FROM signal_sensor_test_runtime",
        ),
        (
            "GRANT CREATE ON SCHEMA signal_sensor_pin TO signal_sensor_test_runtime",
            "REVOKE CREATE ON SCHEMA signal_sensor_pin FROM signal_sensor_test_runtime",
        ),
        (
            "GRANT EXECUTE ON FUNCTION signal_sensor_pin.retain(jsonb,bytea,bytea,bytea) TO signal_sensor_test_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION signal_sensor_pin.retain(jsonb,bytea,bytea,bytea) FROM signal_sensor_test_runtime",
        ),
        (
            "GRANT signal_control_owner TO signal_sensor_test_runtime",
            "REVOKE signal_control_owner FROM signal_sensor_test_runtime",
        ),
        (
            "GRANT EXECUTE ON FUNCTION signal_control.notification(jsonb,bytea,bytea,bytea) TO signal_sensor_test_probe; GRANT signal_sensor_test_probe TO signal_sensor_test_runtime WITH INHERIT FALSE",
            "REVOKE signal_sensor_test_probe FROM signal_sensor_test_runtime; REVOKE EXECUTE ON FUNCTION signal_control.notification(jsonb,bytea,bytea,bytea) FROM signal_sensor_test_probe",
        ),
    ] {
        db.batch_execute(grant).await?;
        assert!(
            matches!(inspect(&runtime, false).await, Err(ControlError::Fenced)),
            "mutable profile accepted: {grant}"
        );
        db.batch_execute(revoke).await?;
        inspect(&runtime, false).await?;
    }
    db.batch_execute("REVOKE EXECUTE ON FUNCTION signal_sensor_pin.retain(jsonb,bytea,bytea,bytea) FROM signal_sensor_test_runtime").await?;
    assert!(matches!(
        inspect(&runtime, false).await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("GRANT EXECUTE ON FUNCTION signal_sensor_pin.retain(jsonb,bytea,bytea,bytea) TO signal_sensor_test_runtime").await?;
    inspect(&runtime, false).await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_window_pin TO signal_sensor_test_runtime; GRANT EXECUTE ON FUNCTION signal_window_pin.retain(jsonb,bytea,bytea,bytea) TO signal_sensor_test_runtime").await?;
    assert!(matches!(
        inspect(&runtime, false).await,
        Err(ControlError::Fenced)
    ));
    inspect(&runtime, true).await?;
    db.batch_execute("REVOKE EXECUTE ON FUNCTION signal_window_pin.retain(jsonb,bytea,bytea,bytea) FROM signal_sensor_test_runtime").await?;
    db.batch_execute("SET ROLE signal_control_owner; CREATE FUNCTION signal_sensor_pin.unknown() RETURNS boolean LANGUAGE sql AS 'SELECT true'; RESET ROLE").await?;
    assert!(matches!(
        inspect(&runtime, false).await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute(
        "SET ROLE signal_control_owner; DROP FUNCTION signal_sensor_pin.unknown(); RESET ROLE",
    )
    .await?;
    inspect(&runtime, false).await?;
    runtime.shutdown(super::context()?).await?;
    db.batch_execute("DROP OWNED BY signal_sensor_test_runtime,signal_sensor_test_probe; DROP ROLE signal_sensor_test_runtime,signal_sensor_test_probe").await?;
    println!(
        "phase: sensor-producer-credentials-worker-isolation-public-membership-grant-option-and-mixed-window-qualified"
    );
    Ok(())
}

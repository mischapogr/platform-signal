//! Actual restricted SQL pin grants; canonical sensor payloads here are synthetic.
use super::multi_event_publication::witness;
use sha2::{Digest, Sha256};
use signal_control::{LeaseToken, ProducerEnrollment, PublicationInput};
use signal_storage::object_manifest::QueryManifest;
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
async fn call(
    db: &Client,
    token: &LeaseToken,
    input: &serde_json::Value,
) -> Result<serde_json::Value> {
    db.batch_execute("SAVEPOINT sensor_pin_call; SET SESSION AUTHORIZATION signal_runtime")
        .await?;
    let token = serde_json::json!({"scope":token.scope,"owner":token.owner,"epoch":token.epoch});
    let schema = signal_control::schema_identity().0.to_vec();
    let routines = signal_control::catalog_schema_identity().1.to_vec();
    let raw = serde_json::to_vec(input)?;
    let result = db
        .query_one(
            "SELECT signal_sensor_pin.retain($1,$2,$3,$4)",
            &[&token, &raw, &schema, &routines],
        )
        .await;
    if result.is_err() {
        db.batch_execute("ROLLBACK TO SAVEPOINT sensor_pin_call")
            .await?;
    }
    db.batch_execute("RESET SESSION AUTHORIZATION; RELEASE SAVEPOINT sensor_pin_call")
        .await?;
    Ok(result?.try_get(0)?)
}
pub async fn qualify(
    db: &Client,
    producer: &ProducerEnrollment,
    token: &LeaseToken,
    publication: &PublicationInput,
) -> Result {
    let before = witness(db).await?;
    db.batch_execute("SAVEPOINT sensor_pin_qualification")
        .await?;
    let source = include_str!("../../../../schemas/shared-control/019-sensor-replay-pin.sql");
    let body = source
        .strip_suffix("COMMIT;\n")
        .ok_or("pin terminator")?
        .replacen("BEGIN;\nSET LOCAL", "SET LOCAL", 1);
    for runtime in [false, true] {
        db.batch_execute("SAVEPOINT sensor_pin_install").await?;
        db.batch_execute(if runtime {
            "SET ROLE signal_runtime"
        } else {
            "SET ROLE signal_control_owner"
        })
        .await?;
        let error = db
            .batch_execute(&body)
            .await
            .err()
            .ok_or("unqualified pin install accepted")?;
        assert_eq!(
            error.as_db_error().ok_or("non-db install")?.code().code(),
            if runtime { "42501" } else { "P0001" }
        );
        db.batch_execute("ROLLBACK TO SAVEPOINT sensor_pin_install; RESET ROLE; RELEASE SAVEPOINT sensor_pin_install").await?;
    }
    db.batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    db.batch_execute(&body).await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_sensor_pin TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_sensor_pin.retain(jsonb,bytea,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let manifest: QueryManifest = serde_json::from_slice(&publication.manifest)?;
    let file = &manifest.files[0].object;
    let backend: Uuid = db
        .query_one(
            "SELECT backend_id FROM signal_control.commits WHERE partition_id=$1 AND id=$2",
            &[&token.scope.partition_id, &publication.id],
        )
        .await?
        .try_get(0)?;
    let object = serde_json::json!({"schema_version":1,"backend_id":backend,"key":file.key,"version":file.version});
    let state = publication
        .states
        .iter()
        .find(|s| s.key == "sensor-fixture")
        .ok_or("sensor state")?;
    let proof = serde_json::json!({"schema_version":1,"scope":producer.scope,"state_key":state.key,
        "rule_revision":state.revision,"metadata_sha256":<[u8;32]>::from(Sha256::digest(&state.bytes)),
        "object":object,"object_bytes":file.bytes,"object_sha256":file.sha256});
    let request = serde_json::json!({"schema_version":1,"operation":"pin","id":Uuid::from_u128(8990),"object":object,"kind":"replay","reference":hex(&serde_json::to_vec(&proof)?)});
    for mode in [
        "hash",
        "revision",
        "state-key",
        "scope",
        "version",
        "length",
        "digest",
        "kind",
        "generation",
        "metadata",
    ] {
        db.batch_execute("SAVEPOINT sensor_pin_refusal").await?;
        let mut bad = proof.clone();
        let mut input = request.clone();
        match mode {
            "hash" => bad["metadata_sha256"] = serde_json::json!(vec![9u8; 32]),
            "revision" => bad["rule_revision"] = serde_json::json!(vec![9u8; 32]),
            "state-key" => bad["state_key"] = serde_json::json!("window-fixture"),
            "scope" => bad["scope"]["tenant"] = serde_json::json!("foreign"),
            "version" => {
                bad["object"]["version"] = serde_json::json!("foreign");
                input["object"] = bad["object"].clone();
            }
            "length" => bad["object_bytes"] = serde_json::json!(file.bytes + 1),
            "digest" => bad["object_sha256"] = serde_json::json!(vec![9u8; 32]),
            "kind" => input["kind"] = serde_json::json!("custody"),
            "generation" => {
                // Preserve a valid FK but change the protected envelope generation.
                let mut value: serde_json::Value = serde_json::from_slice(&state.bytes)?;
                value["scope_generation"] = serde_json::json!(Uuid::new_v4());
                let bytes = serde_json::to_vec(&value)?;
                db.execute(
                    "UPDATE signal_control.state SET value=$1 WHERE partition_id=$2 AND key=$3",
                    &[&bytes, &token.scope.partition_id, &state.key],
                )
                .await?;
                bad["metadata_sha256"] =
                    serde_json::json!(<[u8; 32]>::from(Sha256::digest(&bytes)));
            }
            _ => {
                let mut value: serde_json::Value = serde_json::from_slice(&state.bytes)?;
                value["metadata"]["scope"]["tenant"] = serde_json::json!("foreign");
                let bytes = serde_json::to_vec(&value)?;
                db.execute(
                    "UPDATE signal_control.state SET value=$1 WHERE partition_id=$2 AND key=$3",
                    &[&bytes, &token.scope.partition_id, &state.key],
                )
                .await?;
                bad["metadata_sha256"] =
                    serde_json::json!(<[u8; 32]>::from(Sha256::digest(&bytes)));
            }
        }
        input["reference"] = serde_json::json!(hex(&serde_json::to_vec(&bad)?));
        let unchanged = witness(db).await?;
        assert!(call(db, token, &input).await.is_err(), "{mode}");
        assert_eq!(unchanged, witness(db).await?, "{mode} changed state");
        db.batch_execute(
            "ROLLBACK TO SAVEPOINT sensor_pin_refusal; RELEASE SAVEPOINT sensor_pin_refusal",
        )
        .await?;
    }
    let result = call(db, token, &request).await?;
    let pinned = witness(db).await?;
    assert_eq!(call(db, token, &request).await?, result);
    assert_eq!(pinned, witness(db).await?);
    db.batch_execute("ROLLBACK TO SAVEPOINT sensor_pin_qualification; RELEASE SAVEPOINT sensor_pin_qualification").await?;
    assert_eq!(before, witness(db).await?);
    println!(
        "phase: restricted-sensor-replay-pin-exact-state-scope-generation-object-refusal-and-replay-qualified"
    );
    Ok(())
}

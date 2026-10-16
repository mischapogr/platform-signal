//! Actual unchanged-checkpoint SQL transactions with synthetic sensor metadata.
use super::multi_event_publication::witness;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use signal_control::{LeaseToken, ProducerEnrollment, PublicationInput};
use tokio_postgres::Client;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
async fn call(db: &Client, token: &LeaseToken, r: &Value) -> Result<Value> {
    db.batch_execute("SAVEPOINT maintenance_call; SET SESSION AUTHORIZATION signal_runtime")
        .await?;
    let t = json!({"scope":token.scope,"owner":token.owner,"epoch":token.epoch});
    let raw = serde_json::to_vec(r)?;
    let schema = signal_control::schema_identity().0.to_vec();
    let routines = signal_control::catalog_schema_identity().1.to_vec();
    let result = db
        .query_one(
            "SELECT signal_sensor_maintenance.apply($1,$2,$3,$4)",
            &[&t, &raw, &schema, &routines],
        )
        .await;
    if result.is_err() {
        db.batch_execute("ROLLBACK TO SAVEPOINT maintenance_call")
            .await?;
    }
    db.batch_execute("RESET SESSION AUTHORIZATION; RELEASE SAVEPOINT maintenance_call")
        .await?;
    Ok(result?.try_get(0)?)
}
pub async fn qualify(
    db: &Client,
    producer: &ProducerEnrollment,
    token: &LeaseToken,
    publication: &PublicationInput,
) -> Result {
    let original = witness(db).await?;
    db.batch_execute("SAVEPOINT maintenance_qualification")
        .await?;
    let source = include_str!("../../../../schemas/shared-control/020-sensor-maintenance.sql");
    let body = source
        .strip_suffix("COMMIT;\n")
        .ok_or("maintenance terminator")?
        .replacen("BEGIN;\nSET LOCAL", "SET LOCAL", 1);
    for runtime in [false, true] {
        db.batch_execute("SAVEPOINT maintenance_install").await?;
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
            .ok_or("unsafe maintenance install accepted")?;
        assert_eq!(
            error.as_db_error().ok_or("non-db installer")?.code().code(),
            if runtime { "42501" } else { "P0001" }
        );
        db.batch_execute("ROLLBACK TO SAVEPOINT maintenance_install; RESET ROLE; RELEASE SAVEPOINT maintenance_install").await?;
    }
    db.batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    db.batch_execute(&body).await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_sensor_maintenance TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let state = publication
        .states
        .iter()
        .find(|s| s.key == "sensor-fixture")
        .ok_or("sensor state")?;
    let finding = publication
        .findings
        .iter()
        .find_map(|f| {
            let v: Value = serde_json::from_slice(&f.bytes).ok()?;
            v["rule_id"].as_str()?.starts_with("sensor").then_some(v)
        })
        .ok_or("sensor finding")?;
    let mut plain = finding.clone();
    plain["attributes"]
        .as_object_mut()
        .ok_or("finding attributes")?
        .remove("signal.scope.v1");
    let mut seeded: Value = serde_json::from_slice(&state.bytes)?;
    seeded["metadata"]["sensor"] = json!({"schema_version":1,"canonical_sha256":seeded["metadata"]["canonical_sha256"],
        "snapshot":{"schema_version":1,"stream":producer.scope.stream,"source_binding":vec![1u8;32],"policy_binding":vec![2u8;32],
        "record":{"schema_version":1,"revision":1,"checkpoint":publication.last_sequence,
        "state":{"schema_version":2,"proofs":[],"known":[],"monitor":{"schema_version":1,"policy_sha256":vec![3u8;32],"clock_ms":1000,"slots":[]},"history":{"entries":[],"expired":0,"evicted":0}},
        "outbox":[{"schema_version":1,"id":finding["id"],"bytes":{"schema_version":1,"finding":plain,"evidence":[]}}]}}});
    let seeded_bytes = serde_json::to_vec(&seeded)?;
    db.execute(
        "UPDATE signal_control.store SET used_bytes=used_bytes+$1 WHERE singleton",
        &[&((seeded_bytes.len() as i64) - (state.bytes.len() as i64))],
    )
    .await?;
    db.execute(
        "UPDATE signal_control.state SET value=$1 WHERE partition_id=$2 AND key=$3",
        &[&seeded_bytes, &token.scope.partition_id, &state.key],
    )
    .await?;
    let mut next = seeded.clone();
    next["metadata"]["sensor"]["snapshot"]["record"]["revision"] = json!(2);
    next["metadata"]["sensor"]["snapshot"]["record"]["state"]["monitor"]["clock_ms"] = json!(1001);
    next["metadata"]["sensor"]["snapshot"]["record"]["outbox"] = json!([]);
    let request = json!({"schema_version":1,"head":publication.id,"prior":{"schema_version":1,"key":state.key,"checkpoint":publication.last_sequence,"revision":hex(&state.revision),"value_sha256":hex(&Sha256::digest(&seeded_bytes)),"scope_generation":producer.scope_generation},"state":{"key":state.key,"revision":hex(&state.revision),"bytes":hex(&serde_json::to_vec(&next)?)},"retired":[{"id":finding["id"],"payload":finding}]});
    for mode in [
        "head",
        "prior",
        "checkpoint",
        "scope",
        "revision",
        "clock",
        "proof",
        "outbox",
        "finding",
        "unknown-finding",
        "canonical",
    ] {
        let mut bad = request.clone();
        let mut value = next.clone();
        match mode {
            "head" => bad["head"] = json!(uuid::Uuid::new_v4()),
            "prior" => bad["prior"]["value_sha256"] = json!("ff".repeat(32)),
            "checkpoint" => value["checkpoint"] = json!(publication.last_sequence + 1),
            "scope" => value["metadata"]["scope"]["tenant"] = json!("foreign"),
            "revision" => value["metadata"]["sensor"]["snapshot"]["record"]["revision"] = json!(3),
            "clock" => {
                value["metadata"]["sensor"]["snapshot"]["record"]["state"]["monitor"]["clock_ms"] =
                    json!(999)
            }
            "proof" => {
                value["metadata"]["sensor"]["snapshot"]["record"]["state"]["proofs"] =
                    json!([{"forged":true}])
            }
            "outbox" => bad["retired"] = json!([]),
            "finding" => bad["retired"][0]["payload"]["title"] = json!("changed"),
            "unknown-finding" => bad["retired"][0]["id"] = json!(uuid::Uuid::new_v4()),
            _ => value["canonical_sequences"][uuid::Uuid::new_v4().to_string()] = json!(1),
        }
        bad["state"]["bytes"] = json!(hex(&serde_json::to_vec(&value)?));
        let before = witness(db).await?;
        assert!(call(db, token, &bad).await.is_err(), "{mode}");
        assert_eq!(before, witness(db).await?, "{mode}");
    }
    let before = witness(db).await?;
    db.batch_execute("CREATE FUNCTION public.maintenance_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END $$; CREATE TRIGGER maintenance_fail BEFORE UPDATE ON signal_control.state FOR EACH ROW EXECUTE FUNCTION public.maintenance_fail()").await?;
    assert!(call(db, token, &request).await.is_err());
    assert_eq!(before, witness(db).await?);
    db.batch_execute("DROP TRIGGER maintenance_fail ON signal_control.state; DROP FUNCTION public.maintenance_fail()").await?;
    let maximum: i64 = db
        .query_one(
            "SELECT max_bytes FROM signal_control.store WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    db.batch_execute("UPDATE signal_control.store SET max_bytes=used_bytes WHERE singleton")
        .await?;
    let quota = witness(db).await?;
    let mut larger = next.clone();
    larger["metadata"]["sensor"]["snapshot"]["record"]["state"]["history"]["entries"] =
        json!([{"fixture":"x".repeat(4096)}]);
    let mut growth = request.clone();
    growth["state"]["bytes"] = json!(hex(&serde_json::to_vec(&larger)?));
    let error = call(db, token, &growth)
        .await
        .err()
        .ok_or("quota accepted")?;
    assert_eq!(
        error
            .downcast_ref::<tokio_postgres::Error>()
            .and_then(|e| e.as_db_error())
            .ok_or("non-db quota")?
            .message(),
        "SIGNAL_FULL"
    );
    assert_eq!(quota, witness(db).await?);
    db.execute(
        "UPDATE signal_control.store SET max_bytes=$1 WHERE singleton",
        &[&maximum],
    )
    .await?;
    let result = call(db, token, &request).await?;
    let committed = witness(db).await?;
    assert_eq!(call(db, token, &request).await?, result);
    assert_eq!(committed, witness(db).await?);
    assert_eq!(result["checkpoint"], json!(publication.last_sequence));
    assert_eq!(result["head"], json!(publication.id));
    db.batch_execute("ROLLBACK TO SAVEPOINT maintenance_qualification; RELEASE SAVEPOINT maintenance_qualification").await?;
    assert_eq!(original, witness(db).await?);
    println!(
        "phase: sensor-idle-maintenance-original-head-checkpoint-prefix-refusal-late-rollback-and-target-replay-qualified"
    );
    Ok(())
}

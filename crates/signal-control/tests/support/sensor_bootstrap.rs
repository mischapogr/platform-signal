//! Actual empty-partition bootstrap/idle transactions; enrollment and state are synthetic.
use super::multi_event_publication::witness;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use signal_control::{LeaseToken, ProducerEnrollment};
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
async fn call(db: &Client, token: &LeaseToken, input: &Value, maintenance: bool) -> Result<Value> {
    db.batch_execute("SAVEPOINT bootstrap_call; SET SESSION AUTHORIZATION signal_runtime")
        .await?;
    let t = json!({"scope":token.scope,"owner":token.owner,"epoch":token.epoch});
    let raw = serde_json::to_vec(input)?;
    let schema = signal_control::schema_identity().0.to_vec();
    let routines = signal_control::catalog_schema_identity().1.to_vec();
    let query = if maintenance {
        "SELECT signal_sensor_maintenance.apply($1,$2,$3,$4)"
    } else {
        "SELECT signal_sensor_bootstrap.initialize($1,$2,$3,$4)"
    };
    let result = db.query_one(query, &[&t, &raw, &schema, &routines]).await;
    if result.is_err() {
        db.batch_execute("ROLLBACK TO SAVEPOINT bootstrap_call")
            .await?;
    }
    db.batch_execute("RESET SESSION AUTHORIZATION; RELEASE SAVEPOINT bootstrap_call")
        .await?;
    Ok(result?.try_get(0)?)
}
pub async fn qualify(db: &Client, producer: &ProducerEnrollment, token: &LeaseToken) -> Result {
    let original = witness(db).await?;
    db.batch_execute("SAVEPOINT bootstrap_qualification")
        .await?;
    let source = include_str!("../../../../schemas/shared-control/021-sensor-bootstrap.sql");
    let body = source
        .strip_suffix("COMMIT;\n")
        .ok_or("bootstrap terminator")?
        .replacen("BEGIN;\nSET LOCAL", "SET LOCAL", 1);
    for runtime in [false, true] {
        db.batch_execute("SAVEPOINT bootstrap_install").await?;
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
            .ok_or("unsafe bootstrap install accepted")?;
        assert_eq!(
            error.as_db_error().ok_or("non-db installer")?.code().code(),
            if runtime { "42501" } else { "P0001" }
        );
        db.batch_execute("ROLLBACK TO SAVEPOINT bootstrap_install; RESET ROLE; RELEASE SAVEPOINT bootstrap_install").await?;
    }
    db.batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    db.batch_execute(&body).await?;
    db.batch_execute(
        include_str!("../../../../schemas/shared-control/020-sensor-maintenance.sql")
            .strip_suffix("COMMIT;\n")
            .ok_or("maintenance terminator")?
            .replacen("BEGIN;\nSET LOCAL", "SET LOCAL", 1)
            .as_str(),
    )
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_sensor_bootstrap,signal_sensor_maintenance TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_sensor_bootstrap.initialize(jsonb,bytea,bytea,bytea),signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let mut empty = token.clone();
    empty.scope.partition_id = Uuid::from_u128(8950);
    empty.scope.stream = Uuid::from_u128(8951);
    empty.scope.tenant = "synthetic-bootstrap".into();
    empty.epoch = 1;
    db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind,epoch,owner,lease_until) VALUES($1,$2,$3,'pipeline',1,$4,clock_timestamp()+interval '60 seconds')",&[&empty.scope.partition_id,&empty.scope.tenant,&empty.scope.stream,&empty.owner]).await?;
    db.execute(
        "INSERT INTO signal_control.principals VALUES('signal_runtime',$1,$2,$3)",
        &[
            &empty.scope.tenant,
            &empty.scope.stream,
            &empty.scope.partition_id,
        ],
    )
    .await?;
    db.execute("INSERT INTO signal_finding_scope.producers(partition_id,scope_generation,stream,startup_id,wal_floor) VALUES($1,$2,$3,$4,0)",&[&empty.scope.partition_id,&producer.scope_generation,&empty.scope.stream,&Uuid::from_u128(8952)]).await?;
    let state = json!({"schema_version":1,"scope_generation":producer.scope_generation,"checkpoint":0,"canonical_sequences":{},
        "metadata":{"schema_version":1,"scope":empty.scope,"key":"sensor-empty","rule_revision":vec![1u8;32],"canonical_sha256":{},
        "sensor":{"schema_version":1,"canonical_sha256":{},"snapshot":{"schema_version":1,"stream":empty.scope.stream,"source_binding":vec![2u8;32],"policy_binding":vec![3u8;32],
        "record":{"schema_version":1,"revision":1,"checkpoint":0,"outbox":[],"state":{"schema_version":2,"proofs":[],"known":[],"history":{"entries":[],"expired":0,"evicted":0},
        "monitor":{"schema_version":1,"policy_sha256":vec![4u8;32],"clock_ms":1000,"slots":[{"latest":null,"heartbeat_at_ms":null,"checkpoint":null}]}}}}}}});
    let bytes = serde_json::to_vec(&state)?;
    let request = json!({"schema_version":1,"head":null,"checkpoint":0,"state":{"key":"sensor-empty","revision":hex(&[1;32]),"bytes":hex(&bytes)}});
    for mode in [
        "head",
        "checkpoint",
        "scope",
        "output",
        "proof",
        "observation",
        "revision",
        "canonical",
    ] {
        let mut bad = request.clone();
        let mut value = state.clone();
        match mode {
            "head" => bad["head"] = json!(Uuid::new_v4()),
            "checkpoint" => bad["checkpoint"] = json!(1),
            "scope" => value["metadata"]["scope"]["tenant"] = json!("foreign"),
            "output" => {
                value["metadata"]["sensor"]["snapshot"]["record"]["outbox"] =
                    json!([{"id":Uuid::new_v4()}])
            }
            "proof" => {
                value["metadata"]["sensor"]["snapshot"]["record"]["state"]["proofs"] =
                    json!([{"fixture":true}])
            }
            "observation" => {
                value["metadata"]["sensor"]["snapshot"]["record"]["state"]["monitor"]["slots"][0]
                    ["latest"] = json!({"fixture":true})
            }
            "revision" => value["metadata"]["sensor"]["snapshot"]["record"]["revision"] = json!(2),
            _ => value["canonical_sequences"][Uuid::new_v4().to_string()] = json!(1),
        }
        bad["state"]["bytes"] = json!(hex(&serde_json::to_vec(&value)?));
        let before = witness(db).await?;
        assert!(call(db, &empty, &bad, false).await.is_err(), "{mode}");
        assert_eq!(before, witness(db).await?, "{mode}");
    }
    let maximum: i64 = db
        .query_one(
            "SELECT max_rows FROM signal_control.store WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    db.batch_execute("UPDATE signal_control.store SET max_rows=used_rows WHERE singleton")
        .await?;
    let quota = witness(db).await?;
    assert!(call(db, &empty, &request, false).await.is_err());
    assert_eq!(quota, witness(db).await?);
    db.execute(
        "UPDATE signal_control.store SET max_rows=$1 WHERE singleton",
        &[&maximum],
    )
    .await?;
    let before = witness(db).await?;
    let result = call(db, &empty, &request, false).await?;
    let committed = witness(db).await?;
    assert_eq!(call(db, &empty, &request, false).await?, result);
    assert_eq!(committed, witness(db).await?);
    assert_eq!(committed["core"]["commits"], before["core"]["commits"]);
    assert_eq!(committed["core"]["findings"], before["core"]["findings"]);
    assert_eq!(
        committed["core"]["store"]["used_rows"].as_i64(),
        before["core"]["store"]["used_rows"].as_i64().map(|n| n + 1)
    );
    assert_eq!(
        committed["core"]["store"]["used_bytes"].as_i64(),
        before["core"]["store"]["used_bytes"]
            .as_i64()
            .map(|n| n + 192 + "sensor-empty".len() as i64 + bytes.len() as i64)
    );
    let mut next = state.clone();
    next["metadata"]["sensor"]["snapshot"]["record"]["revision"] = json!(2);
    next["metadata"]["sensor"]["snapshot"]["record"]["state"]["monitor"]["clock_ms"] = json!(1001);
    let mut different = request.clone();
    different["state"]["bytes"] = json!(hex(&serde_json::to_vec(&next)?));
    let before = witness(db).await?;
    assert!(call(db, &empty, &different, false).await.is_err());
    assert_eq!(before, witness(db).await?);
    let maintain = json!({"schema_version":1,"head":null,"prior":{"schema_version":1,"key":"sensor-empty","checkpoint":0,"revision":hex(&[1;32]),"value_sha256":hex(&Sha256::digest(&bytes)),"scope_generation":producer.scope_generation},"state":{"key":"sensor-empty","revision":hex(&[1;32]),"bytes":hex(&serde_json::to_vec(&next)?)},"retired":[]});
    let tick = call(db, &empty, &maintain, true).await?;
    assert!(tick["head"].is_null());
    assert_eq!(tick["checkpoint"], json!(0));
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM signal_control.commits WHERE partition_id=$1",
            &[&empty.scope.partition_id],
        )
        .await?
        .try_get(0)?;
    assert_eq!(count, 0);
    assert_eq!(call(db, &empty, &maintain, true).await?, tick);
    db.batch_execute(
        "ROLLBACK TO SAVEPOINT bootstrap_qualification; RELEASE SAVEPOINT bootstrap_qualification",
    )
    .await?;
    assert_eq!(original, witness(db).await?);
    println!(
        "phase: sensor-explicit-empty-checkpoint-bootstrap-quota-refusal-no-events-idle-tick-and-exact-replay-qualified"
    );
    Ok(())
}

use signal_control::{
    CanonicalObjectRef, ControlClient, ControlError, LeaseToken, PublicationInput, ReleasePinInput,
    RetentionKind, RetentionPinInput, RetirementInput, SnapshotInput,
};
use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;
fn object(token: &LeaseToken, label: &str) -> CanonicalObjectRef {
    CanonicalObjectRef {
        schema_version: 1,
        backend_id: Uuid::from_u128(0x20),
        key: format!("query/{}/orphan/{label}", token.scope.stream),
        version: "synthetic-v1".into(),
    }
}
fn retire(reference: CanonicalObjectRef) -> RetirementInput {
    RetirementInput {
        schema_version: 1,
        id: Uuid::new_v4(),
        object: reference,
        reason: b"explicit-synthetic-retention-decision".to_vec(),
    }
}
fn hold(reference: CanonicalObjectRef, kind: RetentionKind) -> RetentionPinInput {
    RetentionPinInput {
        schema_version: 1,
        id: Uuid::new_v4(),
        object: reference,
        kind,
        reference: b"synthetic-private-retention-provenance".to_vec(),
    }
}
async fn witness(db: &Client) -> Result<serde_json::Value, Error> {
    Ok(db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'partitions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p),'commits',(SELECT jsonb_agg(to_jsonb(c) ORDER BY partition_id,id) FROM signal_control.commits c),'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signal_control.snapshots s),'pins',(SELECT jsonb_agg(to_jsonb(p) ORDER BY partition_id,id) FROM signal_control.object_pins p),'tombstones',(SELECT jsonb_agg(to_jsonb(t) ORDER BY partition_id,id) FROM signal_control.tombstones t))",&[]).await?.try_get(0)?)
}
async fn assert_retirement_denied(
    db: &Client,
    runtime: &ControlClient,
    token: &LeaseToken,
    reference: CanonicalObjectRef,
) -> Result<(), Error> {
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(token.clone(), retire(reference), super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    Ok(())
}
fn publication(token: &LeaseToken, version: &str) -> Result<PublicationInput, Error> {
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: token.scope.stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: 1,
        last_sequence: 1,
        events: 1,
        previous: None,
        files: vec![QueryFile {
            date: "2026-10-10".into(),
            hour: 0,
            object: QueryObjectRef {
                key: data_key(token.scope.stream, "2026-10-10", 0, [9; 32]),
                version: Some(version.into()),
                etag: None,
                bytes: 128,
                sha256: [9; 32],
            },
            rows: 1,
            decoded_bytes: 256,
        }],
    };
    Ok(PublicationInput {
        schema_version: 1,
        id: Uuid::new_v4(),
        previous: None,
        first_sequence: 1,
        last_sequence: 1,
        manifest: serde_json::to_vec(&manifest)?,
        rule_revision: [1; 32],
        normalizer_revision: "synthetic-v1".into(),
        states: vec![],
        findings: vec![],
        work: vec![],
        receipts: vec![],
    })
}
pub async fn qualify(
    db: &Client,
    runtime: &ControlClient,
    original: &LeaseToken,
) -> Result<(), Error> {
    eprintln!("phase: canonical-backend-global-retirement-and-pins");
    // Two partitions alias one physical namespace, with a third independent namespace.
    for (id, tenant, backend) in [
        (7, "synthetic-retirement", 0x20),
        (8, "synthetic-other-backend", 0x21),
        (9, "synthetic-race", 0x20),
    ] {
        if backend == 0x21 {
            db.execute("INSERT INTO signal_control.object_backends(id,canonical_id) VALUES($1,'fixture-independent-object-namespace')",&[&Uuid::from_u128(backend)]).await?;
        }
        db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",&[&Uuid::from_u128(id),&tenant,&original.scope.stream]).await?;
        db.execute("INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES('signal_runtime',$1,$2,$3)",&[&tenant,&original.scope.stream,&Uuid::from_u128(id)]).await?;
        db.execute("INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES($1,$2,$3)",&[&Uuid::from_u128(id),&Uuid::from_u128(backend),&format!("query/{}/",original.scope.stream)]).await?;
    }
    let duplicate=db.execute("INSERT INTO signal_control.object_backends(id,canonical_id) VALUES($1,'fixture-control-object-namespace-v1')",&[&Uuid::new_v4()]).await;
    assert_eq!(
        duplicate
            .err()
            .ok_or("canonical namespace alias must fail")?
            .as_db_error()
            .map(|e| e.code().code()),
        Some("23505")
    );
    let mut scope = original.scope.clone();
    scope.partition_id = Uuid::from_u128(7);
    scope.tenant = "synthetic-retirement".into();
    let mut owner = runtime
        .acquire(scope.clone(), Uuid::from_u128(30), 60000, super::context()?)
        .await?;
    let mut independent_scope = original.scope.clone();
    independent_scope.partition_id = Uuid::from_u128(8);
    independent_scope.tenant = "synthetic-other-backend".into();
    let independent = runtime
        .acquire(
            independent_scope,
            Uuid::from_u128(31),
            60000,
            super::context()?,
        )
        .await?;
    let mut race_scope = original.scope.clone();
    race_scope.partition_id = Uuid::from_u128(9);
    race_scope.tenant = "synthetic-race".into();
    let race = runtime
        .acquire(race_scope, Uuid::from_u128(32), 60000, super::context()?)
        .await?;
    let (schema, routines) = signal_control::schema_identity();
    let reference = object(&owner, "identity");
    let encoded = reference.identity_bytes()?;
    let json = serde_json::to_value(&reference)?;
    let row=db.query_one("SELECT signal_control.object_reference($1),sha256(signal_control.object_reference($1))",&[&json]).await?;
    assert_eq!(row.get::<_, Vec<u8>>(0), encoded);
    assert_eq!(row.get::<_, Vec<u8>>(1), reference.digest()?.to_vec());
    // Current and historical replay roots are global, including predecessor objects.
    let commits=db.query("SELECT manifest FROM signal_control.commits WHERE partition_id=$1 ORDER BY first_sequence",&[&original.scope.partition_id]).await?;
    for index in [0, commits.len() - 1] {
        let manifest: QueryManifest = serde_json::from_slice(&commits[index].get::<_, Vec<u8>>(0))?;
        let referenced = &manifest.files[0].object;
        assert_retirement_denied(
            db,
            runtime,
            &owner,
            CanonicalObjectRef {
                schema_version: 1,
                backend_id: reference.backend_id,
                key: referenced.key.clone(),
                version: referenced.version.clone().ok_or("exact version")?,
            },
        )
        .await?;
        if let Some(prior) = manifest.previous {
            assert_retirement_denied(
                db,
                runtime,
                &owner,
                CanonicalObjectRef {
                    schema_version: 1,
                    backend_id: reference.backend_id,
                    key: prior.object.key,
                    version: prior.object.version.ok_or("predecessor version")?,
                },
            )
            .await?;
        }
    }
    // Omitting a stored object digest cannot make committed data eligible.
    let indexed=db.query_one("SELECT id,object_hashes FROM signal_control.commits WHERE partition_id=$1 ORDER BY first_sequence LIMIT 1",&[&original.scope.partition_id]).await?;
    let indexed_id = indexed.get::<_, Uuid>(0);
    let original_hashes = indexed.get::<_, Vec<Vec<u8>>>(1);
    db.execute("UPDATE signal_control.commits SET object_hashes=ARRAY[decode(repeat('ab',32),'hex')] WHERE partition_id=$1 AND id=$2",&[&original.scope.partition_id,&indexed_id]).await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(
                owner.clone(),
                retire(object(&owner, "corrupt-index")),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute(
        "UPDATE signal_control.commits SET object_hashes=$3 WHERE partition_id=$1 AND id=$2",
        &[&original.scope.partition_id, &indexed_id, &original_hashes],
    )
    .await?;
    let protected = object(&owner, "protected");
    let holds: Vec<RetentionPinInput> = [
        RetentionKind::Restore,
        RetentionKind::Replay,
        RetentionKind::Evidence,
    ]
    .into_iter()
    .map(|kind| hold(protected.clone(), kind))
    .collect();
    for pin in &holds {
        let result = runtime
            .pin_object(owner.clone(), pin.clone(), super::context()?)
            .await?;
        assert_eq!(result.reference_sha256, signal_control_digest(&protected)?);
        let before = witness(db).await?;
        assert_eq!(
            runtime
                .pin_object(owner.clone(), pin.clone(), super::context()?)
                .await?,
            result
        );
        assert_eq!(witness(db).await?, before);
        assert_retirement_denied(db, runtime, original, protected.clone()).await?;
    }
    for (i, pin) in holds.iter().enumerate() {
        let mut stale = owner.clone();
        stale.epoch += 1;
        let release = ReleasePinInput {
            schema_version: 1,
            id: pin.id,
            reason: b"synthetic-explicit-release".to_vec(),
        };
        let before = witness(db).await?;
        assert!(matches!(
            runtime
                .release_object_pin(stale, release.clone(), super::context()?)
                .await,
            Err(ControlError::Fenced)
        ));
        assert_eq!(witness(db).await?, before);
        let result = runtime
            .release_object_pin(owner.clone(), release.clone(), super::context()?)
            .await?;
        let before = witness(db).await?;
        assert_eq!(
            runtime
                .release_object_pin(owner.clone(), release.clone(), super::context()?)
                .await?,
            result
        );
        let mut changed = release;
        changed.reason.push(1);
        assert!(matches!(
            runtime
                .release_object_pin(owner.clone(), changed, super::context()?)
                .await,
            Err(ControlError::Conflict)
        ));
        assert!(matches!(
            runtime
                .pin_object(owner.clone(), pin.clone(), super::context()?)
                .await,
            Err(ControlError::Conflict)
        ));
        assert_eq!(witness(db).await?, before);
        if i < 2 {
            assert_retirement_denied(db, runtime, original, protected.clone()).await?;
        }
    }
    let retired = retire(protected.clone());
    let result = runtime
        .retire_object(original.clone(), retired.clone(), super::context()?)
        .await?;
    let before = witness(db).await?;
    assert_eq!(
        runtime
            .retire_object(original.clone(), retired.clone(), super::context()?)
            .await?,
        result
    );
    assert_eq!(witness(db).await?, before);
    assert!(matches!(
        runtime
            .pin_object(
                owner.clone(),
                hold(protected.clone(), RetentionKind::Evidence),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    let mut changed = retired.clone();
    changed.reason.push(1);
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(original.clone(), changed, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute(
        "UPDATE signal_control.tombstones SET state='blocked' WHERE partition_id=$1 AND id=$2",
        &[&original.scope.partition_id, &retired.id],
    )
    .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(original.clone(), retired.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute(
        "UPDATE signal_control.tombstones SET state='retired' WHERE partition_id=$1 AND id=$2",
        &[&original.scope.partition_id, &retired.id],
    )
    .await?;
    // Unrelated exact versions and backend namespaces are independently eligible.
    let mut different = protected.clone();
    different.version = "synthetic-v2".into();
    runtime
        .pin_object(
            owner.clone(),
            hold(different, RetentionKind::Restore),
            super::context()?,
        )
        .await?;
    let mut foreign = protected.clone();
    foreign.backend_id = Uuid::from_u128(0x21);
    assert!(matches!(
        runtime
            .retire_object(owner.clone(), retire(foreign.clone()), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    runtime
        .retire_object(independent.clone(), retire(foreign), super::context()?)
        .await?;
    // Isolate the reader predicate with a synthetic owned reader root; actual API
    // snapshots above populate the same object digest array from committed manifests.
    let reader_object = object(&owner, "reader-root");
    let reader_id = Uuid::new_v4();
    let digest = reader_object.digest()?.to_vec();
    db.execute("INSERT INTO signal_control.snapshots(id,partition_id,generation,manifest_ids,expires_at,pin_ms,object_hashes,objects_sha256) VALUES($1,$2,$3,uuid_send($4),statement_timestamp()+interval '5 seconds',5000,ARRAY[$5::bytea],signal_control.reader_object_seal($1,$2,$3,uuid_send($4),statement_timestamp()+interval '5 seconds',5000,ARRAY[$5::bytea]))",&[&reader_id,&original.scope.partition_id,&original.scope.generation,&Uuid::from_u128(100),&digest]).await?;
    db.batch_execute(
        "UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+368",
    )
    .await?;
    assert_retirement_denied(db, runtime, &owner, reader_object.clone()).await?;
    db.execute("UPDATE signal_control.snapshots SET expires_at=statement_timestamp()-interval '1 second' WHERE id=$1",&[&reader_id]).await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(
                owner.clone(),
                retire(reader_object.clone()),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, before);
    assert!(matches!(
        runtime
            .read_snapshot(
                original.scope.clone(),
                SnapshotInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    manifest_ids: vec![Uuid::from_u128(100)],
                    pin_ms: 5000
                },
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute("UPDATE signal_control.snapshots SET expires_at=statement_timestamp()-interval '1 second',objects_sha256=signal_control.reader_object_seal(id,partition_id,generation,manifest_ids,statement_timestamp()-interval '1 second',pin_ms,object_hashes) WHERE id=$1",&[&reader_id]).await?;
    runtime
        .retire_object(owner.clone(), retire(reader_object), super::context()?)
        .await?;
    // Tombstoned data is not republished through a different tenant/partition alias.
    let blocked = data_key(owner.scope.stream, "2026-10-10", 0, [9; 32]);
    let blocked_ref = CanonicalObjectRef {
        schema_version: 1,
        backend_id: reference.backend_id,
        key: blocked,
        version: "retired-v1".into(),
    };
    runtime
        .retire_object(original.clone(), retire(blocked_ref), super::context()?)
        .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .publish(
                owner.clone(),
                publication(&owner, "retired-v1")?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    let valid = publication(&owner, "retired-v2")?;
    runtime
        .publish(owner.clone(), valid.clone(), super::context()?)
        .await?;
    runtime
        .read_snapshot(
            owner.scope.clone(),
            SnapshotInput {
                schema_version: 1,
                id: Uuid::new_v4(),
                manifest_ids: vec![valid.id],
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?
        .check()?;
    // Even a synthetically corrupted committed tuple cannot serve a retired object.
    let mut corrupt: QueryManifest = serde_json::from_slice(&valid.manifest)?;
    corrupt.files[0].object.version = Some("retired-v1".into());
    let corrupt = serde_json::to_vec(&corrupt)?;
    db.execute("UPDATE signal_control.commits SET manifest=$3,manifest_sha256=sha256($3),objects_sha256=signal_control.commit_object_seal(backend_id,sha256($3),object_hashes) WHERE partition_id=$1 AND id=$2",&[&owner.scope.partition_id,&valid.id,&corrupt]).await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                owner.scope.clone(),
                SnapshotInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    manifest_ids: vec![valid.id],
                    pin_ms: 5000
                },
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute("UPDATE signal_control.commits SET manifest=$3,manifest_sha256=sha256($3),objects_sha256=signal_control.commit_object_seal(backend_id,sha256($3),object_hashes) WHERE partition_id=$1 AND id=$2",&[&owner.scope.partition_id,&valid.id,&valid.manifest]).await?;
    eprintln!("phase: retirement-quota-stale-authority-and-rollback");
    for command in [
        "UPDATE signal_control.store SET max_rows=used_rows",
        "UPDATE signal_control.store SET max_bytes=used_bytes",
    ] {
        db.batch_execute(command).await?;
        let before = witness(db).await?;
        assert!(matches!(
            runtime
                .retire_object(
                    owner.clone(),
                    retire(object(&owner, "quota")),
                    super::context()?
                )
                .await,
            Err(ControlError::Full)
        ));
        assert!(matches!(
            runtime
                .pin_object(
                    owner.clone(),
                    hold(object(&owner, "quota-pin"), RetentionKind::Evidence),
                    super::context()?
                )
                .await,
            Err(ControlError::Full)
        ));
        assert_eq!(witness(db).await?, before);
        db.batch_execute("UPDATE signal_control.store SET max_rows=65536,max_bytes=67108864")
            .await?;
    }
    let pending = hold(object(&owner, "release-quota"), RetentionKind::Restore);
    runtime
        .pin_object(owner.clone(), pending.clone(), super::context()?)
        .await?;
    db.batch_execute("UPDATE signal_control.store SET max_bytes=used_bytes")
        .await?;
    let before = witness(db).await?;
    let release = ReleasePinInput {
        schema_version: 1,
        id: pending.id,
        reason: b"explicit-synthetic-release".to_vec(),
    };
    assert!(matches!(
        runtime
            .release_object_pin(owner.clone(), release.clone(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(db).await?, before);
    db.batch_execute("UPDATE signal_control.store SET max_bytes=67108864")
        .await?;
    // Forced expiry happens after admission and child writes. Rollback restores the
    // lease as well as the lifecycle/capacity mutation performed in that transaction.
    db.batch_execute("CREATE FUNCTION public.synthetic_retention_expiry() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '20 milliseconds' WHERE id=NEW.partition_id; PERFORM pg_sleep(0.04); RETURN NEW; END $$; CREATE TRIGGER synthetic_retention_expiry BEFORE INSERT OR UPDATE ON signal_control.object_pins FOR EACH ROW EXECUTE FUNCTION public.synthetic_retention_expiry(); CREATE TRIGGER synthetic_retention_expiry BEFORE INSERT ON signal_control.tombstones FOR EACH ROW EXECUTE FUNCTION public.synthetic_retention_expiry()").await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(
                owner.clone(),
                retire(object(&owner, "expiry")),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        runtime
            .pin_object(
                owner.clone(),
                hold(object(&owner, "expiry-pin"), RetentionKind::Evidence),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        runtime
            .release_object_pin(owner.clone(), release, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    db.batch_execute("DROP TRIGGER synthetic_retention_expiry ON signal_control.object_pins; DROP TRIGGER synthetic_retention_expiry ON signal_control.tombstones; DROP FUNCTION public.synthetic_retention_expiry()").await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&owner.scope.partition_id]).await?;
    let old = owner.clone();
    owner = runtime
        .acquire(scope.clone(), Uuid::from_u128(33), 60000, super::context()?)
        .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .retire_object(
                old.clone(),
                retire(object(&owner, "stale")),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    let mut old_generation = owner.clone();
    old_generation.scope.generation = Uuid::new_v4();
    assert!(matches!(
        runtime
            .retire_object(
                old_generation,
                retire(object(&owner, "stale-generation")),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .pin_object(
                old.clone(),
                hold(object(&owner, "takeover-pin"), RetentionKind::Evidence),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    let takeover_release = ReleasePinInput {
        schema_version: 1,
        id: pending.id,
        reason: b"new-current-owner-explicit-release".to_vec(),
    };
    assert!(matches!(
        runtime
            .release_object_pin(old, takeover_release.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    runtime
        .release_object_pin(owner.clone(), takeover_release, super::context()?)
        .await?;
    let audit=db.query_one("SELECT owner,epoch,release_owner,release_epoch FROM signal_control.object_pins WHERE partition_id=$1 AND id=$2",&[&owner.scope.partition_id,&pending.id]).await?;
    assert_eq!(audit.get::<_, Uuid>(0), Uuid::from_u128(30));
    assert_eq!(audit.get::<_, i64>(1), 1);
    assert_eq!(audit.get::<_, Uuid>(2), owner.owner);
    assert_eq!(audit.get::<_, i64>(3), owner.epoch as i64);
    eprintln!("phase: concurrent-pin-and-publication-versus-retirement");
    let contested = object(&owner, "race");
    let before_rows = db
        .query_one("SELECT used_rows FROM signal_control.store", &[])
        .await?
        .get::<_, i64>(0);
    let (pin, tomb) = tokio::join!(
        runtime.pin_object(
            owner.clone(),
            hold(contested.clone(), RetentionKind::Evidence),
            super::context()?
        ),
        runtime.retire_object(original.clone(), retire(contested), super::context()?)
    );
    assert_eq!(usize::from(pin.is_ok()) + usize::from(tomb.is_ok()), 1);
    if pin.is_ok() {
        assert!(matches!(tomb, Err(ControlError::Conflict)));
    } else {
        assert!(matches!(pin, Err(ControlError::Fenced)));
    }
    assert_eq!(
        db.query_one("SELECT used_rows FROM signal_control.store", &[])
            .await?
            .get::<_, i64>(0),
        before_rows + 1
    );
    let candidate = publication(&race, "race-version")?;
    let manifest: QueryManifest = serde_json::from_slice(&candidate.manifest)?;
    let candidate_ref = CanonicalObjectRef {
        schema_version: 1,
        backend_id: reference.backend_id,
        key: manifest.files[0].object.key.clone(),
        version: "race-version".into(),
    };
    let (published, tomb) = tokio::join!(
        runtime.publish(race.clone(), candidate.clone(), super::context()?),
        runtime.retire_object(owner.clone(), retire(candidate_ref), super::context()?)
    );
    assert_eq!(
        usize::from(published.is_ok()) + usize::from(tomb.is_ok()),
        1
    );
    if published.is_ok() {
        assert!(matches!(tomb, Err(ControlError::Conflict)));
    } else {
        assert!(matches!(published, Err(ControlError::Fenced)));
    }
    // Restricted principal input rejection and missing table/helper authority.
    let token_json = serde_json::to_value(&owner)?;
    for malformed in [
        serde_json::json!({"schema_version":1,"operation":"delete","id":Uuid::new_v4()}),
        serde_json::json!({"schema_version":1,"operation":"retire","id":Uuid::new_v4(),"object":{"schema_version":1,"backend_id":reference.backend_id,"key":reference.key,"version":null},"reason":"01"}),
        serde_json::json!({"schema_version":1,"operation":"release","id":pending.id,"reason":"01","force":true}),
    ] {
        let raw = serde_json::to_vec(&malformed)?;
        let before = witness(db).await?;
        db.batch_execute("SET SESSION AUTHORIZATION signal_runtime")
            .await?;
        let result = db
            .query_one(
                "SELECT signal_control.object_control($1,$2,$3,$4)",
                &[&token_json, &raw, &schema.as_slice(), &routines.as_slice()],
            )
            .await;
        db.batch_execute("RESET SESSION AUTHORIZATION").await?;
        assert_eq!(
            result
                .err()
                .ok_or("malformed lifecycle input accepted")?
                .as_db_error()
                .map(|e| e.message()),
            Some("SIGNAL_INVALID")
        );
        assert_eq!(witness(db).await?, before);
    }
    db.batch_execute("SET SESSION AUTHORIZATION signal_denied")
        .await?;
    let raw = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"operation":"retire","id":Uuid::new_v4(),"object":reference,"reason":"01"}),
    )?;
    let denied = db
        .query_one(
            "SELECT signal_control.object_control($1,$2,$3,$4)",
            &[&token_json, &raw, &schema.as_slice(), &routines.as_slice()],
        )
        .await;
    db.batch_execute("RESET SESSION AUTHORIZATION").await?;
    assert_eq!(
        denied
            .err()
            .ok_or("unenrolled principal accepted")?
            .as_db_error()
            .map(|e| e.message()),
        Some("SIGNAL_FENCED")
    );
    let privileges=db.query_one("SELECT has_table_privilege('signal_runtime','signal_control.object_pins','INSERT'),has_table_privilege('signal_runtime','signal_control.object_backends','INSERT'),has_function_privilege('signal_runtime','signal_control.object_reference(jsonb)','EXECUTE')",&[]).await?;
    for i in 0..3 {
        assert!(!privileges.get::<_, bool>(i));
    }
    // Full exact logical charges include immutable pins, releases and tombstones.
    let counters=db.query_one("SELECT used_rows = ((SELECT count(*) FROM signal_control.commits)+(SELECT count(*) FROM signal_control.receipts)+(SELECT count(*) FROM signal_control.state)+(SELECT count(*) FROM signal_control.findings)+(SELECT count(*) FROM signal_control.outbox)+(SELECT count(*) FROM signal_control.snapshots)+(SELECT count(*) FROM signal_control.object_pins)+(SELECT count(*) FROM signal_control.tombstones)), used_bytes = ((SELECT coalesce(sum(512+octet_length(request)+octet_length(manifest)+octet_length(normalizer_revision)+32*cardinality(object_hashes)),0) FROM signal_control.commits)+(SELECT coalesce(sum(256+octet_length(reference)+octet_length(retained_request)),0) FROM signal_control.receipts)+(SELECT coalesce(sum(192+octet_length(key)+octet_length(value)),0) FROM signal_control.state)+(SELECT coalesce(sum(256+octet_length(content)),0) FROM signal_control.findings)+(SELECT coalesce(sum(256+octet_length(plan)),0) FROM signal_control.outbox)+(SELECT coalesce(sum(320+octet_length(manifest_ids)+32*cardinality(object_hashes)),0) FROM signal_control.snapshots)+(SELECT coalesce(sum(512+octet_length(object_reference)+octet_length(request)+coalesce(octet_length(release_request),0)),0) FROM signal_control.object_pins)+(SELECT coalesce(sum(512+octet_length(object_reference)+octet_length(request)),0) FROM signal_control.tombstones)) FROM signal_control.store",&[]).await?;
    assert!(counters.get::<_, bool>(0));
    assert!(counters.get::<_, bool>(1));
    eprintln!("matrix-case:gc_old_owner_or_reachable_object passed");
    eprintln!("phase: exact-version-retirement-qualification-complete");
    Ok(())
}
fn signal_control_digest(reference: &CanonicalObjectRef) -> Result<String, ControlError> {
    Ok(reference
        .digest()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

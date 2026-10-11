//! Actual native TLS grants and PostgreSQL snapshot reads; explicitly owned reader ACLs.
use super::{DB, Fixture, Result, context, grant};
use signal_control::{
    ConnectionSettings, ControlClient, ControlError, ProducerEnrollment, ScopedFindingsBinding,
};
use signal_findings::{Finding, FindingQuery};
use signal_ingest::identity::IdentityBackend;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use tokio_postgres::Client;

pub(super) async fn qualify(
    f: &Fixture,
    producer: &ProducerEnrollment,
    identity: &IdentityBackend,
    db: &Client,
    legacy: &Finding,
    native: &Finding,
) -> Result {
    let connect = |user: &str| {
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
            f.port,
            DB.into(),
            user.into(),
            f.password.as_bytes().to_vec(),
        )
    };
    let binding = ScopedFindingsBinding {
        store: producer.scope.store_id,
        generation: producer.scope.generation,
        scope_generation: producer.scope_generation,
        schema_owner: "signal_control_owner".into(),
    };
    let restricted = Arc::new(grant(identity, "reader").await?);
    let all = Arc::new(grant(identity, "all-reader").await?);
    let paired = Arc::new(grant(identity, "paired-reader").await?);
    let query = FindingQuery {
        limit: 1,
        ..Default::default()
    };
    let runtime = ControlClient::catalog(connect("signal_runtime")?)?;
    assert!(matches!(
        runtime
            .read_scoped_findings(
                binding.clone(),
                query.clone(),
                restricted.clone(),
                context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    runtime.shutdown(context()?).await?;
    let reader = ControlClient::catalog(connect("signal_denied")?)?;
    assert!(matches!(
        reader
            .read_scoped_findings(
                binding.clone(),
                query.clone(),
                restricted.clone(),
                context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    timeout(Duration::from_secs(2),db.batch_execute("GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_denied; GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings,signal_control.partitions,signal_finding_scope.activation,signal_finding_scope.profile,signal_finding_scope.producers,signal_finding_scope.facts,signal_finding_scope.requests TO signal_denied")).await??;
    let list = reader
        .read_scoped_findings(
            binding.clone(),
            query.clone(),
            restricted.clone(),
            context()?,
        )
        .await?;
    assert_eq!(
        list.findings()?.iter().map(|f| f.id).collect::<Vec<_>>(),
        vec![native.id]
    );
    let list = reader
        .read_scoped_findings(
            binding.clone(),
            FindingQuery {
                limit: 2,
                ..Default::default()
            },
            all.clone(),
            context()?,
        )
        .await?;
    assert_eq!(
        list.findings()?.iter().map(|f| f.id).collect::<Vec<_>>(),
        vec![legacy.id, native.id]
    );
    assert_eq!(legacy.created_at.timestamp_subsec_nanos(), 1_999_999_999);
    assert!(legacy.created_at < legacy.created_at + chrono::Duration::nanoseconds(1));
    for (from, to, want) in [
        (
            Some(legacy.created_at + chrono::Duration::nanoseconds(1)),
            None,
            vec![native.id],
        ),
        (None, None, vec![legacy.id]),
        (
            Some(legacy.created_at),
            Some(legacy.created_at + chrono::Duration::nanoseconds(1)),
            vec![legacy.id],
        ),
        (
            Some(native.created_at),
            Some(native.created_at + chrono::Duration::nanoseconds(1)),
            vec![native.id],
        ),
        (None, Some(native.created_at), vec![legacy.id]),
    ] {
        let list = reader
            .read_scoped_findings(
                binding.clone(),
                FindingQuery {
                    from,
                    to,
                    limit: 1,
                    ..Default::default()
                },
                all.clone(),
                context()?,
            )
            .await?;
        assert_eq!(
            list.findings()?.iter().map(|f| f.id).collect::<Vec<_>>(),
            want
        );
    }
    assert!(
        reader
            .read_scoped_findings(binding.clone(), query.clone(), paired, context()?)
            .await?
            .findings()?
            .is_empty()
    );
    let producer_grant = Arc::new(grant(identity, "producer").await?);
    assert!(matches!(
        reader
            .read_scoped_findings(binding.clone(), query.clone(), producer_grant, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let low = FindingQuery {
        severity: Some(signal_findings::DetectionSeverity::Low),
        limit: 1,
        ..Default::default()
    };
    assert!(
        reader
            .read_scoped_findings(binding.clone(), low, all.clone(), context()?)
            .await?
            .findings()?
            .is_empty()
    );
    let empty = FindingQuery {
        rule_id: Some("absent-rule".into()),
        limit: 1,
        ..Default::default()
    };
    assert!(
        reader
            .read_scoped_findings(binding.clone(), empty.clone(), all.clone(), context()?)
            .await?
            .findings()?
            .is_empty()
    );
    let mut wrong = binding.clone();
    wrong.scope_generation = uuid::Uuid::new_v4();
    assert!(matches!(
        reader
            .read_scoped_findings(wrong, empty.clone(), all.clone(), context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let canceled = context()?;
    canceled.cancel();
    assert!(matches!(
        reader
            .read_scoped_findings(binding.clone(), query.clone(), all.clone(), canceled)
            .await,
        Err(ControlError::Cancelled)
    ));
    let retained_context = context()?;
    let retained = reader
        .read_scoped_findings(
            binding.clone(),
            query.clone(),
            all.clone(),
            retained_context.clone(),
        )
        .await?;
    retained_context.cancel();
    assert!(matches!(retained.findings(), Err(ControlError::Cancelled)));
    timeout(
        Duration::from_secs(2),
        db.batch_execute("REVOKE SELECT ON signal_finding_scope.facts FROM signal_denied"),
    )
    .await??;
    assert!(matches!(
        reader
            .read_scoped_findings(binding.clone(), empty.clone(), all.clone(), context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    timeout(Duration::from_secs(2),db.batch_execute("GRANT SELECT ON signal_finding_scope.facts TO signal_denied; UPDATE signal_finding_scope.facts SET account='b'")).await??;
    assert!(matches!(
        reader
            .read_scoped_findings(binding.clone(), empty.clone(), all.clone(), context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    timeout(Duration::from_secs(2),db.batch_execute("UPDATE signal_finding_scope.facts SET account='a'; UPDATE signal_finding_scope.profile SET used_rows=used_rows+1")).await??;
    assert!(matches!(
        reader
            .read_scoped_findings(binding.clone(), empty.clone(), all.clone(), context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    timeout(
        Duration::from_secs(2),
        db.batch_execute("UPDATE signal_finding_scope.profile SET used_rows=used_rows-1"),
    )
    .await??;
    let retained = reader
        .read_scoped_findings(binding, query, all, context()?)
        .await?;
    reader.shutdown(context()?).await?;
    assert!(matches!(retained.findings(), Err(ControlError::Cancelled)));
    println!(
        "phase: actual-native-TLS-shared-scoped-read-paired-before-limit-history-integrity-qualified"
    );
    Ok(())
}

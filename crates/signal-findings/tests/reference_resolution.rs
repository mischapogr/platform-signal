#![allow(clippy::unwrap_used)]
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_findings::{disposition::FindingReference, *};
use std::{fs, time::Duration};
use uuid::Uuid;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn context() -> FindingContext {
    FindingContext::new(Duration::from_secs(5))
}
fn event(minute: u8) -> Result<signal_event::SignalEvent, Box<dyn std::error::Error>> {
    let at = format!("2026-10-27T00:{minute:02}:00Z");
    let input: signal_event::IngestEvent = serde_json::from_value(
        json!({"timestamp":at,"source":{"type":"application","name":"fixture"},"message":"fixture","resource":{"kind":"service","id":"api","account_id":"acct"}}),
    )?;
    Ok(input.normalize(at.parse()?)?)
}
fn finding(event: &signal_event::SignalEvent) -> Result<Finding, FindingError> {
    Finding::for_event("rule", event, DetectionSeverity::Medium, "finding")
}
fn reference(stream: Uuid, finding: &Finding) -> FindingReference {
    FindingReference {
        stream_id: stream,
        finding_id: finding.id,
    }
}
fn original(path: &std::path::Path, id: Uuid) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path.join("findings.journal"))?;
    let mut cursor = 24;
    while cursor < bytes.len() {
        let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into()?) as usize;
        cursor += FINDING_FRAME_BYTES;
        let data = &bytes[cursor..cursor + len];
        if serde_json::from_slice::<Finding>(data)?.id == id {
            return Ok(data.to_vec());
        }
        cursor += len;
    }
    Err("missing original fixture".into())
}
#[tokio::test]
async fn exact_reference_beyond_query_limit_has_original_digest_and_physical_provenance_after_reopen()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let stream = Uuid::from_u128(100);
    let config = FindingConfig {
        directory: dir.path().join("findings"),
        max_query_rows: 1,
        ..FindingConfig::default()
    };
    let store = FindingStore::open(config.clone(), stream).await?;
    let mut legacy = finding(&event(0)?)?;
    legacy.attributes.insert("signal.scope.v1".into(),json!({"schema_version":1,"generation":Uuid::from_u128(10),"source":"application","account":"acct","resource":"api","binding_digest":"0".repeat(64)}));
    assert!(matches!(
        store.append(vec![legacy.clone()], context()).await,
        Err(FindingError::Invalid(_))
    ));
    legacy.attributes.remove("signal.scope.v1");
    store.append(vec![legacy.clone()], context()).await?;
    store.enable_scopes(context()).await?;
    let first = event(1)?;
    let second = event(2)?;
    let target = finding(&second)?;
    store
        .append_derived(
            vec![
                DerivedFinding::from_event(finding(&first)?, &first, true)?,
                DerivedFinding::from_event(target.clone(), &second, true)?,
            ],
            context(),
        )
        .await?;
    let limited = store
        .query(
            FindingQuery {
                from: None,
                to: None,
                severity: None,
                rule_id: None,
                limit: 1,
            },
            context(),
        )
        .await?;
    assert_eq!(limited.len(), 1);
    assert_ne!(limited[0].id, target.id);
    let resolved = store
        .resolve_reference(reference(stream, &target), context())
        .await?
        .ok_or("exact row missing")?;
    assert_eq!(resolved.reference(), reference(stream, &target));
    assert_eq!(resolved.finding().id, target.id);
    let provenance = resolved.canonical_provenance().ok_or("scope missing")?;
    assert!(!provenance.generation().is_nil());
    assert_eq!(provenance.facts().source, Some("application"));
    assert_eq!(provenance.facts().account, Some("acct"));
    assert_eq!(provenance.facts().resource, Some("api"));
    assert_eq!(provenance.binding_digest().len(), 64);
    let digest: [u8; 32] = Sha256::digest(original(&config.directory, target.id)?).into();
    assert_eq!(resolved.original_sha256(), digest);
    assert!(
        store
            .resolve_reference(reference(stream, &legacy), context())
            .await?
            .ok_or("legacy missing")?
            .canonical_provenance()
            .is_none()
    );
    let mut forged = finding(&event(3)?)?;
    forged.attributes.insert("signal.scope.v1".into(),json!({"schema_version":1,"generation":provenance.generation(),"source":"application","account":"acct","resource":"api","binding_digest":"0".repeat(64)}));
    assert!(matches!(
        store.append(vec![forged], context()).await,
        Err(FindingError::Invalid(_))
    ));
    store.shutdown(context()).await?;
    let store = FindingStore::open(config, stream).await?;
    let reopened = store
        .resolve_reference(reference(stream, &target), context())
        .await?
        .ok_or("reopen missing")?;
    assert_eq!(reopened.original_sha256(), digest);
    assert_eq!(reopened.finding(), resolved.finding());
    assert_eq!(
        reopened
            .canonical_provenance()
            .ok_or("provenance lost")?
            .generation(),
        provenance.generation()
    );
    Ok(())
}
#[tokio::test]
async fn unknown_provenance_absence_stream_mismatch_and_lifetime_are_distinct() -> TestResult {
    let dir = tempfile::tempdir()?;
    let stream = Uuid::from_u128(100);
    let store = FindingStore::open(
        FindingConfig {
            directory: dir.path().join("findings"),
            ..FindingConfig::default()
        },
        stream,
    )
    .await?;
    store.enable_scopes(context()).await?;
    let row = finding(&event(0)?)?;
    store.append(vec![row.clone()], context()).await?;
    assert!(
        store
            .resolve_reference(reference(stream, &row), context())
            .await?
            .ok_or("row missing")?
            .canonical_provenance()
            .is_none()
    );
    assert!(
        store
            .resolve_reference(
                FindingReference {
                    stream_id: stream,
                    finding_id: Uuid::from_u128(999)
                },
                context()
            )
            .await?
            .is_none()
    );
    assert!(matches!(
        store
            .resolve_reference(reference(Uuid::from_u128(101), &row), context())
            .await,
        Err(FindingError::StreamMismatch)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        store
            .resolve_reference(reference(stream, &row), cancelled)
            .await,
        Err(FindingError::Cancelled)
    ));
    let mut expired = context();
    expired.deadline = tokio::time::Instant::now();
    assert!(matches!(
        store
            .resolve_reference(reference(stream, &row), expired)
            .await,
        Err(FindingError::Timeout)
    ));
    assert!(matches!(
        store
            .resolve_reference(
                FindingReference {
                    stream_id: stream,
                    finding_id: Uuid::nil()
                },
                context()
            )
            .await,
        Err(FindingError::Invalid(_))
    ));
    Ok(())
}
#[tokio::test]
async fn damaged_original_is_error_and_closes_store_not_absence_or_unknown_scope() -> TestResult {
    let dir = tempfile::tempdir()?;
    let stream = Uuid::from_u128(100);
    let config = FindingConfig {
        directory: dir.path().join("findings"),
        ..FindingConfig::default()
    };
    let store = FindingStore::open(config.clone(), stream).await?;
    let event = event(0)?;
    let row = finding(&event)?;
    store.enable_scopes(context()).await?;
    store
        .append_derived(
            vec![DerivedFinding::from_event(row.clone(), &event, true)?],
            context(),
        )
        .await?;
    let path = config.directory.join("findings.journal");
    let mut bytes = fs::read(&path)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes)?;
    assert!(matches!(
        store
            .resolve_reference(reference(stream, &row), context())
            .await,
        Err(FindingError::Corrupt(_))
    ));
    assert!(store.metrics().closed);
    Ok(())
}
#[tokio::test]
async fn authenticated_absent_or_omitted_selectors_are_not_unknown_provenance() -> TestResult {
    let dir = tempfile::tempdir()?;
    let stream = Uuid::from_u128(100);
    let cfg = FindingConfig {
        directory: dir.path().join("findings"),
        ..FindingConfig::default()
    };
    let store = FindingStore::open(cfg.clone(), stream).await?;
    store.enable_scopes(context()).await?;
    let mut absent = event(0)?;
    absent.resource = None;
    absent.validate()?;
    let mut long_a = event(1)?;
    long_a
        .resource
        .as_mut()
        .ok_or("resource missing")?
        .account_id = Some("a".repeat(257));
    long_a.validate()?;
    let mut long_b = event(2)?;
    long_b
        .resource
        .as_mut()
        .ok_or("resource missing")?
        .account_id = Some("b".repeat(257));
    long_b.validate()?;
    let unverified = event(3)?;
    let inputs = [absent, long_a, long_b, unverified];
    let mut references = Vec::new();
    for (index, event) in inputs.iter().enumerate() {
        let row = finding(event)?;
        references.push(reference(stream, &row));
        store
            .append_derived(
                vec![DerivedFinding::from_event(row, event, index != 3)?],
                context(),
            )
            .await?;
    }
    let mut digests = Vec::new();
    for (index, reference) in references.iter().enumerate() {
        let resolved = store
            .resolve_reference(*reference, context())
            .await?
            .ok_or("row missing")?;
        if index == 3 {
            assert!(resolved.canonical_provenance().is_none());
            continue;
        }
        let provenance = resolved
            .canonical_provenance()
            .ok_or("authenticated provenance missing")?;
        assert_eq!(provenance.facts().source, Some("application"));
        assert_eq!(provenance.facts().account, None);
        assert_eq!(
            provenance.facts().resource,
            if index == 0 { None } else { Some("api") }
        );
        digests.push(provenance.binding_digest().to_owned());
    }
    assert_ne!(
        digests[1], digests[2],
        "omitted selectors must retain distinct full-identity commitments"
    );
    store.shutdown(context()).await?;
    let store = FindingStore::open(cfg, stream).await?;
    for (index, reference) in references.iter().enumerate() {
        let resolved = store
            .resolve_reference(*reference, context())
            .await?
            .ok_or("reopen missing")?;
        if index == 3 {
            assert!(resolved.canonical_provenance().is_none());
        } else {
            assert_eq!(
                resolved
                    .canonical_provenance()
                    .ok_or("reopen provenance missing")?
                    .binding_digest(),
                digests[index]
            );
        }
    }
    Ok(())
}
#[tokio::test]
async fn exact_resolution_cannot_bypass_read_budget_or_discard_prior_rows() -> TestResult {
    let dir = tempfile::tempdir()?;
    let stream = Uuid::from_u128(100);
    let mut cfg = FindingConfig {
        directory: dir.path().join("findings"),
        max_query_bytes: 1,
        ..FindingConfig::default()
    };
    let store = FindingStore::open(cfg.clone(), stream).await?;
    let first = finding(&event(0)?)?;
    store.append(vec![first.clone()], context()).await?;
    assert!(matches!(
        store
            .resolve_reference(reference(stream, &first), context())
            .await,
        Err(FindingError::Quota)
    ));
    assert!(!store.metrics().closed);
    let second = finding(&event(1)?)?;
    store.append(vec![second.clone()], context()).await?;
    assert_eq!(store.metrics().findings, 2);
    store.shutdown(context()).await?;
    cfg.max_query_bytes = FindingConfig::default().max_query_bytes;
    let store = FindingStore::open(cfg, stream).await?;
    assert_eq!(
        store
            .resolve_reference(reference(stream, &first), context())
            .await?
            .ok_or("first missing")?
            .finding(),
        &first
    );
    assert_eq!(
        store
            .resolve_reference(reference(stream, &second), context())
            .await?
            .ok_or("second missing")?
            .finding(),
        &second
    );
    Ok(())
}

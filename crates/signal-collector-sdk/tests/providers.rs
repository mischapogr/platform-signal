use signal_collector_sdk::{
    Enricher, EnrichmentProvider, EventLimits, ExtensionContext, ExtensionError, OverlayPath,
    RuleDocument, RuleDocumentLimits, RuleProvider, apply_enricher, extension, load_enricher,
    load_rules, validate_event,
};
use signal_event::{IngestEvent, SignalEvent};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

fn context() -> Result<ExtensionContext, ExtensionError> {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(1))
}
fn document(yaml: &str) -> RuleDocument {
    RuleDocument {
        schema_version: 1,
        yaml: yaml.into(),
    }
}
struct Documents(Vec<RuleDocument>);
#[extension]
impl RuleProvider for Documents {
    async fn load(&self, context: ExtensionContext) -> Result<Vec<RuleDocument>, ExtensionError> {
        context.check()?;
        Ok(self.0.clone())
    }
}

#[test]
fn explicit_overlay_selection_has_no_filesystem_or_default_requirement()
-> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from("/a/nonexistent/external-overlay");
    assert_eq!(OverlayPath::resolve(Some(path.clone()))?.as_path(), path);
    assert_eq!(
        OverlayPath::new(""),
        Err(ExtensionError::MissingOverlayPath)
    );
    assert_eq!(
        OverlayPath::resolve(Some(PathBuf::new())),
        Err(ExtensionError::MissingOverlayPath)
    );
    Ok(())
}

#[test]
fn overlay_environment_selection_and_missing_path_are_explicit()
-> Result<(), Box<dyn std::error::Error>> {
    // Child processes isolate environment selection without mutating the
    // concurrent test process environment.
    const MARKER: &str = "SIGNAL_SDK_OVERLAY_TEST_MODE";
    if let Some(mode) = std::env::var_os(MARKER) {
        if mode == "missing" {
            assert_eq!(
                OverlayPath::from_env(),
                Err(ExtensionError::MissingOverlayPath)
            );
        } else {
            assert_eq!(
                OverlayPath::resolve(None)?.as_path(),
                std::path::Path::new("/external/fixture")
            );
        }
        return Ok(());
    }
    for mode in ["missing", "selected"] {
        let mut child = std::process::Command::new(std::env::current_exe()?);
        child
            .arg("--exact")
            .arg("overlay_environment_selection_and_missing_path_are_explicit")
            .env(MARKER, mode)
            .env_remove("SIGNAL_OVERLAY_PATH");
        if mode == "selected" {
            child.env("SIGNAL_OVERLAY_PATH", "/external/fixture");
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "child test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[tokio::test]
async fn document_envelopes_preserve_source_and_apply_count_byte_and_total_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let provider: Box<dyn RuleProvider> = Box::new(Documents(vec![document("rules: []\n")]));
    let documents =
        load_rules(provider.as_ref(), context()?, RuleDocumentLimits::default()).await?;
    assert_eq!(documents, vec![document("rules: []\n")]);
    let limits = RuleDocumentLimits {
        max_documents: 1,
        max_document_bytes: 4,
        max_total_bytes: 6,
    };
    for values in [
        vec![document("a"), document("b")],
        vec![document("12345")],
        vec![document("1234"), document("123")],
    ] {
        let local_limits = RuleDocumentLimits {
            max_documents: if values[0].yaml == "1234" { 2 } else { 1 },
            ..limits
        };
        assert_eq!(
            load_rules(&Documents(values), context()?, local_limits).await,
            Err(ExtensionError::RulesTooLarge)
        );
    }
    for invalid in [
        RuleDocument {
            schema_version: 2,
            yaml: "rules: []".into(),
        },
        document(" \n"),
    ] {
        assert_eq!(
            load_rules(
                &Documents(vec![invalid]),
                context()?,
                RuleDocumentLimits::default()
            )
            .await,
            Err(ExtensionError::InvalidRuleDocument)
        );
    }
    // An empty provider is valid: an overlay need not contribute any detections.
    assert!(
        load_rules(&Documents(vec![]), context()?, limits)
            .await?
            .is_empty()
    );
    // The SDK validates transport; rule semantics are the consumer's responsibility.
    assert!(
        load_rules(
            &Documents(vec![document("not valid rule YAML")]),
            context()?,
            RuleDocumentLimits::default()
        )
        .await
        .is_ok()
    );
    assert!(
        serde_json::from_str::<RuleDocument>(
            r#"{"schema_version":1,"yaml":"rules: []","unexpected":true}"#
        )
        .is_err()
    );
    Ok(())
}

struct Waiting;
#[extension]
impl RuleProvider for Waiting {
    async fn load(&self, _: ExtensionContext) -> Result<Vec<RuleDocument>, ExtensionError> {
        std::future::pending().await
    }
}
#[extension]
impl EnrichmentProvider for Waiting {
    async fn load(&self, _: ExtensionContext) -> Result<Arc<dyn Enricher>, ExtensionError> {
        std::future::pending().await
    }
}
struct Failing;
#[extension]
impl RuleProvider for Failing {
    async fn load(&self, _: ExtensionContext) -> Result<Vec<RuleDocument>, ExtensionError> {
        Err(ExtensionError::Failed)
    }
}
#[extension]
impl EnrichmentProvider for Failing {
    async fn load(&self, _: ExtensionContext) -> Result<Arc<dyn Enricher>, ExtensionError> {
        Err(ExtensionError::Failed)
    }
}
#[tokio::test]
async fn provider_failures_cancellation_timeouts_and_invalid_limits_are_static()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        load_rules(&Failing, context()?, RuleDocumentLimits::default()).await,
        Err(ExtensionError::Failed)
    );
    assert!(matches!(
        load_enricher(&Failing, context()?).await,
        Err(ExtensionError::Failed)
    ));
    let token = CancellationToken::new();
    token.cancel();
    let cancelled = ExtensionContext::new(token, Duration::from_secs(1))?;
    assert_eq!(
        load_rules(&Waiting, cancelled.clone(), RuleDocumentLimits::default()).await,
        Err(ExtensionError::Cancelled)
    );
    assert!(matches!(
        load_enricher(&Waiting, cancelled).await,
        Err(ExtensionError::Cancelled)
    ));
    let invalid = RuleDocumentLimits {
        max_documents: 0,
        ..RuleDocumentLimits::default()
    };
    assert_eq!(
        load_rules(&Waiting, context()?, invalid).await,
        Err(ExtensionError::InvalidConfiguration)
    );
    let deadline = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(10))?;
    assert_eq!(
        load_rules(&Waiting, deadline, RuleDocumentLimits::default()).await,
        Err(ExtensionError::Timeout)
    );
    let deadline = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(10))?;
    assert!(matches!(
        load_enricher(&Waiting, deadline).await,
        Err(ExtensionError::Timeout)
    ));
    Ok(())
}

struct Annotation;
#[extension]
impl EnrichmentProvider for Annotation {
    async fn load(&self, context: ExtensionContext) -> Result<Arc<dyn Enricher>, ExtensionError> {
        context.check()?;
        Ok(Arc::new(Annotation))
    }
}
#[extension]
impl Enricher for Annotation {
    async fn enrich(
        &self,
        event: &mut SignalEvent,
        _: ExtensionContext,
    ) -> Result<(), ExtensionError> {
        event.tags.push("external".into());
        Ok(())
    }
}
#[tokio::test]
async fn loaded_enricher_and_public_fixture_validation_share_canonical_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let input: IngestEvent = serde_json::from_str(
        r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"application"},"attributes":{"arbitrary":{"nested":[9007199254740993]}}}"#,
    )?;
    let mut event = input.normalize(chrono::Utc::now())?;
    let original = event.clone();
    validate_event(&event, EventLimits::default(), &context()?)?;
    let enricher = load_enricher(&Annotation, context()?).await?;
    apply_enricher(
        enricher.as_ref(),
        &mut event,
        context()?,
        EventLimits::default(),
    )
    .await?;
    assert_eq!(event.id, original.id);
    assert_eq!(event.timestamp, original.timestamp);
    assert_eq!(event.observed_at, original.observed_at);
    assert_eq!(event.attributes, original.attributes);
    assert_eq!(event.tags, vec!["external"]);
    event.schema_version = 99;
    assert_eq!(
        validate_event(&event, EventLimits::default(), &context()?),
        Err(ExtensionError::InvalidEvent)
    );
    event.schema_version = original.schema_version;
    event.message = Some("x".repeat(70_000));
    assert_eq!(
        validate_event(&event, EventLimits::default(), &context()?),
        Err(ExtensionError::EventTooLarge)
    );
    Ok(())
}

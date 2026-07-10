use signal_collector_sdk::{
    Collector, Enricher, EventLimits, ExtensionContext, ExtensionError, apply_enricher, extension,
    run_collector,
};
use signal_event::{IngestEvent, SignalEvent};
use signal_protocol::{AdmissionError, AdmissionFuture, EventSink, SinkMetrics};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

fn event() -> Result<SignalEvent, Box<dyn std::error::Error>> {
    let input: IngestEvent = serde_json::from_str(
        r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"application"},"message":"original","attributes":{"tenant.metadata":{"nested":[9007199254740993,1.234567890123456789,true]}}}"#,
    )?;
    Ok(input.normalize(chrono::Utc::now())?)
}
fn context() -> Result<ExtensionContext, ExtensionError> {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(1))
}

struct Annotate;
#[extension]
impl Enricher for Annotate {
    async fn enrich(
        &self,
        event: &mut SignalEvent,
        _: ExtensionContext,
    ) -> Result<(), ExtensionError> {
        event
            .attributes
            .insert("tenant.owner".into(), serde_json::json!("ops"));
        Ok(())
    }
}

#[tokio::test]
async fn public_enricher_preserves_version_identity_and_arbitrary_numbers()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = event()?;
    let original = value.clone();
    let enricher: Box<dyn Enricher> = Box::new(Annotate);
    apply_enricher(
        enricher.as_ref(),
        &mut value,
        context()?,
        EventLimits::default(),
    )
    .await?;
    assert_eq!(
        value.attributes["tenant.metadata"],
        original.attributes["tenant.metadata"]
    );
    assert_eq!(value.id, original.id);
    assert_eq!(value.schema_version, original.schema_version);
    assert_eq!(value.timestamp, original.timestamp);
    assert_eq!(value.observed_at, original.observed_at);
    assert_eq!(value.attributes["tenant.owner"], "ops");
    Ok(())
}

struct Broken(u8);
#[extension]
impl Enricher for Broken {
    async fn enrich(
        &self,
        event: &mut SignalEvent,
        context: ExtensionContext,
    ) -> Result<(), ExtensionError> {
        event.message = Some("changed".into());
        match self.0 {
            0 => return Err(ExtensionError::Failed),
            1 => event.schema_version = 99,
            2 => {
                event.id = serde_json::from_str("\"00000000-0000-0000-0000-000000000000\"")
                    .map_err(|_| ExtensionError::Failed)?
            }
            3 => event.timestamp += chrono::Duration::seconds(1),
            4 => event.message = Some("x".repeat(70_000)),
            5 => {
                context.cancellation().cancel();
            }
            6 => {
                std::future::pending::<()>().await;
            }
            7 => event.observed_at += chrono::Duration::seconds(1),
            _ => {
                event.id = serde_json::from_str("\"11111111-1111-4111-8111-111111111111\"")
                    .map_err(|_| ExtensionError::Failed)?
            }
        }
        Ok(())
    }
}
#[tokio::test]
async fn all_extension_failures_leave_caller_event_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..=8 {
        let mut value = event()?;
        let original = value.clone();
        let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(10))?;
        let result = apply_enricher(&Broken(mode), &mut value, ctx, EventLimits::default()).await;
        let expected = match mode {
            0 => ExtensionError::Failed,
            1 | 2 => ExtensionError::InvalidEvent,
            3 | 7 | 8 => ExtensionError::IdentityChanged,
            4 => ExtensionError::EventTooLarge,
            5 => ExtensionError::Cancelled,
            _ => ExtensionError::Timeout,
        };
        assert_eq!(result, Err(expected));
        assert_eq!(value, original);
    }
    Ok(())
}
struct MustNotRun;
#[extension]
impl Enricher for MustNotRun {
    async fn enrich(&self, _: &mut SignalEvent, _: ExtensionContext) -> Result<(), ExtensionError> {
        panic!("invalid input must be rejected before invocation")
    }
}
#[tokio::test]
async fn bounded_input_and_context_fail_before_invocation() -> Result<(), Box<dyn std::error::Error>>
{
    let mut deep = serde_json::json!(0);
    for _ in 0..34 {
        deep = serde_json::json!([deep]);
    }
    let mut value = event()?;
    value.attributes.insert("nested".into(), deep);
    let original = value.clone();
    assert_eq!(
        apply_enricher(&MustNotRun, &mut value, context()?, EventLimits::default()).await,
        Err(ExtensionError::EventTooLarge)
    );
    assert_eq!(value, original);
    let token = CancellationToken::new();
    token.cancel();
    let mut value = event()?;
    assert_eq!(
        apply_enricher(
            &MustNotRun,
            &mut value,
            ExtensionContext::new(token, Duration::from_secs(1))?,
            EventLimits::default()
        )
        .await,
        Err(ExtensionError::Cancelled)
    );
    let invalid = EventLimits {
        max_attribute_nodes: 65_537,
        ..EventLimits::default()
    };
    assert_eq!(
        apply_enricher(&MustNotRun, &mut value, context()?, invalid).await,
        Err(ExtensionError::InvalidConfiguration)
    );
    value.timestamp = value.timestamp.with_year(-1).ok_or("timestamp")?;
    assert_eq!(
        apply_enricher(&MustNotRun, &mut value, context()?, EventLimits::default()).await,
        Err(ExtensionError::InvalidEvent)
    );
    Ok(())
}
use chrono::Datelike;

#[derive(Default)]
struct Sink(Mutex<Vec<SignalEvent>>);
impl EventSink for Sink {
    fn admit(&self, event: SignalEvent) -> AdmissionFuture<'_> {
        Box::pin(async move {
            let mut events = self.0.lock().map_err(|_| AdmissionError::Unavailable)?;
            if events.len() == 1 {
                return Err(AdmissionError::Full);
            }
            events.push(event);
            Ok(())
        })
    }
    fn metrics(&self) -> SinkMetrics {
        SinkMetrics {
            capacity: 1,
            ..SinkMetrics::default()
        }
    }
    fn close(&self) {}
}
struct OneEvent(SignalEvent);
#[extension]
impl Collector for OneEvent {
    async fn run(
        &self,
        sink: Arc<dyn EventSink>,
        context: ExtensionContext,
    ) -> Result<(), ExtensionError> {
        context.check()?;
        sink.admit(self.0.clone()).await?;
        Ok(())
    }
}
#[tokio::test]
async fn public_collector_uses_existing_bounded_admission_seam()
-> Result<(), Box<dyn std::error::Error>> {
    let sink = Arc::new(Sink::default());
    let value = event()?;
    let collector: Box<dyn Collector> = Box::new(OneEvent(value.clone()));
    run_collector(collector.as_ref(), sink.clone(), context()?).await?;
    assert_eq!(sink.0.lock().map_err(|_| "poison")?.as_slice(), &[value]);
    assert_eq!(
        run_collector(collector.as_ref(), sink, context()?).await,
        Err(ExtensionError::Admission(AdmissionError::Full))
    );
    Ok(())
}

#[tokio::test]
async fn oversized_programmatic_scalars_keys_and_numbers_reject_before_invocation()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..5 {
        let mut value = event()?;
        let huge = "7".repeat(100_000);
        match mode {
            0 => value.message = Some(huge),
            1 => {
                value.attributes.insert(huge, serde_json::json!(true));
            }
            2 => {
                value
                    .attributes
                    .insert("number".into(), serde_json::Value::Number(huge.parse()?));
            }
            3 => value.tags = vec![huge],
            _ => value.source.source_type = huge,
        }
        let original = value.clone();
        assert_eq!(
            apply_enricher(&MustNotRun, &mut value, context()?, EventLimits::default()).await,
            Err(ExtensionError::EventTooLarge)
        );
        assert_eq!(value, original);
    }
    let expired = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(1))?;
    tokio::time::sleep(Duration::from_millis(3)).await;
    let mut value = event()?;
    assert_eq!(
        apply_enricher(&MustNotRun, &mut value, expired, EventLimits::default()).await,
        Err(ExtensionError::Timeout)
    );
    Ok(())
}

#[tokio::test]
async fn wide_array_within_default_node_and_byte_caps_is_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = event()?;
    value.attributes.clear();
    value
        .attributes
        .insert("values".into(), serde_json::json!(vec![0; 16_383]));
    let original = value.clone();
    apply_enricher(&Noop, &mut value, context()?, EventLimits::default()).await?;
    assert_eq!(value, original);
    Ok(())
}

struct Noop;
#[extension]
impl Enricher for Noop {
    async fn enrich(&self, _: &mut SignalEvent, _: ExtensionContext) -> Result<(), ExtensionError> {
        Ok(())
    }
}

#[tokio::test]
async fn absolute_worker_context_preserves_deadline_and_parent_cancellation_without_renewal()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = CancellationToken::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let context = ExtensionContext::from_deadline(parent.child_token(), deadline)?;
    assert_eq!(context.deadline(), deadline);
    parent.cancel();
    assert!(matches!(context.check(), Err(ExtensionError::Cancelled)));
    assert!(matches!(
        ExtensionContext::from_deadline(CancellationToken::new(), tokio::time::Instant::now()),
        Err(ExtensionError::Timeout)
    ));
    assert!(matches!(
        ExtensionContext::from_deadline(
            CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_secs(86_401)
        ),
        Err(ExtensionError::InvalidConfiguration)
    ));
    Ok(())
}

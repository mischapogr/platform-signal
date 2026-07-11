//! Generic, bounded collector and enrichment extension hooks.
//!
//! Use [`run_collector`] and [`apply_enricher`] to enforce cancellation and
//! deadlines. Extensions must yield during work and cancel their own I/O when
//! dropped; helpers create no workers. External side effects cannot be rolled back.

use async_trait::async_trait;
use chrono::Datelike;
use serde_json::Value;
use signal_event::SignalEvent;
use signal_protocol::{AdmissionError, EventSink};
use std::{future::Future, io, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub mod cloudtrail;
pub mod coverage;
mod providers;
pub mod receipt;
pub mod transport;
pub use providers::{
    EnrichmentProvider, OverlayPath, RuleDocument, RuleDocumentLimits, RuleProvider, load_enricher,
    load_rules,
};

pub use async_trait::async_trait as extension;

/// Static error classes deliberately exclude plugin data and credentials.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ExtensionError {
    #[error("invalid extension limits or timeout")]
    InvalidConfiguration,
    #[error("extension cancelled")]
    Cancelled,
    #[error("extension deadline expired")]
    Timeout,
    #[error("invalid canonical event")]
    InvalidEvent,
    #[error("event exceeds extension limits")]
    EventTooLarge,
    #[error("enrichment changed immutable event identity")]
    IdentityChanged,
    #[error("overlay path is missing")]
    MissingOverlayPath,
    #[error("invalid rule document contract")]
    InvalidRuleDocument,
    #[error("rule documents exceed extension limits")]
    RulesTooLarge,
    #[error("extension failed")]
    Failed,
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

/// Per-invocation budget shared with the extension. Not a serialized contract.
#[derive(Clone, Debug)]
pub struct ExtensionContext {
    cancellation: CancellationToken,
    deadline: Instant,
}

impl ExtensionContext {
    /// Timeouts must be positive and at most one day.
    pub fn new(cancellation: CancellationToken, timeout: Duration) -> Result<Self, ExtensionError> {
        if timeout.is_zero() || timeout > Duration::from_secs(86_400) {
            return Err(ExtensionError::InvalidConfiguration);
        }
        Ok(Self {
            cancellation,
            deadline: Instant::now() + timeout,
        })
    }

    /// Preserve an existing host-selected monotonic deadline exactly when
    /// bridging a worker/transport context. No elapsed budget is renewed.
    /// Like relative construction, this checks bounds and grants no authority.
    pub fn from_deadline(
        cancellation: CancellationToken,
        deadline: Instant,
    ) -> Result<Self, ExtensionError> {
        let now = Instant::now();
        if deadline <= now {
            return Err(ExtensionError::Timeout);
        }
        if deadline - now > Duration::from_secs(86_400) {
            return Err(ExtensionError::InvalidConfiguration);
        }
        Ok(Self {
            cancellation,
            deadline,
        })
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Check before synchronous work and pass the remaining budget to I/O.
    pub fn check(&self) -> Result<(), ExtensionError> {
        if self.cancellation.is_cancelled() {
            return Err(ExtensionError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ExtensionError::Timeout);
        }
        Ok(())
    }
}

/// Bounded canonical-event validation, checked before any staging clone.
#[derive(Clone, Copy, Debug)]
pub struct EventLimits {
    pub max_event_bytes: usize,
    pub max_attribute_depth: usize,
    pub max_attribute_nodes: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_event_bytes: 64 * 1024,
            max_attribute_depth: 32,
            max_attribute_nodes: 16_384,
        }
    }
}

impl EventLimits {
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.max_event_bytes == 0
            || self.max_event_bytes > 2 * 1024 * 1024
            || self.max_attribute_depth == 0
            || self.max_attribute_depth > 64
            || self.max_attribute_nodes == 0
            || self.max_attribute_nodes > 65_536
        {
            return Err(ExtensionError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Collectors emit canonical events through the existing bounded admission seam.
/// Implementations must bound input buffers and use context for all I/O.
#[async_trait]
pub trait Collector: Send + Sync {
    async fn run(
        &self,
        sink: Arc<dyn EventSink>,
        context: ExtensionContext,
    ) -> Result<(), ExtensionError>;
}

/// Enrichers may annotate fields but must preserve schema, ID and both timestamps.
/// Use `apply_enricher` for validation and transactional event mutation.
#[async_trait]
pub trait Enricher: Send + Sync {
    async fn enrich(
        &self,
        event: &mut SignalEvent,
        context: ExtensionContext,
    ) -> Result<(), ExtensionError>;
}

/// Run without spawning tasks; completion, cancellation and timeout drop the future.
pub async fn run_collector(
    collector: &dyn Collector,
    sink: Arc<dyn EventSink>,
    context: ExtensionContext,
) -> Result<(), ExtensionError> {
    bounded(&context, collector.run(sink, context.clone())).await
}

/// Stage bounded input, enforce the deadline, validate output, then atomically
/// replace the caller event. Every failure leaves the caller event unchanged.
pub async fn apply_enricher(
    enricher: &dyn Enricher,
    event: &mut SignalEvent,
    context: ExtensionContext,
    limits: EventLimits,
) -> Result<(), ExtensionError> {
    context.check()?;
    validate_event(event, limits, &context)?;
    context.check()?;
    let mut staged = event.clone();
    bounded(&context, enricher.enrich(&mut staged, context.clone())).await?;
    context.check()?;
    validate_event(&staged, limits, &context)?;
    if staged.schema_version != event.schema_version
        || staged.id != event.id
        || staged.timestamp != event.timestamp
        || staged.observed_at != event.observed_at
    {
        return Err(ExtensionError::IdentityChanged);
    }
    context.check()?;
    *event = staged;
    Ok(())
}

async fn bounded<T>(
    context: &ExtensionContext,
    work: impl Future<Output = Result<T, ExtensionError>>,
) -> Result<T, ExtensionError> {
    context.check()?;
    tokio::select! {
        biased;
        _ = context.cancellation.cancelled() => Err(ExtensionError::Cancelled),
        _ = tokio::time::sleep_until(context.deadline) => Err(ExtensionError::Timeout),
        result = work => { context.check()?; result }
    }
}

/// Validate a canonical fixture or collected event with the same bounded
/// contract used before and after enrichment. No mutation or cloning occurs.
pub fn validate_event(
    event: &SignalEvent,
    limits: EventLimits,
    context: &ExtensionContext,
) -> Result<(), ExtensionError> {
    context.check()?;
    limits.validate()?;
    let mut remaining = limits.max_event_bytes;
    let mut charge = |length: usize| -> Result<(), ExtensionError> {
        context.check()?;
        remaining = remaining
            .checked_sub(length)
            .ok_or(ExtensionError::EventTooLarge)?;
        Ok(())
    };
    // Cheap byte preflight bounds even programmatic giant scalars before any
    // escaping, semantic string scan, recursive serialization, or cloning.
    charge(event.source.source_type.len())?;
    for text in [
        &event.source.name,
        &event.message,
        &event.trace_id,
        &event.span_id,
    ]
    .into_iter()
    .flatten()
    {
        charge(text.len())?;
    }
    if let Some(resource) = &event.resource {
        charge(resource.kind.len())?;
        charge(resource.id.len())?;
        for text in [&resource.account_id, &resource.region]
            .into_iter()
            .flatten()
        {
            charge(text.len())?;
        }
    }
    for tag in &event.tags {
        charge(tag.len().saturating_add(3))?;
    }
    // At most depth-sized iterator state; keys and scalar data are borrowed.
    type Values<'a> = Box<dyn Iterator<Item = (&'a str, &'a Value)> + 'a>;
    let mut stack: Vec<Values<'_>> = vec![Box::new(
        event
            .attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value)),
    )];
    let mut nodes = 0usize;
    while let Some(iter) = stack.last_mut() {
        context.check()?;
        let Some((key, value)) = iter.next() else {
            stack.pop();
            continue;
        };
        nodes += 1;
        if nodes > limits.max_attribute_nodes || stack.len() > limits.max_attribute_depth {
            return Err(ExtensionError::EventTooLarge);
        }
        charge(key.len().saturating_add(1))?;
        match value {
            Value::Object(map) => stack.push(Box::new(
                map.iter().map(|(key, value)| (key.as_str(), value)),
            )),
            Value::Array(values) => stack.push(Box::new(values.iter().map(|value| ("", value)))),
            Value::String(text) => charge(text.len())?,
            // Workspace serde_json uses arbitrary_precision, exposing borrowed
            // digits so preflight never allocates a giant number representation.
            Value::Number(number) => charge(number.as_str().len())?,
            _ => {}
        }
    }
    context.check()?;
    let mut writer = CountingWriter {
        remaining: limits.max_event_bytes,
        context,
    };
    if serde_json::to_writer(&mut writer, event).is_err() {
        context.check()?;
        return Err(ExtensionError::EventTooLarge);
    }
    context.check()?;
    event.validate().map_err(|_| ExtensionError::InvalidEvent)?;
    if !(0..=9999).contains(&event.timestamp.year())
        || !(0..=9999).contains(&event.observed_at.year())
    {
        return Err(ExtensionError::InvalidEvent);
    }
    context.check()?;
    Ok(())
}

struct CountingWriter<'a> {
    remaining: usize,
    context: &'a ExtensionContext,
}
impl io::Write for CountingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.context
            .check()
            .map_err(|_| io::Error::other("extension stopped"))?;
        if bytes.len() > self.remaining {
            return Err(io::Error::other("event size limit"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

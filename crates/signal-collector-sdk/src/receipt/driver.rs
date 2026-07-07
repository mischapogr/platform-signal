//! One bounded source delivery; adapters and trusted policy remain application-owned.
use super::*;
use async_trait::async_trait;
use signal_protocol::AdmissionDisposition;
use std::future::Future;

/// Ephemeral receive result. Body/IDs are bounded before discovery. Handles are
/// never persisted or logged; adapters must bound actual HTTP bytes before this
/// constructor, authenticate their queue and use its current receipt handle.
pub struct QueueDelivery {
    body: Vec<u8>,
    id: String,
    handle: String,
}
impl QueueDelivery {
    pub fn new(body: Vec<u8>, id: String, handle: String) -> Result<Self, DeliveryError> {
        if body.is_empty()
            || body.len() > MAX_DISCOVERY_BYTES
            || id.len() > 128
            || handle.len() > 16 * 1024
        {
            return Err(SourceFailure::Malformed.into());
        }
        // Reuse the exact ACK delivery bounds without persisting the probe.
        SourceDelivery::new(Uuid::new_v4(), id.clone(), handle.clone())?;
        Ok(Self { body, id, handle })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn message_id(&self) -> &str {
        &self.id
    }
}
#[derive(Debug, Error)]
pub enum SourceFailure {
    #[error("source operation denied")]
    Denied,
    #[error("source operation throttled")]
    Throttled,
    #[error("source operation unavailable or uncertain")]
    Unavailable,
    #[error("source adapter returned malformed input")]
    Malformed,
}
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error(transparent)]
    Source(#[from] SourceFailure),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Capture(#[from] CaptureError),
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
}
/// One receive, at most one message/reference. Adapter owns credential refresh,
/// queue owner validation, actual response bounds and cancellation of owned I/O.
/// It must not receive a batch then silently discard unprocessed deliveries.
#[async_trait]
pub trait SourceQueue: Send + Sync {
    async fn receive(
        &self,
        binding: &ReceiptBinding,
        context: &ExtensionContext,
    ) -> Result<Option<QueueDelivery>, SourceFailure>;
    /// Called only with a store-issued durable-intent ticket and fresh binding.
    /// Return uncertain after an ambiguous response. Even a verified 200 does not
    /// exclude stale-handle success or standard-queue redelivery.
    async fn delete(
        &self,
        binding: &ReceiptBinding,
        ticket: &SourceAckTicket,
        context: &ExtensionContext,
    ) -> Result<SourceAckOutcome, SourceFailure>;
}
/// Trusted application result, not inferred from producer fields or copied files.
/// The application authenticates and reconciles the current control witness and
/// supplies bounded canonical time. A grant constructor alone proves neither.
pub struct AckAuthorization {
    pub grant: ReceiptRecoveryGrant,
    pub observed_at: String,
}
#[async_trait]
pub trait DeliveryPolicy: Send + Sync {
    /// Re-read authenticated configuration/authority; do not cache a permanent
    /// permission bit. The driver compares the complete binding at every seam.
    async fn binding(&self, context: &ExtensionContext) -> Result<ReceiptBinding, SourceFailure>;
    async fn preparation(
        &self,
        discovery: &ObjectDiscovery,
        delivery: &QueueDelivery,
        context: &ExtensionContext,
    ) -> Result<CapturePreparation, SourceFailure>;
    /// Independently verify live ownership/history continuity before each ACK
    /// transition. If prior progress raced cancellation, reconcile it first.
    async fn acknowledge(
        &self,
        binding: &ReceiptBinding,
        progress: &ReceiptProgress,
        context: &ExtensionContext,
    ) -> Result<AckAuthorization, SourceFailure>;
}
pub enum DeliveryStep {
    Idle,
    /// M1 retained; one batch was tried. Caller schedules bounded retry/backoff
    /// and receives a fresh delivery after visibility expiry when necessary.
    Pending {
        receipt: ReceiptInfo,
        progress: ReceiptProgress,
        sent: usize,
        accepted: usize,
        remaining: usize,
        disposition: AdmissionDisposition,
    },
    /// A source result was durably settled. Inspect the progress for confirmed
    /// versus uncertain; this result never attests actual message deletion.
    Settled {
        receipt: ReceiptInfo,
        progress: ReceiptProgress,
    },
}
async fn bounded<T>(
    ctx: &ExtensionContext,
    work: impl Future<Output = Result<T, SourceFailure>>,
) -> Result<T, DeliveryError> {
    check(ctx)?;
    tokio::select! {
        biased;
        _=ctx.cancellation().cancelled()=>Err(ReceiptError::Cancelled.into()),
        _=tokio::time::sleep_until(ctx.deadline())=>Err(ReceiptError::Timeout.into()),
        result=work=>{check(ctx)?;result.map_err(Into::into)}
    }
}
async fn fresh(
    policy: &dyn DeliveryPolicy,
    expected: &ReceiptBinding,
    ctx: &ExtensionContext,
) -> Result<ReceiptBinding, DeliveryError> {
    let binding = bounded(ctx, policy.binding(ctx)).await?;
    if binding != *expected {
        return Err(ReceiptError::Scope.into());
    }
    Ok(binding)
}
async fn authorize(
    policy: &dyn DeliveryPolicy,
    binding: &ReceiptBinding,
    progress: &ReceiptProgress,
    ctx: &ExtensionContext,
) -> Result<AckAuthorization, DeliveryError> {
    fresh(policy, binding, ctx).await?;
    let authorization = bounded(ctx, policy.acknowledge(binding, progress, ctx)).await?;
    fresh(policy, binding, ctx).await?;
    Ok(authorization)
}
fn settled(result: ReceiptAckCommit) -> Result<ReceiptProgress, DeliveryError> {
    match result {
        ReceiptAckCommit::Settled(progress) => Ok(progress),
        _ => Err(ReceiptError::Ack.into()),
    }
}
/// Exactly one receive/capture/physical preparation/batch per call; no spawned
/// worker, retry loop or new queue. Errors retain source responsibility. The
/// application owns aggregate concurrency, spool reserve, source retention and
/// retry cadence. Do not run two drivers against the same receipt owner.
///
/// This conservative driver always waits for full verified M2 before attempting
/// process-local source ACK. Stronger custody and poison/multi-reference input
/// remain blocked by the existing receipt checks. It never deletes source objects.
/// A timeout/revocation may race remote effect or atomic progress: reconcile the
/// current receipt/history and receive a fresh handle rather than invent a ticket.
pub async fn collect_delivery(
    store: &ReceiptStore,
    queue: &dyn SourceQueue,
    capture: &dyn CaptureTransport,
    publisher: &dyn ReceiptPublisher,
    policy: &dyn DeliveryPolicy,
    limits: ReceiptBatchLimits,
    ctx: ExtensionContext,
) -> Result<DeliveryStep, DeliveryError> {
    let binding = bounded(&ctx, policy.binding(&ctx)).await?;
    let Some(delivery) = bounded(&ctx, queue.receive(&binding, &ctx)).await? else {
        return Ok(DeliveryStep::Idle);
    };
    let discovery = discover_object(&delivery.body, &binding, &ctx)?;
    let current = fresh(policy, &binding, &ctx).await?;
    let original = capture_object(capture, discovery, &current, ctx.clone()).await?;
    let pins = bounded(
        &ctx,
        policy.preparation(original.discovery(), &delivery, &ctx),
    )
    .await?;
    if pins.delivery_id != delivery.id {
        return Err(SourceFailure::Malformed.into());
    }
    let current = fresh(policy, &binding, &ctx).await?;
    let receipt = store
        .publish_capture(original, pins, current, ctx.clone())
        .await?;
    let current = fresh(policy, &binding, &ctx).await?;
    match publish_pinned_receipt_batch(store, current, receipt, publisher, limits, ctx.clone())
        .await?
    {
        PublishStep::Attempt {
            sent,
            accepted,
            remaining,
            disposition,
            progress,
        } if remaining > 0 => {
            return Ok(DeliveryStep::Pending {
                receipt,
                progress,
                sent,
                accepted,
                remaining,
                disposition,
            });
        }
        PublishStep::Complete { .. } | PublishStep::Attempt { remaining: 0, .. } => (),
        _ => return Err(ReceiptError::Uncertain.into()),
    }
    let current = fresh(policy, &binding, &ctx).await?;
    let replay = store
        .replay(current, ctx.clone())
        .await?
        .ok_or(ReceiptError::Uncertain)?;
    if replay.receipt.info() != receipt {
        return Err(ReceiptError::StaleProgress.into());
    }
    let mut progress = replay.progress;
    drop(replay.receipt);
    // A lost process-local ticket cannot be reconstructed from persisted IDs.
    // Reconcile intent as uncertain before creating a fresh-delivery intent.
    if progress.value["ack"]["state"] == "intent" {
        let auth = authorize(policy, &binding, &progress, &ctx).await?;
        progress = settled(
            store
                .acknowledge(
                    binding.clone(),
                    progress,
                    auth.grant,
                    ReceiptAckUpdate::RecoverUncertain {
                        observed_at: auth.observed_at,
                    },
                    ctx.clone(),
                )
                .await?,
        )?;
    }
    let auth = authorize(policy, &binding, &progress, &ctx).await?;
    let commit = store
        .acknowledge(
            binding.clone(),
            progress,
            auth.grant,
            ReceiptAckUpdate::BeginProcessLocal {
                delivery: SourceDelivery::new(Uuid::new_v4(), delivery.id, delivery.handle)?,
                observed_at: auth.observed_at,
            },
            ctx.clone(),
        )
        .await?;
    let (ticket, progress) = match commit {
        ReceiptAckCommit::Intent { ticket, progress } => (ticket, progress),
        _ => return Err(ReceiptError::Ack.into()),
    };
    let current = fresh(policy, &binding, &ctx).await?;
    let outcome = bounded(&ctx, queue.delete(&current, &ticket, &ctx)).await?;
    let auth = authorize(policy, &binding, &progress, &ctx).await?;
    let progress = settled(
        store
            .acknowledge(
                binding,
                progress,
                auth.grant,
                ReceiptAckUpdate::Finish {
                    ticket,
                    outcome,
                    observed_at: auth.observed_at,
                },
                ctx,
            )
            .await?,
    )?;
    Ok(DeliveryStep::Settled { receipt, progress })
}

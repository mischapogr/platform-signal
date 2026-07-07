use super::*;
use async_trait::async_trait;
use signal_protocol::{AdmissionDisposition, IngestResponse, verify_admission_response};

/// Match the configured ingest limits; defaults match the server's current
/// 1 MiB/1,000-event contract. This does not negotiate remote configuration.
#[derive(Clone, Copy)]
pub struct ReceiptBatchLimits {
    max_events: usize,
    max_bytes: usize,
}
impl Default for ReceiptBatchLimits {
    fn default() -> Self {
        Self {
            max_events: 1000,
            max_bytes: 1024 * 1024,
        }
    }
}
impl ReceiptBatchLimits {
    pub fn new(max_events: usize, max_bytes: usize) -> Result<Self, ReceiptError> {
        if max_events == 0 || max_events > 1024 || !(32..=16 * 1024 * 1024).contains(&max_bytes) {
            return Err(ReceiptError::Configuration);
        }
        Ok(Self {
            max_events,
            max_bytes,
        })
    }
}
/// Retained event bytes are copied into one bounded batch envelope, never parsed
/// and reserialized. Content can be private; no Debug or wire deserialization.
pub struct PreparedBatch {
    body: Vec<u8>,
    ids: Vec<Uuid>,
}
impl PreparedBatch {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn event_ids(&self) -> &[Uuid] {
        &self.ids
    }
}
impl ReceiptReplay {
    pub fn batch(&self, limits: ReceiptBatchLimits) -> Result<Option<PreparedBatch>, ReceiptError> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        let prefix = b"{\"schema_version\":1,\"events\":[";
        let mut size = prefix.len() + 2;
        let mut count = 0usize;
        for i in 0..self.remaining().min(limits.max_events) {
            let event = self
                .suffix_bytes(i)
                .ok_or(ReceiptError::Invalid("batch suffix"))?;
            let next = size
                .checked_add(event.len())
                .and_then(|n| n.checked_add(usize::from(i > 0)))
                .ok_or(ReceiptError::Quota)?;
            if next > limits.max_bytes {
                break;
            }
            size = next;
            count += 1;
        }
        if count == 0 {
            return Err(ReceiptError::Invalid("event does not fit batch"));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(size)
            .map_err(|_| ReceiptError::Quota)?;
        let mut ids = Vec::new();
        ids.try_reserve_exact(count)
            .map_err(|_| ReceiptError::Quota)?;
        body.extend_from_slice(prefix);
        for i in 0..count {
            if i > 0 {
                body.push(b',');
            }
            let range = &self.receipt.events[self.progress.verified_prefix() + i];
            ids.push(
                Uuid::from_slice(&self.receipt.bytes[range.start - 48..range.start - 32])
                    .map_err(|_| ReceiptError::Invalid("frame id"))?,
            );
            body.extend_from_slice(
                self.suffix_bytes(i)
                    .ok_or(ReceiptError::Invalid("batch suffix"))?,
            );
        }
        body.extend_from_slice(b"]}");
        Ok(Some(PreparedBatch { body, ids }))
    }
}
#[derive(Debug, Error)]
pub enum PublishFailure {
    #[error("publisher transport unavailable or response uncertain")]
    Uncertain,
    #[error("publisher transport denied the request without admission")]
    Denied,
}
/// Transport bounds the actual streamed response to 64 KiB and authenticates the
/// configured endpoint, with no untrusted redirects. A returned status is not
/// admission proof; verification is shared with the agent and receipt store.
pub struct AdmissionReply {
    pub status: u16,
    pub body: Vec<u8>,
}
#[async_trait]
pub trait ReceiptPublisher: Send + Sync {
    async fn publish(
        &self,
        batch: &PreparedBatch,
        context: &ExtensionContext,
    ) -> Result<AdmissionReply, PublishFailure>;
}
pub enum PublishStep {
    Empty,
    Complete {
        progress: ReceiptProgress,
    },
    Attempt {
        sent: usize,
        accepted: usize,
        remaining: usize,
        disposition: AdmissionDisposition,
        progress: ReceiptProgress,
    },
}
/// One batch per invocation; no retry loop or unbounded task creation. Caller
/// refreshes authenticated scope before invocation and owns aggregate budgets.
/// A timeout/lost caller can race remote admission or local progress; replay
/// retained suffix under current authority. No result authorizes source ACK.
pub async fn publish_receipt_batch(
    store: &ReceiptStore,
    binding: ReceiptBinding,
    publisher: &dyn ReceiptPublisher,
    limits: ReceiptBatchLimits,
    ctx: ExtensionContext,
) -> Result<PublishStep, ReceiptError> {
    publish_batch(store, binding, None, publisher, limits, ctx).await
}
/// Publish only the exact receipt selected for a source delivery. Compare the
/// store-issued identity inside the replay used to build the request, never in
/// a separate preflight that can race slot replacement. Physical progress CAS
/// fences a replacement after request dispatch; remote effects may be uncertain.
pub async fn publish_pinned_receipt_batch(
    store: &ReceiptStore,
    binding: ReceiptBinding,
    receipt: ReceiptInfo,
    publisher: &dyn ReceiptPublisher,
    limits: ReceiptBatchLimits,
    ctx: ExtensionContext,
) -> Result<PublishStep, ReceiptError> {
    publish_batch(store, binding, Some(receipt), publisher, limits, ctx).await
}
async fn publish_batch(
    store: &ReceiptStore,
    binding: ReceiptBinding,
    expected: Option<ReceiptInfo>,
    publisher: &dyn ReceiptPublisher,
    limits: ReceiptBatchLimits,
    ctx: ExtensionContext,
) -> Result<PublishStep, ReceiptError> {
    check(&ctx)?;
    let Some(replay) = store.replay(binding.clone(), ctx.clone()).await? else {
        if expected.is_some() {
            return Err(ReceiptError::StaleProgress);
        }
        return Ok(PublishStep::Empty);
    };
    if expected.is_some_and(|info| info != replay.receipt.info()) {
        return Err(ReceiptError::StaleProgress);
    }
    let Some(batch) = replay.batch(limits)? else {
        return Ok(PublishStep::Complete {
            progress: replay.progress,
        });
    };
    check(&ctx)?;
    let response = tokio::select! {
        biased;
        _=ctx.cancellation().cancelled()=>return Err(ReceiptError::Cancelled),
        _=tokio::time::sleep_until(ctx.deadline())=>return Err(ReceiptError::Timeout),
        result=publisher.publish(&batch,&ctx)=>result,
    };
    check(&ctx)?;
    let (attempt, disposition) = match response {
        Ok(reply) => {
            if reply.body.len() > progress::RESPONSE_LIMIT {
                return Err(ReceiptError::InvalidResponse);
            }
            crate::cloudtrail::decode_json(&reply.body, progress::RESPONSE_LIMIT, 16, 8192)
                .map_err(|_| ReceiptError::InvalidResponse)?;
            let response: IngestResponse =
                serde_json::from_slice(&reply.body).map_err(|_| ReceiptError::InvalidResponse)?;
            // This verification supplies retry classification. The physical store
            // independently checks the actual response against its current pins.
            let verified = verify_admission_response(reply.status, response, batch.event_ids())
                .map_err(|_| ReceiptError::InvalidResponse)?;
            (
                ReceiptAttempt::Response {
                    status: reply.status,
                    body: reply.body,
                },
                verified.disposition,
            )
        }
        Err(PublishFailure::Uncertain) => (ReceiptAttempt::Uncertain, AdmissionDisposition::Retry),
        Err(PublishFailure::Denied) => (ReceiptAttempt::Permanent, AdmissionDisposition::Permanent),
    };
    let before = replay.progress.verified_prefix();
    let total = replay.receipt.info.prepared_count;
    let sent = batch.ids.len();
    let progress = store
        .advance(binding, replay.progress, sent as u32, attempt, ctx)
        .await?;
    let after = progress.verified_prefix();
    Ok(PublishStep::Attempt {
        sent,
        accepted: after - before,
        remaining: total - after,
        disposition,
        progress,
    })
}

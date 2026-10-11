//! Bounded global feed adapter. Host authentication/audit and scoped listing
//! remain separate; this component never selects a local finding fallback.
use signal_control::{ControlClient, ControlContext, ControlError, RetainedFinding};
use signal_protocol::{
    access::RequestGrant,
    findings_feed::{FINDINGS_FEED_EMPTY_BYTES, FindingsCursor, FindingsFeedQuery},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum SharedFeedError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("shared findings cursor stream mismatch")]
    CursorStreamMismatch,
    #[error("shared finding wire page budget exceeded")]
    PageBudget,
}
#[derive(Clone, Copy, Debug)]
pub struct SharedFeedMetrics {
    pub active_callers: usize,
    pub caller_capacity: usize,
    pub rejected: u64,
}
pub struct SharedFindingsFeed {
    reader: Arc<ControlClient>,
    store: Uuid,
    generation: Uuid,
    seats: Semaphore,
    capacity: usize,
    max_bytes: usize,
    active: AtomicUsize,
    rejected: AtomicU64,
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
impl SharedFindingsFeed {
    pub fn new(
        reader: Arc<ControlClient>,
        store: Uuid,
        generation: Uuid,
        capacity: usize,
        max_bytes: usize,
    ) -> Result<Self, SharedFeedError> {
        if store.is_nil()
            || generation.is_nil()
            || !(1..=32).contains(&capacity)
            || !(FINDINGS_FEED_EMPTY_BYTES..=signal_control::REPLY_BYTES).contains(&max_bytes)
        {
            return Err(ControlError::Invalid.into());
        }
        Ok(Self {
            reader,
            store,
            generation,
            seats: Semaphore::new(capacity),
            capacity,
            max_bytes,
            active: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
        })
    }
    pub fn store_binding(&self) -> (Uuid, Uuid) {
        (self.store, self.generation)
    }
    pub fn response_bytes(&self) -> usize {
        self.max_bytes
    }
    pub fn metrics(&self) -> SharedFeedMetrics {
        SharedFeedMetrics {
            active_callers: self.active.load(Ordering::Relaxed),
            caller_capacity: self.capacity,
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub async fn read(
        &self,
        query: FindingsFeedQuery,
        grant: Arc<RequestGrant>,
        context: ControlContext,
    ) -> Result<Vec<u8>, SharedFeedError> {
        let result = async {
            context.check()?;
            let _permit = self.seats.try_acquire().map_err(|_| ControlError::Full)?;
            self.active.fetch_add(1, Ordering::Relaxed);
            let _active = Active(&self.active);
            let page = self
                .reader
                .read_findings_feed(self.store, self.generation, query, grant, context.clone())
                .await.map_err(|error| match error {
                    ControlError::Conflict if matches!(query.after,signal_protocol::findings_feed::FindingsAfter::Cursor(c) if c.stream()!=self.store)=>SharedFeedError::CursorStreamMismatch,
                    error=>SharedFeedError::Control(error),
                })?;
            let records = page.records()?;
            let anchor = match query.after {
                signal_protocol::findings_feed::FindingsAfter::Begin => {
                    FindingsCursor::initial(self.store).map_err(|_| ControlError::Invalid)?
                }
                signal_protocol::findings_feed::FindingsAfter::Cursor(c) => c,
            };
            let bytes = encode(records, anchor, page.has_more()?, self.max_bytes, || {
                context.check()?;
                page.next_cursor().map(|_| ())
            })?;
            page.next_cursor()?;
            context.check()?;
            Ok(bytes)
        }
        .await;
        if result.is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
fn encode(
    records: &[RetainedFinding],
    anchor: FindingsCursor,
    more: bool,
    max_bytes: usize,
    mut check: impl FnMut() -> Result<(), ControlError>,
) -> Result<Vec<u8>, SharedFeedError> {
    check()?;
    if !(FINDINGS_FEED_EMPTY_BYTES..=signal_control::REPLY_BYTES).contains(&max_bytes) {
        return Err(SharedFeedError::PageBudget);
    }
    let mut charge = FINDINGS_FEED_EMPTY_BYTES;
    let mut count = 0;
    let mut cursor = anchor;
    for record in records {
        check()?;
        let next = charge
            .checked_add(record.bytes.len())
            .and_then(|n| n.checked_add(usize::from(count > 0)))
            .ok_or(SharedFeedError::PageBudget)?;
        if next > max_bytes {
            if count == 0 {
                return Err(SharedFeedError::PageBudget);
            }
            break;
        }
        charge = next;
        count += 1;
        cursor = record.cursor;
    }
    let mut bytes = Vec::with_capacity(charge);
    bytes.extend_from_slice(b"{\"schema_version\":1,\"findings\":[");
    for (i, record) in records.iter().take(count).enumerate() {
        check()?;
        if i > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(&record.bytes);
    }
    let more = more || count < records.len();
    let suffix = format!(
        "],\"next_cursor\":\"{}\",\"has_more\":{more}}}",
        cursor.encode()
    );
    if suffix.len() > max_bytes.saturating_sub(bytes.len()) {
        return Err(SharedFeedError::PageBudget);
    }
    bytes.extend_from_slice(suffix.as_bytes());
    check()?;
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn shared_feed_caller_capacity_is_finite_and_counted_before_network()
    -> Result<(), Box<dyn std::error::Error>> {
        use signal_protocol::access::{
            AccessPolicy, AuthenticatedIdentity, Operation, Permission, ResourceScope, Role,
            SubjectBinding,
        };
        let reader = Arc::new(ControlClient::catalog(
            signal_control::ConnectionSettings::fixture_loopback(
                "127.0.0.1".parse()?,
                1,
                "unreachable".into(),
                "unreachable".into(),
                b"synthetic".to_vec(),
            )?,
        )?);
        let store = Uuid::new_v4();
        let feed = SharedFindingsFeed::new(reader.clone(), store, Uuid::new_v4(), 1, 1024)?;
        let policy = AccessPolicy {
            schema_version: 1,
            roles: vec![Role {
                id: "synthetic".into(),
                permissions: vec![Permission {
                    operation: Operation::ReadFindingsFeed,
                    scope: ResourceScope::all(),
                }],
            }],
            bindings: vec![SubjectBinding {
                issuer: "synthetic".into(),
                subject: "reader".into(),
                roles: vec!["synthetic".into()],
            }],
        }
        .compile()?;
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let grant = Arc::new(policy.grant(
            AuthenticatedIdentity::from_verified_backend(
                "synthetic".into(),
                "reader".into(),
                at,
                at + 60,
            )?,
            at,
        )?);
        let permit = feed.seats.try_acquire()?;
        assert!(matches!(
            feed.read(
                FindingsFeedQuery {
                    after: signal_protocol::findings_feed::FindingsAfter::Begin,
                    limit: 1
                },
                grant,
                ControlContext::new(std::time::Duration::from_secs(1))?
            )
            .await,
            Err(SharedFeedError::Control(ControlError::Full))
        ));
        assert_eq!(feed.metrics().rejected, 1);
        assert_eq!(feed.metrics().caller_capacity, 1);
        assert_eq!(feed.metrics().active_callers, 0);
        drop(permit);
        reader
            .shutdown(ControlContext::new(std::time::Duration::from_secs(1))?)
            .await?;
        Ok(())
    }
    #[test]
    fn shared_feed_wire_caps_preserve_exact_original_prefix_cursor()
    -> Result<(), Box<dyn std::error::Error>> {
        let anchor = FindingsCursor::initial(Uuid::new_v4())?;
        let original = b"{ \"synthetic\": 1 }".to_vec();
        let next = anchor.advance(&original)?;
        let rows = vec![
            RetainedFinding {
                id: Uuid::new_v4(),
                cursor: next,
                sha256: [0; 32],
                bytes: original.clone(),
            },
            RetainedFinding {
                id: Uuid::new_v4(),
                cursor: next.advance(b"{}")?,
                sha256: [0; 32],
                bytes: b"{}".to_vec(),
            },
        ];
        let bytes = encode(
            &rows,
            anchor,
            false,
            FINDINGS_FEED_EMPTY_BYTES + original.len(),
            || Ok(()),
        )?;
        assert!(bytes.windows(original.len()).any(|s| s == original));
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["findings"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["next_cursor"], next.encode());
        assert_eq!(value["has_more"], true);
        assert!(matches!(
            encode(&rows, anchor, false, FINDINGS_FEED_EMPTY_BYTES, || Ok(())),
            Err(SharedFeedError::PageBudget)
        ));
        let empty = encode(&[], anchor, false, FINDINGS_FEED_EMPTY_BYTES, || Ok(()))?;
        assert_eq!(empty.len(), FINDINGS_FEED_EMPTY_BYTES);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&empty)?["next_cursor"],
            anchor.encode()
        );
        Ok(())
    }
    #[test]
    fn shared_feed_wire_cancellation_never_returns_a_partial_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let anchor = FindingsCursor::initial(Uuid::new_v4())?;
        assert!(matches!(
            encode(&[], anchor, false, 1024, || Err(ControlError::Cancelled)),
            Err(SharedFeedError::Control(ControlError::Cancelled))
        ));
        Ok(())
    }
}

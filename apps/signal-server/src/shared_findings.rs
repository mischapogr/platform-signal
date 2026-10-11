//! Explicit shared scoped listing. No local fallback or feed cursor authority.
use signal_control::{ControlClient, ControlContext, ControlError, ScopedFindingsBinding};
use signal_findings::{Finding, FindingQuery};
use signal_protocol::access::RequestGrant;
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::Semaphore;
use uuid::Uuid;
const EMPTY: &[u8] = br#"{"schema_version":1,"findings":[]}"#;
#[derive(Debug, thiserror::Error)]
pub enum SharedFindingsError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("shared findings wire budget exceeded")]
    WireBudget,
}
#[derive(Clone, Copy, Debug)]
pub struct SharedFindingsMetrics {
    pub active_callers: usize,
    pub caller_capacity: usize,
    pub rejected: u64,
}
pub struct SharedFindings {
    reader: Arc<ControlClient>,
    binding: ScopedFindingsBinding,
    seats: Semaphore,
    capacity: usize,
    max_bytes: usize,
    active: AtomicUsize,
    rejected: AtomicU64,
}
struct Active<'a> {
    active: &'a AtomicUsize,
    rejected: &'a AtomicU64,
    completed: bool,
}
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if !self.completed {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl SharedFindings {
    pub fn new(
        reader: Arc<ControlClient>,
        binding: ScopedFindingsBinding,
        capacity: usize,
        max_bytes: usize,
    ) -> Result<Self, SharedFindingsError> {
        if binding.store.is_nil()
            || binding.generation.is_nil()
            || binding.scope_generation.is_nil()
            || binding.schema_owner.is_empty()
            || binding.schema_owner.len() > 63
            || binding.schema_owner.capacity() > 63
            || !binding
                .schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !(1..=32).contains(&capacity)
            || !(EMPTY.len()..=signal_control::REPLY_BYTES).contains(&max_bytes)
        {
            return Err(ControlError::Invalid.into());
        }
        Ok(Self {
            reader,
            binding,
            seats: Semaphore::new(capacity),
            capacity,
            max_bytes,
            active: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
        })
    }
    pub fn store_binding(&self) -> (Uuid, Uuid) {
        (self.binding.store, self.binding.generation)
    }
    pub fn response_bytes(&self) -> usize {
        self.max_bytes
    }
    pub fn metrics(&self) -> SharedFindingsMetrics {
        SharedFindingsMetrics {
            active_callers: self.active.load(Ordering::Relaxed),
            caller_capacity: self.capacity,
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub async fn read(
        &self,
        query: FindingQuery,
        grant: Arc<RequestGrant>,
        context: ControlContext,
    ) -> Result<Vec<u8>, SharedFindingsError> {
        let mut tracked = false;
        let result = async {
            context.check()?;
            let _permit = self.seats.try_acquire().map_err(|_| ControlError::Full)?;
            self.active.fetch_add(1, Ordering::Relaxed);
            let mut active = Active {
                active: &self.active,
                rejected: &self.rejected,
                completed: false,
            };
            tracked = true;
            let list = self
                .reader
                .read_scoped_findings(self.binding.clone(), query, grant, context.clone())
                .await?;
            let bytes = encode(list.findings()?, self.max_bytes, || {
                context.check()?;
                list.findings().map(|_| ())
            })?;
            context.check()?;
            list.findings()?;
            active.completed = true;
            Ok(bytes)
        }
        .await;
        if result.is_err() && !tracked {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
fn encode(
    findings: &[Finding],
    max_bytes: usize,
    mut check: impl FnMut() -> Result<(), ControlError>,
) -> Result<Vec<u8>, SharedFindingsError> {
    check()?;
    if !(EMPTY.len()..=signal_control::REPLY_BYTES).contains(&max_bytes) {
        return Err(SharedFindingsError::WireBudget);
    }
    #[derive(serde::Serialize)]
    struct Response<'a> {
        schema_version: u32,
        findings: &'a [Finding],
    }
    struct Wire<'a> {
        bytes: Vec<u8>,
        limit: usize,
        check: &'a mut dyn FnMut() -> Result<(), ControlError>,
    }
    impl Write for Wire<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            (self.check)().map_err(|_| std::io::Error::other("request no longer live"))?;
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("wire capacity"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Fixed capacity avoids a Vec growth doubling beyond the configured budget.
    let mut wire = Wire {
        bytes: Vec::with_capacity(max_bytes),
        limit: max_bytes,
        check: &mut check,
    };
    if serde_json::to_writer(
        &mut wire,
        &Response {
            schema_version: 1,
            findings,
        },
    )
    .is_err()
    {
        (wire.check)()?;
        return Err(SharedFindingsError::WireBudget);
    }
    (wire.check)()?;
    Ok(wire.bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn shared_findings_wire_contract_budget_and_mid_serialization_cancellation() -> Result {
        assert_eq!(encode(&[], EMPTY.len(), || Ok(()))?, EMPTY);
        assert!(matches!(
            encode(&[], EMPTY.len() - 1, || Ok(())),
            Err(SharedFindingsError::WireBudget)
        ));
        let mut calls = 0;
        assert!(matches!(
            encode(&[], 128, || {
                calls += 1;
                if calls >= 3 {
                    Err(ControlError::Cancelled)
                } else {
                    Ok(())
                }
            }),
            Err(SharedFindingsError::Control(ControlError::Cancelled))
        ));
        let finding = Finding {
            schema_version: 1,
            id: Uuid::new_v4(),
            rule_id: "r".into(),
            title: "quoted \" unicode ß".into(),
            severity: signal_findings::DetectionSeverity::High,
            event_ids: vec![Uuid::new_v4()],
            created_at: "2026-10-11T00:00:00Z".parse()?,
            attributes: Default::default(),
        };
        let bytes = encode(std::slice::from_ref(&finding), 65536, || Ok(()))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["findings"][0], serde_json::to_value(&finding)?);
        assert!(matches!(
            encode(&[finding], EMPTY.len(), || Ok(())),
            Err(SharedFindingsError::WireBudget)
        ));
        Ok(())
    }
}

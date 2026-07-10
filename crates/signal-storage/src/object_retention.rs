//! Advisory retention/reachability only. No object deletion or custody authority.
use crate::object_manifest::QueryObjectRef;
use crate::object_publication::CommittedSnapshot;
use crate::{OperationContext, StorageError, check_context};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Write};
use uuid::Uuid;

const MAX_SECONDS: u64 = 10 * 366 * 24 * 3600;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub schema_version: u16,
    /// None means raw policy is independently managed, not infinite retention.
    pub raw_seconds: Option<u64>,
    pub query_seconds: u64,
    pub index_seconds: Option<u64>,
    pub replay_seconds: u64,
    pub evidence_reference_seconds: u64,
    pub reader_seconds: u64,
    pub orphan_grace_seconds: u64,
}
impl RetentionPolicy {
    pub fn validate(&self) -> Result<(), StorageError> {
        let positive = |seconds: u64| (1..=MAX_SECONDS).contains(&seconds);
        if self.schema_version != 1
            || !positive(self.query_seconds)
            || !positive(self.reader_seconds)
            || !positive(self.orphan_grace_seconds)
            || self.raw_seconds.is_some_and(|v| !positive(v))
            || self.index_seconds.is_some_and(|v| !positive(v))
            || self.replay_seconds > MAX_SECONDS
            || self.evidence_reference_seconds > MAX_SECONDS
        {
            return Err(StorageError::Config("bounded retention policy"));
        }
        if self.query_seconds < self.replay_seconds
            || self.query_seconds < self.reader_seconds
            || self.index_seconds.is_some_and(|v| v > self.query_seconds)
            || self
                .raw_seconds
                .is_some_and(|v| v < self.evidence_reference_seconds || v < self.replay_seconds)
            || self.orphan_grace_seconds < self.reader_seconds.max(self.replay_seconds)
        {
            return Err(StorageError::Config("conflicting retention horizons"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ReportLimits {
    pub max_objects: usize,
    pub max_bytes: usize,
}
impl ReportLimits {
    fn validate(self) -> Result<(), StorageError> {
        if self.max_objects == 0
            || self.max_objects > 100_000
            || self.max_bytes == 0
            || self.max_bytes > 64 * 1024 * 1024
        {
            return Err(StorageError::Config("bounded retention report"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    ManifestChain,
    CommittedData,
    UnreferencedQuery,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionDecision {
    KeepCommitted,
    ReplayBlocked,
    RequiresRetirementCommit,
    UnknownOrphanAge,
}
#[derive(Debug, Serialize)]
pub struct ReportObject {
    pub object: QueryObjectRef,
    pub reachability: Reachability,
    pub decision: RetentionDecision,
}
/// An advisory report carries no reader/owner/checkpoint/deletion capability.
#[derive(Debug, Serialize)]
pub struct RetentionReport {
    pub schema_version: u16,
    pub stream_id: Uuid,
    pub assessed_at: DateTime<Utc>,
    pub query_before: DateTime<Utc>,
    pub declared_wal_checkpoint: u64,
    pub objects: Vec<ReportObject>,
}
impl RetentionReport {
    pub fn assess(
        snapshot: &CommittedSnapshot,
        policy: &RetentionPolicy,
        stream: Uuid,
        declared_wal_checkpoint: u64,
        now: DateTime<Utc>,
        limits: ReportLimits,
        context: &OperationContext,
    ) -> Result<Self, StorageError> {
        check_context(Some(context))?;
        policy.validate()?;
        limits.validate()?;
        if stream.is_nil() {
            return Err(StorageError::Config("retention stream"));
        }
        let cutoff = now
            .checked_sub_signed(TimeDelta::seconds(policy.query_seconds as i64))
            .ok_or(StorageError::Config("retention clock range"))?;
        let mut seen = BTreeSet::new();
        let mut weight = std::mem::size_of::<Self>();
        if weight > limits.max_bytes {
            return Err(StorageError::Full);
        }
        // Check input and aggregate copy budget before producing owned output.
        for committed in snapshot.manifests() {
            if committed.manifest.stream_id != stream {
                return Err(StorageError::StreamMismatch);
            }
            for reference in std::iter::once(&committed.reference.object)
                .chain(committed.manifest.files.iter().map(|f| &f.object))
            {
                preflight(reference, stream, &mut seen, &mut weight, limits, context)?;
            }
        }
        for reference in snapshot.orphans() {
            preflight(reference, stream, &mut seen, &mut weight, limits, context)?;
        }
        let object_count = seen.len();
        drop(seen);
        let mut objects = Vec::with_capacity(object_count);
        for committed in snapshot.manifests() {
            check_context(Some(context))?;
            objects.push(ReportObject {
                object: committed.reference.object.clone(),
                reachability: Reachability::ManifestChain,
                decision: RetentionDecision::KeepCommitted,
            });
            for file in &committed.manifest.files {
                check_context(Some(context))?;
                let old = !file
                    .intersects(Some(cutoff), None)
                    .map_err(|_| StorageError::Corrupt("retention partition"))?;
                let decision = if !old {
                    RetentionDecision::KeepCommitted
                } else if committed.reference.last_sequence > declared_wal_checkpoint {
                    RetentionDecision::ReplayBlocked
                } else {
                    RetentionDecision::RequiresRetirementCommit
                };
                objects.push(ReportObject {
                    object: file.object.clone(),
                    reachability: Reachability::CommittedData,
                    decision,
                });
            }
        }
        for reference in snapshot.orphans() {
            check_context(Some(context))?;
            objects.push(ReportObject {
                object: reference.clone(),
                reachability: Reachability::UnreferencedQuery,
                decision: RetentionDecision::UnknownOrphanAge,
            });
        }
        check_context(Some(context))?;
        Ok(Self {
            schema_version: 1,
            stream_id: stream,
            assessed_at: now,
            query_before: cutoff,
            declared_wal_checkpoint,
            objects,
        })
    }
    pub fn encode(
        &self,
        max_bytes: usize,
        context: &OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(StorageError::Config("bounded retention encoding"));
        }
        let mut output = BoundedOutput {
            bytes: Vec::new(),
            maximum: max_bytes,
            context,
        };
        if serde_json::to_writer(&mut output, self).is_err() {
            check_context(Some(context))?;
            return Err(StorageError::Full);
        }
        check_context(Some(context))?;
        Ok(output.bytes)
    }
}
fn preflight<'a>(
    reference: &'a QueryObjectRef,
    stream: Uuid,
    seen: &mut BTreeSet<&'a str>,
    weight: &mut usize,
    limits: ReportLimits,
    context: &OperationContext,
) -> Result<(), StorageError> {
    check_context(Some(context))?;
    reference
        .validate(1024 * 1024 * 1024)
        .map_err(|_| StorageError::Corrupt("retention reference"))?;
    if !reference.key.starts_with(&format!("query/{stream}/")) {
        return Err(StorageError::Corrupt("retention foreign namespace"));
    }
    if seen.contains(reference.key.as_str()) {
        return Err(StorageError::Corrupt("duplicate retention reference"));
    }
    if seen.len() >= limits.max_objects {
        return Err(StorageError::Full);
    }
    let next_weight = weight
        .checked_add(
            std::mem::size_of::<ReportObject>()
                + 128
                + reference.key.len()
                + reference.version.as_ref().map_or(0, String::len)
                + reference.etag.as_ref().map_or(0, String::len),
        )
        .ok_or(StorageError::Full)?;
    if next_weight > limits.max_bytes {
        return Err(StorageError::Full);
    }
    seen.insert(&reference.key);
    *weight = next_weight;
    Ok(())
}
struct BoundedOutput<'a> {
    bytes: Vec<u8>,
    maximum: usize,
    context: &'a OperationContext,
}
impl Write for BoundedOutput<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        check_context(Some(self.context))
            .map_err(|_| std::io::Error::other("retention context"))?;
        if input.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("retention encoding capacity"));
        }
        self.bytes
            .try_reserve_exact(input.len())
            .map_err(|_| std::io::Error::other("retention encoding allocation"))?;
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;

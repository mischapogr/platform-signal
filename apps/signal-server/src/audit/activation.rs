//! Host-computed limited control revisions and fresh startup confirmations.
use super::{Action, Actor, ConfigurationKind, Control, Unavailable};
use sha2::{Digest, Sha256};
use signal_collector_sdk::ExtensionContext;
use std::{
    io::{self, Write},
    sync::{Arc, atomic::Ordering},
};

pub(crate) struct HashWriter(Sha256);
impl HashWriter {
    pub(crate) fn new() -> Self {
        Self(Sha256::new())
    }
    pub(crate) fn finish(self) -> String {
        hex_digest(self.0.finalize().as_ref())
    }
}
fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    // Both callers pass a fixed 32-byte SHA256 result. Nibbles are 0..=15.
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    text
}
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Only these prepared nonsecret resource controls and enabled-mode bits are
/// covered. Never claim this is a commitment to paths, credentials, actual TLS/
/// identity/coverage policies, endpoint contents, logging or backend-specific
/// object settings. No Settings/file/environment lookup occurs here.
pub(crate) struct RuntimeInputs<'a> {
    pub ingest: &'a signal_ingest::IngestConfig,
    pub server: &'a signal_ingest::server::ServerLimits,
    pub buffer: &'a signal_buffer::BufferConfig,
    pub storage: &'a signal_storage::StorageConfig,
    pub query: &'a signal_query::QueryConfig,
    pub findings: &'a signal_findings::FindingConfig,
    pub rules: &'a signal_rules::RuleLimits,
    pub consumer: &'a crate::pipeline::ConsumerConfig,
    pub rule_timeout: std::time::Duration,
    pub tls: bool,
    pub identity: bool,
    pub coverage: bool,
    pub separate_metrics: bool,
}

pub(crate) fn runtime_revision(
    input: RuntimeInputs<'_>,
    context: &ExtensionContext,
) -> Result<String, Unavailable> {
    let mut hash = Sha256::new();
    hash.update(b"platform-signal/runtime-resource-revision/v1\0");
    // Fixed finite named scalar projection of the values handed to the actual
    // runtime. Durations use exact nanoseconds; no debug/whole-config serialization.
    let fields = [
        (
            "ingest.request_bytes",
            input.ingest.max_request_bytes as u128,
        ),
        ("ingest.batch_events", input.ingest.max_batch_events as u128),
        ("ingest.in_flight", input.ingest.max_in_flight as u128),
        ("ingest.timeout", input.ingest.request_timeout.as_nanos()),
        (
            "ingest.bootstrap",
            u128::from(input.ingest.api_token.is_some()),
        ),
        ("server.connections", input.server.max_connections as u128),
        (
            "server.connection_timeout",
            input.server.connection_timeout.as_nanos(),
        ),
        (
            "server.shutdown_timeout",
            input.server.shutdown_timeout.as_nanos(),
        ),
        ("buffer.events", input.buffer.max_events as u128),
        ("buffer.memory", input.buffer.max_memory_bytes as u128),
        ("buffer.record", input.buffer.max_record_bytes as u128),
        ("buffer.disk", input.buffer.max_wal_bytes as u128),
        ("buffer.segment", input.buffer.segment_bytes as u128),
        ("buffer.segments", input.buffer.max_segments as u128),
        ("buffer.commands", input.buffer.command_capacity as u128),
        ("buffer.waiters", input.buffer.max_waiters as u128),
        (
            "buffer.operation_timeout",
            input.buffer.operation_timeout.as_nanos(),
        ),
        (
            "buffer.block_timeout",
            input.buffer.block_timeout.as_nanos(),
        ),
        (
            "buffer.policy",
            match input.buffer.policy {
                signal_buffer::Policy::RejectNew => 0,
                signal_buffer::Policy::DropOldest => 1,
                signal_buffer::Policy::BlockWithTimeout => 2,
            },
        ),
        (
            "storage.batch_events",
            input.storage.max_batch_events as u128,
        ),
        ("storage.batch_bytes", input.storage.max_batch_bytes as u128),
        ("storage.event_bytes", input.storage.max_event_bytes as u128),
        ("storage.disk", input.storage.max_disk_bytes as u128),
        ("storage.files", input.storage.max_files as u128),
        ("storage.commands", input.storage.command_capacity as u128),
        (
            "storage.timeout",
            input.storage.operation_timeout.as_nanos(),
        ),
        (
            "storage.compression",
            match input.storage.compression {
                signal_storage::StorageCompression::Snappy => 0,
                signal_storage::StorageCompression::Zstd => 1,
                signal_storage::StorageCompression::Uncompressed => 2,
            },
        ),
        ("query.memory", input.query.memory_bytes as u128),
        ("query.concurrency", input.query.max_concurrent as u128),
        ("query.files", input.query.max_files as u128),
        ("query.limit", input.query.max_limit as u128),
        (
            "query.response_bytes",
            input.query.max_response_bytes as u128,
        ),
        ("query.batch_rows", input.query.batch_rows as u128),
        ("query.partitions", input.query.target_partitions as u128),
        ("query.timeout", input.query.timeout.as_nanos()),
        ("findings.disk", input.findings.max_disk_bytes as u128),
        ("findings.records", input.findings.max_findings as u128),
        (
            "findings.record_bytes",
            input.findings.max_record_bytes as u128,
        ),
        (
            "findings.append_rows",
            input.findings.max_append_rows as u128,
        ),
        (
            "findings.append_bytes",
            input.findings.max_append_bytes as u128,
        ),
        ("findings.query_rows", input.findings.max_query_rows as u128),
        (
            "findings.query_bytes",
            input.findings.max_query_bytes as u128,
        ),
        (
            "findings.index_bytes",
            input.findings.max_index_bytes as u128,
        ),
        ("findings.commands", input.findings.command_capacity as u128),
        (
            "findings.timeout",
            input.findings.operation_timeout.as_nanos(),
        ),
        ("rules.count", input.rules.max_rules as u128),
        ("rules.entries", input.rules.max_directory_entries as u128),
        ("rules.document", input.rules.max_document_bytes as u128),
        ("rules.total", input.rules.max_total_bytes as u128),
        ("rules.predicates", input.rules.max_predicates as u128),
        ("rules.nodes", input.rules.max_value_nodes as u128),
        ("rules.depth", input.rules.max_depth as u128),
        ("rules.field", input.rules.max_field_bytes as u128),
        ("rules.title", input.rules.max_title_bytes as u128),
        ("rules.load_timeout", input.rule_timeout.as_nanos()),
        ("consumer.events", input.consumer.max_events as u128),
        ("consumer.bytes", input.consumer.max_bytes as u128),
        (
            "consumer.timeout",
            input.consumer.operation_timeout.as_nanos(),
        ),
        ("consumer.flush", input.consumer.flush_interval.as_nanos()),
        ("mode.tls", u128::from(input.tls)),
        ("mode.identity", u128::from(input.identity)),
        ("mode.coverage", u128::from(input.coverage)),
        ("mode.metrics", u128::from(input.separate_metrics)),
    ];
    for (name, value) in fields {
        context.check().map_err(|_| Unavailable)?;
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update(value.to_le_bytes());
    }
    context.check().map_err(|_| Unavailable)?;
    Ok(hex_digest(hash.finalize().as_ref()))
}

struct PendingActivation<'a> {
    control: &'a Control,
    confirmed: bool,
}
impl Drop for PendingActivation<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.control.incomplete.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Control {
    pub(crate) fn selects_activation(&self, kind: ConfigurationKind) -> bool {
        self.activations.contains(&kind)
    }
    pub(crate) fn has_activations(&self) -> bool {
        !self.activations.is_empty()
    }
    /// Installed inactive runtime state, never a claim of served readiness.
    /// Every invocation stages a fresh record; old replay cannot substitute.
    pub(crate) async fn activate(
        self: &Arc<Self>,
        kind: ConfigurationKind,
        revision: String,
        context: ExtensionContext,
    ) -> Result<(), Unavailable> {
        context.check().map_err(|_| Unavailable)?;
        if !self.selects_activation(kind) || self.metrics().held {
            return Err(Unavailable);
        }
        let _slot = self.slots.clone().try_acquire_owned().map_err(|_| {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            Unavailable
        })?;
        let mut pending = PendingActivation {
            control: self,
            confirmed: false,
        };
        let record = self
            .outbox
            .stage(
                Actor::System {},
                Action::ConfigurationActivation {
                    configuration: kind,
                    revision_sha256: revision,
                },
                chrono::Utc::now(),
                context.clone(),
            )
            .await
            .map_err(|_| Unavailable)?;
        let confirmed = self
            .outbox
            .flush(self.destination.as_ref(), context.clone())
            .await
            .map_err(|_| Unavailable)?;
        if confirmed != Some(record.record().record_id) {
            return Err(Unavailable);
        }
        context.check().map_err(|_| Unavailable)?;
        pending.confirmed = true;
        Ok(())
    }
}

/// Bound the caller's selected preparation under the original context. Dropping
/// started disk/network futures retains their existing physical-worker ownership.
/// This boundary does not renew those workers or claim they all end at timeout.
pub(crate) async fn within_startup<T>(
    context: &ExtensionContext,
    work: impl std::future::Future<Output = Result<T, crate::AppError>>,
) -> Result<T, crate::AppError> {
    context.check().map_err(|_| Unavailable)?;
    let result = tokio::select! {
        biased;
        _ = context.cancellation().cancelled() => return Err(Unavailable.into()),
        result = tokio::time::timeout_at(context.deadline(),work) => result.map_err(|_|Unavailable)?,
    };
    // A work reply can already be ready when polled after its original clock.
    context.check().map_err(|_| Unavailable)?;
    result
}

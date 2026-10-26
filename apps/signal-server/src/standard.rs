//! Standard executable composition; existing owner enrollment only.
use crate::{AppError, config::Settings, logging::LoggerGuard};
#[cfg(feature = "s3-query")]
#[path = "standard_findings.rs"]
mod finding_batch;
#[cfg(feature = "s3-query")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Shared(#[from] signal_server::shared::SharedError),
    #[error(transparent)]
    Recovery(#[from] signal_server::shared_recovery::RecoveryError),
    #[error(transparent)]
    Feed(#[from] signal_server::shared_feed::SharedFeedError),
    #[error(transparent)]
    Window(#[from] crate::standard_window::Error),
    #[error(transparent)]
    Sensor(#[from] crate::standard_sensor::Error),
    #[error("Standard runtime held; unfinished events remain in WAL")]
    Held,
    #[error("Standard consumer task failed")]
    Task,
}
#[cfg(not(feature = "s3-query"))]
pub(crate) async fn run(_: Settings, _: &LoggerGuard) -> Result<(), AppError> {
    Err(crate::config::ConfigError::Invalid("Standard requires s3-query build feature").into())
}
#[cfg(feature = "s3-query")]
pub(crate) use host::run;
#[cfg(feature = "s3-query")]
mod host {
    use super::*;
    use crate::{audit, finding_api, query_api, runtime_config, standard_config, ui};
    use axum::{Router, extract::State, routing::get};
    use sha2::{Digest, Sha256};
    use signal_buffer::DurableBuffer;
    use signal_control::{
        CatalogInput, ControlClient, ControlContext, ControlError, LeaseToken, SharedQuerySource,
    };
    use signal_findings::DerivedFinding;
    use signal_ingest::{IngestService, server};
    use signal_protocol::{
        AdmissionFuture, EventSink, QuerySinkMetrics, SinkMetrics, access::RequestGrant,
    };
    use signal_server::{
        shared::{PublicationDraft, SharedPublisher},
        shared_admission::SharedAdmission,
        shared_feed::SharedFindingsFeed,
        shared_findings::SharedFindings,
        shared_recovery::{RECOVERY_BYTES, SharedRecovery},
        shared_scoped::ScopedPublicationDraft,
    };
    use signal_storage::{
        OperationContext, StorageError, StoredEvent,
        object_cache::MaterializationConfig,
        object_codec::ObjectCodec,
        object_io::{ObjectIo, ObjectIoLimits},
        object_manifest::ManifestLimits,
        object_s3::{self, S3Config, S3Credentials},
        object_selection::{ObjectSelection, SelectionConfig},
    };
    use std::{
        fmt::Write,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::{
        net::TcpListener,
        time::{Instant, timeout_at},
    };
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    fn context(cancel: &CancellationToken) -> Result<ControlContext, ControlError> {
        ControlContext::new_cancellable(Duration::from_secs(5), cancel)
    }
    fn io_context(deadline: Instant) -> OperationContext {
        OperationContext {
            deadline,
            cancellation: CancellationToken::new(),
        }
    }
    fn remote(
        settings: &Settings,
        doc: &standard_config::Document,
        resources: &mut StartupResources,
    ) -> Result<(), AppError> {
        let required = |name| {
            settings
                .optional(name)?
                .ok_or(crate::config::ConfigError::Invalid(
                    "Standard S3 setting missing",
                ))
        };
        if required("SIGNAL_STORAGE_TYPE")? != "s3" {
            return Err(StorageError::Config("Standard requires versioned S3").into());
        }
        let allow = match settings
            .optional("SIGNAL_S3_ALLOW_LOOPBACK_HTTP")?
            .as_deref()
        {
            None | Some("false") => false,
            Some("true") => true,
            _ => return Err(StorageError::Config("S3 loopback setting").into()),
        };
        let bytes = settings.number("SIGNAL_S3_OBJECT_BYTES", 64 * 1024 * 1024)?;
        let cfg = S3Config {
            endpoint: required("SIGNAL_S3_ENDPOINT")?,
            region: required("SIGNAL_S3_REGION")?,
            bucket: required("SIGNAL_S3_BUCKET")?,
            max_object_bytes: bytes,
            allow_loopback_http: allow,
        };
        let credentials = S3Credentials {
            access_key: settings.secret_environment("SIGNAL_S3_ACCESS_KEY")?,
            secret_key: settings.secret_environment("SIGNAL_S3_SECRET_KEY")?,
            session_token: settings.optional("SIGNAL_S3_SESSION_TOKEN")?,
        };
        let encryption = crate::storage::kms_selection(settings)?;
        let (store, _) = object_s3::build_with_kms(&cfg, &credentials, encryption.as_ref())
            .map_err(|_| StorageError::Config("Standard S3 adapter"))?;
        let limits = ObjectIoLimits {
            bytes,
            entries: settings.number("SIGNAL_S3_INVENTORY_OBJECTS", 10000)?,
            timeout: Duration::from_secs(5),
        };
        resources.publish_io = Some(Arc::new(
            ObjectIo::remote(Arc::new(store), tokio::runtime::Handle::current(), limits)
                .map_err(StorageError::ObjectIo)?,
        ));
        // Each physical pool needs its own bounded HTTP transport seat. Sharing
        // one S3 adapter makes concurrent publication/query requests reject each
        // other even though their ObjectIo admission seats are independent.
        let (query_store, _) = object_s3::build_with_kms(&cfg, &credentials, encryption.as_ref())
            .map_err(|_| StorageError::Config("Standard S3 query adapter"))?;
        resources.query_io = Some(Arc::new(
            ObjectIo::remote(
                Arc::new(query_store),
                tokio::runtime::Handle::current(),
                limits,
            )
            .map_err(StorageError::ObjectIo)?,
        ));
        if let Some(c) = &doc.custody {
            let (store, _) = object_s3::build(&cfg, &credentials)
                .map_err(|_| StorageError::Config("custody S3 adapter"))?;
            let (reader, _) =
                object_s3::build_custody_reader(&cfg, &credentials, &c.expected_bucket_owner)
                    .map_err(|_| StorageError::Config("custody S3 retention adapter"))?;
            resources.custody_io = Some(Arc::new(
                ObjectIo::remote_retained(
                    Arc::new(store),
                    reader,
                    tokio::runtime::Handle::current(),
                    limits,
                )
                .map_err(StorageError::ObjectIo)?,
            ));
        }
        Ok(())
    }
    struct Sink {
        admission: Arc<SharedAdmission>,
        wal: Arc<DurableBuffer>,
        control: Arc<ControlClient>,
        reader: Arc<ControlClient>,
        publisher: Arc<SharedPublisher>,
        recovery: Arc<SharedRecovery>,
        source: Arc<SharedQuerySource>,
        query: Arc<signal_query::QueryEngine>,
        lease_deadline: Mutex<Instant>,
        held: AtomicBool,
        audit: Option<Arc<audit::Control>>,
        coverage: Option<Arc<signal_coverage::CoverageStore>>,
        evaluated: AtomicU64,
        matches: AtomicU64,
        failures: AtomicU64,
        logging: crate::logging::LogWriter,
        window: Option<Arc<crate::standard_window::Health>>,
        sensor: Option<Arc<crate::standard_sensor::Health>>,
        loaded_rules: usize,
    }
    impl Sink {
        fn deadline(&self) -> Option<Instant> {
            self.lease_deadline.lock().ok().map(|d| *d)
        }
        fn hold(&self) {
            if let Some(window) = &self.window {
                window.stop();
            }
            if let Some(sensor) = &self.sensor {
                sensor.stop();
            }
            self.held.store(true, Ordering::Release);
            self.admission.close();
        }
        fn live(&self) -> bool {
            !self.held.load(Ordering::Acquire)
                && self.deadline().is_some_and(|d| Instant::now() < d)
                && !self.publisher.metrics().closed
                && !self.publisher.metrics().objects.closed
                && !self.publisher.metrics().codec.closed
                && !self.source.metrics().objects.closed
                && !self.source.metrics().io.closed
                && !self.source.metrics().codec.closed
                && self.control.metrics().quarantined < self.control.metrics().connection_capacity
                && self.reader.metrics().quarantined < self.reader.metrics().connection_capacity
                && self.audit.as_ref().is_none_or(|a| !a.metrics().held)
                && self.coverage.as_ref().is_none_or(|c| c.metrics().available)
        }
    }
    impl EventSink for Sink {
        fn admit(&self, event: signal_event::SignalEvent) -> AdmissionFuture<'_> {
            Box::pin(async move {
                if let Some(sensor) = &self.sensor {
                    sensor.validate(&event)?;
                }
                self.admission.admit(event).await
            })
        }
        fn admit_with_grant<'a>(
            &'a self,
            event: signal_event::SignalEvent,
            grant: &'a RequestGrant,
            deadline: std::time::Instant,
        ) -> AdmissionFuture<'a> {
            Box::pin(async move {
                if !self.live() {
                    return Err(signal_protocol::AdmissionError::Unavailable);
                }
                let lease = self
                    .deadline()
                    .ok_or(signal_protocol::AdmissionError::Unavailable)?;
                if let Some(sensor) = &self.sensor {
                    sensor.validate(&event)?;
                }
                self.admission
                    .admit_with_grant(event, grant, deadline.min(lease.into_std()))
                    .await
            })
        }
        fn close(&self) {
            self.admission.close();
        }
        fn metrics(&self) -> SinkMetrics {
            let mut m = self.admission.metrics();
            m.closed |= !self.live();
            m.audit = self.audit.as_ref().map(|a| a.metrics());
            m.rules = Some(signal_protocol::RuleSinkMetrics {
                loaded: self.loaded_rules,
                evaluated: self.evaluated.load(Ordering::Relaxed),
                matches: self.matches.load(Ordering::Relaxed),
                failures: self.failures.load(Ordering::Relaxed),
                window: self.window.as_ref().map(|w| w.metrics()),
                sensor_health: self.sensor.as_ref().map(|s| s.metrics()),
            });
            m.closed |= m.audit.is_some_and(|a| a.held)
                || self
                    .coverage
                    .as_ref()
                    .is_some_and(|c| !c.metrics().available);
            {
                let query = &self.query;
                let query = query.metrics();
                m.query = Some(QuerySinkMetrics {
                    io_queue_depth: query.io_queue_depth,
                    io_queue_capacity: query.io_queue_capacity,
                    io_running: query.io_running,
                    io_worker_capacity: query.io_worker_capacity,
                    io_depth: query.io_depth,
                    io_capacity: query.io_capacity,
                    io_rejected: query.io_rejected,
                    io_bytes: query.io_bytes,
                    io_byte_capacity: query.io_byte_capacity,
                    io_waiters: query.io_waiters,
                    io_waiter_capacity: query.io_waiter_capacity,
                    depth: query.depth,
                    capacity: query.capacity,
                    requests: query.requests,
                    completed: query.completed,
                    failures: query.failures,
                    rejected: query.rejected,
                    timeouts: query.timeouts,
                    cancelled: query.cancelled,
                    scanned_files: query.scanned_files,
                    selected_partitions: query.selected_partitions,
                    latency_micros: query.latency_micros,
                    memory_bytes: query.memory_bytes,
                    memory_capacity: query.memory_capacity,
                });
            }
            {
                let logger = &self.logging;
                let logs = logger.metrics();
                m.logging = Some(signal_protocol::LoggingSinkMetrics {
                    depth: logs.depth,
                    capacity: logs.capacity,
                    bytes: logs.bytes,
                    byte_capacity: logs.capacity_bytes,
                    queued: logs.queued_records,
                    dropped: logs.dropped_records,
                    full: logs.full_records,
                    oversized: logs.oversized_records,
                    closed_records: logs.closed_records,
                    written: logs.written_records,
                    errors: logs.write_errors,
                    closed: logs.closed,
                });
            }
            m
        }
    }
    #[derive(Clone)]
    struct MetricsState {
        sink: Arc<Sink>,
        findings: Arc<SharedFindings>,
        feed: Arc<SharedFindingsFeed>,
        custody: Option<Arc<signal_server::shared_custody_api::CustodyApi>>,
    }
    async fn shared_metrics(State(state): State<MetricsState>) -> String {
        let s = state.sink;
        let p = s.publisher.metrics();
        let r = s.recovery.metrics();
        let c = s.control.metrics();
        let q = s.reader.metrics();
        let f = s.source.metrics();
        let a = s.admission.admission_metrics();
        let list = state.findings.metrics();
        let feed = state.feed.metrics();
        let rows = [
            (
                "producer_quarantined_connections",
                c.quarantined,
                c.connection_capacity,
            ),
            (
                "reader_quarantined_connections",
                q.quarantined,
                q.connection_capacity,
            ),
            ("producer_queue", c.queue_depth, c.queue_capacity),
            ("producer_connections", c.active, c.connection_capacity),
            ("reader_queue", q.queue_depth, q.queue_capacity),
            ("reader_connections", q.active, q.connection_capacity),
            ("admission", a.active, a.capacity),
            ("publication", p.active, p.capacity),
            ("object_queue", p.objects.depth, p.objects.capacity),
            (
                "object_workers",
                p.objects.running,
                p.objects.worker_capacity,
            ),
            ("codec_queue", p.codec.depth, p.codec.capacity),
            ("codec_workers", p.codec.running, p.codec.worker_capacity),
            (
                "query_objects_workers",
                f.objects.running,
                f.objects.worker_capacity,
            ),
            ("recovery", r.active, r.capacity),
            ("recovery_bytes", r.retained_bytes, r.retained_capacity),
            ("query_objects_queue", f.objects.depth, f.objects.capacity),
            ("query_io_queue", f.io.depth, f.io.capacity),
            ("query_io_workers", f.io.running, f.io.worker_capacity),
            ("query_codec_queue", f.codec.depth, f.codec.capacity),
            (
                "query_codec_workers",
                f.codec.running,
                f.codec.worker_capacity,
            ),
            (
                "findings_callers",
                list.active_callers,
                list.caller_capacity,
            ),
            ("feed_callers", feed.active_callers, feed.caller_capacity),
        ];
        let mut out = String::with_capacity(4096);
        if let Some(api) = &state.custody {
            let m = api.metrics();
            let _ = writeln!(
                &mut out,
                "signal_shared_custody_requests_depth {}\nsignal_shared_custody_requests_capacity {}\nsignal_shared_custody_confirmed_total {}\nsignal_shared_custody_rejected_total {}",
                m.depth, m.capacity, m.confirmed, m.rejected
            );
        }
        for (name, depth, capacity) in rows {
            let _ = writeln!(
                &mut out,
                "signal_shared_{name}_depth {depth}\nsignal_shared_{name}_capacity {capacity}"
            );
        }
        let counters = [
            ("producer_fenced_results", c.fenced_results),
            ("reader_fenced_results", q.fenced_results),
            ("producer_transaction_timeouts", c.transaction_timeouts),
            ("reader_transaction_timeouts", q.transaction_timeouts),
            ("producer_lease_acquired_results", c.lease_acquired_results),
            ("producer_lease_renewed_results", c.lease_renewed_results),
            ("reader_lease_acquired_results", q.lease_acquired_results),
            ("reader_lease_renewed_results", q.lease_renewed_results),
            ("producer_snapshot_expired", c.snapshot_expired),
            ("reader_snapshot_expired", q.snapshot_expired),
            ("producer_snapshot_retries", c.snapshot_retries),
            ("reader_snapshot_retries", q.snapshot_retries),
            ("producer_retirement_retries", c.retirement_retries),
            ("reader_retirement_retries", q.retirement_retries),
            (
                "producer_notification_uncertain_results",
                c.notification_uncertain_results,
            ),
            (
                "reader_notification_uncertain_results",
                q.notification_uncertain_results,
            ),
            (
                "publication_orphan_candidate_results",
                p.orphan_candidate_results,
            ),
            ("publication_prepared", p.prepared),
            ("publication_committed", p.committed),
            ("producer_rejected", c.rejected),
            ("reader_rejected", q.rejected),
            ("admission_rejected", a.rejected),
            ("publication_rejected", p.rejected),
            ("object_rejected", p.objects.rejected),
            ("codec_rejected", p.codec.rejected),
            ("recovery_rejected", r.rejected),
            ("query_objects_rejected", f.rejected),
            ("query_selection_rejected", f.objects.rejected),
            ("query_io_rejected", f.io.rejected),
            ("query_codec_rejected", f.codec.rejected),
            ("findings_rejected", list.rejected),
            ("feed_rejected", feed.rejected),
            ("rules_evaluated", s.evaluated.load(Ordering::Relaxed)),
            ("rules_matches", s.matches.load(Ordering::Relaxed)),
            ("failures", s.failures.load(Ordering::Relaxed)),
        ];
        for (name, value) in counters {
            let _ = writeln!(&mut out, "signal_shared_{name}_total {value}");
        }
        if let Some(window) = &s.window {
            let (pins, capacity) = window.pins();
            let _ = writeln!(
                &mut out,
                "signal_shared_window_replay_pin_queue_depth {pins}\nsignal_shared_window_replay_pin_queue_capacity {capacity}"
            );
        }
        if let Some(sensor) = &s.sensor {
            let (pins, capacity) = sensor.pins();
            let _ = writeln!(
                &mut out,
                "signal_shared_sensor_replay_pin_queue_depth {pins}\nsignal_shared_sensor_replay_pin_queue_capacity {capacity}"
            );
        }
        out
    }
    struct ConsumerGuard {
        sink: Arc<Sink>,
        failed: CancellationToken,
    }
    impl Drop for ConsumerGuard {
        fn drop(&mut self) {
            self.sink.hold();
            self.failed.cancel();
        }
    }
    struct Consumer {
        onboarding: Option<Arc<crate::onboarding::Host>>,
        window: Option<crate::standard_window::Consumer>,
        sensor: Option<crate::standard_sensor::Consumer>,
        sink: Arc<Sink>,
        token: LeaseToken,
        head: Option<Uuid>,
        rules: signal_rules::RuleSet,
        revision: [u8; 32],
        cfg: crate::pipeline::ConsumerConfig,
        lease_ms: u32,
        drain: CancellationToken,
        cancel: CancellationToken,
        failed: CancellationToken,
        finding_rows: usize,
        finding_bytes_limit: usize,
    }
    async fn consume(input: Consumer) -> Result<(), AppError> {
        let Consumer {
            onboarding,
            mut window,
            mut sensor,
            sink,
            mut token,
            mut head,
            rules,
            revision,
            cfg,
            lease_ms,
            drain,
            cancel,
            failed,
            finding_rows,
            finding_bytes_limit,
        } = input;
        let _guard = ConsumerGuard {
            sink: sink.clone(),
            failed,
        };
        let lease = Duration::from_millis(u64::from(lease_ms));
        loop {
            if cancel.is_cancelled() {
                return Err(Error::Held.into());
            }
            if sink
                .deadline()
                .is_none_or(|d| d.saturating_duration_since(Instant::now()) <= lease / 2)
            {
                let anchor = Instant::now();
                token = sink
                    .control
                    .renew(token, lease_ms, context(&cancel)?)
                    .await?;
                *sink.lease_deadline.lock().map_err(|_| Error::Held)? = anchor + lease;
            }
            let original = context(&cancel)?;
            let batch = sink
                .wal
                .read_batch_at(
                    cfg.max_events
                        .min(4096)
                        .min(finding_rows / rules.len().max(1)),
                    cfg.max_bytes.min(16 * 1024 * 1024),
                    original.deadline(),
                )
                .await?;
            if batch.is_empty() {
                if drain.is_cancelled() {
                    return Ok(());
                }
                if let Some(sensor) = sensor.as_mut()
                    && sensor.due()
                {
                    sensor
                        .maintain(&sink.control, token.clone(), head, original)
                        .await
                        .map_err(Error::from)?;
                    if let Some(head) = head {
                        sensor
                            .cleanup(&sink.control, token.clone(), head, context(&cancel)?)
                            .await
                            .map_err(Error::from)?;
                    }
                }
                let delay = sensor
                    .as_ref()
                    .map_or(Duration::from_secs(1), |s| s.wait())
                    .min(cfg.flush_interval)
                    .min(Duration::from_secs(1));
                tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::Held.into()),_=drain.cancelled()=>{},_=tokio::time::sleep(delay)=>{}}
                continue;
            }
            let rows: Vec<_> = batch
                .into_iter()
                .map(|r| StoredEvent {
                    sequence: r.sequence,
                    event: r.event,
                })
                .collect();
            let mut derived = Vec::new();
            let mut legacy = Vec::new();
            let mut finding_bytes = 0usize;
            for row in &rows {
                let context = signal_rules::RuleContext {
                    deadline: original.deadline(),
                    cancellation: original.cancellation_token(),
                };
                let findings = match &onboarding {
                    Some(host) => {
                        host.evaluate(
                            &rules,
                            &row.event,
                            &context,
                            row.sequence > sink.admission.admission_floor(),
                        )
                        .await?
                    }
                    None => rules.evaluate_with_context(&row.event, &context)?,
                };
                sink.evaluated.fetch_add(1, Ordering::Relaxed);
                for finding in findings {
                    if derived.len() + legacy.len() >= finding_rows {
                        return Err(ControlError::Full.into());
                    }
                    let bytes = serde_json::to_vec(&finding).map_err(|_| ControlError::Invalid)?;
                    finding_bytes = finding_bytes
                        .checked_add(bytes.len())
                        .ok_or(ControlError::Full)?;
                    if finding_bytes > finding_bytes_limit {
                        return Err(ControlError::Full.into());
                    }
                    sink.matches.fetch_add(1, Ordering::Relaxed);
                    if row.sequence > sink.admission.admission_floor() {
                        let scoped = DerivedFinding::from_event(finding, &row.event, true)?
                            .into_scoped(sink.admission.enrollment().scope_generation)?;
                        derived.push((row.sequence, scoped));
                    } else {
                        legacy.push(signal_control::FindingInput {
                            id: finding.id,
                            bytes,
                        });
                    }
                }
            }
            let mut plan = PublicationDraft {
                schema_version: 1,
                id: Uuid::new_v4(),
                previous: head,
                rule_revision: revision,
                normalizer_revision: "signal-event-v1".into(),
                states: vec![],
                findings: legacy,
                work: vec![],
                receipts: vec![],
            };
            let result = if window.is_some() || sensor.is_some() {
                let primary = window
                    .as_ref()
                    .map(|w| w.binding.key.clone())
                    .or_else(|| sensor.as_ref().map(|s| s.binding.key.clone()))
                    .ok_or(ControlError::Invalid)?;
                let mut owners = std::collections::BTreeMap::new();
                for (_, finding) in &derived {
                    owners
                        .entry(finding.finding().id)
                        .or_insert(primary.clone());
                }
                let mut window_candidate = match window.as_mut() {
                    Some(window) => Some(
                        window
                            .prepare(
                                &rows,
                                sink.admission.admission_floor(),
                                sink.wal.snapshot().last_sequence,
                                &original,
                            )
                            .await
                            .map_err(Error::from)?,
                    ),
                    None => None,
                };
                let mut sensor_candidate = match sensor.as_mut() {
                    Some(sensor) => Some(
                        sensor
                            .prepare(&rows, &original)
                            .await
                            .map_err(Error::from)?,
                    ),
                    None => None,
                };
                let mut groups = Vec::new();
                if let (Some(window), Some(candidate)) =
                    (window.as_ref(), window_candidate.as_mut())
                {
                    plan.states.push(candidate.value.clone());
                    for (_, finding) in &candidate.derived {
                        owners
                            .entry(finding.finding().id)
                            .or_insert(window.binding.key.clone());
                    }
                    sink.matches
                        .fetch_add(candidate.derived.len() as u64, Ordering::Relaxed);
                    derived.append(&mut candidate.derived);
                    groups.push(signal_control::StateFindingGroup {
                        state_key: window.binding.key.clone(),
                        prior: window.prior.clone(),
                        retained: window.retained.clone(),
                        derived: Vec::new(),
                    });
                }
                if let (Some(sensor), Some(candidate)) =
                    (sensor.as_ref(), sensor_candidate.as_mut())
                {
                    if groups.iter().any(|g| g.state_key == sensor.binding.key) {
                        return Err(ControlError::Conflict.into());
                    }
                    plan.states.push(candidate.value.clone());
                    for (_, finding) in &candidate.derived {
                        owners
                            .entry(finding.finding().id)
                            .or_insert(sensor.binding.key.clone());
                    }
                    sink.matches
                        .fetch_add(candidate.derived.len() as u64, Ordering::Relaxed);
                    derived.append(&mut candidate.derived);
                    groups.push(signal_control::StateFindingGroup {
                        state_key: sensor.binding.key.clone(),
                        prior: sensor.prior.clone(),
                        retained: sensor.retained.clone(),
                        derived: Vec::new(),
                    });
                }
                // Reconcile all detectors together before assigning each original
                // fact to its first producer. Known findings retain original bytes.
                let batch =
                    super::finding_batch::reconcile(derived, std::mem::take(&mut plan.findings))?;
                if batch.candidates.len() > finding_rows {
                    return Err(ControlError::Full.into());
                }
                let total_bytes = batch.candidates.iter().try_fold(0usize, |n, f| {
                    n.checked_add(f.bytes.len()).ok_or(ControlError::Full)
                })?;
                if total_bytes > finding_bytes_limit {
                    return Err(ControlError::Full.into());
                }
                let known = sink
                    .control
                    .known_findings(token.clone(), head, batch.candidates, original.clone())
                    .await?;
                plan.findings = batch.legacy;
                plan.findings.retain(|f| !known.contains(&f.id));
                for (sequence, finding) in batch.scoped {
                    if known.contains(&finding.finding().id) {
                        continue;
                    }
                    let key = owners
                        .get(&finding.finding().id)
                        .ok_or(ControlError::Corrupt)?;
                    let group = groups
                        .iter_mut()
                        .find(|g| &g.state_key == key)
                        .ok_or(ControlError::Corrupt)?;
                    group.derived.push((sequence, finding));
                }
                let draft=signal_server::shared_multi_event::MultiEventPublicationDraft::from_state_groups(plan,sink.admission.enrollment(),&rows,&primary,groups)?;
                let prepared = sink
                    .recovery
                    .prepare_multi_event(token.clone(), draft, rows.len(), original.clone())
                    .await
                    .map_err(Error::from)?;
                let result = sink.recovery.commit(prepared).await.map_err(Error::from)?;
                if sink.wal.snapshot().checkpoint != result.last_sequence
                    || sink
                        .wal
                        .read_recovery(context(&cancel)?.deadline())
                        .await?
                        .is_some()
                {
                    return Err(Error::Held.into());
                }
                // Confirm both original candidates before follow-up operations
                // can consume their immutable publication/confirmation deadline.
                if let (Some(sensor), Some(candidate)) = (sensor.as_mut(), sensor_candidate) {
                    sensor
                        .accept(candidate, result.last_sequence, &original)
                        .map_err(Error::from)?;
                }
                if let (Some(window), Some(candidate)) = (window.as_mut(), window_candidate) {
                    window
                        .accept(candidate, result.last_sequence)
                        .map_err(Error::from)?;
                }
                if let Some(window) = window.as_mut() {
                    window
                        .cleanup(&sink.control, token.clone(), result.id, context(&cancel)?)
                        .await
                        .map_err(Error::from)?;
                    window
                        .refresh_history(&sink.control, token.clone(), result.id, context(&cancel)?)
                        .await
                        .map_err(Error::from)?;
                }
                if let Some(sensor) = sensor.as_mut() {
                    sensor
                        .cleanup(&sink.control, token.clone(), result.id, context(&cancel)?)
                        .await
                        .map_err(Error::from)?;
                }
                result
            } else {
                let scoped = ScopedPublicationDraft::from_host(
                    plan,
                    sink.admission.enrollment(),
                    &rows,
                    derived,
                )?;
                let prepared = sink
                    .recovery
                    .prepare_scoped(token.clone(), scoped, rows.len(), original)
                    .await
                    .map_err(Error::from)?;
                sink.recovery.commit(prepared).await.map_err(Error::from)?
            };
            head = Some(result.id);
        }
    }

    // Retain physical resources outside the cancellable preparation future.
    // Cancelling startup drops callers before draining their owned workers.
    #[derive(Default)]
    struct StartupResources {
        identity: Option<signal_ingest::identity::IdentityBackend>,
        control: Option<Arc<ControlClient>>,
        reader: Option<Arc<ControlClient>>,
        wal: Option<Arc<DurableBuffer>>,
        publisher: Option<Arc<SharedPublisher>>,
        publish_io: Option<Arc<ObjectIo>>,
        query_io: Option<Arc<ObjectIo>>,
        custody_io: Option<Arc<ObjectIo>>,
        publish_codec: Option<Arc<ObjectCodec>>,
        query_codec: Option<Arc<ObjectCodec>>,
        source: Option<Arc<SharedQuerySource>>,
        query: Option<Arc<signal_query::QueryEngine>>,
        coverage: Option<Arc<signal_coverage::CoverageStore>>,
        service: Option<IngestService>,
        coverage_stopping: CancellationToken,
        shutdown_timeout: Option<Duration>,
    }
    impl StartupResources {
        async fn shutdown(&self, deadline: Instant) -> Result<(), AppError> {
            if let Some(service) = &self.service {
                service.stop_admission();
            }
            self.coverage_stopping.cancel();
            let mut outcome = Ok(());
            macro_rules! collect {
                ($result:expr) => {
                    if let Err(error) = $result {
                        if outcome.is_ok() {
                            outcome = Err(AppError::from(error));
                        }
                    }
                };
            }
            if let Some(identity) = &self.identity {
                collect!(identity.close());
            }
            if let Some(query) = &self.query {
                collect!(query.shutdown(io_context(deadline)).await);
            }
            if let Some(source) = &self.source {
                collect!(source.shutdown(io_context(deadline)).await);
            }
            for codec in [&self.publish_codec, &self.query_codec]
                .into_iter()
                .flatten()
            {
                collect!(codec.shutdown(io_context(deadline)).await);
            }
            if let Some(io) = &self.publish_io {
                collect!(
                    io.shutdown(io_context(deadline))
                        .await
                        .map_err(StorageError::ObjectIo)
                );
            }
            if let Some(io) = &self.query_io {
                collect!(
                    io.shutdown(io_context(deadline))
                        .await
                        .map_err(StorageError::ObjectIo)
                );
            }
            if let Some(io) = &self.custody_io {
                collect!(
                    io.shutdown(io_context(deadline))
                        .await
                        .map_err(StorageError::ObjectIo)
                );
            }
            // Construct one cleanup budget; every component is visited even if
            // an earlier component cannot finish within that original budget.
            let cleanup = ControlContext::new(Duration::from_secs(5))?.limited_to(deadline);
            if let Some(publisher) = &self.publisher {
                collect!(
                    publisher
                        .shutdown(cleanup.clone())
                        .await
                        .map_err(Error::from)
                );
            }
            if let Some(control) = &self.control {
                collect!(control.shutdown(cleanup.clone()).await);
            }
            if let Some(reader) = &self.reader {
                collect!(reader.shutdown(cleanup).await);
            }
            if let Some(wal) = &self.wal {
                match timeout_at(deadline, wal.shutdown()).await {
                    Ok(result) => collect!(result),
                    Err(_) => collect!(Err::<(), _>(Error::Held)),
                }
            }
            if let Some(coverage) = &self.coverage {
                collect!(
                    coverage
                        .shutdown(signal_coverage::OperationContext {
                            deadline,
                            cancellation: CancellationToken::new(),
                        })
                        .await
                );
            }
            if let Some(identity) = &self.identity {
                collect!(identity.shutdown(deadline).await);
            }
            outcome
        }
    }

    async fn prepare_until<T>(
        deadline: Instant,
        interruption: impl std::future::Future<Output = ()>,
        preparation: impl std::future::Future<Output = Result<T, AppError>>,
    ) -> Result<T, AppError> {
        if Instant::now() >= deadline {
            return Err(Error::Held.into());
        }
        let result = tokio::select! { biased;
            _ = interruption => Err(Error::Held.into()),
            _ = tokio::time::sleep_until(deadline) => Err(Error::Held.into()),
            result = preparation => result,
        };
        if result.is_ok() && Instant::now() >= deadline {
            return Err(Error::Held.into());
        }
        result
    }

    pub(crate) async fn run(settings: Settings, logger: &LoggerGuard) -> Result<(), AppError> {
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(AppError::Signal)?;
        #[cfg(unix)]
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(AppError::Signal)?;
        let stopping = CancellationToken::new();
        let _guard = stopping.clone().drop_guard();
        let startup =
            signal_collector_sdk::ExtensionContext::new(stopping.clone(), Duration::from_secs(60))
                .map_err(|_| Error::Held)?;
        let mut resources = StartupResources::default();
        let preparation = async {
            let audit = audit::Control::load(&settings, &startup).await?;
            let doc = standard_config::Document::load(&settings).await?;
            let mut cfg = runtime_config::load(&settings).await?;
            resources.identity = cfg.identity.clone();
            resources.shutdown_timeout = Some(cfg.limits.shutdown_timeout);
            if cfg.identity.is_none() || cfg.tls.is_none() || cfg.config.api_token.is_some() {
                return Err(crate::config::ConfigError::Invalid(
                    "Standard requires native identity and server TLS",
                )
                .into());
            }
            if cfg.rules.len() > cfg.max_finding_rows.min(128)
                || cfg.max_finding_rows == 0
                || cfg.max_finding_bytes == 0
            {
                return Err(crate::config::ConfigError::Invalid(
                    "Standard rule fanout exceeds atomic finding limits",
                )
                .into());
            }
            let backend = settings
                .optional("SIGNAL_S3_BACKEND_ID")?
                .ok_or(ControlError::Invalid)?;
            if backend != doc.backend_id.to_string() {
                return Err(ControlError::Fenced.into());
            }
            let mut revision = Vec::new();
            cfg.rules.write_revision(
                &mut revision,
                64 * 1024 * 1024,
                &signal_rules::RuleContext {
                    deadline: startup.deadline(),
                    cancellation: stopping.clone(),
                },
            )?;
            if let Some(window) = &cfg.window_configuration {
                std::io::Write::write_all(
                    &mut revision,
                    b"platform-signal/shared-window-rule/v1\0",
                )
                .map_err(|_| Error::Held)?;
                serde_json::to_writer(&mut revision, &window.policy)
                    .map_err(|_| ControlError::Invalid)?;
                if let Some(shared) = window.shared() {
                    let host = cfg.onboarding.as_ref().ok_or(ControlError::Fenced)?;
                    std::io::Write::write_all(
                        &mut revision,
                        &shared.source_binding(host.window_binding()),
                    )
                    .map_err(|_| Error::Held)?;
                }
            }
            if let Some(sensor) = &cfg.sensor_configuration {
                std::io::Write::write_all(
                    &mut revision,
                    b"platform-signal/shared-sensor-rule/v1\0",
                )
                .map_err(|_| Error::Held)?;
                serde_json::to_writer(&mut revision, &sensor.detector)
                    .map_err(|_| ControlError::Invalid)?;
                std::io::Write::write_all(
                    &mut revision,
                    &sensor.source_binding().map_err(AppError::from)?,
                )
                .map_err(|_| Error::Held)?;
            }
            let rule_revision: [u8; 32] = Sha256::digest(&revision).into();
            let mut writer = audit::HashWriter::new();
            std::io::Write::write_all(&mut writer, &revision).map_err(|_| Error::Held)?;
            let rule_hash = writer.finish();
            let runtime_revision = audit::runtime_revision(
                audit::RuntimeInputs {
                    ingest: &cfg.config,
                    server: &cfg.limits,
                    buffer: &cfg.wal_config,
                    storage: &cfg.storage_config,
                    query: &cfg.query_config,
                    findings: &cfg.finding_config,
                    rules: &cfg.rule_limits,
                    consumer: &cfg.consumer_config,
                    rule_timeout: Duration::from_millis(cfg.rule_timeout_ms as u64),
                    tls: true,
                    identity: true,
                    coverage: cfg.coverage_configuration.is_some(),
                    onboarding: cfg.onboarding.is_some(),
                    window: cfg.window_configuration.is_some(),
                    sensor_health: cfg.sensor_configuration.is_some(),
                    cases: false,
                    separate_metrics: cfg.metrics_listen.is_some(),
                },
                &startup,
            )?;
            let mut runtime_hash = audit::HashWriter::new();
            std::io::Write::write_all(
                &mut runtime_hash,
                b"platform-signal/standard-runtime-resource-revision/v1\0",
            )
            .map_err(|_| Error::Held)?;
            std::io::Write::write_all(&mut runtime_hash, runtime_revision.as_bytes())
                .map_err(|_| Error::Held)?;
            std::io::Write::write_all(&mut runtime_hash, &doc.revision).map_err(|_| Error::Held)?;
            let runtime_revision = runtime_hash.finish();
            let (control, reader) = doc.clients(&settings)?;
            resources.control = Some(control.clone());
            resources.reader = Some(reader.clone());
            if cfg.window_configuration.is_some() || cfg.sensor_configuration.is_some() {
                control
                    .verify_detector_producer_credentials(
                        doc.schema_owner.clone(),
                        doc.custody.is_some(),
                        doc.custody.as_ref().is_some_and(|c| c.restored_receipts),
                        signal_control::ProducerDetectors {
                            window: cfg.window_configuration.is_some(),
                            sensor_health: cfg.sensor_configuration.is_some(),
                        },
                        context(&stopping)?.limited_to(startup.deadline()),
                    )
                    .await?;
            } else if doc.custody.as_ref().is_some_and(|c| c.restored_receipts) {
                control
                    .verify_restored_custody_producer_credentials(
                        doc.schema_owner.clone(),
                        context(&stopping)?.limited_to(startup.deadline()),
                    )
                    .await?;
            } else if doc.custody.is_some() {
                control
                    .verify_custody_producer_credentials(
                        doc.schema_owner.clone(),
                        context(&stopping)?.limited_to(startup.deadline()),
                    )
                    .await?;
            } else {
                control
                    .verify_producer_credentials(
                        doc.schema_owner.clone(),
                        context(&stopping)?.limited_to(startup.deadline()),
                    )
                    .await?;
            }
            let (wal, wal_ready) =
                DurableBuffer::begin_open_with_recovery(cfg.wal_config, RECOVERY_BYTES)?;
            let wal = Arc::new(wal);
            resources.wal = Some(wal.clone());
            wal_ready.wait_until(startup.deadline()).await?;
            if wal.snapshot().stream_id != doc.scope.stream {
                return Err(ControlError::Fenced.into());
            }
            remote(&settings, &doc, &mut resources)?;
            let publish_codec = Arc::new(ObjectCodec::new(
                cfg.storage_config.clone(),
                ManifestLimits::default(),
            )?);
            resources.publish_codec = Some(publish_codec.clone());
            let publisher = Arc::new(
                SharedPublisher::with_workers(
                    control.clone(),
                    doc.scope.clone(),
                    doc.backend_id,
                    resources.publish_io.clone().ok_or(ControlError::Invalid)?,
                    publish_codec,
                    cfg.storage_config.clone(),
                    ManifestLimits::default(),
                )
                .map_err(Error::from)?,
            );
            resources.publisher = Some(publisher.clone());
            let recovery =
                Arc::new(SharedRecovery::new(publisher.clone(), wal.clone()).map_err(Error::from)?);
            let anchor = Instant::now();
            let token = control
                .acquire(
                    doc.scope.clone(),
                    Uuid::new_v4(),
                    doc.lease_ms,
                    context(&stopping)?.limited_to(startup.deadline()),
                )
                .await?;
            recovery
                .resume(
                    token.clone(),
                    context(&stopping)?.limited_to(startup.deadline()),
                )
                .await
                .map_err(Error::from)?;
            let original = reader
                .inspect_existing_finding_scope(
                    doc.scope.clone(),
                    doc.binding(),
                    context(&stopping)?.limited_to(startup.deadline()),
                )
                .await?;
            let admission = Arc::new(SharedAdmission::new(wal.clone(), original)?);
            let catalog = control
                .read_catalog_snapshot(
                    doc.scope.clone(),
                    CatalogInput {
                        schema_version: 1,
                        id: Uuid::new_v4(),
                        pin_ms: 5000,
                    },
                    context(&stopping)?.limited_to(startup.deadline()),
                )
                .await?;
            if catalog.backend()? != doc.backend_id
                || catalog.checkpoint()? != wal.snapshot().checkpoint
            {
                return Err(ControlError::Fenced.into());
            }
            let head = catalog.head()?;
            let window = match cfg.window_configuration.take() {
                Some(configuration) => Some(
                    crate::standard_window::Consumer::open(crate::standard_window::Startup {
                        configuration,
                        host: cfg.onboarding.clone().ok_or(ControlError::Fenced)?,
                        producer: admission.enrollment().clone(),
                        revision: rule_revision,
                        backend: doc.backend_id,
                        control: &control,
                        objects: resources.publish_io.as_ref().ok_or(ControlError::Invalid)?,
                        codec: resources
                            .publish_codec
                            .as_ref()
                            .ok_or(ControlError::Invalid)?,
                        token: token.clone(),
                        head,
                        wal_checkpoint: wal.snapshot().checkpoint,
                        context: context(&stopping)?.limited_to(startup.deadline()),
                    })
                    .await
                    .map_err(Error::from)?,
                ),
                None => None,
            };
            let sensor = match cfg.sensor_configuration.take() {
                Some(configuration) => Some(
                    crate::standard_sensor::Consumer::open(crate::standard_sensor::Startup {
                        configuration,
                        producer: admission.enrollment().clone(),
                        revision: rule_revision,
                        backend: doc.backend_id,
                        control: &control,
                        objects: resources.publish_io.as_ref().ok_or(ControlError::Invalid)?,
                        codec: resources
                            .publish_codec
                            .as_ref()
                            .ok_or(ControlError::Invalid)?,
                        token: token.clone(),
                        head,
                        wal: wal.snapshot(),
                        admission_floor: admission.admission_floor(),
                        context: context(&stopping)?.limited_to(startup.deadline()),
                    })
                    .await
                    .map_err(Error::from)?,
                ),
                None => None,
            };
            // Parse every fallible cache setting while the registry still owns
            // the raw query worker; argument evaluation must not consume it early.
            let selection_config = SelectionConfig {
                stream: doc.scope.stream,
                backend: doc.backend_id,
                storage: cfg.storage_config,
                manifests: ManifestLimits::default(),
                cache: MaterializationConfig {
                    directory: settings
                        .optional("SIGNAL_S3_CACHE_DIR")?
                        .ok_or(ControlError::Invalid)?
                        .into(),
                    max_files: settings.number("SIGNAL_S3_CACHE_FILES", 1024)?,
                    max_disk_bytes: settings.number("SIGNAL_S3_CACHE_BYTES", 1073741824)? as u64,
                },
            };
            selection_config.storage.validate()?;
            selection_config.cache.validate()?;
            selection_config
                .manifests
                .validate()
                .map_err(|_| ControlError::Invalid)?;
            let query_codec = Arc::new(ObjectCodec::new(
                selection_config.storage.clone(),
                selection_config.manifests,
            )?);
            resources.query_codec = Some(query_codec.clone());
            let selection = ObjectSelection::with_workers(
                resources.query_io.clone().ok_or(ControlError::Invalid)?,
                query_codec,
                tokio::runtime::Handle::current(),
                selection_config,
            )?;
            let source = Arc::new(SharedQuerySource::new(
                control.clone(),
                doc.scope.clone(),
                selection,
            )?);
            resources.source = Some(source.clone());
            let query = Arc::new(signal_query::QueryEngine::with_source(
                cfg.query_config,
                source.clone(),
            )?);
            resources.query = Some(query.clone());
            let coverage_stopping = resources.coverage_stopping.clone();
            let identity = cfg.identity.ok_or(ControlError::Invalid)?;
            let coverage = match cfg.coverage_configuration {
                Some(c) => {
                    let (state, ready) = c.begin_open_with_identity(
                        cfg.config.request_timeout,
                        coverage_stopping.clone(),
                        Some(identity.clone()),
                        audit.clone(),
                        signal_coverage::OperationContext {
                            deadline: startup.deadline(),
                            cancellation: stopping.child_token(),
                        },
                    )?;
                    resources.coverage = Some(state.store.clone());
                    ready.wait().await?;
                    Some(state)
                }
                None => None,
            };
            if let Some(state) = coverage.as_ref() {
                state.set_onboarding(cfg.onboarding.clone())?;
            }
            let sink = Arc::new(Sink {
                // Onboarding policy is fixed to this host runtime.
                admission,
                wal,
                control,
                reader,
                publisher,
                recovery,
                source,
                query: query.clone(),
                lease_deadline: Mutex::new(anchor + Duration::from_millis(u64::from(doc.lease_ms))),
                held: AtomicBool::new(false),
                audit: audit.clone(),
                coverage: coverage.as_ref().map(|c| c.store.clone()),
                evaluated: AtomicU64::new(0),
                matches: AtomicU64::new(0),
                failures: AtomicU64::new(0),
                logging: logger.writer(),
                window: window.as_ref().map(|w| w.health.clone()),
                sensor: sensor.as_ref().map(|s| s.health.clone()),
                loaded_rules: cfg.rules.len()
                    + usize::from(window.is_some())
                    + usize::from(sensor.is_some()),
            });
            let service = IngestService::new_with_security(
                cfg.config.clone(),
                sink.clone(),
                Some(identity.clone()),
                audit.as_ref().and_then(|a| a.ingest_auditor()),
            )?;
            resources.service = Some(service.clone());
            let feed = Arc::new(
                SharedFindingsFeed::new(
                    sink.reader.clone(),
                    doc.scope.store_id,
                    doc.scope.generation,
                    4,
                    cfg.finding_bytes.min(signal_control::REPLY_BYTES),
                )
                .map_err(Error::from)?,
            );
            let findings = Arc::new(
                SharedFindings::new(
                    sink.reader.clone(),
                    doc.binding(),
                    4,
                    cfg.finding_bytes.min(signal_control::REPLY_BYTES),
                )
                .map_err(|_| ControlError::Invalid)?,
            );
            let custody = doc
                .custody
                .as_ref()
                .map(|c| {
                    let objects = resources.custody_io.clone().ok_or(ControlError::Invalid)?;
                    let verifier = Arc::new(if c.restored_receipts {
                        signal_server::shared_custody::ConfiguredCustodyVerifier::new_restored(
                            c.binding(&doc),
                            objects,
                        )?
                    } else {
                        signal_server::shared_custody::ConfiguredCustodyVerifier::new(
                            c.binding(&doc),
                            objects,
                        )?
                    });
                    signal_server::shared_custody_api::CustodyApi::new(
                        sink.control.clone(),
                        token.clone(),
                        verifier,
                        identity.clone(),
                        stopping.clone(),
                    )
                })
                .transpose()?;
            let extras = Router::new()
                .route("/metrics/shared", get(shared_metrics))
                .with_state(MetricsState {
                    sink: sink.clone(),
                    findings: findings.clone(),
                    feed: feed.clone(),
                    custody: custody.clone(),
                });
            let mut router = service
                .router()
                .merge(query_api::router_with_identity(
                    query.clone(),
                    cfg.config.clone(),
                    cfg.query_limit,
                    cfg.query_timeout,
                    service.cancellation(),
                    Some(identity.clone()),
                    audit.clone(),
                ))
                .merge(finding_api::router_with_shared_findings(
                    findings,
                    feed,
                    cfg.config,
                    cfg.finding_limit.min(128),
                    cfg.finding_timeout,
                    service.cancellation(),
                    finding_api::Security {
                        identity: Some(identity.clone()),
                        audit: audit.clone(),
                    },
                )?)
                .merge(extras.clone())
                .merge(ui::router());
            if let Some(c) = &coverage {
                router = router.merge(c.router());
            }
            if let Some(api) = &custody {
                router = router.merge(api.router());
            }
            let listener = timeout_at(
                (Instant::now() + Duration::from_secs(5)).min(startup.deadline()),
                TcpListener::bind(cfg.listen),
            )
            .await
            .map_err(|_| AppError::BindTimeout)?
            .map_err(AppError::Bind)?;
            let metrics_listener = match cfg.metrics_listen {
                Some(a) => Some(
                    timeout_at(
                        (Instant::now() + Duration::from_secs(5)).min(startup.deadline()),
                        TcpListener::bind(a),
                    )
                    .await
                    .map_err(|_| AppError::BindTimeout)?
                    .map_err(AppError::Bind)?,
                ),
                None => None,
            };
            if let Some(a) = &audit {
                if a.selects_activation(signal_protocol::audit::ConfigurationKind::Runtime) {
                    a.activate(
                        signal_protocol::audit::ConfigurationKind::Runtime,
                        runtime_revision,
                        startup.clone(),
                    )
                    .await?;
                }
                if a.selects_activation(signal_protocol::audit::ConfigurationKind::Rules) {
                    a.activate(
                        signal_protocol::audit::ConfigurationKind::Rules,
                        rule_hash,
                        startup.clone(),
                    )
                    .await?;
                }
            }
            startup.check().map_err(|_| Error::Held)?;
            if !sink.live() {
                return Err(Error::Held.into());
            }
            let drain = CancellationToken::new();
            let cancel = CancellationToken::new();
            let failed = CancellationToken::new();
            let task_sink = sink.clone();
            let diagnostics = sink.clone();
            let task_failed = failed.clone();
            let consumer_input = Consumer {
                onboarding: cfg.onboarding.clone(),
                window,
                sensor,
                sink: task_sink,
                token,
                head,
                rules: cfg.rules,
                revision: rule_revision,
                cfg: cfg.consumer_config,
                lease_ms: doc.lease_ms,
                drain: drain.clone(),
                cancel: cancel.clone(),
                failed: task_failed,
                finding_rows: cfg.max_finding_rows.min(128),
                finding_bytes_limit: cfg.max_finding_bytes.min(1024 * 1024),
            };
            Ok::<_, AppError>((
                consumer_input,
                diagnostics,
                sink,
                service,
                router,
                extras,
                listener,
                metrics_listener,
                query,
                identity,
                coverage,
                coverage_stopping,
                drain,
                cancel,
                failed,
                cfg.limits,
                cfg.tls,
            ))
        };
        #[cfg(unix)]
        let interruption = async {
            tokio::select! { biased;
                _ = terminate.recv() => (),
                _ = interrupt.recv() => (),
            }
        };
        #[cfg(not(unix))]
        let interruption = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        let prepared = prepare_until(startup.deadline(), interruption, preparation).await;
        let (
            consumer_input,
            diagnostics,
            sink,
            service,
            router,
            extras,
            listener,
            metrics_listener,
            query,
            identity,
            coverage,
            coverage_stopping,
            drain,
            cancel,
            failed,
            limits,
            tls,
        ) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                stopping.cancel();
                let deadline = Instant::now()
                    + resources
                        .shutdown_timeout
                        .unwrap_or(Duration::from_secs(10));
                match resources.shutdown(deadline).await {
                    Ok(()) => tracing::info!(target: "signal_shared",
                        "Standard startup resources drained"),
                    Err(cleanup) => tracing::error!(target: "signal_shared", error = %cleanup,
                        "Standard startup resource cleanup failed"),
                }
                return Err(error);
            }
        };
        let mut consumer = tokio::spawn(async move {
            let result = consume(consumer_input).await;
            if let Err(error) = &result {
                diagnostics.failures.fetch_add(1, Ordering::Relaxed);
                // AppError contains typed static context, never credentials or event data.
                tracing::error!(target: "signal_shared", error = %error, "Standard consumer stopped");
            }
            result
        });
        let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
        let transport = async {
            let api = server::serve_router_with_tls_budget(
                listener,
                service.clone(),
                router,
                limits,
                permits.clone(),
                tls.clone(),
                std::future::pending::<()>(),
            );
            if let Some(listener) = metrics_listener {
                let metrics = server::serve_router_with_tls_budget(
                    listener,
                    service.clone(),
                    service.metrics_router().merge(extras),
                    limits,
                    permits,
                    tls,
                    std::future::pending::<()>(),
                );
                let (a, m) = tokio::join!(api, metrics);
                a.and(m)
            } else {
                api.await
            }
        };
        tokio::pin!(transport);
        #[cfg(unix)]
        let finished = tokio::select! {biased;_=terminate.recv()=>None,_=interrupt.recv()=>None,_=failed.cancelled()=>None,result=&mut transport=>Some(result)};
        #[cfg(not(unix))]
        let finished = tokio::select! {biased;_=tokio::signal::ctrl_c()=>None,_=failed.cancelled()=>None,result=&mut transport=>Some(result)};
        let deadline = Instant::now() + limits.shutdown_timeout;
        service.stop_admission();
        let identity_closed = identity.close();
        coverage_stopping.cancel();
        drain.cancel();
        let transport_result = match finished {
            Some(r) => r,
            None => timeout_at(deadline, &mut transport)
                .await
                .unwrap_or(Err(server::ServerError::ShutdownTimeout)),
        };
        let consumed = match timeout_at(deadline, &mut consumer).await {
            Ok(r) => r
                .map_err(|_| Error::Task)
                .and_then(|r| r.map_err(|_| Error::Held)),
            Err(_) => {
                cancel.cancel();
                consumer.abort();
                let _ = consumer.await;
                Err(Error::Held)
            }
        };
        // Every physical resource gets the same cleanup deadline, even after a failure.
        let queried = query.shutdown(io_context(deadline)).await;
        let selected = sink.source.shutdown(io_context(deadline)).await;
        let published = sink
            .publisher
            .shutdown(ControlContext::new(Duration::from_secs(5))?.limited_to(deadline))
            .await;
        let control_stopped = sink
            .control
            .shutdown(ControlContext::new(Duration::from_secs(5))?.limited_to(deadline))
            .await;
        let reader_stopped = sink
            .reader
            .shutdown(ControlContext::new(Duration::from_secs(5))?.limited_to(deadline))
            .await;
        let wal_stopped = timeout_at(deadline, sink.wal.shutdown()).await;
        let coverage_stopped = match coverage {
            Some(c) => c
                .store
                .shutdown(signal_coverage::OperationContext {
                    deadline,
                    cancellation: CancellationToken::new(),
                })
                .await
                .map_err(AppError::from),
            None => Ok(()),
        };
        let identity_stopped = identity.shutdown(deadline).await;
        transport_result?;
        consumed?;
        queried?;
        selected?;
        published.map_err(Error::from)?;
        control_stopped?;
        reader_stopped?;
        wal_stopped.map_err(|_| Error::Held)??;
        coverage_stopped?;
        identity_closed?;
        identity_stopped?;
        Ok(())
    }
    #[cfg(test)]
    mod startup_deadline_tests {
        use super::*;
        #[tokio::test]
        async fn preparation_steps_share_one_original_deadline() {
            let finished = Arc::new(AtomicBool::new(false));
            let observed = finished.clone();
            let deadline = Instant::now() + Duration::from_millis(20);
            let preparation = async {
                tokio::task::yield_now().await;
                // A later step cannot receive a fresh budget past the host clock.
                tokio::time::sleep_until(deadline + Duration::from_millis(20)).await;
                observed.store(true, Ordering::Release);
                Ok::<_, AppError>(())
            };
            assert!(matches!(
                prepare_until(deadline, std::future::pending(), preparation).await,
                Err(AppError::Shared(Error::Held))
            ));
            assert!(!finished.load(Ordering::Acquire));
        }
        #[tokio::test]
        async fn expired_startup_cannot_accept_an_immediately_ready_preparation() {
            assert!(matches!(
                prepare_until(
                    Instant::now(),
                    std::future::pending(),
                    std::future::ready(Ok::<_, AppError>(()))
                )
                .await,
                Err(AppError::Shared(Error::Held))
            ));
            assert!(
                prepare_until(
                    Instant::now() + Duration::from_secs(1),
                    std::future::pending(),
                    std::future::ready(Ok::<_, AppError>(()))
                )
                .await
                .is_ok()
            );
        }
    }
}

#[cfg(all(test, not(feature = "s3-query")))]
mod unsupported_tests {
    use super::*;
    #[tokio::test]
    async fn explicit_standard_never_falls_back_in_a_default_build()
    -> Result<(), Box<dyn std::error::Error>> {
        let settings = Settings::for_test(
            "schema_version: 1\nshared: {config: '/nonexistent/private.json'}",
            &[],
        )?;
        let logger = LoggerGuard::stderr(crate::logging::LoggingConfig {
            queue_records: 2,
            queue_bytes: 4096,
            max_record_bytes: 1024,
        })?;
        let result = run(settings, &logger).await;
        logger
            .shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await?;
        assert!(matches!(
            result,
            Err(AppError::Settings(crate::config::ConfigError::Invalid(
                "Standard requires s3-query build feature"
            )))
        ));
        Ok(())
    }
}

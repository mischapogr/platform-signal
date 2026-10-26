use super::*;
use crate::contracts::{NodeSourceIdentity, NodeTermination};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use signal_collector_sdk::kubernetes_log::{self, Profile};
use signal_event::{SCHEMA_VERSION, Severity, SignalEvent, Source};
use std::{fs::File, os::unix::fs::FileExt};
use uuid::Uuid;

struct Slot {
    position: SourceCheckpoint,
    file: Option<File>,
    partial: Vec<u8>,
    oversized: bool,
    eof: bool,
    read_limit: Option<u64>,
    unavailable: Option<(NodeTermination, &'static str)>,
}
impl Slot {
    fn terminal(&self) -> bool {
        self.position
            .source_identity
            .as_ref()
            .is_some_and(|s| s.terminal.is_some())
    }
}
struct Pending {
    slot: usize,
    record: InputRecord,
}
pub(super) struct State {
    config: Config,
    root: node_root::Root,
    profile: CursorProfile,
    native: Profile,
    slots: Vec<Option<Slot>>,
    pending: Option<Pending>,
    restored: bool,
    scan_at: Option<Instant>,
    scan_valid: bool,
    once_snapshot: Option<node_root::Snapshot>,
    next: usize,
    counters: Arc<Counters>,
}
impl State {
    pub fn new(
        config: Config,
        root: node_root::Root,
        profile: CursorProfile,
        counters: Arc<Counters>,
    ) -> Result<Self, Error> {
        let native =
            Profile::new(&config.cluster, &config.node).map_err(|_| Error::Configuration)?;
        Ok(Self {
            config,
            root,
            profile,
            native,
            slots: (0..16).map(|_| None).collect(),
            pending: None,
            restored: false,
            scan_at: None,
            scan_valid: false,
            once_snapshot: None,
            next: 0,
            counters,
        })
    }
    pub fn restore(&mut self, cursors: Vec<SourceCheckpoint>) -> Result<(), Error> {
        if self.restored || cursors.len() > 16 {
            return Err(Error::Cursor);
        }
        let mut seen = [false; 16];
        for c in &cursors {
            self.profile.checkpoint(c).map_err(|_| Error::Cursor)?;
            if c.anchor.len() as u64 != c.offset.min(64)
                || std::mem::replace(&mut seen[c.input as usize], true)
            {
                return Err(Error::Cursor);
            }
            if c.source_identity
                .as_ref()
                .is_some_and(|s| s.terminal.is_none())
                && cursors.iter().any(|o| {
                    o.input != c.input
                        && o.device == c.device
                        && o.inode == c.inode
                        && o.source_identity
                            .as_ref()
                            .zip(c.source_identity.as_ref())
                            .is_some_and(|(a, b)| a.terminal.is_none() && a.source == b.source)
                })
            {
                return Err(Error::Cursor);
            }
        }
        for c in cursors {
            let i = c.input as usize;
            self.slots[i] = Some(Slot {
                position: c,
                file: None,
                partial: Vec::new(),
                oversized: false,
                eof: false,
                read_limit: None,
                unavailable: None,
            });
        }
        self.restored = true;
        Ok(())
    }
    fn scan(&mut self, context: &Context) -> Result<(), Error> {
        context.check()?;
        self.scan_valid = false;
        self.scan_at = Some(Instant::now());
        let snapshot = if !self.config.follow && self.once_snapshot.is_some() {
            self.once_snapshot.as_ref().ok_or(Error::Cursor)?.clone()
        } else {
            let s = self.root.scan_namespace(self.config.namespace.as_deref())?;
            if !self.config.follow {
                self.once_snapshot = Some(s.clone());
            }
            s
        };
        context.check()?;
        self.counters.scans.fetch_add(1, Ordering::Relaxed);
        self.counters
            .scan_entries
            .store(snapshot.metrics.examined, Ordering::Relaxed);
        self.counters
            .scan_active
            .store(snapshot.active.len(), Ordering::Relaxed);
        self.counters
            .scan_rotated
            .store(snapshot.rotated.len(), Ordering::Relaxed);
        for slot in self.slots.iter_mut().flatten().filter(|s| !s.terminal()) {
            context.check()?;
            let source = slot
                .position
                .source_identity
                .as_ref()
                .ok_or(Error::Cursor)?
                .source
                .clone();
            let matches: Vec<_> = snapshot
                .active
                .iter()
                .chain(snapshot.rotated.iter())
                .filter(|c| {
                    c.source == source
                        && c.device == slot.position.device
                        && c.inode == slot.position.inode
                })
                .collect();
            if matches.len() > 1 {
                slot.unavailable =
                    Some((NodeTermination::UncertainRotation, "ambiguous_generation"));
                continue;
            }
            if let Some(c) = matches.first() {
                if c.compressed {
                    slot.unavailable = Some((
                        NodeTermination::CompressedGeneration,
                        "compressed_generation",
                    ));
                    continue;
                }
                if slot.file.is_none() {
                    let file = self.root.open_candidate(c)?;
                    context.check()?;
                    if file.metadata()?.len() < slot.position.offset
                        || anchor(&file, slot.position.offset)? != slot.position.anchor
                    {
                        slot.unavailable =
                            Some((NodeTermination::UncertainRotation, "changed_anchor"));
                        continue;
                    }
                    slot.file = Some(file);
                    if !self.config.follow {
                        slot.read_limit = Some(c.length);
                    }
                }
                if let Some(identity) = &mut slot.position.source_identity {
                    identity.file_name = c.file_name.clone();
                }
                // A rotated old writer may still append. Drain its held FD first;
                // transition records explicit uncertainty instead of claiming EOF
                // proves that writer closed.
                slot.unavailable = if snapshot
                    .active
                    .iter()
                    .any(|a| a.source == source && (a.device != c.device || a.inode != c.inode))
                    || c.file_name != format!("{}.log", source.restart_count)
                {
                    Some((NodeTermination::UncertainRotation, "rotation_observed"))
                } else {
                    None
                };
            } else {
                slot.unavailable = Some(
                    if snapshot
                        .rotated
                        .iter()
                        .any(|c| c.source == source && c.compressed)
                    {
                        (
                            NodeTermination::CompressedGeneration,
                            "compressed_generation",
                        )
                    } else {
                        (NodeTermination::MissingGeneration, "missing_generation")
                    },
                );
            }
        }
        // A terminal marker for an unchanged still-present file must retain its
        // slot. Otherwise repeated once-runs or slot reuse would reingest the
        // same unterminated prefix and mint endless new gap IDs.
        let mut blocked_terminal = [false; 16];
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else {
                continue;
            };
            if !slot.terminal() {
                continue;
            }
            let source = &slot
                .position
                .source_identity
                .as_ref()
                .ok_or(Error::Cursor)?
                .source;
            if let Some(candidate) = snapshot.active.iter().find(|c| {
                c.source == *source
                    && c.device == slot.position.device
                    && c.inode == slot.position.inode
                    && c.length == slot.position.offset
            }) {
                context.check()?;
                let file = self.root.open_candidate(candidate)?;
                blocked_terminal[index] =
                    anchor(&file, slot.position.offset)? == slot.position.anchor;
            }
        }
        for candidate in &snapshot.active {
            context.check()?;
            if self.slots.iter().enumerate().any(|(i, s)| {
                blocked_terminal[i]
                    && s.as_ref().is_some_and(|s| {
                        s.position.device == candidate.device
                            && s.position.inode == candidate.inode
                            && s.position
                                .source_identity
                                .as_ref()
                                .is_some_and(|identity| identity.source == candidate.source)
                    })
            }) {
                continue;
            }

            if self.slots.iter().flatten().any(|s| {
                !s.terminal()
                    && s.position.device == candidate.device
                    && s.position.inode == candidate.inode
                    && s.position
                        .source_identity
                        .as_ref()
                        .is_some_and(|i| i.source == candidate.source)
            }) {
                continue;
            }
            // A terminal decision for an older generation must be durable before
            // replacing its slot or reading the new logical generation.
            if self.slots.iter().flatten().any(|s| {
                !s.terminal()
                    && s.position
                        .source_identity
                        .as_ref()
                        .is_some_and(|i| i.source == candidate.source)
            }) {
                continue;
            }
            let Some(index) = self.slots.iter().enumerate().position(|(i, s)| {
                s.as_ref().is_none()
                    || (s.as_ref().is_some_and(Slot::terminal) && !blocked_terminal[i])
            }) else {
                self.counters
                    .admission_refusals
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let file = self.root.open_candidate(candidate)?;
            context.check()?;
            self.slots[index] = Some(Slot {
                position: SourceCheckpoint {
                    input: index as u16,
                    device: candidate.device,
                    inode: candidate.inode,
                    offset: 0,
                    anchor: vec![],
                    source_binding: self.profile.binding(),
                    source_identity: Some(NodeSourceIdentity {
                        schema_version: 1,
                        source: candidate.source.clone(),
                        file_name: candidate.file_name.clone(),
                        terminal: None,
                    }),
                },
                file: Some(file),
                partial: Vec::new(),
                oversized: false,
                eof: false,
                read_limit: if self.config.follow {
                    None
                } else {
                    Some(candidate.length)
                },
                unavailable: None,
            });
        }
        self.scan_at = Some(Instant::now());
        self.scan_valid = true;
        Ok(())
    }
    fn gap(
        &mut self,
        index: usize,
        terminal: NodeTermination,
        reason: &'static str,
    ) -> Result<ReadOutcome, Error> {
        let slot = self.slots[index].as_ref().ok_or(Error::Cursor)?;
        let mut cursor = slot.position.clone();
        let identity = cursor.source_identity.as_mut().ok_or(Error::Cursor)?;
        identity.terminal = Some(terminal);
        let source = &identity.source;
        let attributes=serde_json::json!({"kubernetes":{"schema_version":1,"cluster_id":self.config.cluster,"node_name":self.config.node,"namespace":source.namespace,"pod":{"name":source.pod_name,"runtime_uid":source.runtime_pod_uid},"container":{"name":source.container,"restart_count":source.restart_count}},"collection":{"schema_version":1,"status":"gap","reason":reason,"previous_offset":cursor.offset,"device":cursor.device,"inode":cursor.inode,"partial_prefix_base64":if slot.partial.is_empty(){None}else{Some(STANDARD.encode(&slot.partial))},"oversized_partial":slot.oversized}}).as_object().ok_or(Error::Cursor)?.clone();
        let now = Utc::now();
        let event = SignalEvent {
            schema_version: SCHEMA_VERSION,
            id: Uuid::new_v4(),
            timestamp: now,
            observed_at: now,
            source: Source {
                source_type: "kubernetes.collector".into(),
                name: Some(self.config.cluster.clone()),
            },
            severity: Severity::Warn,
            message: Some("Kubernetes log generation continuity is unknown".into()),
            attributes,
            resource: None,
            trace_id: None,
            span_id: None,
            tags: vec![],
        };
        let rejected = u64::from(!slot.partial.is_empty() || slot.oversized);
        self.counters.gaps.fetch_add(1, Ordering::Relaxed);
        self.counters
            .rejected
            .fetch_add(rejected, Ordering::Relaxed);
        let record = InputRecord {
            event: Some(event),
            checkpoint: Some(cursor),
            rejected,
        };
        self.pending = Some(Pending {
            slot: index,
            record: record.clone(),
        });
        Ok(ReadOutcome::Record(Box::new(record)))
    }
    pub fn read(&mut self, context: &Context) -> Result<ReadOutcome, Error> {
        if !self.restored {
            return Err(Error::Cursor);
        }
        if let Some(p) = &self.pending {
            return Ok(ReadOutcome::Record(Box::new(p.record.clone())));
        }
        if (self.scan_at.is_none()
            || (self.config.follow
                && self.scan_at.is_some_and(|at| {
                    Instant::now().duration_since(at) >= self.config.scan_interval
                })))
            && let Err(error) = self.scan(context)
        {
            self.counters.scan_refusals.fetch_add(1, Ordering::Relaxed);
            match &error {
                Error::Root(node_root::Error::Changed) => {}
                Error::Root(node_root::Error::Io(io))
                    if io.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(error),
            }
            if !self.config.follow {
                return Err(error);
            }
            return Ok(ReadOutcome::Idle);
        }
        if !self.scan_valid {
            return Ok(ReadOutcome::Idle);
        }
        for _ in 0..16 {
            context.check()?;
            let index = self.next;
            self.next = (self.next + 1) % 16;
            let Some(slot) = self.slots[index].as_mut() else {
                continue;
            };
            if slot.terminal() {
                continue;
            }
            if let Some(file) = &slot.file {
                if file.metadata()?.len() < slot.position.offset
                    || anchor(file, slot.position.offset)? != slot.position.anchor
                {
                    return self.gap(index, NodeTermination::UncertainRotation, "changed_anchor");
                }
                let mut buffer = [0; 4096];
                context.check()?;
                let capacity = slot.read_limit.map_or(buffer.len(), |limit| {
                    limit
                        .saturating_sub(slot.position.offset)
                        .min(buffer.len() as u64) as usize
                });
                let n = if capacity == 0 {
                    0
                } else {
                    file.read_at(&mut buffer[..capacity], slot.position.offset)?
                };
                if n > 0 {
                    slot.eof = false;
                    for (consumed, byte) in buffer[..n].iter().enumerate() {
                        slot.position.offset =
                            slot.position.offset.checked_add(1).ok_or(Error::Cursor)?;
                        if slot.partial.len() < self.config.max_line_bytes {
                            slot.partial.push(*byte);
                        } else {
                            slot.oversized = true;
                        }
                        if *byte == b'\n' {
                            extend_anchor(&mut slot.position.anchor, &buffer[..consumed + 1]);
                            let source = &slot
                                .position
                                .source_identity
                                .as_ref()
                                .ok_or(Error::Cursor)?
                                .source;
                            let event = if slot.oversized {
                                None
                            } else {
                                kubernetes_log::normalize_record(
                                    &slot.partial,
                                    &self.native,
                                    source,
                                    Uuid::new_v4(),
                                    Utc::now(),
                                )
                                .ok()
                            };
                            let rejected = u64::from(event.is_none());
                            self.counters
                                .rejected
                                .fetch_add(rejected, Ordering::Relaxed);
                            slot.partial.clear();
                            slot.oversized = false;
                            let record = InputRecord {
                                event,
                                checkpoint: Some(slot.position.clone()),
                                rejected,
                            };
                            self.pending = Some(Pending {
                                slot: index,
                                record: record.clone(),
                            });
                            return Ok(ReadOutcome::Record(Box::new(record)));
                        }
                    }
                    extend_anchor(&mut slot.position.anchor, &buffer[..n]);
                } else {
                    slot.eof = true;
                }
            } else {
                slot.eof = true;
            }
            if slot.eof {
                if let Some((terminal, reason)) = slot.unavailable {
                    return self.gap(index, terminal, reason);
                }
                if !self.config.follow && (!slot.partial.is_empty() || slot.oversized) {
                    return self.gap(
                        index,
                        NodeTermination::UncertainRotation,
                        "unterminated_physical_record",
                    );
                }
            }
        }
        if !self.config.follow && self.slots.iter().flatten().all(|s| s.terminal() || s.eof) {
            Ok(ReadOutcome::End)
        } else {
            Ok(ReadOutcome::Idle)
        }
    }
    pub fn commit(&mut self) -> Result<(), Error> {
        let pending = self.pending.take().ok_or(Error::Cursor)?;
        let slot = self.slots[pending.slot].as_mut().ok_or(Error::Cursor)?;
        slot.position = pending.record.checkpoint.ok_or(Error::Cursor)?;
        if slot.terminal() {
            slot.file = None;
            slot.partial.clear();
            slot.oversized = false;
            slot.unavailable = None;
            self.scan_at = None;
            self.scan_valid = false;
        }
        Ok(())
    }
    pub fn metrics(&self) {
        self.counters.slots.store(
            self.slots
                .iter()
                .flatten()
                .filter(|s| !s.terminal())
                .count(),
            Ordering::Relaxed,
        );
        self.counters.fds.store(
            self.slots
                .iter()
                .flatten()
                .filter(|s| s.file.is_some())
                .count(),
            Ordering::Relaxed,
        );
        self.counters.buffered.store(
            self.slots.iter().flatten().map(|s| s.partial.len()).sum(),
            Ordering::Relaxed,
        );
        self.counters
            .pending
            .store(usize::from(self.pending.is_some()), Ordering::Relaxed);
    }
}
// Build the witness from bytes actually consumed. Re-reading it from the file
// after I/O could accidentally adopt a concurrent copy-truncate's replacement
// prefix and let restart skip bytes that this reader never admitted.
fn extend_anchor(previous: &mut Vec<u8>, consumed: &[u8]) {
    if consumed.len() >= 64 {
        previous.clear();
        previous.extend_from_slice(&consumed[consumed.len() - 64..]);
    } else {
        let excess = previous
            .len()
            .saturating_add(consumed.len())
            .saturating_sub(64);
        previous.drain(..excess);
        previous.extend_from_slice(consumed);
    }
}

fn anchor(file: &File, offset: u64) -> Result<Vec<u8>, Error> {
    let n = offset.min(64) as usize;
    let mut bytes = vec![0; n];
    let mut read = 0;
    while read < n {
        let count = file.read_at(&mut bytes[read..], offset - n as u64 + read as u64)?;
        if count == 0 {
            return Err(Error::Cursor);
        }
        read += count;
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

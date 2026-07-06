//! Volatile bootstrap sink. Admission is count/encoded-byte bounded and cancellation-safe.
use crate::ConfigError;
use signal_event::SignalEvent;
use signal_protocol::{AdmissionError, AdmissionFuture, EventSink, SinkMetrics};
use std::{collections::VecDeque, io, sync::Mutex};

struct State {
    queue: VecDeque<(SignalEvent, usize)>,
    metrics: SinkMetrics,
}

pub struct MemorySink {
    state: Mutex<State>,
    byte_capacity: usize,
}

impl MemorySink {
    pub fn new(capacity: usize, byte_capacity: usize) -> Result<Self, ConfigError> {
        if capacity == 0 || byte_capacity == 0 {
            return Err(ConfigError::Invalid("queue capacities must be positive"));
        }
        Ok(Self {
            byte_capacity,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                metrics: SinkMetrics {
                    capacity,
                    byte_capacity,
                    ..SinkMetrics::default()
                },
            }),
        })
    }

    /// Remove one retained event, freeing both capacity budgets. No automatic consumer.
    pub fn take(&self) -> Result<Option<SignalEvent>, AdmissionError> {
        let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        let Some((event, bytes)) = state.queue.pop_front() else {
            return Ok(None);
        };
        state.metrics.depth -= 1;
        state.metrics.bytes -= bytes;
        Ok(Some(event))
    }

    /// Explicitly discard retained volatile events at process shutdown and count loss.
    pub fn discard_pending(&self) -> Result<usize, AdmissionError> {
        let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        if !state.metrics.closed {
            return Err(AdmissionError::Unavailable);
        }
        let count = state.queue.len();
        state.queue.clear();
        state.metrics.depth = 0;
        state.metrics.bytes = 0;
        state.metrics.dropped += count as u64;
        Ok(count)
    }
}

impl EventSink for MemorySink {
    fn admit(&self, event: SignalEvent) -> AdmissionFuture<'_> {
        Box::pin(async move {
            // Count encoded bytes without allocating a duplicate event-sized buffer.
            let mut counter = ByteCounter {
                bytes: 0,
                limit: self.byte_capacity,
                exceeded: false,
            };
            let encoded = if event.validate().is_err() {
                Err(AdmissionError::Unavailable)
            } else if serde_json::to_writer(&mut counter, &event).is_err() {
                Err(if counter.exceeded {
                    AdmissionError::Full
                } else {
                    AdmissionError::Unavailable
                })
            } else {
                Ok(counter.bytes)
            };
            let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
            if state.metrics.closed {
                state.metrics.rejected += 1;
                return Err(AdmissionError::Closed);
            }
            let bytes = match encoded {
                Ok(bytes) => bytes,
                Err(error) => {
                    state.metrics.rejected += 1;
                    return Err(error);
                }
            };
            if state.metrics.depth >= state.metrics.capacity
                || bytes > state.metrics.byte_capacity - state.metrics.bytes
            {
                state.metrics.rejected += 1;
                return Err(AdmissionError::Full);
            }
            // This commit has no await points; dropping the future never detaches admission.
            state.queue.push_back((event, bytes));
            state.metrics.depth += 1;
            state.metrics.bytes += bytes;
            state.metrics.accepted += 1;
            Ok(())
        })
    }

    fn metrics(&self) -> SinkMetrics {
        match self.state.lock() {
            Ok(state) => state.metrics,
            Err(_) => SinkMetrics {
                closed: true,
                ..SinkMetrics::default()
            },
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.metrics.closed = true;
        }
    }
}

struct ByteCounter {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}
impl io::Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit - self.bytes {
            self.exceeded = true;
            return Err(io::Error::other("encoded event capacity exceeded"));
        }
        self.bytes += buffer.len();
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

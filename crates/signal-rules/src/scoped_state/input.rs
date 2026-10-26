use super::*;
use crate::RuleContext;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;
use std::io::Write;

pub struct Input<'a> {
    pub(crate) event: &'a SignalEvent,
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: [u8; 32],
}

struct Budget {
    bytes: usize,
    nodes: usize,
}
impl Budget {
    fn text(&mut self, value: &str) -> Result<(), Error> {
        self.bytes = self.bytes.checked_sub(value.len()).ok_or(Error::Capacity)?;
        Ok(())
    }
    fn value(&mut self, value: &Value, depth: usize, context: &RuleContext) -> Result<(), Error> {
        check(context)?;
        self.nodes = self.nodes.checked_sub(1).ok_or(Error::Capacity)?;
        if depth > 32 {
            return Err(Error::Capacity);
        }
        match value {
            Value::Number(_) => {
                // serde_json emits Number by reference through write_number_str;
                // the capped writer rejects a huge arbitrary-precision lexeme
                // before copying/parsing it. Do not call Number::to_string here.
                let bytes = encode(value, 64, context)?;
                self.bytes = self.bytes.checked_sub(bytes.len()).ok_or(Error::Capacity)?;
            }
            Value::String(s) => self.text(s)?,
            Value::Array(values) => {
                if values.len() > self.nodes {
                    return Err(Error::Capacity);
                }
                for value in values {
                    self.value(value, depth + 1, context)?;
                }
            }
            Value::Object(values) => {
                if values.len() > self.nodes {
                    return Err(Error::Capacity);
                }
                for (key, value) in values {
                    self.text(key)?;
                    self.value(value, depth + 1, context)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
}

pub(crate) struct Writer<'a> {
    pub bytes: Vec<u8>,
    pub limit: usize,
    pub context: &'a RuleContext,
}
impl Write for Writer<'_> {
    fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
        check(self.context).map_err(std::io::Error::other)?;
        if value.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("scoped state byte budget"));
        }
        self.bytes.extend_from_slice(value);
        Ok(value.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(
    value: &impl Serialize,
    limit: usize,
    context: &RuleContext,
) -> Result<Vec<u8>, Error> {
    check(context)?;
    let mut writer = Writer {
        bytes: Vec::new(),
        limit,
        context,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| Error::Capacity)?;
    check(context)?;
    Ok(writer.bytes)
}
impl<'a> Input<'a> {
    /// Bound before validation, traversal, allocation or hashing. Exact serialized
    /// input bytes are retained for replay; reordered bytes are a distinct input.
    pub fn new(event: &'a SignalEvent, context: &RuleContext) -> Result<Self, Error> {
        check(context)?;
        if event.tags.len() > 256 || event.attributes.len() > 16384 {
            return Err(Error::Capacity);
        }
        let mut budget = Budget {
            bytes: MAX_INPUT_BYTES,
            nodes: 16384,
        };
        budget.text(&event.source.source_type)?;
        for value in [
            event.source.name.as_deref(),
            event.message.as_deref(),
            event.trace_id.as_deref(),
            event.span_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            budget.text(value)?;
        }
        if let Some(resource) = &event.resource {
            for value in [&resource.kind, &resource.id] {
                budget.text(value)?;
            }
            for value in [resource.account_id.as_deref(), resource.region.as_deref()]
                .into_iter()
                .flatten()
            {
                budget.text(value)?;
            }
        }
        for tag in &event.tags {
            check(context)?;
            budget.text(tag)?;
        }
        for (key, value) in &event.attributes {
            budget.text(key)?;
            budget.value(value, 0, context)?;
        }
        event.validate().map_err(|_| Error::Invalid)?;
        let bytes = encode(event, MAX_INPUT_BYTES, context)?;
        let mut hash = Sha256::new();
        hash.update(b"PLATFORM::SIGNAL/scoped-state/input/v1\0");
        hash.update(&bytes);
        check(context)?;
        Ok(Self {
            event,
            bytes,
            sha256: hash.finalize().into(),
        })
    }
    pub fn event(&self) -> &SignalEvent {
        self.event
    }
    pub fn original_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

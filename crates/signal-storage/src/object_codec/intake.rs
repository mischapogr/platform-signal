//! Borrowed prequeue validation. Invalid caller-owned trees are never transferred
//! or recursively dropped by the worker. Only finite canonical wire is admitted.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
const DEPTH: usize = 32;
const NODES: usize = 65536;
#[derive(Serialize)]
struct Row<'a> {
    sequence: u64,
    event: &'a signal_event::SignalEvent,
}
#[derive(Serialize)]
struct Wire<'a> {
    schema_version: u16,
    rows: Vec<Row<'a>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedWire {
    schema_version: u16,
    rows: Vec<OwnedRow>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRow {
    sequence: u64,
    event: signal_event::SignalEvent,
}
struct Writer<'a> {
    bytes: Vec<u8>,
    limit: usize,
    context: &'a OperationContext,
}
impl Write for Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        check_context(Some(self.context)).map_err(|_| std::io::Error::other("input context"))?;
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("input capacity"));
        }
        if self.bytes.capacity() - self.bytes.len() < bytes.len() {
            self.bytes
                .try_reserve_exact(bytes.len())
                .map_err(|_| std::io::Error::other("input allocation"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn walk(
    rows: &[StoredEvent],
    config: &StorageConfig,
    context: &OperationContext,
) -> Result<(), StorageError> {
    let mut count = rows.len();
    if count > NODES {
        return Err(StorageError::Full);
    }
    let mut stack = Vec::with_capacity(64);
    let string = |value: &str| {
        if value.len() > config.max_event_bytes {
            Err(StorageError::Full)
        } else {
            Ok(())
        }
    };
    for row in rows {
        check_context(Some(context))?;
        let e = &row.event;
        string(&e.source.source_type)?;
        for field in [&e.source.name, &e.message, &e.trace_id, &e.span_id]
            .into_iter()
            .flatten()
        {
            string(field)?;
        }
        if let Some(r) = &e.resource {
            string(&r.kind)?;
            string(&r.id)?;
            for field in [&r.account_id, &r.region].into_iter().flatten() {
                string(field)?;
            }
        }
        if e.tags.len() > NODES.saturating_sub(count)
            || e.attributes.len() > NODES.saturating_sub(count)
        {
            return Err(StorageError::Full);
        }
        count += e.tags.len();
        for tag in &e.tags {
            check_context(Some(context))?;
            string(tag)?;
        }
        for (key, value) in &e.attributes {
            string(key)?;
            stack.push((value, 1usize));
        }
        while let Some((value, depth)) = stack.pop() {
            check_context(Some(context))?;
            count += 1;
            if count > NODES || depth > DEPTH {
                return Err(StorageError::Full);
            }
            match value {
                Value::String(s) => string(s)?,
                Value::Array(array) => {
                    if array.len() > NODES.saturating_sub(count + stack.len()) {
                        return Err(StorageError::Full);
                    }
                    stack.extend(array.iter().map(|v| (v, depth + 1)));
                }
                Value::Object(object) => {
                    if object.len() > NODES.saturating_sub(count + stack.len()) {
                        return Err(StorageError::Full);
                    }
                    for (key, value) in object {
                        string(key)?;
                        stack.push((value, depth + 1));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
pub(super) fn encode(
    rows: &[StoredEvent],
    config: &StorageConfig,
    context: &OperationContext,
) -> Result<Vec<u8>, StorageError> {
    check_context(Some(context))?;
    walk(rows, config, context)?;
    crate::validate_batch(rows, config)?;
    let limit = config
        .max_batch_bytes
        .checked_add(rows.len().checked_mul(64).ok_or(StorageError::Full)?)
        .and_then(|n| n.checked_add(128))
        .ok_or(StorageError::Full)?;
    let wire = Wire {
        schema_version: 1,
        rows: rows
            .iter()
            .map(|r| Row {
                sequence: r.sequence,
                event: &r.event,
            })
            .collect(),
    };
    let mut writer = Writer {
        bytes: Vec::new(),
        limit,
        context,
    };
    let result = serde_json::to_writer(&mut writer, &wire);
    check_context(Some(context))?;
    result.map_err(|_| StorageError::Full)?;
    if writer.bytes.capacity() > limit {
        return Err(StorageError::Full);
    }
    Ok(writer.bytes)
}
pub(super) fn decode(
    bytes: &[u8],
    context: &OperationContext,
) -> Result<Vec<StoredEvent>, StorageError> {
    check_context(Some(context))?;
    let wire: OwnedWire = serde_json::from_slice(bytes).map_err(|_| StorageError::InvalidBatch)?;
    if wire.schema_version != 1 {
        return Err(StorageError::InvalidBatch);
    }
    check_context(Some(context))?;
    Ok(wire
        .rows
        .into_iter()
        .map(|row| StoredEvent {
            sequence: row.sequence,
            event: row.event,
        })
        .collect())
}
pub(super) fn copy(bytes: &[u8], limit: usize) -> Result<Vec<u8>, StorageError> {
    if bytes.len() > limit {
        return Err(StorageError::Full);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| StorageError::Full)?;
    result.extend_from_slice(bytes);
    if result.capacity() > limit {
        return Err(StorageError::Full);
    }
    Ok(result)
}

/// Allocation-free structural/node preflight. Serde remains the JSON syntax
/// authority; this guards recursive/container allocation before deserialization.
pub(super) fn json_preflight(
    bytes: &[u8],
    byte_limit: usize,
    node_limit: usize,
    context: &OperationContext,
) -> Result<usize, StorageError> {
    if bytes.len() > byte_limit {
        return Err(StorageError::Full);
    }
    let mut at = 0usize;
    let mut nodes = 0usize;
    let mut depth = 0usize;
    let mut stack = [0u8; 64];
    while at < bytes.len() {
        if at.is_multiple_of(4096) {
            check_context(Some(context))?;
        }
        match bytes[at] {
            b' ' | b'\r' | b'\n' | b'\t' | b',' | b':' => at += 1,
            b'{' | b'[' => {
                if depth == stack.len() {
                    return Err(StorageError::Full);
                }
                stack[depth] = bytes[at];
                depth += 1;
                at += 1;
                nodes += 1;
            }
            b'}' | b']' => {
                if depth == 0
                    || !matches!((stack[depth - 1], bytes[at]), (b'{', b'}') | (b'[', b']'))
                {
                    return Err(StorageError::InvalidBatch);
                }
                depth -= 1;
                at += 1;
            }
            b'"' => {
                nodes += 1;
                at += 1;
                let mut closed = false;
                while at < bytes.len() {
                    if at.is_multiple_of(4096) {
                        check_context(Some(context))?;
                    }
                    let value = bytes[at];
                    at += 1;
                    if value == b'"' {
                        closed = true;
                        break;
                    }
                    if value == b'\\' {
                        if at == bytes.len() {
                            return Err(StorageError::InvalidBatch);
                        }
                        at += 1;
                    }
                }
                if !closed {
                    return Err(StorageError::InvalidBatch);
                }
            }
            _ => {
                nodes += 1;
                at += 1;
                while at < bytes.len()
                    && !matches!(
                        bytes[at],
                        b' ' | b'\r'
                            | b'\n'
                            | b'\t'
                            | b','
                            | b':'
                            | b'{'
                            | b'['
                            | b'}'
                            | b']'
                            | b'"'
                    )
                {
                    if at.is_multiple_of(4096) {
                        check_context(Some(context))?;
                    }
                    at += 1;
                }
            }
        }
        if nodes > node_limit {
            return Err(StorageError::Full);
        }
    }
    if depth != 0 {
        return Err(StorageError::InvalidBatch);
    }
    check_context(Some(context))?;
    Ok(nodes)
}
pub(super) fn wire_node_limit(rows: usize) -> Result<usize, StorageError> {
    NODES
        .checked_mul(2)
        .and_then(|n| {
            rows.checked_mul(64)
                .and_then(|overhead| n.checked_add(overhead))
        })
        .and_then(|n| n.checked_add(16))
        .ok_or(StorageError::Full)
}

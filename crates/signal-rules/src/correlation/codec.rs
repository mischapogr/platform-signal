use super::*;
use std::io::Write;
struct Writer<'a> {
    bytes: Vec<u8>,
    limit: usize,
    context: &'a RuleContext,
}
impl Write for Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        check(self.context).map_err(std::io::Error::other)?;
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("correlation byte capacity"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn encode(
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
pub(super) fn canonical(event: &SignalEvent, context: &RuleContext) -> Result<Vec<u8>, Error> {
    let input = crate::scoped_state::Input::new(event, context).map_err(|e| match e {
        crate::scoped_state::Error::Cancelled => Error::Cancelled,
        _ => Error::Capacity,
    })?;
    if input.original_bytes().len() > 65536 {
        return Err(Error::Capacity);
    }
    Ok(input.original_bytes().to_vec())
}

pub(super) mod bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > 65536_usize.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom("correlation effect byte limit"));
        }
        let value = STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        if value.len() > 65536 {
            return Err(serde::de::Error::custom("correlation effect byte limit"));
        }
        Ok(value)
    }
}

//! Private projection of retained, validated rule definitions; never a rule wire format.
use super::{Operation, Predicate, Rule, RuleContext, RuleError, RuleSet};
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq, SerializeTuple},
};
use serde_json::Value;
use std::io::{self, Write};

const MAX_BYTES: usize = 64 * 1024 * 1024;
const DOMAIN: &[u8] = b"platform-signal/rules-revision/v1\0";

impl RuleSet {
    /// Stream a deterministic, versioned commitment input from these retained rules.
    /// The caller supplies a nonblocking in-memory sink (for example a hash writer)
    /// and must discard partial output after any error. Contents include private
    /// definitions and must never enter ordinary diagnostics. This is neither an
    /// activation record nor proof that the original source files remain current.
    /// The original context and a hard 64 MiB ceiling bound serialization; no
    /// complete projection or second rule tree is allocated or retained.
    pub fn write_revision(
        &self,
        writer: &mut impl Write,
        max_bytes: usize,
        context: &RuleContext,
    ) -> Result<(), RuleError> {
        if max_bytes == 0 || max_bytes > MAX_BYTES {
            return Err(RuleError::Invalid("revision byte limit"));
        }
        context.check()?;
        let mut bounded = BoundedWriter {
            writer,
            remaining: max_bytes,
            context,
            failure: None,
        };
        let result = bounded.write_all(DOMAIN).and_then(|()| {
            serde_json::to_writer(&mut bounded, &Rules(&self.rules)).map_err(io::Error::other)
        });
        if result.is_err() {
            return Err(bounded.failure.take().unwrap_or(RuleError::Io));
        }
        context.check()
    }
}

struct BoundedWriter<'a, W> {
    writer: &'a mut W,
    remaining: usize,
    context: &'a RuleContext,
    failure: Option<RuleError>,
}
impl<W: Write> BoundedWriter<'_, W> {
    fn check(&mut self) -> io::Result<()> {
        if let Err(error) = self.context.check() {
            self.failure = Some(error);
            return Err(io::Error::other("rule revision unavailable"));
        }
        Ok(())
    }
}
impl<W: Write> Write for BoundedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.len() > self.remaining {
            self.failure = Some(RuleError::Limit);
            return Err(io::Error::other("rule revision limit"));
        }
        let written = self.writer.write(bytes)?;
        if written > bytes.len() {
            return Err(io::Error::other("invalid revision sink write"));
        }
        self.remaining -= written;
        self.check()?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.writer.flush()?;
        self.check()
    }
}

struct Rules<'a>(&'a [Rule]);
impl Serialize for Rules<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        // The validated RuleSet already owns the unique-ID sorted order.
        for rule in self.0 {
            sequence.serialize_element(&Definition(rule))?;
        }
        sequence.end()
    }
}
struct Definition<'a>(&'a Rule);
impl Serialize for Definition<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let rule = self.0;
        let mut tuple = serializer.serialize_tuple(8)?;
        tuple.serialize_element(&rule.api_version)?;
        tuple.serialize_element(&rule.kind)?;
        tuple.serialize_element(&rule.metadata.id)?;
        tuple.serialize_element(&rule.metadata.name)?;
        tuple.serialize_element(&rule.spec.severity)?;
        tuple.serialize_element(&rule.spec.matches.all.as_deref().map(Predicates))?;
        tuple.serialize_element(&rule.spec.matches.any.as_deref().map(Predicates))?;
        tuple.serialize_element(&rule.spec.finding.title)?;
        tuple.end()
    }
}
struct Predicates<'a>(&'a [Predicate]);
impl Serialize for Predicates<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for predicate in self.0 {
            sequence.serialize_element(&Condition(predicate))?;
        }
        sequence.end()
    }
}
struct Condition<'a>(&'a Predicate);
impl Serialize for Condition<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(&self.0.field)?;
        match &self.0.operation {
            Operation::Eq(value) => {
                tuple.serialize_element("eq")?;
                tuple.serialize_element(&CanonicalValue(value))?;
            }
            Operation::Neq(value) => {
                tuple.serialize_element("neq")?;
                tuple.serialize_element(&CanonicalValue(value))?;
            }
            Operation::Contains(value) => {
                tuple.serialize_element("contains")?;
                tuple.serialize_element(value)?;
            }
            Operation::Exists(value) => {
                tuple.serialize_element("exists")?;
                tuple.serialize_element(value)?;
            }
        }
        tuple.end()
    }
}
struct CanonicalValue<'a>(&'a Value);
impl Serialize for CanonicalValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(object) => {
                // Validated values have at most 65,536 total nodes. Sort only
                // borrowed keys, so preserve_order feature unification cannot
                // change the commitment or require a second value tree.
                let mut entries: Vec<_> = object.iter().collect();
                entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, &CanonicalValue(value))?;
                }
                map.end()
            }
            Value::Array(array) => {
                let mut sequence = serializer.serialize_seq(Some(array.len()))?;
                for value in array {
                    sequence.serialize_element(&CanonicalValue(value))?;
                }
                sequence.end()
            }
            other => other.serialize(serializer),
        }
    }
}

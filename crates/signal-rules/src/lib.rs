//! Bounded startup rule loading and deterministic stateless event predicates.
use serde::Deserialize;
use serde_json::Value;
use signal_event::{SignalEvent, lookup_attribute_path};
use signal_findings::{DetectionSeverity, Finding};
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{Semaphore, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

mod revision;

#[derive(Clone, Debug)]
pub struct RuleLimits {
    pub max_rules: usize,
    pub max_directory_entries: usize,
    pub max_document_bytes: usize,
    pub max_total_bytes: usize,
    pub max_predicates: usize,
    pub max_value_nodes: usize,
    pub max_depth: usize,
    pub max_field_bytes: usize,
    pub max_title_bytes: usize,
}
impl Default for RuleLimits {
    fn default() -> Self {
        Self {
            max_rules: 256,
            max_directory_entries: 4096,
            max_document_bytes: 65536,
            max_total_bytes: 4 * 1024 * 1024,
            max_predicates: 128,
            max_value_nodes: 4096,
            max_depth: 32,
            max_field_bytes: 512,
            max_title_bytes: 4096,
        }
    }
}
impl RuleLimits {
    fn validate(&self) -> Result<(), RuleError> {
        if self.max_rules == 0
            || self.max_rules > 256
            || self.max_directory_entries == 0
            || self.max_directory_entries > 65536
            || self.max_document_bytes == 0
            || self.max_document_bytes > 1024 * 1024
            || self.max_total_bytes == 0
            || self.max_total_bytes > 64 * 1024 * 1024
            || self.max_predicates == 0
            || self.max_predicates > 1024
            || self.max_value_nodes == 0
            || self.max_value_nodes > 65536
            || self.max_depth == 0
            || self.max_depth > 64
            || self.max_field_bytes == 0
            || self.max_field_bytes > 4096
            || self.max_title_bytes == 0
            || self.max_title_bytes > 4096
        {
            return Err(RuleError::Invalid("limits"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct RuleContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
impl RuleContext {
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancellation: CancellationToken::new(),
        }
    }
    fn check(&self) -> Result<(), RuleError> {
        if self.cancellation.is_cancelled() {
            Err(RuleError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(RuleError::Timeout)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid rule or configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid YAML rule document")]
    Yaml,
    #[error("rule resource limit exceeded")]
    Limit,
    #[error("duplicate rule ID")]
    DuplicateId,
    #[error("rule loading I/O failed")]
    Io,
    #[error("rule loading timed out")]
    Timeout,
    #[error("rule loading cancelled")]
    Cancelled,
    #[error("rule loader capacity exhausted")]
    Full,
    #[error("finding construction failed")]
    Finding,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: Spec,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    id: String,
    name: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    severity: DetectionSeverity,
    #[serde(rename = "match")]
    matches: Match,
    finding: Output,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    title: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Match {
    #[serde(default, deserialize_with = "deserialize_group")]
    all: Option<Vec<Predicate>>,
    #[serde(default, deserialize_with = "deserialize_group")]
    any: Option<Vec<Predicate>>,
}
fn deserialize_group<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<Predicate>>, D::Error> {
    Vec::<Predicate>::deserialize(deserializer).map(Some)
}
// Deserialize each operator as a map entry to preserve the difference between
// `eq: null` and no eq operator; Option<Value> would erase that distinction.
#[derive(Debug)]
struct Predicate {
    field: String,
    operation: Operation,
}
#[derive(Debug)]
enum Operation {
    Eq(Value),
    Neq(Value),
    Contains(String),
    Exists(bool),
}
impl<'de> Deserialize<'de> for Predicate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        let field = fields
            .remove("field")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| serde::de::Error::custom("invalid field"))?;
        if fields.len() != 1 {
            return Err(serde::de::Error::custom("exactly one operator required"));
        }
        let (operator, value) = fields
            .into_iter()
            .next()
            .ok_or_else(|| serde::de::Error::custom("missing operator"))?;
        let operation = match operator.as_str() {
            "eq" => Operation::Eq(value),
            "neq" => Operation::Neq(value),
            "contains" => Operation::Contains(
                value
                    .as_str()
                    .ok_or_else(|| serde::de::Error::custom("contains requires string"))?
                    .into(),
            ),
            "exists" => Operation::Exists(
                value
                    .as_bool()
                    .ok_or_else(|| serde::de::Error::custom("exists requires boolean"))?,
            ),
            _ => return Err(serde::de::Error::custom("unknown operator")),
        };
        Ok(Self { field, operation })
    }
}
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}
static LOADER: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
impl RuleSet {
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    pub fn from_yaml_documents<I, S>(documents: I, limits: RuleLimits) -> Result<Self, RuleError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        limits.validate()?;
        let mut rules = Vec::new();
        let mut ids = HashSet::new();
        let mut total = 0usize;
        for document in documents {
            let text = document.as_ref();
            total = total.checked_add(text.len()).ok_or(RuleError::Limit)?;
            if rules.len() >= limits.max_rules
                || text.len() > limits.max_document_bytes
                || total > limits.max_total_bytes
            {
                return Err(RuleError::Limit);
            }
            let options = serde_saphyr::options! {
                budget: serde_saphyr::budget! { max_documents: 1, max_nodes: limits.max_value_nodes, max_events: limits.max_value_nodes.saturating_mul(4), max_depth: limits.max_depth, max_anchors: 0, max_aliases: 0, max_total_scalar_bytes: limits.max_document_bytes, flow_nesting_limit: limits.max_depth },
                duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
                merge_keys: serde_saphyr::MergeKeyPolicy::Error,
                strict_booleans: true, no_schema: true, reject_unsupported_tags: true, emit_comments: false, with_snippet: false,
            };
            let rule: Rule =
                serde_saphyr::from_str_with_options(text, options).map_err(|_| RuleError::Yaml)?;
            reject_lossy_integers(text)?;
            validate_rule(&rule, &limits)?;
            if !ids.insert(rule.metadata.id.clone()) {
                return Err(RuleError::DuplicateId);
            }
            rules.push(rule);
        }
        rules.sort_by(|a, b| a.metadata.id.cmp(&b.metadata.id));
        Ok(Self { rules })
    }
    /// One ordinary worker holds the process-wide permit until all disk work ends.
    /// Timed out/dropped callers cancel it; a stuck filesystem cannot create more workers.
    pub async fn load(
        directories: &[PathBuf],
        limits: RuleLimits,
        context: RuleContext,
    ) -> Result<Self, RuleError> {
        limits.validate()?;
        context.check()?;
        if directories.len() > limits.max_directory_entries {
            return Err(RuleError::Limit);
        }
        let permit = LOADER
            .clone()
            .try_acquire_owned()
            .map_err(|_| RuleError::Full)?;
        let context = RuleContext {
            deadline: context.deadline,
            cancellation: context.cancellation.child_token(),
        };
        let _cancel_on_drop = context.cancellation.clone().drop_guard();
        let worker_context = context.clone();
        let directories = directories.to_vec();
        let (tx, rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("signal-rule-loader".into())
            .spawn(move || {
                let result = load_files(&directories, limits, &worker_context);
                drop(permit);
                let _ = tx.send(result);
            })
            .map_err(|_| RuleError::Io)?;
        tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => Err(RuleError::Cancelled),
            result = tokio::time::timeout_at(context.deadline, rx) => result.map_err(|_| RuleError::Timeout)?.map_err(|_| RuleError::Io)?,
        }
    }
    pub fn evaluate(&self, event: &SignalEvent) -> Result<Vec<Finding>, RuleError> {
        self.evaluate_with_context(event, &RuleContext::new(Duration::from_secs(5)))
    }
    pub fn evaluate_with_context(
        &self,
        event: &SignalEvent,
        context: &RuleContext,
    ) -> Result<Vec<Finding>, RuleError> {
        context.check()?;
        event.validate().map_err(|_| RuleError::Invalid("event"))?;
        let mut findings = Vec::new();
        for rule in &self.rules {
            let matches = &rule.spec.matches;
            // When both groups are present, all must hold AND any must hold.
            context.check()?;
            if group_matches(&matches.all, event, context, true)?
                && group_matches(&matches.any, event, context, false)?
            {
                findings.push(
                    Finding::for_event(
                        &rule.metadata.id,
                        event,
                        rule.spec.severity,
                        &rule.spec.finding.title,
                    )
                    .map_err(|_| RuleError::Finding)?,
                );
            }
        }
        Ok(findings)
    }
}
fn validate_rule(rule: &Rule, limits: &RuleLimits) -> Result<(), RuleError> {
    if rule.api_version != "signal.dev/v1" || rule.kind != "Rule" {
        return Err(RuleError::Invalid("version or kind"));
    }
    if rule.metadata.id.trim().is_empty()
        || rule.metadata.id.len() > 256
        || rule.metadata.name.trim().is_empty()
        || rule.metadata.name.len() > 256
        || rule.spec.finding.title.trim().is_empty()
        || rule.spec.finding.title.len() > limits.max_title_bytes
    {
        return Err(RuleError::Invalid("metadata or title"));
    }
    let groups = [&rule.spec.matches.all, &rule.spec.matches.any];
    if groups.iter().all(|g| g.is_none())
        || groups.iter().any(|g| g.as_ref().is_some_and(Vec::is_empty))
    {
        return Err(RuleError::Invalid("match groups"));
    }
    let mut count = 0;
    for group in groups.into_iter().flatten() {
        for predicate in group {
            count += 1;
            if count > limits.max_predicates || predicate.field.len() > limits.max_field_bytes {
                return Err(RuleError::Limit);
            }
            if predicate.field.split('.').any(str::is_empty)
                || predicate.field.chars().any(char::is_control)
            {
                return Err(RuleError::Invalid("field path"));
            }
        }
    }
    Ok(())
}
fn load_files(
    directories: &[PathBuf],
    limits: RuleLimits,
    context: &RuleContext,
) -> Result<RuleSet, RuleError> {
    let mut files = Vec::new();
    let mut entries = 0usize;
    for directory in directories {
        context.check()?;
        let meta = fs::symlink_metadata(directory).map_err(|_| RuleError::Io)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(RuleError::Invalid("rule directory"));
        }
        for entry in fs::read_dir(directory).map_err(|_| RuleError::Io)? {
            context.check()?;
            entries += 1;
            if entries > limits.max_directory_entries {
                return Err(RuleError::Limit);
            }
            let entry = entry.map_err(|_| RuleError::Io)?;
            let kind = entry.file_type().map_err(|_| RuleError::Io)?;
            if kind.is_symlink() {
                return Err(RuleError::Invalid("symlink"));
            }
            let path = entry.path();
            if !matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("yaml" | "yml")
            ) {
                continue;
            }
            if !kind.is_file() {
                return Err(RuleError::Invalid("rule file"));
            }
            if files.len() >= limits.max_rules {
                return Err(RuleError::Limit);
            }
            files.push(path);
        }
    }
    files.sort();
    let mut documents = Vec::new();
    let mut total = 0usize;
    for path in files {
        context.check()?;
        if fs::symlink_metadata(&path)
            .map_err(|_| RuleError::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(RuleError::Invalid("symlink"));
        }
        let mut bytes = Vec::new();
        open_rule_file(&path)?
            .take((limits.max_document_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RuleError::Io)?;
        context.check()?;
        total = total.checked_add(bytes.len()).ok_or(RuleError::Limit)?;
        if bytes.len() > limits.max_document_bytes || total > limits.max_total_bytes {
            return Err(RuleError::Limit);
        }
        documents.push(String::from_utf8(bytes).map_err(|_| RuleError::Yaml)?);
    }
    let rules = RuleSet::from_yaml_documents(documents, limits)?;
    context.check()?;
    Ok(rules)
}
impl Predicate {
    fn matches(&self, event: &SignalEvent) -> bool {
        let value = lookup(event, &self.field);
        match &self.operation {
            Operation::Eq(expected) => value.as_ref().is_some_and(|v| v.as_ref() == expected),
            Operation::Neq(expected) => value.as_ref().is_some_and(|v| v.as_ref() != expected),
            Operation::Contains(expected) => value
                .as_ref()
                .and_then(|v| v.as_ref().as_str())
                .is_some_and(|v| v.contains(expected)),
            Operation::Exists(expected) => value.is_some() == *expected,
        }
    }
}
fn lookup<'a>(event: &'a SignalEvent, field: &str) -> Option<std::borrow::Cow<'a, Value>> {
    use std::borrow::Cow;
    if let Some(path) = field.strip_prefix("attributes.") {
        return lookup_attribute_path(&event.attributes, path).map(Cow::Borrowed);
    }
    let string = |s: &str| Some(Cow::Owned(Value::String(s.into())));
    match field {
        "schema_version" => Some(Cow::Owned(Value::from(event.schema_version))),
        "id" => string(&event.id.to_string()),
        "timestamp" => string(
            &event
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        ),
        "observed_at" => string(
            &event
                .observed_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        ),
        "source.type" => string(&event.source.source_type),
        "source.name" => event.source.name.as_deref().and_then(string),
        "message" => event.message.as_deref().and_then(string),
        "resource.kind" => event.resource.as_ref().and_then(|r| string(&r.kind)),
        "resource.id" => event.resource.as_ref().and_then(|r| string(&r.id)),
        "resource.account_id" => event
            .resource
            .as_ref()
            .and_then(|r| r.account_id.as_deref())
            .and_then(string),
        "resource.region" => event
            .resource
            .as_ref()
            .and_then(|r| r.region.as_deref())
            .and_then(string),
        "trace_id" => event.trace_id.as_deref().and_then(string),
        "span_id" => event.span_id.as_deref().and_then(string),
        "severity" => serde_json::to_value(event.severity).ok().map(Cow::Owned),
        "tags" => serde_json::to_value(&event.tags).ok().map(Cow::Owned),
        "source" => serde_json::to_value(&event.source).ok().map(Cow::Owned),
        "resource" => event
            .resource
            .as_ref()
            .and_then(|r| serde_json::to_value(r).ok())
            .map(Cow::Owned),
        "attributes" => Some(Cow::Owned(Value::Object(event.attributes.clone()))),
        _ => None,
    }
}

fn group_matches(
    group: &Option<Vec<Predicate>>,
    event: &SignalEvent,
    context: &RuleContext,
    all: bool,
) -> Result<bool, RuleError> {
    let Some(predicates) = group else {
        return Ok(true);
    };
    for predicate in predicates {
        context.check()?;
        let matched = predicate.matches(event);
        if matched != all {
            return Ok(!all);
        }
    }
    Ok(all)
}
fn open_rule_file(path: &std::path::Path) -> Result<fs::File, RuleError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| RuleError::Io)?;
    if !file.metadata().map_err(|_| RuleError::Io)?.is_file() {
        return Err(RuleError::Invalid("rule file"));
    }
    Ok(file)
}
// serde-saphyr's deserialize_any uses i64/u64 then f64. Reject integer
// literals outside those exact domains rather than silently rounding them.
fn reject_lossy_integers(text: &str) -> Result<(), RuleError> {
    use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};
    for event in Parser::new_from_str(text) {
        let (event, _) = event.map_err(|_| RuleError::Yaml)?;
        if let Event::Scalar(value, ScalarStyle::Plain, _, _) = event {
            let value = value.replace('_', "");
            let negative = value.starts_with('-');
            let digits = value.trim_start_matches(['-', '+']);
            let (digits, radix) = if let Some(d) = digits.strip_prefix("0x") {
                (d, 16)
            } else if let Some(d) = digits.strip_prefix("0o") {
                (d, 8)
            } else {
                (digits, 10)
            };
            if !digits.is_empty() && digits.chars().all(|c| c.is_digit(radix)) {
                let magnitude = u64::from_str_radix(digits, radix)
                    .map_err(|_| RuleError::Invalid("integer range"))?;
                if negative && magnitude > (i64::MAX as u64) + 1 {
                    return Err(RuleError::Invalid("integer range"));
                }
            }
        }
    }
    Ok(())
}

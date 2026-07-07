//! Regional point-in-time CloudTrail configuration observation. This does not
//! prove delivery continuity, digest authenticity or a complete quiet interval.
use super::{observer::*, *};
use crate::{
    ExtensionContext,
    receipt::{AwsCredentialsProvider, SourceFailure, aws},
};
use reqwest::{
    Method, Url,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

const REPLY_CAP: usize = 64 * 1024;
const TARGET: &str = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigWire {
    schema_version: u32,
    trail_arn: String,
    observed_region: String,
    endpoint: String,
    allow_loopback_http: bool,
    expected_bucket: String,
    expected_prefix: String,
    management_read_write: String,
    require_multi_region: bool,
    require_global_events: bool,
    require_organization: bool,
    require_digest_delivery: bool,
}
/// Trusted application requirements, never inferred from delivered event data.
/// One trail/observed region and management stream only; no organization inventory.
pub struct CloudTrailProbeConfig {
    wire: ConfigWire,
    endpoint: Url,
    binding: Binding,
    observer_id: String,
}
impl CloudTrailProbeConfig {
    pub fn parse(bytes: &[u8], trusted_context: &[u8]) -> Result<Self, ProbeFailure> {
        let wire: ConfigWire = decode(bytes).map_err(|_| ProbeFailure::Malformed)?;
        let context =
            CoverageContext::parse(trusted_context).map_err(|_| ProbeFailure::Malformed)?;
        let parts: Vec<_> = wire.trail_arn.split(':').collect();
        if wire.schema_version != 1
            || parts.len() != 6
            || parts[0..3] != ["arn", "aws", "cloudtrail"]
            || !aws::region(parts[3])
            || parts[4].len() != 12
            || !parts[4].bytes().all(|b| b.is_ascii_digit())
            || !parts[5].strip_prefix("trail/").is_some_and(|name| {
                (3..=128).contains(&name.len())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
            || !aws::region(&wire.observed_region)
            || !(3..=63).contains(&wire.expected_bucket.len())
            || !wire
                .expected_bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
            || wire.expected_bucket.starts_with(['.', '-'])
            || wire.expected_bucket.ends_with(['.', '-'])
            || wire.expected_bucket.contains("..")
            || wire.expected_prefix.len() > MAX_STRING_BYTES
            || wire.expected_prefix.bytes().any(|b| b.is_ascii_control())
            || !matches!(
                wire.management_read_write.as_str(),
                "All" | "ReadOnly" | "WriteOnly"
            )
        {
            return Err(ProbeFailure::Malformed);
        }
        let endpoint =
            aws::endpoint(&wire.endpoint, wire.allow_loopback_http).map_err(map_failure)?;
        if endpoint.path() != "/" {
            return Err(ProbeFailure::Malformed);
        }
        let stream = match wire.management_read_write.as_str() {
            "All" => "aws.cloudtrail.management.all",
            "ReadOnly" => "aws.cloudtrail.management.read",
            _ => "aws.cloudtrail.management.write",
        };
        if context.wire.mode != AssessmentMode::Current
            || context.wire.binding.resource_scope.kind != "aws.cloudtrail.trail"
            || context.wire.binding.resource_scope.id != wire.trail_arn
            || context.wire.binding.resource_scope.attributes.len() != 1
            || context.wire.binding.resource_scope.attributes.get("region")
                != Some(&wire.observed_region)
            || context.wire.binding.expected_stream != stream
        {
            return Err(ProbeFailure::Denied);
        }
        Ok(Self {
            wire,
            endpoint,
            binding: context.wire.binding,
            observer_id: context.wire.observer_id,
        })
    }
}
pub struct CloudTrailConfigurationProbe {
    config: CloudTrailProbeConfig,
    transport: aws::SignedAwsTransport,
}
impl CloudTrailConfigurationProbe {
    pub fn new(
        config: CloudTrailProbeConfig,
        credentials: Arc<dyn AwsCredentialsProvider>,
        connect_timeout: Duration,
    ) -> Result<Self, ProbeFailure> {
        Ok(Self {
            config,
            transport: aws::SignedAwsTransport::new(credentials, connect_timeout)
                .map_err(map_failure)?,
        })
    }
    async fn read(
        &self,
        action: &str,
        key: &str,
        context: &ExtensionContext,
    ) -> Result<(Value, String), ProbeFailure> {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{TARGET}.{action}"))
                .map_err(|_| ProbeFailure::Malformed)?,
        );
        let body = serde_json::to_vec(&json!({key: self.config.wire.trail_arn}))
            .map_err(|_| ProbeFailure::Malformed)?;
        let response = self
            .transport
            .signed_request(
                Method::POST,
                self.config.endpoint.clone(),
                ("cloudtrail", &self.config.wire.observed_region),
                headers,
                body,
                context,
            )
            .await
            .map_err(map_failure)?;
        let status = response.status().as_u16();
        let body = aws::read_body(response, REPLY_CAP, context)
            .await
            .map_err(map_failure)?;
        if status != 200 {
            return Err(map_failure(aws::source_error(status, &body)));
        }
        let value = crate::cloudtrail::decode_json(&body, REPLY_CAP, 16, 8192)
            .map_err(|_| ProbeFailure::Malformed)?;
        if !value.is_object()
            || ["__type", "Error", "Code"]
                .iter()
                .any(|key| value.get(key).is_some())
        {
            return Err(ProbeFailure::Malformed);
        }
        let proof = format!(
            "sha256:{}",
            Sha256::digest(&body)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        Ok((value, proof))
    }
}
#[crate::extension]
impl CoverageProbe for CloudTrailConfigurationProbe {
    async fn probe(
        &self,
        request: &ProbeRequest<'_>,
        context: &ExtensionContext,
    ) -> Result<ProbeReport, ProbeFailure> {
        let current =
            CoverageContext::parse(request.context_bytes()).map_err(|_| ProbeFailure::Malformed)?;
        if current.wire.mode != AssessmentMode::Current
            || current.wire.binding != self.config.binding
            || current.wire.observer_id != self.config.observer_id
        {
            return Err(ProbeFailure::Denied);
        }
        if current.end > current.at
            || current.end.signed_duration_since(current.start)
                > seconds(request.profile().0.max_interval_seconds)
        {
            return Err(ProbeFailure::Malformed);
        }
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        let (trail, trail_proof) = self.read("GetTrail", "Name", context).await?;
        let (status, status_proof) = self.read("GetTrailStatus", "Name", context).await?;
        let (selectors, selectors_proof) =
            self.read("GetEventSelectors", "TrailName", context).await?;
        let trail = trail
            .get("Trail")
            .filter(|v| v.is_object())
            .ok_or(ProbeFailure::Malformed)?;
        if required_text(trail, "TrailARN")? != self.config.wire.trail_arn
            || required_text(&selectors, "TrailARN")? != self.config.wire.trail_arn
        {
            return Err(ProbeFailure::Denied);
        }
        let config = &self.config.wire;
        let prefix = match trail.get("S3KeyPrefix") {
            None => "",
            Some(v) => v.as_str().ok_or(ProbeFailure::Malformed)?,
        };
        let configuration = if bool_field(&status, "IsLogging")?
            && required_text(trail, "S3BucketName")? == config.expected_bucket
            && prefix == config.expected_prefix
            && (!config.require_digest_delivery || bool_field(trail, "LogFileValidationEnabled")?)
        {
            CoverageStatus::Verified
        } else {
            CoverageStatus::Failed
        };
        let home = config
            .trail_arn
            .split(':')
            .nth(3)
            .ok_or(ProbeFailure::Malformed)?;
        let region_matches = required_text(trail, "HomeRegion")? == home
            && (config.observed_region == home || bool_field(trail, "IsMultiRegionTrail")?)
            && (!config.require_multi_region || bool_field(trail, "IsMultiRegionTrail")?)
            && (!config.require_global_events || bool_field(trail, "IncludeGlobalServiceEvents")?)
            && (!config.require_organization || bool_field(trail, "IsOrganizationTrail")?);
        let scope = if region_matches {
            selector_status(&selectors, &config.management_read_write)?
        } else {
            CoverageStatus::Failed
        };
        // A current API configuration snapshot cannot establish interval continuity,
        // data arrivals, checkpoints, digest authenticity or a complete gap inventory.
        let validation = Validation {
            configuration,
            scope,
            continuity: CoverageStatus::Unknown,
            source_integrity: CoverageStatus::Unknown,
        };
        let (summary, _) = reduce(&validation, &request.profile().0.required_components, true);
        let expires = current
            .at
            .checked_add_signed(seconds(request.profile().0.max_verification_age_seconds))
            .ok_or(ProbeFailure::Malformed)?;
        let raw: Value =
            serde_json::from_slice(request.context_bytes()).map_err(|_| ProbeFailure::Malformed)?;
        let binding = &raw["binding"];
        let report = json!({
            "schema_version":1, "record_id":uuid::Uuid::new_v4().to_string(),
            "source_id":binding["source_id"],"collector_id":binding["collector_id"],"resource_scope":binding["resource_scope"],
            "expected_stream":binding["expected_stream"],"coverage_profile":binding["coverage_profile"],"collection_config_revision":binding["collection_config_revision"],
            "coverage_start":current.wire.interval.start,"coverage_end":current.wire.interval.end,"last_observed_at":null,
            "last_verified_at":current.wire.at,"valid_until":expires.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true),
            "checkpoint":null,"validation_status":summary,"validation":{"configuration":configuration,"scope":scope,"continuity":"unknown","source_integrity":"unknown"},
            "gaps":[],"gap_summary":{"total":null,"truncated":true},
            "provenance":{"observer_id":current.wire.observer_id,"method":"aws.cloudtrail.regional_configuration.v1","observed_at":current.wire.at,
                "proof_refs":[trail_proof,status_proof,selectors_proof]}
        });
        let bytes = serde_json::to_vec(&report).map_err(|_| ProbeFailure::Malformed)?;
        ValidatedCoverage::parse(&bytes, Some(request.profile()))
            .map_err(|_| ProbeFailure::Malformed)?;
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        ProbeReport::new(&bytes).map_err(|_| ProbeFailure::Malformed)
    }
}
fn required_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProbeFailure> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_STRING_BYTES)
        .ok_or(ProbeFailure::Malformed)
}
fn bool_field(value: &Value, key: &str) -> Result<bool, ProbeFailure> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(ProbeFailure::Malformed)
}
fn selector_status(value: &Value, expected: &str) -> Result<CoverageStatus, ProbeFailure> {
    if value.get("NextToken").is_some() {
        return Ok(CoverageStatus::Unsupported);
    }
    if let Some(advanced) = value.get("AdvancedEventSelectors") {
        let advanced = advanced.as_array().ok_or(ProbeFailure::Malformed)?;
        if !advanced.is_empty() {
            return Ok(CoverageStatus::Unsupported);
        }
    }
    let selectors = value
        .get("EventSelectors")
        .and_then(Value::as_array)
        .filter(|v| v.len() <= 5)
        .ok_or(ProbeFailure::Malformed)?;
    let mut reads = false;
    let mut writes = false;
    for selector in selectors {
        let object = selector.as_object().ok_or(ProbeFailure::Malformed)?;
        if object.keys().any(|k| {
            !matches!(
                k.as_str(),
                "ReadWriteType"
                    | "IncludeManagementEvents"
                    | "ExcludeManagementEventSources"
                    | "DataResources"
            )
        }) {
            return Ok(CoverageStatus::Unsupported);
        }
        let excluded = match selector.get("ExcludeManagementEventSources") {
            None => false,
            Some(v) => !string_array(v)?.is_empty(),
        };
        if let Some(resources) = selector.get("DataResources") {
            let resources = resources
                .as_array()
                .filter(|a| a.len() <= 250)
                .ok_or(ProbeFailure::Malformed)?;
            for resource in resources {
                let object = resource.as_object().ok_or(ProbeFailure::Malformed)?;
                if object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "Type" | "Values"))
                {
                    return Ok(CoverageStatus::Unsupported);
                }
                // AWS defines both members as optional; present members still
                // need their documented types. Data selection does not expand
                // this management-only observation into data-event coverage.
                if resource.get("Type").is_some() {
                    required_text(resource, "Type")?;
                }
                if let Some(values) = resource.get("Values") {
                    string_array(values)?;
                }
            }
        }
        let read_write = match selector.get("ReadWriteType") {
            None => "All",
            Some(_) => required_text(selector, "ReadWriteType")?,
        };
        if !matches!(read_write, "All" | "ReadOnly" | "WriteOnly") {
            return Err(ProbeFailure::Malformed);
        }
        let include = match selector.get("IncludeManagementEvents") {
            None => true,
            Some(_) => bool_field(selector, "IncludeManagementEvents")?,
        };
        if include && !excluded {
            reads |= matches!(read_write, "All" | "ReadOnly");
            writes |= matches!(read_write, "All" | "WriteOnly");
        }
    }
    let covers = match expected {
        "All" => reads && writes,
        "ReadOnly" => reads,
        _ => writes,
    };
    Ok(if covers {
        CoverageStatus::Verified
    } else {
        CoverageStatus::Failed
    })
}
fn string_array(value: &Value) -> Result<&[Value], ProbeFailure> {
    let values = value
        .as_array()
        .filter(|a| a.len() <= 250)
        .ok_or(ProbeFailure::Malformed)?;
    if values.iter().any(|v| {
        v.as_str()
            .is_none_or(|s| s.is_empty() || s.len() > MAX_STRING_BYTES)
    }) {
        return Err(ProbeFailure::Malformed);
    }
    Ok(values)
}
fn map_failure(error: SourceFailure) -> ProbeFailure {
    match error {
        SourceFailure::Denied => ProbeFailure::Denied,
        SourceFailure::Throttled => ProbeFailure::Throttled,
        SourceFailure::Malformed => ProbeFailure::Malformed,
        _ => ProbeFailure::Unavailable,
    }
}

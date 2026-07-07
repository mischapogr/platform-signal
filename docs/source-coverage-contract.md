# SourceCoverage v1 contract and transition fixtures

Status: PS-01 contract and pure validator locally accepted, 2026-10-07. These
standalone v1 JSON contracts formalize [failure-domain requirements](failure-domains.md)
for the [detection catalog](source-detection-catalog.md). Semantic validation and
assessment run in the SDK; collection, persistence and deployment remain separate.

## Artifacts and offline acceptance

- [Record schema](../schemas/source-coverage.schema.json): required fields,
  closed objects, explicit nullable values and bounded collections.
- [Profile schema](../schemas/source-coverage-profile.schema.json): immutable
  profile identity/revision, required components and finite time budgets.
- [Fixtures](../tests/fixtures/source-coverage/contract.json): two laboratory
  profiles, 60 record cases, 39 assessment cases and seven transition sequences.
- [Offline checker](../scripts/check-source-coverage-contract.py): structural
  keyword checks and fixture-reference consistency, using Python's standard library.
- [Rust validator](../crates/signal-collector-sdk/src/coverage.rs) and
  [integration tests](../crates/signal-collector-sdk/tests/coverage.rs): bounded
  semantic validation, current/historical assessment and transition evaluation.
- [Intake/history contract](source-coverage-history-contract.md) and
  [history fixtures](../tests/fixtures/source-coverage/history.json): bounded
  replay/retention/correction/recovery requirements, checked as an offline inventory.

```bash
python3 scripts/check-source-coverage-contract.py
# A report path must be new; existing evidence is preserved.
python3 scripts/check-source-coverage-contract.py \
  --report target/source-coverage-local/structural.json
```

The checker exercises the keywords used by these owned schemas and refuses
unknown schema keywords/remote references. It is not a general JSON Schema
implementation or a production coverage validator. Of 60 record cases, 42 satisfy
the structural schema and 18 intentionally fail it. Twenty-one of the structural
accepts fail semantic validation. The offline checker inventories the 39
assessments and seven sequences without executing them. Their original `planned`
fixture markers describe design-time expectations; the Rust suite now executes
all of them. Its 24 tests cover 60 record cases (21 valid, 21 semantic rejects,
18 structural rejects), 39 assessments and seven pure transition sequences,
plus focused wire/time/identity regressions. This is not durable history proof.

```bash
cargo test -p signal-collector-sdk --test coverage
```

Both schemas declare Draft 2020-12. Its `maxLength` counts Unicode code points;
UTF-8 byte limits therefore need a separate check. The standard dialect does not
automatically make `format` an assertion. This checker treats `date-time`/`uuid`
as annotations and uses the schema's lexical patterns; calendar validity, timestamp
ordering and profile-dependent decisions belong to semantic validation.
[JSON Schema 2020-12 validation](https://json-schema.org/draft/2020-12/json-schema-validation).

## Meaning and authority

SourceCoverage states which declared capture preconditions an authorized observer
checked for one source/collector/scope/stream and a completed interval. It does
not prove universal upstream completeness, producer honesty or absence of attacks.
For example, a configuration probe can verify enabled logging without proving
that every upstream event was delivered. Native source proofs and drop counters
support additional claims; consumers select a profile that requires them.

The JSON record is an assertion, not authentication. Observer identity, source
binding and profile resolution must come from trusted configuration/transport.
Caller-supplied `verified`, an evidence URI or a matching observer name is
insufficient. Profiles, account/cluster inventories, policies and credentials are
supplied by separately authorized applications. Synthetic profile durations here
are acceptance parameters, not production SLOs or retention policy.

## Wire fields and identity

| Fields | Contract |
| --- | --- |
| `schema_version`, `record_id` | Version 1; canonical lowercase, non-nil UUID. Allocate once per immutable observation; retries retain ID and exact content |
| `source_id`, `collector_id`, `resource_scope`, `expected_stream` | Exact scope identity. Scope contains `kind`, `id` and optional bounded string attributes; attributes do not imply hierarchical resource membership |
| `coverage_profile.id/revision`, `collection_config_revision` | Immutable references to the capture requirements and configuration being checked; a new revision cannot reuse an old verification |
| `coverage_start`, `coverage_end` | Completed, nonempty half-open UTC interval `[start, end)` for the profile's capture preconditions, independently of delivery/processing time |
| `last_observed_at` | Observer-clock time of the latest stream-data arrival known to this observation, or null; it may precede/follow the coverage interval. Null does not by itself prove a quiet/complete stream |
| `last_verified_at`, `valid_until` | Observer's completed verification attempt and expiry of its current-health assertion. A completed failed/unknown check is still a verification observation; it is not a successful validation |
| `checkpoint` | Null when unavailable, otherwise versioned `kind`, `milestone` and opaque `value`; milestone is `capture`, `durable_receipt` or `processed_input` |
| `validation`, `validation_status` | Four explicit component results and a derived summary; states are `verified`, `partial`, `unknown`, `failed`, `unsupported` |
| `gaps`, `gap_summary` | Bounded gap evidence for this record's interval/scope; summary preserves known total or explicit truncation/unknown count |
| `provenance` | Observer ID, method, proof references and observation time; proof references convey no access credentials or independent proof verification |

All top-level fields are required, including explicit nulls and empty lists.
Unknown object fields fail structural validation; use a separately versioned
contract for new fields. This does not restrict the existing event envelope's
arbitrary nested attributes.

Scope comparison uses exact `kind`, `id` and attribute map equality, independent
of object-key order. Omitted scope attributes and an empty map represent the same
scope. No wildcard/subset matching, ARN parsing, label inference or cross-account
principal/resource equivalence is implied. The full binding includes source,
collector, scope, expected stream, profile ID/revision and configuration revision.
Changing any binding field needs a new verification for the requested binding.

Checkpoint kinds are source-specific. Never compare opaque values lexically or
translate them into WAL sequence/event time. An adapter declares advancement and
replay semantics for its milestone: durable receipt differs from processed input.
Null positions cannot support a profile that requires a checkpoint for `verified`
coverage. If unavailable, record continuity as unknown and retain that uncertainty.

Record IDs bind immutable content, not a cryptographic chain. A future store
must return an identical retry as a replay and reject the same ID with different
content within its declared replay/identity horizons. The
[history contract](source-coverage-history-contract.md) makes those finite horizons
and unavailable-retry outcomes explicit. Its retained ID/content identity and
history need bounded storage and retention. The separate
[`signal-coverage` library](../crates/signal-coverage/README.md) implements prepared
append/recovery, trusted intake/retry and immutable correction admission. Prefix
pruning and distributed fencing remain unimplemented.

## Structural bounds and required semantic checks

| Bound | v1 contract |
| --- | --- |
| Serialized record | At most 65,536 UTF-8 bytes at admission, including supplied whitespace |
| Text fields and scope attribute keys/values | At most 1,024 UTF-8 bytes; schema character limits are only a first bound |
| Gap entries / proof references / scope attributes | At most 128 / 32 / 16 |
| Gap total | Null or integer in `[0, 2^53-1]`; null is permitted only with explicit truncation |
| Timestamps | UTC `Z`, year 0001–9999, ordinary seconds 00–59, optional 1–9 fractional digits; calendar-valid, compared at nanosecond precision |
| Profile budgets | Interval/verification-age 1–86,400 seconds; clock skew 0–300 seconds; actual profile chooses tighter values |

Reject duplicate JSON keys, invalid UTF-8, non-finite numbers, malformed timestamps
and over-limit wire input before trusting a record. Do not silently truncate
strings/lists or strip/change checkpoint values. Source positions containing binary
data require an adapter's stable textual encoding; references must not embed
credentials or presigned access tokens. Schema success does not perform these
semantic, byte or trust checks.

The validator implements the following rules, in this order:

1. Bound/decode input; apply the structural contract and calendar/UUID/text checks.
   Resolve the exact immutable profile through trusted configuration. It always
   requires configuration, scope and continuity; source integrity may additionally
   be required. Missing/unsupported profile revision yields `profile_unavailable`.
2. Require `coverage_start < coverage_end <= last_verified_at < valid_until`.
   The coverage interval and expiry duration must fit the profile's respective
   interval/verification-age budgets. Verification time and a non-null data-arrival
   time must be no later than provenance observation time. Provenance is when this
   report was assembled; it may be after expiry. A later data arrival/report never
   advances the retained verification time or expiry without a new verification.
   Compare integer nanoseconds; do not round fractional seconds or use floats.
3. Require every gap's scope to equal the record scope, and its start to lie in
   the covered interval. A finite gap end satisfies `start < end <= coverage_end`;
   null denotes a gap still open, clipped to this record's interval for assessment.
   Gap IDs are distinct. An unrecovered gap prevents continuity from being
   `verified`; its positive loss evidence belongs in `failed`, uncertainty in
   `unknown/partial`. `recovered` needs referenced recovery evidence and rechecked
   continuity, never deletion of the previous failed/unknown observation.
4. With `truncated=false`, total equals the number of listed gaps. With
   `truncated=true`, total is null or strictly greater than listed count; omitted
   details never permit a verified summary. Truncation degrades to at least partial
   unless another required result is unknown/unsupported/failed.
5. Derive the summary: any **failed** component, even an optional integrity check,
   yields failed. Otherwise required components reduce in precedence
   `unknown > unsupported > partial > verified`; include truncation as partial.
   Optional unsupported/unknown components remain explicit but do not reduce a
   profile that does not require them. Reject a supplied summary that disagrees.
6. Verified coverage has at least one proof reference and, when its profile
   requires it, a non-null checkpoint. Referencing a proof does not validate its
   contents; a trusted provider must establish the component claim separately.

Rejected candidates cannot become verified assessments. Preserve their reason
and degradation through the future intake/observer mechanism. Do not replace a
valid historical record with malformed new content or report an empty clean result.

## Current and historical assessment

The fixture context is a proposed consumer input, not a public HTTP API. It
contains the requested binding and interval, trusted profile/observer identity,
consumer observation clock, observer health and mode (`current` or `historical`).
Its expected result is a coverage status plus bounded reason codes. Detection
`match/no_match/indeterminate` is a separate decision using those preconditions.

Apply assessment guards before interpreting the component summary:

1. Missing trusted profile produces unknown/`profile_unavailable`; a rejected
   record produces unknown/`invalid_record`. Requested binding or observer identity
   mismatch produces unknown/`binding_mismatch` or `observer_mismatch`.
2. Verification later than the consumer clock plus profile clock-skew allowance
   produces unknown/`verification_in_future` in either mode.
   Report observation later than that allowance produces
   unknown/`observation_in_future` after the verification guard.
3. For **current** mode, unhealthy or unknown observer health overrides the summary
   to unknown. At `at >= valid_until`, return unknown/`expired`; equality is expired.
   Retries/replayed telemetry do not change verification time or expiry.
4. For **historical** mode, current expiry/observer health do not erase a previously
   trusted interval assertion. Profile, binding, identity, record validity and
   evidence authority still apply. Historical verified means the profile's stated
   preconditions held for that interval, not that the source is healthy now.
5. No overlap with the requested interval gives unknown/`interval_uncovered`.
   Partial overlap cannot produce verified for the entire request: degrade a
   verified base to partial/`interval_partial`, preserving more severe base
   uncertainty/failure. Complete containment uses the validated summary, with
   component failure/unknown/unsupported/partial or truncation reasons as applicable.

Fixture v1 returns zero or one primary reason in `reason_codes`: the first
failing guard wins. For a contained interval, summary reasons reduce in order
`component_failed`, `component_unknown`, `component_unsupported`,
`gap_details_truncated`, `component_partial`; verified has no reason. Additional
diagnostics may be retained separately without changing that primary result.

These statuses can support a finding from valid positive evidence during a gap;
they cannot support a negative detection claim that needs a missing component.
An observer outage is not proof of collector failure, and collection failure is
not proof of host compromise. A newly arrived log changes `last_observed_at`, not
configuration, continuity or probe freshness.

## Transition expectations and retained history

| Sequence | Expected current coverage | Historical requirement |
| --- | --- | --- |
| `quiet_gap_recovery` | verified → failed → verified for a later interval | Original failed interval remains failed |
| `observer_outage_recovery` | verified → unknown health → unknown gap → newly verified | Observer-blind interval remains unknown |
| `expiry_and_replay` | verified → unknown at expiry → unknown on replay/late arrival | Original interval assertion remains available |
| `profile_strengthening` | basic verified → unknown mismatch → signed unsupported → signed verified | Basic assertion is not silently promoted to signed coverage |
| `configuration_change` | verified → unknown for changed binding → newly verified | Earlier revision's record remains unchanged |
| `truncation_and_recovery` | partial → verified for a later interval | Earlier omitted gap detail remains partial |
| `telemetry_is_not_a_probe` | unknown → unknown despite telemetry | An event never establishes missing capture preconditions |

Each sequence names immutable record fixtures, assessment contexts and retained
record IDs. Recovery appends a new observation/interval. Historical gap detail is
retained independently rather than copying all previous gaps into every record.
If later backfill proves a former interval recovered, append a referenced correction
observation and preserve the original; correction resolution/retention is a future
store contract, not permission to overwrite history.

The initial semantic-rejection fixtures cover interval/calendar errors, verification
and expiry timing, inconsistent summary, missing proof/checkpoint, gap scope/count,
truncation, UTF-8/wire overflow, nil ID and unresolved profile. Duplicate-ID content
conflict, trusted transport, receiver checkpoints, bounded source cardinality,
durable observer-gap storage and fencing need additional store/intake acceptance.

## SDK API and accepted evidence boundary

`signal_collector_sdk::coverage` exposes immutable `CoverageProfile`,
`CoverageContext` and `ValidatedCoverage` types through bounded `parse` methods.
The application resolves one exact trusted profile, supplies trusted consumer
context and retains typed `CoverageError` details when rejecting an assertion.
`ValidatedCoverage::assess` evaluates a previously validated immutable assertion;
`assess_coverage(bytes, profile, context)` accepts raw candidates and returns an
unknown assessment for rejection or unavailable profile. A missing trusted profile
wins before malformed-input assessment. `CoverageAssessment` serializes version 1,
status and zero/one reason. There is no fallback profile or authority inferred from
JSON names. Profile/context inputs also have the 65,536-byte parser ceiling.

The parser uses closed [Serde structs](https://serde.rs/container-attrs.html)
and a [custom map visitor](https://serde.rs/deserialize-map.html) to reject duplicate
keys, including escaped scope-key aliases. Required nullable fields reject omission.
Lexical UTC/calendar guards precede [Chrono parsing](https://docs.rs/chrono/latest/chrono/struct.DateTime.html#method.parse_from_rfc3339);
timestamp/duration comparisons preserve nanoseconds over years 0001–9999 without
converting epoch nanoseconds to an overflowing `i64` or rounding seconds.

The module performs finite synchronous work on bounded borrowed wire input; it
opens no files/sockets, spawns no workers and stores no history. There is no new
dependency, event field, server endpoint, detection behavior or service process.
Full local Linux AMD64 acceptance passed formatting, strict all-target Clippy,
255 workspace tests and the 12-package boundary guard. Evidence and focused
self-review are retained at `target/source-coverage-validator-20261007/`.

The [bounded intake/history contract](source-coverage-history-contract.md) is now
written with 56 planned storage cases and offline rejection guards.
[ADR-015](adr/015-source-coverage-store.md) now records the bounded local SQLite
library, frozen format/prefix vectors and actual process-crash, quota, corruption
and cancellation acceptance. The complete history state machine remains
unimplemented. Trusted local application-grant intake and exact-byte original
receipt replay and bounded correction admission now pass 45 focused library tests.
Payload-prefix pruning is next; identity pruning and scans follow separately.

An observer, complete durable coverage history, source adapter, server API, detection negative
assessment and independent security-account reporting remain later tasks. Native
ARM64, EKS, remote CI, released dependencies and publication remain gated by
[release readiness](21-release-readiness.md). This contract is generic; real scopes,
profile configuration, evidence access and response policy stay private.

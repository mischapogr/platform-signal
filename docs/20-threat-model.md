# Threat model and bounded hardening (Phase 10)

This model covers the current monolith, file/stdin agent, canonical event contract,
URL queries, stateless rules, durable findings and trusted external SDK providers.
It describes Linux AMD64 local mechanisms. Native ARM64 qualification, EKS,
release publication and customer deployment acceptance require their own evidence.
It does not assert that an entire deployment or dependency tree is vulnerability
free.

## Assets and trust boundaries

Protect accepted event durability, event identity/precision, findings, availability,
API tokens, source cursors and private event metadata. The HTTP 202 boundary means
a synced WAL admission, rather than completed queries or detections. Consumer
ordering is event publication → rule evaluation → finding persistence → WAL
checkpoint. Crash replay is at least once; deduplication and deterministic finding
identity make repeat publication safe.

An HTTP client or collected line can supply hostile bytes. Validation, byte/count
limits and admission deadlines apply before publication. A shared optional Bearer
token authenticates data API access when configured; it provides no tenant
identity, roles or per-source authorization. It is possible to run without a
token. The server speaks HTTP directly, so transport encryption must be provided
by an appropriately configured trusted edge or network. Authentication alone does
not prevent interception on a plaintext network. Health, readiness and metrics
are operational endpoints without the data API token requirement; restrict their
network reachability, including the optional separate metrics listener.

Rules and configuration are trusted operator inputs whose syntax and resource
cost are nevertheless bounded. YAML is declarative data: there is no expression
interpreter, shell command or SQL interface. Filesystems, mounts and their owners
form another boundary. Regular-file checks, exclusive locks, restricted spool
creation modes and container security settings protect specific local operations;
they do not protect data against a privileged host or storage administrator.
CRC detects accidental corruption and incomplete records; it is not a keyed MAC,
signature, encryption or defense against deliberate rewrite by a storage owner.

SDK collectors/enrichers/providers are trusted cooperative code in the process.
Their deadline and cancellation contexts cannot preempt code that blocks the
runtime, lies about cancellation, allocates outside the SDK budget or starts its
own unmanaged work. There is no plugin sandbox. Cancellation does not roll back
external side effects; a collector may already have admitted an event. Use the
supported wrappers and honor cancellation inside provider I/O.

OSS supplies mechanisms. Policy, environment identities, private metadata schemas,
detections, alert routing and fixtures stay in the external application. Attribute
values can still contain confidential data. Event storage, backups, logs captured
by surrounding systems, API responses and overlay deployment settings require
operator access control and retention decisions; there is no built-in encryption
at rest or multi-tenant isolation.

## Threats, controls and verification

The table names source tests and gates that exercise each mechanism. It does not
turn a source test into production environment proof. Root workspace gates and
independent review determine the consolidated acceptance status in
[07-progress.md](07-progress.md).

| Threat | Implemented boundary/control | Concrete verification |
| --- | --- | --- |
| Unauthorized ingestion/query or credential forwarding | Optional Bearer authentication, duplicate Authorization rejection, constant-time token comparison; agent redirects disabled | `crates/signal-ingest/tests/http.rs`: `optional_authentication_rejects_missing_wrong_and_duplicate_credentials`; `apps/signal-agent/src/http.rs`: `redirect_never_receives_token_and_cancel_interrupts_request` |
| HTTP body, stream, connection or concurrency exhaustion | Bounded request bodies/batches/connections/admission, body/idle deadlines and cancellation | Ingest `oversized_fixed_and_streamed_bodies_and_batch_counts_are_rejected`, `stalled_body_and_request_concurrency_are_bounded`, `connection_capacity_idle_deadline_and_shutdown_release_sockets` |
| Crafted event JSON, unknown schema, invalid UTF-8 or silent numeric loss | Strict envelope/version validation, JSON parse rejection, arbitrary-precision attributes and canonical serialization | `crates/signal-event/tests/phase10-properties.rs`: `bounded_invalid_wire_and_semantic_errors`, `seeded_nested_attributes_and_precision_roundtrip`; storage `tests/codec.rs`: `roundtrip_preserves_nested_numbers_optionals_and_negative_nanosecond_time` |
| Raw payload or token leaked through diagnostics | Static event semantic/rule/query errors, sanitized ingest responses, bounded server logging; credentials excluded from config Debug | New event/rule/query diagnostic campaigns; server config `strict_schema_null_duplicate_types_and_static_redaction`; agent HTTP `unauthorized_retains_every_event_without_echoing_secret`; process gates inspect secret sentinels |
| Query injection, encoded duplicate keys or type confusion | URL parameter allowlist; strict percent/UTF-8 decoding, decoded-name duplicate rejection, exact JSON types and bounded paths | `crates/signal-protocol/tests/phase10-properties.rs`: `seeded_url_transport_preserves_filter_types_and_precision`, `adversarial_url_dictionary_fails_with_static_diagnostics` |
| Query memory, compressed input, file scan or response exhaustion | Filter/result/file/memory budgets, bounded I/O workers and queue, partition pruning, cancellable deadlines; no spill | Query `configured_limits_bound_response_count_bytes_and_candidate_files`, `shared_memory_pool_exhaustion_has_no_spill_and_recovers`, `compressed_scan_input_is_rejected_before_datafusion_decoding`, `caller_dropping_query_future_releases_admission` |
| YAML aliases, tags, duplicate keys, deep values or rule-count exhaustion | Parser node/depth/scalar/document budgets, anchors/aliases prohibited, strict rule schema, duplicate IDs rejected before readiness | `crates/signal-rules/tests/phase10-properties.rs`: `yaml_dictionary_limits_duplicates_and_schema_are_safe`; existing `invalid_documents_fail_without_echoing_yaml` |
| Detections changed by missing/null or boolean group ambiguity | Typed predicates, absent-field semantics, deterministic `all`/`any` conjunction and finding identity | New `seeded_predicates_match_independent_truth_model`; existing `missing_and_null_are_distinct`, `replay_findings_and_sorted_multiple_rules` |
| A corrupted WAL is mistaken for an incomplete final write | Record/header CRC and sequence checks; only incomplete final tail can be truncated; corrupt interiors fail closed | `crates/signal-buffer/tests/phase10-properties.rs`: `seeded_crc_and_checkpoint_mutations_fail_without_destroying_evidence`, `every_final_record_cut_preserves_complete_prefix_and_reuses_sequence`; recovery `interior_truncation_missing_segment_and_missing_checkpoint_fail` |
| Checkpoint corruption, early acknowledgement or replay loss | Validated atomic checkpoint; acknowledgements require delivered records; replay complete unacknowledged prefix | New `ack_prefix_replay_and_reclaim_match_durable_sequence_model`; pipeline `finding_quota_after_parquet_publish_never_acks_and_replays_both_stores`, `publication_before_ack_restarts_without_duplicate_rows` |
| Storage write failure after durable admission | Publication failure exits the process before WAL acknowledgement; replay retains admitted work | `tests/integration/foundation.rs`: `storage_os_create_failure_preserves_admitted_events_until_replay`, invoking `phase10-storage-process.py`: real `EEXIST` on a precreated unpublished Parquet temporary file, durable 202, checkpoint remains zero, sentinel unchanged/no published Parquet; remove only the owned blocker, then exact event/finding replay with checkpoint one and another clean restart |
| Resource exhaustion or caller cancellation leaves workers unaccounted | Bounded memory/disk/queues/spool and physical worker permits retained until completion; default `reject_new`; drops counted for explicit alternative policy | WAL `reject_new_count_byte_disk_and_segment_quotas_preserve_accepted_events`; agent spool `real_disk_record_index_and_event_quotas`, `cancellation_keeps_physical_worker_permit_until_completion`; server `stalled_consumer_has_one_shutdown_budget_and_keeps_wal_replayable` |
| Source rotation, partial lines or retries lose or change event identity | Durable cursor/spool, bounded file input, verified accepted-prefix HTTP acknowledgements, retry retained suffix | Agent input `partial_lines_restart_and_rotation`, `copytruncate_regrow_and_oversize_are_bounded`; spool `cursor_only_checkpoint_does_not_rewind_on_pending_replay`; HTTP `partial_retry_preserves_suffix_ids_and_order`, `malformed_success_has_no_acknowledgement` |
| File path/symlink substitution, shared spool or excessive container privileges | Regular-file/lock checks, owned spool modes; runtime non-root, read-only root, writable data mount, capabilities dropped | Agent spool `lock_symlink_and_unowned_directory_refused`; findings `symlinks_are_rejected`; `scripts/check-container.py` and actual kind persistence/restart gate |
| Extension failure mutates event identity or imports private policy into OSS | Transactional clone/validate/commit enrichment; immutable identity checks; explicit external providers and bounded documents | SDK `all_extension_failures_leave_caller_event_unchanged`, `public_enricher_preserves_version_identity_and_arbitrary_numbers`, `provider_failures_cancellation_timeouts_and_invalid_limits_are_static`; `scripts/check-workspace.py` and external-overlay process gate |
| Vulnerable dependencies or substituted scanner artifacts | Locked Cargo dependencies; checksum-pinned tool releases, Cargo and final-image SPDX inventories, fresh public advisory checks and unsigned artifact digests | `scripts/check-supply-chain.py`; [18-supply-chain.md](18-supply-chain.md); final Phase 8 report directory and image ID in progress evidence |

Typed parser diagnostics are static where the API contract promises it. Raw
Serde errors may include input details and must not be passed through to logs or
HTTP responses. The event semantic test exercises `SignalEvent::validate`;
it does not claim that arbitrary library error formatting is safe to publish.

## Deterministic campaign and limits

Run the fixed campaign without downloading test corpora or adding dependencies:

```bash
python3 scripts/check-hardening.py
```

The orchestrator imposes a five-minute Cargo subprocess deadline, then terminates
its owned process group, escalates surviving children to SIGKILL and reaps Cargo
with bounded cleanup waits. The regression `python3 scripts/test-hardening.py`
starts a parent and sleeper that ignore SIGTERM, verifies both die and are reaped,
and verifies an unrelated process survives. The orchestrator saves a
command, elapsed time, exit status, seeds, test-source SHA256s, log SHA256 and
observed WAL case counts under ignored `target/phase10-hardening/<timestamp>/`.
Every generated input is at most 64 KiB. Loops are finite and seeds are fixed;
the tests neither choose counts from the environment nor run an open-ended fuzz
loop. Tests use real temporary WAL directories, fixed record/memory/disk limits
and two-second WAL operation deadlines. Temporary directories are owned by each
test and removed when the fixture drops.

The event generator varies nested objects/arrays, null/booleans/text and large
JSON integers through 512 canonical roundtrips. The URL generator runs 512 typed
attribute/filter transports and encoded duplicate-name rejections. The rule
campaign evaluates 512 generated rule/event pairs against an independent boolean
truth model, including missing `neq`, missing `exists`, null equality and combined
`all`/`any`. Fixed dictionaries additionally exercise malformed bytes, truncated
JSON/YAML, schema versions, timestamps, invalid severity/order, broken encoding,
path/depth limits, prohibited YAML anchors/tags and duplicate rule IDs.

WAL tests mutate every segment/first-record header byte plus 64 seeded payload
positions and every checkpoint byte; every corrupt fixture must fail without
truncating the damaged evidence. They enumerate every incomplete position of the
final record, preserve the two complete earlier canonical events exactly, and verify the replacement record reuses only the lost tail sequence.
Nine acknowledgement prefixes prove that restarts recover exactly the
unacknowledged suffix, then reclaim all fully acknowledged segments. External
truncation is simulated damaged storage; this test does not claim that deleting
an already accepted record is harmless or that a host filesystem cannot lose
synced writes.

These are finite deterministic property and mutation campaigns, without a
coverage-guided fuzzing engine, coverage percentage, exhaustive input-space claim
or ARM64 execution claim. An accepted invalid-JSON attribute spelling remains a
plain string by the documented query contract; the campaign verifies this
fallback rather than treating it as typed nested JSON.

## Residual risks and evidence limits

The final Phase 8 local scan reports zero HIGH/CRITICAL container occurrences,
23 MEDIUM and eight LOW occurrences; Cargo audit reports zero known security
advisories. These snapshots do not establish zero vulnerabilities. Retain the
actual image ID, fresh database metadata and unfiltered reports; reevaluate when
the image, dependencies or databases change. Signed releases, builder identity
attestation and released SDK dependency integration remain separate gates.

The current server does not implement native TLS, OIDC/RBAC, tenant isolation,
per-publisher rate limits, signed rule/config bundles or encryption at rest.
Network controls, TLS termination, token custody/rotation, monitoring access,
filesystem/PVC permissions and backups remain deployment responsibilities.
Resource quotas bound application-owned use, without establishing free-space or
availability guarantees on shared host disks. A privileged host, a compromised
operator or non-cooperative in-process provider can defeat this threat boundary.

A malformed rule is rejected; a syntactically valid incorrect rule can still
create false detections or omit real ones. The private application owns policy
review and acceptance. Deterministic finding IDs and replay do not create an
exactly-once external alert delivery guarantee. Kubernetes local restart proof
is distinct from EKS deployment, service exposure, IAM/network policies, backup
recovery and production load qualification.

The 2026-10-06 Linux AMD64 campaign passed all nine tests in 15.971 seconds.
Observed WAL counts: 104 record/segment mutations, 28 checkpoint mutations,
303 final-record cut positions and nine acknowledgement-prefix cases. The three
seeded event/URL/rule loops each completed 512 cases. Report and test-source
hashes are in `target/phase10-hardening/20261006T185925.121730Z/campaign.json`;
log SHA256 is
`a81b47982f2541ef3100a25284d96268043a9a60d928420bf027b91c2621dce4`.
This is local campaign proof; consolidated workspace and source-review gates
remain recorded separately.

The real storage process gate also passed on Linux AMD64: a precreated owned
Parquet temporary file caused the kernel `EEXIST` failure after durable HTTP 202.
The process failed closed with WAL checkpoint zero and the sentinel intact.
Repairing only that file allowed the unchanged WAL identity to replay the exact
event and corresponding finding, advance checkpoint to one, and preserve both
through another SIGTERM/restart. The consolidated workspace run passed 227 tests;
its command and scope are recorded in `07-progress.md`.

# Findings cursor contract proposal

**Status:** Implemented and locally accepted, 2026-10-08. Version-1 public
feed acceptance is recorded in `target/goal-execution-20261007/FINDINGS-CURSOR/validation.json`.
Private consumption and destination delivery remain their separate OUTBOX item.
Existing journal/finding/list contracts are preserved; release gates remain open.

A consumer needs to read every durable finding without relying on event time.
The feed returns bounded pages in durable append order, with a cursor
that identifies a consumed history prefix. A stream ID and position identify
where to continue; a digest of that prefix detects divergent history after
restore. The server owns no consumer acknowledgements or delivery destinations.

## Existing journal and compatibility

The existing [findings contract](14-phase5-core.md) lists findings in ascending
`(created_at, id)` order. Creation time is the event's observed time, so a late
event can produce a finding behind a timestamp watermark. The list has a limit
and filters but no page continuation.

The [journal worker](../crates/signal-findings/src/store.rs) appends framed JSON
behind a WAL-bound stream header. It syncs a batch before exposing its indexed
findings. New records within a batch are currently written in finding-ID order.
Identical finding identities/content are deduplicated; conflicting content
fails closed. Recovery scans file order, validates frames and findings, and can
truncate an incomplete final frame. It can encounter complete duplicate frames
and excludes them from the unique finding index.

The feed reconstructs first-unique append positions from this journal,
preserving existing bytes. This avoids a required disk-format change for the
initial implementation. It uses bounded index accounting, recovery
synchronization, protocol types, handler wiring and tests. Existing images and
runtime campaigns do not qualify those changes.

## Position and history identity

For a store stream `S`, define `F1` through `FT` as the first persisted occurrence
of each unique finding, in physical journal order. Position `n` is a count of
these occurrences, not a byte offset, WAL sequence, timestamp or finding ID.
Position zero is the prefix before any finding. All positions use checked
unsigned 64-bit arithmetic; overflow fails closed rather than wrapping.

Identical duplicate frames and identical replay appends allocate no new
position. Finding-ID/content conflict remains an error. Once readable, positions
never change within the retained journal history. This order makes no claim
about source arrival or detection importance.

Define a SHA-256 prefix digest using the exact first-occurrence journal payload
bytes. Domain strings below are fixed UTF-8 bytes without a terminating NUL:

```text
H0 = SHA256("SIGNAL-FINDINGS-CURSOR-V1" || S)
Hn = SHA256("SIGNAL-FINDINGS-RECORD-V1" || H(n-1)
            || u64be(n) || u32be(payload_length) || payload_bytes)
```

`S` is the 16 raw UUID bytes; digest values are 32 raw bytes. The payload excludes
the frame header and includes its original JSON encoding. Recovery must not
reserialize old records to compute this digest. Complete identical duplicate
frames are validated but do not enter the chain. Each distinct first occurrence
advances both the logical position and digest.

The version-1 opaque token encodes these fixed fields:

| Field | Width |
| --- | ---: |
| Cursor version, value 1 | 1 byte |
| Store stream UUID | 16 bytes |
| Consumed prefix position, big endian | 8 bytes |
| Digest of that prefix | 32 bytes |

The 57-byte token uses canonical unpadded URL-safe Base64, producing 76 ASCII
characters. Reject noncanonical encoding, padding, unsupported versions and
incorrect field lengths. Clients store the returned string unchanged and do
not construct, decode or increment it.

A token is a history reference, not an authentication credential or signed
attestation. Its digest is unkeyed and does not authorize access. Authenticated
readers can deliberately choose their own starting progress; the server does
not enforce an exactly-once consumer history. Filesystem ownership remains
within the existing trusted-host boundary.

## HTTP interface

Add a separate bounded read at `GET /v1/findings/feed`. Preserve the existing
`GET /v1/findings` route and its ordering and filters.

| Parameter | Meaning |
| --- | --- |
| `after` | Required: a previously returned opaque cursor, or the explicit bootstrap value `begin` |
| `limit` | Optional positive result bound; default `min(100, configured query-row maximum)`; cannot exceed that maximum |

The initial `after=begin` selects position zero in the current stream. It never
selects the current tail. A stored continuation must not be replaced by `begin`
automatically after a cursor error. Unknown, duplicate, empty, malformed or
over-limit parameters are rejected. Time, severity and rule filters are not
part of this feed: routing and selection happen after durable consumption.

The success envelope is:

```json
{
  "schema_version": 1,
  "findings": [],
  "next_cursor": "<opaque cursor>",
  "has_more": false
}
```

For a validated input cursor at position `p`, capture the readable tail `T` at
the start of the worker operation. Return a contiguous nonempty prefix of
`F(p+1)` through `FT` when records remain and the first record fits the budgets.
Stop at the requested count or resource budget. The next cursor references the
last returned position; `has_more` means records remained through captured tail
`T`. It describes that read only. New appends may arrive immediately afterward.

At `p = T`, return an empty page, the canonical input cursor and `has_more=false`.
For bootstrap on an empty store, return the position-zero cursor. Clients poll
that same cursor after an empty page; empty does not mean permanently complete.
This is an ordinary bounded HTTP request, with no long polling or new streaming
transport.

A retry from the same cursor cannot skip a finding. Its page boundary can vary
as the tail grows or the requested limit changes, but it always starts with the
same next finding while the referenced prefix and suffix remain available.
There is no tail shortcut or server-side progress mutation.

## Cursor validation and failures

Authenticate and validate transport bounds before dispatching store work. Then
validate token syntax/version, stream identity, available position and prefix
digest. All errors contain static messages and no cursor, finding or token
content. The feed error envelope carries `schema_version: 1` and an
`error` with a stable `code` and static `message`; it is separate from ingest
admission counts and changes no existing response envelope.

| HTTP status | Code or condition | Consumer action |
| --- | --- | --- |
| 400 | `invalid_query`, `invalid_cursor`, `unsupported_cursor_version` | Correct the request or use a compatible client; preserve stored progress |
| 401 | Missing or invalid configured authentication | Restore authorized access; preserve progress |
| 409 | `cursor_stream_mismatch` | Reconcile which store/history the consumer is attached to |
| 409 | `cursor_position_unavailable` when `p > T` | Reconcile lost history or the selected backup |
| 409 | `cursor_history_mismatch` when the prefix digest differs | Stop consumption and reconcile divergent history |
| 413 | `page_budget_exceeded` when the next finding cannot fit | Correct the resource budget; never skip that finding |
| 408, 429, 503 | Deadline, bounded capacity, unavailable store or shutdown | Retry with capped backoff from the saved cursor |

For all failures, return no success page and no replacement cursor. A partial
HTTP body, malformed response or schema/version mismatch grants no progress.
Journal corruption fails store recovery or closes the store; it is not a reason
to issue a cursor against whatever records remain readable.

## Durability and resource limits

Publish a newly appended position/digest only after the corresponding finding
bytes are synced. If append or sync has an uncertain outcome, fail closed using
the existing worker ownership rules. Reopening validates every complete frame,
truncates only an allowed incomplete final frame, rebuilds positions/digests,
and syncs the validated retained journal before exposing the recovered feed.
Complete frames left by a crash before a previous sync must not bypass this
recovery synchronization step. A completed disk sync has the same filesystem
and hardware evidence limits as the existing persistence contract.

Keep feed commands under existing finite command/operation permits and explicit
deadlines/cancellation. A physical disk syscall may finish after its caller
times out; retain its permit and store ownership until it actually completes.
Reading advances no consumer state, and cancellation must not start detached
workers or close a healthy store as though the read were an uncertain mutation.

Charge the recovered append-order index and every stored prefix digest against
the index budget before allocation. Rebuild it in a single bounded journal scan;
requests use indexed position lookup and bounded page reads rather than hashing
the complete journal again. No persistent side index is required by this design.
The larger index charge can reject a previously full store under unchanged
limits, so upgrade preflight must calculate the required budget explicitly.

Apply both a serialized response-byte bound, including envelope and cursor, and
conservative live-memory accounting. Reserve record decoding and response
construction before doing the work. Account for all concurrent operations,
temporary buffers and queues. Share the existing query row/byte limits in the
first implementation; validate that the empty envelope is representable.

If adding the next finding exceeds a budget after at least one finding was
selected, return the selected prefix and `has_more=true`. If even the first
finding cannot fit, return 413 with unchanged progress. Never return an empty
success page with `has_more=true`. Do not allocate a full response before checking
its limit. Shared-worker saturation, append latency under readers, depth/capacity
metrics and rejection counts need focused acceptance.

## Restart and restore traces

Let `C(n)` be the opaque cursor for the first `n` findings. Letters below denote
generic distinct findings; their event timestamps are irrelevant to feed order.

| Trace | Required outcome |
| --- | --- |
| Append A and B; read one from `begin` | Return A and C(1), with `has_more=true` |
| Restart; continue C(1) | Return B at the same position as before restart |
| Re-append identical A and B | No new positions or feed records |
| At C(2), append C with an older observed time | Return C on the next read despite its old timestamp |
| Many findings share one observed time | Continue through all pages without timestamp arithmetic |
| Read a page, lose its response | Retry the saved cursor; no server acknowledgement has occurred |
| Restore a backup ending at A; supply C(2) | Reject unavailable position until the consumer reconciles history |
| Restore A, then append D at position 2; supply old C(2) | Reject different prefix even though stream and position match |
| Restore a byte-identical consumed prefix ending at A; supply C(1) | Accept; it references the same consumed prefix |
| Move an identical offline store to another path | Cursor remains valid; path is not history identity |
| Connect to another store stream | Reject wrong stream even if its finding count matches |
| Incomplete final frame on recovery | Preserve complete findings; truncate only the incomplete frame; rebuild and sync before feed readiness |

A cursor proves consistency of its referenced prefix under the chosen digest;
it cannot prove preservation of an unseen suffix. If a client consumed only A,
restoring A and replacing an unseen B with D still leaves C(1) valid. It also
cannot detect a rollback where lost history is reconstructed byte-identically.
Private backup/delivery reconciliation must handle these cases. Two writable
clones sharing a stream are outside this single-writer design; identical prefix
tokens are not a fencing mechanism.

The first implementation supports retained append-only history only. It neither
prunes records nor compacts/reorders the journal. Future retention or migration
must preserve consumed-prefix validation or explicitly invalidate incompatible
cursors. It must never silently map a missing cursor to the current tail.

## Consumer progress and upgrades

The private delivery worker durably commits the complete page's delivery plan
and `next_cursor` in one crash-safe transaction before using the cursor for
further reads. Its plan fixes routing and destination identities. Progress means
the consumer owns recoverable work, not that external delivery succeeded. A
full private backlog stops reads without changing server acknowledgement or
deleting findings. Multiple consumers keep independent progress.

The cursor version, response schema, finding schema, journal format and package
version are separate contracts. Preserving the existing journal means old
cursor-free binaries can still read its bytes, subject to the qualified
[upgrade policy](../UPGRADING.md). They do not expose this feed. Clients must
pause on an unavailable feed after rollback and retain their cursor; they cannot
fall back to timestamp polling with the same completeness guarantee.

Qualify dependency versions, index budgets, server backup and private consumer
backup together. A server restore does not automatically restore delivery
state, and restoring delivery state does not undo external effects. Repeated
pages or source admissions require the private stable delivery identities and
destination-specific deduplication from the integration proposal.

## Implemented acceptance and upgrade limits

The public feed uses protocol types in `signal-protocol`, indexed reads on the
existing findings worker, and monolith route wiring in `apps/signal-server`.
Eighteen new protocol/store/HTTP/real-process checks pass, together with default
557/all-feature580 tests, formatting, strict all-target Clippy and the 13-package
boundary guard. Independent review has no unresolved blocker/high. Evidence:
`target/goal-execution-20261007/FINDINGS-CURSOR/validation.json`.

Three map indexes are conservatively charged at `FINDING_INDEX_BYTES = 512` per
unique finding before allocation. Upgrade preflight needs `unique_findings * 512`
index bytes (checked arithmetic), within the configured finite ceilings. The
default 16 MiB index admits 32,768 unique findings, subject to earlier quotas.
The journal format remains unchanged; an undersized index fails startup without
exposing a partial history. Old binaries cannot serve the new feed; clients retain
their cursor on rollback and do not fall back to timestamp watermarks.

Feed-enabled server startup calls `FindingConfig::validate_feed`: query memory
must be at least 288 bytes, twice the 144-byte empty wire envelope. Cursor-free
library use still supports smaller preexisting budgets; a feed call under such
limits fails without progress. Page reads precharge conservative record decoding,
vector/JSON allocations and output before reading, and preallocate final output
to its counted complete upper bound. Actual encoded output has a separate caller
cap, limited by the configured query budget. Returned buffers require caller
concurrency budgeting; HTTP uses existing finite connections/lifetimes. Requested
frames verify CRC, exact-byte prefix, finding ID and contract before return.

These checks are local Linux AMD64 evidence, with generic owned fixtures. Native
ARM64, actual EKS, remote CI, released dependencies and publication remain open.
No continuous whole-history tamper scan, consumer ACK, pruning, unseen-suffix
rollback proof or distributed fencing is claimed.

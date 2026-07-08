# SourceCoverage intake and bounded history

Status: PS-01 design/fixture contract, 2026-10-07. The
[pure v1 validator](source-coverage-contract.md) and bounded local persistence
primitives and trusted application-grant intake/retry are implemented.
[ADR-015](adr/015-source-coverage-store.md) records prepared append, immutable
receipts, recovery, full-binding authorized reads, original-byte replay and bounded
correction admission and bounded payload/identity-prefix pruning. Scans
and source observers remain **unimplemented**;
the complete 56-outcome state machine remains planned. This
contract selects responsibilities and acceptance. The local backend and
exact encodings are selected in ADR-015;
there is no new endpoint or split of `signal-server`.

## Identity and authority

An observation is immutable: one non-nil UUID and the **exact original UTF-8 JSON
bytes**, including whitespace and key order. The producer prepares bytes once and
retains them across retries. Semantically equivalent reserialization is different
content. Store `SHA256(raw_bytes)` for diagnostics/integrity; compare actual bytes
for replay while they remain available. A hash alone is not an exact-byte replay
decision. Receipt metadata and correction links are immutable too.

The application supplies an authenticated observer and an authorized full binding:
source, collector, exact scope, stream, profile ID/revision and configuration
revision. Observer identity joins that binding to form the bounded history key.
The existing Bearer token, record names and proof URIs do not establish this
authority. Resolve and pin the exact trusted profile for each new observation;
record its fingerprint and the authority revision at admission. Authorization is
checked on reads and retries as well as new writes. Never disclose another scope's
payload or receipt through an ID conflict.

Keep the pinned profile definition with retained history, inside bounded metadata
accounting. The trusted catalog supplies stable prepared canonical definition bytes; a
different fingerprint under a retained ID/revision is `profile_revision_conflict`.
Readers resolve that exact definition before SDK assessment; a similarly named
replacement must not reinterpret old evidence. ADR-015 freezes the fingerprint
encoding/vectors. These retained pins do not promise lifetime detection of
profile-version reuse after all corresponding history is pruned.

Record IDs are unique across retained history, not just within a source key.
Changing source/configuration/profile/observer requires a new record ID and
verification. The full binding normalizes omitted scope attributes to `{}` and
otherwise uses exact equality; no wildcard or subset membership follows.

## Proposed operations and receipts

These are logical application operations, not new SDK functions or HTTP routes.

| Operation | Result and limit |
| --- | --- |
| `submit(record_id, raw_bytes, correction_of, trusted_context)` | New durable receipt, identical replay, or typed rejection/uncertainty |
| `retry(receipt, raw_bytes, correction_of, trusted_context)` | Validate referenced history/position and original submission; never turn an expired/missing retry into a new write |
| `get(record_id, trusted_context)` | Retained original bytes/receipt, explicit payload-pruned result, or record unavailable; absence is not a negative detection |
| `scan(binding, cursor, limit, trusted_context)` | Bounded append-order page and explicit continuation/retention state; no health aggregation |

A version-1 receipt contains `history_id` (non-nil UUID), `sequence` (canonical
decimal string in `[1, 2^64-1]`), `record_id`, `content_sha256` (64 lowercase hex
digits), `prefix_digest`, trusted `accepted_at`, fixed `replay_until` and
`identity_until`, profile fingerprint, authority revision and nullable
`correction_of`. It references the stored full binding. Text inherits v1 byte
bounds; receipt metadata has an additional finite encoded-byte cap. Sequence is
commit order, not source checkpoint, verification time, server WAL position or
event time. Checked overflow stops admission.

The receipt says that this assertion and its immutable metadata were durably
committed. It does not authenticate source proofs, establish current health,
acknowledge M2/M3/M4, or prove security-account independence. `accepted_at` is a
receiver clock; it must never replace `last_verified_at` or `valid_until`.

## Admission and replay order

1. Require a healthy, exclusively owned store and validated finite configuration.
   Authenticate/authorize the caller before consulting/disclosing scope history.
   Bound request bytes and record-ID syntax before allocation or hashing.
2. For a known retained ID, authorize its original binding. Exact raw bytes and
   identical `correction_of` within the replay window return the **original**
   receipt, even when the original profile is now retired. Current authorization
   still applies. Changed content/link yields `id_content_conflict`. Replays do
   not allocate a sequence, extend retention, renew verification or mark an
   observer healthy. Full new-write quotas do not evict/block a readable replay;
   bounded operation slots and I/O deadlines still apply.
3. At `at >= replay_until`, return `replay_window_expired`; never manufacture a
   replay success from a tombstone hash. If the caller supplies an old receipt,
   validate its history/position/prefix before deciding availability. Unknown
   bare IDs have no lifetime deduplication guarantee after identity pruning.
4. For a new submission, enforce v1 structural/semantic validation and exact
   trusted binding/observer/profile agreement. Failed, unknown, partial and
   unsupported assertions are valid history entries; do not retain only green
   results. Require verification/report time no later than receiver time plus
   profile clock skew. Bound report admission age using `provenance.observed_at`,
   not `coverage_end`. A fresh report about an expired verification can be
   admitted as historical evidence; it cannot renew the verification.
5. Validate a correction link if supplied, reserve all count/byte/key/write
   capacity, then commit original bytes, receipt metadata, sequence, retention
   deadlines and lookup identity as one recoverable transaction. Required indexes
   may be rebuilt from committed material. Expose/acknowledge only complete,
   synced commits. No memory enqueue is a durable receipt.

Known-ID conflict detection takes precedence over treating changed bytes as a
new probe. Rejected input never replaces historical evidence. An authorized
observer's malformed report/intake failure degrades its independently supervised
current health to unknown; an unauthorized attempt must not poison another
observer's state. A store outage needs an independently reachable failure path;
the unavailable store cannot be the only recorder of its own outage.

## Bounded state and retention

Before readiness, require finite positive limits for retained payload count,
retained identity count, full binding keys, logical ledger bytes, transient
write/compaction bytes, operation slots, response records/bytes, scan work and
deadlines. Retention/admission duration fields fit unsigned 32-bit seconds;
clock skew may be zero and remains at most 300 seconds. Identity capacity includes
payloads and tombstones; it is at least the
payload count cap. Scope/config/profile revisions consume distinct binding keys.
Reject a new key before allocating it when the registry is full. Reclaim a key
only when no retained identity references it. Keep metric labels to registered
keys/fixed reason classes, not arbitrary rejected identifiers.

Record bytes remain bounded at 65,536. Full binding metadata and per-receipt
metadata need explicit caps too; raw payload, receipts, identity/index entries,
headers, pending writes and temporary compaction files all count against their
respective budgets. The selected backend must define conservative memory/index
charges before allocation and test them. Logical file-byte caps are not physical
disk-space or whole-process RSS guarantees. Fail closed on accounting uncertainty.

The fixture uses 4 payloads, 8 identities, 2 keys and short time windows solely
as test parameters. Production retention/capacity and permissions remain private.
There is no `drop_oldest` policy for unexpired acknowledged history: reclaim only
eligible prefixes, otherwise reject new submissions and report degraded intake.
Oldest retained entries can block later reclamation; do not silently prune around
them. A lower configured cap does not delete admitted history to achieve readiness.

Assign replay and identity deadlines once from receiver admission time and pinned
policy. Identity retention is at least payload/replay retention. Payload retention
must exceed maximum report admission age plus allowed clock skew; this prevents
an unchanged old report being treated as fresh after its replay window ends.
Equality at a deadline is expired/eligible for reclamation. Retry traffic extends
neither deadline. Retention promises are minimum preservation periods; prefix
reclamation can lag. An exact physical deletion deadline is a separate requirement.

Two durable, monotonic prefix markers distinguish payload and identity pruning:
`identity_pruned_through <= payload_pruned_through <= committed_sequence`.
Payload pruning preserves identity, receipt and digest metadata until identity
pruning is eligible. Advance markers/anchors crash consistently before declaring
data unavailable; recovery accounts for remaining old files. A retry with an old
receipt at/below the identity marker returns `identity_pruned`, not new admission.
The implementation checks current authorization before classifying a pruned
reference, validates canonical receipt shape/deadline ordering and rejects wrong
history/future positions. At the identity marker its prefix must match the retained
anchor. Below that anchor, original receipt fields/full bindings cannot be
independently authenticated after deletion; `identity_pruned` classifies unavailable
history and never asserts receipt authenticity or admits a replacement.
An unknown bare ID cannot prove whether it ever existed. Producers must never
reuse IDs; changed-content reuse after all identity evidence is deleted cannot
be detected forever by a bounded store. No global exactly-once claim follows.

Receiver clock regression behind the durable retention/admission clock floor
pauses mutation and pruning. Do not manufacture age/expiry from a backward clock
or advance the floor solely because a retry arrived. Explicit historical reads
may remain possible if integrity/ownership are healthy; the supervisor reports
current intake uncertainty. Clock repair and actual outage SLOs require acceptance.

## Corrections and current assessment

Backfill creates a new observation/ID and nullable intake `correction_of` link;
it does not mutate SourceCoverage v1 or erase the earlier failed/unknown record.
The target must still have available original evidence, be authorized under the
same full binding/observer, precede the correction in commit order, and have an
overlapping interval. The correction's verification is later than the target's.
Source backfill/recovery proof references still need the trusted provider.
Missing/pruned/cross-binding targets reject the link. A record links at most one
earlier target; no recursive correction traversal occurs in this first contract.

The library now enforces these admission checks on its existing worker. The link
and new report/receipt/accounting commit in one transaction under the frozen prefix
encoding. Only the direct target's available evidence is inspected; its ancestors
are not followed. Target expiry alone does not make retained original evidence
unavailable. A retained correction replays its original immutable receipt before
its own deadline without revalidating target availability; later pruning cannot
erase or reinterpret an admitted correction. It still requires the correction's
current exact authorization grant, and changed links conflict. Payload-prefix
pruning and identity pruning now preserve this behavior in real maintenance tests.

Storage does not select the last appended row as current health, assemble intervals
across records, or silently resolve corrections into a green historical view.
Late arrivals and corrections can be appended after newer source intervals.
Callers assess an explicitly selected retained assertion using the existing SDK,
trusted current observer status/profile and requested interval. A selection policy
for multiple assertions needs its own acceptance, including ties and reordering.
Pruned evidence produces `record_unavailable`/indeterminate, never `no_match`.

## Bounded reads, recovery and ownership

Scans capture a committed frontier on the first page. An opaque versioned cursor
binds history ID, full binding, frontier, last scanned sequence and consumed-prefix
witness. Continuation validates that witness/frontier before reading. Each page
bounds records, response bytes, scanned entries/bytes, concurrency and elapsed
work. A sparse scan may return zero matches with continuation; that does not
mean exhaustion or healthy collection. An oversized first result returns a limit
error without progress. Require page capacity for one maximum-sized row/receipt.

Pruning can invalidate a reader between pages: return `history_pruned` with
bounded availability markers, not an empty successful remainder. Scans do not pin
unbounded history. The first page discloses current pruning markers. There is no
timestamp cursor or rehydration claim and no new query language.

Backend acceptance must bind receipts/cursors to exact committed prefix content,
as in the [findings cursor rationale](25-findings-cursor-proposal.md), without
sharing that protocol's domain or confusing its positions with coverage history.
The backend ADR must freeze commit encoding, prefix construction, framing/checksum,
durable anchors and golden vectors. Hashes are integrity/consistency witnesses,
not signatures or proof against an operator rewriting all local evidence.

| Failure point | Required observable result |
| --- | --- |
| Before committing starts | Known not committed; reservation released |
| Write/sync outcome uncertain or cancellation during commit | `outcome_unknown`; reconcile exact admission identity or maintenance markers after owner exit/recovery; never assume rollback |
| After sync, before response | Admission commit recovers once; exact admission retry returns original receipt; maintenance reconciles markers |
| Incomplete unacknowledged final transaction | Recover complete prefix; discard/truncate only incomplete tail under chosen format |
| Complete interior corruption or inconsistent sequence/index/anchor | Fail readiness/intake; no silent reset, skipped row or green response |
| Crash during prefix pruning/compaction | Restore a consistent committed/pruned state; preserve unexpired acknowledgements and count surviving files |
| Byte-identical restart/offline relocation | History/positions/receipt metadata preserved |
| Restore missing a receipt's position | `history_unavailable`; do not accept that retry as new |
| Restore and replace a consumed prefix at the same position | Prefix mismatch; reject old receipt/cursor despite matching history ID/position |
| Restore an unseen suffix | Prefix witnesses cannot prove preservation of data the caller never observed; reconcile backup scope independently |
| Writer ownership lost | Stop admission/commit; exclusive ownership must cover durable mutation, not a pre-write check |

A cancellation/timeout does not free a physical operation's reservation or slot
while its I/O is still running. Settle that work or fail the store closed before
reusing its capacity. Ownership loss during an in-flight commit can leave the
caller uncertain whether it committed before ownership ended; it never permits
a stale owner to commit after its durable fence is invalid.

Initial acceptance targets one writer on qualified local storage. RWO, UUIDs,
prefix hashes and two copies of a backup are not fencing. Writable clones and
network filesystems need a separate supported-ownership contract. HA requires
an authoritative fence checked by the durable commit operation; a lease checked
earlier is insufficient. Graceful shutdown stops admission, resolves bounded
in-flight outcomes and syncs before closing. Every actual disk/network operation
will need timeout/cancellation semantics in the selected implementation.

## Fixtures, acceptance and next task

The [history fixtures](../tests/fixtures/source-coverage/history.json) specify
16 requirements, 12 candidate encodings and 56 planned
admission/retry/retention/correction/read/recovery expectations. The
[offline checker](../scripts/check-source-coverage-contract.py) checks bounded
inventory, references, raw-byte relationships, receipt shape and coverage of
these requirements. It does **not** execute a history state machine, sync files,
kill a process, validate an actual prefix token or qualify an observer.

Its receipt example predates ADR-015: the profile fingerprint hashes illustrative
JSON bytes and the prefix is explicitly a placeholder. Neither is a backend-v1
golden value. Use the separate
[backend vectors](../tests/fixtures/source-coverage/backend-vectors.json) for the
selected canonical profile/prefix format; the 56 history outcomes remain planned.

```bash
python3 scripts/check-source-coverage-contract.py
```

[ADR-015](adr/015-source-coverage-store.md) now selects SQLite on one worker,
freezes profile/binding/commit/state/identity encodings and supplies executable
golden checks and a limited system-SQLite mechanics probe. The probe is not the
complete Rust history state machine. The earlier persistence/intake/correction slices
passed 45 focused tests and 300 workspace tests, including process-crash recovery,
corruption, page exhaustion, cancellation ownership and immutable-link receipt replay.
The application's fresh `AuthorizedBinding` grant represents its authenticated
observer and current full-binding permission; credential authentication/revocation
and independently supervised current health remain application responsibilities.
Admission checks finite report-age/skew/retention policy with fixed original
deadlines. Bounded payload-prefix pruning now adds 13 regressions (58 focused/320
workspace tests), preserving receipts/pins/links and atomically advancing only an
eligible global prefix under finite record/raw-byte/VM/deadline bounds. No-op calls
leave the floor unchanged; clock regression and corruption reject. Evidence:
`target/source-coverage-payload-pruning-20261007/`. Identity pruning subsequently
adds 16 regressions (74 focused/336 workspace tests), bounded selected-metadata/
record work, atomic eligible identity/pin reclamation, preserved anchors/receipts/
links, stale-reference classification and all-pruned pin-deletion SIGKILL/restart/
sequence continuity. Evidence: `target/source-coverage-identity-pruning-20261007/`.
Fixed-frontier scans follow separately. Maintenance has no durable operation receipt: reconcile markers after
unknown-outcome recovery rather than assuming an exact retry. Do not adapt the event
WAL/findings journal by assuming its contracts already satisfy this one.

# ADR-015: Local SourceCoverage persistence and integrity encoding

Status: Selected decision with bounded library implementation, 2026-10-07.
Encodings, explicit initialization/ownership, prepared append, recovery and
trusted one-row inspection, application-grant intake/retry and bounded correction
admission, bounded payload/identity-prefix pruning and fixed-frontier scans are implemented in [`signal-coverage`](../../crates/signal-coverage/README.md).
Credential authentication and source observers remain unimplemented.
This ADR does not select production retention or claim release readiness.

## Context and decision

The [history contract](../source-coverage-history-contract.md) requires original
byte replay, pinned profiles, immutable receipts, separate payload/identity
retention, and atomic prefix pruning. The current event WAL acknowledges consumer
progress and permits policy-controlled drops. The findings journal deduplicates
decoded findings, keeps an in-memory index, and has no coverage retention
transaction. Neither format meets this contract by reuse alone.

Use **SQLite through `rusqlite`, with `bundled`, `limits` and `hooks` features**, on one
dedicated ordinary worker thread. That worker owns one connection and the root
lock through recovery, requests, uncertain I/O and shutdown. Keep the SDK's pure
validator free of database dependencies. The `signal-coverage` library introduces
no service or server integration. The workspace locks `rusqlite` 0.40.2,
`libsqlite3-sys` 0.38.2 (bundled SQLite 3.53.2) and `sha2` 0.11.0. The `hooks`
feature enables finite VM/deadline/cancellation progress checks. Build options,
source ID and amalgamation SHA-256 are retained in
`target/source-coverage-store-20261007/sqlite-build.json`; compilation and runtime
acceptance currently cover local Linux AMD64 only.

| Alternative | Assessment |
| --- | --- |
| Adapt event WAL or findings journal | Different identity/acknowledgement contracts; pruning would require a new transaction/recovery format |
| New framed append journal | Precise file-byte control, but multi-file pruning, indexes, anchors and uncertain compaction become another custom durability protocol |
| SQLite rollback journal | Selected: admission, counters, profile pins and pruning markers can share one local transaction |
| SQLite WAL mode | Reconsider only if measured reader contention needs it; no parallel readers in the first worker and no checkpoint/WAL lifecycle needed now |
| Remote database/object store | Separate availability, authority and distributed fencing task |

Context7 was consulted for SQLite and `rusqlite`; the SQLite retrieval did not
resolve durability detail, so the following primary pages were checked directly.
[`rusqlite::Connection`](https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html)
is `Send`, not `Sync`; its transaction wrapper and busy handling suit one worker.
The [`bundled` feature](https://github.com/rusqlite/rusqlite/blob/master/Cargo.toml)
selects bundled SQLite sources. C compilation, FFI dependencies and image/native
qualification are new implementation build inputs; the Python probe does
not establish their compatibility.

## Transaction, recovery and ownership

Use `journal_mode=DELETE`, `synchronous=EXTRA`, `foreign_keys=ON`,
`mmap_size=0`, `temp_store=MEMORY`, `auto_vacuum=NONE` and normal SQLite locking.
Create databases with 4,096-byte pages. Set a positive database-page maximum and
finite cache/VM/request limits; verify returned settings and build capabilities
on every open before readiness. Unknown PRAGMAs can be silently ignored.
[`EXTRA`](https://sqlite.org/pragma.html#pragma_synchronous) also synchronizes the
directory after deleting the rollback journal. SQLite's
[atomic-commit contract](https://sqlite.org/atomiccommit.html) still assumes
working locks, filesystem operations and device flushes.

New admission runs in one `BEGIN IMMEDIATE` transaction: validate prepared
inputs/reservations, insert any new binding/profile pin, insert identity and
payload, advance committed sequence/digest/clock floor/counters and state
checksum, then `COMMIT`. Only a successfully completed commit exposes its
receipt. An acknowledged row is immutable except for eligible payload pruning;
`INSERT OR REPLACE`, conflict upserts and sequence allocation outside that
transaction are forbidden. Exact replay is a read of retained original bytes
and immutable metadata, after scope authorization, with no transaction clock
floor/deadline/sequence renewal.

Each bounded pruning transaction removes an eligible contiguous prefix and
updates its marker, anchor, counters and checksum together. Payload pruning
sets raw payload unavailable; identity pruning deletes identities and then
unreferenced profile/binding pins. Never prune around a blocked oldest row.
Do not renumber survivors or reset the high-water sequence when history is empty.

Before SQLite mutation starts, cancellation/deadline expiry is known not
committed. Once mutation starts, caller timeout/cancellation or ambiguous commit
I/O returns `outcome_unknown`; the worker retains its operation slot, buffers,
transaction and ownership until it settles or closes the store. `busy_timeout`
bounds lock waiting, not disk I/O. SQLite
[interrupts](https://sqlite.org/c3ref/interrupt.html) do not provide a bounded
kernel `fsync` deadline. No detached worker or assumed rollback is allowed.
An overdue active mutation closes admission; a stuck syscall may outlive shutdown.
Reads remain bounded and never publish partial pages as successful progress.

Open an existing root without `CREATE`; initialization is an explicit operation
on a newly created private root. A non-nil history UUID is preserved across
restart/offline relocation. The root contains only `.lock`, `identity`,
`coverage.sqlite3`, and SQLite's `coverage.sqlite3-journal`; `identity.tmp` is
allowed only as retained interrupted-initialization evidence. Create directories
0700 and files 0600, validate regular files/ancestors, and reject symlinks,
unexpected paths and ambiguous initialization. The empty root lock is acquired
before SQLite open/recovery and held until the worker actually exits. Never
replace/unlink a live lock inode. The identity sidecar is published by
create-new temporary file, sync, rename and directory sync. Interrupted
initialization fails closed; it does not authorize automatic deletion/recreation.
Missing established database/identity is unavailable, not a fresh store.

Allow SQLite to recover its hot rollback journal while holding ownership.
Never manually delete/truncate that journal to imitate event-WAL tail recovery.
Then run bounded integrity/foreign-key checks and verify the logical invariants
below before readiness. Complete logical corruption fails closed even if
`integrity_check` reports valid SQLite pages. Existing corruption, a changed
history UUID, inconsistent sidecar/state, or an unsupported schema never opens as
an empty store. Backup/copy is supported only while closed and with no pending
journal, including the identity sidecar; live copy needs its own protocol.

This is one writer on qualified local storage. The advisory lock and SQLite
transaction lock do not fence writable clones, a replaced root, network storage
or a stale distributed leader. Those deployments remain unsupported; HA requires
a fence enforced by the durable operation. No security-account isolation follows.

## Version 1 logical encoding

The following bytes define fingerprints and prefixes independently of SQLite
page layout or JSON serializer order. All integers are checked unsigned big
endian. `B(x) = u32be(byte_length(x)) || x`; `S(s) = B(UTF8(s))`, with 1–1,024
bytes per text. UUIDs are 16 raw bytes from canonical lowercase non-nil UUIDs.
Digests are 32 raw bytes, rendered as 64 lowercase hex characters in receipts.
No Unicode normalization occurs. These definitions apply only to already
validated bounded inputs; they do not replace the SDK semantic validator.

`T(t)` is exactly 30 ASCII bytes, `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`.
Validate ordinary calendar time in years 0001–9999, seconds 00–59, UTC `Z` and
zero to nine fractional digits; right-pad the fraction with zeros. Never use
floating point or signed 64-bit epoch nanoseconds for this range. The receiver
sets fixed retention times with checked arithmetic; overflow rejects admission.

Each `D(kind)` below is ASCII `SIGNAL-COVERAGE-<kind>-V1` **followed by one NUL**.
Domains are `PROFILE`, `BINDING`, `HISTORY`, `COMMIT`, `PREFIX` and `STATE`.
They are separate from the findings cursor domains and event-WAL positions.

### Pinned profiles and full bindings

```text
P = D(PROFILE) || u32be(1) || S(id) || S(revision)
    || u8(component_mask) || u8(requires_checkpoint)
    || u32be(max_interval_seconds) || u32be(max_verification_age_seconds)
    || u32be(max_clock_skew_seconds)
profile_fingerprint = SHA256(P)
```

Component bits are configuration=1, scope=2, continuity=4, source_integrity=8;
the valid mask is 7 or 15. Checkpoint is exactly 0 or 1. All v1 profile fields
are encoded. Component order and JSON key/whitespace changes do not change a
profile definition; changed semantics under a retained ID/revision conflict.
The trusted catalog prepares this canonical definition, at most 8,192 bytes.
Retain it and decode/reconstruct bounded profile JSON for SDK assessment;
never substitute a current definition after catalog retirement.

```text
K = D(BINDING) || S(source_id) || S(collector_id)
    || S(scope.kind) || S(scope.id) || u32be(attribute_count)
    || [ S(key) || S(value) for attributes in ascending raw UTF-8 key order ]
    || S(expected_stream) || S(profile.id) || S(profile.revision)
    || S(collection_config_revision) || S(observer_id)
```

Omitted scope attributes and `{}` encode alike; otherwise compare the complete
binding. Attributes have at most 16 entries; `K` has a 65,536-byte cap.
Store canonical binding bytes as the unique registry key. Its hash is a bounded
diagnostic/reference, not the authority/equality decision. Profile pins use
`(id, revision)` plus exact canonical bytes, not fingerprint-only equality.

### Immutable commit and prefix

```text
M(n) = D(COMMIT) || history_uuid || u64be(n) || record_uuid
       || u32be(raw_length) || SHA256(original_raw_bytes) || B(K)
       || profile_fingerprint || S(authority_revision)
       || T(accepted_at) || T(replay_until) || T(identity_until)
       || correction
correction = u8(0)                     if absent
             u8(1) || correction_uuid if present

H(0) = SHA256(D(HISTORY) || history_uuid)
H(n) = SHA256(D(PREFIX) || H(n-1) || SHA256(M(n)))
```

Original raw UTF-8 JSON bytes have a 65,536-byte cap and remain separately stored
through payload retention. A decoder must cross-check record ID/full binding
against those bytes. Changes to whitespace/order alter the content digest;
replay compares actual bytes and correction metadata, never hashes alone.
`M(n)` includes every immutable receipt value except its derived prefix and
constant schema version. Store `M(n)` and `H(n)` at their sequence, with binding/
profile references; derived columns must agree during recovery. Receipt values
are reconstructed from immutable metadata, with a 4,096-byte JSON metadata cap
checked before admission. No HTTP receipt encoding is added in this task.

Sequences start at 1, advance once per commit and stop at `2^64-1`. Store sequences
as exactly **8-byte BLOBs**, ordered lexicographically, including foreign keys,
frontiers and pruning markers. SQLite signed INTEGER/AUTOINCREMENT cannot model
this complete range. Counts/byte-charge integers fit checked `i64`; configuration
rejects values/conversions outside that range.

Payload pruning leaves `M(n)`/receipt/identity/digest intact. Recovery verifies
each remaining raw payload's length/hash, then recomputes prefixes over retained
identity metadata. Identity pruning retains `H(identity_pruned_through)` as its
starting anchor. The payload anchor and committed tail are retained too, including
when all rows are gone. Deleted payloads cannot be rehashed; these anchors preserve
consistency references, not proof that deleted bytes still exist. Neither SHA-256
nor the sidecar/state checksum authenticates evidence against an administrator
rewriting the entire store.

### Identity file and durable state

The 56-byte identity file is `SIGCOV01` (8 ASCII bytes), history UUID (16), then
`SHA256` of those first 24 bytes (32). It is not an owner lease.

The singleton state stores the following canonical bytes and `SHA256(A)`:

```text
A = D(STATE) || u32be(1) || history_uuid
    || u64be(committed_sequence) || H(committed_sequence)
    || u64be(payload_pruned_through) || H(payload_pruned_through)
    || u64be(identity_pruned_through) || H(identity_pruned_through)
    || T(clock_floor)
    || u64be(payload_count) || u64be(identity_count)
    || u64be(binding_count) || u64be(profile_count) || u64be(ledger_charge)
```

At zero, each anchor is `H(0)`. Equal positions require equal anchors.
`identity_floor <= payload_floor <= committed_sequence`; retained identities and
payloads form contiguous suffixes behind those floors. Every row is within the
committed frontier. Recompute counters, registry references, charge, prefix and
state checksum on bounded startup. SQLite's file/journal framing and recovery
checks remain SQLite's format; they are not a cryptographic page checksum.
Use the logical checks above to detect complete evidence/metadata corruption.
Receipt/cursor validation checks supplied history/position/prefix against this
state. The scan cursor layout is frozen in the separately accepted scan section below.

## Accounting and pruning reserves

Retained logical charge is conservative and deterministic:

| Item | Charge in bytes |
| --- | ---: |
| State/root metadata allowance | 16,384 |
| Retained identity, including tombstone | `len(M(n)) + 8,192` (receipt and index allowance) |
| Retained payload | `raw_length + 256` |
| Registered binding | `len(K) + 4,096` |
| Pinned profile | `len(P) + 4,096` |

Reject before reserving/allocating any count, key, profile or ledger cap. Only a
readable exact replay bypasses new-write reserves. Recompute charges after prefix
pruning; lower caps do not delete unexpired acknowledgements. Include profile pins
and identity tombstones. Metadata `M(n)` must fit 73,728 bytes, profiles 8,192,
and complete logical entries 397,312. These charges bound application state, not
SQLite page slack, allocator RSS or filesystem blocks.

Bound queues/operation slots and reserve transient input/encoding/response memory
before dispatch. The first implementation reserves `2 * max_entry_bytes` per
operation plus an explicit finite worker cache/VM allowance; reject configurations
whose total transient budget cannot cover every admitted slot and the worker.
No complete raw-history in-memory index or dynamically unbounded statement cache.
Fixed prepared SQL only: no user SQL, extension loading, `ATTACH`, savepoints,
temporary disk tables, vacuum or automatic maintenance. Query VM steps, decoded
rows, response bytes, scan bytes and deadline are independent finite budgets.

Let `N=4096`, database-page cap `p`, and qualified VFS sector ceiling `s<=65536`.
Reserve database bytes `p*N` separately from an entire active rollback journal.
A conservative proposed journal reserve is:

```text
J(p,s) = p*(N+8) + 2*(p+1)*s
```

This follows the [rollback journal format](https://sqlite.org/fileformat.html#the_rollback_journal):
one before-image per original page, page records with eight framing bytes, and
sector-padded headers. It assumes at most `p+1` headers for the fixed single
transaction path. The pinned Linux Unix-VFS/pager source has been reviewed:
default sectors are 4096 bytes and the pager clamps sector sizes to 65536. The
library disables and verifies `cache_spill`, uses no savepoints/attached databases,
and observes journals below the reserve at three real transaction crash points.
That establishes limited local source/process evidence; **VFS write/sync failure
injection and deployment storage qualification remain open**. The Python probe
does not establish those guarantees. Set the finite transient-file reserve at
least to `J`; count surviving hot
journals on recovery. Reject unsupported VFS/sector geometry, oversized roots and
reserve/configuration changes without deleting evidence.

[`max_page_count`](https://sqlite.org/pragma.html#pragma_max_page_count) limits the
main database, not the journal. `journal_size_limit` concerns files retained
after commit/checkpoint, not an active-journal cap. Filesystem/volume quota can
add physical protection; its exhaustion must fail closed and preserve previously
acknowledged data. A hard syscall-time journal cap would require qualified VFS
enforcement and is not promised here. Page reuse after DELETE is supported;
automatic vacuum/compaction and exact physical erasure deadlines are excluded.

## Executable acceptance and scope

[Golden vectors](../../tests/fixtures/source-coverage/backend-vectors.json) freeze
profile set ordering, omitted/empty attributes, UTF-8 ordering with no normalization,
raw-byte divergence, corrections, store domains, full unsigned sequence width,
calendar boundaries, pruning state and the identity file. The reference checker
also checks the standard SHA-256 `abc` known answer. Vectors are static review
inputs; the implementation must consume them without regenerating expectations.
Standalone sequence/calendar vectors exercise encoding boundaries; they are not
admissible SourceCoverage reports or committed histories. The original chain's
synthetic reports retain ordered receiver/probe times.

```bash
python3 scripts/check-source-coverage-backend.py --self-test
python3 scripts/check-source-coverage-backend.py --probe-dir target/coverage-sqlite-probe
python3 scripts/check-source-coverage-contract.py
```

The probe directory must be new; existing evidence is preserved. The probe uses
Python's **system SQLite**, a deliberately minimal table projection, and real
subprocess SIGKILL at controlled pre/post-commit and pruning points. It checks
transactions, restart, page-cap exhaustion, prefix reconstruction, unsigned BLOB
order, contention, OS advisory locking and closed-database relocation. It has no
SDK validation, authority provider, intake API, receipt retry policy, fixed
retention scheduler, operation worker or production database schema. Passing it
does not execute the 56 history cases or prove kernel/device power-loss behavior.

| Rust implementation gate | Required observable acceptance |
| --- | --- |
| Format/initialization | All frozen vectors; exact sidecar/state; fail existing missing/changed files and interrupted initialization without reset |
| Commit/retry | Authorized semantic intake; one atomic row/pin/state commit; original exact replay; changed bytes/link conflict; old profile retirement; response-loss retry |
| Clock/retention | Fixed equality deadlines; regression pauses mutation; overflow; payload/identity prefix GC; unavailable reads and no health renewal |
| Crash/integrity | Child-process crash points and VFS write/sync failure injection; complete-prefix recovery; interior payload/profile/binding/state corruption fails closed |
| Bounds/ownership | Logical/count/key/pin/memory/page/journal limits; no quota-dependent replay failure; lock for complete worker lifetime; active cancellation holds slots until I/O settles |
| Read/restore | Fixed-frontier bounded scans; divergent/missing prefix; pruning between pages; sparse continuation; no unseen-suffix/health claim |
| Build/runtime | Fresh required Cargo gates and bundled-dependency evidence; AMD64/ARM64 image/native qualification separately |

The bounded library slice passes all frozen vectors and 18 focused Rust tests:
explicit initialization/ownership, atomic prepared append, trusted inspection,
restart, closed relocation, quotas/actual SQLite page exhaustion, corruption,
cancellation races and SIGKILL after row insertion, before commit and after commit
with the response lost. Recovery preserves acknowledged original bytes and
receipts. Full local acceptance passes formatting, strict Clippy, 273 workspace
tests and the 13-package boundary guard. Evidence is retained under
`target/source-coverage-store-20261007/`.

The table still includes future requirements. The subsequent intake slice passes
31 focused tests and 286 workspace tests with unchanged encodings/dependencies.
`submit`, `retry` and `get_authorized` require a fresh exact application grant.
Retained IDs authorize their original binding before evidence disclosure; exact
original bytes/link return the original receipt within its fixed replay window,
including retired pins and full new-write quotas. Missing/divergent receipt
references cannot be admitted as new. Report age uses `provenance.observed_at`;
checked fixed retention arithmetic preserves nanoseconds. Replay never advances
sequence, deadlines, verification or the admission clock floor. Low-level append
still rejects retained IDs with `IdentityExists` and remains caller-trusted.
Evidence: `target/source-coverage-intake-20261007/`. The subsequent correction slice
passes 45 focused tests and 300 workspace tests, including an actual admission of
the frozen correction chain. It validates one available earlier target under the
same full binding/observer, overlapping half-open intervals and strictly later
verification; the existing atomic metadata/prefix encoding carries the immutable
link. Original evidence/receipts remain unchanged. Recovery/replay needs no ancestor
traversal or target reauthorization for an already admitted link. Tests cover
target/link corruption, quota/restart/concurrency, queued cancellation and SIGKILL
before/after commit. A pre-pruned fixture checks availability behavior, not runtime
GC. Evidence: `target/source-coverage-corrections-20261007/`. At that correction acceptance, payload-prefix pruning was next; identity GC and
scan integration follow separately. No observer, current-health selection, protected S3 evidence,
source adapter or detection wiring follows from this library acceptance.


## Bounded payload-prefix pruning acceptance

`prune_payloads(now, budget, context)` streams a globally ordered prefix under
positive configured record/raw-byte caps and existing VM/deadline/memory/slot
limits. Metadata is bounded before decoding; only selected bodies fitting the
remaining byte budget are read and length/hash checked. A blocked oldest row
halts progress, and stored corruption fails closed. Equality at replay expiry is
eligible. No-op calls leave the clock floor unchanged; clock regression rejects.
One existing immediate transaction clears raw bytes and atomically updates
payload marker/anchor, receiver floor, count, charge and state checksum. Identities,
receipts, bindings, profiles, immutable correction links and committed tail remain.
The schema and all frozen encodings are unchanged.

Local acceptance adds 13 regressions (58 coverage/320 workspace tests): frozen
anchors/receipts, time equality, cross-binding obstruction, budgets, quota recovery,
retained corrections, corruption, actual queued cancellation/timeout and actual
pruning SIGKILL before/after commit. Generic active-mutation ownership tests remain
separate; no actual fsync cancellation, VFS failure or power-loss proof is added.
Evidence: `target/source-coverage-payload-pruning-20261007/`. This is an isolated
post-MVP library mechanism, with no server/cloud/observer wiring or release claim.

Maintenance has no durable operation receipt. After an unknown result, the caller
reconciles the retained payload marker/accounting after ownership settles and
recovery. Repeating a bounded call can prune another prefix. Logical charge
reclamation does not promise physical erasure, page-file shrinkage or deletion
at a strict deadline. At that acceptance identity-prefix pruning was next.


## Bounded identity-prefix pruning acceptance

`prune_identities(now, budget, context)` point-loads a global eligible prefix under
positive configured record/selected-metadata-byte caps. Each row must already have
no payload and reach its immutable identity deadline; equality is eligible.
The first blocked row stops progress. Preflight plus transaction loads at most
twice the record budget, with one bounded row/profile at a time; a blocked
candidate can be inspected under the fixed metadata cap. Each selected row can
reclaim at most one bounded binding/profile pin. Existing VM/deadline/memory/slot
limits bound reference lookups; there is no global orphan sweep or growing set.

One immediate transaction deletes selected identities and only newly unreferenced
pins, debits exact metadata/pin charges and updates identity marker/anchor/counts,
clock floor, ledger and checksum. Shared references preserve pins. History UUID,
committed high water/tail, payload anchor and surviving immutable corrections
remain even when all rows are removed. No-op calls leave the floor unchanged;
clock regression and stored corruption reject. Schema and encodings are unchanged.

Referenced retries at/below the identity marker return typed `IdentityPruned`
after current authorization; they never admit a replacement. Canonical receipt
shape/deadline ordering and history/position are checked, as is the retained marker
anchor. Below it, deleted original binding/prefix fields cannot be authenticated;
the result classifies unavailable history only. Bare-ID absence is not lifetime
deduplication. Surviving corrections replay without revalidating deleted targets.

Local acceptance adds 16 regressions (74 coverage/336 workspace tests), including
actual queued timeout/cancellation and pre/post identity-commit SIGKILL. A separate
prune-all crash case executes final binding/profile deletion, checks exact empty
root/anchors and appends sequence 3 after recovery. Exact shared-pin accounting,
quota reuse, authorization, corruption and correction survival also pass.
Evidence: `target/source-coverage-identity-pruning-20261007/`. No actual fsync
cancellation, VFS injection, physical power loss, secure erasure, server/source/
cloud integration or release qualification is claimed. Maintenance still lacks
an exact retry receipt; reconcile markers after old-owner exit and recovery.
At that acceptance, bounded fixed-frontier scans were next.


## Fixed-frontier scan cursor and acceptance

The trusted local `scan` API requires a fresh full-binding application grant on
every page. A first page captures the committed frontier and retained identity
start; later appends do not extend it. Continuation validates scope, history,
frontier and consumed witnesses before returning data or terminal emptiness.
Any retention-marker advance returns typed `HistoryPruned` with bounded current
availability; regression or missing/divergent history returns `HistoryUnavailable`.
This deliberately conservative policy does not pin history across pages.

Cursor v1 is canonical lowercase hex of exactly these bytes, with no trailing data:

```text
C = "SIGNAL-COVERAGE-SCAN-V1\0"   (24 ASCII bytes including NUL)
    || u32be(1) || history_uuid   (16 bytes)
    || u32be(len(K)) || K         (full canonical BINDING-v1 bytes)
    || u64be(frontier) || H(frontier)
    || u64be(last_scanned) || H(last_scanned)
    || u64be(initial_payload_marker) || u64be(initial_identity_marker)
    || SHA256(all preceding C bytes)
```

`H` remains the existing coverage prefix; the token domain is independent of
findings cursors and event-WAL positions. Require non-nil history and canonical
bounded K, `identity_marker <= payload_marker <= frontier` and
`identity_marker <= last_scanned <= frontier`. Input token size is capped at
131,584 bytes before allocation/copy; the encoder uses exact-sized buffers.
The checksum detects inconsistent input; it is not a signature or grant. The
independently calculated 728-character golden token in
[`scan_tests.rs`](../../crates/signal-coverage/src/scan_tests.rs) uses the frozen
three-commit chain's history/K/H(1)/H(3), frontier 3, last 1 and zero markers.
Existing backend-vector JSON/checkers are unchanged and do not cover this token.

Positive result-record/work-record/work-byte caps apply alongside VM/deadline
limits. Length probes precede each full row; examined work charges
`len(M)+raw_length+len(K)+len(P)+4096`, at most 217,088 per row. First work overflow
returns `ScanWorkLimit`. A page charges `4096+2*(24+152+len(K))`, including potential
output token even when terminal, plus `raw_length+8192` per result. Response cap
397,312 plus command allowance 287,232 totals 684,544 below the existing per-slot
794,624 reservation; worker scratch is separate. First matching response overflow
returns `ResponseLimit` without progress; a later blocked row is counted as
examined but not consumed. Sparse empty pages can continue. No limit-sized vector
or history-sized raw/key/profile collection is allocated.

Returned `ScanRecord`s contain only original receipt/optional raw bytes. Every
examined row is checked under its pinned profile internally; later assessment
must resolve that exact profile rather than substituting a current definition.
Non-cloneable pages retain their admitted operation permit and expose borrowed
records/cursor. Retaining capacity pages rejects more operations until drop.
The budget is per instance, not global RSS; caller copies/new instances have
separate ownership. A retained post-shutdown snapshot is not a filesystem lease.
Boundary witnesses and examined rows are verified, without recertifying every
unread row or claiming current source health/absence of unseen source events.

Local acceptance adds 22 regressions (96 coverage/358 workspace tests): exact
independent encoding, fixed frontier, sparse continuation, first/later limits,
per-page grants, pruning, divergent/truncated restores, held-page capacity,
shutdown/restart, metadata/raw/pin/prefix corruption, finite maximal-u64 positions,
actual queued timeout/cancellation and predispatch saturation rejection.
Evidence: `target/source-coverage-scans-20261007/`. All frozen history encodings,
schema and dependencies remain unchanged. Source observers/credential proof,
server/HTTP/cloud wiring, native ARM64/EKS, physical power loss, global HA/fencing
and complete 56-outcome history-state-machine qualification remain open. Next:
bounded CloudTrail source-receipt/normalization-profile design.

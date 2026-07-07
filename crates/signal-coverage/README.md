# Local SourceCoverage store and trusted intake

This unpublished library implements bounded persistence and trusted intake from
[ADR-015](../../docs/adr/015-source-coverage-store.md). It preserves original report
bytes, canonical profile pins, full bindings, immutable receipts and a checked
commit prefix on one owned local root. It does not change `signal-server`.

`CoverageStore::initialize` explicitly creates a new root with a non-nil history
UUID and receiver clock floor. `open` requires the established identity and
database. Missing, partial, unsupported or corrupt state fails closed; opening
does not recreate it. An initialization error may leave partial files; preserve
them for inspection rather than deleting or reinitializing automatically. The
`available` metric describes a usable local worker, not deployment qualification
or source health. Root directories use 0700 and regular files 0600. The
advisory root lock is held through SQLite recovery, requests and physical worker
exit. Relocation requires a stopped store, its identity, database and empty lock
file, with no pending journal. Writable clones require external fencing.

`PreparedObservation::prepare` applies the pure SDK validator, exact binding and
profile matching, future-time checks and bounded admission metadata. **The caller
supplies trusted authority, receiver time and fixed deadlines.** Preparation does
not authenticate an observer, enforce maximum report admission age, validate
source proofs or choose retention policy. Input construction and retained output
ownership are the caller's memory responsibility.

`append` reserves count/key/profile/ledger capacity before one SQLite transaction
inserts the original bytes, pins and metadata and advances sequence, prefix,
clock floor and accounting. It returns a receipt only after commit. A retained ID
returns `IdentityExists`, including identical bytes. Use `submit`/`retry` for
authorized exact-byte replay. Profile revision reuse with different canonical bytes and
receiver clock regression reject new admission. Exhausted quotas preserve
acknowledged history; payload pruning reclaims only eligible prefixes.

`load` is trusted local inspection by UUID, returning a bounded original report
and receipt or explicit absence. It validates metadata, references, raw bytes,
semantics and the local prefix link. It does not authorize scope access, assess
current source health or establish that absent events were collected.

`AuthorizedBinding::new` checks that the application's authenticated observer
matches the binding's observer. **The application must authenticate the caller,
authorize the entire binding and issue a fresh grant for every operation.** The
constructor is not a credential verifier or revocation service; source names,
tokens and proof URIs cannot authorize access. The library compares the complete
original binding, including scope attributes, profile/config revision and
observer, before exposing retained bytes or receipts through `get_authorized`,
`submit` or `retry`. Low-level `append` and `load` remain trusted primitives and
bypass this layer; do not expose them directly to untrusted callers.

`CoverageSubmission::new` bounds original bytes before copying them. The trusted
application supplies receiver time, a currently permitted profile and finite
`IntakePolicy` durations through `IntakeContext`. Admission age uses
`provenance.observed_at`; verification/report future times use the pinned profile's
skew, bounded by the configured allowance. Failed, partial, unknown and unsupported
assertions are retained as historical evidence. Fresh assertions about expired
verification never renew `last_verified_at` or `valid_until`.

`submit` serializes retained-ID lookup and new admission on the existing worker.
New admissions receive fixed, checked nanosecond-precision replay/identity
deadlines. Retained identical bytes and correction links return
`IntakeOutcome::Replayed` with the original receipt, even when the profile is
retired or new-write quota is full. Different bytes, including equivalent JSON
reserialization, conflict. At the original replay deadline, replay expires.
Retries allocate no sequence, extend no deadline and advance no clock floor.
Receiver time behind the durable floor rejects intake; authorized historical
reads remain available. The `accepted` counter counts writes and `replayed`
counts successful original-receipt replays; neither reports source health.

`retry` validates retained original receipts against their history, position,
prefix and full immutable metadata. Missing or divergent history never becomes a new admission.
Receipt parsing and input construction are caller-owned memory; bound serialized
requests before decoding them. Typed references are checked for finite field
sizes/canonical forms before dispatch. Library ownership/slots/deadlines apply
equally to reads, replays and new writes.

New submissions may carry one immutable `correction_of` link. Admission requires
the direct target's original evidence to remain available, under the same full
binding and observer. The target must already be committed, its half-open interval
must overlap the correction's, and the correction's verification must be strictly
later, including at nanosecond boundaries. Self/missing/future targets, different
bindings, disjoint intervals and equal/older verification reject without changing
history. An expired target can still be corrected while its original bytes remain.
The link is committed with the new report/receipt/accounting in the same transaction
and participates in the existing prefix encoding. The original row and receipt
are unchanged; storage never resolves corrections into current health.

Only the direct target is inspected; correcting a correction does not traverse
ancestors. A retained correction replays its original bytes/link/receipt before
its fixed deadline without checking target availability again. Later target
pruning therefore cannot erase or reinterpret an already admitted correction.
Changed links still conflict on a retained ID. No correction counters, queues,
indexes, database schema or serialization format were added.

`prune_payloads(now, PayloadPruneBudget, context)` is trusted local maintenance.
The caller supplies receiver time and positive record/raw-byte limits bounded by
store configuration. Selection streams at most `max_records` bounded metadata
rows; only eligible bodies fitting `max_raw_bytes` are read and hashed. Existing
VM, deadline, operation-slot and memory reserves apply. The oldest unexpired or
oversized row blocks later rows across every binding. Equality at the original
`replay_until` is eligible; clock regression rejects, and no-op calls do not
advance the clock floor.

One transaction clears selected payloads and advances the durable payload marker,
matching prefix anchor, receiver clock floor, count and logical ledger checksum.
It preserves identities, receipts, pins, correction links and committed tail.
Reclaimed logical charge is original raw length plus 256 bytes per payload;
SQLite page slack/blocks can remain. This is not physical secure erasure or a
maximum deletion-delay guarantee. Historical reads return `raw: None` with the
original receipt; expired original replay stays expired. New corrections cannot
use unavailable original evidence, but retained corrections remain valid.

Metrics expose the durable `payload_pruned_through` marker. Prune operation/count/
raw-byte counters measure successfully completed nonempty calls and restart at
zero. Maintenance has no durable operation receipt or exact retry identity:
after `OutcomeUnknown`, reopen only when the old owner exits and reconcile the
marker/accounting before proceeding. Another call can prune the next eligible
prefix. Lower configured caps fail readiness with `Quota`, preserving history;
restore sufficient limits before maintenance rather than deleting evidence.

`prune_identities(now, IdentityPruneBudget, context)` reclaims the expired global
identity prefix only after its payloads are unavailable. Positive `max_records`
and `max_metadata_bytes` are bounded by configured identity/ledger capacity. The
byte budget counts selected immutable commit encodings; the first blocked candidate
may still be inspected under the fixed metadata cap. Preflight and transaction
point-load at most twice the record budget, holding one bounded row at a time.
Each deleted row can reclaim at most one 65,536-byte binding and one 8,192-byte
profile, with reference queries bounded by the existing VM/deadline limits.
An unexpired or oversized oldest row blocks younger rows; equality is eligible,
clock regression rejects and a no-op leaves the durable floor unchanged.

One transaction deletes selected identities and only their newly unreferenced
pins, updating marker/anchor, counts, receiver floor, logical charge and checksum.
Each identity releases encoded metadata length plus 8,192 bytes; each removed pin
releases encoded length plus 4,096. Shared pins remain until their last reference
is removed. The history UUID, committed high water/tail, payload anchor and
surviving correction links/receipts stay unchanged, including an empty store.
A later append continues the previous sequence and prefix. This is logical
reclamation, with the same physical-erasure and maintenance-retry limits above.

A same-history retry reference at/below the identity marker returns
`IdentityPruned` after current authorization; it never becomes admission.
Malformed references, unordered retention times, wrong history and future
positions reject. A reference at the marker must match its retained anchor.
Below that anchor, deleted original bindings/prefixes cannot be authenticated:
the result classifies unavailable history, not the authenticity of every supplied
receipt field. When the original row is absent, the supplied report's full binding
and producer ID must match the current grant before this classification. Bare-ID
absence cannot prove prior existence; a bounded store cannot detect changed-content
ID reuse forever. Producers must never reuse IDs. Old unchanged reports remain
subject to admission-age checks; retained corrections replay without rechecking
their deleted target. New links still require available original evidence.

Metrics expose durable `identity_pruned_through` and runtime successful nonempty
`identity_prune_operations`, `identities_pruned` and `identity_metadata_bytes_pruned`.
Runtime counters reset on restart; retained markers do not. Scans and maintenance
scheduling remain separate tasks; no HTTP/server/source integration is added.

`OperationContext` carries cancellation and a deadline, capped at the configured
timeout (at most 300 seconds). One ordinary worker owns SQLite; operation slots
and the command queue are finite. Cancellation before mutation prevents it from
starting. Cancellation or failure after mutation starts returns `OutcomeUnknown`
and closes admission. An abandoned active request keeps its slot and root lock
until physical work settles. A shutdown deadline does not kill a blocked syscall
or authorize a replacement owner. For admission, reopen and inspect the original
identity to reconcile uncertainty; never create another report ID solely because
a response was lost. For maintenance, reconcile the durable marker/accounting
as described above.

`CoverageConfig` supplies finite laboratory limits for payloads, identities,
bindings, ledger bytes, database pages, journal reserve, operation slots, memory
allowances, VM steps and timeout. Defaults are test/development parameters. The
SQLite page cap and checked application accounting are separate from physical
disk blocks, inode limits and whole-process RSS. The conservative active-journal
reserve is `p*4104 + 2*(p+1)*65536`, with 4096-byte pages and cache spilling disabled.
Each open verifies SQLite settings and limits. SQLite uses DELETE journals,
EXTRA synchronization and the pinned bundled Unix VFS. Hashes detect inconsistent
stored content; they do not authenticate a source or prevent coherent host-admin
rewrites. Filesystem/device flush guarantees remain deployment prerequisites.

Earlier Linux AMD64 persistence/intake/correction acceptance had 45 focused tests, including frozen independent
vectors, actual page exhaustion, corruption, ownership/cancellation races,
closed relocation and subprocess SIGKILL at three transaction boundaries.
Thirteen intake regressions add authorization across all ten binding dimensions,
exact receipt replay, concurrent duplicates, full quotas, age/skew/expiry boundaries,
profile retirement/redefinition, nongreen history and missing/divergent references.
The crash test reconciles the recovered lost-response receipt; queued cancellation
exercises the new intake path. Evidence: `target/source-coverage-intake-20261007/`.
Fourteen correction regressions add all ten target-binding dimensions,
half-open overlap/later-verification nanoseconds, self/future/missing targets,
quotas/concurrent duplicates, corruption of target/link, one-hop corrections,
queued timeout and SIGKILL at three transaction boundaries. A manually constructed
pre-pruned persisted fixture checks unavailable-target rejection and retained
correction replay/one-hop behavior; it does not test a pruning implementation.
Historical correction acceptance: `target/source-coverage-corrections-20261007/`.
Payload pruning adds 13 regressions, for 58 focused tests and 320 workspace tests
under `target/source-coverage-payload-pruning-20261007/`. Actual queued pruning
timeout/cancellation, generic active-worker ownership tests and actual pruning
SIGKILL before/after commit are separate evidence; no in-process fsync cancellation
or physical power-loss qualification is implied.
Bundled SQLite 3.53.2 build options and the reviewed source fingerprint are retained
in `target/source-coverage-store-20261007/sqlite-build.json`. VFS write/sync fault
injection, power-loss behavior, refreshed images and native ARM64 remain open.

```bash
cargo test -p signal-coverage --locked --offline
python3 scripts/check-source-coverage-backend.py --self-test
```

Frontier scans, observers and cloud/server
integration require separately bounded tasks. The 56 planned history outcomes
are not claimed as implemented by these primitives.


Identity-prefix pruning adds 16 regressions: 74 focused coverage and 336 workspace
tests pass. They cover exact pin/identity accounting, original deadlines, budgets,
stale references/current grants, bare-ID limits, retained corrections, corruption,
quota/restart behavior and actual queued timeout/cancellation. Actual SIGKILL
before/after identity commit covers shared pins and final pin deletion/prune-all,
then appends sequence 3 from the retained tail. Evidence:
`target/source-coverage-identity-pruning-20261007/`. Independent review accepted.
Fixed-frontier scans are next; no source health or server/cloud wiring follows.

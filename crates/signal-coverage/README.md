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
acknowledged history; this slice has no eviction or pruning operation.

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

`retry` also validates the original receipt's history, position, prefix and full
immutable metadata. Missing or divergent history never becomes a new admission.
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

`OperationContext` carries cancellation and a deadline, capped at the configured
timeout (at most 300 seconds). One ordinary worker owns SQLite; operation slots
and the command queue are finite. Cancellation before mutation prevents it from
starting. Cancellation or failure after mutation starts returns `OutcomeUnknown`
and closes admission. An abandoned active request keeps its slot and root lock
until physical work settles. A shutdown deadline does not kill a blocked syscall
or authorize a replacement owner. Reopen and inspect the original identity to
reconcile uncertainty; never create another report ID solely because a response
was lost.

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

Local Linux AMD64 acceptance has 45 focused tests, including frozen independent
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
Current acceptance: `target/source-coverage-corrections-20261007/`.
Bundled SQLite 3.53.2 build options and the reviewed source fingerprint are retained
in `target/source-coverage-store-20261007/sqlite-build.json`. VFS write/sync fault
injection, power-loss behavior, refreshed images and native ARM64 remain open.

```bash
cargo test -p signal-coverage --locked --offline
python3 scripts/check-source-coverage-backend.py --self-test
```

Payload/identity prefix pruning, frontier scans, observers and cloud/server
integration require separately bounded tasks. The 56 planned history outcomes
are not claimed as implemented by these primitives.

# Local SourceCoverage store primitives

This unpublished library implements the first persistence slice of
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
returns `IdentityExists`, including identical bytes: successful retry policy is
a later intake task. Profile revision reuse with different canonical bytes and
receiver clock regression reject new admission. Exhausted quotas preserve
acknowledged history; this slice has no eviction or pruning operation.

`load` is trusted local inspection by UUID, returning a bounded original report
and receipt or explicit absence. It validates metadata, references, raw bytes,
semantics and the local prefix link. It does not authorize scope access, assess
current source health or establish that absent events were collected.

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

Local Linux AMD64 acceptance has 18 focused tests, including frozen independent
vectors, actual page exhaustion, corruption, ownership/cancellation races,
closed relocation and subprocess SIGKILL at three transaction boundaries.
Bundled SQLite 3.53.2 build options and the reviewed source fingerprint are retained
in `target/source-coverage-store-20261007/sqlite-build.json`. VFS write/sync fault
injection, power-loss behavior, refreshed images and native ARM64 remain open.

```bash
cargo test -p signal-coverage --locked --offline
python3 scripts/check-source-coverage-backend.py --self-test
```

Trusted intake and exact-byte original-receipt replay, correction admission,
payload/identity prefix pruning, frontier scans, observers and cloud/server
integration require separately bounded tasks. The 56 planned history outcomes
are not claimed as implemented by these primitives.

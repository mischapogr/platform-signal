# Development upgrade and restore compatibility

The current package is `0.1.0-dev.0`. No released-to-released upgrade is qualified.
Supported state transitions are explicit operator actions, never startup migration.
The runtime requires the selected schema profile and exact compiled artifact hashes.

| Source | Supported action | Destination | Conditions |
| --- | --- | --- | --- |
| Absent control namespace | `ControlAdministrator::initialize` | Administration revision 2 | Explicit schema owner, identity and finite budgets; readiness remains false |
| Exact notification-qualified revision 1 | `ControlAdministrator::migrate` | Administration revision 2 | Frozen 001/002 identities, complete valid catalog/history, stopped readiness and cleared owners/leases |
| Exact administration revision 2 | Explicit catalog migration | Catalog revision 4 | Exact ordered source chain, stopped ownership, valid retained history and bounded exclusive locks |
| Consistent stopped revision 2 checkpoint | Explicit stopped restore | Fresh restored revision 3 | Verified immutable originals, source/cursor witnesses, fresh destination generation and explicit current authority |
| Consistent stopped catalog revision 4 checkpoint | Explicit catalog restore | Fresh restored catalog revision 5 | Complete exact catalog/object versions and history; separately selected scoped/custody addons require their own exact contracts |
| Exact retained multi-event v2/v3 function | Explicit stopped `018-multi-state-publication-upgrade.sql` | Multi-event v2/v3/v4 function | Exact legacy body retained in `010-v3-multi-event-publication.sql`; schema owner, stopped readiness and bounded exclusive lock; original function identity, ACL and data preserved |
| Absent sensor maintenance namespace | Explicit stopped `020-sensor-maintenance.sql` installation | Sensor maintenance addon | Schema owner and stopped readiness; function grants remain explicit; no event/head/checkpoint publication or startup migration |
| Absent sensor bootstrap namespace | Explicit stopped `021-sensor-bootstrap.sql` installation | Sensor bootstrap addon | Schema owner and stopped readiness; separate runtime grant initializes only an absent state at the explicitly selected current checkpoint; no schema migration or event publication at startup |
| Same current server/agent binaries and stopped Small state | Isolated byte-preserving copy and restart | Same Small formats | WAL identity/checkpoint, spool, Parquet/findings and permissions retained together; original/backup unchanged |

The [shared-control contract](48-shared-control-runtime.md) defines exact artifact
identities, privileges, locks and migration witnesses. The [custody contract](51-object-custody.md)
defines protected originals and fresh restored confirmation. A copied source file
has a new inode: its old file cursor cannot be reused; rereading can duplicate
source lines under new canonical event IDs. The stopped restore rehearsal checks
that behavior explicitly rather than claiming exactly-once source delivery.

Unknown/newer revisions, earlier development bundle variants, partial or divergent
migration history, corrupted functions/catalogs/cursors and incompatible selected
runtime profiles fail closed. Repeating committed migration conflicts. Cancellation
or DDL error rolls back; uncertain COMMIT requires read-only inspection, never
blind retry. Readiness and authority are separate operator decisions.

Binary downgrade after a committed schema migration is unsupported. Restore is a
separate procedure with a fresh generation and current authority; it is not a
schema downgrade and does not revive old owner credentials. Before an upgrade,
stop all writers, retain consistent state plus independent originals, rehearse the
selected supported path, and preserve exact artifact/binary/checksum evidence.

The multi-state addon is under SENSOR-HEALTH implementation. Fresh installations
use the current `010-multi-event-publication.sql`; existing installations must
use the explicit stopped 018 upgrade. The legacy file is a qualification input,
not an instruction to replace a live function. Runtime startup never applies
either installer. The upgrade refuses ready stores, runtime roles, unknown bodies
and repeated application; it leaves readiness stopped. The local PostgreSQL
qualification at `target/sensor-health-standard-20261015/postgres-02/` verifies
these refusals and preservation of populated data, function identity and ACL.
This does not qualify Standard sensor execution or released-to-released upgrades.

Run `python3 scripts/check-upgrade.py --output target/<fresh-owned-upgrade> --image
postgres@sha256:<qualified-digest>` with current prebuilt server/agent binaries.
The helper runs the existing owned PostgreSQL migration/restore fixture and Small
stopped backup/restore fixture, checks their complete reports, cleanup, binary
identities and source drift, and retains gate logs. This proves local development
state transitions and simulated object authority; actual release binaries,
external provider retention, EKS, remote architecture and production recovery
remain separate qualification gates.


Physical state-scope migration after a supported scoped catalog restore is a
separate explicit owner operation. Build `StateScopeRebindInput::new` from the
current scope, sealed old physical generation and exact retained `RevisionedState`,
then call `ControlAdministrator::rebind_state_scope`. It requires restored
catalog5, a complete authentic restore record, stopped readiness and cleared
leases. The existing bounded administrator worker supplies cancellation,
transaction rollback and uncertain-COMMIT handling. No runtime grant or installer
is added, and startup never invokes the migration.

The target changes only `metadata.scope.generation`. Logical `scope_generation`,
rule revision, checkpoint, canonical references and pending output data stay
unchanged. Exact source comparison prevents applying a stale migration; an exact
already-current target is an idempotent echo. This state CAS differs from repeating
a schema upgrade. After uncertain COMMIT, inspect the exact current state and
sealed lineage read-only; retain the hold on divergence. The operation preserves
readiness, leases, event/finding history and row count, and accounts for any byte
delta atomically, including the retained restore-record charge. Native sensor
restore integration and final release qualification remain separate.

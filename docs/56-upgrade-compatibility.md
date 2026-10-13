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

Run `python3 scripts/check-upgrade.py --output target/<fresh-owned-upgrade> --image
postgres@sha256:<qualified-digest>` with current prebuilt server/agent binaries.
The helper runs the existing owned PostgreSQL migration/restore fixture and Small
stopped backup/restore fixture, checks their complete reports, cleanup, binary
identities and source drift, and retains gate logs. This proves local development
state transitions and simulated object authority; actual release binaries,
external provider retention, EKS, remote architecture and production recovery
remain separate qualification gates.

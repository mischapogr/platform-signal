# Upgrade and versioning policy

The workspace is `0.1.0-dev.0`. No production release or published artifact has
been qualified. There is no released-version upgrade path or automatic format
migration tool. The [release audit](docs/21-release-readiness.md) tracks remaining
qualification; development checkout compatibility does not establish released
crate compatibility.

## Current contracts

Version numbers describe separate contracts and are validated independently:

| Contract | Current version | Reference |
| --- | --- | --- |
| Canonical event and HTTP JSON response | `schema_version: 1`, HTTP `/v1` | [Event contract](docs/adr/003-event-contract.md), [ingest](docs/09-phase1-ingest.md), [query](docs/13-phase4-query.md) |
| Server YAML | `schema_version: 1` | [Server configuration](docs/14-phase5-core.md) |
| Rule YAML | `apiVersion: signal.dev/v1` | [Rules and findings](docs/14-phase5-core.md) |
| SDK rule-provider envelope | `RuleDocument` version 1 | [Collector SDK](docs/16-collector-sdk.md) |
| WAL framing/checkpoint | Format 1; stable stream UUID | [WAL ADR](docs/adr/006-wal-durability.md) |
| Parquet event/commit metadata | Storage schema 1 | [Storage ADR](docs/adr/004-parquet-format.md) |
| Findings journal | Versioned stream-bound journal, deterministic finding IDs | [Findings ADR](docs/adr/011-rules-findings.md) |
| Agent spool and persisted source state | Version 1 records/state | [Agent ADR](docs/adr/012-agent-spool.md), [agent contract](docs/15-phase6-agent.md) |

Unsupported versions and invalid configuration fail validation; corruption is
not a migration signal. Preserve nested event attributes and existing event and
finding identities. The WAL, event store and findings store must retain the same
stream identity. Changing rule definitions can change replay results; preserve
the rule set with the deployment and its backup.

Before any format or public contract change, document its compatibility,
migration and rollback behavior, add fixtures from the preceding supported
version, and qualify the actual upgrade and restore paths. No compatibility with
an untested future version is promised. A package version change alone does not
change event or disk format versions.

## Offline backup and restore rehearsal

The synthetic Linux AMD64 [offline restore gate](tests/integration/README.md)
has exercised these mechanisms with identical `0.1.0-dev.0` binaries. It copies
stopped server data/configuration/rules and a pending agent spool, checks file
hashes, modes and ownership, and restores into separate local directories.
Pending WAL/spool events retain canonical identities; existing findings and a
further restart remain stable. Original and backup inventories stay unchanged.
This is local same-binary proof, not production backup acceptance, cross-version
migration, or crash durability of the backup media.

1. Record the exact application/image identity, configuration, rule set,
   architecture, volume mapping and agent source paths. Keep credentials and
   organization values in their external configuration store.
2. Stop agent input and allow its existing spool to drain when possible. Stop
   server admission and perform graceful shutdown. Verify the server and agent
   processes and their disk workers have exited before copying files. An HTTP
   202 proves WAL synchronization, so preserve any undrained WAL records.
3. Copy the entire stopped server data root together: WAL segments, checkpoint,
   stream identity, Parquet files and commit metadata, and findings journal.
   Copy the entire stopped agent spool, including persisted cursor/source state.
   Preserve file ownership, permissions and relative paths. Do not copy only
   visible event partitions or only the WAL checkpoint.
4. Retain an untouched backup with a file inventory and checksums. Restore a
   separate copy onto isolated local volumes with the recorded versions,
   configuration and rules. Use one server writer and one owner of each agent
   spool. Do not let rehearsal agents read or advance live source files.
5. Verify startup, readiness, authenticated ingestion and queries, canonical
   event/finding identities, replay completion and storage limits. Verify agent
   cursor behavior using copied sources and fixtures. Record the actual image,
   results and any rejected or replayed inputs. Keep at-least-once delivery in
   mind: independent admissions with the same event ID are not globally deduped.
   A file cursor also requires the original device/inode, offset and byte anchor.
   A copied source usually has a new inode, so its old cursor does not apply:
   reread lines can produce new IDs even after the restored spool has drained.
   The gate observes this reread, then verifies cursor reuse on the restored
   file and delivery of one newly appended line. Plan source replay and downstream
   duplicate handling in the external application; do not edit spool cursor bytes
   to pretend that two source files have the same identity.
6. A rollback uses a qualified previous binary and a compatible untouched data
   backup. Never start an older binary against a store modified by an unqualified
   newer format. Keep the originals stopped and preserved until the rehearsal
   result has been reviewed.

Helm upgrades use a single replica and `Recreate`. For manual replacement,
verify the old writer has stopped before starting its replacement; a live
ReplicaSet pod deletion alone can overlap writers. ReadWriteOnce limits nodes,
not processes on the same node. ConfigMap config/rule keys use regular `subPath`
mounts; external rule or Secret changes need a controlled restart. See the
[chart contract](deploy/helm/signal/README.md) and
[packaging reference](docs/19-packaging.md).

Source cursor guarantees have limits: an agent restart cannot rediscover unread
bytes in a renamed old file, and unspooled partial lines are not durable. Preserve
rotated source files and establish source retention outside the OSS mechanism.
Retention, archive ownership and deployment-specific backup schedules belong to
the external application.

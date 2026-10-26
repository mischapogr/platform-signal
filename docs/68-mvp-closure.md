# Core MVP closure without AWS

Historical decision snapshot: 2026-10-23. Records the owner's decision to close the core MVP without AWS
qualification, what that leaves open, and the review packet and owner steps that
remain. It selects no version and publishes nothing. This is not a v0.1.0 release.

## Decision

The core MVP is the scope in [02-mvp.md](02-mvp.md): ingest, bounded WAL, Parquet,
query, YAML rules with durable findings, the edge agent, the private-overlay boundary,
AMD64/ARM64 artifacts and the minimal SecOps UI. The security roadmap in
[04-implementation-plan.md](04-implementation-plan.md#security-requirements-roadmap)
and AWS qualification are post-MVP. Qualified runtime: `7fa481e`.

The qualification below applies to the exact historical runtime `7fa481e`.
Subsequent AWS-free development changes runtime inputs; this evidence does not
qualify the current checkout. Current source/evidence boundaries and remaining
work are in [progress](07-progress.md), [release readiness](21-release-readiness.md)
and the [execution ledger](31-execution-ledger.json).

## Definition-of-done status

At the 2026-10-23 snapshot, all [06](06-definition-of-done.md) boxes were checked except three:

| Open box | Why | Class |
| --- | --- | --- |
| EKS test-environment persistent restart smoke | Needs an AWS account; harness and runbook exist ([66](66-aws-eks-qualification.md)), not executed | Post-MVP, owner-authorized AWS |
| Required remote native CI passes on the reviewed revision | CI passes at `7fa481e` (run 38898992993); "reviewed" waits on the independent review below | Open until review |
| External overlay builds/tests against released OSS dependencies | Needs a published public version | Follows publication |

The ARM64 build, native ARM64 kind smoke and native ARM64 hardening/benchmark boxes
were checked on 2026-10-23 from the digest-verified run 38898992993 artifacts
(`target/candidate-replay-retry-20261016/NATIVE-ACCEPTANCE.json`). The soaks are
finite; they prove neither capacity nor prolonged stability.

## Ledger classification

The 2026-10-23 ledger listed 36 accepted and 16 unfinished items. The current
2026-10-26 inventory is 40 accepted and 12 unfinished, with CORRELATION in progress;
the linked ledger is authoritative. Historical classification after core MVP closure:

| Items | Class | Reason |
| --- | --- | --- |
| CLOUDWATCH, AWS-PROFILES | Post-MVP | AWS source adapters (Phase 9); off the path to LOCAL-CANDIDATE |
| EKS-AUDIT, K8S-CONTEXT, BASELINES, STATE | Next, AWS-free | Rewritten 2026-10-23; EKS CloudWatch transport and SIG-D12 stay deferred |
| CORRELATION, PROFILE-LOAD, SCALE-DECISION | Next, AWS-free | Follow STATE in dependency order |
| SOC-UX | Next, AWS-free | Advanced SOC UX stays outside the core MVP; the minimal UI is done |
| RELEASE-TRUST | Next, AWS-free | Offline slice passes; the full item follows BASELINES |
| LOCAL-CANDIDATE | Last | Needs the items above, KIND, RELEASE-REVIEW and UPGRADE |
| EXT-AWS, EXT-VENDORS | External | Need real accounts and providers |
| EXT-DEPENDENCY, EXT-PUBLICATION | External | Need a released version and owner authority |

The ledger dependencies were rewritten on 2026-10-23 so none of these paths reaches an
AWS adapter or EXT-* item (see the note at the top of the ledger). "Post-MVP" here means
after the core MVP closure, not unplanned.

## Independent review packet

Historical status: prepared, not delegated. This packet concerns only `7fa481e`;
focused implementation reviews do not replace a current-source release review.

- Scope file: `target/candidate-replay-retry-20261016/INDEPENDENT-REVIEW-SCOPE.json`
  (60 read paths with SHA-256, read-only, no write paths).
- Review immutable `7fa481e` with `git show`; current runtime changes require their own source-bound review.
- Focus: original deadline/cancellation and at-least-once recovery under uncertain
  COMMIT; atomic WINDOW/sensor state and original finding bytes; stopped sealed-lineage
  restore scope rebind and quotas; bounded bootstrap/pins and least-privilege producers.
- Evidence to read: `target/sensor-health-standard-20261016/ACCEPTANCE.json`,
  `target/candidate-replay-retry-20261016/ACCEPTANCE.json` and `NATIVE-ACCEPTANCE.json`.
- Excluded: `.envrc`, `.codex/`, `.mcp.json`, `.aws/`, `.serena/`, `docs/presentations/`.
- Stop condition: one report of source-bound findings with location, severity and
  reproduction. The reviewer writes nothing, contacts no service and spawns no agent.

## Owner steps

Not run. Version, publication and `main` decisions need the owner. At the historical
snapshot the remote had only `develop`; verify remote topology before release work.

1. Choose the version; align Cargo, chart and binaries ([VERSIONING.md](VERSIONING.md)).
2. Authorize the independent review above, or accept its absence in limit 9 of the
   [release notes](67-release-notes-draft.md).
3. Fill the remaining `<…>` fields in the release notes and convert the CHANGELOG
   `Unreleased` section.
4. Create `main` from the reviewed commit and tag it:
   `git switch -c main <commit> && git push -u origin main && git tag -s v<version>`.
5. Satisfy [50-ghcr-publication.md](50-ghcr-publication.md) and signing
   ([57-offline-release-trust.md](57-offline-release-trust.md)) before publishing.

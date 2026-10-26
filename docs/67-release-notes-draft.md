# Release notes and limits wording (draft)

Draft only. No version is selected, nothing is published and EXT-AWS is open. Figures below are filled for runtime `7fa481e`; the remaining `<…>` fields need the owner. See [MVP closure](68-mvp-closure.md). The owner
fills the `<…>` fields and re-verifies every figure against `docs/07-progress.md`,
`docs/21-release-readiness.md` and the ledger at the release revision before use.
Wording rules: say what was run, where, and what it does not prove; never imply AWS,
HA or production capacity.

## Release notes — `<version>` (<date>)

PLATFORM::SIGNAL is a lightweight log and security-event pipeline in Rust for small and
mid-sized AWS-centric teams: validated HTTP ingest, bounded durable WAL, Parquet storage,
URL-parameter query, YAML rules with durable findings, an edge agent and a collector SDK.

### Highlights

- HTTP 202 means the event was synced to the WAL. A consumer then publishes Parquet,
  evaluates rules, persists findings and only then advances the checkpoint. Delivery is
  at least once; replays may duplicate.
- Single-writer monolith (`signal-server`) plus `signal-agent` and `signalctl`; Small
  profile (filesystem) and Standard profile (PostgreSQL, S3-compatible custody) paths.
- Hardened container (non-root, read-only root) and Helm chart for Kubernetes, one replica,
  one writable volume.
- Selected source profiles verified against simulated providers: CloudTrail objects,
  Cloudflare Logpush, FortiGate syslog (mTLS), Microsoft 365 activity, Cato eventsfeed,
  host authentication, Falco; detectors for authentication windows and sensor health.
- Linux AMD64 and ARM64 artifacts and images from native GitHub-hosted CI, with source maps,
  digests and SBOMs. Artifacts are unsigned unless the signing step in doc 57/50 ran.

### Qualification summary

| Area | Evidence | Scope |
| --- | --- | --- |
| Rust gates | 1,121 default / 1,191 all-feature tests (local); 1,191 on each native architecture, strict Clippy, fmt, workspace boundaries | Runtime `7fa481e` |
| Native CI | Run [38898992993](https://github.com/mischapogr/platform-signal/actions/runs/38898992993): AMD64 and ARM64 Rust, production image, hardening, pipeline profiles, finite soaks, Cargo audit, image scan | GitHub-hosted runners, finite duration |
| Kubernetes | kind: probes, PVC, SIGKILL and pod-replacement recovery with the original WAL checkpoint | kind only |
| AWS/EKS | Not performed | See limits |

### Upgrade and compatibility

Event/finding serialization, rule `apiVersion`, HTTP `/v1` and WAL format are versioned
independently of the crate version (`docs/VERSIONING.md`). Supported migrations and
restore paths: `docs/56-upgrade-compatibility.md` and `UPGRADING.md`. No
released-to-released upgrade has been tested because no earlier release exists.

## Known limitations (use verbatim)

1. **Not proven on AWS.** No AWS, EKS, EBS, KMS or Object Lock qualification has
   been run; Kubernetes testing used kind, and object storage tests used simulated S3.
2. **Single writer, no HA.** One server process owns the WAL and store. Replicas, failover
   and zone/account loss are not provided or qualified.
3. **Finite load only.** Pipeline and soak runs are finite (e.g. 120 s) on shared runners.
   They do not establish prolonged stability, a resource plateau or physical-device throughput.
4. **Simulated providers.** Vendor and cloud sources were tested with owned simulators.
   Real permissions, retention, delivery completeness and feed behaviour are unqualified.
   Cloud collection of AWS services (Phase 9) is not included.
5. **Synthetic identity and custody authority.** Identity, observer, restore and S3 custody
   authority used test fixtures. Production IdP, key rotation and retention are the operator's
   responsibility and unqualified.
6. **Delivery semantics.** At-least-once; consumers must tolerate duplicates. `reject_new`
   is the default admission policy. UDP syslog is best-effort and unsupported.
7. **Query scope.** URL parameters on `GET /v1/events`; no query language. Time ranges prune
   date/hour partitions.
8. **Scanner results.** Cargo audit reported 0 findings and image scanning 0 HIGH/CRITICAL at
   the recorded revision; MEDIUM/LOW findings remain (`<counts>`). Scans are point-in-time.
9. **Review.** Independent current-source review of runtime `7fa481e` is pending. Writer
   reviews recorded in the progress log are not independent review.
10. **Released dependencies.** The private overlay has not yet been tested against a released public version.

## Do not claim

- "Production ready", "highly available", "AWS qualified" (unless item 1(b), and then only as worded).
- Throughput, capacity or cost figures from finite CI soaks.
- Detection coverage of any vendor beyond the selected, simulated profiles.

## Owner checklist before publishing

- [ ] Version chosen; Cargo, chart and binaries match (`docs/VERSIONING.md`).
- [ ] Figures in the tables above replaced from the evidence at the release revision.
- [ ] Limits 1, 9 and 10 re-checked at the release revision (they now state the current facts).
- [x] README implementation status and CHANGELOG qualification wording updated on 2026-10-23.
- [ ] `CHANGELOG.md` `Unreleased` section converted to the chosen version.
- [ ] Signed provenance/SBOM steps and `docs/50-ghcr-publication.md` conditions satisfied.

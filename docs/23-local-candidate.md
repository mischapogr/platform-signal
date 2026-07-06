# Unpublished local candidate bundle

This procedure prepares a bounded, unsigned local evidence bundle for the
current development snapshot. It is not an alpha, a release candidate, a
registry-ready package or evidence that `v0.1.0` is ready. The owner has asked
to hold staging, commits, pushes and publication until an alpha or first minor
release is ready; no version is selected or bumped here.

The tool does not build, pull, tag, load or publish an image. On native Linux
AMD64, it inspects and saves the exact already-present image ID accepted by the
review record. Its four payloads are:

- `source.tar.gz`: positively allowlisted OSS source, documentation and
  development inputs;
- `signal-0.1.0.tgz`: the public Helm chart;
- `evidence.tar.gz`: selected accepted review inputs and evidence files;
- `image.tar`: Docker's saved archive for the exact local image.

`candidate.json` binds the image, accepted review, source and evidence hashes,
archive inventories, preparation changes and external gates. `SHA256SUMS`
covers the manifest and all four payloads. The metadata fixes the package
version at `0.1.0-dev.0`, records `git_commit: null`, and marks the result
`local_unpublished: true`, `full_release: false` and `registry_ready: false`.
The accepted runtime review binds a 167-file source snapshot. The preview
contains 166 allowlisted source files, retains the accepted snapshot hashes,
and records preparation tooling/documentation separately; its
`source_snapshot_exact: false` field means the prepared source bundle is not
byte-for-byte the runtime image's source snapshot. These preparation deltas
are not accepted runtime changes.

## Prepare and verify

Pass the immutable image ID and the accepted review JSON. Choose a new output
directory under the repository's `target/` tree that does not already exist;
preparation takes exclusive ownership of that path. The paths below show the
current locally qualified image and review record; use the IDs and accepted
review from the evidence being bundled.

```bash
python3 scripts/prepare-local-candidate.py prepare \
  --image sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1 \
  --review target/phase10-longer-soak-20261006/review/final-header-buffer-review.json \
  --output target/local-candidate-team-20261007/final

python3 scripts/prepare-local-candidate.py verify \
  --candidate target/local-candidate-team-20261007/final
```

Preparation requires a Linux AMD64 host, a local Docker daemon with that exact
Linux/AMD64 image, and an accepted review record whose source and artifact
hashes still match. The review must include the matching image report and its
binary-origin evidence. Image preparation uses local `docker info`, `image
inspect` and `image save`; it does not need to pull or rebuild the image.

`verify` is offline: it reads only the completed directory. It checks the
manifest and checksums, requires the expected closed file inventory, validates
safe archive paths and file types, recomputes archive inventories and verifies
the saved Docker image config and ordered layer digests. Its successful result
is `scope: offline-unsigned-local-integrity` with `full_release: false`; this
is integrity verification, not a signature, provenance attestation or release
approval. Do not edit, add or remove files in the candidate directory before
verification.

The tool fails closed on an existing output path, wrong host/image identity,
changed review binding, unallowlisted input, unsafe path, oversized artifact,
archive mismatch, command failure or timeout. It bounds source/evidence/image
archives at 16/64/512 MiB, JSON at 2 MiB, and archive entries at 1,024. A failed
preparation retains a failed `candidate.json` and removes partial payloads it
created so the failure is inspectable; use a new output directory for a rerun.

## Evidence and limits

The source, chart and evidence archives use fixed positive allowlists. The
evidence selection uses these fixed roots:
`target/phase10-header-buffer-20261006`,
`target/phase10-longer-soak-20261006/review`,
`target/phase10-longer-buffered-20261006`, and
`target/phase10-query-reads-20261006`, plus
`target/release-tools-20261006/installation.json`. It includes the accepted
local runtime review and its bound reports, bounded-soak and Parquet-read
evidence, and the recorded AWS-tool installation result. `candidate.json`
lists identified hash references outside the selected inputs as exclusions;
that list does not claim exhaustive provenance closure. No private overlay,
credentials, arbitrary workspace files or whole `target/` tree are included.

The archive preserves the development workspace version and existing chart;
it does not create or choose a version. `signalctl` is source-only in the source
archive and is not present in the server image, which contains the qualified
server/agent image inputs. Preparation changes and the previously accepted
runtime evidence remain separate in the manifest.

The accepted runtime image and local Kubernetes proof are Linux AMD64/kind
evidence. The owner-selected local Kubernetes milestone is complete with kind
1.34 and the standard chart, but this does not establish actual EKS or AWS
storage/runtime behavior. Native ARM64, actual EKS, remote CI, released
dependencies and publication remain separate release gates. Keep the
bundle local and unpublished under the owner's release hold.

The bundle is unsigned; this describes its bounded integrity scope and does
not add a signing prerequisite to the existing release gates.

## Local preview evidence — 2026-10-07

The dated preview at `target/local-candidate-team-20261007/preview2/` passed
preparation, offline verification and relocation/source-path-graph validation.
The relocated validation records seven checks total, including four
packaged-chart checks: strict lint and default/optional renders.
The relocated validation is retained at
`target/local-candidate-team-20261007/preview2-relocated/validation.json`;
its candidate-manifest SHA-256 is
`b14b290ac34c4ec6daf26f974d709a45f2c5cc998515a03db99b6305e9cf17f2`, and its
scope records `full_release: false`. The preview contains 11 chart files and
129 evidence files; the exact AMD64 image archive is
110,772,224 bytes and matches image
`sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1`.
This validates the local preparation path only; remote dependencies were not
qualified and image runtime was not repeated. The first preview failure and
its retained diagnostic are historical; the fixed standard tar padding passed
16 focused regressions. The relocated bundle also passed its bundled offline
verification without the original source checkout, recorded in
`target/local-candidate-team-20261007/preview2-relocated/bundled-offline-verify.json`.
Final candidate export and independent review are separate checks, with result
locations at `target/local-candidate-team-20261007/final/`,
`target/local-candidate-team-20261007/final-relocated/validation.json`, and
`target/local-candidate-team-20261007/review/final-candidate-review.json`.

The exact tool contract and bounds are in
[`prepare-local-candidate.py`](../scripts/prepare-local-candidate.py); local
candidate evidence and completion status are recorded in
[`07-progress.md`](07-progress.md) and the
[`release-readiness audit`](21-release-readiness.md).

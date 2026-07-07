# Supply-chain reports (Phase 8-C)

CI builds and scans an image on each native Linux AMD64/ARM64 runner. Reports
are saved even when the scanner gate fails. No image, package or attestation is
published by this workflow. Remote CI execution requires a pushed revision; local
results do not establish remote CI or release qualification.

## Reproduce locally

Build the production image, then scan that existing local image:

```bash
docker build -f deploy/docker/Dockerfile -t platform-signal:phase8 .
python3 scripts/check-supply-chain.py --image platform-signal:phase8
```

The script downloads pinned official release binaries into ignored
`target/supply-chain/tools/`, verifies SHA256 before extracting the regular
executable, and revalidates the archive on each run. It never installs global
tools. Linux AMD64 and ARM64 have separate checksum pins in the script. Download
time is at most 180 seconds per tool, archive size at most 128 MiB, and individual
scan subprocesses have 600-second deadlines and a 2 GiB per-file limit (the
current Trivy SQLite database is about 1.4 GiB). Report files exceeding 64 MiB
are removed after each command and fail the gate; transient files remain bounded
by the subprocess limit. Trivy
also has a nine-minute deadline. An unavailable database or scanner produces a
failed gate; it is never represented as a clean report. Database cache disk
usage is owned by the tools; remove `target/supply-chain/` after retaining the
needed evidence. CI uses disposable runners and a finite job timeout.

Each invocation writes a fresh timestamp directory under
`target/supply-chain/reports/` (or under the supplied `--output` directory).
Reports include:

- `cargo.spdx.json`: SPDX dependency inventory from copies of the OSS Cargo.lock
  and root manifest, without scanning source files or the external overlay.
- `cargo-audit.json`: fresh RustSec audit of Cargo.lock, with database commit,
  timestamp, vulnerability details and informational warnings. Yanked-package
  checks are disabled; this gate checks security advisories rather than crate
  availability.
- `image.spdx.json`: SPDX inventory of the final local container filesystem.
- `image-vulnerabilities.json`: Trivy report for all vulnerability severities.
  HIGH or CRITICAL findings fail the gate, including findings without a fix.
- `image.json`: Docker's inspected image configuration and immutable image ID.
- `provenance.json`: versioned local evidence including Cargo.lock SHA256,
  image ID/architecture, release archive and executable hashes, report digests,
  scanner versions, database metadata, timestamps and check exit codes.
- Per-command logs and bounded standard output for failures.

The immutable local image ID is used for both image scanners after inspection.
The image scan uses the Docker daemon explicitly and does not pull an image.
Cargo dependency audit failures also fail CI. Informational RustSec warnings
remain visible without automatically becoming vulnerability exceptions. There
are no ignored advisories or vulnerability IDs supplied by this script. Scanner
configuration is explicitly empty, and the container ignore file is empty.
An owned local `.cargo/audit.toml` takes precedence over the user's Cargo home
configuration (confirmed in the pinned official cargo-audit source). The Cargo
audit's actual settings are recorded in JSON and checked for unexpected advisory
filters. Inherited Syft/Trivy environment settings are cleared before scans.

The Cargo inventory identifies locked dependencies, including build and test
packages; it does not prove every dependency is linked in a shipped executable.
Static Rust executable discovery in container scanners is incomplete. Use the
Cargo audit alongside the final-image OS/library scan; a clean image scan alone
does not establish absence of vulnerable Rust dependencies. SPDX includes
available license metadata; it does not constitute legal approval or a complete
license policy check.

These hashes bind local artifacts to the recorded inputs and scanner reports.
They are unsigned local evidence, without a signing identity, independent
builder attestation, registry digest or SLSA provenance claim. CI uploads the
reports with 14-day retention using a commit-pinned official action.

## Tool provenance and command references

Pins were obtained from official release metadata and checksum manifests on
2026-10-06:

- [Syft v1.54.1 release](https://github.com/anchore/syft/releases/tag/v1.54.1),
  [SHA256 manifest](https://github.com/anchore/syft/releases/download/v1.54.1/syft_1.54.1_checksums.txt).
- [Trivy v0.75.0 release](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0),
  [SHA256 manifest](https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_checksums.txt).
- [cargo-audit v0.22.2 release](https://github.com/rustsec/rustsec/releases/tag/cargo-audit/v0.22.2):
  SHA256 pins come from GitHub's official release asset `digest` metadata.
- [upload-artifact v7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1),
  commit `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` resolved through the
  official repository API.

Checksum verification detects substituted download bytes against the repository
pins. It does not claim independent signature verification or trust in an
upstream release's security. Review release provenance when updating pins.

Current command syntax was checked with Context7's official Syft and Trivy
documentation and with the pinned executables' help output. cargo-audit was not
available as a matching Context7 library, so its
[official README](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/README.md)
and pinned executable help were used. Reference:
[Syft sources](https://github.com/anchore/syft/wiki/Supported-Sources),
[Syft outputs](https://github.com/anchore/syft/wiki/Multiple-Outputs),
[Trivy container targets](https://github.com/aquasecurity/trivy/blob/main/docs/guide/target/container_image.md),
[Trivy SBOM](https://github.com/aquasecurity/trivy/blob/main/docs/guide/supply-chain/sbom.md).

## Local verification evidence

The first fresh RustSec report inspected 327 locked dependencies and found zero
security vulnerabilities and no informational warnings. Database: 1,290
advisories, commit `ef6173cbc5c50ec8166f9a5b28f07834144373ee`, updated
`2026-10-03T10:14:03+02:00`. Current complete run evidence is recorded in
[07-progress.md](07-progress.md); retain the corresponding report directory for
exact image IDs, package counts, hashes and database metadata.

The initial complete AMD64 scan of image
`sha256:cbf2746cf81fe6aced3c0627df9d1f483a24b0171d7b6a3dddd97b10ee39c745`
completed on 2026-10-06. The Cargo SBOM contained 328 packages and image SBOM
107 packages. Both SBOMs, cargo-audit and Trivy completed successfully; the
container policy failed with 65 HIGH and four CRITICAL package/advisory
occurrences (25 distinct HIGH/CRITICAL advisory IDs). The remaining severities
were 130 MEDIUM, 123 LOW and two UNKNOWN. Seven HIGH/CRITICAL occurrences had a
reported fixed version: `perl-base` `5.36.0-7+deb12u3` →
`5.36.0-7+deb12u4`. Other HIGH/CRITICAL findings had no reported fixed version,
including `CVE-2023-45853` for `zlib1g` with vendor status `will_not_fix`.
No findings were ignored. These are scanner findings, without an application
reachability or exception acceptance claim.

Initial reports: `target/supply-chain/reports/20261006T183917.087860Z/`.
Trivy DB updated `2026-10-06T13:07:05.606377799Z`; report SHA256
`536e159131c98a6a958a8dd53b57c1defe5631ba921c8fef7e7968c54c35218b`.
Later image remediation and final qualification status belong to
[07-progress.md](07-progress.md). The scan mechanism is working; these findings
must not be described as a passing container security gate.

## Remediated runtime evidence

The pinned distroless Debian 13 C++ runtime replaces the shell/package-manager
image and its curl probe with a bounded Rust health helper. The fresh image
`sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97`
passed all scanner commands and the HIGH/CRITICAL policy gate. Its SPDX inventory
contains 15 runtime packages; Cargo inventory remains 328 packages with zero
RustSec vulnerabilities. Trivy reports zero HIGH, zero CRITICAL, 23 MEDIUM and
eight LOW occurrences. No advisories are ignored; lower-severity findings remain
in the report. These counts do not establish application reachability or the
absence of vulnerabilities outside scanner coverage.

Final reports: `target/supply-chain/reports/20261006T184541.680363Z/`.
The provenance binds reports and database metadata to the new immutable image ID.
Earlier failed reports remain available; they describe the previous image.

# ADR-014: Minimal runtime and a single persistent Kubernetes writer

**Status:** Implemented; Linux AMD64 container and scan gates passed. Local
Kubernetes restart/PVC qualification passed. Native ARM64 and EKS remain unverified.

**Phase:** 8

## Context

The monolith must retain WAL, events and findings across restarts, run without
root or a writable root filesystem, and keep the company overlay external.
Existing configuration and rule loaders reject symlinks and nonregular files.
Multiple processes must not write the same filesystem stores concurrently.

The initial Debian 12 runtime scanned with 65 HIGH and four CRITICAL
package/advisory occurrences. Its package manager, shell and curl were unnecessary
to run the application. These concrete findings require runtime remediation.

## Decision

- Pin the Rust builder and distroless Debian 13 C++ runtime by verified public
  multiarchitecture index digests. Include server and agent binaries and licenses.
  The runtime provides the dynamic libraries and CA certificates without a shell
  or package manager.
- Use a small standalone Rust health probe. Numeric-address connection, request
  writes and response reads share one two-second deadline; its response buffer
  is 128 bytes. It returns an exit status without emitting values or credentials.
- Run as UID/GID 65532 with a read-only root, dropped capabilities and explicit
  writable data and bounded temporary mounts.
- Deploy one replica with `Recreate`. Retain the PVC on uninstall and allow an
  existing claim. Stop the old process before replacing its pod; verify the same
  claim and exact event/finding identities afterward.
- Mount ConfigMap configuration and explicitly listed YAML rule keys using
  read-only `subPath` file mounts. Ordinary ConfigMap directory projections expose
  symlinks and fail the existing loader contract. External keys are validated as
  filenames, without paths or duplicates.
- Require controlled restart for external ConfigMap/Secret changes. Reference
  tokens through existing Secrets; private deployment values and rules remain
  outside the OSS repository.
- Pin tools and CI actions. Generate SBOMs and scan the inspected immutable local
  image ID. HIGH/CRITICAL findings fail, including unfixed findings. Retain all
  severities and unsigned local provenance; do not claim signed attestations.

## Verification and limits

Two real TCP probe tests cover status validation and an absolute deadline under
trickled responses. Three Kubernetes cleanup regressions exercise ignored
termination, failed kill and unattempted-cluster isolation. Helm schema/render
checks enforce one replica and file-mount compatibility.

The remediated image passes native AMD64 container restart/auth/security checks
and the scan policy with zero HIGH/CRITICAL findings. Twenty-three MEDIUM and
eight LOW findings remain recorded. Earlier failed image/cluster attempts remain
documented. ReadWriteOnce restricts node attachment, while SIGNAL additionally
requires a single process writer. These choices do not provide high availability,
backups or production qualification. Native ARM64, EKS, remote CI, publication
and complete release gates remain separate. See
[packaging](../19-packaging.md) and [progress](../07-progress.md).

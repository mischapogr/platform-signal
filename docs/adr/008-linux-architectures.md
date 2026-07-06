# ADR-008: Linux AMD64 and ARM64

Status: Established by the supplied architecture specification.

## Context and decision

Support both architectures with the same crate graph and serialization contracts.
Use native CI runners for each architecture and a multi-platform Docker build.
Avoid architecture-specific intrinsics and native dependencies unless measured
need and both target builds justify them.

## Consequences and verification

Phase 0 supplies a native CI matrix and a container skeleton built on each target.
Local AMD64 checks do not prove ARM64. Image publishing, runtime health checks,
SBOM, scanning and Kubernetes proof belong to Phase 8 and release hardening.

# Versioning and compatibility

All workspace crates share a version. The foundation is `0.1.0-dev.0` and all
packages have `publish = false` until an intentional release prepares metadata
and satisfies `docs/06-definition-of-done.md`. Use SemVer and Conventional Commits.

For `0.x`, compatibility-breaking public API changes increment the minor version;
compatible fixes increment the patch version. Record migrations and limitations
in release notes. Stable `1.x` releases use normal major-version breaking changes.

Event/finding serialization, rule `apiVersion`, HTTP `/v1` and WAL on-disk format
are independently versioned contracts. A crate version bump does not silently
change those formats. Reject unsupported versions with a contextual error and
document any migration before changing persisted representations.

Commit `Cargo.lock` for reproducible application builds. MCP dependencies have a
separate npm lockfile. The tested Rust toolchain is pinned; update the pin and
minimum Rust version together with CI evidence, including ARM64. Arrow/Parquet
versions must match the chosen DataFusion dependency family when Phase 3/4 lands.

# Contributing

Read `AGENTS.md` and `docs/01..06` before changing architecture. Implement one
phase at a time and attach its exit evidence and phase review to the change.
Public code contains generic mechanisms; company policy lives in a separate
overlay. Preserve existing work and never include credentials.

## Development

Install Rust through rustup. `rust-toolchain.toml` pins the tested toolchain and
components. Start with:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-workspace.py
```

See `docs/08-development-tooling.md` for optional Codex/Claude Code MCP tools.
Node and MCP packages are development tooling only, not Rust/runtime dependencies.

Add tests for meaningful behavior and failure modes. Prefer real filesystem and
process integration tests for WAL, storage and recovery. No unbounded queues,
undocumented production unwrap/expect, or secret logging. Network/disk operations
need cancellation and deadlines. Build and test Linux AMD64 and ARM64 in CI.

## Changes and licensing

Use Conventional Commits when commits are requested, for example `feat(ingest):
validate event batches`. Keep one reviewable change set per phase. Contributors
retain copyright; submissions are licensed under Apache-2.0, the project license.
Do not add third-party content without compatible terms and attribution.

See `docs/VERSIONING.md` for release and serialized-contract versioning.

Develop on `develop`. Merge into `main` only when the required
[release gates](docs/21-release-readiness.md) pass and the release is authorized.
Use SemVer for releases; a development commit does not select a release version.
Commit messages describe the change without agent-attribution trailers. Local
commits, remote pushes and publication have separate authorization; preserve an
explicit request to leave a task unstaged/uncommitted.

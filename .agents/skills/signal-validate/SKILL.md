---
name: signal-validate
description: Select and run PLATFORM::SIGNAL acceptance checks, preserving evidence scope and avoiding redundant full campaigns. Use when validating a change or preparing phase acceptance.
---

Read AGENTS.md and the task's contracts before selecting checks. During Rust
implementation, run regressions for the affected crate and failure cases. At a
phase/code acceptance boundary, run the required gates from the repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-workspace.py
```

Apply the phase review checklist in docs/05-implementation-prompts.md and the
applicable process/container/overlay/security gates. Reuse scripts/check-*.py
and scripts/test-*.py rather than inventing parallel validators. Tooling-only
changes need their configuration/skill/helper checks; they do not need a Rust
campaign unless Rust behavior or build inputs changed.

Reuse accepted image/campaign evidence only when the source, configuration,
architecture and immutable image still match. Rerun checks affected by subsequent
corrections. A missing credential or host is an environment boundary, not a
reason to rerun completed local acceptance or increase model effort.

Retain full logs and machine-readable reports under an owned target/<task>/
directory and return command, exit status, exact count/scope and artifact path.
Inspect real untracked files: this repository can have an unborn HEAD, so
`git diff` alone cannot establish the change set. Preserve retained target
qualification evidence. Report source/local/cluster/remote acceptance separately.

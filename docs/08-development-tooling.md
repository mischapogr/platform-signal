# Development tooling

For remaining task allocation and recommended Codex/Claude models, see
[11-model-work-plan.md](11-model-work-plan.md). Model and effort examples there
apply to individual new sessions. The owner-approved 2026-10-07 setup below
applies the routine defaults locally to SIGNAL.

## Rust and repository

The existing Git repository is initialized already. No initial commit is needed
to build or test. Install rustup; the repository pins Rust 1.94.1 with rustfmt and
Clippy. Runtime dependencies are locked in `Cargo.lock`; Phase 0's earlier
dependency-free scaffold is historical. See `CONTRIBUTING.md`
for the three required Cargo gates and dependency-direction check.

## Codex and Claude Code MCP

Context7 supplies current Tokio, Axum, Serde, Arrow/Parquet and DataFusion
documentation. It is the only project MCP needed for the foundation. Cargo, Git,
filesystem and shell operations use the agents' built-in tools. Add AWS or
Kubernetes integrations when their phase needs them, with an explicit scope.

Both clients use the same locally installed server, pinned to **4.1.1** with
transitive dependencies in `tools/mcp/package-lock.json`. It needs Node.js
20.18.1 or newer; Node 24 is tested here. No global npm package is installed.

```bash
npm ci --prefix tools/mcp --ignore-scripts --no-fund
python3 scripts/ai/check-mcp.py
python3 scripts/ai/check-mcp.py --live
```

The first check initializes the actual process and lists documentation tools.
The second resolves Tokio through the live service. Handshake success proves
server startup, not external connectivity. Do not rely on this optional service
for CI's Rust correctness gates.

Launch both clients from the repository root so the relative launcher resolves:

- **Codex:** `.codex/config.toml` adds the project `context7` stdio server with
  startup/tool deadlines. Trusted projects load this layer. Check discovery with
  `codex mcp get context7 --json` and restart an existing session to use it.
- **Claude Code:** `.mcp.json` adds the same stdio server. `CLAUDE.md` points to
  shared `AGENTS.md`. Check `claude mcp get context7`; approve the project server
  in Claude Code's interactive workspace/MCP prompt if requested.

These files contain no credentials. The project selects model/effort defaults
without editing global client settings, authentication or permissions. A same-name project entry overrides inherited Context7
configuration in terminal clients. Project overrides disable unrelated inherited servers; an existing session
can retain its previous model and catalog until restarted.

Context7 recommends an API key for higher limits. An optional `CONTEXT7_API_KEY`
may be supplied in the launching shell; never put it in tracked configuration or
command arguments. Anonymous lookup is used for initial verification. Queries go
to an external documentation service: send generic library topics, not private
logs, rule content, identifiers or credentials.

Official configuration references:

- [Codex MCP](https://developers.openai.com/codex/mcp)
- [Codex project configuration](https://developers.openai.com/codex/config-basic)
- [Claude Code project MCP](https://code.claude.com/docs/en/mcp)
- [Context7](https://github.com/upstash/context7)

## SIGNAL session defaults and focused skills

The owner approved project-local optimization on 2026-10-07:

- `.codex/config.toml`: `gpt-6.1-sol`, medium reasoning, Standard (`default`) speed.
- `.claude/settings.json`: `sonnet`, medium effort. Explicit client/environment or
  managed overrides can still take precedence; confirm the actual model/effort.
- Context7 is the only enabled project-configured MCP baseline. Other inherited
  servers remain off unless an individual task needs them. Connected app/plugin
  catalogs are separate from these server entries.
- `.agents/skills/signal-{task,validate,handoff}/SKILL.md` provides compact task
  preparation, acceptance selection and evidence/usage handoff. Claude loads the
  same folders through `.claude/skills/` symlinks. Automatic skill selection is
  enabled; Codex also supports `$signal-task`, `$signal-validate`, `$signal-handoff`.

Start a new session from the repository root. Existing sessions keep their
selected model/effort and may keep an older MCP catalog. The installed Codex
0.160.1 uses external named profile files; use the explicit per-run flags in
[11](11-model-work-plan.md) rather than old embedded `[profiles]` examples.

```bash
# Normal Codex task: project defaults, Context7 baseline
scripts/ai/codex

# A focused Rust rule/security investigation; opt-in lasts only this invocation
scripts/ai/codex --with semgrep

# Upstream issues/source/PR status; read-only GitHub tools
scripts/ai/codex --with github

# Claude: only the project's .mcp.json servers, with project model/effort defaults
scripts/ai/claude
```

The launchers change to this repository before starting the client, preserve
arguments and inherited authentication/permission settings, and do not submit
prompts or start paid comparisons themselves. Plain `claude` still inherits user
MCPs; use `scripts/ai/claude` for strict project MCP isolation.

### Reuse from Shop/CMS and global tooling

Inspecting the current Shop/CMS maps found generic integrations mixed with
project-specific database, payment, astrology and design services. Reuse the
capability selectively, with a SIGNAL root and the smallest relevant tool set:

| Integration | SIGNAL use | Configuration |
| --- | --- | --- |
| Context7 | Current Rust/library and tooling contracts | Enabled, pinned project server; both clients share it |
| Semgrep | Targeted Rust AST/custom-rule inspection | Optional installed local CLI; only language/schema/AST/custom-rule tools exposed |
| GitHub | Read upstream issues/source and PR status | Optional installed server; read-only allowlist, launching-shell credentials |
| tmux | A task that specifically needs persistent interactive execution | Optional installed server; operate only task-owned sessions |
| Serena | Trial Rust symbol/reference navigation when repeated code discovery is a measured bottleneck | Candidate only; uses rust-analyzer and needs a SIGNAL project/index |
| CodeGraph | Candidate for dependency/call graph discovery if Rust support and indexing benefit are established | Not added; existing Astro launchers bind their own repository graph |
| Browser tools | Future web-interface testing | Not enabled for the current HTTP/CLI slice |

The optional Semgrep/GitHub/tmux entries use the installed generic executables
rather than Astro launchers, which load another checkout's environment and can
bind Git/index paths to that checkout. No Astro credentials, graph or fixtures
are copied. GitHub access and optional server connectivity are not established
by configuration parsing. Semgrep complements the existing RustSec/Trivy gates;
it does not replace them or establish a new release acceptance gate.

To enable an optional server for one Codex invocation, use the launcher above
or `codex -c 'mcp_servers.<name>.enabled=true'`. For additional Claude tools, launch the client with
`claude --strict-mcp-config --mcp-config .mcp.json <task-config.json>`; keep the
explicit config list at the end of the command so it cannot consume a prompt. No global setting
needs to change. Serena's documented Rust backend is
[rust-analyzer](https://github.com/oraios/serena/blob/main/docs/02-usage/050_configuration.md);
Semgrep supports [local rules](https://semgrep.dev/docs/running-rules).

### Per-task usage measurement

The read-only helper reads the local Codex thread registry and rollout counters,
without credentials, prompt content, external calls or price assumptions:

```bash
python3 scripts/ai/usage.py --output target/ai-usage/task-before.json
# Complete the task and its applicable acceptance checks.
python3 scripts/ai/usage.py --output target/ai-usage/task-after.json \
  --baseline target/ai-usage/task-before.json
```

Output files are created exclusively, so pick a new name for each snapshot.
Use the same `--thread-id <id>` on both calls to isolate a project thread.
Project-wide deltas include concurrent tasks, delegated work and approval reviews;
single-thread deltas exclude children. Model/effort labels describe the current
registry snapshot, not historical per-model attribution. The helper refuses
comparisons when counters decrease, threads disappear, scope differs or known
usage records are unavailable. Elapsed snapshot time is wall time, not model API
time. Cached input and reasoning output are subsets, not extra totals.

For each accepted task, retain actual model/effort, token delta, elapsed time,
correction/escalation cycles and acceptance result in its handoff. Compare five
similar tasks before forecasting savings. Use Codex `/status` and Claude `/usage`
for current allowance; these JSON snapshots are neither bills nor plan limits.

## Shared platform launcher entry points

SIGNAL, IPAM and the private SIGNAL overlay now provide `scripts/ai/codex` and
`scripts/ai/claude`. Each selects its own root and preserves caller arguments;
Claude launchers use their explicit project MCP map. IPAM keeps its existing
native Codex diagnostics and allocation-specific settings. The private overlay
inherits model/permission defaults and passes only its declared MCP map as a
per-invocation override, so it works before native workspace trust is set.
No global trust entry or client configuration is rewritten. Its Context7
transport reuses this repository's pinned mechanism, matching the existing
sibling dependency direction. Private policy and fixtures remain external.

Configuration and launcher checks passed for this setup. IPAM's existing helper
suite passed 22 of 23 tests; the remaining legacy-Terraform status test expects
BLOCKED but receives NOT_CHECKED from the previously modified checks.py. That file
and IPAM's Codex/model/MCP settings were preserved. This tooling validation does
not add product/runtime/release evidence. The setup report is retained locally
under `target/ai-workflow-setup-20261007/`.

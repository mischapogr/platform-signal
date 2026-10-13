# Onboarding readiness

SDK slice locally accepted on 2026-10-14. The full ONBOARDING ledger item is
in progress; authenticated server integration, console presentation and actual
rule activation gating are still open.

`signal_collector_sdk::coverage::onboarding::assess_onboarding` returns a
serialized v1 snapshot with disconnected, connected, coverage_verified or
detections_active stage and explicit per-detection blockers. Detections_active
means at least one listed rule is eligible and loaded; inspect each rule's
active flag and blockers. An empty inventory cannot establish active detections.

The host supplies live connection evidence, configured prerequisites and actual
loaded-rule state for the exact source scope. These inputs have no deserialization
contract and must never come from collector claims, token entry, event receipt
or caller-selected HTTP parameters. Actual enabled rules, permissions, categories,
state requirements and policy stay in the private application/configuration.
An empty prerequisite list means the trusted inventory requires none in that
category; an unavailable prerequisite is Unknown and blocks readiness.

The SDK reuses SourceCoverage assessment and requires current mode, matching
profile/scope/observer, healthy observer and fresh coverage. Historical verified
coverage cannot advance onboarding beyond connected. Invalid, missing-profile,
expired or mismatched coverage cannot activate any detection. Every missing or
unknown permission, category or state prerequisite blocks its rule. Unsupported
or unloaded rules also remain blocked, independently of other eligible rules.

This is a read-only snapshot with no I/O, queues, retained state, source
authentication or rule mutation. Recompute with fresh trusted context at use time.
Serialized reports grant no activation authority and cannot establish that a
running engine actually suppresses unsupported rules.

Input limits are 64 detections, 32 prerequisites per category per detection,
and 128-byte nonempty ASCII identifiers using letters, digits, dot, underscore,
colon or hyphen. Duplicate detection IDs and duplicate prerequisites within a
category fail; bounds are checked before report construction. Errors contain
static codes without credential/source values. Existing coverage byte budgets
continue to apply.

Eight focused regressions cover progression, empty inventories, disconnected,
historical/stale/unhealthy/mismatched coverage, malformed/unprofiled records,
missing/unknown/met prerequisites, unsupported/unloaded rules and input bounds.
The frozen local campaign passes formatting, both strict Clippy modes, default
and all-feature workspace tests and the workspace boundary guard. Evidence:
`target/onboarding-sdk-20261014/ACCEPTANCE.json` and its source-bound campaign.

Next: supply fresh authorized scoped host evidence, bind loaded/eligible rules
to actual engine execution, expose the read-only assessment under existing
coverage access control, and present all states/blockers in the console. Qualify
scope isolation, expiry/revocation, rule suppression and actual browser behavior
before accepting ONBOARDING. OAuth/AssumeRole success alone is insufficient.

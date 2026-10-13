# Onboarding rule execution gate

Generic execution gate locally accepted on 2026-10-14. Full ONBOARDING remains
in progress; neither Main pipeline uses this gate yet. Current-health reads,
authenticated host integration and console presentation remain open.

`RuleSet::rule_ids()` exposes the exact immutable loaded inventory.
`RuleSet::evaluate_ready_with_context(event, context, readiness)` requires one
explicit trusted-host decision for every loaded rule. Input order is irrelevant.
Missing, duplicate, foreign, empty or oversized IDs refuse before predicate
evaluation. Inventory size must equal the validated loaded-rule count (at most
256); IDs are bounded at 256 bytes before allocation into a borrowed-key map.

Blocked rules are skipped even when their predicates match. Enabled rules use
the existing predicate implementation and preserve finding IDs and replay
behavior. The gate retains no decisions across calls. Cancellation/deadlines
apply before inventory validation, during decisions and during evaluation;
events are validated even with zero enabled rules or zero loaded rules.

The caller must freshly assess trusted connection, current coverage, scope and
prerequisites before passing decisions. Rules without configured onboarding
proof need explicit blocked decisions. Producer event fields, HTTP selectors
and serialized prior reports cannot supply authority. The gate does not itself
authenticate a decision, determine its age or bind an event to a private scope.
Those checks belong to the host. Existing unconditional evaluation remains
available for deployments until they explicitly adopt the onboarding path.

Four new regressions cover actual suppression/unchanged enabled findings,
incomplete/duplicate/foreign/oversized inventories, cancellation/deadline and
empty inventory with invalid-event refusal. Six frozen gates pass: formatting,
both strict Clippy modes, default/all-feature workspace tests and workspace
boundaries. Exact evidence: `target/onboarding-rules-20261014/ACCEPTANCE.json`.

Next coherent change: implement fresh scoped host evidence, wire both Small and
Standard Main evaluation paths, expose the same authorized assessment and show
per-rule blockers in the console. The coverage history endpoint currently
reports current_health=unknown; retained history is not an independent live
connection/observer-health check. Bind policy using trusted host/partition
scope, never producer-controlled source fields. Qualify scope isolation,
expiry/revocation, no unconditional fallback and actual console behavior before
accepting the full ONBOARDING item.

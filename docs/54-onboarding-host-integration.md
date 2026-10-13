# Scoped onboarding host integration

Local host/Small Main/browser slice accepted on 2026-10-14. ONBOARDING remains
in progress. This continues the SDK snapshot at eacbd7f ([52](52-onboarding-readiness.md))
and library gate at 3ad87b2 ([53](53-onboarding-rule-gate.md)); their integration
status describes those earlier revisions. Both Main paths now call the gate when
configured. Standard with onboarding enabled still needs native qualification.

## Trust and configuration

Opt in with `SIGNAL_ONBOARDING_CONFIG`, pointing to a deployment-owned JSON
document. Its v1 fields are `schema_version`, `scope_id`, `public_key_base64`,
absolute `report_path`, `coverage_profile_json`, `coverage_context_json`,
`event_scope` and `detections`. No signing secret belongs in this document.
Native identity and an existing configured coverage scope are required.
The exact full coverage binding, observer and profile definition must match
that scope before admission/readiness. A historical context is refused.

`event_scope` declares exact canonical `source`, `account`, `resource` membership.
This fixed private policy is not selected by producer attributes or HTTP input.
Evaluation requires matching canonical facts and host-proven newly authenticated
admission; retained/unverified WAL cannot acquire readiness from a new report.

Each configured detection declares `id`, `supported`, and explicit `permissions`,
`categories`, `state` prerequisite ID lists. The list must exactly cover the
actual immutable loaded inventory. The SDK enforces 64 detections, 32 checks per
category and 128-byte identifiers. Startup bounds the all-unknown serialized
report below 500,000 bytes so all blockers fit the scoped HTTP response budget.
Actual source names, requirements, enabled rules and signing authority are private.

## Fresh evidence

A private trusted observer writes an envelope with v1 `schema_version`,
`payload_base64`, `signature_base64`. Ed25519 signs the exact decoded payload
bytes prefixed with `PLATFORM::SIGNAL/onboarding/v1` and a zero byte. The pinned
32-byte public key verifies the 64-byte signature before payload interpretation.
No collector, API caller or successful login can supply this authority.

The payload contains v1 `schema_version`, exact `scope_id`, `observed_at`,
`expires_at`, `connected`, `observer_status`, original `coverage_record`,
`interval`, and `permissions`, `categories`, `state` maps of prerequisite IDs to
`met`, `missing` or `unknown`. Observer status is healthy/unhealthy/unknown.
The trusted private observer must perform actual source checks; the signature
authenticates its attestation, not vendor APIs or completeness by itself.

The receiver rejects future observation, expired or nonpositive validity, wrong
scope/signer and validity longer than 30 seconds. Missing checks become Unknown.
SDK assessment uses receiver time/current mode and the pinned profile/binding.
Connection alone cannot activate rules. A valid signature cannot override bad
coverage, unhealthy observers, unsupported rules or missing prerequisite checks.

Every event evaluation reads evidence afresh through the existing physical
bounded configuration worker. No retained activation, extra worker queue or
renewed caller deadline is introduced. The effective deadline is capped by the
attestation, coverage valid_until and profile verification-age limit. Cancellation
or expiry during evaluation refuses findings. Missing/invalid/malformed evidence
produces an explicit unverified snapshot and blocked decisions, without an
unconditional fallback. Configuration remains immutable until validated restart.
The runtime resource audit revision includes the enabled onboarding mode bit;
it continues to exclude actual private policy contents and credentials.

## API and console

`GET /v1/coverage/onboarding` uses current ReadCoverage authorization, exact
configured scope selection, audit completion, finite request leases and no-store
responses. Select with the existing `x-signal-coverage-scope` header; selection
is not a grant. The response adds `assessed_at` and nullable `valid_until` to the
SDK v1 snapshot. Other scopes and write-only identities cannot read it.
Existing coverage history still reports current_health=unknown.

The read-only console's Source readiness view displays connected/verified/active
states and each rule's blockers. Token entry leaves readiness unassessed. Expired
assessments clear the display; denied/cancelled/stale-session responses cannot
preserve active rows. Rendering uses text nodes, requests remain bounded to two,
and tokens remain page-local.

## Evidence and remaining work

Thirteen frozen gates pass: 952 default/1,013 all-feature tests, both strict
Clippy modes, formatting/workspace, five host regressions, seven actual Small
native identity/WAL/finding checks, five onboarding Chromium checks, 26 existing
console checks and ownership regressions. The corrected restored Standard
baseline passes in 81.17 seconds with the exact newly built fixture and cleanup.
Evidence: `target/onboarding-host-20261014/ACCEPTANCE.json`. The earlier fixture
argument/campaign and failed preliminary fixtures are retained.

Still qualify onboarding enabled in actual Standard Main and the composed
browser/native endpoint, plus expiry/cancellation/scope and source prerequisites
in that deployment. Vendor health checks here are signed synthetic assertions;
actual AWS/vendor environments and private observer implementation are separate
evidence. Full ONBOARDING and the release goal are not accepted by this slice.

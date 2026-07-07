# Disposition and outcome backend contract

Status: implemented and accepted locally under finite DISPOSITIONS, 2026-10-08. No additional
product scope, service split or writable UI is selected here. Advanced SOC UX
remains post-MVP. OUTBOX is accepted synthetically; real environments remain open.

The public findings crate supplies versioned generic outcome/reference types.
Private control state consumes them through the existing bounded SQLite owner.
Policy, actor mapping, incident identifiers and analyst notes remain private.
No outcome changes the original finding, evidence, detection identity or delivery.

An update has a stable operation UUID, stream/finding reference, expected revision,
true-positive/benign-positive/false-positive/incident outcome, optional bounded
note and incident reference. Incident requires a nonnil incident UUID; other
outcomes do not accept one. The request does not supply actor identity or time.
A separate trusted application authority supplies authenticated actor and the
exact permitted stream/finding scope. Mismatches are denied before persistence.
This is an authorization seam; current construction is not proof of OIDC/RBAC.

The backend verifies that the referenced finding exists in its consumed immutable
history. It assigns receipt time once and atomically appends an immutable audit
record and advances the finding's revision from the exact expected value. Every
correction is another record. Exact operation replay returns the original record
and receipt time; differing actor/content under that operation conflicts. Stale
revisions and unknown finding references cannot advance or replace audit history.

Notes, scopes, operation IDs, record bytes, audit count, database pages, query
count/bytes, command capacity, VM work and I/O lifetime remain bounded. Cancellation
before mutation performs no update; uncertain started mutations close the owner
and recover the same atomic state. No implicit pruning, audit overwrite or
unbounded history read is allowed. A full audit backlog stops updates visibly.

The initial implementation uses the private local control backend. Shared control
and fencing remain SHARED-CONTRACT/SHARED-RUNTIME; authenticated user mapping and
roles remain SECURITY-ACCESS; restricted independently owned security audit
remains SECURITY-AUDIT. Immutable local disposition records are not an independent
tamper-proof audit archive. Explicit schema migration belongs to UPGRADE and normal
open must not silently reset or migrate an older development store.

Acceptance covers outcome/incident/reference validation, forbidden scope, unknown
finding, stale revision, exact replay/conflicting operation, corrections retaining
history, finite quotas, restart/crash recovery and the relevant strict local gates.
Evidence destination: `target/goal-execution-20261007/DISPOSITIONS/`.

Two public and nine private regression tests pass. Public default559/all-feature582
and private37 full tests, strict checks, boundary guard and existing overlay
process recovery pass. Three bounded private subprocess helpers are invoked by
their parent tests. Source review has no unresolved blocker/high. Complete page
byte counting and latest retained head checks have exact boundary regressions.
Evidence: `target/goal-execution-20261007/DISPOSITIONS/`. This acceptance does not
close any real-environment, release, identity-provider or advanced SOC UI gate.

# MVP SecOps UI contract

Status: owner-selected MVP requirement, 2026-10-07. UI-01 and UI-02 are bounded
implementation/qualification items with local AMD64 acceptance. Evidence and
remaining external release gates are recorded in
[progress](07-progress.md) and [release readiness](21-release-readiness.md).

## Product boundary

A minimal SecOps interface belongs in MVP. A small shared DevOps/SecOps team must
be able to inspect persisted findings and search their available event evidence
without maintaining another application. It remains a read-only surface over the
existing APIs and the modular Rust monolith described in
[product architecture](27-product-architecture.md).

Advanced SOC UX is post-MVP: cases/incidents with persisted workflow state,
assignment, analyst dispositions, suppression/tuning workflows, correlation
workbenches, automation/playbooks, escalation and multi-analyst collaboration.
No client-only status or button may imply those mechanisms exist. OIDC/RBAC,
source-coverage observers, protected source originals and complete source adapters
remain separate follow-on capabilities with their own acceptance.

## UI-01 — bounded embedded findings and event search

Serve an embedded shell at `/ui` with fixed same-origin assets from
`signal-server`. The HTML/CSS/JavaScript are compiled into the binary: no separate
frontend service, build toolchain, runtime package installation, CDN, analytics
or new production dependency is required. Shell availability is independent of
query authorization; existing API authentication is enforced on each request.

| View | Required behavior |
| --- | --- |
| Findings | Manual `GET /v1/findings` with creation-time `from`/`to`, detection `severity`, exact `rule_id` and `limit`; show finding ID, title, severity, rule and creation time |
| Finding detail | Inspect the complete returned finding and its source `event_ids`; preserve identifiers for investigation without claiming a case, disposition or delivery status |
| Event search | Manual `GET /v1/events` with event-time `from`/`to`, log `severity`, exact `source_type`, `account`, `resource_id`, message `contains`, `limit`, and `order=desc` |
| Event detail | Show the complete serialized canonical event row returned by the API, including nested attributes and source/resource identity |
| Request state | Clearly distinguish loading, success with results, valid empty results, cancellation and error; manual retry; retain keyboard access and readable status announcements |

Both limits default to 100 and accept only integer values from 1 through 100;
a lower configured server maximum remains authoritative. These are bounded
samples, not complete result sets, pagination or a live feed. Findings retain API
ascending `(created_at,id)` ordering; event search requests descending timestamp,
ID and WAL-sequence ordering. The findings API cannot yet request newest-first.
Do not silently re-sort a limited old-first sample as though it were the latest
findings. UTC RFC3339 inputs retain the API's half-open `[from,to)` semantics;
findings filter creation time, events filter event time. Blank optional filters
are omitted and submitted values are encoded as URL query parameters.

Finding severity is `low`, `medium`, `high`, `critical`; event log severity is
`trace`, `debug`, `info`, `warn`, `error`, `critical`. Labels and controls must keep
these contracts distinct. Event detail means the exact complete API-returned row
serialized for display; it is not proof of original vendor wire bytes, source
completeness, archive immutability or source validation. If an event carries a
vendor payload in attributes it is visible as stored, without an authenticity
claim. Rendering must preserve large JSON numbers rather than silently round
stored evidence through ordinary JavaScript number conversion.

### Authentication and browser safety

The optional API Bearer token is entered in a password field and retained only
in current page memory. Never persist it in cookies, local/session storage,
IndexedDB, URL parameters, fragments, markup, logs or cached requests. Clearing
the token clears application-held credentials and cancels outstanding requests;
reload requires re-entry. Browser password-manager behavior is outside SIGNAL's
memory guarantee. Development without a configured token follows current API
behavior; production deployment still requires trusted TLS and the scoped
security controls of the product architecture. The UI does not add user identity,
RBAC or tenant/account authorization to a shared token.

Use fixed relative API paths and same-origin requests. Disable credential-bearing
redirects and request caching. No background polling, external requests,
downloaded scripts or telemetry. Render all event/finding/error-derived content
as text; no dynamic HTML insertion or script evaluation. Apply a restrictive CSP
allowing only embedded same-origin assets and requests, denying framing, object
content and alternate base URLs. Set content types and anti-sniffing policy for
fixed assets. Error messages must not echo token or untrusted response bodies.

At most one request is active per findings/event pane, two in total. Cancel a
pane's prior request on replacement or explicit Cancel, and cancel both on token
clear or page teardown; bound each complete fetch/body operation to 30 seconds.
Reject decoded responses beyond 8 MiB using a streaming byte bound, including error
responses; do not trust Content-Length alone. Cancel body consumption at the
limit. Only schema-version 1 responses with the expected array and at most 100
rows can be rendered. Failed/cancelled/oversized responses must not leave stale
results presented as fresh. Server query bounds, deadlines and authentication
continue to apply independently.

### Accessibility and layout

Use semantic forms, headings, lists/tables and native buttons with visible labels,
focus indication and programmatic error/status announcements. All filters,
request controls and row-detail actions must work by keyboard. Details must remain
readable at narrow widths; tables and long raw rows may scroll inside bounded
containers without making primary controls inaccessible. Status must use text,
not severity color alone. Manual requests keep focus predictable.

### UI-01 acceptance — local Linux AMD64

The embedded shell is implemented. Acceptance records 301 workspace Rust tests,
21 real-Chromium checks over fixture APIs, four actual-server/browser/restart
checks and 24 source-candidate helper regressions under
`target/secops-ui-20261007/`. Actual-server asset responses match the source bytes;
detail preserves large integers and hostile content remains text. Focused review
corrected a cancelled/superseded 401 race and source-export asset omissions.
Browser testing corrected mobile grid overflow. At UI-01 acceptance, UI-02 exact
evidence navigation and fresh container/architecture qualification remained open.

- Embedded routes return fixed typed assets with the intended security headers;
  malformed/unrecognized asset paths do not become arbitrary filesystem reads.
- Existing API authorization remains effective: shell load does not bypass a
  401; token never appears in URLs, persisted client state or diagnostics.
- Query controls encode supported filters, limits and order; finding and event
  severity remain distinct; invalid time/limit inputs fail clearly.
- Findings and complete canonical rows are inspectable; arbitrary hostile text
  and large-number attributes retain safe, faithful representations.
- Deadline, cancellation, request replacement, oversized body and error-response
  paths stop work and present clear state; no stale-response race.
- Focused HTTP/static/client checks and the required Rust workspace gates pass.
  Static/source checks alone do not establish browser interaction or deployment
  proof; those gates were assigned to UI-02.

## UI-02 — evidence navigation and qualification

The finding detail supplies keyboard-accessible buttons for its first100 valid
`event_ids`; further IDs remain visible in the complete detail for manual search.
Each button switches to events, sets exact `event_id`, clears unrelated filters
and both event-time bounds, and searches up to100 retained matches. A finding's
creation time must not become an assumed source event time: delayed events can
be much older. Manual event-ID search can optionally narrow either time bound;
ordinary event search still requires both bounds.

`GET /v1/events?event_id=<uuid>` accepts a canonical lowercase, hyphenated,
non-nil UUID through the versioned optional `EventQuery.event_id` field. Absent
fields remain compatible with the previous serialized contract. Identity is
conjoined with other selected filters. Storage retains separate admissions with
the same ID, so lookup can return multiple records in the existing timestamp/ID/
WAL-sequence order. UUIDs occurring only in message text do not match.

A blank result states absence within retained/search scope, not proof an event
never existed. Authorization denial, unavailable evidence and scan/file/time/
memory limits remain errors, rather than successful empty results. Clearing time
bounds does not bypass these server budgets; narrow the interval when a broad
retained-history query exceeds them. Exact row details preserve large numbers
and hostile content as safe text.

Qualify the complete workflow with an actual browser: configured-token success
and denial, findings filters/detail, exact evidence navigation, event filters,
empty/error/cancel/oversize states, hostile content, faithful large numbers,
keyboard focus/status announcements and responsive layouts. Include browser
regressions and the embedded assets in container/packaging checks tied to the
reviewed source/binary/image. Browser tools or test dependencies may be selected
for verification; they do not become production dependencies. Native ARM64,
authorized EKS, remote CI, released overlay dependencies and publication gates
remain governed by the existing release contract, even if locally unavailable.

UI-02 is part of MVP acceptance. Advanced SOC UX starts only after MVP's locally
runnable work is accepted; missing external evidence remains explicitly open.
Coverage-history payload pruning, identity pruning and scans stay post-MVP PS-01,
not prerequisites for these read-only UI slices.

### UI-02 acceptance — local Linux AMD64

Exact identity navigation and optional UUID query filtering are implemented.
Acceptance records 307 workspace Rust tests (six new protocol/Parquet regressions),
26 Chromium fixture checks, four real-server/browser/restart checks, 24 candidate
helper regressions and 14 browser checks over the real immutable AMD64 container
(seven before and seven after SIGTERM). The existing native container gate also
passes nonroot/read-only/auth and SIGTERM/SIGKILL persistence checks. Current
source export includes all embedded assets and the exact browser helpers;
strict Helm lint passes. Evidence is retained under
`target/secops-ui-evidence-20261007/` and reviewed independently.

The container image is
`sha256:14c56dcf65bcbb41d95a7ee1a8ced9464732ec71db80c014b3fab734b21cbf55`.
Its asset bytes match the reviewed source. Delayed 10-day evidence returns both
same-ID admissions, excludes a different-ID message containing the UUID,
preserves large numbers, rejects wrong credentials, and survives restart.
Native ARM64, current host-blocked kind, actual EKS, remote CI, released external
dependencies and publication remain open. No advanced SOC workflow is implied.

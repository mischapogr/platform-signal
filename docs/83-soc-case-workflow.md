# Bounded SOC case workflow

SOC-UX implementation contract. The Small backend prerequisite passes bounded
local acceptance on2026-10-27; `target/soc-ux-20261026/backend/ACCEPTANCE.json`
records exact source/evidence/limits. The whole ledger item remains unfinished and requires
persisted cases, assignments, existing analyst dispositions, authorized evidence
views and actual browser/restart qualification. This first backend packet enables
explicit create/assign/unassign only. No automatic case creation, remediation,
suppression, notifications or new SOAR platform is implied.

## Identity and immutable history

A version1 case has a namespace UUID and case UUID, title, immutable nonempty
finding references (stream UUID + finding UUID), current optional assignee and
revision. Creation is revision1; later assign/unassign changes use exact expected
revision CAS. References are sorted and distinct, never inferred from a first
finding or producer attributes. Each operation has a namespace-wide UUID.
The journal atomically retains request, original actor/time, revision and resulting
head. Exact retry returns the original record; changed request OR actor under an
old operation UUID conflicts. Retry remains subject to fresh authorization of the
original complete contributor inventory; it never renews an old permission.
A case's finding references cannot be changed by this first version.

The host authenticates actors, verifies referenced findings and their complete
source/policy contributor scopes, and authorizes the target assignee independently.
CaseAuthority is nonserialized, request-bound host testimony with its own deadline
and cancellation token. Its constructor validates shape, not authentication/RBAC.
Read and write permissions are distinct; exact complete reference inventory must
match the immutable stored case on every mutation, replay and read. Missing,
unknown, stale or denied evidence refuses; serialized case/audit bytes never grant
permission. No HTTP request may construct authority from actor/scope attributes.
The next packet must implement this boundary through actual server identity and
finding/evidence checks, not claim the constructor authenticates callers.

## Durable Small backend and bounds

The host supplies an existing protected parent directory. New root creation is
followed by parent directory sync before startup succeeds.
One private local root/namespace and exclusive file lock; one serial journal
mutation at a time. This is a local Small mechanism, not PostgreSQL shared control
or distributed fencing. The host protects its parent directory against concurrent
untrusted replacement. Refuse symlinks, nonregular/hardlinked journal/control
files, unexpected entries, unsafe permissions and namespace mismatch. Initial
header installation is fsynced temporary + rename + directory sync. Frames bind
length/header and payload CRC. An independent atomically replaced, fsynced commit
witness pins namespace, record count, end and full prefix SHA256 before receipt.
Recovery refuses any missing/shortened/changed committed prefix, including whole
final-frame deletion. Only an uncommitted suffix beyond the final witness may be
truncated and synced; a temporary witness cannot promote it. Whole-root/witness
rollback needs external protected custody and is not detected locally.
Committed checksum/schema/revision/identity corruption refuses without
repair or history deletion. Worker I/O or lifetime failure after mutation begins closes the live store;
reopen and exact operation replay reconcile physical uncertainty before ACK/retry.
If physical commit and in-memory application completed but result delivery then
expires/is cancelled, the known original remains available for fresh exact live
replay. Result delivery still rechecks caller and authority; no old permit renews.

Finite configured bounds cover cases, total operations/history records, journal
bytes, per-record bytes, index/retained state charge, page records/bytes and active
operations. Queue admission never creates unbounded blocking work. Capacity
refuses atomically and preserves prior heads, audit records and operation IDs;
no automatic eviction or pruning. Expose depth/capacity and refusals. Original
records remain immutable when assignments change. Notes are opaque bounded text,
not logs or executable content. Errors never echo them or actor credentials.

Every operation preserves caller AND authority deadlines/cancellation through
queueing, mutex wait, all disk work and result delivery. A finite physical permit
remains held until blocking work retires, including after a caller stops waiting;
a completed unpolled response retains capacity. Shutdown stops admission, waits
with a bound and never releases a live file lock while physical work still owns it.

## Acceptance sequence

1. Backend: actual create/assign/unassign/reopen; exact lost-response retry and
   conflicting actor/payload; concurrent revision race; complete multi-reference
   authority and assignee denial; every count/byte/page boundary; cancellation,
   authority expiry and physical capacity; actual owned process kill before/after
   durable mutation, incomplete-tail recovery and committed corruption refusal.
2. Scoped API: explicit case/disposition operations, authenticated actor mapping,
   all-contributor permissions on writes/reads and audited decision/completion.
   Shared bootstrap credentials do not imply analyst mutation rights. Preserve
   current identity expiry/revocation and per-operation cancellation semantics.
3. Console: persisted case/list/detail/assignment, existing disposition history,
   explicit correlation/evidence navigation and conflict/exact retry handling.
   Preserve in-memory credentials, same-origin bounded requests, safe text and
   large-number rendering, keyboard/status/focus and responsive layout.
4. Whole SOC-UX: actual browser/native backend/restart/lost-response/conflict and
   denied multi-scope tests, independent source review and frozen applicable
   workspace/helper/process/browser/package gates. Backend-only proof is not
   whole SOC-UX acceptance. Current ARM64/CI/images/AWS/release remain separate.

## Bounded host discovery and exact references — accepted local prerequisite

This prerequisite passes bounded local acceptance on2026-10-27; source/evidence
and limits are in `target/soc-ux-20261026/references/ACCEPTANCE.json`.
Resolve (finding stream,finding UUID) through the existing physical ID/cursor
index, never a truncated query sample. Verify original frame and prefix before
returning immutable finding bytes' SHA256 and stored provenance. Enforce the
selected store read budget with conservative decoded/original/provenance charge
before reading a known row. A known physical
canonical scope boundary may describe historical single-scope facts; older,
forged or missing provenance stays Unknown. This result is host data, not a grant,
current source/custody verification or complete multi-stream episode inventory.
Wrong stream,corruption and unavailable storage are errors; absent UUID alone
is an exact None within the enrolled store. Keep existing feed/query bytes and
permission behavior unchanged.

Case discovery is internal metadata only: namespace,case UUID,immutable complete
finding references and head revision. No notes,title or actors. Require a separate
nonserialized host inventory testimony with caller AND authority lifetimes;
constructors validate shape only. Reuse existing heads/worker/physical permits and
page/count/byte limits. UUID traversal is deterministic. Continuations bind the
exact committed prefix and refuse any changed snapshot. Internal cursors and
metadata have no client authorization role and must never be serialized directly
to HTTP. A subsequent authenticated adapter must resolve and authorize ALL original
contributors before exposing any case/list row or constructing CaseAuthority.

An episode provider needs separate explicit enrollment and protected originals
and complete canonical/native indexes. It must retain policy-only contributors
and original scopes through pruning/carry; unknown or partial provider custody
refuses. Canonical finding provenance cannot stand in for this provider or activate
Main correlation. API/assignee/audit/disposition/console/browser work remains open.

## API foundation checkpoint — 2026-10-27

The case backend and exact reference/inventory prerequisite are committed in
`4ee43f6`. The subsequent API foundations are work in progress: explicit scoped
case/disposition operations, closed resource/intent audit targets, paired durable
audit sessions, and absolute UTC windows through physical case commit. They do
not expose HTTP routes or establish identity/provider/assignee authorization.

Checkpoint validation: protocol/findings tests passed 123 tests (2 ignored),
and the server workflow-audit regression passed 1 test. Formatting, workspace
boundaries and AI workflow checks passed. Strict targeted Clippy failed because
`Control::begin_workflow` is unused in the production server until route wiring.
The checkpoint is preserved on a separate WIP branch; it is not API acceptance.
Logs remain in `target/soc-ux-20261026/api/checkpoint-{tests,clippy}.log`.

Next: wire the actual opt-in authenticated API with enrolled original-contributor
providers, independent assignee eligibility, minimal write acknowledgements and
mandatory resource-bound auditing. Complete focused independent review and
source-bound full acceptance before integrating this checkpoint into develop.
Durable dispositions and console/browser/restart evidence remain open. The
whole SOC-UX item remains in progress; no AWS or release qualification is added.

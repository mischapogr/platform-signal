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

## Canonical Small HTTP implementation in progress — 2026-10-27

Opt-in `cases.config` / `SIGNAL_CASE_CONFIG` now installs bounded create,
assignment, detail, history, full bounded list and selected-finding evidence
routes. Startup requires native identity and selected case/evidence audits;
Standard composition refuses. The original request lease caps physical case
commit and result delivery. Fresh introspection, exact-original resolution and
recipient verification run after decision auditing and around completion
confirmation. A later refusal withholds the response without claiming rollback;
reconcile writes with their original operation UUID.

Write responses contain only schema_version, case_id, operation_id,
result_revision and replayed. History/detail require ReadCases plus ReadFindings
for every immutable reference; selected evidence additionally requires its own
ReadEvidence grant. Lists examine at most100 cases and refuse a larger inventory
rather than returning false-empty or exposing an internal cursor/denied count.
Request and physical depth/capacity/refusals are operational metrics; closed case
storage participates in readiness and admission shutdown.

Canonical enrollment means actual physical provenance from authenticated
`from_event` or complete same-scope `from_events`, including retained canonical
windows. It does not assert every row in the stream is known. Unknown legacy
provenance refuses individually; reserved attributes cannot promote it. This is
not a D11/D14 episode-provider enrollment or a substitute for policy-only scopes.

Assignment targets use an independently pinned Ed25519 directory observer and
fixed alias-to-issuer/subject mappings. A freshly read signed report binds the
namespace, audience, observer, key/policy/directory revisions, target active status,
capabilities and scopes. Each recipient needs ReadCases and ReadFindings across
the full original inventory. No target AuthenticatedIdentity/RequestGrant is
fabricated. Reports have an absolute configured freshness bound of at most30s;
new inactive reports refuse fresh assignments/retries, while a retained report
can only speak for its original bounded observation window. This is not an
instantaneous live IdP revocation guarantee. Local signed observers qualify
adapter mechanics only.

The HTTP router tests use actual TLS introspection and real finding/case stores,
including close/reopen and controlled decision/completion audit barriers. They
are not a monolith subprocess restart, complete episode custody, durable public
disposition, browser, Standard, current ARM64/CI/image or release campaign.
The full scoped API task and whole SOC-UX acceptance remain open; continue those
requirements rather than declaring the canonical path a replacement for them.

## Protected episode provider implementation in progress — 2026-10-27

Explicit `episode_providers` enroll separate publication stream UUIDs and pinned
observer/config/history generations. They cannot shadow the canonical store or
fall back to its scope metadata. A fresh domain-separated Ed25519 custody report
binds the exact finding publication receipt, original raw finding bytes, validated
original archive/effect, complete contributor commitment and current cumulative
canonical/native index ancestry. Artifact names derive from digests or UUIDs;
no report-supplied path or arbitrary scope map grants authority. The observer is
responsible for current-root/rollback visibility outside the bounded observation
window; local hashes cannot prove a newest external root.

The provider validates actual typed archives and every index witness/key set,
including prior indexes, original effects and recorded ancestry. Historical
summary fields are data: detector partition, journal commitment, original
keys/config/policy binding and prior Anchor. Finding IDs and episode output IDs
are distinct and connected only by the protected publication receipt and original
effect. Pruning/carry cannot replace old contributor scopes with newer policy.

A private rooted artifact reader pins directory/file descriptors, refuses leaf
symlinks, special files, hardlinks and unsafe permissions, and checks replacement
metadata before/after reading. It uses the existing retained physical worker and
original cancellation/deadline. Its separate32MiB artifact cap does not expand
ordinary configuration limits. Shared reader depth/capacity/refusals are exposed
through operational metrics, including cancelled physical work that has not retired.
The configured graph allowance counts raw encoded
artifact bytes and is applied before each decoder; typed state/index/work limits
remain separate. Reference inventories retain per-reference contributor ranges
with a1024-scope ceiling. Actor and recipient checks cover the full original
inventory; evidence permission covers all contributors of the selected reference.
Provider lease minima cap physical case authority and delivery and cannot be
renewed within an old request by a later signed report.

Current tests generate actual D11/D14 journal/export/publication/index files,
prune and reopen stores, carry new keys and policy scopes, and exercise TLS IdP
router access, semantic partial/duplicate/conflicting indexes, publication and
inventory substitution, lease expiry, audit barriers and no fallback. Source,
classification, directory and custody authority remain synthetic. Native monolith
process/mTLS-audit/restart composition, full final acceptance, durable public
dispositions and console/browser evidence are still required for whole SOC-UX.

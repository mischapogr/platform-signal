# Company integration design proposal

**Status:** Integration design with locally accepted public append feed and
private transactional outbox/notification simulations, 2026-10-08. Complete
source-to-notification composition remains the SMALL-PILOT item; acceptance of
these bounded mechanisms does not close real-environment or release gates. Private implementation, schemas, fixtures and deployment remain in the
separate application. AWS collection requires its own task.

One company integration should consume public SIGNAL components through their
existing APIs: establish source identity, prepare an enriched event, obtain
durable admission, evaluate private rules, and deliver a durable finding. The
public feed now supplies bounded consumption of findings in durable append order. Collector and enrichment hooks already exist.

The example is one application event with ownership enrichment, one matching
private rule and one external destination. It specifies behavior without
publishing company identifiers, metadata schemas, detection conditions or
fixtures. [ADR-007](adr/007-oss-boundary.md) governs the ownership boundary.

## Ownership and event flow

```text
PRIVATE APPLICATION                         PUBLIC SIGNAL

authenticated source
    |
bounded durable receipt
    |
metadata snapshot -> enrichment
    |
bounded durable prepared event -----------> HTTP ingest -> synced WAL
    ^                                          |              |
    |----------- admission response -----------+              v
                                                      Parquet -> rules
                                                                  |
private immutable rule bundle ----------------------------->      v
                                                           durable findings
                                                                  |
bounded finding consumption <-------------------------------------+
    |
durable delivery plan -> external destination
```

The public findings feed and private transactional delivery mechanisms are
accepted locally/synthetically under FINDINGS-CURSOR and OUTBOX. Full operational
receipt/enrichment/source-to-notification composition remains SMALL-PILOT.
The existing [SDK](16-collector-sdk.md) invokes cooperative providers; it does
not create a durable integration runner, wire enrichers into the normal server,
or sandbox extensions. The existing [external gate](17-external-overlay.md)
proves local source-path integration, not this operational workflow.

| Public responsibility | Private responsibility |
| --- | --- |
| Canonical event validation, identity and serialization | Source authentication and mapping to company identity |
| Collector/enricher invocation limits and cancellation | Provider wiring, metadata schema and refresh policy |
| HTTP admission, bounded WAL and replay | Durable source receipt, prepared-event persistence and retries |
| Stateless rule evaluation and durable findings | Detection content, rule bundles and activation policy |
| Bounded findings-consumption contract | Routing, destination credentials and durable delivery state |
| Generic packaging and resource-limit mechanisms | Actual topology, access controls, quotas and operator procedures |

The company can run public server artifacts alongside its integration
application. It consumes public dependencies rather than copying engine source.
Local path dependencies support co-development; production qualification must
use the actual selected released dependencies and artifact identities.

## Source identity and durable receipt

The private source adapter or gateway establishes publisher identity independently
of event fields. It maps that identity to allowed sources and company context.
Producer-supplied account or ownership claims cannot select permissions or
impersonate verified metadata. The private schema keeps producer assertions
distinct from verified identity and enrichment, and controls which fields it
replaces. Downstream deployment must prevent publishers from bypassing this
verification path when detections rely on its assertions.

Current server authentication is an optional shared Bearer token. It does not
establish per-publisher account identity, RBAC or tenant isolation. Event metadata
does not provide authorization. See the [threat model](20-threat-model.md).

Assign canonical event identity once and durably persist a bounded receipt before
acknowledging a replayable source. Keep the identity, original event and verified
source context together. Source redelivery must recover this receipt when the
source supplies a stable delivery identifier. Sources without replay or stable
identifiers require an explicit weaker guarantee; the receipt cannot recover
bytes lost before it was persisted.

This receipt stage is private integration work. The existing agent's stdin/file
spool has its own [source and crash limits](15-phase6-agent.md) and is not a
drop-in durable runner for arbitrary enriched events. Receipt capacity is finite:
stop pulling or reject without source acknowledgement when full. Count pressure,
rejections and explicit policy drops.

## Enrichment and preparation

Load a bounded metadata snapshot, validate it completely, and publish it for
lookups only after validation succeeds. Retain the last valid snapshot during
an unsuccessful refresh. A private policy selects maximum age and behavior
when no acceptable snapshot exists. Refresh work needs finite input, memory,
disk and concurrency budgets, plus deadlines and cancellation.

For an ownership lookup, the proposed default is to preserve the event when a
mapping is missing and record that enrichment status. A stale snapshot may be
used only within the selected age limit. Beyond that limit, use the selected
missing-metadata policy; do not silently present stale ownership as current.
Identity-dependent admission can require stricter handling than descriptive
ownership enrichment. Detections must define their behavior on missing metadata.

Invoke `apply_enricher` with an explicit context. The current helper validates
input/output and preserves schema version, event ID, timestamp and observed
timestamp. Failure leaves the caller event unchanged. It does not undo external
side effects or constrain a non-cooperative extension's own allocations.

Durably commit the exact enriched event and snapshot identity as a prepared
record before sending it. Record provenance through the private schema using
existing nested attributes and private receipt metadata; introduce no company
fields into the public event envelope. The transition from receipt to prepared
record must survive crashes without losing the original receipt. Once prepared,
retry the same event bytes. A metadata refresh must not re-enrich a pending
prepared event under the same event ID.

A crash before preparation may repeat enrichment using the then-allowed
snapshot. A crash after preparation must recover the stored result. The private
fixture should exercise both boundaries.

## Admission and detection

Submit prepared events using the existing [HTTP contract](09-phase1-ingest.md).
HTTP 202 establishes synced WAL admission; it does not establish Parquet
publication, completed detection or external delivery. For batches, acknowledge
only the accepted prefix confirmed by a validated response. Retain the rest.

After a timeout or lost response, retain and retry the unchanged prepared event:
admission may already have succeeded. Delivery is at least once. Independent
admissions with identical event IDs can produce duplicate stored events; the
server does not provide global event-ID deduplication. Any source acknowledgement
and local spool reclamation must follow a crash-safe private receipt state.

The existing single consumer persists Parquet, evaluates the loaded rule set,
syncs findings, then advances the WAL checkpoint. Persistence failure leaves
uncheckpointed work for replay and stops admission. Findings use deterministic
rule/event identities; identical content is idempotent, while conflicting
content for the same identity fails closed. These are existing
[Phase 5 semantics](14-phase5-core.md), not proposed alert-delivery semantics.

## Rule versions and upgrades

Keep an immutable rule bundle, its content digest, dependency/artifact versions,
configuration identity and activation record in the private deployment. Retain
metadata snapshots needed to explain prepared events. The current rule evaluator
does not automatically stamp a bundle revision into finding attributes, although
the finding envelope permits attributes.

For an initial integration, pair an external deployment manifest with a bounded
private dispatch ledger that records each event's processing run before sending.
Keep one verified immutable bundle active for that run. The manifest alone
cannot associate a finding with a bundle: current findings carry neither the
run nor the bundle digest. The ledger must retain the event/run association for
as long as that provenance is required, independently of spool reclamation.
Richer per-finding revision provenance is a candidate if direct public producers
or multiple processing runs make this private ledger insufficient. Keep revisions
separate from current deterministic finding identity.

There is currently no per-event rule-bundle selector or automatic cross-version
migration. Preserve the exact old rule bundle while recovering any pending WAL
work. For a planned activation, quiesce source pulls, settle all attempted
prepared events and uncertain admission responses against the old bundle, then
stop admission. Establish that admitted work completed with the old bundle,
stop the writer, preserve the complete backup, and activate the new bundle.
Draining the server alone does not settle a sender's ambiguous retries; retrying
an already admitted event under changed rules can conflict with an existing
finding. A forced or incomplete shutdown is not proof of a drained checkpoint;
recover with the old bundle first. Never-attempted prepared events waiting
outside the server can be assigned to the new run. This proposal applies the
bundle active for the selected processing run rather than promising detection
against the bundle active at source observation.

Changed rule content under the same ID can change replay results. Do not treat
renaming rule IDs as a replay fix: it changes finding identity and can produce
new detections. Qualify activation, recovery and rollback against the actual
selected artifacts using the [upgrade policy](../UPGRADING.md). Only one writer
may own a server store or private spool at a time.

## Findings consumption contract

The [findings cursor proposal](25-findings-cursor-proposal.md) specifies the
implemented append-order read, consumed-prefix digest, bounded paging and restore
behavior. Public local acceptance does not qualify private delivery.

The current `GET /v1/findings` is a bounded list ordered by `(created_at, id)`;
`created_at` is the event's observed time. It supplies time/severity/rule filters
and a limit, but no cursor. A late event can create a finding behind a time
watermark. A full page, especially many findings at one timestamp, cannot be
reliably continued by advancing that timestamp. An overlap window does not
establish complete consumption of arbitrarily late arrivals.

The proposed smallest public hook is a separate bounded cursor contract over
durable finding append order. Keep the current list API's behavior. Design the
consumption contract around these requirements before selecting its API syntax:

- Bind an opaque versioned cursor to a store stream and append position; reject
  wrong-stream, unsupported or invalid cursors explicitly.
- Return only synced findings with stable positions across restart and replay.
  Identical finding re-appends must not create a second delivery record.
- Bound page count, response bytes, concurrent readers and operation duration;
  carry cancellation without unbounded background work.
- Return a continuation position even at the current tail. Later appends must
  remain discoverable regardless of event timestamps, including after a reader
  restarts.
- Preserve complete traversal across pages containing equal observed timestamps
  and findings inserted after a previous read.
- Define behavior when a retained history or restored store no longer supports
  a cursor. A restored copy can keep the same stream ID yet lose a previously
  observed tail; reject an unavailable position and require reconciliation.
  Never silently jump to the current tail or assume stream ID alone detects all
  divergent restore histories.

The public hook is now locally accepted without a journal-format change. Its
version-1 consumption-position and restore contract is defined in document 25.
Consumer progress remains private; OUTBOX owns its atomic delivery-plan acceptance
and core has no company destinations.

## Durable delivery and failure handling

The private worker reads a bounded page and atomically persists a delivery plan
with its consumed cursor. The plan pins finding identity/content, routing
revision and selected destinations. Persist all work for that page before
advancing progress; a crash must recover either the earlier cursor or the
complete pending plan. Subsequent routing changes do not silently retarget
pending deliveries. Fan-out and pending records have finite bounds.

Attempt delivery with a deadline, cancellation, capped backoff and bounded
concurrency. Persist per-destination outcomes. Use a stable delivery identity
that includes the finding, logical destination and delivery generation. Reuse
it for retries. An explicit operator-authorized redelivery creates a new
generation. Destination idempotency support determines whether external
duplicates can be suppressed; no exactly-once promise follows from core finding
deduplication.

An unknown outcome remains pending because the destination may have accepted
the request before a timeout or worker crash. Permanent rejection and exhausted
retry policy enter a bounded failed state for operator handling. Never discard
failed work while reporting successful delivery. Credentials and payloads stay
out of diagnostics.

| Failure | Proposed response | Owner |
| --- | --- | --- |
| Unverified publisher or invalid snapshot | Reject identity-dependent input or retain receipt under explicit policy | Private integration |
| Missing ownership mapping | Preserve event and record missing status; apply rule policy | Private enrichment and detections |
| Crash after preparation or uncertain HTTP response | Retry the stored prepared event without re-enrichment | Private integration |
| Event/finding persistence failure | Stop admission; recover pending WAL with compatible artifacts and original rules | Existing public pipeline and private operator |
| Destination unavailable or outcome unknown | Keep durable pending delivery; retry using the same delivery identity | Private worker |
| Delivery backlog full | Stop consuming new pages; expose depth/capacity and failure status | Private worker |
| Findings history unavailable after restore | Stop cursor progression and reconcile retained delivery state/history | Public cursor contract and private operator |

External delivery is outside the WAL checkpoint. Its outage does not directly
hold a pipeline acknowledgement, but all stores are finite: a prolonged outage
can eventually exhaust finding storage and stop admission under existing
fail-closed semantics. The private application owns backlog capacity, retention,
reconciliation and recovery. Cursor advancement alone is not authority to delete
findings needed by another reader or an audit policy.

## Acceptance and implementation order

Future private fixtures and expected outputs remain external. Begin locally with
synthetic replayable input and a controllable destination; real AWS collection
and company systems are later authorized environments. Extend the existing
external integration gate rather than treating its earlier success as proof of
the new workflow.

| Acceptance case | Required observation |
| --- | --- |
| One event, one matching rule, one destination | Canonical identity and enrichment preserved; event and finding durable; delivery plan/outcome recorded |
| Crash around receipt and preparation | No acknowledged source input lost; prepared retries preserve bytes and snapshot identity |
| Metadata missing, stale, invalid or refresh unavailable | Selected policy observed; limits enforced; no fabricated verified identity |
| HTTP timeout after admission and partial batch admission | Only confirmed prefixes reclaimed; retries tolerate duplicate event rows |
| Restart with pending WAL, ambiguous admission or changed rules | Original bundle used for recovery and attempted-event settlement; event/run provenance and activation boundary recorded |
| More findings than one page, equal timestamps and late arrivals | Complete append-order traversal with stable restart/replay continuation |
| Wrong-stream or unavailable restored cursor | Explicit failure and reconciliation; no silent skipped history |
| Destination accepts before timeout or worker crash | Durable retry state preserved; destination deduplication tested if supported |
| Routing change, fan-out and full backlog | Pinned routing survives restart; no partial page progress or unbounded queue |
| Dependency or disk-contract upgrade and rollback | Actual artifact versions and compatible complete backups exercised |

First specify and review the public finding-consumption contract with its
restart/replay/restore cases. Implement it as a bounded change using generic
fixtures only after that task is selected. Then implement private receipt,
snapshot preparation and delivery state with the external fixtures. Add richer
rule provenance or a reusable delivery SDK only when those cases demonstrate a
missing generic hook. Existing Collector/Enricher interfaces do not require a
new plugin loader or process split for this walkthrough.

Public Rust changes will require focused regressions and the existing format,
Clippy, workspace-test and boundary gates, followed by the applicable review.
The current design proposal has no new runtime acceptance evidence and adds no
requirement to complete these post-MVP features before the existing release.

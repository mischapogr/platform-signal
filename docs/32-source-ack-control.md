# Bounded source acknowledgement control

Status: implemented SOURCE-ACK mechanism, 2026-10-07; acceptance recorded in
[progress](07-progress.md) and the finite ledger. Builds on the
frozen [receipt/progress schema](30-source-receipt-contract.md); no additional
wire fields. This first slice explicitly selects process-local recovery only.
It does not fetch sources, authenticate credentials, execute deletion, validate
stronger custody or authorize S3-original deletion.

## Authority and ephemeral delivery

Every mutation checks the exact store-issued prior control, current full binding,
OS owner/generation and a fresh trusted independently current checkpoint.
Checkpoint authentication/continuity remains the application’s responsibility.
Process-local custody must be explicitly selected and match the pinned binding;
stronger requirements fail closed until their independent custody verifier exists.
All quarantine remains blocked in this initial ACK slice, including mixed
receipts with any `quarantine_record`, quarantined objects and zero-prepared
objects. Active retirement is mandatory.

A bounded source delivery carries a non-nil attempt UUID, opaque delivery ID
(maximum 128 bytes) and current in-memory handle (maximum 16 KiB). It has no
serialization/Debug/Clone implementation. The source adapter must establish the
latest authorized delivery/handle; constructors cannot prove provider freshness.
ACK state stores the attempt and delivery identifiers only, never the handle.
An ACK ticket exposes the handle only after the intent’s atomic control commit.
No source call follows an uncertain intent-publication result.

## Transitions

`acknowledge(BeginProcessLocal)` checks local custody, non-quarantine content, selected
M2 completion, retention/replay capacity for the configured recovery budget and
a current fresh grant. It accepts not_requested/uncertain/confirmed, requires a
fresh attempt ID distinct from the previous attempt, and commits intent with
the exact pinned observation time. It increments revision/checksum link once
and resets admission attempt to none without changing any prepared bytes/prefix.

A finish operation consumes its ticket and accepts a fresh current progress
token/checkpoint if admission advanced while the same intent remained active.
The ticket binds the immutable receipt checksum, owner/generation and exact
ACK attempt/delivery, rather than the original intent control checksum. It
verifies exact current intent,
attempt/delivery, trusted current checkpoint and nondecreasing observation time.
It records confirmed or uncertain; raw response/handle never enter control.
The source-specific verifier for AWS JSON DeleteMessage accepts only status 200
and empty body. Other or missing responses remain uncertain. This verifies the
response shape from a trusted adapter, not endpoint identity or guaranteed removal.

After loss of a ticket/reply, a fresh checkpoint-authorized recovery operation
may mark the retained intent uncertain, preserving its IDs and preparation.
Redelivery starts a new intent/attempt using a newly received handle, then retries
source deletion. A retained intent is not silently reset to not_requested.
Dispatch may continue pending prepared work when the selected ACK policy did not
require M2 completion. Retirement remains blocked until confirmed ACK, complete
verified prefix, elapsed horizons and separate fresh reclamation authority.

Revision-one ACK-only transitions retain zero prefix and the exact initial
predecessor check. The takeover predecessor exception remains separate; a `none`
admission attempt alone is insufficient to bypass history checks.

## Time and failure behavior

Canonical observations use the existing exact nanosecond UTC encoding. No
observation precedes preparation or a prior ACK observation. Begin cannot extend
fixed horizons: observation plus recovery budget must fit both retained/source
replay horizons. A later result can still record an already-issued deletion
outcome after the horizon, without issuing a new handle or extending retention.
All control writes use the bounded temp/sync/atomic-replace/directory-sync path.
Timeout/cancel/lost caller cannot prove rejection; the physical worker retains
its lock and mutation uncertainty requires verified reopen/reconciliation.

## Acceptance

Positive intent/result and uncertain/redelivery paths must preserve exact
original/event identities across reopen. Reject stale token/current checkpoint,
full-binding changes, wrong attempt/delivery, insufficient M2, expired or backward
time, unsupported stronger custody and quarantine. Check handle absence from
files and diagnostics; test actual queue/cancel/timeout/fault/crash milestones
and local provider response cases. Independent source review plus workspace
acceptance precedes transport or reclamation claims.

Context7 did not return matching SQS operation documentation. The official
[DeleteMessage reference](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteMessage.html)
was checked: JSON success is HTTP 200 with an empty body, newest received handles
are required, and a successful delete does not exclude standard-queue redelivery.
These facts constrain the verifier and replay design; local tests do not qualify
actual AWS transport, credentials, source completeness or account-loss custody.

`ReceiptStore::acknowledge` accepts `ReceiptAckUpdate` (BeginProcessLocal, Finish,
RecoverUncertain) and returns an intent ticket/current token or settled token.
`SourceAckOutcome` verifies only AWS JSON response shape or represents uncertainty.
The application supplies fresh checkpoint authentication and provider transport.

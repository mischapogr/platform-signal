# Local source-receipt retirement and slot replacement

Implemented and accepted locally as the final RECEIPT-RECOVERY substep; see
[progress](07-progress.md) for 447-test workspace evidence and independent review. This uses the
frozen control schema, process-local custody and accepted source ACK mechanism.
Only the local immutable `.src` payload is removed; source objects are untouched.

`retire` requires exact prior control, full current binding, exclusive owner and
a fresh independently current application checkpoint. Active retirement needs
confirmed ACK, fully verified prepared prefix and observation at/after the pinned
`retain_until` and last ACK observation. `source_replay_until` constrains new ACK
issuance; the frozen reclaim examples permit local removal at `retain_until`.
Elapsed time never grants authority by itself. Non-send changes reset the attempt.

Preflight capacity for both control revisions before any side effect. Commit
intent, remove the exact generated receipt filename, sync the directory,
then commit completion. Every failure poisons the current worker; a missing active
payload remains corruption. Intent with an absent payload is unsettled reclamation,
not a new empty slot. Reopening retired state requires an independently current
checkpoint even when the physical payload is absent. The retained control keeps
binding, count, prefix witness, digest, owner/generation and fixed horizons; its
syntax/checksum alone cannot establish the now-removed payload's history.

Expose the bounded current control for reconciliation. After a lost reply, the
application can syntax-check a bounded raw snapshot with
`ReceiptProgress::inspect_retirement_control`, authenticate its continuity against
independent history, then call `open_reconciled`; inspection provides no permission
or lock assurance and opening rechecks the current bytes. A fresh grant may resume
intent, recheck optional present payload, confirm absence plus directory sync and
commit completion at a nondecreasing time. Complete state is idempotent. Dispatch
and ACK stay blocked during intent/complete. A same-process owner transfer remains
allowed with fresh authority and preserves retirement; remote fencing is separate.

`publish_next` explicitly authorizes local replacement using the completed prior
token/checkpoint and a trusted new full binding. New UUID is mandatory. Preserve
completed control while the new immutable payload is exclusively published/synced;
atomically replace it with the new receipt's initial control only afterward.
An interrupted publication with temps or an unexpected payload fails closed and
does not adopt, delete or regenerate an orphan. Such uncertain roots need external
history reconciliation before controlled cleanup; this is not automatic adoption.

Acceptance covers guards, unchanged pins, repeated retirement, checkpoint-aware
missing-payload recovery, new UUID/no-clobber replacement, bounded queue/physical
worker lifetime and syscall/process failures at intent/removal/sync/completion/
replacement. Checks qualify process recovery on a surviving local filesystem,
not power/device/account loss or stronger custody. No unbounded tombstone journal.

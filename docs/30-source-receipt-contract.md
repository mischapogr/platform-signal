# Source receipt and progress encoding v1

Status: **frozen schema contract**, 2026-10-07. The initial
[Rust local store](../crates/signal-collector-sdk/src/receipt.rs) now has bounded
process/filesystem evidence; the complete progress/custody protocol remains ahead.
This freezes the proposed
`SIGSRC01` framing in [29](29-cloudtrail-source-receipt.md) and introduces
`SIGSCP01` progress. The schema witnesses do not implement source ACK, gzip
parsing, source proofs
or AWS collection. The bounded store accepts already prepared receipt bytes and
initial controls only; it does not implement the full transition matrix. The
[fixture](../tests/fixtures/cloudtrail-receipt/contract.json)
and [checker](../scripts/check-cloudtrail-receipt-contract.py) are synthetic
encoding/transition witnesses. They are separate from SourceCoverage history.

## Scope and finite representation

The first backend has one exclusive local owner and one retained receipt. Its
assurance is process recovery on a surviving, qualified filesystem. Local sync,
a generation field and three replicas do not establish host/AZ/account-loss
custody or fence remote side effects. All networking remains a subsequent task.
The Rust normalizer still handles one decoded record; object parsing and atomic
preparation of every ordinal must be qualified before admitting real objects.

All lengths count bytes. Checked integer limits are inherited from [29](29-cloudtrail-source-receipt.md):
original 8 MiB, decoded object 32 MiB, records/prepared entries 1,024, native
record 256 KiB, event 64 KiB, prepared payload total 16 MiB, metadata 1 MiB,
framing 64 KiB and receipt 32 MiB. Progress and its replacement each reserve
8 MiB; root quota is at least 64 MiB. Reject before allocation/mutation in the
future backend. The offline reference encoder is not a resource-qualified reader.
The single retained slot includes completed, unexpired and quarantined receipts.
Intake blocks rather than evicting them. Files, interrupted temporaries and
quarantine count against the same quota; publication renames the one complete
preparation file rather than creating a second full receipt copy.

Canonical metadata/progress JSON is UTF-8, no BOM/whitespace/newline, keys sorted by Unicode scalar
value, no duplicate keys, and no unknown schema fields. Integers are unsigned
base-10 without leading zero and at most `2^64-1`; floats are forbidden in metadata/progress. Event payload
attributes retain the existing v1 JSON number semantics and exact pinned bytes;
these metadata rules do not narrow the public event envelope. JSON
booleans are distinct from integers. Strings escape only quote, backslash and
U+0000–001F (the latter as lowercase `\u00xx`); other scalars are literal UTF-8,
including `/` and non-ASCII text. Lone surrogates reject. Arrays preserve order.
This exact encoding is enforced on decode; semantically equivalent JSON is not
an alternate representation. All schema keys are ASCII. Time is exactly
`YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`, valid Gregorian UTC, years 0001–9999, no leap
second. UUIDs are canonical lowercase, non-nil; hashes are 64 lowercase hex.
Time is caller-pinned, never regenerated on replay.

## Immutable metadata schema

Every object below has exactly the listed fields. A nullable field is present
with JSON null when absent. `text(n)` is nonempty UTF-8 of at most n bytes.
Revisions are opaque identifiers, not lexically ordered version numbers.

| Object | Required fields and types |
| --- | --- |
| Metadata | `schema_version=1`, `receipt_id:uuid`, `binding:Binding`, `original:Original`, `prepared_at:time`, `normalizer_sha256:hash`, `retention:Retention`, `object_disposition`, `object_reasons`, `records:Record[]` |
| Binding | `tenant_id`, `collector_id`, `source_id`, `config_revision`, `authority_revision`: text(128); `queue_arn`, `trail_arn`: text(512); `queue_owner`, `bucket_owner`: 12 ASCII digits; `bucket`: text(63); `key_prefix`: UTF-8 at most 1,024 bytes (empty permitted); `stream`, `profile_id`, `profile_revision`: text(128); `recipient_accounts`: 1–128 distinct 12-digit strings; `regions`: 1–64 distinct lowercase ASCII letter/digit/hyphen strings, 64 bytes each; `custody_mode`; `ack_requires_m2`: bool |
| Original | `bucket:text(63)`, `key:text(1024)`, `version_id:text(1024)` other than `null`; `etag:null or text(1024)`, `compression="gzip"`, `length:u64`, `sha256:hash`, `decoded_length:u64`, `captured_at:time`, `discovery_sha256:hash`, `delivery_id:text(128)`, `reference_count=1` |
| Retention | `retain_until:time`, `source_replay_until:time`, `recovery_budget_seconds`: integer 1–`2^32-1` |
| Record | `ordinal:u32`, `start:u64`, `length:u64`, `sha256:hash`, `native_event_id:null or uuid`, `disposition`, `reasons:Reason[]`, `prepared_index:null or u32`, `prepared_id:null or uuid`, `prepared_sha256:null or hash` |

Binding account/region arrays are sorted in ASCII byte order. The original
bucket and decoded key prefix must match the **full trusted application grant**;
byte-prefix matching alone is insufficient authority. Require exact equality of
the entire binding for retained replay/access/progress/ACK. A fingerprint cannot
replace full-binding comparison. This schema stores no access token, receipt
handle or credential. Delivery IDs and source hashes do not grant permission.
The fixed normalizer profile is `cloudtrail-management`/`v1`; the fingerprint
pins the application-reviewed definition used to prepare those bytes, rather
than being recomputed from a mutable current binary on replay.

Custody modes are `process_local`, `independent_durable` and `protected_replay`.
They are requirements, not attained assurances. Capture <= preparation <=
retention and source-replay horizons. Both horizons must cover the checked
preparation + recovery-budget sum; timestamp overflow rejects. They are pinned
private inputs: retries cannot extend retention. Native event time may be older.
No production SLO or authorized original-deletion policy is selected here.

Object disposition is `prepared` with no object reasons, or `quarantine_object`
with 1–4 distinct ordered reasons. Object reasons are `invalid_compression`,
`invalid_object_json`, `object_limits_exceeded`, `unsupported_object` and
`empty_records`. Quarantined objects have no records or prepared bytes; they
retain the captured compressed original and bounded failure reason. An original
that cannot be captured within bounds never becomes a receipt or safe source ACK.
A prepared object has 1–1,024 contiguous ordinals starting at zero. Spans are
nonoverlapping, strictly increasing, positive, within decoded length and at
most 256 KiB; each is the exact JSON value byte range without outer whitespace.
A qualified object reader verifies spans/hashes and native IDs against the full
original. Header-only validation cannot establish that relationship.

Record dispositions/reasons are exactly the normalizer's `emit`,
`emit_indeterminate`, `quarantine_record` and its finite reason enum. `emit` has
no reason; indeterminate/quarantine has 1–4 distinct ordered reasons. Emitted
entries have a contiguous prepared index in native order and non-nil unique
prepared IDs; quarantined entries have all three prepared fields null. IDs may
repeat natively across records: this is not a global dedupe index.

## Immutable binary layout

```text
SIGSRC01 (8 ASCII bytes)
u32be metadata_length
u64be original_length
u64be prepared_count
u64be prepared_payload_total
canonical_metadata_json
exact_compressed_original
repeat prepared_count times:
    u32be event_length
    uuid16 (RFC 4122 byte order, not text or little-endian GUID)
    SHA256(event_bytes) (32 raw bytes)
    exact_event_bytes
SHA256(all preceding bytes) (32 raw bytes)
```

Header values agree exactly with metadata and actual sections. Prepared mapping,
UUIDs and hashes agree with every framed entry. No trailing padding/bytes,
truncated frames, unknown version, duplicate prepared IDs or out-of-order mapping.
Framing is `36 + 52 * prepared_count + 32` bytes (53,316 at 1,024), within 64 KiB.
All section sums and file length are checked before reads. Canonical event bytes
remain opaque pinned payload for replay; before first publication a qualified
preparer validates event v1, IDs, time, profile/revision, the granted
CloudTrail recipient account/region and
`receipt://<receipt_id>/record/<ordinal>` against each descriptor. Never rewrite
an old payload merely to match a current serializer. The final receipt digest
is not embedded in events, avoiding a circular encoding. Checksums are accidental
inconsistency witnesses, not signatures, source authentication or rollback proof.

## Separate progress schema and encoding

```text
SIGSCP01 || u32be(json_length) || canonical_progress_json
         || SHA256(all preceding bytes)
```

| Object | Exactly required fields |
| --- | --- |
| Progress | `schema_version=1`, `receipt_id:uuid`, `receipt_sha256:hash`, `binding:Binding`, `retention:Retention`, `prepared_count:u32`, `owner_id:uuid`, `owner_generation:u64>0`, `revision:u64`, `previous_sha256:null or hash`, `verified_prefix:u32`, `prefix_sha256:hash`, `attempt:Attempt`, `custody:Custody`, `ack:Ack`, `retirement:Retirement` |
| Attempt | `kind` (`none`, `verified`, `uncertain`, `permanent`), `start:u32`, `count:u32`, `accepted:u32`, `response_sha256:null or hash` |
| Custody | `status` (`pending`, `local_only`, `verified_independent`), `witness_id:null or text(512)`, `receipt_sha256:null or hash`, `retain_until:null or time` |
| Retirement | `state` (`active`, `intent`, `complete`), `observed_at:null or time` |
| Ack | `state` (`not_requested`, `intent`, `uncertain`, `confirmed`), `attempt_id:null or uuid`, `delivery_id:null or text(128)`, `observed_at:null or time` |

Prefix witness is SHA256 of ASCII `SIGPRF01`, the 32 raw receipt-digest bytes,
u32be(prefix), and for entries `[0,prefix)` their UUID16 then event hash32.
This binds order/content; exact immutable event bytes still remain authoritative.
The initial revision is zero, previous hash null, prefix zero, attempt `none`
with zero counts/null response, custody `local_only` with null witness fields,
and ACK `not_requested` with all other fields null, retirement `active` with null
time. The copied full binding, retention and prepared count must exactly match
the receipt. They remain available for authority checks when the retired
receipt file has been removed. Quarantine-object/all-record
quarantine receipts have prepared_count zero and a valid empty-prefix witness.

Each replacement increments revision exactly once, links the prior progress
trailer digest, preserves receipt identity, and never decreases verified prefix.
A send starts at the old prefix, count is 1..remaining. `verified` accepts a
leading prefix of zero through count and stores the verified response hash. All other
outcomes accept zero, store no response hash and advance zero; `none` has zero
count/start/accepted. Lost/malformed/cancelled responses are `uncertain`, even
if admission may have happened. The **existing transport verifier** must verify
response schema, ordered IDs/counts/error index before writing `verified`.
A fixture's claimed accepted count or response hash is not itself that proof.
Non-send replacements use `none`; submitted attempts do not roll backwards.

Same-owner generation is unchanged. A qualified exclusive-owner takeover changes
owner ID and increments generation exactly one, resets attempt to `none` and
preserves prefix/custody/ACK. An unrelated restore is not a takeover. The local
backend must acquire and hold its actual OS lock before reading/changing state;
metadata cannot fence live owners or remote calls. A lost or corrupt progress
file is never replaced by a fresh zero-prefix record for an existing receipt.
A consistent older backup cannot prove history continuity. Recovery holds ACK
until independent custody/replay reconciliation and fresh exclusive ownership;
this condition is external to the copied local progress bits.

`pending`/`local_only` custody has null witness fields. `verified_independent`
requires a current independently verified witness binding the **entire receipt**
(original plus every prepared/quarantined entry and revisions), with a retention
horizon at least the pinned horizon. A local field set to `verified_independent`
is not the verification mechanism. No custody downgrade is a safe ACK transition.
The bounded Ed25519 whole-receipt witness and explicit stronger ACK mechanism
are specified in [protected evidence](38-protected-evidence-contract.md). Their
immutable manifest identity is retained in the existing custody fields; fresh
verification and trusted quarantine permission are not serialized into progress.
`process_local` accepts local custody only with explicit current owner authority
for process-only recovery. The other modes require the independent witness.
All ACK attempts also require a fresh full grant, exclusive ownership, known
reconciled history and M2 prefix completion if `ack_requires_m2=true`.

ACK transitions: `not_requested -> intent -> confirmed|uncertain`, and
`uncertain|confirmed -> intent` for a newly received delivery and fresh attempt
UUID. Persist intent before source deletion; use only the fresh in-memory receipt
handle, never a stored old handle. `intent` remains replayable after process loss;
uncertain deletion retains the immutable receipt. Confirmation records a verified
result of that attempt; it does not guarantee no redelivery. Duplicate delivery
uses the retained receipt and a new attempt. ACK-only changes use attempt `none`.
No source ACK is allowed from a quarantined object without selected quarantine
custody. Neither successful deletion nor horizon expiry authorizes S3 deletion.

## Local publication and control commit points

The backend uses a private owned root and internally generated UUID filenames,
never bucket/key/metadata text as a filesystem path. Hold the OS lock throughout
inspection and mutation. Receipt construction writes one bounded preparation
file; sync it, publish to the immutable UUID path without clobbering another
entry, then sync the directory. The current initial-only local backend uses
exclusive hard-link creation then temporary-name removal, with no second payload
copy; a crash between them fails closed. Write/sync initial progress referencing
that exact receipt; publish its first root-control name with the same exclusive
no-clobber sequence and sync the directory. A later mutable backend atomically
replaces an existing root control; this slice never overwrites one. **M1 is
exposed only after this final control commit**, when both files are verified.
A receipt filename or successfully synced temp alone does not expose M1.
Progress replacements use the same temp/sync/atomic-replace/directory-sync order;
no verified prefix or ACK intent is exposed before that commit settles.

Any uncertain sync/rename completion stops dispatch and is reconciled by reopen
under the exclusive owner. A receipt present without a verified current control
is an orphan/uncertain publication, counted against quota and the sole slot; it
cannot be adopted as fresh zero-prefix history. A missing active control also
cannot prove that source deletion never occurred. Hold intake/ACK until the
selected external custody/replay and history reconciliation permits recovery.
The backend must distinguish these uncertainty paths in its fault tests.

Retirement intent commits before unlinking the immutable receipt. Verify unlink
and directory sync before committing retirement completion in current control.
Only then may a new slot be prepared. Preserve the old completed control until
the new receipt's initial control replacement commits atomically. New progress
starts a new receipt chain with a different UUID; this does not establish a global
history or make an older self-consistent root backup safe to activate. A fresh
owner and independent history reconciliation remain necessary after restore.
The fixed root/control files and interrupted replacements fit the reserved
control/index quota. There is no append-only, unbounded progress-chain journal.

## Storage acceptance and reclaim boundary

| Scenario | Required local behavior before qualification |
| --- | --- |
| Preparation/capture fails or quota fills before commit | No receipt exposed, no send or source ACK; retain source responsibility; count temp/quarantine bytes |
| Temp sync, atomic rename or directory sync fails/has uncertain completion | Fail closed; reopen and verify under exclusive lock; do not infer M1 from filename |
| Complete M1 and process loss | Reopen exact bytes/IDs/revisions; validate all sections before replay |
| Response verified, progress sync fails | Retry previous committed suffix; duplicates allowed, guessed progress forbidden |
| Torn/corrupt/missing progress or original/prepared payload | Hold intake and ACK; reconcile retained custody, never regenerate preparation |
| HTTP partial prefix then retry | Advance only verified leading prefix; subsequent dispatch uses immutable suffix |
| Source deletion lost/timeout/redelivery | Retain intent/uncertainty and receipt; new handle/attempt, same preparation |
| Grant revoked, stale owner or unknown restored history | No access/send/ACK/reclaim until selected authority/reconciliation is qualified |
| Completed unexpired receipt | Hold sole slot; no intake eviction |
| Retention elapsed | Reclaim only with fresh exact authority, fully verified prepared prefix, confirmed ACK and known history |
| Reclaim unlink/directory sync uncertainty or crash | Durable retired-state intent precedes removal; reopen fails closed; avoid identity reuse before settled reclamation |
| Host/disk/account loss | Exceeds process-local assurance; independent durable custody and restore protocol need separate qualification |

A replacement changes retirement `active -> intent` only after the reclaim
guards pass, with the pinned elapsed-horizon time. It changes `intent -> complete`
only after verified file removal and directory sync, at a nondecreasing time.
These changes preserve prefix, custody and ACK and reset attempt to `none`.
Retirement blocks send/custody/source-ACK changes; takeover may preserve it while
reconciling deletion. Missing payload under an active control is corruption;
missing payload under retirement intent is uncertain reclaim to settle under
the exclusive owner. The control retains full binding, horizon, count, prefix
witness and receipt digest for that distinction, rather than being recreated.

A future backend must retain a bounded retired-state/reclaim intent in control
space until deletion is settled. New-slot publication uses a new receipt UUID
and an atomic, recoverable root-control transition; retiring the previous slot
does not authorize identity reuse. This root publication protocol requires
backend fault tests and is not a global tombstone ledger. No receipt recreation under the old identity
from missing files. Retirement is not proof of global deduplication after the
retained horizon. Crash/process, partial writes, lock ownership, quota, cancellation,
shutdown, conflicting restore and fresh-grant behavior need actual Rust/backend
fault tests. The offline matrix checks decisions and binary witnesses only.
Native ARM64, actual EKS/AWS, remote CI, released dependencies and publication
remain the gates in [21](21-release-readiness.md).

## Bounded initial-store evidence

`receipt::ReceiptStore` now executes immutable decoding and initial publication/
reopen behind a single bounded blocking worker. Twenty-one focused Rust tests
cover three exact receipt/initial-control golden pairs, eight publication-stage
process exits and eight injected fault paths, an actual destination-exists syscall
failure, corruption/orphan/quota/lock/path/scope checks, queued cancellation,
caller timeout and lost-reply durability. The helper process test is ignored in
normal enumeration and is invoked explicitly by its parent test. Evidence is
`target/source-receipt-store-20261007/`; review is focused writer review, not new
independent source review. Earlier offline vectors remain their separate scope.

The initial-only slice refused non-initial progress on reopen and never rewrote
retained preparation; the progress slice below supersedes that restriction. Original gzip validity, object-record span derivation and authenticity
remain preparer/source qualification work. The next slice implements atomic
verified-prefix progress and replay, then retirement/takeover/restore qualification
before source delivery. Process exits on the current filesystem do not establish
power-loss/device/AZ/account durability or administrator-resistant proof.

## Atomic verified-prefix progress slice

The SDK now exposes store-issued `ReceiptProgress` compare-and-swap tokens and
`ReceiptReplay` immutable suffix views. `advance` receives the actual bounded
response body/status and executes the shared v1 admission verifier in
`signal-protocol`; the agent uses the same verifier. Schema, ordered IDs/counts
and partial-error index must agree with the exact retained suffix. Response
bytes are hashed after verification. Missing responses can be recorded as
uncertain; no caller-provided accepted count or witness hash advances progress.
A malformed response rejects before mutation; retry the committed suffix or
record uncertainty. Application-supplied transport responses and grants remain
trusted inputs: this library does not authenticate a remote endpoint itself.

Each update checks the complete current binding, pinned owner/generation and
exact prior control bytes, increments revision once, links its checksum and
commits via bounded temp write/sync, atomic replacement and directory sync.
The decoder verifies complete immutable pins and prefix witness on reopen.
Revision one must follow the exact initial control and a zero starting prefix.
Custody/ACK/retirement changes remain unsupported in this slice. Checksums do
not detect an older self-consistent backup or prove source authenticity.

Timeout/cancellation cannot preempt a kernel filesystem operation. One physical
worker retains the OS lock until exit, queue capacity remains one, and a mutation
error poisons further dispatch. A pre-replacement interrupted temp fails closed;
a surviving post-replacement control can reopen only after full verification.
This remains process recovery on the current filesystem. Evidence and independent
review are retained in `target/goal-execution-20261007/`.

## Voluntary owner handover and reconciled opening

`ReceiptRecoveryGrant` is a bounded, non-deserializable trusted application input
binding full scope to an independently current control checksum and authority
revision. Its constructor checks bounds, not authentication or source proof.
Never derive recovery authority from producer fields or copied root bits.

`transfer_owner` consumes the store and requires exact prior control/current
grant under the existing OS lock. A different non-nil owner increments generation
and control revision once, preserves receipt/prefix/retention/custody/ACK, and
resets attempt to the exact `none` value. Atomic replacement uses the same bounded
control commit path. Every transfer outcome terminates ordinary worker admission;
success awaits physical exit. New-owner open cannot overlap the old worker.
The first handover has a zero prefix and an old-owner predecessor, so the decoder
distinguishes it from first-send predecessor validation. No remote fence follows.

`open_reconciled` checks the independently current checkpoint and full binding
before exposing any store. A consistent older copied root is rejected when the
trusted checkpoint remains current elsewhere. Ordinary `open` continues to
promise process-local recovery only; selecting it is not restore reconciliation.
Unknown/missing/divergent authority cannot be replaced by a fresh initial record.
The caller must authenticate/qualify checkpoint durability outside this library.

Twelve local handover/opening tests and independent source review are retained in
`target/goal-execution-20261007/RECEIPT-RECOVERY/`; current workspace acceptance is
422 tests. Source ACK and retirement/reclamation remain separate: confirmed ACK
control must exist before the frozen retirement guard can pass.

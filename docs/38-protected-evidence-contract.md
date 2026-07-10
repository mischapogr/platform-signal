# Protected originals, source proofs and independent custody

Status: selected finite EVIDENCE contract, 2026-10-08. OUTBOX and DISPOSITIONS
have local acceptance. This item does not add services or change release/version
authority. Real AWS/Object Lock/IAM/KMS/native ARM64 remain unqualified.

## Distinct assertions

Protected evidence preserves authorized original bytes before observability
filtering. An archive write, a retention control, validated source provenance,
independent receipt custody, source coverage and server M2 are separate assertions.
A field saying `verified` grants none of these by itself. The archive authority
must be separate from the observability publisher, with independently configured
verification keys, least privileges, bounded requests and retained originals.

The existing receipt binds original plus every prepared/quarantined entry and
configuration/profile revisions. Independent custody must bind that complete
receipt checksum, exact source bucket/key/version/owner, full trusted binding,
retention/replay horizons, witness version and authority revision. It cannot
substitute a different version with equal-length bytes, shorten retention, or
renew the original verification time on replay. Uncertain/denied verification
holds custody progression and any ACK that requires it. Source ACK is never
permission to delete originals. Existing process-local quarantine/stronger-mode
denials remain intact. A quarantine ACK additionally requires explicitly selected
trusted quarantine custody; a valid independent witness alone cannot authorize it. The generic receipt stays in the SDK; actual
policies, account identities, trusted signing keys and deployment stay private.

## Native CloudTrail proof support

The bounded validator uses exact uncompressed bytes and the native digest shape,
not reserialized JSON. Native uncompressed content hashes, compressed-original
hashes and complete framed-receipt checksums remain distinct. AWS places the current signature in object metadata and
links prior signatures/hashes in digest content. The signing input combines end
time, original bucket/key, content SHA256 and prior signature with newline
separators (a starting previous signature uses literal `null`, as in the
[official validator](https://github.com/aws/aws-cli/blob/develop/awscli/customizations/cloudtrail/validation.py)); RSA verification uses an independently obtained regional key.
See [AWS custom validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html).

The trusted key source is regional `ListPublicKeys`, with finite response/key/
page/token/time limits and key validity checks. A digest cannot supply its own
trusted key. Original-version capture, metadata algorithms and required source
scope must match trusted configuration before validation. See
[the API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListPublicKeys.html).

Chain traversal has fixed count/bytes/CPU/deadline budgets, authenticates every
referenced original and detects changed/missing links. A retained authenticated
anchor/checkpoint defines the covered delivery interval; a starting chain is
explicit bootstrap, not proof of an earlier interval. Unanchored, missing or
temporally gapped chains establish only bounded integrity/bootstrap evidence.
Backfill and redelivery cannot silently heal an earlier coverage interval. Signed empty digests can
prove their bounded delivered-file interval. Delayed files, missing/redelivered
links and backfill remain explicit; backfill key selection uses its authenticated
object metadata generation time. See [AWS digest structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html).

Source signatures prove validated referenced bytes and supported delivery-chain
continuity. They do not prove that every desired API category/resource was logged,
that selectors stayed enabled for the entire interval, or that no later backfill
exists. Coverage reports must preserve those separate missing/unknown dimensions.
Never upgrade the existing configuration-only probe into complete coverage merely
because one digest verifies. Native proof adapters and their bounded checkpoint/
continuity behavior are implementation here, rather than deferred credential work.

## Protected route and local simulation

Use generic archive/verifier seams and an independently owned local stand-in for
versioned storage, retention controls, authenticated requests and signed custody.
The stand-in must enforce its controls, not simply return expected success flags.
Use separate synthetic authorities/permissions and owned private roots. Every
queue, retained identity, object, manifest, proof/key list and caller response has
finite count/byte/operation budgets. One physical writer owns each coherent
mutable backend; cancellation/timeout cannot release ownership during active I/O.

Qualification follows source capture through original preservation, native proof
validation, complete receipt custody, required ACK and normalized M2/replay.
Run with the observability server unavailable while independent protected capture
continues; recover without changing original/version/identity or renewing proof
age. Exercise malformed/oversized input, bad signatures/keys/algorithms, wrong
account/region/version/owner/path, missing/tampered chain/logs, pagination cycles,
throttling/permission denial, lost responses, retention insufficiency, bounded
exhaustion and process crashes. Proof failure and recovery remain visible and
must not fabricate validated source or custody.

These local controls and simulations do not certify AWS IAM isolation, Object
Lock compliance mode, KMS, account/region/AZ-loss protection or live source
completeness. Object-backed server custody and shared control remain the separate
OBJECT-CUSTODY/SHARED-RUNTIME items; EVIDENCE does not claim Standard HA readiness.
Normal open/recovery must never silently reset a consumed checkpoint or replace
an unavailable proof with a fresh zero-position history.

Evidence destination: `target/goal-execution-20261007/EVIDENCE/`. Context7 is quota
unavailable; primary AWS documentation and the exact locked crypto sources are
the documentation basis. Synthetic proof keys must never be used in production.

## Native validator and read-only source implementation

`signal_collector_sdk::cloudtrail::proof` separates immutable signed-digest,
complete referenced-log delivery and classified chain results. Exact bytes are
hashed before projection; authenticated unsupported vendor bytes can still be
quarantined by normalization. Caller-configured source/home regions, trail path,
recipient account, bucket owner and captured version are retained separately.
An authorized checkpoint can be serialized/restored with strict version/shape/
byte checks; restoration itself neither authenticates it nor prevents rollback.
Durable independent checkpoint ownership and coverage integration remain part of
EVIDENCE's protected-route work.

The optional `aws-source` adapters perform actual SigV4 `ListPublicKeys` and
exact-version S3 reads through the existing bounded transport. They use trusted
endpoints/credentials, no automatic retry or latest-version fallback, one active
read each and observable capacity/rejections. S3 capture requires matching version
and nonduplicate native signature/algorithm/backfill metadata before exposing an
EOF-complete body. The expected-owner header is part of the signed request; only
real S3 qualification can establish AWS's enforcement. Crypto validation follows
capture and does not infer it from request success. Regional key responses with
unsupported continuation or error envelopes fail closed.

Budgets: 1 MiB compressed/decoded digest; 8 MiB compressed and 32 MiB streamed
decoded log; 1,024 referenced logs; 64 digest links; 64 MiB aggregate compressed
and decoded delivery/chain work; 64 KiB complete key response, 64 keys and 4 KiB
DER per key; fixed JSON depth/node limits. UTC API request epochs must be
nonnegative, nanoseconds below one billion, and the interval at most 90 exact
days. Decimal key validity is parsed without floating-point widening. CPU work
belongs on a caller-owned bounded worker; aggregate retained results/copies also
need a caller budget. Cancellation/deadline checks bracket parsing, RSA and
chunked decompression/hashing. No asynchronous disk/network work is hidden in the
pure validator.

Synthetic fixtures deliberately contain a public, non-production RSA test key.
The baseline signature was produced by OpenSSL independently of the Rust verifier;
whitespace changes invalidate its exact native byte hash. Local HTTP simulations
exercise signed requests and source failures; they cannot qualify AWS delivery,
Object Lock, archive authority or complete collection. Native proof mechanisms
alone do not close the parent EVIDENCE item or source-coverage assertions.

## Independent witness protocol selected for implementation

A version-1 bounded witness carries an immutable manifest and a fresh signed
verification envelope. The manifest binds the frozen receipt ID/checksum, a
separate SHA256 of all framed bytes, exact full binding/original/pinned retention,
archive version identity, retained-until horizon, custody mode/purpose and the
original custody commit time. Its content SHA256 is the stable witness identity.
A new verification challenge cannot rewrite that manifest or renew commit time.
`protected_replay` requires archive retention through the maximum of pinned
retention and source-replay horizons; independent durable custody requires the
pinned retention horizon.

The independent archive authority signs both manifest and challenge/verification
fields with a configured Ed25519 key. The verifier pins authority/key revision,
a caller-generated nonnil nonce and a short trusted UTC request/expiry window.
Reject unknown/duplicate fields, unsupported versions, wrong signature, scope,
original version, receipt bytes, authority, nonce or retention before producing
an ephemeral nonserialized custody token. Producer metadata cannot set trusted
keys, current time or quarantine permission. Archive custody alone makes no native
source-signature or collection-completeness assertion; retained proof validation
and coverage remain separate requirements in EVIDENCE integration.

A durable custody transition uses the existing physical receipt worker, complete
CAS progress and a freshly authenticated history grant. Reopen checks the frozen
custody shape without treating stored flags as fresh verification. Every stronger
ACK side effect must additionally consume independently verified current custody
for the exact retained witness and selected purpose; plain process-local ACK
retains its current restrictions. A quarantine ACK also requires explicit trusted
quarantine selection. Custody/ACK cannot downgrade, bypass pinned M2, retarget
source identity or authorize original deletion. Deadline/cancellation uncertainty
retains the owner until physical I/O ends. These mechanisms precede the
protected-route simulation; they do not establish real archive permissions.

The byte frame is `SIGCUS01 | manifest_length:u32be | manifest_json |
attestation_length:u32be | attestation_json | signature:64`. The Ed25519 signature
covers every preceding byte. Manifest JSON is the existing canonical receipt
encoding; both objects reject unknown and duplicate fields. Maximum sizes are
64 KiB manifest, 2 KiB attestation and 67,664 bytes complete witness. Neither
object permits embedded credentials or arbitrary fields.

| Object | Exact fields |
| --- | --- |
| Manifest | `schema_version=1`, `receipt_id`, `receipt_sha256`, `framed_sha256`, `binding`, `original`, `retention`, `archive_id`, `archive_version`, `authority_id`, `mode`, `purpose`, `committed_at`, `retain_until` |
| Attestation | `schema_version=1`, `authority_id`, `key_revision`, `manifest_sha256`, `challenge`, `verified_at` |

Archive ID/version are at most 512 bytes, version cannot be `null`, and authority
ID/key revision are at most 128 bytes. Text rejects control characters. Trusted
UTC times use the receipt's exact 30-byte nanosecond format. The challenge window
is at most 60 exact seconds. Signed verification time must be within the request
and configured key validity window and no later than the caller's observed time.
The token's monotonic deadline is the earliest challenge, key, archive retention
or original operation expiry; elapsed verification work is not refunded.

`prepare_custody_manifest` constructs a statement after the caller has actually
published to its independent archive; it writes nothing and grants no custody.
`verify_custody_witness` authenticates the assertion and whole receipt, producing
a non-Clone, nonserialized `VerifiedCustody`. The authority constructor checks
shape; selecting the key, trusted clock, purpose and independent archive controls
belongs to the authenticated application. Crypto does not inspect deployment
isolation or replace the native CloudTrail proof validator.

`ReceiptStore::verify_custody` uses full progress CAS/current-history authority on
the existing worker. An identical manifest is idempotent; a different version,
identity or retention cannot replace it. All stronger `BeginIndependent`,
`FinishIndependent` and `RecoverIndependent` ACK updates require a newly verified
token matching that retained manifest. The ordinary collector driver remains
explicitly process-local; it does not opt into these stronger operations.

Issued tickets also carry a local owner fence. Transfer cancels it before the
new owner control is published; worker poison and exit cancel it as well.
Adapters must use `ticket.current_context` and select `ticket.owner_fenced`
alongside their authenticated operation. The AWS adapter applies both before and
during credentials/request/body work. A retained fenced ticket starts no new
delete; a request already accepted remotely remains uncertain. This local fence
does not establish distributed fencing or recall a remote side effect.

After confirmed ACK, complete M2 prefix, elapsed pinned local retention and fresh
reclamation authority, local receipt retirement preserves the exact independent
witness controls. This includes explicitly authorized quarantined receipts with
zero prepared events. Retirement reclaims only the local slot: no archive client
or original-delete authority is present, and independent archive retention is
not shortened. Saved control syntax still requires independently authenticated
history during recovery; it supplies no fresh custody token.

## Selected local protected archive and proof-history backend

The next EVIDENCE slice uses a separate private, single-owner SQLite backend.
It does not share the notification/disposition worker, credentials or privileges.
Its explicit initialize/open contract forbids implicit reset, migration or
adoption of an unrelated database. A private 0700 root, regular 0600 files,
stable inode checks and an OS owner lock protect local operation; only the
physical worker releases ownership after I/O finishes. SQLite uses checked
EXTRA synchronous/DELETE journal mode, foreign keys, no mmap, bounded cache,
finite page/VM/time budgets and immutable rows. This is local process recovery,
not AWS account/AZ-loss or shared-control qualification.

The backend retains complete framed receipt bytes, exact immutable manifest and
native digest/log proof inputs, with version identities and original publication
time. `StoredReceipt::from_framed_bytes` reuses the frozen validator without disk
publication or mutable progress. Inspection checks bounded syntax, hashes and
content pins; it authenticates no producer and grants no source proof/custody.
The archive must independently compare the full trusted binding and validate
native proof inputs before accepting a source-validated assertion. Witness
signing follows actual committed/read-back bytes, not a supplied success field.

Default local budgets target 128 retained receipts and 512 MiB database capacity,
with one operation permit and one bounded command slot. A receipt is at most
32 MiB, a native proof bundle obeys the existing 64 MiB aggregate proof budget,
and total input/retained copies have an explicit finite operation memory budget (default 256 MiB, four frame allocations plus 64 MiB bounded decoder/query workspace; smaller budgets reduce admitted receipt size).
A command reply retains its operation lease until consumed/dropped; separately retained caller results require caller aggregate budgeting. A full store rejects
new protected work and counts the rejection. This first backend exposes no
original-delete or retention-shortening operation; later retention work remains
its existing ledger item. These laboratory budgets are not fleet throughput claims.

Native proof continuity is retained independently of observability admission.
An immutable proof-history entry binds source scope/configuration revision,
validated checkpoint/classification, original versions, predecessor and interval.
The atomic head advances only from exact current CAS and supported validated
delivery; missing/tampered/unanchored/backfill/gapped evidence never fabricates
continuous coverage or silently heals an earlier gap. Bootstrap remains explicit.
Reopen validates retained history and requires independently current reconciliation
where continuity cannot be established; copied consistent bits alone cannot
prove absence of rollback. Configuration/category coverage remains separate.

The local HTTP stand-in uses separately configured producer, verifier and owner
roles with scoped synthetic credentials. It enforces permission/version/retention
checks and bounded actual bodies, concurrency, deadlines and pagination. Archive
signing keys stay with the archive role. The collector keeps its trusted witness
key/purpose/time and obtains fresh verification/current history for ACK. Tests
exercise denial, exhausted capacity, crashes/lost replies, redelivery and archive/
observability outages through actual role paths. The stand-in and caller must
retain enough exact inputs to revalidate native proof and restore pending
normalized delivery without rewriting preparation or renewing custody age.

## Locally accepted archive mechanism and remaining route

The separate private `evidence::ArchiveStore` now implements explicit init/open,
one physical worker, immutable complete-receipt publication/readback and actual
SIGCUS01 signing after verified retained bytes. Exact schema checks precede
metadata/receipt queries; unexpected triggers, views, additional/altered tables
are denied, since `trusted_schema=OFF` alone cannot prevent a built-in allocation
in a trigger. Owner, full binding and actual key/revision are pinned. One command
slot and operation permit hold allocation/physical ownership until bounded reply
consumption; interruption cannot refund active work or release the disk lock.

The native tables are still deliberately empty. Reopen rejects nonzero proof
head or retained native rows under zero metadata. Native inputs/checkpoints,
authenticated current-head/CAS/reconciliation and conservative coverage need the
next implementation slice; role HTTP, protected outage and archive crash/replay
composition remain unfinished. Signed archive custody alone claims none of these.
See the current progress/release evidence for local gate counts and limitations.

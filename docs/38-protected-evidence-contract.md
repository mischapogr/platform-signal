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

# Restricted independent audit

This is the contract for frozen SECURITY-AUDIT. Status: in_progress. A record
protocol is preparation for operative collection; it does not qualify an audit
sink, audit completeness, independent health or encrypted storage.

## Boundaries and records

Keep the monolith and use a bounded external destination seam. Actual routing,
identity, credentials, keys and account policy remain in the private overlay.
Audit destinations must be separately restricted from ordinary query/storage
credentials; an observability outage must not erase independently accepted audit
records or silence that destination's external health. Audit events are control
records, not ordinary input events or proof that a monitored source was complete.

A version 1 audit record has non-nil record/producer UUIDs, positive per-producer
sequence, UTC time, typed actor and action. Actions distinguish an access decision
from operation completion and configuration/rules activation. Granted access
means an authorization decision, never that the operation's effect committed;
uncertain completion remains explicitly uncertain. A request's operation UUID
correlates decisions/completion. Configuration activation carries only a revision
hash, never document contents. No arbitrary attributes, token, request/response
body, header, path, secret, raw event or free-text diagnostic is allowed.

Verified actors use a domain-separated SHA-256 reference computed only by the
host-verified live RequestGrant, including framed issuer/subject bytes. The
reference is pseudonymous audit metadata; it grants no authority and does not
prove identity independently of the host verifier. Bootstrap, anonymous, unattributed and system actors are distinct. Expired grants cannot supply a verified actor.
Never hash an unverified forwarded subject or bearer credential into an actor.
References and record IDs are not written to ordinary diagnostics.

Strict JSON decoding checks a 4 KiB document cap before deserialization, schema 1,
unknown/duplicate/type/null/enum fields, semantic time/UUID/sequence and fixed
lowercase SHA-256 references. Serialization validates before a bounded writer;
caller-constructed structs cannot bypass those checks. A source-provided record
is not authority; only host-created records are emitted by native hooks.

## Acknowledgement and uncertainty

A configured destination's version 1 acknowledgement must bind exact record UUID,
producer UUID, sequence and SHA-256 of original transmitted bytes. ACK documents
cap at 1 KiB and reject unknown/duplicate/malformed fields. A semantic ACK is a
claim by that configured destination; it cannot by itself prove fsync, encryption,
Object Lock, source completeness or durable effects elsewhere. Local destination
fixtures must actually persist/sync before acknowledging and exercise lost replies,
exact replay, wrong/stale replies, saturation, failure and recovery.

An audit record's accepted decision never authorizes a request or advances WAL/
source receipts. An uncertain reply never becomes a confirmed audit append.
Host-selected policy decides whether admission must wait for independently durable
intent/decision recording; unavailable audit cannot silently switch to ordinary
query storage. Operation-completion uncertainty cannot roll back existing effects.
Native hooks must retain those distinctions and bounded original request clocks.

## Remaining executable scope

1. Qualify protocol and live-grant subject reference.
2. Wire independent bounded destination and actual access/config/rule activation
   hooks. Prove destination health/records survive observability shutdown, and
   audit outages produce explicit health and selected fail-closed behavior.
3. Qualify explicit secrets/encrypted-storage integration settings, rotation and
   restore checks with local providers. Use established encryption/workload
   identity; do not invent a cipher/KMS or equate a setting with actual encrypted
   disks/objects/backups. Actual AWS KMS/Secrets Manager/volume configuration and
   production least-privilege/restore remain real-environment checks.

Unavailable admin/rule mutation/raw-evidence HTTP routes remain absent. Audit
existing runtime activation and operative access paths; do not claim nonexistent
operations were implemented merely by giving them an action enum.

The pinned Serde's internally tagged unit variant accepted an unexpected actor
field in a reproduced negative test. Empty struct variants now enforce rejection,
with retained red/green evidence for every payload-free actor kind. The wire shape
stays `{ "kind": "..." }`; there is no flatten or permissive content map. Current
[Serde attributes](https://serde.rs/container-attrs.html) and
[enum representations](https://serde.rs/enum-representations.html) were checked via
official documentation after Context7 quota exhaustion. These sources explain
the representation; the exact strict behavior is proven by the pinned-code tests.

## Protocol slice acceptance

Six audit regressions plus existing protocol tests pass. Strict 739 default/790
all-feature workspace tests, both Clippy, fmt/workspace 13 and independent review
pass. Exact complete array and large spare-capacity regressions failed before
correction and pass afterward. The tagged-unit unexpected-field failure is also
retained. This accepts only the bounded protocol and live-grant subject reference;
no destination/native hook, independent failure health or encrypted storage is
qualified. Parent remains in_progress. See
`target/goal-execution-20261007/SECURITY-AUDIT/protocol-acceptance.json`.

## Destination client acceptance

The AuditSink trait supplies an original monotonic deadline and static Busy/
Uncertain outcomes. HttpAuditSink production construction requires private mTLS
and a dedicated audit bearer credential. Its separately named simulation
constructor permits numeric loopback HTTP only. One physically retained worker
owns HTTP/runtime teardown; rejected callers do not clone operation inputs. Shared
DNS independently retains a pending kernel lookup after cancellation. No audit
queue or implicit application retries are added. Original bytes, IDs, sequence and
digest are preserved; status 200 alone never confirms an append.

Four new regressions, 20 compound HTTP/mTLS cases, strict 743/794 workspace checks,
both Clippy/fmt/workspace 13 and focused review pass. Shared test TLS fixtures are
reused by receipt tests. Durable receiver, native collection, independent health
and encryption remain unqualified. See `destination-acceptance.json` under the
SECURITY-AUDIT evidence directory. Continue durable outbox/native hooks/receiver.

Current reqwest retry/TLS policy and Tokio runtime teardown documentation were
checked at official docs.rs after Context7 reported quota exhaustion:
[reqwest ClientBuilder](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html),
[Tokio Runtime](https://docs.rs/tokio/1.53.2/tokio/runtime/struct.Runtime.html).
Pinned source and runtime regressions bind the selected behavior.

## Durable control outbox acceptance

The Linux outbox retains one immutable pending record, a persistent producer UUID
and an exact-ACK sequence/hash checkpoint. A separately selected current-user
0700 root holds only fixed-name 0600 regular files. Safe descriptor-relative
operations use the owned directory descriptor through `/proc/self/fd`; missing
proc access, foreign owners, symlinks, external hard links, unknown inventory,
oversize documents and inconsistent history fail closed. No new service or
dependency is required. This is ordinary crash recovery, not proof that a copied
older root is independently current history.

Pending bytes and the directory are synced before possible delivery. A complete
semantic ACK must match the original record, producer, sequence and body digest;
its checkpoint is synced before reclaiming pending bytes. Lost replies replay the
same bytes and identity. Recovered aliases are changed only after the complete
bounded history graph validates. Live temporary controls prohibit disclosure or
checkpoint advancement, including controls appearing while a reply is in flight.
An old record's confirmed replay does not authorize a different operation.

One physically retained disk worker has no queue and preserves ownership/locking
after caller cancellation or timeout. Original request deadlines never renew;
uncertain started mutations hold the open instance until validated reopen. Queue
capacity, physical rejection and uncertainty are exposed separately. Actor/revision
strings are compacted before entering the physical worker. Native hooks must still
apply host-selected admission policy and correlate decisions with actual effects.

Nine meaningful regressions pass, including eleven actual subprocess crash
boundaries across identity publication, pending publication, checkpoint and
reclamation. Strict 752 default/803 all-feature workspace tests, both Clippy,
fmt/workspace13 and focused review pass. Review failures for premature alias
cleanup, retained spare capacity and live temporary controls remain recorded.
The inherited configuration timing fixture now explicitly synchronizes worker
start/release/completion before its original-deadline denial; production behavior
is unchanged. An isolated pre-correction pass does not establish the prior failure's
cause. Failed/interrupted campaigns and a mistaken zero-test filter are retained
and excluded from acceptance.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/outbox-acceptance.json`,
`outbox-validation-final/validation.json`, `outbox-review.json` and crash/review logs.
This accepts the outbox mechanism only. Operative native hooks, an independently
restricted durable receiver and outage health, and secrets/encrypted-storage
integration remain unfinished. SECURITY-AUDIT stays in_progress.

## Native query hook acceptance

Optional `audit.config` YAML / `SIGNAL_AUDIT_CONFIG` selects a strict version1
JSON profile with `operations: ["query_events"]`, an HTTPS `endpoint`, absolute
`tls_config` and existing private `outbox_directory`, and bounded
`connect_timeout_ms`. `SIGNAL_AUDIT_TOKEN` is a dedicated environment credential;
the ordinary API token cannot substitute for a missing audit credential. Private
TLS material uses the established transport envelope. Startup validates the
profile/client and reconciles exact pending bytes before enabling this scope.
No public/default deployment values or private identifiers are added.

The existing query handler authenticates once. Only a live host-verified grant
can supply a verified subject reference; bootstrap, anonymous and failed/unverified
authentication remain distinct. A single bounded session confirms its newly
staged access decision before executing the query and its matching completion
before disclosing a response. Both records share an operation UUID and original
request deadline/cancellation. Completion describes query execution/prepared
response status, not proof the client received bytes. Later deadline/grant checks
still deny disclosure. All query errors carry `Cache-Control: no-store`.

Dropped/incomplete sessions and uncertain appends hold selected audit readiness;
capacity/depth, rejection, incomplete, pending and physical/destination metrics
contain no identity or payload labels. No detached completion is invented.
Uncertainty cannot authorize a fresh request. Stopped restart may replay the exact
pending record, but a new request must stage a new operation and confirm its exact
record ID. Restart is not proof of independently current restored history.

Six focused regressions and strict758 default/809 all-feature workspace tests,
both Clippy/fmt/workspace13 and source review pass. A separate actual AMD64
monolith/mTLS peer campaign passes27 finite checks: persisted query disclosure,
denial auditing, lost decision/completion replies with withheld results/readiness
failure, exact restart replay, wrong-ACK denial and receiver survival through
monolith shutdown. Fourteen fsynced fixture receipts and nine canary-free ordinary
logs are retained. The no-store review regression failed before fixing; test-only
helper lint errors, sandbox denial and three fixture preparation failures remain
recorded. No production source/binary drift or cleanup failure occurred.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/query-hooks-acceptance.json`,
`query-hooks-validation-corrected/validation.json`, `query-hooks-review.json` and
`query-hooks-native-independent/report.json`. The native campaign uses bootstrap
identity and a synthetic receiver; enabled IdP auditing and production receiver
durability/encryption remain separate. Other access paths, configuration/rules
activation, independent production health and secrets/encryption seams are still
unfinished. The profile deliberately rejects unimplemented operation scopes;
parent SECURITY-AUDIT remains in_progress.

## Selected findings hook acceptance

The optional profile now accepts a nonempty unique subset of `query_events`,
`read_findings` and `read_findings_feed` only. Every selected path shares the same
one-session/outbox capacity and exact decision/completion contract. The findings
router preserves scoped list authorization, global-only immutable feed access,
strict cursor handling, original request clocks and final grant checks. A durable
completion describes prepared operation results, never proof of client delivery.
Only explicit unselected paths skip control recording; startup rejects unsupported,
empty and duplicate selections. Ingest/coverage/config/rule hooks are still absent.

Five new regressions and settled strict763/814 tests, both Clippy/fmt/workspace13,
source reviews and59 actual AMD64/mTLS/fsynced-peer checks pass. Lost ACKs for
both endpoints withhold finding/cursor disclosure, hold all selected paths and
readiness, and replay original bytes after stopped restart without reusing operation
identity. Thirty-five receipts and11 ordinary logs retain privacy checks. Two
inherited fixture synchronization corrections preserve production behavior and
retain failed campaigns; the idle failure cause remains unestablished. This is
bootstrap/synthetic finite proof; enabled native IdP/audit composition and the
production receiver/health/encryption remain unqualified. Parent stays in_progress.
See `target/goal-execution-20261007/SECURITY-AUDIT/findings-hooks-acceptance.json`.

## Selected coverage hook acceptance

The optional selected-operation profile now accepts `read_coverage` and
`write_coverage` alongside query/findings/feed, with one shared bounded session and
outbox. Coverage authorizes once and confirms a durable decision before journal
access, then matching completion before disclosing originals/history/aggregate or
receipts. Existing paired scope/writer authority, original request clocks and final
grant checks remain. A new coverage commit returns201; exact replay returns200.
Completion uncertainty can withhold a receipt for an already committed record;
an exact retry recovers it. A late authority denial preserves that503 uncertainty.
Every response is no-store; control records contain no coverage body/binding/IDs.

Five additional regressions, strict768/819 workspace tests, both Clippy,
fmt/workspace13, source review and 93 actual AMD64/mTLS process
checks pass. 54 fsynced receipts and 9 ordinary logs retain privacy proof.
The process campaign covers original bytes/receipts, separate write decision and
completion loss, read withholding, shared selected-route/readiness failure, exact
stopped replay/fresh operation identity and bounded fixed-frontier pagination.
Failed fixture campaigns and the uncertain-write red regression remain retained.
No source/binary drift or cleanup failure. This is finite bootstrap/synthetic proof;
IdP composition, production receiver/health/encryption and other hooks remain open.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/coverage-hooks-acceptance.json`,
`coverage-hooks-validation/validation.json`, `coverage-hooks-review.json` and
`coverage-hooks-native-independent/report.json`. Parent SECURITY-AUDIT stays
in_progress; the frozen52 item inventory and status counts do not change.

## Selected ingest hook acceptance

The optional generic ingest seam now confirms a new decision before reading the
body or admitting WAL records, then matching completion before any prefix/ID
receipt disclosure. The monolith selects `ingest_events` alongside five existing
access operations and shares one bounded Control/outbox. Authentication runs once;
a live actor is captured while whole-batch canonical scope preflight remains before
first admission. Granted decision means request-processing capability, not approval
of an unexamined event. Original request clock/cancellation and live-grant checks
remain effective through the final reply. Every handled response is no-store.

Lost completion or late disclosure authority withholds all prefix/IDs through a
verifier-valid503 unknown-total retry response. Actual partial/full WAL effects and
admission counters remain truthful; retry may duplicate immutable IDs. Uncertainty
cannot become a permanent403 or an invalid full-prefix503. Dropped completions
count incomplete/failed requests without inventing rollback or detached completion.

Ten additional regressions, strict 778/829 tests, both Clippy/fmt/workspace13,
source review and 50 actual AMD64/mTLS process checks pass. The
native campaign retains 28 fsynced receipts and 6 clean ordinary logs, confirming
full/partial WAL effects, lost decision/completion, exact restart replay/fresh IDs
and shared selected-route/readiness failure. Actual queued-success late handoff and
native HTTPS grant expiry have separate source fixtures. Failed fixture campaigns
remain retained; no source/binary drift or cleanup errors. Native IdP plus actual
monolith auditing, production receiver/independent health/encryption and runtime/
rule activation remain unfinished. Parent SECURITY-AUDIT stays in_progress.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/ingest-hooks-acceptance.json`,
`ingest-hooks-validation/validation.json`, `ingest-hooks-review.json` and
`ingest-hooks-native-independent/report.json`. The frozen52 inventory/status counts
are unchanged; this is a bounded substep, not whole-item or release qualification.

## Retained rule revision acceptance

`RuleSet::write_revision` streams a domain-framed version1 commitment input from
immutable retained validated definitions. Unique rule IDs and nested object keys
have deterministic order; metadata, output/severity, group presence, operators,
nulls, typed values and array order are included. No file/environment reread,
whole projection allocation, rule-tree clone or dependency is added. A caller
supplies a nonblocking in-memory sink, an original RuleContext and a finite byte
cap (hard64MiB). Deadline/cancellation is checked before and after sink handoff;
partial output must be discarded after failure. Projection contents are private
hash input and must stay out of ordinary logs; this is not a public rule format.

Eight meaningful regressions, strict 786/837 workspace tests, both Clippy/fmt/
workspace13 and independent review pass. Actual loaded definitions keep their
projection and evaluation after source rewrite/deletion. Deep escaped-value
counting-sink, exact cap, partial/error writer and late/cancelled handoff cases pass.
The restricted campaign's seven existing TCP/subprocess permission failures and
initial fixture/compile corrections remain retained. Static successes are reused
only with matching hashes; runtime permission-enabled acceptance is separate.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/rules-revision-acceptance.json`,
`rules-revision-validation/validation.json`,
`rules-revision-validation-runtime/validation.json`, `rules-revision-review.json`.
This accepts only the revision primitive. Actual runtime/rules activation records,
original startup clocks/fresh confirmation, IdP/audit composition, receiver/health/
secrets-encryption remain. Parent SECURITY-AUDIT and frozen52 counts do not change.

## Native startup activation acceptance

Explicit optional unique `configuration_activations: [runtime, rules]` selects
fresh System records independently of API operations. Operations-only profiles
retain their behavior; activation-only profiles are supported. The installed
runtime resource revision commits named typed limits/mode bits from actual
prepared immutable values. It excludes credential values, paths, private TLS,
IdP/coverage policy, backend-specific object settings and logging; it is not a
commitment to the entire configuration. Actual retained validated RuleSet feeds
the accepted bounded revision stream into a memory hash sink without file reread.
The existing pinned sha2 dependency moves from test-only to runtime; lock unchanged.

The original60s selected startup clock bounds inactive preparation, pending replay,
revision capture and both fresh exact confirmations. No old replay substitutes
for a fresh record. Shared Control capacity, incomplete/drop latch, final clock
checks and finite cleanup remain. Only after both selected confirmations may the
consumer spawn or API/metrics transport be polled. Activation records describe
installed state, not proof that serving began. Caller timeout/drop retains existing
physical worker ownership; it does not prove kernel/disk work ended at timeout.

Six additional compound regressions, strict 792/843 workspace tests, both Clippy,
fmt/workspace13 and independent source review pass. Actual default AMD64 monolith
and separate synthetic fsynced mTLS peer pass 88 checks with
40 receipts and 14 canary-free
ordinary logs. Normalized/changed rule digests, fresh activation-only and selected
query startups, lost/wrong ACK, pending exact replay/new identity, no failed-start
consumer effects and bounded SIGTERM are covered with clean cleanup/source/binary
guards. The first fixture's held single-threaded peer prevented its own health
request; retained failure and hold-release ordering correction are distinct from
production acceptance. Compile/lint corrections and review's original-clock
finding are retained; final required checks have no failures.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/activation-hooks-acceptance.json`,
`activation-hooks-validation-final/validation.json`, `activation-hooks-review.json`,
`activation-hooks-native-independent/report.json`, `activation-hooks-stable-build/build.json`.
This accepts a bounded substep, not all SECURITY-AUDIT. Production receiver,
independent health/permission isolation, native IdP+audit composition, secrets and
encrypted storage remain. Frozen52 item statuses/counts do not change. Current
remote-image/native/cluster/candidate/cloud gates remain separate.

## Independent receipt journal acceptance

SDK `audit::receiver::AuditReceiver` is a generic Linux mechanism separate from
ordinary WAL/query storage. Trusted host setup explicitly initializes an empty
current-user0700 root or opens existing history; absent/corrupt history is never
implicitly reset. Configured authenticated namespace membership is finite and
checked before physical admission/input copy. `TrustedProducer` construction is
a host responsibility and authenticates no request or source field by itself.
First sequence1, exact next head, globally unique record UUIDs and byte-exact old
retries are enforced across interleaved producers. Original order/whitespace/time
remain unchanged; exact ACK follows synced journal and verified original readback.

Record/producers/index/bytes have finite validated caps and precharged indexes;
full rejects without overwrite/eviction. One retained physical disk worker/root
lock owns input and syscall through caller loss. Aggregate health reads atomics
without the disk mutex and exposes no identities; it is not independent external
health. Descriptor identity/mode/link/type and fixed store control are checked.
A version1 private frame binds store identity and original body in SHA256, with
an independent header checksum over identity/magic/length/body digest checked
before tail arithmetic or truncation. Only a complete validated header followed
by an incomplete final body can be truncated after preceding history validates;
partial/altered headers and corrupt complete frames remain evidence.

Independent review found two real defects despite pre-review 801/852 strict
success: final length growth could erase an ACKed complete frame, and caller loss
between the final context check and mutation arming could leave unheld effects.
Both actual regressions failed before correction. Header validation now precedes
recovery, and arming precedes the final original-clock check: drop-before-arm
prevents writes; drop-after-arm conservatively holds until exclusive reopen.
Eleven compound regressions, five actual process crash stages, both physical-drop
cases, final strict 803/854, both Clippy/fmt/workspace13 and renewed review pass.
Exact replay after complete/lost reply effects does not duplicate history.

Evidence: `target/goal-execution-20261007/SECURITY-AUDIT/receiver-store-acceptance.json`,
`receiver-store-validation-corrected/validation.json`, `receiver-store-review.json`,
`receiver-store-length-red/receiver-length-red.json`,
`receiver-store-arm-red/receiver-arm-red.json`. Earlier reports remain superseded.
This does not qualify a receiver HTTP host/TLS/authentication/probe, separate UID
or account permissions, encryption, independently current restore, source
completeness, power-loss durability, native/full CI or cloud/release operation.
SECURITY-AUDIT remains in_progress; frozen52 counts unchanged. Next: actual
independent receiver role and separately credentialed bounded health owner.

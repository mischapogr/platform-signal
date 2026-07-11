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

A version1 audit record has non-nil record/producer UUIDs, positive per-producer
sequence, UTC time, typed actor and action. Actions distinguish an access decision
from operation completion and configuration/rules activation. Granted access
means an authorization decision, never that the operation's effect committed;
uncertain completion remains explicitly uncertain. A request's operation UUID
correlates decisions/completion. Configuration activation carries only a revision
hash, never document contents. No arbitrary attributes, token, request/response
body, header, path, secret, raw event or free-text diagnostic is allowed.

Verified actors use a domain-separated SHA256 reference computed only by the
host-verified live RequestGrant, including framed issuer/subject bytes. The
reference is pseudonymous audit metadata; it grants no authority and does not
prove identity independently of the host verifier. Bootstrap, anonymous, unattributed and system actors are distinct. Expired grants cannot supply a verified actor.
Never hash an unverified forwarded subject or bearer credential into an actor.
References and record IDs are not written to ordinary diagnostics.

Strict JSON decoding checks a4KiB document cap before deserialization, schema1,
unknown/duplicate/type/null/enum fields, semantic time/UUID/sequence and fixed
lowercase SHA256 references. Serialization validates before a bounded writer;
caller-constructed structs cannot bypass those checks. A source-provided record
is not authority; only host-created records are emitted by native hooks.

## Acknowledgement and uncertainty

A configured destination's version1 acknowledgement must bind exact record UUID,
producer UUID, sequence and SHA256 of original transmitted bytes. ACK documents
cap at1KiB and reject unknown/duplicate/malformed fields. A semantic ACK is a
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

Six audit regressions plus existing protocol tests pass. Strict739default/790
all-feature workspace tests, both Clippy, fmt/workspace13 and independent review
pass. Exact complete array and large spare-capacity regressions failed before
correction and pass afterward. The tagged-unit unexpected-field failure is also
retained. This accepts only the bounded protocol and live-grant subject reference;
no destination/native hook, independent failure health or encrypted storage is
qualified. Parent remains in_progress. See
`target/goal-execution-20261007/SECURITY-AUDIT/protocol-acceptance.json`.

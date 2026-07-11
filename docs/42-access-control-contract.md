# Explicit identity and scoped access

This contract implements the frozen SECURITY-ACCESS item from the
[execution ledger](31-execution-ledger.md) and the trust requirements in
[product architecture](27-product-architecture.md#7-security-and-useful-defaults).
Accepted slices provide bounded paired grants, an introspection response profile
and fixed-provider native HTTPS token authentication. Mandatory trusted-host query filtering and generic producer admission are accepted.
The composed server supports explicit native identity for durable admission and
persisted event queries. Bootstrap token mode remains available only when identity
is absent. Trusted compatible finding scopes and restricted reads are implemented below.
SECURITY-ACCESS stays in progress until coverage binding, remaining capability
handling and established local IdP gates pass.

## Policy and trust boundary

The operator supplies a version1 JSON policy. Real issuer/subject bindings,
roles and environment selectors belong in private configuration. The public
repository supplies mechanisms and synthetic test identities only.

```json
{
  "schema_version": 1,
  "roles": [{
    "id": "read-synthetic-account",
    "permissions": [{
      "operation": "query_events",
      "scope": {
        "sources": {"mode": "all"},
        "accounts": {"mode": "only", "values": ["synthetic-account"]},
        "resources": {"mode": "all"}
      }
    }]
  }],
  "bindings": [{
    "issuer": "https://identity.example.test",
    "subject": "synthetic-reader",
    "roles": ["read-synthetic-account"]
  }]
}
```

All scope dimensions are required. `all` is an explicit operator choice;
`only` uses exact case-sensitive equality, including a literal `*` value.
There is no wildcard, prefix, regex or implicit administrator role. A permission
conjoins source, account and resource selectors. Permissions from assigned roles
are disjoined as complete operation/scope pairs; their operations and selectors
must never be unioned independently. A missing fact fails a restricted selector.
Empty roles/bindings represent deny-all; unknown bindings and capabilities deny.

The schema rejects missing fields, unknown fields and duplicate JSON struct
fields. Compilation rejects duplicate role IDs, subject bindings, assigned roles,
operations in a role and selector values; unknown role references, empty permission
lists and empty `only` lists fail validation. Multiple scopes for an operation can
be represented by separate assigned roles within the finite role bound.

| Bound | Maximum |
| --- | ---: |
| Input and encoded policy | 256 KiB |
| Roles / bindings | 64 / 1,024 |
| Roles assigned to one subject / permissions in one role | 8 / 16 |
| Exact values in one selector | 64 |
| Role ID / selector or subject / issuer bytes | 128 / 256 / 2,048 |

Identifiers must be nonempty, have no control characters or surrounding
whitespace, and meet byte limits. Errors contain static category text only;
policy and identity types provide no automatic Debug or identity serialization.
Both JSON-loaded and programmatically constructed policies must compile before
granting authority. Nonallocating nested length/count preflight precedes serialization
and lookup allocation. Compaction discards input spare capacity from all retained
role/permission/selector vectors and identity strings. Compiled policies are
immutable shared snapshots.

## Authenticated identity and request grants

An identity backend must verify its transport/provider and the credential,
including active status, exact issuer and audience, subject and expiry, before
calling `AuthenticatedIdentity::from_verified_backend`. That constructor is a
host trust boundary; it validates bounded structure and time, not authenticity.
It cannot deserialize an HTTP header or token into verified identity. Never
construct it from forwarded user/role headers or producer claims. Policy lookup
uses the exact verified issuer and subject. Provider group/role claims do not
implicitly assign policy roles.

A grant has an explicit verified-at time, expiry and request issue time. Grant
creation rejects future verification and expired identity. Permission use denies
times before issuance and at/after expiry. Identity expiry is finite and strictly
after verification. A grant is not a token, persisted proof or revocation cache.
The trusted host supplies current time and checks permission at each relevant
use; this pure module does not observe a clock or obtain revocation information.
Replacing policy does not mutate a grant's retained snapshot. Backend integration
must bound requests and define revocation/configuration-change behavior.

`ScopeFacts::event` extracts source type and canonical resource account/ID only.
Arbitrary attributes, tags and user headers never supply authorization identity.
Canonical event identity is still producer-supplied data: a source credential
must be bound to allowed source/resource domains and all admission checked before
that data becomes trusted stored context. Matching a supplied account does not
prove AWS ownership. Missing or historically unverified context cannot be repaired
by reading a convenient attribute.

`RequestGrant::scopes` exposes only complete permissions for the requested
operation. The trusted-host query integration imposes mandatory predicates before
sorting, limits and serialization, and fails closed if the grant expires. It must
never turn an empty/expired selector set into an unfiltered query. Query URL
parameters remain optional user filters, not authorization controls.

## Capabilities and route integration still required

Operations are `ingest_events`, `query_events`, `read_findings`,
`read_findings_feed`, `read_evidence`, `read_coverage`, `write_coverage`,
`configure`, `manage_rules` and `read_audit`. These are distinct capabilities;
granting one never implies another. This enum does not create new HTTP routes.

The findings journal feed and global configuration/rule/audit controls
have no scoped row contract. Their permissions require all dimensions to be
explicit `all`; compilation rejects restricted scopes for those operations.
Do not post-filter an unscoped cursor feed and claim scoped isolation. Finding scope metadata/history is implemented below; original-evidence reads
still require their separate trusted contract. An unavailable route or missing
scope must not obtain authority from another operation.

The selected backend direction is established OAuth2 access-token
introspection against a fixed authenticated provider endpoint, with OIDC sign-in
handled by an existing trusted IdP/ingress. The implemented pure profile requires active status, issuer, audience,
subject, expiry and Bearer token type; access tokens are not
OIDC ID tokens. Provider timeouts, bounded bodies/concurrency, revocation, denial,
malformed replies pass finite native local fixtures; server cross-scope route
behavior still needs implementation and local HTTP simulations. The standard endpoint contract is
[RFC7662](https://datatracker.ietf.org/doc/html/rfc7662); sign-in semantics follow
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
Live IdP/TLS/rotation and cloud authority remain separate external evidence.

Trust boundaries remain logical modules inside the existing monolith. No identity
server, new mandatory broker/database, shared multi-tenant isolation claim or
microservice split follows from this contract.

## Grant-slice local acceptance

Nine focused regressions and strict default668/all-feature719 workspace gates,
formatting, both Clippy configurations, all-feature build, workspace13 and focused
independent review pass. The final source-bound report is
`target/goal-execution-20261007/SECURITY-ACCESS/grant-validation-preflight-final/validation.json`.
Review resolved retained programmatic spare capacity and serialization before
nested length validation. This qualifies the pure grant model only; all backend,
HTTP isolation/revocation and real-environment requirements above remain open.

## Selected introspection response profile

`access::introspection::IntrospectionProfile` operates only on a successful
response obtained from an authenticated fixed provider. It proves neither that
transport trust nor token authenticity. The provider must validate an access
token; client-supplied identity JSON, OIDC ID-token payloads and forwarded user
headers must never reach this constructor as authenticated provider responses.

The response must be a JSON object no larger than16KiB. Recognized duplicate
fields and malformed types fail; unknown RFC extension fields are ignored, never
retained as permissions. The SIGNAL profile deliberately requires claims that
RFC7662 permits providers to omit: exact configured issuer, exact audience (a
string or at most16 unique bounded strings), nonempty subject<=256bytes,
nonexpired integer expiry and a case-insensitive Bearer token type. Provider
roles, groups, username and scope strings do not assign SIGNAL capabilities.
An inactive token denies. Optional nbf/iat must not be future or at/after expiry;
there is no clock-skew leeway. The trusted host supplies current Unix seconds.

Operator profile issuer/audience bounds are2,048/256bytes. An explicit1–300second
lease is clamped to token expiry; it bounds use of the returned identity but does
not establish revocation. The parser has no network client or token cache.
Errors expose static categories only. Private policy loading also rejects
positional top-level arrays before typed parsing.

Six profile fixtures plus the nine grant regressions pass with strict
674default/725all-feature, formatting, both Clippy configurations, all-feature
build, workspace13 and focused review. Evidence is source-bound in
`target/goal-execution-20261007/SECURITY-ACCESS/introspection-validation-final/validation.json`.
The array-shape review correction and integer-width fixture compile failure are
retained. Native authenticated HTTPS and real server scope enforcement remain
next; this acceptance closes no live IdP, cloud, ARM64, remote CI or release gate.

## Native authenticated provider mechanism

`signal-ingest::identity::IdentityBackend` requires one fixed operator endpoint,
client ID/secret, response profile and immutable compiled private policy. The
endpoint is HTTPS only (2,048 bytes), with no userinfo, query or fragment; caller
input never selects its origin. Client ID/secret each cap at1,024 bytes. Only
`client_secret_basic` is supported; each credential is form-encoded before the
colon/Base64 header. The header is sensitive and errors contain static categories.
Additional DER roots cap at8,16KiB each and64KiB total, alongside public WebPKI
roots. Established rustls verifies trust, expiry and DNS/IP server name. No
insecure verifier, redirects, proxy discovery, retry, connection pool or detached
HTTP driver exists. Direct Hyper HTTP/1 work is driven within the physical request.

Every request introspects fresh. Opaque credentials cap at4,096 graphic ASCII
bytes; request form body caps at16KiB. Only an authenticated200 response with
JSON content type, absent/identity encoding and bounded unique integrity headers
reaches parsing. HTTP headers cap at32/16KiB; decoded response body caps16KiB.
Trailers, oversized declared/chunked bodies and malformed responses fail closed.
Operator request duration is positive and at most30 seconds and clamps caller
deadlines. Cancellation is checked before and after physical phases; dropped
callers cancel their request. There is no revocation cache; a returned request
lease still requires permission checks at use time.

A fixed1–16 physical worker pool and global admission semaphore bound queued,
running and unconsumed completion work together. Native DNS runs only on these
retained workers. A caller timeout cannot release its physical lease before an
OS lookup finishes. Stop closes admission/cancels requests; shutdown joins only
finished threads within its deadline. A stalled physical worker makes shutdown
fail with visible capacity/alive metrics; it is never silently replaced. Queue,
physical depth/capacity, workers alive, request/rejection/denial/failure counters
are available. Dropping the last backend closes its sender; explicit shutdown
is required to prove complete physical termination.

Ten finite local tests use real TLS with fresh synthetic certificate material,
including trust/name/expiry failures before credential transmission and fresh
active/inactive checks. A controlled blocking worker pause qualifies capacity
retention, not OS DNS latency. Provider fixture shutdown retains task ownership
through await, with abort-on-drop qualification. Strict684/735 and source review
are bound in `target/goal-execution-20261007/SECURITY-ACCESS/native-validation-corrected/validation.json`.
Server routes/configuration, sign-in and full local HTTP authorization remain
next. This proof closes no live provider, native ARM64, AWS or release gate.

## Mandatory trusted-host query execution

`QueryEngine::execute_authorized` takes a backend-authenticated `RequestGrant`.
No HTTP header or caller-selected selector list reaches this boundary as a grant.
Only QueryEvents permission scopes contribute: each complete scope conjoins
canonical `source_type`, `resource_account_id` and `resource_id`; complete scopes
are disjoined. Immutable policy bounds one operation to at most8 scopes with
64 exact literals per dimension. DataFusion predicates apply before user filters,
sorting and limits. Restricted missing facts (SQL NULL) deny; attribute data and
literal `*` values cannot supply wildcard or fallback authority.

A missing/expired query permission denies before file selection. Time/permission
checks repeat after selection, on decoded rows and before returning any response,
including empty storage. Final success checks the original monotonic context
before grant validity, preventing a ready inner result from defeating timeout
when caller polling resumes late. No partially authorized event response returns.
The legacy `execute` entry point remains only a trusted host API for deployments
without configured identity; authenticated server routes must use the new method.

Five real committed Parquet/DataFusion tests cover complete pair combinations,
filter-before-limit/order, optional filter intersection, literals/missing facts,
absence/expiry before selection, expiry while holding prepared files/empty data,
and a reproduced late-ready result. Strict689/740 and source review are bound in
`target/goal-execution-20261007/SECURITY-ACCESS/query-validation-final/validation.json`.
Source selection and scan-budget metadata remain aggregate storage diagnostics;
this is row authorization, not per-account physical file selection or cloud
ownership attestation. Server route integration and admission trust remain next.

## Native identity producer admission

The explicit `IngestService::new_with_identity` constructor installs the backend;
a simultaneous shared API token is configuration failure. Identity mode never
falls back to legacy `authorized`. `authenticate_headers` requires exactly one
Bearer authorization field; malformed or oversized opaque credentials deny and
forwarded user/role headers are irrelevant. Native authentication uses the
original request deadline and service cancellation before reading its body.

A grant must contain IngestEvents authority. Complete normalized batch scope
checks precede every sink admission; exact canonical source/account/resource
facts authorize and missing restricted facts deny without attribute fallback.
No mixed unauthorized batch prefix is admitted. Preflight uses one clock snapshot
for capability/scope checks after normalization. A lease ending during preflight
or between admissions reports RequestTimeout408. A committed prefix remains
truthful and retryable; a fresh request introspects again. Never report rollback
of an admitted event. Native/provider/per-request timeouts are counted.

Forbidden403 is a version1 permission-error category. The semantic validator
classifies it permanent only with zero accepted events; permanent committed
prefixes remain invalid. Body-unread denials use unknown zero totals rather than
inventing an event count. Error text is static. Closed identity authority fails
readiness. Metrics expose fixed physical/queue depth/capacity, workers, counters
and closed state without secret/subject labels.

Five generic producer-route regressions join ten native tests; actual TLS and
Axum exercise a bounded volatile MemorySink and prefix suspension, not the
composed durable server. Strict694/745 and review are bound in
`target/goal-execution-20261007/SECURITY-ACCESS/admission-validation-final/validation.json`.
Validated server access configuration, persisted HTTP admission/query checks and
remaining scope-aware routes/local IdP acceptance remain next.


## Composed private configuration and HTTP enforcement

Set `SIGNAL_ACCESS_CONFIG` or the strict settings mapping
`access: {config: /mounted/private-access.json}`. Resolve the provider client secret
only from `SIGNAL_IDENTITY_CLIENT_SECRET`; unset the conflicting `SIGNAL_API_TOKEN`
including empty values. The version1 private JSON document is a regular file
bounded to512KiB and read/parsed on the retained single physical configuration
worker within5seconds. Existing server/coverage settings retain64KiB limits.
Final completion checks the original deadline and cancellation even if the worker
reply was already ready when caller polling resumed.

A deny-all synthetic configuration illustrates the wire contract:

```json
{
  "schema_version": 1,
  "endpoint": "https://identity.example.test/token",
  "client_id": "synthetic-client",
  "issuer": "https://identity.example.test",
  "audience": "signal",
  "lease_seconds": 30,
  "workers": 2,
  "request_timeout_ms": 1000,
  "roots_der_base64": [],
  "policy": {"schema_version": 1, "roles": [], "bindings": []}
}
```

Unknown/duplicate fields, positional arrays, invalid profiles/policies and
capacity violations fail before readiness. The nested policy is retained as
bounded raw JSON so duplicate-field validation is not erased by a Value map.
Additional roots are standard Base64 DER: at most8 roots,16KiB per decoded root
and64KiB aggregate. Public WebPKI roots remain enabled. The native constructor
validates transport/secret/roots before opening the WAL; there is no insecure
TLS option. Configuration and provider identity stay fixed until validated restart.

Explicit identity mode never falls back to the bootstrap token. Authentication
precedes body/query parsing. Ingest uses whole-batch canonical scope preflight
before WAL admission; query uses `execute_authorized` before user limits. The
HTTP query deadline includes introspection and serialization, with final grant
checks and no-store responses. Normal shutdown closes authentication and joins
physical workers using the same deadline as transport/query/persistence cleanup.

At the initial composed-server slice, finding list/feed used distinct explicit
all-scope permissions. The trusted finding slice below enables restricted lists.
Coverage routes still fail closed in identity
mode until its configured binding bridge exists; legacy coverage tokens cannot
bypass native authentication. Unimplemented original-evidence/admin/rules/audit
HTTP routes remain404 even for a subject assigned those operation enums.
The UI shell remains public and data requests use the API's authorization.

Actual monolith/TLS/WAL/Parquet simulation proves zero admission for mixed scopes,
exact persisted query-before-limit rows, no forwarded-identity or operation bypass,
active/inactive/expired/audience denial, provider timeout and recovery, SIGKILL/
restart and policy-binding removal on validated restart. Four fixture regressions
qualify finite logs, owned child interruption, silent TLS and unstarted-provider
cleanup; the short-log drainer preserves existing byte caps. Strict697/748 and
corrected default/all-feature focused reruns, ten existing helpers and15 persistent
retirement scenarios pass with independent review. The composite
`target/goal-execution-20261007/SECURITY-ACCESS/server-acceptance.json` explicitly
records full-workspace reuse after a Python-only correction and retains the failed
optional helper invocation. This synthetic provider is not established OIDC
sign-in, live tenant, native ARM64, AWS/EKS, current image or release qualification.


## Trusted finding scope and preserved history

`DerivedFinding::from_event` is an explicit host boundary, not a credential verifier.
It requires the deterministic FindingV1 reconstructed from that canonical event;
ordinary attributes, tags, roles and caller-selected findings cannot supply scope.
The constructor retains the bounded reconstruction rather than caller spare
capacity. Canonical source type, resource account and resource ID are hashed in a
length/presence-delimited SHA256 binding. Each retained selector fact caps at 256
bytes; longer facts become unknown without truncation, while the full binding
digest still distinguishes divergent canonical identities on replay.

Native monolith startup captures the retained WAL last sequence before HTTP
admission, and activates the finding store before readiness. Only native identity
mode plus a sequence above that startup floor allows a NEW finding to carry scope.
A sequence by itself proves no identity. Retained unprocessed WAL remains unknown;
already persisted exact findings keep original bytes/provenance during replay.
The legacy bootstrap path does not create trusted scope. This finding mechanism
does not retroactively establish legacy event provenance or source completeness.

`scope.control` is an immutable 144-byte activation: magic, random UUID generation,
exact logical feed cursor, physical byte offset, SHA256 of the complete original
journal prefix, and control CRC. Recovery verifies stream/cursor/first-row boundary
and the physical frame boundary/digest, including old semantic duplicate frames.
Both current and complete pending controls sync journal/control/root before
adoption. Invalid, partial, foreign, missing-journal or ambiguous controls remain
held; recovery cannot truncate a tail first and hide invalid control evidence.
A complete validated pending publication may finish. Restricted facts require a
post-boundary row with this exact generation and valid bounded metadata.

New raw append cannot insert reserved `signal.scope.v1` metadata, even before
activation; existing exact legacy duplicate rows remain readable/replayable as
unknown. Historical rows are never rewritten or upgraded. Known same-ID finding
replay with a different canonical binding conflicts. Original indexed payload CRC,
feed cursor digest, contract and ID are verified for list/duplicate reads as well
as feed reads. Post-open substitution fails closed even if frame CRC is rewritten.
These checks bind retained bytes; they are not signed authentication/custody proofs.
Older software refuses the new root control entry; no permissive downgrade follows.

Activation charges 144 disk bytes and 256 conservative index bytes. Derived batch
rows/encoded previews use existing finite record/append bounds, and queued vector
spare capacity is discarded. Existing retained physical-worker/cancellation and
uncertain-mutation rules apply. Any recovery issue needs explicit reconciliation;
there is no reset endpoint or implicit history repair.

`GET /v1/findings` freshly authenticates native identity, checks ReadFindings before
input parsing/queue admission, then applies complete paired scopes to verified
canonical metadata before user filters and result limit. Unknown facts deny a
restricted selector; explicit all dimensions may read unknown history. Lease and
context checks repeat in the worker, after completion and after bounded response
serialization, including empty results. The original deadline includes provider
work; cancellation closes the response and all responses use no-store.

`GET /v1/findings/feed` remains a global immutable cursor feed, requiring the
separate ReadFindingsFeed capability with explicit all dimensions. It is never
post-filtered into a scoped feed. Native coverage stays closed pending its binding
bridge; unavailable evidence/admin/rules/audit routes remain absent. Scoped list
permission does not imply feed, event-query or producer permission.

Thirteen added regressions and strict 710/761 workspace acceptance pass with
independent review. The actual TLS/monolith gate seeds real synced unprocessed WAL
before native startup, verifies its newly generated finding stays unknown while
fresh authenticated findings filter before limit, and checks the complete global
feed remains exact across crash/restart. See
`target/goal-execution-20261007/SECURITY-ACCESS/finding-acceptance.json`.
Coverage identity/binding and established local IdP/OIDC acceptance remain next;
this closes no native ARM64, full remote CI, actual cloud/live tenant, image or
release gate.

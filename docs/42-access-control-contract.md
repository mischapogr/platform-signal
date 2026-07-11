# Explicit identity and scoped access

This contract implements the frozen SECURITY-ACCESS item from the
[execution ledger](31-execution-ledger.md) and the trust requirements in
[product architecture](27-product-architecture.md#7-security-and-useful-defaults).
The first accepted slice is a pure bounded grant model in `signal-protocol`.
It does **not** authenticate HTTP requests or replace the development server's
optional single bearer token. SECURITY-ACCESS remains in progress until a trusted
identity backend, route enforcement and local identity-provider simulations pass.

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
operation. A later query integration must impose mandatory predicates before
sorting, limits and serialization, and fail closed if the grant expires. It must
never turn an empty/expired selector set into an unfiltered query. Query URL
parameters remain optional user filters, not authorization controls.

## Capabilities and route integration still required

Operations are `ingest_events`, `query_events`, `read_findings`,
`read_findings_feed`, `read_evidence`, `read_coverage`, `write_coverage`,
`configure`, `manage_rules` and `read_audit`. These are distinct capabilities;
granting one never implies another. This enum does not create new HTTP routes.

The current findings journal feed and global configuration/rule/audit controls
have no scoped row contract. Their permissions require all dimensions to be
explicit `all`; compilation rejects restricted scopes for those operations.
Do not post-filter an unscoped cursor feed and claim scoped isolation. Findings
and original evidence need trustworthy scope metadata and compatible historical
handling before restricted reads can be enabled. An unavailable route or missing
scope must not obtain authority from another operation.

The selected next backend direction is established OAuth2 access-token
introspection against a fixed authenticated provider endpoint, with OIDC sign-in
handled by an existing trusted IdP/ingress. Active status, issuer, audience,
subject and expiry will be required by the SIGNAL profile; access tokens are not
OIDC ID tokens. Provider timeouts, bounded bodies/concurrency, revocation, denial,
malformed replies and cross-scope route behavior still need implementation and
local simulations. The standard endpoint contract is
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

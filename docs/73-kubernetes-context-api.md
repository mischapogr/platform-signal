# Scoped Kubernetes metadata API collection

K8S-CONTEXT API slice, 2026-10-25. Builds on [72](72-kubernetes-context.md).
Node-local CRI collection and actual Kubernetes permissions/churn remain required
for full-item acceptance. No AWS/EKS or release qualification follows here.

`kubernetes_context::client::Collector` owns immutable normalized API origin,
explicit caller-owned TLS configuration/trust revision, Profile and a new private
Reconciler. It never accepts a foreign reconciler or restores authority from a
snapshot. A versioned binding combines origin, trust revision and profile binding.
The trust digest names caller configuration; it is not proof of opaque rustls
settings. Production uses HTTPS with explicit trust; service-account Bearer access
does not require a client certificate. A separate explicit HTTP literal-loopback
fixture constructor cannot accept a remote endpoint. No ambient proxies, roots,
credentials, redirects, retries, decompression or authentication refresh are added.

Namespace paths require DNS labels1–63; node selectors require DNS subdomains<=253
with labels1–63. Validate before token acquisition. Build only fixed core/RBAC kind
collection routes. Opaque continuation tokens and resource versions are query
values, never supplied URLs. Namespace=None intentionally selects all namespaces.
Node selectors remain exact `spec.nodeName=<validated node>` on every request.

Tokens are opaque bounded values supplied per request by the trusted host. Token
acquisition, send, headers and every body chunk share one original ExtensionContext
and cancellation token. Static errors never include tokens, bodies or continuation
values. HTTP401/403,410, other unsuccessful statuses or encoded responses fail;
there is no implicit refresh/retry. List bodies/pages and native objects retain
all foundation budgets. A list publishes only its complete final page.

A successful watch returns an owned WatchSession. Each next_frame operation keeps
the same original deadline, retains split chunks/JSON bytes within independent
frame/pending/cumulative limits, and applies exactly one complete frame with its
local stream epoch/sequence. Charge every received byte, including whitespace and
line delimiters. Snapshots are usable while the owned stream remains connected
and the original list is unexpired. Bookmarks do not renew freshness. EOF, partial
frame, ERROR status, capacity, timeout, cancellation or dropped future/session
invalidate state; a complete relist is required. A closed session cannot be reused.
No authoritative snapshot is returned merely because the last frame before EOF
was valid. A timed-out/dropped refresh also invalidates retained state.

One mutable owner permits one operation/session; expose active depth/capacity and
count every invalidated operation. No detached tasks or unbounded queues are
introduced. Current snapshots export source binding plus the original collection
observation/expiry and selected metadata. They are not independent source-health,
effective permission, historical D08/D09 decision or protected-custody proof.

Acceptance: native loopback HTTP/TLS tests cover exact routes/filters and pagination,
pre-token scope refusal, Bearer-only success and foreign CA/hostname refusal,
original token/header/body deadlines, split/chunk/frame/cumulative bounds,
410/ERROR/EOF/drop invalidation, immutable source binding and relist. Apply focused
independent review and frozen workspace gates before local acceptance. Actual
namespace service-account denies, metadata churn and node-local paths follow.

Reqwest Response::chunk incremental capture was checked through Context7 and the
installed crate source; it does not require enabling bytes_stream's stream feature.
Kubernetes list/watch/RBAC semantics follow the official sources retained in72.

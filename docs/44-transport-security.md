# Native transport security

This is the implementation contract for the frozen SECURITY-TRANSPORT item.
Status: passed_simulated for the frozen local scope. Native monolith/agent,
shared receipt publishing and protected deployment probes have the evidence below.
Real PKI/cloud/native/CI/current-image/cluster/release qualification is separate.

Keep the existing monolith and outbound agent. Optional native mTLS uses the
already selected Rustls/ring stack. The server requires a valid client certificate
before HTTP on every configured API/metrics listener; selected TLS never accepts
plaintext or anonymous fallback. Native OIDC or explicit bootstrap API credentials
still apply. Certificate subjects, forwarding headers and network peer identity
never assign operation/scope grants or prove source collection completeness.

## Private configuration and trust

Set `SIGNAL_TLS_CONFIG` on the server (or `server.tls_config` in version1 YAML),
and `SIGNAL_AGENT_TLS_CONFIG` on the agent. Both files have this private versioned
JSON shape; actual keys/trust remain outside the public repository:

```json
{
  "schema_version": 1,
  "certificate_chain_der_base64": ["<leaf DER and optional intermediate DER>"],
  "private_key_der_base64": "<one unencrypted PKCS#8/PKCS#1/SEC1 DER key>",
  "peer_roots_der_base64": ["<explicit peer CA DER>"],
  "peer_crls_der_base64": ["<optional signed issuer CRL DER>"]
}
```

This is key material, not an event/provenance envelope. Unknown/duplicate fields,
nulls, absent required fields, empty identities/roots, duplicate DER entries,
invalid Base64/DER/key correspondence and resource bounds fail before readiness
or agent source/spool admission. The runtime has no insecure trust option or
private-material Debug/serialization diagnostics. Kubernetes secret-volume
symlinks may resolve to regular files; the operator owns their trust boundary.

Documents cap at512KiB. Chains and roots each have at most8 entries,16KiB each,
64KiB aggregate. The key caps at16KiB. Up to8 CRLs cap at64KiB each and128KiB
aggregate. Pure protocol decoding only checks the envelope/bounds; established
Rustls/WebPKI validates cryptographic material and peers. Explicit roots replace
ambient public/system roots for the selected agent mTLS configuration. Selecting
it requires an HTTPS endpoint, without redirects or ambient proxies.

Both sides use TLS1.2/1.3 defaults and established chain/time/signature checking;
the client also verifies the endpoint hostname. Session resumption and early data
are disabled. Provided CRLs use stock full-chain revocation checking, deny unknown
status and enforce nextUpdate expiry. Omitting CRLs does not perform serial
revocation checks; root/identity removal through explicit rotation remains distinct.
There is no homemade OCSP, dynamic CRL fetcher or certificate identity-to-RBAC map.

## Physical budgets and rotation

The server's TLS handshake holds the existing connection slot and counts towards
the original connection lifetime. Its shorter handshake deadline is the minimum
of request/connection timeouts. Silent peers cannot create detached TLS workers.
Header/body/HTTP/cancellation/shutdown limits continue to apply. Every configured
metrics listener uses the same mTLS configuration and connection budget; there is
no secondary plaintext API or metrics bypass when selected.

The agent has one physically owned configuration-file worker and one DNS worker,
each with a retained handle and one operation slot. Timeout, cancellation or a
dropped caller cannot release a still-running kernel read/lookup. Replacement
requests fail busy until physical retirement. DNS returns at most8 addresses,
uses a bounded hostname and connects within the existing request/connect budgets.
DNS capacity/depth/rejections are observable in agent metrics. Regular-file checks
and finite chunk reads bound private configuration intake; completed replies are
rechecked against the caller's original deadline before use.

Rotation is an explicit validated stopped/restart operation. Replace private
material/configuration atomically under operator control, preserve the original
spool/WAL/storage roots, and restart the single owner. Remove old roots/identities
or publish a signed CRL when revoking credentials; changing a file alone does not
change a running process. Existing accepted HTTP prefixes remain exact, uncertain
sends retain their original IDs, and replay remains at least once. Native OIDC
revocation remains fresh introspection, independent of transport certificate
revocation. No in-place authority refresh, automatic recovery or exactly-once
claim follows.

Agents initiate outbound delivery. Optional agent metrics are separate diagnostics,
not an inbound event/configuration endpoint; deployment must bind/restrict those
explicitly. Provider cloud authority and independent secret/encryption/audit work
remain in their existing frozen items.

## Native acceptance and remaining work

Sixteen compound actual local process checks prove named-endpoint agent/server
mTLS admission, WAL/Parquet/query, both-listener missing/foreign/expired client
denial, separate API credentials, plaintext denial, wrong server roots/hostname/time,
signed CRL client revocation, pre-replay zero rows and exact retained IDs after
stopped/restart certificate/root/token replacement. Valid incomplete TLS records
remain active during trickling and before shutdown; the original250ms handshake
clock closes a trickling peer within100ms scheduling allowance, and cancellation
retires active sockets within the configured1500ms shutdown bound plus200ms
allowance. Certificates/material stay in a private disposable scratch root outside
retained artifacts. Four harness fault regressions and independent review pass.

Strict727default/778all-feature workspace tests, both strict Clippy, formatting,
workspace13 and five deadline red/green regressions pass. Guards prevent a late
ready handshake/HTTP result from dispatching/acknowledging work. Source is exactly
restored after deliberately disabled safeguards; mutants remain failed evidence.
Evidence: `target/goal-execution-20261007/SECURITY-TRANSPORT/native-acceptance.json`
and `process-final/qualification.json`. This is local Linux AMD64 simulation,
not production PKI, physical power loss, remote CI or native ARM64 qualification.

The SDK now owns the single client TLS builder and retained physical DNS/file
workers used by the agent and receipt publisher. `HttpReceiptPublisher::with_tls`
requires HTTPS. Four actual TLS peer cases prove valid exact-prefix admission
and unchanged original receipt IDs/prefix across reopen on wrong-root, foreign
or missing client identity. The peer simulates HTTP admission; separate actual
monolith/agent16 checks pass. Original ExtensionContext guards both polling and
ready handoff. Strict730/781 tests, both Clippy/fmt/workspace13 and review pass.
Evidence: `target/goal-execution-20261007/SECURITY-TRANSPORT/shared-acceptance.json`.

## Protected deployment probes

The existing outbound `signal-agent` supplies quiet `--healthcheck`/`--readycheck`
modes, before agent source/config/spool admission. `SIGNAL_HEALTHCHECK_ADDR`
selects a nonzero numeric loopback socket; default127.0.0.1:8080. Optional
`SIGNAL_PROBE_TLS_CONFIG` selects the same shared native client and private file
limits. If server TLS is selected via `SIGNAL_TLS_CONFIG`, missing probe material
fails closed. TLS never falls back to HTTP or weak verification. Even when server
TLS is selected only through YAML, a plaintext probe fails at that TLS listener.

One original two-second budget begins before environment/runtime/configuration
initialization and includes TLS/HTTP/full response. The response must be200 and
complete within at most1KiB; status alone cannot pass an unfinished body. Every
poll/ready handoff rechecks the clock. No API token, source reads, spool mutation,
redirect, ambient proxy or DNS target is used. The server certificate must include
the chosen loopback IP SAN; the probe verifies this exact instance rather than a
load balancer or sibling. Client certificate identity grants no API privileges.

Docker's existing health executable performs a shell-free same-PID exec of that
probe. Helm's three probes use exec with a three-second supervisor budget and
separate private server/probe material from an existing Secret. Version1 Secret
JSON contents remain outside the public repository. Material/root changes need a
controlled stopped server restart; new probe invocations reload their own file.
With TLS metrics, ServiceMonitor requires separate explicit CA/client/key Secret
and server-name verification. Missing TLS metrics identity fails chart rendering.
There is no `insecureSkipVerify` or HTTP scrape bypass.

Kubernetes built-in HTTPS probes skip server certificate verification; the shared
native exec probe avoids that bypass. Official [Kubernetes probe documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
was used after Context7's current documentation quota was exhausted. Native probe,
chart, adapter and current image/cluster qualifications are distinct evidence.

Protected probe acceptance passes actual monolith/agent19 compound checks, three
current-binary adapter container cases with explicit UID/GID65532 and owned cleanup,
seven positive/negative chart contracts, four harness regressions and independent
review. Strict733/784 default/all-feature tests, both Clippy/fmt/workspace13 pass.
The first query-status trial failure is retained without an inferred cause; the
harness now records status and subsequent gates pass. Finite local evidence does
not prove prolonged availability or a current full production image/cluster.
See `target/goal-execution-20261007/SECURITY-TRANSPORT/probe-acceptance.json`.

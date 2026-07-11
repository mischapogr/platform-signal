# Native transport security

This is the implementation contract for the frozen SECURITY-TRANSPORT item.
Status: in_progress. Native agent/server transport has passed_simulated acceptance
below; protected deployment probes and shared collector publishing remain pending.
Real cloud/native/CI/release qualification remains separate.

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

The collector SDK publishing path still needs the same explicit TLS trust/identity
seam. Existing HTTP health probes cannot probe an mTLS-only listener without
appropriate credentials; packaging/deployment must configure a qualified protected
probe instead of silently weakening trust. These are remaining substeps within
SECURITY-TRANSPORT; the parent stays in_progress.

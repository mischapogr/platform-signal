# Established local IdP qualification

The optional gate uses actual Keycloak, an established OIDC client and Chromium
against `signal-server`. It qualifies synthetic local sign-in and native access
control; it does not qualify a live tenant, managed cloud, native ARM64 or remote
CI. The production monolith gains no dependency, login server or required service.

OIDC sign-in is handled by an established external IdP/client. The SDK verifies
signed ID tokens, issuer/subject, state, nonce and PKCE during authorization-code
exchange. The console retains its existing session-only Access token field; the
test supplies an actual IdP-issued access token there and checks a scoped finding.
There is no new embedded SIGNAL login button, cookie session, BFF or token store.
Native API authority still comes from fresh bounded authenticated introspection
and complete private operation/scope pairs, never browser ID tokens or role names.

## Reproduce

Use Node >=20.18.1, Docker, OpenSSL and the current built server. Optional tooling
has a separate private npm package with exact lock/integrity entries. It is test
infrastructure, independent of Cargo and the production image.

```bash
npm ci --prefix tools/identity --engine-strict --ignore-scripts --no-audit --no-fund --fetch-retries=1 --fetch-timeout=15000 --cache target/idp-npm-cache
PLAYWRIGHT_SKIP_BROWSER_GC=1 PLAYWRIGHT_BROWSERS_PATH="$PWD/target/idp-browsers" node tools/identity/node_modules/playwright-core/cli.js install --no-shell chromium
docker pull quay.io/keycloak/keycloak@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc
PLAYWRIGHT_BROWSERS_PATH="$PWD/target/idp-browsers" python3 scripts/run-ci-check.py --name idp-browser --timeout 360 -- python3 scripts/check-access-idp.py --output target/ci/idp-browser-qualification --binary target/debug/signal-server
python3 scripts/test-access-idp.py
```

Use a fresh qualification output directory. The helper can accept an explicit
`--browser-path`; reports record its actual version/hash. CI installs the
lock-selected Chromium and runner dependencies using `install --with-deps
--no-shell chromium` on disposable VMs. Local commands deliberately avoid changing
host packages. The browser cache is project-owned, with garbage collection disabled
for local downloads. `--provider-only` checks authenticated HTTPS discovery only
and emits `passed_provider_only`, never complete OIDC acceptance.

Dependencies are Keycloak26.8.0 pinned by multiarchitecture manifest digest,
openid-client6.8.8, playwright-core1.64.0 and undici7.30.0. A uniquely owned derived
IdP image runs Keycloak's supported offline optimization with dev-file storage and
local cache. The base image digest remains pinned; reports also identify the
actual native base and derived image IDs. This ephemeral development database is
not a production IdP topology. Full-scope permissions are not inferred from IdP
roles. Keycloak >=26.6.2 requires the authenticated introspecting client in `aud`;
the fixture includes it separately from SIGNAL's resource audience. The wrong
resource fixture remains introspectable while lacking SIGNAL's audience.

## Executable boundaries

The actual browser gate checks:

- Exact local authenticated HTTPS discovery and SDK signature validation;
  authorization-code PKCE/state/nonce sign-in in isolated contexts.
- State mismatch, consumed-code replay and incorrect verifier denial. Scope
  tests use fresh sessions because real providers can revoke replayed sessions.
- Cross-account whole-batch rejection with zero admission; each scoped user's
  durable events and findings filter before limits. Forged roles/attributes
  provide no authority. Exact canonical event identities remain queryable.
- ID-token, wrong-resource access-token, unbound-user and forwarded-header denial.
  Explicit admin roles do not inherit event access or producer authority. Global
  findings feed requires its separate capability. Unimplemented evidence/admin/
  rule/audit HTTP routes remain404 even with explicit corresponding grants.
- Actual IdP-token use in the existing SecOps console, one scoped finding, empty
  local/session storage and token clearing on disconnect.
- Actual session revocation and short-lived token admission followed by expiry
  denial. Pausing the owned provider yields a bounded408; unpause permits fresh
  authentication without credential caching.
- Malformed callback targets return bounded400 without request/credential
  diagnostics or callback resolution.

Existing coverage acceptance separately tests authenticated access to the exact
original coverage bytes, full binding/cursor isolation, actor-specific writes,
revocation and preserved receipts across crash/restart. This is distinct from
protected archive originals: their operative read HTTP contract is not invented
by this gate. Missing capabilities stay closed, and independent audit/configuration
work remains in SECURITY-AUDIT and onboarding items.

## Resource ownership and failure evidence

The container is bound to loopback, read-only with synthetic read-only fixture
mounts, 768MiB memory, one CPU,256 PIDs, bounded tmpfs and1MiB Docker logs. It has
its own random name/ownership label; cleanup checks labels and confirms absence.
No ambient containers/images, Kubernetes context or cloud credentials are used.
The pinned base remains cached; only the owned derived image is removed.

At most three process leaders and eight1MiB logs are retained. Group signalling
ends before reaping the leader; drain-join failures cannot restore signalling
rights to a reusable PID. Physical cleanup joins bounded drains and surfaces late
output failures. Request discovery uses a main-thread Linux absolute deadline
covering trickling headers/body. Provider startup has75seconds, server readiness
15, browser startup10, SDK/client100 and outer gate360seconds. The SDK also exits
at90seconds; its parent retains process/container cleanup authority.

HTTP bodies, network calls, connection counts, callback input and response sizes
are bounded. SDK HTTPS uses the generated CA with fixed origins, no proxies or
redirects. The test browser uses only the synthetic leaf SPKI exception and runs
headless without the sandbox; this is an explicit local harness setting, not a
production browser security qualification. Origin routing blocks external pages,
service workers/downloads are disabled, and no HAR/screenshots/authenticated
response payloads are retained.

Only synthetic credentials are created under a mode0700 temporary directory,
outside uploadable artifact trees. Docker uncertainty is not NotFound. Unconfirmed
cleanup records `failed`, retains private scratch and exact recovery identifiers,
and never uploads those mounts. Review/regressions exercise reaped leaders, failed
thread starts, persistent join failure, output overflow, foreign ownership,
uncertain inspection, unexpected cleanup failure and trickling HTTP headers/body.
A killed VM can lose recovery/artifact evidence; absence of proof cannot pass.

## Evidence and remaining qualification

Final source-bound qualification, helper results and review are recorded under
`target/goal-execution-20261007/SECURITY-ACCESS/`. Early provider startup, audience,
session-replay and cleanup attempts remain failed records. They are not promoted
by later success. The optional npm advisory check reported zero vulnerabilities
on2026-10-09; it is a dated result, not a future security guarantee.

The new CI steps run this gate on both native public Linux runners, retaining
finite logs/status. Reviewed-revision remote execution remains required. No Rust
behavior/build input changed in this tooling slice; existing strict718default/
769all-feature source-bound acceptance remains applicable. The current production
image, live IdP/rotation, real AWS/EKS and complete native ARM64/release gates stay
separate.

Current primary references: [Keycloak containers](https://www.keycloak.org/server/containers),
[TLS](https://www.keycloak.org/server/enabletls),
[realm import](https://www.keycloak.org/server/importExport),
[OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[audience migration](https://www.keycloak.org/docs/26.8.0/upgrading/),
[openid-client](https://github.com/panva/openid-client) and
[Playwright CI](https://playwright.dev/docs/ci). Context7 documentation lookups
were attempted but its monthly quota was exhausted; official current sources and
the locked SDK implementation/types supplied the fallback.

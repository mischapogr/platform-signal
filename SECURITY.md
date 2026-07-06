# Security

Signal is in development at `0.1.0-dev.0`; there are no supported production
releases yet. The current server implements HTTP ingestion, event/finding queries,
a bounded durable WAL, Parquet persistence and stateless rules. The agent and SDK
support local collection and trusted external extensions. Qualification remains
local Linux AMD64; native ARM64, EKS and release gates remain open.

See the [threat model](docs/20-threat-model.md) for assets, trust boundaries,
controls and residual risks, and the [release audit](docs/21-release-readiness.md)
and [definition of done](docs/06-definition-of-done.md) for current proof and open
gates. Configure token authentication and appropriate network/TLS controls before
exposing data APIs; the optional token does not provide RBAC or tenant isolation.

Report vulnerabilities privately through the repository's GitHub **Security →
Report a vulnerability** feature if it is enabled. If it is unavailable, ask a
maintainer to establish a private reporting channel without publishing exploit
details or credentials. A dedicated security contact is not yet designated.

Include affected versions, reproduction steps and impact. Redact tokens and
company identifiers. Avoid testing against production or third-party systems.
Maintainers will acknowledge and coordinate remediation when available; no
response-time commitment is established before the first release.

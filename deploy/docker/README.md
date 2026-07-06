# Production container

The multi-stage image builds the monolith and `signal-agent` with the locked
Rust 1.94.1 workspace. The Rust builder and distroless Debian 13 C++ runtime
are pinned to public multi-platform index digests resolved on 2026-10-06;
each index includes Linux AMD64 and ARM64. The runtime provides glibc,
libgcc and CA certificates, without a shell, curl or package manager.
Refresh the base digests and rebuild when security updates become available.

The default entrypoint is `signal-server`. The runtime uses UID/GID 65532,
contains no compiler, and needs a writable `/var/lib/signal` volume. Mount
configuration and rules read-only. The image healthcheck requests `/healthz`
every five seconds through a shell-free Rust helper with one two-second I/O
deadline and a 128-byte response limit. A custom HTTP bind port
requires `SIGNAL_HEALTHCHECK_ADDR=127.0.0.1:<port>` (a numeric socket address). Kubernetes
uses its own HTTP liveness and readiness probes.

From the repository root, build and qualify the **native host architecture**:

```bash
docker build --pull -f deploy/docker/Dockerfile -t platform-signal:phase8 .
python3 scripts/check-container.py --image platform-signal:phase8 \
  --expect-architecture amd64
```

Use `--expect-architecture arm64` on an ARM64 host with an ARM64 Docker daemon.
The script never builds or pulls an image. It verifies non-root operation,
a read-only root, dropped capabilities, no privilege escalation, one writable
persistent volume, read-only configuration/rules, 1 GiB memory, two CPUs and
128 PIDs. It checks Docker health, executable versions, ingestion, exact event
and finding queries, SIGTERM/SIGKILL persistence, authentication and redacted
logs. Each run owns and removes its temporary Compose project and data volume.
An agent `--version` check qualifies binary packaging; the separate agent
process gate qualifies collection and delivery.

The developer demonstration remains:

```bash
docker compose up --build
```

Compose binds the API to loopback port 8080 and metrics to loopback port 9090,
retains `/var/lib/signal` in a named volume, and mounts config/rules read-only.
Set `SIGNAL_API_TOKEN` to require Bearer authentication. Request examples are
in the repository [README](../../README.md).

Run the packaged agent with a persistent spool and explicit configuration:

```bash
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 256m --cpus 1 \
  --no-healthcheck --entrypoint /usr/local/bin/signal-agent \
  platform-signal:phase8 --version
```

For collection, mount the agent configuration and input files read-only and
mount its configured spool directory writable, owned by UID/GID 65532.
Pass the token from an explicit environment/configuration source, following
[the agent contract](../../docs/15-phase6-agent.md). Disable the server image's
HTTP healthcheck when selecting the agent entrypoint.

A configured builder can produce a multi-platform OCI artifact:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deploy/docker/Dockerfile --output type=oci,dest=/tmp/platform-signal.oci.tar .
```

An emulated build or execution does not establish native runtime qualification.
Native AMD64 and ARM64 CI runners must each build and run the gate. The exact
completed checks and remaining ARM64, CI, SBOM/scan, Kubernetes and EKS evidence
are recorded in [progress](../../docs/07-progress.md). These commands do not
publish an image or qualify the full release.

Docker configuration follows the current
[base-image pinning guidance](https://docs.docker.com/build/building/best-practices/)
and [Dockerfile reference](https://docs.docker.com/reference/dockerfile/).
Runtime selection follows the official
[distroless C++/Rust runtime documentation](https://github.com/GoogleContainerTools/distroless/blob/main/cc/README.md).

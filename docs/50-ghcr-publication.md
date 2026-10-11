# Public OSS container publication

Prepared 2026-10-10; publication is held until release readiness. No release
version, tag, repository variable or package visibility has been configured by
this local implementation. The current `0.1.0-dev.0` is not publishable.

The [publication workflow](../.github/workflows/publish-images.yml) publishes
the existing server and agent roles from an owner-published GitHub Release.
Images follow the lowercase repository owner, currently:

```text
ghcr.io/mischapogr/signal-server:<release-tag>
ghcr.io/mischapogr/signal-agent:<release-tag>
```

Both image indexes contain native `linux/amd64` and `linux/arm64` builds. The
shared Dockerfile has `server` and `agent` targets, with server as its default.
The agent target selects the agent entrypoint and disables the server probe.
Both contain only the OSS workspace. There is no independently deployed UI image.
Private overlays must use a separate private package/registry and workflow.

## Readiness and trigger

First complete the applicable [release gates](21-release-readiness.md), select
a release version, update the workspace version, and obtain the owner-held Git
and release authority. Actual EKS, released dependencies, independent reviews
and other external requirements are not established by this workflow.

The owner then sets the Actions repository variable `SIGNAL_RELEASE_READY_TAG`
to the exact approved tag, for example `v0.1.0-alpha.1`. This is a per-release
readiness declaration; changing it is a release action. The tag must equal the
workspace version prefixed with `v`. Development/dirty versions, private
repositories, draft releases and inconsistent prerelease flags are refused.
Do not set the variable while required readiness gates are still open.

Publishing that GitHub Release starts the workflow automatically. Pushes to
main, bare version-tag pushes and pull requests do not publish images. Existing
CI continues to build and test those changes. Alpha/prerelease images receive
only their version tag; `latest` is reserved for a stable release. No personal
access token is required: jobs use their scoped `GITHUB_TOKEN` and GitHub OIDC
for attestations, with write permissions limited to publication jobs.

## Qualification and exact artifact identities

1. Preflight verifies the event, owner readiness, version and source revision.
2. The reusable CI workflow runs its complete native AMD64/ARM64 Rust,
   process, container, Kubernetes and supply-chain qualification.
3. Native runners build each role, load it locally, qualify server persistence
   and agent packaging, then scan the exact image IDs. Failed dependency audit,
   HIGH/CRITICAL vulnerabilities, missing checks or altered SBOM/report bytes
   prevent platform publication. The helper binds reports to current Cargo.lock.
4. Successful platform manifests are uploaded with release/role/architecture/
   revision-bound digest records. SPDX SBOM attestations are signed for those
   exact platform digests using GitHub OIDC.
5. Each release index combines exactly the two qualified platform digests. The
   index receives signed build provenance. An empty Docker credential config
   must then retrieve it anonymously by digest.
6. Only after both signed public indexes succeed does a stable release promote
   `latest` by digest. Updating two image tags is not an atomic transaction;
   retain the per-role digest records if a registry/network failure interrupts
   promotion, and use the versioned digest references for deployment.

Third-party Actions are pinned to immutable commits. Supply-chain tooling and
base images retain their existing pins and fail-closed scanner policies. Reports,
SBOMs and exact published digest records are retained as workflow artifacts.
Action pins and base/scanner versions require review when updated.

## First publication and production use

GHCR creates packages private by default, even for a public repository. After
the first successful platform upload, the owner must set **each package's
visibility to public** in GitHub package settings and confirm its repository
association. OCI source labels link images to this repository. The workflow
fails its anonymous verification while either package remains private; `latest`
is withheld. After visibility is corrected, rerun the failed release workflow
jobs. An authenticated pull does not meet the public OSS acceptance check.
[GitHub's container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
defines package visibility and anonymous public pulls.

Production manifests must pin the accepted index digest, for example
`ghcr.io/mischapogr/signal-server@sha256:<accepted-index-digest>`, rather than a
mutable `latest` tag. Keep the signed provenance, platform SBOMs and release
reports alongside that identity. The local policy tests and YAML review prepare
the workflow; they do not prove a remote run, ARM64 execution or public registry
availability.

References: [GitHub Docker publication](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images),
[GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations),
[Docker index inspection](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/).

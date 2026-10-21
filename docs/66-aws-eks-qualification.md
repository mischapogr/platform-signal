# AWS/EKS qualification runbook (EXT-AWS)

Closes the `EXT-AWS` ledger item only when run against an owner-authorized AWS
account. Nothing here has been executed: the harness is prepared and unit-tested
locally (dry-run, account guard, TTL cap), but no AWS evidence exists yet.

## Scope

| Proven by `scripts/check-eks.py` | Not proven (stays open) |
| --- | --- |
| Production image runs on real EKS 1.34 (chosen arch), non-root, from ECR | Standard profile (PostgreSQL, S3 custody runtime, IdP) on AWS |
| Authenticated ingest, finding, canonical rows on an encrypted gp3 EBS PVC | Multi-AZ, AZ/account loss, HA, replicas (still one writer) |
| Pod replacement and node drain reattach the same EBS volume with identical rows | Prolonged soak, physical-device throughput, cost at scale |
| S3 bucket: default KMS encryption, Object Lock GOVERNANCE default retention, locked-version delete denied, TLS-only policy | The product writing custody objects to S3 (not wired to this bucket) |
| Resource tagging `signal-qual=<run-id>`, TTL cap, teardown with residual scan | IAM denial for the product role (add when the Standard S3 runtime is pointed at AWS) |

Be explicit in the progress record: a pass closes "Small chart on EKS/EBS and
S3/KMS/Object Lock behaviour", not full Standard AWS qualification.

## Prerequisites (owner)

1. **Account.** A disposable AWS account or isolated sandbox, never production. Note its 12-digit ID and
   choose a region (for example `eu-central-1`).
2. **Budget.** Create a budget alarm (suggest USD 25) under Billing → Budgets before the first run.
3. **Permissions.** An admin-equivalent sandbox user/role (IAM Identity Center is simplest). The run
   creates and deletes EKS, EC2, IAM roles and the OIDC provider, CloudFormation stacks, ECR, S3
   (needs `s3:BypassGovernanceRetention`), KMS keys and tags. Scope it down afterwards.
4. **Tools.** `aws` v2, `eksctl`, `kubectl`, `helm`, Docker (and Rust only to rebuild the image).
   `scripts/install-kubernetes-tools.py` covers the Kubernetes tools; install `aws` and `eksctl` from
   their vendors' current instructions.
5. **Credentials.** Short-lived only: `aws configure sso`, `aws sso login`, or `AWS_PROFILE`. Never commit
   keys. Confirm with `aws sts get-caller-identity` that `Account` is the sandbox.
6. **Image.** Build the image for the architecture under test (default `platform-signal:phase8`):
   `docker build -f deploy/docker/Dockerfile -t platform-signal:phase8 .` (see [packaging](19-packaging.md)).
   The image must be `linux/amd64` for `--arch amd64` or `linux/arm64` for `--arch arm64`.
7. **Cost.** One EKS control plane (~USD 0.10/h), one t3.medium/t4g.medium, EBS and NAT (eksctl default
   VPC): roughly USD 0.25/h, 45–75 min per run. KMS keys bill for the 7-day deletion window. Verify
   current pricing.

### Install and log in (example, Linux)

Check each vendor's current instructions; versions and URLs change.

```bash
python3 scripts/install-kubernetes-tools.py --help   # pinned, checksum-verified helm/kind/kubectl into a directory you own; then add it to PATH
aws --version && eksctl version && kubectl version --client && helm version --short && docker version --format '{{.Server.Version}}'
aws configure sso --profile signal-qual              # one-time: SSO start URL, region, account, role
aws sso login --profile signal-qual
export AWS_PROFILE=signal-qual
aws sts get-caller-identity --query Account --output text   # must print the sandbox account ID
```

### Before `--execute` (checklist)

- [ ] Dry-run output reviewed; account ID and region are the sandbox's.
- [ ] Budget alarm exists; you will be reachable for the next ~90 minutes to run teardown if needed.
- [ ] Image built for the chosen `--arch` and `docker image inspect` shows the expected architecture.
- [ ] Calendar reminder set for the next day to confirm billing and the KMS key deletion date.

## Procedure

```bash
export ACC=<12-digit-account> REGION=<region>

# 1. Review the exact plan; executes nothing and needs no credentials.
python3 scripts/check-eks.py all --account-id $ACC --region $REGION

# 2. Real run (bills resources). Teardown runs automatically, even on failure.
python3 scripts/check-eks.py all --account-id $ACC --region $REGION --arch amd64 --execute

# 3. If the run was interrupted or teardown reported residuals:
python3 scripts/check-eks.py teardown --account-id $ACC --region $REGION --run-id <id> --execute
```

The run ID is printed first and names `target/aws-qualification/<id>/`. Repeat with `--arch arm64` and
an ARM64 image to qualify both architectures. Stages can be run separately: `preflight`, `provision`,
`verify`, `teardown`.

What the run does, in order: account/image/TTL checks; EKS 1.34 with EBS CSI and encrypted gp3;
ECR push; S3 bucket with KMS and Object Lock; S3 behaviour checks; Helm deploy; ingest and finding;
pod-replacement and node-drain recovery on the same EBS volume; teardown with a residual scan.

## Evaluating readiness

Accept the run only if all of these hold:

1. `ACCEPTANCE.json` has `"status": "passed"` and lists every check: cluster/EBS CSI, ECR push, bucket,
   default KMS encryption, Object Lock retention, locked-version delete denial, TLS-only policy,
   ingest and finding, pod-replacement recovery, node-drain recovery.
2. `TEARDOWN.json` has `"status": "clean"`.
3. The console or `aws resourcegroupstaggingapi get-resources --tag-filters Key=signal-qual,Values=<id>`
   shows nothing but the KMS key pending deletion; no stray EBS volumes, NAT gateways or load balancers.
4. The next day's billing shows no running charges.

Caveats when reading the result:

- `--ttl-hours` only caps the planned duration and is written to `state.json`; **nothing deletes
  the resources automatically after it elapses**. Teardown runs at the end of `all` or when you run it.
  If the terminal dies mid-run, run `teardown` yourself.
- The cluster has one node. The "node drain" check evicts the pod, then uncordons the same node, so it
  proves EBS detach/reattach and rescheduling, not recovery onto a different node or zone.

A partial pass is a fail: record it as such and do not change the ledger.

## Recording the result

1. Add a dated entry to `docs/07-progress.md`: region, architecture, run ID, image ID, scope limits from
   the table above. Keep account IDs, ARNs and credentials out of committed files.
2. Set `EXT-AWS` to `passed_external` in `docs/31-execution-ledger.md` and `.json` with the narrowed scope.
3. Use the "passed" wording for limit 1 in [the release notes draft](67-release-notes-draft.md) and add a
   `CHANGELOG.md` line.
4. Open items remain after a pass: the Standard profile on AWS, multi-AZ/HA and the product writing to S3.

## If something fails

The harness has never run against real AWS, so expect small first-run fixes (eksctl flags, drain timing,
missing IAM permission, PodSecurity). Read the `FAILED:` line, fix the script and rerun; never edit evidence
by hand. Always finish with `teardown` so nothing keeps billing, and confirm residuals as above.
If teardown reports `residual`, delete the listed resources manually (EKS cluster, bucket after removing
versions with the governance bypass, ECR repository, EBS volumes) and rerun the residual scan.

## Safety properties

- Dry-run by default; `--execute` required for any mutation; caller account must equal `--account-id`.
- `--ttl-hours` capped at 8; Object Lock uses GOVERNANCE (never COMPLIANCE) so teardown can delete
  with an explicit bypass permission.
- Every resource is tagged; `teardown` is idempotent, continues past individual failures and lists residuals.
- The ECR password goes to `docker login` via stdin only; the API token is random per run.
- Untrusted CI must never receive this role. If automated later, use GitHub OIDC restricted to the
  exact repository and a protected environment (see doc 40).

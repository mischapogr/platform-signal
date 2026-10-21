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

1. A disposable AWS account (or isolated sandbox) with a budget alarm (suggest USD 25) and an
   authorized 12-digit account ID. Do not use a production account.
2. Short-lived credentials in the shell (`aws sso login` or `AWS_PROFILE`); never commit keys.
3. IAM permissions to create/delete EKS, EC2, IAM roles/OIDC provider, CloudFormation, ECR,
   S3 (incl. `s3:BypassGovernanceRetention`), KMS, and tag lookups. An admin-equivalent sandbox
   role is simplest; scope it down afterwards.
4. Tools: `aws` v2, `eksctl`, `kubectl`, `helm`, Docker, and the local image
   (`platform-signal:phase8` by default; must match `--arch`).
5. Expected cost: one EKS control plane (~USD 0.10/h) + one t3.medium/t4g.medium + EBS + NAT
   (eksctl default VPC) — roughly USD 0.25/h; a run takes 45–75 min. KMS keys bill for the
   7-day deletion window (~USD 1/month prorated). Verify current pricing.

## Procedure

```bash
export ACC=<12-digit-account> REGION=<region>

# 1. Review the exact plan; executes nothing.
python3 scripts/check-eks.py all --account-id $ACC --region $REGION

# 2. Real run (bills resources). Teardown runs automatically, even on failure.
python3 scripts/check-eks.py all --account-id $ACC --region $REGION --arch amd64 --execute

# 3. If the run was interrupted or teardown reported residuals:
python3 scripts/check-eks.py teardown --account-id $ACC --region $REGION --run-id <id> --execute
```

Repeat with `--arch arm64` and an ARM64 image if both architectures should be qualified.
Stages can also be run separately: `preflight`, `provision`, `verify`, `teardown`.

## Evidence and acceptance

Outputs land in `target/aws-qualification/<run-id>/` (`state.json`, `ACCEPTANCE.json`,
`TEARDOWN.json`). Accept only when:

- `ACCEPTANCE.json` status is `passed` with the six check groups (cluster/EBS CSI, ECR, bucket,
  ingest, pod-replacement recovery, node-drain recovery) and `TEARDOWN.json` status is `clean`.
- AWS console/`aws resourcegroupstaggingapi` shows nothing tagged with the run ID except the KMS
  key pending deletion; no stray EBS volumes or load balancers; billing shows no ongoing charge.

Then record in `docs/07-progress.md` (date, run ID, region, arch, image ID, scope limits above),
and move `EXT-AWS` in `docs/31-execution-ledger.md` and `.json` to `passed_external` with the
narrowed scope. Keep account IDs, ARNs and credentials out of committed docs (record region and run ID only).

## Safety properties

- Dry-run by default; `--execute` required for any mutation; caller account must equal `--account-id`.
- `--ttl-hours` capped at 8; Object Lock uses GOVERNANCE (never COMPLIANCE) so teardown can delete
  with an explicit bypass permission.
- Every resource is tagged; `teardown` is idempotent, continues past individual failures and lists residuals.
- The ECR password goes to `docker login` via stdin only; the API token is random per run.
- Untrusted CI must never receive this role. If automated later, use GitHub OIDC restricted to the
  exact repository and a protected environment (see doc 40).

## Known limitations of the prepared harness

Untested against real AWS (no account available): expect small fixes on first run, e.g. eksctl flag
changes, node-drain timing, or PodSecurity settings. Fix them in the script and rerun; do not hand-edit
evidence.

#!/usr/bin/env python3
"""Qualify an existing image on an exclusively owned, disposable AWS EKS cluster (EXT-AWS).

Dry-run by default: prints the exact planned commands and runs nothing. Pass --execute
to create billed resources. Every resource is tagged signal-qual=<run-id>; state lives in
target/aws-qualification/<run-id>/state.json so `teardown` works after any failure.
Requires aws, eksctl, kubectl, helm and Docker. Uses the caller's AWS credentials
(prefer short-lived SSO/OIDC); never stores or prints them. See docs/66-aws-eks-qualification.md.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
NAMESPACE = "gate"
INSTANCE_TYPES = {"amd64": "t3.medium", "arm64": "t4g.medium"}
KUBERNETES_VERSION = "1.34"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Runner:
    """Single process seam: dry-run records commands, execute runs them."""

    def __init__(self, execute, env):
        self.execute = execute
        self.env = env
        self.planned = []

    def run(self, command, data=None, timeout=300, mutating=True):
        if not self.execute and mutating:
            self.planned.append(command)
            print("[dry-run] " + " ".join(command))
            return ""
        result = subprocess.run(command, input=data, env=self.env, cwd=ROOT,
                                text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("command failed: " + " ".join(command) + "\n" +
                               (result.stderr or result.stdout)[-3000:])
        return result.stdout.strip()


class Qualification:
    def __init__(self, args, runner, directory):
        self.args = args
        self.runner = runner
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.run_id = args.run_id
        self.name = "signal-qual-" + self.run_id
        self.bucket = self.name + "-custody"
        self.repository = self.name
        self.state_path = self.directory / "state.json"
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.kubeconfig = str(self.directory / "kubeconfig")
        runner.env["KUBECONFIG"] = self.kubeconfig
        self.tags = "signal-qual=" + self.run_id
        self.token = secrets.token_hex(32)
        self.forward = None
        self.port = None
        self.checks = []

    # -- helpers ---------------------------------------------------------
    def aws(self, *args, mutating=True, timeout=300):
        return self.runner.run([self.args.aws, "--region", self.args.region, *args],
                               mutating=mutating, timeout=timeout)

    def kube(self, *args, data=None, mutating=True):
        return self.runner.run([self.args.kubectl, "--namespace", NAMESPACE, *args],
                               data=data, mutating=mutating)

    def save(self, **values):
        self.state.update(values)
        if self.runner.execute:
            self.state_path.write_text(json.dumps(self.state, indent=2))

    def record(self, name, detail=None):
        self.checks.append({"check": name, "status": "passed", **({"detail": detail} if detail else {})})
        print(("PASS " if self.runner.execute else "PLAN ") + name)

    def request(self, path, method="GET", payload=None, authorized=True):
        headers = {"Authorization": "Bearer " + self.token} if authorized else {}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    def poll(self, check, label, seconds=180):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (OSError, urllib.error.URLError, RuntimeError):
                pass
            time.sleep(1)
        raise RuntimeError("timed out waiting for " + label)

    # -- preflight -------------------------------------------------------
    def preflight(self):
        require(self.args.ttl_hours <= 8, "--ttl-hours is capped at 8 for a disposable run")
        if not self.runner.execute:
            print("[dry-run] preflight: tools, caller account == %s, local linux/%s image, no existing cluster"
                  % (self.args.account_id, self.args.arch))
            return {"Id": "dry-run"}
        for tool in (self.args.aws, self.args.eksctl, self.args.kubectl, self.args.helm, "docker"):
            require(shutil.which(tool), "missing tool: " + tool)
        require(self.args.account_id.isdigit() and len(self.args.account_id) == 12, "12-digit --account-id required")
        identity = json.loads(self.aws("sts", "get-caller-identity", mutating=False))
        require(identity["Account"] == self.args.account_id,
                "caller account %s does not match the authorized --account-id" % identity["Account"])
        image = json.loads(self.runner.run(["docker", "image", "inspect", self.args.image], mutating=False))[0]
        require(image["Os"] == "linux" and image["Architecture"] == self.args.arch,
                "local image must be linux/" + self.args.arch)
        existing = self.aws("eks", "list-clusters", "--query", "clusters", "--output", "json", mutating=False)
        require(self.name not in json.loads(existing), "run id already has a cluster")
        self.record("preflight", {"account": identity["Account"], "arn_redacted": True,
                                  "arch": self.args.arch, "region": self.args.region})
        return image

    # -- provision -------------------------------------------------------
    def provision(self):
        image = self.preflight()
        self.save(run_id=self.run_id, region=self.args.region, account=self.args.account_id,
                  created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  expires_hours=self.args.ttl_hours, cluster=self.name, bucket=self.bucket,
                  repository=self.repository, image_id=image["Id"])
        self.runner.run([self.args.eksctl, "create", "cluster", "--name", self.name,
                         "--region", self.args.region, "--version", KUBERNETES_VERSION,
                         "--nodegroup-name", "workers", "--node-type", INSTANCE_TYPES[self.args.arch],
                         "--nodes", "1", "--nodes-min", "1", "--nodes-max", "1", "--managed",
                         "--with-oidc", "--tags", self.tags,
                         "--kubeconfig", self.kubeconfig, "--auto-kubeconfig=false"], timeout=2400)
        self.save(cluster_created=True)
        self.runner.run([self.args.eksctl, "create", "iamserviceaccount", "--cluster", self.name,
                         "--region", self.args.region, "--namespace", "kube-system",
                         "--name", "ebs-csi-controller-sa", "--role-only", "--role-name", self.name + "-ebs-csi",
                         "--attach-policy-arn", "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",
                         "--tags", self.tags, "--approve"], timeout=600)
        self.runner.run([self.args.eksctl, "create", "addon", "--cluster", self.name, "--region", self.args.region,
                         "--name", "aws-ebs-csi-driver",
                         "--service-account-role-arn",
                         "arn:aws:iam::%s:role/%s-ebs-csi" % (self.args.account_id, self.name)], timeout=900)
        self.kube("apply", "-f", "-", data=json.dumps({
            "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "signal-gp3"},
            "provisioner": "ebs.csi.aws.com", "volumeBindingMode": "WaitForFirstConsumer",
            "parameters": {"type": "gp3", "encrypted": "true"}}))
        self.record("eks-cluster-and-ebs-csi", {"kubernetes": KUBERNETES_VERSION,
                                                "node": INSTANCE_TYPES[self.args.arch]})
        self.provision_ecr(image)
        self.provision_custody()

    def provision_ecr(self, image):
        self.aws("ecr", "create-repository", "--repository-name", self.repository,
                 "--image-scanning-configuration", "scanOnPush=true",
                 "--encryption-configuration", "encryptionType=KMS", "--tags", "Key=signal-qual,Value=" + self.run_id)
        self.save(ecr_created=True)
        registry = "%s.dkr.ecr.%s.amazonaws.com" % (self.args.account_id, self.args.region)
        # Password goes through stdin to docker, never argv or logs.
        password = self.aws("ecr", "get-login-password", mutating=False) if self.runner.execute else ""
        self.runner.run(["docker", "login", "--username", "AWS", "--password-stdin", registry], data=password)
        target = "%s/%s:qual" % (registry, self.repository)
        self.runner.run(["docker", "tag", self.args.image, target])
        self.runner.run(["docker", "push", target], timeout=900)
        self.record("ecr-push", {"repository": self.repository})

    def provision_custody(self):
        key = self.aws("kms", "create-key", "--description", "signal qualification " + self.run_id,
                       "--tags", "TagKey=signal-qual,TagValue=" + self.run_id,
                       "--query", "KeyMetadata.KeyId", "--output", "text")
        self.save(kms_key_id=key)
        self.aws("s3api", "create-bucket", "--bucket", self.bucket, "--object-lock-enabled-for-bucket",
                 *([] if self.args.region == "us-east-1" else
                   ["--create-bucket-configuration", "LocationConstraint=" + self.args.region]))
        self.save(bucket_created=True)
        self.aws("s3api", "put-bucket-tagging", "--bucket", self.bucket,
                 "--tagging", "TagSet=[{Key=signal-qual,Value=%s}]" % self.run_id)
        self.aws("s3api", "put-public-access-block", "--bucket", self.bucket, "--public-access-block-configuration",
                 "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
        self.aws("s3api", "put-bucket-encryption", "--bucket", self.bucket, "--server-side-encryption-configuration",
                 json.dumps({"Rules": [{"ApplyServerSideEncryptionByDefault":
                                        {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key}, "BucketKeyEnabled": True}]}))
        self.aws("s3api", "put-object-lock-configuration", "--bucket", self.bucket, "--object-lock-configuration",
                 json.dumps({"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}}))
        self.aws("s3api", "put-bucket-policy", "--bucket", self.bucket, "--policy", json.dumps({
            "Version": "2012-10-17", "Statement": [{
                "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                "Resource": ["arn:aws:s3:::" + self.bucket, "arn:aws:s3:::%s/*" % self.bucket],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
        self.record("s3-kms-object-lock-bucket", {"bucket": self.bucket, "default_retention": "GOVERNANCE/1d"})

    # -- verify ----------------------------------------------------------
    def verify(self):
        require(self.state.get("cluster_created") or not self.runner.execute, "provision first")
        self.verify_custody()
        self.verify_runtime()

    def verify_custody(self):
        """Actual S3 behaviour, not configuration alone."""
        probe = self.directory / "probe.txt"
        if self.runner.execute:
            probe.write_text("signal-qualification " + self.run_id)
        put = self.aws("s3api", "put-object", "--bucket", self.bucket, "--key", "probe/object",
                       "--body", str(probe), "--query", "[ServerSideEncryption,SSEKMSKeyId,VersionId]", "--output", "json")
        if self.runner.execute:
            encryption, key_arn, version = json.loads(put)
            require(encryption == "aws:kms" and self.state["kms_key_id"] in (key_arn or ""),
                    "object encrypted with the run's KMS key by bucket default")
        else:
            version = "DRYRUN"
        self.record("s3-default-kms-encryption")
        head = self.aws("s3api", "head-object", "--bucket", self.bucket, "--key", "probe/object",
                        "--query", "[ObjectLockMode,ObjectLockRetainUntilDate]", "--output", "json", mutating=False) \
            if self.runner.execute else None
        if head is not None:
            mode, until = json.loads(head)
            require(mode == "GOVERNANCE" and until, "default Object Lock retention applied")
        self.record("s3-object-lock-retention")
        denied = False
        try:
            self.aws("s3api", "delete-object", "--bucket", self.bucket, "--key", "probe/object", "--version-id", version)
        except RuntimeError as error:
            denied = "AccessDenied" in str(error)
        require(denied or not self.runner.execute, "locked version delete denied without governance bypass")
        self.record("s3-locked-version-delete-denied")
        if self.runner.execute:
            policy = json.loads(json.loads(self.aws("s3api", "get-bucket-policy", "--bucket", self.bucket,
                                                    mutating=False))["Policy"])
            require(any(s["Sid"] == "DenyInsecureTransport" for s in policy["Statement"]), "TLS-only policy present")
        self.record("s3-tls-only-policy")

    def start_forward(self):
        self.stop_forward()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        if self.runner.execute:
            self.forward = subprocess.Popen(
                [self.args.kubectl, "--namespace", NAMESPACE, "port-forward", "service/proof-signal",
                 "%d:8080" % self.port], env=self.runner.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.poll(lambda: self.request("/readyz")[0] == 200, "port-forward readiness")

    def stop_forward(self):
        if self.forward:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forward.kill()
                self.forward.wait(timeout=10)
            self.forward = None

    def pod(self):
        pods = json.loads(self.kube("get", "pods", "-l", "app.kubernetes.io/instance=proof", "-o", "json", mutating=False))
        require(len(pods["items"]) == 1, "single writer pod")
        return pods["items"][0]

    def rows(self, name):
        status, body = self.request("/v1/" + name)
        require(status == 200, name + " query")
        return json.loads(body)[name]

    def verify_runtime(self):
        registry = "%s.dkr.ecr.%s.amazonaws.com" % (self.args.account_id, self.args.region)
        self.runner.run([self.args.kubectl, "create", "namespace", NAMESPACE])
        self.kube("apply", "-f", "-", data=json.dumps({
            "apiVersion": "v1", "kind": "Secret", "metadata": {"name": "gate-auth"},
            "data": {"api-token": base64.b64encode(self.token.encode()).decode()}}))
        self.kube("create", "configmap", "gate-rules", "--from-file=" + str(ROOT / "rules/examples/login-failure.yaml"))
        self.runner.run([self.args.helm, "install", "proof", str(ROOT / "deploy/helm/signal"),
                         "--namespace", NAMESPACE, "--wait", "--timeout", "600s",
                         "--set", "image.repository=%s/%s" % (registry, self.repository),
                         "--set-string", "image.tag=qual", "--set-string", "image.digest=",
                         "--set", "auth.existingSecret=gate-auth", "--set", "rules.existingConfigMap=gate-rules",
                         "--set", "rules.keys[0]=login-failure.yaml", "--set", "persistence.size=2Gi",
                         "--set", "persistence.storageClass=signal-gp3", "--set", "pdb.enabled=true"], timeout=700)
        if not self.runner.execute:
            self.record("helm-deploy-ebs-recovery (planned)")
            return
        self.start_forward()
        pod = self.pod()
        require(pod["spec"]["securityContext"]["runAsUser"] == 65532, "non-root user")
        claim = json.loads(self.kube("get", "pvc", "proof-signal", "-o", "json", mutating=False))
        require(claim["status"]["phase"] == "Bound" and claim["spec"]["storageClassName"] == "signal-gp3", "gp3 PVC bound")
        volume = claim["spec"]["volumeName"]
        pv = json.loads(self.runner.run([self.args.kubectl, "get", "pv", volume, "-o", "json"], mutating=False))
        require(pv["spec"]["csi"]["driver"] == "ebs.csi.aws.com", "volume is an EBS CSI volume")
        event = {"schema_version": 1, "id": str(uuid.uuid4()), "timestamp": "2026-10-06T12:00:00Z",
                 "observed_at": "2026-10-06T12:00:01Z", "source": {"type": "application", "name": "eks-gate"},
                 "severity": "warn", "message": "login failed EKS gate",
                 "attributes": {"nested": {"verified": True}}, "tags": ["eks", "verification"]}
        require(self.request("/v1/events", "POST", event, authorized=False)[0] == 401, "unauthorized ingest rejected")
        require(self.request("/v1/events", "POST", event)[0] == 202, "durable ingest accepted")
        self.poll(lambda: self.rows("events") == [event] and len(self.rows("findings")) == 1, "event and finding")
        findings = self.rows("findings")
        self.record("eks-ingest-and-finding")
        # Process crash: kill PID 1's child via the container runtime is unavailable on EKS;
        # the probe-visible equivalent is deleting the pod while the writer holds the volume,
        # after scale-down so a second writer can never mount the EBS volume.
        self.stop_forward()
        self.kube("scale", "deployment/proof-signal", "--replicas=0")
        self.kube("wait", "--for=delete", "pod/" + pod["metadata"]["name"], "--timeout=120s")
        self.kube("scale", "deployment/proof-signal", "--replicas=1")
        self.kube("rollout", "status", "deployment/proof-signal", "--timeout=300s")
        self.start_forward()
        self.poll(lambda: self.rows("events") == [event] and self.rows("findings") == findings,
                  "canonical rows after EBS reattach")
        replacement = self.pod()
        require(replacement["metadata"]["uid"] != pod["metadata"]["uid"], "replacement pod UID")
        after = json.loads(self.kube("get", "pvc", "proof-signal", "-o", "json", mutating=False))
        require(after["spec"]["volumeName"] == volume, "same EBS volume after replacement")
        self.record("eks-pod-replacement-ebs-recovery", {"volume_unchanged": True})
        # Node replacement: cordon + delete the pod's node so the volume must detach and reattach.
        node = replacement["spec"]["nodeName"]
        self.runner.run([self.args.kubectl, "drain", node, "--ignore-daemonsets", "--delete-emptydir-data",
                         "--timeout=300s"], timeout=400)
        self.stop_forward()
        self.runner.run([self.args.kubectl, "uncordon", node])
        self.kube("rollout", "status", "deployment/proof-signal", "--timeout=300s")
        self.start_forward()
        self.poll(lambda: self.rows("events") == [event] and self.rows("findings") == findings,
                  "canonical rows after node drain")
        self.record("eks-node-drain-ebs-recovery")
        self.stop_forward()

    # -- teardown --------------------------------------------------------
    def teardown(self):
        """Best-effort and idempotent; reports every residual resource it still finds."""
        errors = []

        def step(label, action):
            try:
                action()
            except Exception as error:  # keep going so one failure cannot strand billed resources
                errors.append("%s: %s" % (label, str(error)[:300]))

        planned = not self.runner.execute
        step("forward", self.stop_forward)
        if planned or self.state.get("cluster_created"):
            step("helm", lambda: self.runner.run([self.args.helm, "uninstall", "proof", "--namespace", NAMESPACE]))
            step("pvc", lambda: self.kube("delete", "pvc", "--all", "--wait=true", "--timeout=300s"))
            step("cluster", lambda: self.runner.run([self.args.eksctl, "delete", "cluster", "--name", self.name,
                                                     "--region", self.args.region, "--wait"], timeout=2400))
        if planned or self.state.get("ecr_created"):
            step("ecr", lambda: self.aws("ecr", "delete-repository", "--repository-name", self.repository, "--force"))
        if planned or self.state.get("bucket_created"):
            step("bucket", self.empty_and_delete_bucket)
        key = self.state.get("kms_key_id")
        if key:
            step("kms", lambda: self.aws("kms", "schedule-key-deletion", "--key-id", key, "--pending-window-in-days", "7"))
        residual = self.residual()
        report = {"status": "clean" if not errors and not residual else "residual", "errors": errors,
                  "residual": residual, "kms_deletion_pending_days": 7 if key else None}
        if self.runner.execute:
            (self.directory / "TEARDOWN.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report))
        require(report["status"] == "clean", "teardown incomplete; rerun teardown or delete the residuals listed")

    def empty_and_delete_bucket(self):
        if not self.runner.execute:
            self.aws("s3api", "delete-bucket", "--bucket", self.bucket)
            return
        listing = json.loads(self.aws("s3api", "list-object-versions", "--bucket", self.bucket, "--output", "json",
                                      mutating=False) or "{}")
        for item in listing.get("Versions", []) + listing.get("DeleteMarkers", []):
            # Governance mode needs the explicit bypass permission; compliance mode is never used here.
            self.aws("s3api", "delete-object", "--bucket", self.bucket, "--key", item["Key"],
                     "--version-id", item["VersionId"], "--bypass-governance-retention")
        self.aws("s3api", "delete-bucket", "--bucket", self.bucket)

    def residual(self):
        if not self.runner.execute:
            return []
        found = []
        clusters = json.loads(self.aws("eks", "list-clusters", "--query", "clusters", "--output", "json", mutating=False))
        if self.name in clusters:
            found.append("eks:" + self.name)
        buckets = json.loads(self.aws("s3api", "list-buckets", "--query", "Buckets[].Name", "--output", "json",
                                      mutating=False))
        if self.bucket in buckets:
            found.append("s3:" + self.bucket)
        tagged = json.loads(self.aws("resourcegroupstaggingapi", "get-resources", "--tag-filters",
                                     "Key=signal-qual,Values=" + self.run_id, "--query",
                                     "ResourceTagMappingList[].ResourceARN", "--output", "json", mutating=False))
        found.extend("tagged:" + arn for arn in tagged if ":key/" not in arn)  # KMS keys stay pending deletion
        volumes = json.loads(self.aws("ec2", "describe-volumes", "--filters",
                                      "Name=tag:kubernetes.io/created-for/pvc/namespace,Values=" + NAMESPACE,
                                      "Name=tag-key,Values=kubernetes.io/cluster/" + self.name,
                                      "--query", "Volumes[].VolumeId", "--output", "json", mutating=False))
        found.extend("ebs:" + v for v in volumes)
        return found

    # -- report ----------------------------------------------------------
    def report(self):
        data = {"status": "passed" if self.runner.execute else "dry-run", "ext_gate": "EXT-AWS", "run_id": self.run_id, "region": self.args.region,
                "architecture": self.args.arch, "kubernetes": KUBERNETES_VERSION,
                "image_id": self.state.get("image_id"), "checks": self.checks,
                "created_at": self.state.get("created_at"),
                "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "scope": "Small chart on EKS/EBS plus S3 KMS/Object Lock behaviour; Standard S3 custody runtime "
                         "and multi-AZ/account loss are not covered"}
        if self.runner.execute:
            (self.directory / "ACCEPTANCE.json").write_text(json.dumps(data, indent=2))
        return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "provision", "verify", "teardown", "all"])
    parser.add_argument("--account-id", required=True, help="Authorized 12-digit AWS account ID")
    parser.add_argument("--region", required=True)
    parser.add_argument("--arch", choices=sorted(INSTANCE_TYPES), default="amd64")
    parser.add_argument("--image", default="platform-signal:phase8")
    parser.add_argument("--run-id", default=None, help="Reuse an earlier run for verify/teardown")
    parser.add_argument("--ttl-hours", type=int, default=4)
    parser.add_argument("--execute", action="store_true", help="Create and bill real AWS resources")
    for tool in ("aws", "eksctl", "kubectl", "helm"):
        parser.add_argument("--" + tool, default=tool)
    args = parser.parse_args(argv)
    args.run_id = args.run_id or uuid.uuid4().hex[:8]
    directory = ROOT / "target" / "aws-qualification" / args.run_id
    env = os.environ.copy()
    env.pop("SIGNAL_API_TOKEN", None)
    qual = Qualification(args, Runner(args.execute, env), directory)
    try:
        if args.command == "preflight":
            qual.preflight()
        elif args.command == "provision":
            qual.provision()
        elif args.command == "verify":
            qual.verify()
        elif args.command == "teardown":
            qual.teardown()
        else:
            try:
                qual.provision()
                qual.verify()
                print(json.dumps(qual.report()))
            finally:
                qual.teardown()
    except Exception as error:
        print("FAILED: %s\nrun `check-eks.py teardown --run-id %s ...` if resources remain" % (error, args.run_id),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

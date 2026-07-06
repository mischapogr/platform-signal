#!/usr/bin/env python3
"""Qualify an existing local image in an exclusively owned, disposable kind cluster.

Requires helm, kind, kubectl and Docker. Never uses the caller's kubeconfig,
changes global tools, provisions cloud resources, builds or pushes images.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
# Published in https://github.com/kubernetes-sigs/kind/releases/tag/v0.30.0
NODE_IMAGE = "kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Gate:
    def __init__(self, args, directory):
        self.args = args
        self.name = "signal-gate-" + uuid.uuid4().hex[:12]
        self.token = secrets.token_hex(32)
        self.directory = Path(directory)
        self.env = os.environ.copy()
        self.env["KUBECONFIG"] = str(self.directory / "kubeconfig")
        self.env["KIND_EXPERIMENTAL_PROVIDER"] = "docker"
        self.env.pop("SIGNAL_API_TOKEN", None)
        self.forward = None
        self.port = None
        self.metrics_port = None
        self.cluster_attempted = False

    def run(self, command, data=None, timeout=120):
        result = subprocess.run(command, input=data, env=self.env, cwd=ROOT,
                                text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            detail = (result.stderr or result.stdout)[-3000:].replace(self.token, "[redacted]")
            detail = detail.replace(base64.b64encode(self.token.encode()).decode(), "[redacted]")
            raise RuntimeError("command failed: " + " ".join(command) + "\n" + detail)
        return result.stdout.strip()

    def kube(self, *args, data=None):
        return self.run([self.args.kubectl, "--context", "kind-" + self.name,
                         "--namespace", "gate", *args], data=data)

    @staticmethod
    def poll(check, label, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise RuntimeError("timed out waiting for " + label)

    def request(self, path, method="GET", payload=None, authorized=True, metrics=False):
        headers = {"Authorization": "Bearer " + self.token} if authorized else {}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        request = urllib.request.Request("http://127.0.0.1:" + str(self.metrics_port if metrics else self.port) + path,
                                         data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    def start_forward(self):
        self.stop_forward()
        with socket.socket() as sock, socket.socket() as metrics_sock:
            sock.bind(("127.0.0.1", 0))
            metrics_sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
            self.metrics_port = metrics_sock.getsockname()[1]
        self.forward = subprocess.Popen(
            [self.args.kubectl, "--context", "kind-" + self.name, "-n", "gate",
             "port-forward", "service/proof-signal", str(self.port) + ":8080",
             str(self.metrics_port) + ":9090"],
            env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.poll(lambda: self.request("/readyz")[0] == 200, "port-forward readiness")

    def pod(self):
        pods = json.loads(self.kube("get", "pods", "-l", "app.kubernetes.io/instance=proof", "-o", "json"))
        require(len(pods["items"]) == 1, "single writer pod")
        return pods["items"][0]

    def rows(self, name):
        status, body = self.request("/v1/" + name)
        require(status == 200, name + " query")
        result = json.loads(body)
        require(result["schema_version"] == 1, name + " response schema")
        return result[name]

    def execute(self):
        image = json.loads(self.run(["docker", "image", "inspect", self.args.image]))[0]
        require(image["Os"] == "linux", "Linux image required")
        self.cluster_attempted = True
        self.run([self.args.kind, "create", "cluster", "--name", self.name,
                  "--image", NODE_IMAGE, "--wait", "120s"], timeout=240)
        self.run([self.args.kind, "load", "docker-image", "--name", self.name, self.args.image], timeout=240)
        self.kube("create", "namespace", "gate")
        secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "gate-auth"},
                  "data": {"api-token": base64.b64encode(self.token.encode()).decode()}}
        self.kube("apply", "-f", "-", data=json.dumps(secret))
        self.kube("create", "configmap", "gate-rules", "--from-file=" +
                  str(ROOT / "rules/examples/login-failure.yaml"))
        repository, tag = self.args.image.rsplit(":", 1)
        self.run([self.args.helm, "install", "proof", str(ROOT / "deploy/helm/signal"),
                  *(["--values", str(Path(self.args.values).resolve())] if self.args.values else []),
                  "--kube-context", "kind-" + self.name, "--namespace", "gate", "--wait", "--timeout", "180s",
                  "--set", "image.repository=" + repository, "--set-string", "image.tag=" + tag,
                  "--set-string", "image.digest=", "--set", "image.pullPolicy=Never", "--set", "auth.existingSecret=gate-auth",
                  "--set", "rules.existingConfigMap=gate-rules", "--set", "rules.keys[0]=login-failure.yaml", "--set", "persistence.size=2Gi",
                  "--set", "pdb.enabled=true", "--set", "service.port=8080",
                  "--set", "service.metricsPort=9090"], timeout=240)
        self.start_forward()
        metric_status, metric_text = self.request("/metrics", authorized=False, metrics=True)
        require(metric_status == 200 and "signal_" in metric_text, "separate metrics listener")
        require(self.request("/healthz", authorized=False)[0] == 200, "liveness endpoint")
        pod = self.pod()
        container = pod["spec"]["containers"][0]
        require(container["image"] == self.args.image, "requested local image tag deployed")
        runtime_image = pod["status"]["containerStatuses"][0]["imageID"]
        reference = runtime_image.removeprefix("docker://").removeprefix("containerd://")
        runtime_details = json.loads(self.run(["docker", "exec", self.name + "-control-plane",
                                              "crictl", "inspecti", reference]))
        require(runtime_details["status"]["id"] == image["Id"],
                "runtime image ID matches inspected local image")
        require(pod["spec"]["securityContext"]["runAsUser"] == 65532, "non-root user")
        require(container["securityContext"]["readOnlyRootFilesystem"], "read-only root")
        claim = json.loads(self.kube("get", "pvc", "proof-signal", "-o", "json"))
        require(claim["status"]["phase"] == "Bound", "PVC bound")
        volume = claim["spec"]["volumeName"]
        event = {"schema_version": 1, "id": str(uuid.uuid4()),
                 "timestamp": "2026-10-06T12:00:00Z", "observed_at": "2026-10-06T12:00:01Z",
                 "source": {"type": "application", "name": "kubernetes-gate"},
                 "severity": "warn", "message": "login failed Kubernetes gate",
                 "attributes": {"nested": {"verified": True, "roles": ["reader"]}},
                 "tags": ["kubernetes", "verification"]}
        require(self.request("/v1/events", "POST", event, authorized=False)[0] == 401,
                "unauthorized ingest rejected")
        require(self.request("/v1/events", "POST", event)[0] == 202, "durable ingest accepted")
        self.poll(lambda: self.rows("events") == [event] and len(self.rows("findings")) == 1,
                  "persisted event and finding")
        findings = self.rows("findings")
        require(findings[0]["event_ids"] == [event["id"]], "finding event linkage")
        # Kill the running process inside this exclusively owned node. Waiting for
        # restart prevents a second WAL writer, unlike force-deleting a live pod.
        status = self.pod()["status"]["containerStatuses"][0]
        old_restarts = status["restartCount"]
        container_id = status["containerID"].split("://", 1)[1]
        details = json.loads(self.run(["docker", "exec", self.name + "-control-plane",
                                      "crictl", "inspect", "--output", "json", container_id]))
        pid = details["info"]["pid"]
        require(isinstance(pid, int) and pid > 1, "owned container PID")
        self.run(["docker", "exec", self.name + "-control-plane", "kill", "-9", str(pid)])
        self.poll(lambda: (lambda s: s["restartCount"] > old_restarts and s["ready"])(
            self.pod()["status"]["containerStatuses"][0]), "SIGKILL container restart")
        self.start_forward()
        self.poll(lambda: self.rows("events") == [event] and self.rows("findings") == findings,
                  "canonical rows after crash recovery")
        # A replacement pod must mount the same PVC as well.
        # Scale down and wait for the writer to exit before creating its replacement;
        # direct deletion can make a ReplicaSet start the new pod while the old
        # writer is still terminating. The installed chart always declares one.
        self.kube("scale", "deployment/proof-signal", "--replicas=0")
        self.kube("wait", "--for=delete", "pod/" + pod["metadata"]["name"], "--timeout=60s")
        self.kube("scale", "deployment/proof-signal", "--replicas=1")
        self.kube("rollout", "status", "deployment/proof-signal", "--timeout=120s")
        self.start_forward()
        self.poll(lambda: self.rows("events") == [event] and self.rows("findings") == findings,
                  "canonical rows after pod replacement")
        replacement = self.pod()
        require(replacement["metadata"]["uid"] != pod["metadata"]["uid"], "replacement pod UID")
        claim_after = json.loads(self.kube("get", "pvc", "proof-signal", "-o", "json"))
        require(claim_after["spec"]["volumeName"] == volume, "same persistent volume")
        return {"status": "passed", "image_id": image["Id"],
                          "architecture": image["Architecture"], "node_image": NODE_IMAGE,
                          "events": 1, "findings": 1, "sigkill_recovery": True,
                          "replacement_pod_pvc_recovery": True, "non_root": True,
                          "read_only_root": True, "authenticated": True, "separate_metrics": True}

    def stop_forward(self):
        if self.forward:
            process = self.forward
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            finally:
                self.forward = None

    def cleanup(self):
        try:
            self.stop_forward()
        finally:
            if self.cluster_attempted:
                self.run([self.args.kind, "delete", "cluster", "--name", self.name], timeout=120)

    def failure_diagnostics(self):
        """Read bounded diagnostics from this gate's namespace before cleanup."""
        result = {}
        for label, namespace, args in (
            ("pods", "gate", ["get", "pods", "-o", "wide"]),
            ("claims", "gate", ["get", "pvc", "-o", "wide"]),
            ("events", "gate", ["get", "events", "--sort-by=.metadata.creationTimestamp"]),
            ("logs", "gate", ["logs", "-l", "app.kubernetes.io/instance=proof", "--all-containers", "--tail=50"]),
            ("system_pods", "kube-system", ["get", "pods", "--all-namespaces", "-o", "wide"]),
            ("provisioner", "local-path-storage", ["logs", "deployment/local-path-provisioner", "--tail=50"]),
        ):
            try:
                output = self.run([self.args.kubectl, "--context", "kind-" + self.name,
                                   "--namespace", namespace, *args], timeout=10)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                output = str(error)
            output = output.replace(self.token, "[redacted]")
            output = output.replace(base64.b64encode(self.token.encode()).decode(), "[redacted]")
            result[label] = output[-10000:]
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="platform-signal:phase8")
    parser.add_argument("--values", help="External overlay values; fixed owned gate settings take precedence")
    parser.add_argument("--helm", default="helm")
    parser.add_argument("--kind", default="kind")
    parser.add_argument("--kubectl", default="kubectl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="signal-kubernetes-gate-") as directory:
        gate = Gate(args, directory)
        try:
            report = gate.execute()
        except Exception:
            if gate.cluster_attempted:
                print(json.dumps({"status": "failed", "diagnostics": gate.failure_diagnostics()}),
                      file=sys.stderr)
            raise
        finally:
            gate.cleanup()
        print(json.dumps(report))


if __name__ == "__main__":
    main()

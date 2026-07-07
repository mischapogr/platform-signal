#!/usr/bin/env python3
"""Qualify an already-built local image using an exclusively owned Compose project.

Run from any directory with `python3 scripts/check-compose.py`. This never builds
or pulls an image. Its temporary containers, network and volume are removed even
on failure. No host API token is inherited; the auth check uses a fresh sentinel.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT = 60
HTTP_TIMEOUT = 5
POLL_TIMEOUT = 20


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Gate:
    def __init__(self):
        self.project = "signal-gate-" + uuid.uuid4().hex
        self.env = os.environ.copy()
        self.env.pop("SIGNAL_API_TOKEN", None)
        self.env.update(SIGNAL_HTTP_PORT="0", SIGNAL_METRICS_PORT="0")
        self.http = None
        self.metrics = None
        self.token = None
        self.payload_sentinel = "private-compose-gate-" + secrets.token_hex(16)

    def run(self, args):
        # Never emit environment values or unfiltered inspect/log output.
        result = subprocess.run(args, cwd=ROOT, env=self.env, capture_output=True,
                                text=True, timeout=COMMAND_TIMEOUT)
        if result.returncode:
            detail = (result.stderr or result.stdout)[-3000:]
            for sentinel in (self.token, self.payload_sentinel):
                if sentinel:
                    detail = detail.replace(sentinel, "[redacted]")
            raise RuntimeError("command failed: " + " ".join(args) + "\n" + detail)
        return result.stdout.strip()

    def compose(self, *args):
        return self.run(["docker", "compose", "--env-file", "/dev/null", "-f", str(ROOT / "docker-compose.yml"),
                         "-p", self.project, *args])

    def up(self):
        self.compose("up", "-d", "--no-build", "--pull", "never")
        self.http = "http://" + self.compose("port", "signal", "8080")
        self.metrics = "http://" + self.compose("port", "signal", "9090")
        self.poll(lambda: self.request(self.http, "/readyz")[0] == 200, "readiness")

    def request(self, base, path, method="GET", payload=None, authorized=False):
        headers = {}
        if authorized:
            headers["Authorization"] = "Bearer " + self.token
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    @staticmethod
    def poll(check, label):
        deadline = time.monotonic() + POLL_TIMEOUT
        while time.monotonic() < deadline:
            try:
                if check():
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.2)
        raise RuntimeError("timed out waiting for " + label)

    def rows(self, name, authorized=False):
        status, body = self.request(self.http, "/v1/" + name, authorized=authorized)
        require(status == 200, name + " query status " + str(status))
        result = json.loads(body)
        require(result["schema_version"] == 1, name + " response schema")
        return result[name]

    def canonical(self, event, finding, authorized=False):
        events = self.rows("events", authorized)
        findings = self.rows("findings", authorized)
        require(events in ([], [event]), "event changed or duplicate rows")
        require(findings in ([], [finding]), "finding changed or duplicate rows")
        return events == [event] and findings == [finding]

    def metric_values(self):
        status, text = self.request(self.metrics, "/metrics")
        require(status == 200, "metrics status")
        return {line.split()[0]: int(line.split()[1]) for line in text.splitlines()
                if line and not line.startswith("#")}

    def check_logs(self):
        logs = self.compose("logs", "--no-color", "--tail", "200", "signal")
        require(self.payload_sentinel not in logs, "event payload leaked in container logs")
        require(not self.token or self.token not in logs, "API token leaked in container logs")

    def exit_code(self, expected):
        container = self.compose("ps", "-a", "-q", "signal")
        code = self.run(["docker", "inspect", "--format", "{{json .State.ExitCode}}", container])
        require(int(code) == expected, "unexpected container exit code " + code)

    def inspect(self):
        container = self.compose("ps", "-q", "signal")
        # Restrict the format so Config.Env (which may contain tokens) is never read.
        fields = '{"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"cap_drop":{{json .HostConfig.CapDrop}},"mounts":{{json .Mounts}},"image":{{json .Image}}}'
        info = json.loads(self.run(["docker", "inspect", "--format", fields, container]))
        require(info["user"] == "65532:65532", "container user")
        require(info["readonly"] is True, "root filesystem must be read only")
        require("ALL" in info["cap_drop"], "container capabilities")
        mounts = {mount["Destination"]: mount for mount in info["mounts"]}
        for destination, writable in [("/var/lib/signal", True),
                                      ("/etc/signal/server.yaml", False),
                                      ("/etc/signal/rules", False)]:
            require(mounts[destination]["RW"] is writable, destination + " mount access")
        require(mounts["/var/lib/signal"]["Name"] == self.project + "_signal-data",
                "volume must be exclusively owned by this gate")
        image_fields = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"tags":{{json .RepoTags}}}'
        image = json.loads(self.run(["docker", "image", "inspect", "--format", image_fields,
                                     info["image"]]))
        require(image["os"] == "linux", "image OS")
        require(image["architecture"] in ("amd64", "arm64"), "supported image architecture")
        require("platform-signal:local" in image["tags"], "local image tag")
        return {"user": info["user"], "readonly_rootfs": info["readonly"],
                "cap_drop": info["cap_drop"], "image": image}

    def execute(self):
        self.up()
        details = self.inspect()
        event = {
            "schema_version": 1, "id": str(uuid.uuid4()),
            "timestamp": "2026-10-06T12:00:00.123456789Z",
            "observed_at": "2026-10-06T12:00:01.987654321Z",
            "source": {"type": "application", "name": "compose-gate"},
            "severity": "warn", "message": "login failed " + self.payload_sentinel,
            "attributes": {"user": {"name": "example", "roles": ["reader", "writer"]},
                           "integer": 1844674407370955161600001, "nested": {"enabled": True}},
            "resource": {"kind": "service", "id": "integration-gate"},
            "trace_id": "1234567890abcdef1234567890abcdef",
            "span_id": "1234567890abcdef", "tags": ["compose", "verification"],
        }
        rule = b"auth.login-failure"
        name = len(rule).to_bytes(8, "big") + rule + uuid.UUID(event["id"]).bytes
        digest = hashlib.sha1(b"SIGNAL-FINDING01" + name).digest()[:16]
        finding = {"schema_version": 1, "id": str(uuid.UUID(bytes=digest, version=5)),
                   "rule_id": rule.decode(), "created_at": event["observed_at"],
                   "severity": "medium", "title": "Failed login detected",
                   "event_ids": [event["id"]], "attributes": {}}
        require(self.request(self.http, "/v1/events", "POST", event)[0] == 202,
                "anonymous default Compose ingest")
        self.poll(lambda: self.canonical(event, finding), "durable event and finding")
        for path in ("/healthz", "/readyz"):
            require(self.request(self.metrics, path)[0] == 200, "metrics listener " + path)
        require(self.request(self.metrics, "/v1/events")[0] == 404, "metrics query isolation")
        require(self.request(self.metrics, "/v1/events", "POST", event)[0] == 404,
                "metrics ingest isolation")
        metrics = self.metric_values()
        capacities = ["signal_queue_capacity", "signal_wal_command_capacity",
                      "signal_wal_byte_capacity", "signal_storage_command_capacity",
                      "signal_storage_byte_capacity", "signal_findings_capacity",
                      "signal_findings_command_capacity", "signal_logging_capacity",
                      "signal_logging_byte_capacity", "signal_query_capacity",
                      "signal_query_io_queue_capacity", "signal_query_memory_capacity"]
        for metric in capacities:
            require(metrics.get(metric, 0) > 0, "missing positive metric " + metric)
        require(metrics.get("signal_rules_loaded") == 1, "example rule loaded")
        require(metrics.get("signal_rule_matches_total") == 1, "example rule matched once")
        require(metrics.get("signal_findings_count") == 1, "durable finding metric")
        self.poll(lambda: self.metric_values().get("signal_queue_depth") == 0,
                  "WAL checkpoint drained")
        self.compose("stop")
        self.exit_code(0)
        self.check_logs()
        self.up()
        self.poll(lambda: self.canonical(event, finding), "SIGTERM restart identity")
        self.compose("kill", "--signal", "SIGKILL")
        self.exit_code(137)
        self.check_logs()
        self.up()
        self.poll(lambda: self.canonical(event, finding), "SIGKILL restart identity")
        self.compose("stop")
        self.exit_code(0)
        self.check_logs()
        self.token = secrets.token_hex(32)
        self.env["SIGNAL_API_TOKEN"] = self.token
        self.up()
        for path in ("/v1/events", "/v1/findings"):
            require(self.request(self.http, path)[0] == 401, "auth required on " + path)
        require(self.request(self.http, "/v1/events", "POST", event)[0] == 401,
                "auth required on ingest")
        self.poll(lambda: self.canonical(event, finding, True), "authenticated persisted queries")
        self.compose("stop")
        self.exit_code(0)
        self.check_logs()
        details.update(events=1, findings=1, event_id=event["id"], finding_id=finding["id"],
                       restarts=["SIGTERM", "SIGKILL", "authenticated"],
                       capacities={key: metrics[key] for key in capacities},
                       project=self.project, cleanup="passed")
        return details


def main():
    gate = Gate()
    try:
        result = gate.execute()
    finally:
        # Explicit project scope prevents touching default or unrelated resources.
        gate.compose("down", "--volumes", "--remove-orphans")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("Compose gate failed: " + str(error), file=sys.stderr)
        sys.exit(1)

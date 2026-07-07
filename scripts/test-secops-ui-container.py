#!/usr/bin/env python3
"""Qualify an existing immutable native image with the real SecOps browser/API.

Never builds or pulls. Reuses ContainerGate's exclusively owned Compose project,
resource bounds and cleanup. Requires Node, Playwright Core and Chromium; those
paths can be supplied explicitly without installing dependencies.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


container = load("secops_container_gate", "check-container.py")
native = load("secops_native_gate", "check-native-qualification.py")
require = container.compose_gate.require
ROOT = container.compose_gate.ROOT


def browser_stage(gate, command, output):
    """Bound output/time and reap the owned browser group, including on interrupt."""
    env = gate.env.copy()
    env["SIGNAL_UI_GATE_TOKEN"] = gate.token
    process = selector = None
    captured = bytearray()
    reason = None
    deadline = time.monotonic() + 60
    try:
        with native.defer_spawn_signals():
            process = subprocess.Popen(command, cwd=ROOT, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() >= deadline:
                reason = "browser deadline exceeded"
                break
            for key, _ in selector.select(timeout=0.05):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                elif len(captured) + len(block) > 1024 * 1024:
                    reason = "browser output exceeds 1 MiB bound"
                    break
                else:
                    captured.extend(block)
            if reason:
                break
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not selector.get_map():
                break
    finally:
        try:
            if process is not None:
                # WNOWAIT reserves the leader PID until its entire group is killed.
                for signum in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(process.pid, signum)
                    except ProcessLookupError:
                        pass
                code = process.wait(timeout=5)
                process.stdout.close()
        finally:
            if selector is not None:
                selector.close()
            text = captured.decode("utf-8", errors="replace")
            for sentinel in (gate.token, gate.payload_sentinel):
                text = text.replace(sentinel, "[redacted]")
            output.write_text(text)
    if reason:
        raise RuntimeError(reason)
    require(code == 0, "browser stage failed; inspect " + str(output))


class UiContainerGate(container.ContainerGate):
    def execute_ui(self, args, output, temporary, image, daemon):
        self.token = secrets.token_hex(32)
        self.env["SIGNAL_API_TOKEN"] = self.token
        self.up()
        details = self.inspect()
        require(details["image"]["id"] == image["id"] == args.image,
                "container must execute the selected immutable image")
        server_binary = temporary / "signal-server"
        self.run(["docker", "cp", self.compose("ps", "-q", "signal") +
                  ":/usr/local/bin/signal-server", str(server_binary)])
        binary_hash = native.verify_binary(server_binary, args.expect_architecture)
        observed = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).replace(microsecond=123000)
        stamp = observed - datetime.timedelta(days=10)
        timestamp = lambda value: value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        event = {
            "schema_version": 1, "id": str(uuid.uuid4()), "timestamp": timestamp(stamp),
            "observed_at": timestamp(observed),
            "source": {"type": "application", "name": "ui-container-gate"},
            "severity": "warn",
            "message": "login failed " + self.payload_sentinel +
                       ' <img src=x onerror="globalThis.UI_CONTAINER_XSS=true">',
            "attributes": {"integer": 9007199254740993, "nested": {"retained": True}},
            "resource": {"kind": "service", "id": "ui-container-gate"}, "tags": [],
        }
        unrelated = {**event, "id": str(uuid.uuid4()),
                     "source": {"type": "fixture.unrelated"},
                     "message": "Message-only reference " + event["id"], "attributes": {}}
        rule = b"auth.login-failure"
        name = len(rule).to_bytes(8, "big") + rule + uuid.UUID(event["id"]).bytes
        digest = hashlib.sha1(b"SIGNAL-FINDING01" + name).digest()[:16]
        finding = {"schema_version": 1, "id": str(uuid.UUID(bytes=digest, version=5)),
                   "rule_id": rule.decode(), "created_at": event["observed_at"],
                   "severity": "medium", "title": "Failed login detected",
                   "event_ids": [event["id"]], "attributes": {}}
        for endpoint in ("/v1/events", "/v1/findings"):
            require(self.request(self.http, endpoint)[0] == 401, "API requires authentication")
        for payload in (event, event, unrelated):
            require(self.request(self.http, "/v1/events", "POST", payload, True)[0] == 202,
                    "authenticated synced WAL admission")

        def durable():
            status, body = self.request(self.http, "/v1/events?event_id=" + event["id"], authorized=True)
            return (status == 200 and json.loads(body)["events"] == [event, event] and
                    self.rows("findings", True) == [finding] and
                    len(self.rows("events", True)) == 3)

        self.poll(durable, "persisted duplicate exact identities and deterministic finding")
        assets = {name: native.sha256(ROOT / "apps/signal-server/ui" / name)
                  for name in ("index.html", "app.js", "style.css")}
        fixture = {"event_id": event["id"], "unrelated_id": unrelated["id"],
                   "missing_id": str(uuid.uuid4()), "finding_id": finding["id"],
                   "event_timestamp": event["timestamp"], "raw_integer": "9007199254740993",
                   "assets_sha256": assets}
        fixture_path = output / "browser-fixture.json"
        fixture_path.write_text(json.dumps(fixture, indent=2) + "\n")
        browser_reports = []
        for stage in ("initial", "restart"):
            report_path = output / ("browser-" + stage + ".json")
            command = [args.node, str(ROOT / "scripts/test-secops-ui-container.cjs"),
                       "--base-url", self.http, "--fixture", str(fixture_path),
                       "--output", str(report_path)]
            for option in ("playwright_path", "browser_path"):
                if getattr(args, option):
                    command.extend(["--" + option.replace("_", "-"), getattr(args, option)])
            browser_stage(self, command, output / ("browser-" + stage + ".log"))
            report = native.bounded_json(report_path)
            require(report["status"] == "passed" and report["passed"] == 7,
                    "complete real-container browser checks")
            browser_reports.append(report)
            self.compose("stop")
            self.exit_code(0)
            self.check_logs()
            if stage == "initial":
                self.up()
                require(self.inspect()["image"]["id"] == image["id"], "restart image unchanged")
                self.poll(durable, "restart preserves identical retained evidence and finding")
        details.update(scope="Native immutable container + real Chromium + WAL/Parquet/findings and graceful restart; no mock API; not EKS, HA, remote CI or release qualification",
                       host={"os": native.platform.system(), "architecture": native.platform.machine()},
                       daemon=daemon, binary_sha256=binary_hash, server_elf="native ELF64 verified",
                       events=3, exact_identity_copies=2, findings=1,
                       browser_reports=browser_reports, browser_checks=14,
                       assets_sha256=assets, restarts=["SIGTERM"], project=self.project)
        return details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Immutable local sha256 image ID")
    parser.add_argument("--expect-architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--playwright-path")
    parser.add_argument("--browser-path")
    args = parser.parse_args()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "an immutable image ID is required")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = {"status": "failed", "image": args.image, "started_at": started}
    with tempfile.TemporaryDirectory(prefix="signal-ui-container-") as directory:
        temporary = Path(directory)
        override = temporary / "override.json"
        override.write_text(json.dumps({"services": {"signal": {
            "image": args.image, "mem_limit": "1g", "cpus": 2.0, "pids_limit": 128}}}))
        gate = UiContainerGate(args.image, args.expect_architecture, override)
        try:
            daemon = json.loads(gate.run(["docker", "info", "--format",
                                         '{"os":{{json .OSType}},"architecture":{{json .Architecture}}}']))
            image = json.loads(gate.run(["docker", "image", "inspect", "--format",
                                        '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}}}', args.image]))
            native.verify_native(args.expect_architecture, native.platform.system(),
                                 native.platform.machine(), daemon, image)
            result.update(gate.execute_ui(args, output, temporary, image, daemon), status="passed")
        except BaseException as error:
            text = str(error)
            for sentinel in (gate.token, gate.payload_sentinel):
                if sentinel:
                    text = text.replace(sentinel, "[redacted]")
            result["error"] = text
            raise
        finally:
            try:
                gate.compose("down", "--volumes", "--remove-orphans")
                result["cleanup"] = "passed"
            except BaseException:
                result.update(status="failed", cleanup="failed")
                raise
            finally:
                result["captured_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


def interrupted(signum, _frame):
    raise KeyboardInterrupt("interrupted by signal " + str(signum))


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print("SecOps UI container gate failed: " + str(error), file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Check an external SDK overlay against an unmodified local SIGNAL server.

The private runner's --check contract is a bounded JSON report containing event,
findings and overlay-relative rule_directories. No policy fixtures live here.
"""

import argparse
import http.client
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 1024 * 1024


class GateError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def read_json(path):
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "fixture exceeds gate limit")
    return json.loads(data)


def runner_report(binary, overlay, environment):
    """Drain both pipes under one deadline and a combined finite byte budget."""
    process = subprocess.Popen(
        [str(binary), "--check"],
        env=dict(environment, SIGNAL_OVERLAY_PATH=str(overlay)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = bytearray()
    total = 0
    deadline = time.monotonic() + 10
    try:
        with selectors.DefaultSelector() as selector:
            for handle in (process.stdout, process.stderr):
                os.set_blocking(handle.fileno(), False)
                selector.register(handle, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "overlay runner deadline expired")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), min(4096, MAX_BYTES - total + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    require(total <= MAX_BYTES, "overlay runner output exceeds gate limit")
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
        require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
                "overlay runner rejected configuration or fixture")
        return json.loads(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, type=Path,
                        help="compiled executable in the separate private repository")
    parser.add_argument("--overlay", type=Path, help="overrides SIGNAL_OVERLAY_PATH")
    parser.add_argument("--server", type=Path, default=ROOT / "target/debug/signal-server")
    args = parser.parse_args()
    selected = args.overlay if args.overlay is not None else os.environ.get("SIGNAL_OVERLAY_PATH")
    require(bool(selected), "supply --overlay or SIGNAL_OVERLAY_PATH")
    overlay = Path(selected).resolve(strict=True)
    runner = args.runner.resolve(strict=True)
    server = args.server.resolve(strict=True)
    require(overlay.is_dir() and not overlay.is_relative_to(ROOT),
            "overlay must be outside the OSS repository")
    require(runner.is_file() and not runner.is_relative_to(ROOT),
            "runner must belong to the external repository")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    report = runner_report(runner, overlay, environment)
    require(isinstance(report, dict), "invalid overlay report")
    event, findings, relative_dirs = (report.get(key) for key in ("event", "findings", "rule_directories"))
    require(isinstance(event, dict) and isinstance(findings, list) and 0 < len(findings) <= 256,
            "overlay must supply one enriched event and expected detections")
    require(isinstance(relative_dirs, list) and 0 < len(relative_dirs) <= 16,
            "invalid private rule directories")
    rule_dirs = []
    for relative in relative_dirs:
        require(isinstance(relative, str) and len(relative) <= 4096 and not Path(relative).is_absolute(),
                "invalid private rule directory path")
        directory = (overlay / relative).resolve(strict=True)
        require(directory.is_dir() and directory.is_relative_to(overlay),
                "private rule directory escapes overlay")
        rule_dirs.append(str(directory))
    expected = read_json(overlay / "fixtures/expected/enriched-security-event.json")
    original = read_json(overlay / "fixtures/input/security-event.json")
    require(event == expected, "enriched event differs from private expected fixture")
    require(all(event.get(key) == original.get(key)
                for key in ("schema_version", "id", "timestamp", "observed_at")),
            "overlay changed canonical event identity")
    require(all(isinstance(item, dict) and item.get("event_ids") == [event.get("id")]
                for item in findings), "expected finding has invalid event reference")

    with tempfile.TemporaryDirectory(prefix="signal-overlay-gate-") as temporary:
        data = Path(temporary)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        token = "overlay-gate-local-token"
        env = dict(environment, SIGNAL_LISTEN=f"127.0.0.1:{port}", SIGNAL_API_TOKEN=token,
                   SIGNAL_WAL_DIR=str(data / "wal"), SIGNAL_STORAGE_DIR=str(data / "events"),
                   SIGNAL_FINDINGS_DIR=str(data / "findings"), SIGNAL_STORAGE_FLUSH_MS="10",
                   SIGNAL_RULE_DIRS=os.pathsep.join(rule_dirs))
        process = None

        def request(method, path, body=None, authenticated=True):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                headers = {"Content-Type": "application/json"}
                if authenticated:
                    headers["Authorization"] = "Bearer " + token
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read(MAX_BYTES + 1)
                require(len(payload) <= MAX_BYTES, "server response exceeds gate limit")
                return response.status, json.loads(payload)
            finally:
                connection.close()

        def wait_for(predicate, message):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                require(process.poll() is None, "server exited during overlay check")
                try:
                    if predicate():
                        return
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.05)
            raise GateError(message)

        def ready():
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request("GET", "/readyz")
                response = connection.getresponse()
                response.read(MAX_BYTES + 1)
                return response.status == 200
            finally:
                connection.close()

        def start():
            nonlocal process
            process = subprocess.Popen([str(server)], env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_for(ready, "server did not become ready with private rules")

        def persisted():
            status, events = request("GET", "/v1/events?limit=1000")
            other_status, detections = request("GET", "/v1/findings?limit=1000")
            require(status == other_status == 200, "persisted query failed")
            return (events.get("events") == [expected]
                    and sorted(detections.get("findings", []), key=lambda row: row["id"])
                    == sorted(findings, key=lambda row: row["id"]))

        try:
            start()
            require(request("GET", "/v1/events", authenticated=False)[0] == 401,
                    "unauthenticated event query was accepted")
            status, admission = request("POST", "/v1/events", json.dumps(event).encode())
            require(status == 202 and admission.get("accepted") == 1,
                    "enriched event was not admitted")
            wait_for(persisted, "event or private finding did not persist")
            process.send_signal(signal.SIGKILL)
            require(process.wait(timeout=5) == -signal.SIGKILL, "forced server stop failed")
            start()
            wait_for(persisted, "event or private finding changed after restart")
            process.send_signal(signal.SIGTERM)
            require(process.wait(timeout=15) == 0, "graceful server shutdown failed")
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    print(f"External overlay gate passed: 1 event, {len(findings)} finding(s), SIGKILL recovery and SIGTERM")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        # Private fixture values, paths, tokens and provider diagnostics remain private.
        print("External overlay gate failed; check local configuration and private fixtures", file=sys.stderr)
        sys.exit(1)

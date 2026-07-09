#!/usr/bin/env python3
"""Real bounded monolith coverage HTTP/history/bootstrap/restart gate; synthetic assertions."""
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2]).resolve()
    fixture = json.loads((Path(__file__).parents[1] / "fixtures/source-coverage/backend-vectors.json").read_text())
    token = "coverage-process-observer-secret"
    operator = "coverage-process-operator-secret"
    payload_secret = "coverage-process-private-proof-sentinel"
    config = {
        "schema_version": 1, "directory": str(root / "coverage"),
        "limits": {"max_payloads": 128, "max_identities": 128, "max_bindings": 32,
                   "max_ledger_bytes": 4194304, "max_database_pages": 1024,
                   "max_journal_bytes": 146800640, "operation_capacity": 4,
                   "transient_memory_bytes": 16777216, "worker_memory_bytes": 8388608,
                   "max_vm_steps": 10000000, "operation_timeout_ms": 1000},
        "scopes": [{"binding_json": json.dumps(fixture["bindings"][0]["input"]),
                    "profile_json": json.dumps(fixture["profiles"][0]["input"]),
                    "authority_revision": "fixture-v1", "token_env": "COVERAGE_FIXTURE_TOKEN",
                    "max_report_age_seconds": 60, "max_clock_skew_seconds": 2,
                    "payload_retention_seconds": 300, "identity_retention_seconds": 600}],
    }
    coverage_config = root / "coverage.json"
    coverage_config.write_text(json.dumps(config))
    server_config = root / "server.yaml"
    server_config.write_text("schema_version: 1\ncoverage:\n  config: " + json.dumps(str(coverage_config)) + "\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SIGNAL_")}
    env.update(SIGNAL_CONFIG=str(server_config), SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_API_TOKEN=operator,
               SIGNAL_WAL_DIR=str(root / "wal"), SIGNAL_STORAGE_DIR=str(root / "events"),
               SIGNAL_FINDINGS_DIR=str(root / "findings"), SIGNAL_REQUEST_TIMEOUT_MS="500",
               COVERAGE_FIXTURE_TOKEN=token)
    process, generation, port = None, 0, 0
    assertions = []

    def command(arguments=(), overrides=None):
        result = subprocess.run([binary, *arguments], env=dict(env, **(overrides or {})), capture_output=True, timeout=15)
        assert token.encode() not in result.stderr and operator.encode() not in result.stderr
        return result

    def request(method, path, body=b"", credential=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            headers = {"Content-Type": "application/json"}
            if credential is not None:
                headers["Authorization"] = "Bearer " + credential
            connection.request(method, path, body, headers)
            reply = connection.getresponse()
            data = reply.read(524289)
            assert len(data) <= 524288
            if path.startswith("/v1/coverage/"):
                assert reply.getheader("cache-control") == "no-store"
                return reply.status, json.loads(data)
            return reply.status, data
        finally:
            connection.close()

    def start():
        nonlocal process, port, generation
        generation += 1
        log = root / f"coverage-server-{generation}.log"
        with log.open("wb") as output:
            process = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=output)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None, "server failed before listening"
            for line in log.read_text().splitlines():
                try:
                    address = json.loads(line).get("fields", {}).get("listen")
                except ValueError:
                    continue
                if address:
                    port = int(address.rsplit(":", 1)[1])
                    assert request("GET", "/readyz")[0] == 200
                    return
            time.sleep(0.01)
        raise TimeoutError("coverage server startup")

    def stop(crash=False):
        process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
        assert process.wait(timeout=15) == (-signal.SIGKILL if crash else 0)

    try:
        assert command().returncode != 0
        assert not (root / "coverage").exists()
        assert command(["--initialize-coverage"]).returncode == 0
        identity = (root / "coverage" / "identity").read_bytes()
        assert command(["--initialize-coverage"]).returncode != 0
        assert (root / "coverage" / "identity").read_bytes() == identity
        assertions.append("explicit bootstrap; missing root and duplicate bootstrap fail closed")
        record = json.loads(fixture["chains"][0]["commits"][0]["input"]["raw_utf8"])
        at = datetime.now(timezone.utc) - timedelta(seconds=2)
        stamp = lambda delta: (at + timedelta(seconds=delta)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        record.update(record_id=str(uuid.uuid4()), coverage_start=stamp(-300), coverage_end=stamp(0),
                      last_verified_at=stamp(0), valid_until=stamp(60))
        record["provenance"]["observed_at"] = stamp(0)
        record["provenance"]["proof_refs"] = ["fixture://" + payload_secret]
        raw = json.dumps(record, indent=2).encode()
        url = "/v1/coverage/records/" + record["record_id"]
        start()
        for wrong in (None, operator, "wrong-credential"):
            assert request("POST", url, b"x" * 65537, wrong)[0] == 401
        status, accepted = request("POST", url, raw, token)
        assert status == 201 and accepted["current_health"] == "unknown"
        status, replay = request("POST", url, raw, token)
        assert status == 200 and replay["receipt"] == accepted["receipt"]
        status, read = request("GET", url, credential=token)
        assert status == 200 and read["raw"].encode() == raw and read["receipt"] == accepted["receipt"]
        assertions.append("actual HTTP scoped auth, immutable original/pin/receipt, replay without healing")
        # A stalled authorized chunked body must not acquire a durable sequence.
        stalled = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            stalled.sendall((f"POST {url} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
                             "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").encode())
            reply = http.client.HTTPResponse(stalled)
            reply.begin()
            assert reply.status == 408
            reply.read()
        finally:
            stalled.close()
        status, page = request("GET", "/v1/coverage/history", credential=token)
        assert status == 200 and page["frontier"] == "1" and len(page["records"]) == 1
        assert page["current_health"] == "unknown" and page["continuation"] is None
        assertions.append("actual stalled body deadline; bounded history remains one immutable commit")
        stop(crash=True)
        start()
        status, read = request("GET", url, credential=token)
        assert status == 200 and read["receipt"] == accepted["receipt"] and read["raw"].encode() == raw
        assert read["current_health"] == "unknown"
        stop()
        assertions.append("SIGKILL reopen preserves exact receipt/original and unknown current health")
        # Fresh startup configuration retires admissions and rotates the source credential.
        config["scopes"][0]["profile_json"] = None
        config["scopes"][0]["authority_revision"] = "fixture-v2"
        coverage_config.write_text(json.dumps(config))
        env["COVERAGE_FIXTURE_TOKEN"] = token + "-rotated"
        start()
        assert request("GET", url, credential=token)[0] == 401
        status, replay = request("POST", url, raw, env["COVERAGE_FIXTURE_TOKEN"])
        assert status == 200 and replay["receipt"] == accepted["receipt"]
        assert replay["receipt"]["authority_revision"] == "fixture-v1" and replay["current_health"] == "unknown"
        record["record_id"] = str(uuid.uuid4())
        assert request("POST", "/v1/coverage/records/" + record["record_id"], json.dumps(record).encode(), env["COVERAGE_FIXTURE_TOKEN"])[0] == 503
        stop()
        assertions.append("credential rotation and retired-profile replay preserve original pins; new admission denied")
        for log in root.glob("coverage-server-*.log"):
            text = log.read_text()
            assert token not in text and operator not in text and payload_secret not in text
        (root / "coverage-process-result.json").write_text(json.dumps({"status": "passed", "assertions": assertions,
            "limits": "Real local AMD64 monolith/SQLite/HTTP only. Synthetic reports do not prove native source continuity or external qualification."}, indent=2) + "\n")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    print("Coverage process gate passed: " + "; ".join(assertions))


if __name__ == "__main__":
    main()

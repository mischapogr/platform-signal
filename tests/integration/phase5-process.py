#!/usr/bin/env python3
"""Real coordinated WAL/event/finding publication, crash recovery and query gate."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid
import zlib


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2]).resolve()
    token = "phase5-redaction-sentinel"
    payload_secret = "phase5-private-event-payload"
    clean_env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    rules = root / "rules"
    rules.mkdir()
    rule_text = """apiVersion: signal.dev/v1
kind: Rule
metadata:
  id: auth.login-failure
  name: Failed login example
spec:
  severity: medium
  match:
    all:
      - field: source.type
        eq: application
      - field: message
        contains: login failed
      - field: attributes.user.name
        exists: true
  finding:
    title: Failed login detected
"""
    (rules / "login.yaml").write_text(rule_text)
    (rules / "high.yaml").write_text("""apiVersion: signal.dev/v1
kind: Rule
metadata:
  id: severity.high
  name: Nested severity example
spec:
  severity: critical
  match:
    any:
      - field: attributes.nested.index
        eq: 2
      - field: severity
        eq: error
  finding:
    title: High severity detected
""")
    settings = root / "settings"
    settings.mkdir()
    config = settings / "server.yaml"
    # YAML supplies real rules; environment takes precedence over invalid YAML listen.
    config.write_text("schema_version: 1\nserver:\n  listen: invalid-address\nrules:\n  directories:\n    - " + json.dumps(str(rules)) + "\n")
    process = None
    host, port, generation = "127.0.0.1", 0, 0
    active = root / "core"
    env = {}

    def environment(directory, overrides=None):
        result = dict(clean_env, SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_API_TOKEN=token,
                      SIGNAL_WAL_DIR=str(directory / "wal"), SIGNAL_STORAGE_DIR=str(directory / "events"),
                      SIGNAL_FINDINGS_DIR=str(directory / "findings"), SIGNAL_CONFIG=str(config),
                      SIGNAL_STORAGE_FLUSH_MS="10")
        result.update(overrides or {})
        return result

    def request(method, path, body=None, auth=True):
        connection = http.client.HTTPConnection(host, port, timeout=5)
        try:
            headers = {"Content-Type": "application/json"}
            if auth:
                headers["Authorization"] = "Bearer " + token
            connection.request(method, path, json.dumps(body) if body is not None else None, headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def start(directory=None, overrides=None, cli_config=False):
        nonlocal process, host, port, generation, active, env
        active = directory or active
        active.mkdir(exist_ok=True)
        env = environment(active, overrides)
        generation += 1
        log = root / f"slice-server-{generation}.log"
        command = [binary]
        if cli_config:
            command += ["--config", str(config)]
            env.pop("SIGNAL_CONFIG")
        with log.open("wb") as logs:
            process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=logs)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None, "server exited before listening: " + log.read_text()
            for line in log.read_text().splitlines():
                try:
                    address = json.loads(line).get("fields", {}).get("listen")
                except ValueError:
                    continue
                if address:
                    host, port_text = address.rsplit(":", 1)
                    port = int(port_text)
                    assert request("GET", "/readyz")[0] == 200
                    return
            time.sleep(0.01)
        raise TimeoutError("server startup deadline exceeded")

    def stop(kill=False):
        process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
        assert process.wait(timeout=15) == (-signal.SIGKILL if kill else 0)

    def rows(endpoint="events", params=None, status=200):
        code, body = request("GET", "/v1/" + endpoint + "?" + urllib.parse.urlencode(params or {}))
        assert code == status, f"{endpoint} query returned {code}: {body!r}"
        result = json.loads(body)
        assert result["schema_version"] == 1
        return result[endpoint] if status == 200 else result

    def checkpoint():
        data = (active / "wal" / "checkpoint").read_bytes()
        assert len(data) == 28 and data[:8] == b"SIGACK01"
        assert zlib.crc32(data[:24]) == struct.unpack_from("<I", data, 24)[0]
        return struct.unpack_from("<Q", data, 8)[0]

    def wait_for(predicate, message):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, "server exited: " + message
            if predicate():
                return
            time.sleep(0.02)
        raise TimeoutError(message)

    def event(index):
        return {"schema_version": 1, "id": str(uuid.UUID(int=index + 1)),
                "timestamp": f"2026-10-06T{index:02d}:00:00.123456789Z",
                "observed_at": f"2026-10-06T12:{index:02d}:00.123456789Z",
                "source": {"type": "application", "name": "slice-fixture"},
                "severity": "error" if index == 2 else "info",
                "message": payload_secret + (" login failed" if index in (0, 2, 4) else " passed"),
                "attributes": {"user": {"name": "fixture-user"}, "nested": {"index": index,
                               "array": [None, True, {"large": 1844674407370955161600001}]}},
                "tags": ["integration"]}

    def finding(rule, row, severity, title):
        name = struct.pack(">Q", len(rule)) + rule.encode() + uuid.UUID(row["id"]).bytes
        digest = bytearray(hashlib.sha1(b"SIGNAL-FINDING01" + name).digest()[:16])
        digest[6] = (digest[6] & 15) | 80
        digest[8] = (digest[8] & 63) | 128
        return {"schema_version": 1, "id": str(uuid.UUID(bytes=bytes(digest))), "rule_id": rule,
                "created_at": row["observed_at"], "severity": severity, "title": title,
                "event_ids": [row["id"]], "attributes": {}}

    def findings(expected):
        result = []
        for row in expected:
            index = row["attributes"]["nested"]["index"]
            if index in (0, 2, 4):
                result.append(finding("auth.login-failure", row, "medium", "Failed login detected"))
            if index == 2:
                result.append(finding("severity.high", row, "critical", "High severity detected"))
        return sorted(result, key=lambda row: (row["created_at"], row["id"]))

    def accept(expected):
        code, body = request("POST", "/v1/events/batch", {"events": expected})
        result = json.loads(body)
        assert code == 202 and result["event_ids"] == [row["id"] for row in expected]
        assert result["accepted"] == len(expected) and result["rejected"] == 0

    def exact(expected):
        assert rows() == expected
        assert rows("findings") == findings(expected)

    def startup_failure(overrides):
        result = subprocess.run([binary], env=environment(root / "invalid", overrides),
                                capture_output=True, timeout=15)
        assert result.returncode != 0, "invalid startup accepted"
        for line in result.stderr.decode().splitlines():
            try:
                assert not json.loads(line).get("fields", {}).get("listen"), "invalid startup listened"
            except ValueError:
                pass
        assert token.encode() not in result.stderr and payload_secret.encode() not in result.stderr

    try:
        expected = [event(index) for index in range(4)]
        start(overrides={"SIGNAL_STORAGE_FLUSH_MS": "60000"})
        for endpoint in ("events", "findings"):
            code, body = request("GET", "/v1/" + endpoint, auth=False)
            assert code == 401 and json.loads(body)["schema_version"] == 1
        accept(expected)
        # Below batch threshold and a 60s interval: prove accepted rows remain WAL-only.
        assert rows() == [] and rows("findings") == [] and checkpoint() == 0
        stop(kill=True)
        start(cli_config=True)
        wait_for(lambda: rows() == expected and rows("findings") == findings(expected) and checkpoint() == 4,
                 "WAL replay did not publish both stores and checkpoint")
        exact(expected)
        target = findings(expected)
        for key, value in {"severity": "critical", "rule_id": "severity.high"}.items():
            assert rows("findings", {key: value}) == [row for row in target if row[key] == value]
        assert rows("findings", {"severity": "low"}) == []
        assert rows("findings", {"severity": "high"}) == []
        assert rows("findings", {"limit": "2"}) == target[:2]
        assert rows("findings", {"from": expected[2]["observed_at"]}) == target[1:]
        assert rows("findings", {"to": expected[2]["observed_at"]}) == target[:1]
        assert rows("findings", {"from": expected[0]["observed_at"], "to": expected[2]["observed_at"],
                                  "severity": "medium", "rule_id": "auth.login-failure"}) == target[:1]
        for invalid in ({"limit": "0"}, {"limit": "1001"}, {"severity": "error"}, {"rule_id": ""},
                        {"from": "invalid"}, {"unknown": "x"}, {"from": expected[2]["observed_at"],
                        "to": expected[0]["observed_at"]}):
            assert "error" in rows("findings", invalid, 400)
        code, body = request("GET", "/v1/findings?limit=1&limit=2")
        assert code == 400 and json.loads(body)["schema_version"] == 1
        stop()
        start(overrides={"SIGNAL_STORAGE_FLUSH_MS": "60000"})
        accept([event(4)])
        expected.append(event(4))
        stop()  # Drain accepted rows on SIGTERM without awaiting publication.
        start()
        exact(expected)
        assert checkpoint() == 5
        stop()
        start(overrides={"SIGNAL_FINDINGS_QUERY_BYTES": "288"})
        assert "error" in rows("findings", status=413)
        stop()

        # Persist one prefix, then force a finding write failure after Parquet publish.
        quota_root = root / "quota"
        start(quota_root, {"SIGNAL_STORAGE_BATCH_EVENTS": "1"})
        accept([event(0)])
        wait_for(lambda: rows("findings") == findings([event(0)]) and checkpoint() == 1, "prefix not durable")
        stop()
        journal_bytes = (quota_root / "findings" / "findings.journal").stat().st_size
        start(overrides={"SIGNAL_FINDINGS_BYTES": str(journal_bytes), "SIGNAL_STORAGE_BATCH_EVENTS": "1"})
        accept([event(2)])
        assert process.wait(timeout=20) != 0, "finding quota did not fail closed"
        assert checkpoint() == 1, "WAL acknowledged the unpersisted finding"
        start(overrides={"SIGNAL_STORAGE_BATCH_EVENTS": "1"})
        wait_for(lambda: rows("findings") == findings([event(0), event(2)]) and checkpoint() == 2,
                 "quota recovery failed to retry findings after existing Parquet")
        exact([event(0), event(2)])
        code, body = request("GET", "/metrics")
        assert code == 200
        metrics = dict(line.split() for line in body.decode().splitlines() if not line.startswith("#"))
        assert int(metrics["signal_storage_replayed_total"]) >= 1, "failed event was not already in Parquet"
        stop()
        start()
        exact([event(0), event(2)])
        stop()

        # The configured telemetry listener exposes health/metrics without the API.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            metrics_port = reservation.getsockname()[1]
        start(overrides={"SIGNAL_METRICS_LISTEN": f"127.0.0.1:{metrics_port}"})
        api_port = port
        port = metrics_port
        assert request("GET", "/metrics")[0] == 200
        assert request("GET", "/readyz")[0] == 200
        assert request("GET", "/v1/events")[0] == 404
        port = api_port
        exact([event(0), event(2)])
        stop()

        # Real startup must apply rule limits from YAML and environment precedence.
        limited_config = settings / "limited-rules.yaml"
        limited_config.write_text(config.read_text() + "  max_document_bytes: 1\n")
        startup_failure({"SIGNAL_CONFIG": str(limited_config)})
        valid_limits = settings / "valid-rule-limits.yaml"
        valid_limits.write_text(config.read_text() + "  max_document_bytes: 65536\n")
        start(overrides={"SIGNAL_CONFIG": str(valid_limits)})
        exact([event(0), event(2)])
        stop()
        start(overrides={"SIGNAL_CONFIG": str(limited_config),
                         "SIGNAL_RULES_MAX_DOCUMENT_BYTES": "65536"})
        exact([event(0), event(2)])
        stop()

        bad_rules = root / "bad-rules"
        bad_rules.mkdir()
        (bad_rules / "invalid.yaml").write_text(rule_text.replace("exists: true", "unsupported: " + token))
        startup_failure({"SIGNAL_RULE_DIRS": str(bad_rules)})
        (bad_rules / "invalid.yaml").write_text(rule_text)
        (bad_rules / "duplicate.yaml").write_text(rule_text)
        startup_failure({"SIGNAL_RULE_DIRS": str(bad_rules)})
        bad_config = settings / "invalid.yaml"
        bad_config.write_text("schema_version: 1\ningest:\n  api_token: " + token + "\nunknown: invalid\n")
        startup_failure({"SIGNAL_CONFIG": str(bad_config)})
        for log in root.glob("slice-server-*.log"):
            assert token not in log.read_text() and payload_secret not in log.read_text(), "secret appeared in logs"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    print("Process slice gate passed: canonical events/findings, YAML/env/CLI, nested rules, all finding filters, auth, limits, SIGKILL WAL replay, SIGTERM drain, fail-closed quota error after Parquet publication, no early ack, exact recovery and redaction")


if __name__ == "__main__":
    main()

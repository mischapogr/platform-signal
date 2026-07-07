#!/usr/bin/env python3
"""Real HTTP ingest -> Parquet -> URL query, SIGKILL/restart and query bounds."""
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2]).resolve()
    token = "phase4-redaction-sentinel"
    payload_secret = "phase4-private-event-payload"
    env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    env.update(SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_API_TOKEN=token,
               SIGNAL_FINDINGS_DIR=str(root / "findings"), SIGNAL_WAL_DIR=str(root / "wal"), SIGNAL_STORAGE_DIR=str(root / "events"),
               SIGNAL_STORAGE_FLUSH_MS="10")
    process = None
    host, port, generation = "127.0.0.1", 0, 0
    expected = []
    for index in range(4):
        expected.append({"schema_version": 1, "id": str(uuid.uuid4()),
                         "timestamp": f"2026-10-06T{index:02d}:00:00.123456789Z",
                         "observed_at": "2026-10-06T12:00:00.123456789Z",
                         "source": {"type": "application", "name": "query-fixture"},
                         "severity": "error" if index == 1 else "info",
                         "message": payload_secret + (" failed" if index == 1 else " passed"),
                         "attributes": {"environment": "prod" if index == 1 else "dev",
                                        "nested": {"active": index == 1, "index": index}},
                         "resource": {"kind": "host", "id": "fixture-host", "account_id": "fixture-account"},
                         "tags": ["integration"]})

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

    def start(overrides=None):
        nonlocal process, host, port, generation
        generation += 1
        log = root / f"query-server-{generation}.log"
        with log.open("wb") as logs:
            process = subprocess.Popen([binary], env=dict(env, **(overrides or {})),
                                       stdout=subprocess.DEVNULL, stderr=logs)
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

    def stop():
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == 0

    def query(params=None, status=200):
        code, body = request("GET", "/v1/events?" + urllib.parse.urlencode(params or {}))
        assert code == status, f"query returned {code}: {body!r}"
        result = json.loads(body)
        assert result["schema_version"] == 1
        return result

    def rows(params=None):
        return query(params)["events"]

    def exact_queries():
        assert rows() == expected
        assert rows({"order": "desc", "limit": "2"}) == list(reversed(expected))[:2]
        filters = {"from": "2026-10-06T01:00:00Z", "to": "2026-10-06T02:00:00Z",
                   "contains": "failed", "severity": "error", "source_type": "application",
                   "source_name": "query-fixture", "resource_kind": "host", "resource_id": "fixture-host",
                   "account": "fixture-account", "attribute.environment": "prod",
                   "attribute.nested.active": "true", "attribute.nested.index": "1"}
        for key, value in filters.items():
            # Shared fixture fields match all rows; selective fields match the error row.
            shared = key in ("source_type", "source_name", "resource_kind", "resource_id", "account")
            actual = rows({key: value})
            if shared:
                target = expected
            elif key == "from":
                target = expected[1:]
            elif key == "to":
                target = expected[:2]
            else:
                target = [expected[1]]
            assert actual == target, key
        assert rows({"source": "application", "resource": "fixture-host"}) == expected
        assert rows(filters) == [expected[1]]
        assert rows({"from": "2026-10-06T04:00:00Z"}) == []
        for invalid in ({"limit": "0"}, {"limit": "1001"}, {"order": "random"},
                        {"from": "invalid"}, {"unknown": "x"}, {"attribute..x": "x"}):
            assert "error" in query(invalid, 400)

    try:
        start()
        code, body = request("GET", "/v1/events", auth=False)
        assert code == 401 and json.loads(body)["schema_version"] == 1
        code, body = request("POST", "/v1/events/batch", {"events": expected})
        assert code == 202 and json.loads(body)["event_ids"] == [row["id"] for row in expected]
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if len(rows()) == len(expected):
                break
            time.sleep(0.02)
        else:
            raise TimeoutError("persisted queries did not become visible")
        exact_queries()
        status, metrics_body = request("GET", "/metrics")
        assert status == 200
        metrics = dict(line.split() for line in metrics_body.decode().splitlines() if not line.startswith("#"))
        assert int(metrics["signal_query_completed_total"]) > 0
        assert int(metrics["signal_query_scanned_files_total"]) > 0
        assert int(metrics["signal_query_latency_microseconds_total"]) > 0
        assert metrics["signal_query_depth"] == "0"
        assert metrics["signal_query_capacity"] == "4"
        process.kill()
        assert process.wait(timeout=3) == -signal.SIGKILL
        start()
        exact_queries()
        stop()
        start({"SIGNAL_QUERY_RESPONSE_BYTES": "128"})
        assert "error" in query(status=413)
        stop()
        invalid = subprocess.run([binary], env=dict(env, SIGNAL_QUERY_CONCURRENCY="0"),
                                 capture_output=True, timeout=10)
        assert invalid.returncode != 0 and b"configuration" in invalid.stderr
        for log in root.glob("query-server-*.log"):
            assert token not in log.read_text() and payload_secret not in log.read_text()
        assert token.encode() not in invalid.stderr and payload_secret.encode() not in invalid.stderr
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    print("Query process gate passed: auth, canonical events, all filters, order, URL validation, SIGKILL restart, resource bounds, configuration and redaction")


if __name__ == "__main__":
    main()

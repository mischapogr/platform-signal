#!/usr/bin/env python3
"""Actual storage create failure after WAL admission, then exact replay recovery."""
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
import uuid
import zlib


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    rules = root / "rules"
    rules.mkdir()
    public_rule = Path(__file__).resolve().parents[2] / "rules/examples/login-failure.yaml"
    (rules / public_rule.name).write_bytes(public_rule.read_bytes())
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    token = "owned-storage-fault-token"
    payload = "owned-storage-fault-payload"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    environment.update(
        SIGNAL_LISTEN=f"127.0.0.1:{port}", SIGNAL_API_TOKEN=token,
        SIGNAL_WAL_DIR=str(root / "wal"), SIGNAL_STORAGE_DIR=str(root / "events"),
        SIGNAL_FINDINGS_DIR=str(root / "findings"), SIGNAL_RULE_DIRS=str(rules),
        # One input stays below the batch count, allowing its 202 response before
        # the consumer reaches the real filesystem failure.
        SIGNAL_STORAGE_BATCH_EVENTS="2", SIGNAL_STORAGE_FLUSH_MS="500",
    )
    process = None
    logs = []
    event = {"schema_version": 1, "id": str(uuid.uuid4()),
             "timestamp": "2026-10-06T12:00:00.123456789Z",
             "observed_at": "2026-10-06T12:00:01.123456789Z",
             "source": {"type": "application", "name": "storage-fault-gate"},
             "severity": "warn", "message": "login failed " + payload,
             "attributes": {"nested": {"large": 1844674407370955161600001}}, "tags": []}

    def request(method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request(method, path, json.dumps(body).encode() if body else None,
                               {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            assert len(data) <= 1024 * 1024
            return response.status, data
        finally:
            connection.close()

    def wait_for(predicate, label):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None, "server exited during " + label
            try:
                if predicate():
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        raise TimeoutError(label)

    def start():
        nonlocal process
        log = root / f"server-{len(logs)}.log"
        logs.append(log)
        with log.open("wb") as output:
            process = subprocess.Popen([binary], env=environment, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=output)
        wait_for(lambda: request("GET", "/readyz")[0] == 200, "startup readiness")

    def checkpoint():
        data = (root / "wal/checkpoint").read_bytes()
        assert len(data) == 28 and data[:8] == b"SIGACK01"
        assert zlib.crc32(data[:24]) == struct.unpack_from("<I", data, 24)[0]
        return struct.unpack_from("<Q", data, 8)[0]

    def rows(name):
        status, body = request("GET", "/v1/" + name)
        assert status == 200
        return json.loads(body)[name]

    try:
        start()
        identity = (root / "wal/identity").read_bytes()
        # Create the exact unpublished file after startup. OpenOptions::create_new
        # encounters a real OS AlreadyExists failure during append, independent
        # of test-user permissions or injected mocks. The sentinel stays intact.
        partition = root / "events/date=2026-10-06/hour=12"
        partition.mkdir(parents=True)
        blocker = partition / "batch-00000000000000000001-00000000000000000001.parquet.tmp"
        marker = b"owned storage create failure sentinel"
        blocker.write_bytes(marker)
        status, body = request("POST", "/v1/events", event)
        admission = json.loads(body)
        assert status == 202 and admission["event_ids"] == [event["id"]]
        assert admission["accepted"] == 1
        assert process.wait(timeout=20) != 0, "storage failure did not fail closed"
        assert checkpoint() == 0, "failed storage publication was acknowledged"
        assert blocker.read_bytes() == marker, "failed create overwrote the sentinel"
        assert not list((root / "events").rglob("*.parquet")), "failed write was published"

        blocker.unlink()  # Repair only this test's exact owned fault artifact.
        start()
        assert (root / "wal/identity").read_bytes() == identity
        wait_for(lambda: rows("events") == [event] and len(rows("findings")) == 1
                 and checkpoint() == 1, "replay event and finding publication")
        findings = rows("findings")
        assert findings[0]["event_ids"] == [event["id"]]
        assert findings[0]["rule_id"] == "auth.login-failure"
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == 0
        start()
        assert rows("events") == [event] and rows("findings") == findings and checkpoint() == 1
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == 0
        for log in logs:
            text = log.read_text()
            assert token not in text and payload not in text, "secret leaked in logs"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    print("Storage OS failure gate passed: durable 202, failed create, no early ack, exact replay/restart")


if __name__ == "__main__":
    main()

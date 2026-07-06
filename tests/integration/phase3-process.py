#!/usr/bin/env python3
"""Real HTTP acknowledgments survive kill/replay and graceful Parquet drains."""
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2]).resolve()
    sentinel = "phase3-redaction-sentinel"
    payload_secret = "phase3-private-event-payload"
    env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    env.update(SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_API_TOKEN=sentinel,
               SIGNAL_MEMORY_EVENTS="10", SIGNAL_MEMORY_BYTES="65536",
               SIGNAL_WAL_RECORD_BYTES="2048", SIGNAL_WAL_SEGMENT_BYTES="65536",
               SIGNAL_WAL_BYTES="1048576", SIGNAL_FINDINGS_DIR=str(root / "findings"), SIGNAL_WAL_DIR=str(root / "wal"),
               SIGNAL_STORAGE_DIR=str(root / "events"), SIGNAL_STORAGE_BATCH_EVENTS="10",
               SIGNAL_STORAGE_BATCH_BYTES="65536", SIGNAL_STORAGE_EVENT_BYTES="2048")
    process = None
    host, port = "127.0.0.1", 0
    log_number = 0
    expected = []

    def start():
        nonlocal process, host, port, log_number
        log_number += 1
        log_path = root / f"server-{log_number}.log"
        with log_path.open("wb") as logs:
            process = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=logs)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("server exited before listening: " + log_path.read_text())
            for line in log_path.read_text().splitlines():
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
        raise TimeoutError("server listen deadline exceeded")

    def request(method, path, body=None, authenticated=False):
        connection = http.client.HTTPConnection(host, port, timeout=3)
        try:
            headers = {"Content-Type": "application/json"}
            if authenticated:
                headers["Authorization"] = "Bearer " + sentinel
            connection.request(method, path, body=json.dumps(body) if body is not None else None,
                               headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def drained(count):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert process.poll() is None, "consumer process exited during drain"
            status, body = request("GET", "/metrics")
            assert status == 200
            metrics = dict(line.split() for line in body.decode().splitlines() if not line.startswith("#"))
            if metrics.get("signal_storage_high_water") == str(count) and metrics.get("signal_queue_depth") == "0":
                assert request("GET", "/readyz")[0] == 200
                return
            time.sleep(0.02)
        raise TimeoutError("WAL -> Parquet -> checkpoint drain deadline exceeded")

    def stop():
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == 0, "graceful drain failed"

    def event(index):
        return {"schema_version": 1, "id": str(uuid.uuid4()),
                "timestamp": f"2026-10-{6 + index // 24:02d}T{index % 24:02d}:00:00.{index + 1:09d}Z",
                "observed_at": "2026-10-06T12:00:00.123456789Z",
                "source": {"type": "application", "name": "process-fixture"},
                "severity": "info", "message": payload_secret,
                "attributes": {"index": index, "private": payload_secret,
                               "nested": {"array": [None, True, {"large": 1844674407370955161600001}]}},
                "resource": {"kind": "host", "id": "fixture-host", "region": "fixture-region"},
                "tags": ["integration"]}

    def accepted_batch(pending):
        saw_partial = False
        deadline = time.monotonic() + 20
        while pending:
            assert time.monotonic() < deadline, "batch retries exceeded deadline"
            status, body = request("POST", "/v1/events/batch", {"events": pending}, True)
            result = json.loads(body)
            assert status in (202, 429), f"unexpected batch status {status}"
            count = result["accepted"]
            assert result["rejected"] == len(pending) - count
            assert result["event_ids"] == [row["id"] for row in pending[:count]]
            if status == 429:
                assert result["rejected"] > 0
                saw_partial |= count > 0
            else:
                assert count == len(pending)
            expected.extend(pending[:count])
            pending = pending[count:]
            if pending:
                drained(len(expected))
        return saw_partial

    def startup_failure(task_env, required):
        result = subprocess.run([binary], env=task_env, capture_output=True, timeout=10)
        assert result.returncode != 0 and required in result.stderr, "missing startup rejection"
        assert sentinel.encode() not in result.stderr and payload_secret.encode() not in result.stderr

    try:
        start()
        original_stream = (root / "wal" / "identity").read_text()
        uuid.UUID(original_stream)
        first = event(0)
        assert request("POST", "/v1/events", first)[0] == 401
        status, body = request("POST", "/v1/events", first, True)
        result = json.loads(body)
        assert status == 202 and result["accepted"] == 1 and result["rejected"] == 0
        assert result["event_ids"] == [first["id"]]
        expected.append(first)
        # Deliberately do not wait for storage: recovery may read WAL or committed Parquet.
        process.kill()
        assert process.wait(timeout=3) == -signal.SIGKILL
        start()
        drained(1)
        startup_failure(env, b"locked")
        assert accepted_batch([event(index) for index in range(1, 100)]), "no partial 429 observed"
        drained(len(expected))
        # A new accepted row is drained by SIGTERM without waiting for a storage metric.
        last = event(100)
        status, body = request("POST", "/v1/events", last, True)
        result = json.loads(body)
        assert status == 202 and result["event_ids"] == [last["id"]]
        expected.append(last)
        stop()
        start()
        drained(len(expected))
        stop()
        startup_failure(dict(env, SIGNAL_STORAGE_BATCH_EVENTS="0"), b"configuration")
        (root / "expected.json").write_text(json.dumps({"stream_id": original_stream, "events": expected}))
        # Preserve original WAL for evidence, replace its path, and retain original Parquet.
        (root / "wal").rename(root / "wal-original")
        startup_failure(env, b"stream identities differ")
        for path in root.glob("server-*.log"):
            logs = path.read_text()
            assert sentinel not in logs and payload_secret not in logs, "secret appeared in logs"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    print("Process gate passed: HTTP/auth, partial 429, SIGKILL recovery, SIGTERM drain, restart, locks, config, stream identity and redaction")


if __name__ == "__main__":
    main()

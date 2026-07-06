#!/usr/bin/env python3
"""Actual HTTP -> fsynced WAL -> SIGKILL -> replay, with quotas and redaction."""
import http.client
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zlib


def wal_ids(directory):
    ids = []
    for path in sorted(Path(directory).glob("*.wal")):
        data = path.read_bytes()
        assert data[:8] == b"SIGWAL01"
        assert zlib.crc32(data[:16]) == struct.unpack_from("<I", data, 16)[0]
        offset = 20
        while offset < len(data):
            size, sequence, header_crc, payload_crc = struct.unpack_from("<IQII", data, offset)
            assert zlib.crc32(data[offset:offset + 12]) == header_crc
            payload = data[offset + 20:offset + 20 + size]
            assert len(payload) == size and zlib.crc32(payload) == payload_crc
            assert sequence == len(ids) + 1
            ids.append(json.loads(payload)["id"])
            offset += 20 + size
    return ids


def start(binary, task_env, logs):
    logs.seek(0)
    logs.truncate()
    process = subprocess.Popen([binary], env=task_env, stdout=subprocess.DEVNULL, stderr=logs)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited before readiness")
        logs.seek(0)
        for line in logs.read().splitlines():
            try:
                address = json.loads(line).get("fields", {}).get("listen")
            except ValueError:
                continue
            if address:
                host, port = address.rsplit(":", 1)
                return process, host, int(port)
        time.sleep(0.01)
    process.kill()
    process.wait(timeout=3)
    raise TimeoutError("server readiness log deadline exceeded")


def main():
    binary = str(Path(sys.argv[1]).resolve())
    sentinel = "phase2-redaction-sentinel"
    task_env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    process = None
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryFile(mode="w+b") as logs:
        task_env.update(SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_API_TOKEN=sentinel,
                        SIGNAL_MEMORY_EVENTS="10", SIGNAL_MEMORY_BYTES="4096",
                        SIGNAL_WAL_RECORD_BYTES="2048", SIGNAL_WAL_SEGMENT_BYTES="4096",
                        SIGNAL_WAL_BYTES="16384", SIGNAL_FINDINGS_DIR=str(Path(root) / "findings"), SIGNAL_STORAGE_DIR=str(Path(root) / "events"), SIGNAL_WAL_DIR=str(Path(root) / "wal"))
        try:
            process, host, port = start(binary, task_env, logs)

            def request(method, path, body=None, authenticated=False):
                connection = http.client.HTTPConnection(host, port, timeout=2)
                try:
                    headers = {"Content-Type": "application/json"}
                    if authenticated:
                        headers["Authorization"] = "Bearer " + sentinel
                    connection.request(method, path, body=body, headers=headers)
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            def metric(name, expected):
                text = request("GET", "/metrics")[1].decode()
                if f"{name} {expected}\n" not in text:
                    raise RuntimeError(f"missing metric {name}={expected}")

            def stop():
                process.send_signal(signal.SIGTERM)
                if process.wait(timeout=3) != 0:
                    raise RuntimeError("SIGTERM did not shut down successfully")
                logs.seek(0)
                text = logs.read().decode()
                if sentinel in text:
                    raise RuntimeError("secret-bearing request data appeared in logs")
                if "unacknowledged events remain in WAL" not in text:
                    raise RuntimeError("graceful shutdown did not retain WAL")

            assert request("GET", "/readyz")[0] == 200
            event = {"timestamp": "2026-10-06T12:00:00Z", "source": {"type": "application"},
                     "message": sentinel, "attributes": {"private": sentinel}}
            assert request("POST", "/v1/events", json.dumps(event))[0] == 401
            status, body = request("POST", "/v1/events", json.dumps(event), True)
            result = json.loads(body)
            assert status == 202 and (result["accepted"], result["rejected"]) == (1, 0)
            ids = result["event_ids"]
            metric("signal_queue_depth", 1)
            assert wal_ids(task_env["SIGNAL_WAL_DIR"]) == ids
            locked = subprocess.run([binary], env=task_env, capture_output=True, timeout=3)
            assert locked.returncode != 0 and b"locked" in locked.stderr
            assert sentinel.encode() not in locked.stderr
            process.kill()
            assert process.wait(timeout=3) == -signal.SIGKILL
            process, host, port = start(binary, task_env, logs)
            metric("signal_queue_depth", 1)
            metric("signal_wal_replayed_total", 1)
            status, body = request("POST", "/v1/events/batch", json.dumps({"events": [event] * 12}), True)
            result = json.loads(body)
            assert status == 429 and (result["accepted"], result["rejected"]) == (9, 3)
            ids.extend(result["event_ids"])
            assert len(set(ids)) == 10 and wal_ids(task_env["SIGNAL_WAL_DIR"]) == ids
            metric("signal_queue_depth", 10)
            stop()
            process, host, port = start(binary, task_env, logs)
            metric("signal_queue_depth", 10)
            metric("signal_wal_replayed_total", 10)
            assert wal_ids(task_env["SIGNAL_WAL_DIR"]) == ids
            stop()
            invalid_env = dict(task_env, SIGNAL_MEMORY_EVENTS="0")
            invalid = subprocess.run([binary], env=invalid_env, capture_output=True, timeout=3)
            assert invalid.returncode != 0 and sentinel.encode() not in invalid.stderr
            first = sorted(Path(task_env["SIGNAL_WAL_DIR"]).glob("*.wal"))[0]
            data = bytearray(first.read_bytes())
            data[40] ^= 1
            first.write_bytes(data)
            corrupt = subprocess.run([binary], env=task_env, capture_output=True, timeout=3)
            assert corrupt.returncode != 0 and b"corruption" in corrupt.stderr
            assert sentinel.encode() not in corrupt.stderr
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=3)
    print("Process gate passed: durable HTTP, SIGKILL replay with matching IDs, quota counts, SIGTERM replay, directory lock, corruption startup failure, redacted logs")


if __name__ == "__main__":
    main()

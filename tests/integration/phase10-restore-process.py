#!/usr/bin/env python3
"""Stopped, same-binary server/agent backup and isolated restore rehearsal.

Synthetic fixtures only. The supplied root must not exist. Copies are verified
before startup; originals and backup stay stopped and unchanged. Each network
call, process wait and polling loop is bounded. No live source is reopened.
"""
import collections
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid
import zlib


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), path
        result[str(path.relative_to(root))] = {
            "kind": "file" if path.is_file() else "directory",
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
            **({"bytes": info.st_size, "sha256": sha256(path)} if path.is_file() else {}),
        }
    return result


def frame(path):
    data = path.read_bytes()
    assert 12 <= len(data) <= 65536, path
    length, payload_crc, header_crc = struct.unpack_from("<III", data)
    assert len(data) == length + 12 and zlib.crc32(data[:8]) == header_crc
    assert zlib.crc32(data[12:]) == payload_crc
    return json.loads(data[12:])


def checkpoint(bundle):
    data = (bundle / "server/wal/checkpoint").read_bytes()
    assert len(data) == 28 and data[:8] == b"SIGACK01"
    assert zlib.crc32(data[:24]) == struct.unpack_from("<I", data, 24)[0]
    return struct.unpack_from("<Q", data, 8)[0]


def main():
    started = time.monotonic()
    agent_binary, server_binary = [str(Path(arg).resolve()) for arg in sys.argv[1:3]]
    root = Path(sys.argv[3]).resolve()
    root.mkdir()  # Refuse existing roots, including operator data directories.
    original = root / "original"
    original.mkdir(mode=0o700)
    (original / "rules").mkdir()
    rule = Path(__file__).resolve().parents[2] / "rules/examples/login-failure.yaml"
    shutil.copy2(rule, original / "rules" / rule.name)
    (original / "server.yaml").write_text(
        "schema_version: 1\ningest: {api_token_env: SIGNAL_API_TOKEN}\n"
        "buffer: {wal_directory: server/wal}\n"
        "storage: {directory: server/events, flush_events: 2, flush_interval: '500ms'}\n"
        "findings: {directory: server/findings}\nrules: {directories: [rules]}\n"
    )
    source = original / "source.log"
    source.write_text('{"message":"already delivered","nested":{"n":1844674407370955161600001}}\n')
    token = "owned-restore-token-sentinel"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    port, metrics_port = free_port(), free_port()
    while metrics_port == port:
        metrics_port = free_port()
    processes, logs = [], []
    server = None

    def request(path, body=None, telemetry=False, authenticated=True):
        connection = http.client.HTTPConnection("127.0.0.1", metrics_port if telemetry else port, timeout=2)
        try:
            headers = {"Content-Type": "application/json"}
            if authenticated:
                headers["Authorization"] = "Bearer " + token
            connection.request("POST" if body is not None else "GET", path,
                               json.dumps(body).encode() if body is not None else None, headers)
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            assert len(data) <= 1024 * 1024
            return response.status, data
        finally:
            connection.close()

    def wait_for(predicate, label, process):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, "process exited during " + label
            try:
                if predicate():
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.03)
        raise TimeoutError(label)

    def launch(command, bundle, env, piped=False):
        log = root / f"process-{len(logs)}.log"
        logs.append(log)
        with log.open("wb") as output:
            process = subprocess.Popen(command, cwd=bundle, env=env,
                                       stdin=subprocess.PIPE if piped else subprocess.DEVNULL,
                                       stdout=output, stderr=output)
        processes.append(process)
        return process

    def start_server(bundle):
        nonlocal server
        server = launch([server_binary, "--config", "server.yaml"], bundle,
                        dict(environment, SIGNAL_LISTEN=f"127.0.0.1:{port}", SIGNAL_API_TOKEN=token))
        wait_for(lambda: request("/readyz")[0] == 200, "server readiness", server)
        return server

    def start_agent(bundle, args):
        return launch([agent_binary, "--server", f"http://127.0.0.1:{port}",
                       "--spool-dir", "spool", "--source-name", "restore-file",
                       "--flush-ms", "20", "--retry-base-ms", "20", "--retry-max-ms", "100",
                       "--request-timeout-ms", "500", "--shutdown-timeout-ms", "1000",
                       "--metrics-listen", f"127.0.0.1:{metrics_port}", *args], bundle,
                      dict(environment, SIGNAL_AGENT_API_TOKEN=token), piped=True)

    def stop(process, pending=False):
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=15)
        assert (code > 0 if pending else code == 0), (code, logs[-1].read_text())

    def rows(name):
        status, body = request("/v1/" + name + "?limit=100")
        assert status == 200
        return json.loads(body)[name]

    def by_id(events):
        result = {event["id"]: event for event in events}
        assert len(result) == len(events), "duplicate event IDs"
        return result

    def metric(name):
        status, data = request("/metrics", telemetry=True)
        assert status == 200
        return dict(line.split() for line in data.decode().splitlines()
                    if line and not line.startswith("#"))[name]

    def file_once(bundle):
        agent = start_agent(bundle, ["--file", "source.log", "--once"])
        assert agent.wait(timeout=15) == 0, logs[-1].read_text()

    def event(message):
        return {"schema_version": 1, "id": str(uuid.uuid4()),
                "timestamp": "2026-10-06T12:00:00.123456789Z",
                "observed_at": "2026-10-06T12:00:01.123456789Z",
                "source": {"type": "application", "name": "restore-gate"},
                "severity": "warn", "message": message,
                "attributes": {"nested": {"n": 1844674407370955161600001}}, "tags": []}

    def admit(item):
        status, body = request("/v1/events", item)
        admission = json.loads(body)
        assert status == 202 and admission["accepted"] == 1 and admission["event_ids"] == [item["id"]]

    try:
        start_server(original)
        assert request("/v1/events", authenticated=False)[0] == 401
        persisted = event("login failed before backup")
        admit(persisted)
        file_once(original)
        wait_for(lambda: len(rows("events")) == 2 and len(rows("findings")) == 1
                 and checkpoint(original) == 2, "initial persistence", server)
        initial_events, initial_findings = rows("events"), rows("findings")
        assert by_id(initial_events)[persisted["id"]] == persisted
        file_once(original)
        assert by_id(rows("events")) == by_id(initial_events), "original cursor reread source"
        stop(server)

        # Retain a real durable-but-unpublished WAL record in the stopped backup.
        start_server(original)
        partition = original / "server/events/date=2026-10-06/hour=12"
        blocker = partition / "batch-00000000000000000003-00000000000000000003.parquet.tmp"
        blocker.write_bytes(b"owned restore publication blocker")
        pending = event("login failed pending WAL backup")
        admit(pending)
        assert server.wait(timeout=20) > 0
        assert checkpoint(original) == 2
        assert blocker.read_bytes() == b"owned restore publication blocker"
        blocker.unlink()  # Repair only the fault fixture, after its writer exits.

        # The offline agent stops with pending durable records, without killing it.
        with source.open("a") as file:
            file.write('pending source one\npending source two\n')
        agent = start_agent(original, ["--file", "source.log"])
        wait_for(lambda: metric("signal_agent_spool_events") == "2", "offline spool", agent)
        stop(agent, pending=True)
        records = [frame(path) for path in sorted((original / "spool").glob("record-*"))]
        assert [record["sequence"] for record in records] == [2, 3]
        queued = [record["event"] for record in records]
        assert [item["message"] for item in queued] == ["pending source one", "pending source two"]
        cursor = records[-1]["checkpoint"]
        assert cursor["offset"] == source.stat().st_size and cursor["inode"] == source.stat().st_ino
        assert all(process.poll() is not None for process in processes), "backup has a live writer"
        before = inventory(original)
        backup, restored = root / "backup", root / "restored"
        shutil.copytree(original, backup, copy_function=shutil.copy2)
        assert inventory(backup) == before, "backup checksum/ownership/mode mismatch"
        shutil.copytree(backup, restored, copy_function=shutil.copy2)
        assert inventory(restored) == before, "restore checksum/ownership/mode mismatch"
        assert restored.joinpath("source.log").stat().st_ino != source.stat().st_ino
        (root / "inventory.json").write_text(json.dumps(before, indent=2) + "\n")

        start_server(restored)
        assert request("/v1/events", authenticated=False)[0] == 401
        expected = initial_events + [pending]
        wait_for(lambda: by_id(rows("events")) == by_id(expected)
                 and len(rows("findings")) == 2 and checkpoint(restored) == 3, "restored WAL replay", server)
        restored_findings = rows("findings")
        assert by_id(restored_findings)[initial_findings[0]["id"]] == initial_findings[0]
        assert {tuple(finding["event_ids"]) for finding in restored_findings} == {
            (persisted["id"],), (pending["id"],)}
        assert (restored / "server/wal/identity").read_bytes() == (backup / "server/wal/identity").read_bytes()

        # Drain copied spool without touching the original or rereading a source.
        agent = start_agent(restored, ["--stdin"])
        expected += queued
        wait_for(lambda: by_id(rows("events")) == by_id(expected)
                 and metric("signal_agent_spool_events") == "0" and checkpoint(restored) == 5,
                 "copied spool drain preserves canonical events", agent)
        stop(agent)
        restored_state = frame(restored / "spool/state")
        assert restored_state["acknowledged"] == 3 and restored_state["cursors"] == [cursor]

        # A copied source has a different inode: the old cursor cannot apply.
        file_once(restored)
        wait_for(lambda: len(rows("events")) == 8 and checkpoint(restored) == 8,
                 "copied source reread", server)
        reread_events = rows("events")
        assert all(by_id(reread_events)[item["id"]] == item for item in expected)
        file_events = [item for item in reread_events if item["source"]["name"] == "restore-file"]
        assert collections.Counter(item["message"] for item in file_events) == {
            "already delivered": 2, "pending source one": 2, "pending source two": 2}
        assert frame(restored / "spool/state")["cursors"][0]["inode"] == (restored / "source.log").stat().st_ino
        file_once(restored)
        assert by_id(rows("events")) == by_id(reread_events), "restored cursor duplicated events"
        with (restored / "source.log").open("a") as file:
            file.write("after isolated restore\n")
        file_once(restored)
        wait_for(lambda: len(rows("events")) == 9 and checkpoint(restored) == 9,
                 "new restored source line", server)
        final_events = rows("events")
        assert all(by_id(final_events)[item["id"]] == item for item in reread_events)
        assert sum(item["message"] == "after isolated restore" for item in final_events) == 1
        assert by_id(rows("findings")) == by_id(restored_findings)
        stop(server)
        start_server(restored)
        assert by_id(rows("events")) == by_id(final_events)
        assert by_id(rows("findings")) == by_id(restored_findings) and checkpoint(restored) == 9
        stop(server)
        assert inventory(original) == before and inventory(backup) == before, "backup/original mutated"
        for log in logs:
            assert token not in log.read_text(), "token leaked"
        report = {"schema_version": 1, "architecture": platform.machine(),
                  "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "scope": "synthetic local same-binary offline restore; no cross-version/cloud qualification",
                  "binaries": {name: {"sha256": sha256(Path(binary)), "version": subprocess.check_output(
                      [binary, "--version"], env=environment, timeout=5).decode().strip()}
                      for name, binary in (("agent", agent_binary), ("server", server_binary))},
                  "harness_sha256": sha256(Path(__file__)), "inventory_sha256": sha256(root / "inventory.json"),
                  "backup_files": sum(item["kind"] == "file" for item in before.values()),
                  "initial_events": 2, "pending_wal_events": 1, "pending_spool_events": 2,
                  "copied_source_reread_events": 3, "new_source_events": 1,
                  "final_events": 9, "final_findings": 2, "final_checkpoint": 9,
                  "original_and_backup_unchanged": True}
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdin is not None:
                process.stdin.close()
    print("Offline restore gate passed: checksummed stopped copies, pending WAL/spool, exact events/findings, inode/cursor behavior, stable restart")


if __name__ == "__main__":
    main()

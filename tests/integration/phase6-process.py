#!/usr/bin/env python3
"""Real agent -> authenticated server -> Parquet query acceptance gate.

Every wait has a deadline. Child processes, listeners and data belong to this run.
Run after cargo build -p signal-agent -p signal-server.
"""
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.parse


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(predicate, description, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.04)
    raise TimeoutError(description)


def main():
    agent_binary, server_binary = [str(Path(arg).resolve()) for arg in sys.argv[1:3]]
    root = Path(sys.argv[3]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    token = "phase6-token-redaction-sentinel"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    processes = []
    logs = []
    server = None

    def request(path, telemetry_port=None):
        connection = http.client.HTTPConnection("127.0.0.1", telemetry_port or port, timeout=2)
        try:
            connection.request("GET", path, headers={"Authorization": "Bearer " + token})
            response = connection.getresponse()
            body = response.read()
            assert response.status == 200, (response.status, body)
            return body
        finally:
            connection.close()

    def start_server():
        nonlocal server
        directory = root / "server"
        directory.mkdir(exist_ok=True)
        env = dict(environment, SIGNAL_LISTEN=f"127.0.0.1:{port}", SIGNAL_API_TOKEN=token,
                   SIGNAL_WAL_DIR=str(directory / "wal"), SIGNAL_STORAGE_DIR=str(directory / "events"),
                   SIGNAL_FINDINGS_DIR=str(directory / "findings"), SIGNAL_STORAGE_FLUSH_MS="10")
        log = root / f"server-{len(logs)}.log"
        logs.append(log)
        with log.open("wb") as output:
            server = subprocess.Popen([server_binary], env=env, stdout=output, stderr=output)
        processes.append(server)

        def ready():
            assert server.poll() is None, log.read_text()
            try:
                return request("/readyz") is not None
            except (OSError, http.client.HTTPException):
                return False
        wait_for(ready, "server did not become ready")

    def stop(process, kill=False):
        process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
        code = process.wait(timeout=15)
        assert code == (-signal.SIGKILL if kill else 0), (code, [log.read_text() for log in logs])

    def start_agent(name, args, metrics_port=None):
        log = root / f"agent-{name}-{len(logs)}.log"
        logs.append(log)
        command = [agent_binary, "--server", url, "--spool-dir", str(root / name),
                   "--flush-ms", "20", "--retry-base-ms", "20", "--retry-max-ms", "100",
                   "--request-timeout-ms", "500", "--shutdown-timeout-ms", "1000", *args]
        if metrics_port:
            command += ["--metrics-listen", f"127.0.0.1:{metrics_port}"]
        with log.open("wb") as output:
            process = subprocess.Popen(command, env=dict(environment, SIGNAL_AGENT_API_TOKEN=token),
                                       stdin=subprocess.PIPE, stdout=output, stderr=output)
        processes.append(process)
        return process

    def rows(source):
        query = urllib.parse.urlencode({"source_name": source, "limit": "1000"})
        return json.loads(request("/v1/events?" + query))["events"]

    def messages(source):
        return [row.get("message") for row in rows(source)]

    def expect_messages(source, expected):
        wait_for(lambda: sorted(messages(source)) == sorted(expected), f"missing/duplicate rows: {source} {expected}")

    def telemetry(metrics_port):
        text = request("/metrics", metrics_port).decode()
        return {line.split()[0]: float(line.split()[1]) for line in text.splitlines()
                if line and not line.startswith("#") and len(line.split()) == 2}

    try:
        # Tokens are environment-only, and rejected CLI input must remain redacted.
        invalid = subprocess.run([agent_binary, "--token", token], env=environment,
                                 capture_output=True, timeout=5)
        assert invalid.returncode != 0
        assert token.encode() not in invalid.stdout + invalid.stderr
        cross_limit = subprocess.run([agent_binary, "--max-spool-bytes", "32768"],
                                     env=environment, capture_output=True, timeout=5)
        assert cross_limit.returncode != 0, "event larger than usable spool accepted"
        start_server()
        stdin = start_agent("stdin", ["--stdin", "--source-name", "stdin-gate"])
        stdin.communicate(b'plain first\n{"message":"json second","nested":{"array":[null,true,{"n":1844674407370955161600001}]}}\n', timeout=15)
        assert stdin.returncode == 0
        expect_messages("stdin-gate", ["plain first", "json second"])
        json_row = next(row for row in rows("stdin-gate") if row["message"] == "json second")
        assert json_row["attributes"]["nested"]["array"][2]["n"] == 1844674407370955161600001
        assert json_row["source"]["type"] == "log" and json_row["schema_version"] == 1
        assert json_row["id"] and json_row["timestamp"] and json_row["observed_at"]

        snapshot = root / "snapshot.log"
        snapshot.write_text("snapshot one\nsnapshot two\n")
        args = ["--file", str(snapshot), "--once", "--source-name", "snapshot-gate"]
        first = start_agent("snapshot", args)
        assert first.wait(timeout=15) == 0
        expect_messages("snapshot-gate", ["snapshot one", "snapshot two"])
        initial_ids = {row["id"] for row in rows("snapshot-gate")}
        # A durable cursor must prevent generation of new IDs for an already read file.
        second = start_agent("snapshot", args)
        assert second.wait(timeout=15) == 0
        assert {row["id"] for row in rows("snapshot-gate")} == initial_ids
        with snapshot.open("a") as file:
            file.write("snapshot three\n")
        third = start_agent("snapshot", args)
        assert third.wait(timeout=15) == 0
        expect_messages("snapshot-gate", ["snapshot one", "snapshot two", "snapshot three"])

        # Canonical event bytes include envelope overhead and escaped attributes.
        # Oversize events must be counted, advance the durable file cursor, and
        # leave the next valid line deliverable instead of retrying forever.
        oversized = root / "oversized.log"
        oversized.write_text(json.dumps({"message": "oversized", "padding": "z" * 1500})
                             + '\n{"message":"after oversized"}\n')
        oversized_args = ["--file", str(oversized), "--once", "--source-name", "oversized-gate",
                          "--max-event-bytes", "1024"]
        oversize_first = start_agent("oversized", oversized_args)
        first_log = logs[-1]
        assert oversize_first.wait(timeout=15) == 0, first_log.read_text()
        expect_messages("oversized-gate", ["after oversized"])
        reports = [json.loads(line) for line in first_log.read_text().splitlines()]
        assert any(row.get("accepted") == 1 and row.get("rejected") == 1 for row in reports), reports
        oversized_ids = {row["id"] for row in rows("oversized-gate")}
        oversize_second = start_agent("oversized", oversized_args)
        second_log = logs[-1]
        assert oversize_second.wait(timeout=15) == 0, second_log.read_text()
        assert {row["id"] for row in rows("oversized-gate")} == oversized_ids
        reports = [json.loads(line) for line in second_log.read_text().splitlines()]
        assert any(row.get("accepted") == 0 and row.get("rejected") == 0 for row in reports), reports

        followed = root / "follow.log"
        followed.write_text("follow initial\npartial")
        follow = start_agent("follow", ["--file", str(followed), "--source-name", "follow-gate"])
        expect_messages("follow-gate", ["follow initial"])
        time.sleep(0.2)
        assert messages("follow-gate") == ["follow initial"], "unterminated line published during follow"
        with followed.open("a") as file:
            file.write(" completed\n")
        expect_messages("follow-gate", ["follow initial", "partial completed"])
        followed.rename(root / "follow.log.1")
        followed.write_text("rotated new\n")
        expect_messages("follow-gate", ["follow initial", "partial completed", "rotated new"])
        followed.write_text("x\n")  # Smaller same-inode rewrite: truncate detection.
        expect_messages("follow-gate", ["follow initial", "partial completed", "rotated new", "x"])
        stop(follow)

        # Idle piped stdin must remain cancellable while no bytes arrive.
        idle_metrics = free_port()
        idle = start_agent("idle", ["--stdin"], idle_metrics)

        def idle_ready():
            assert idle.poll() is None, logs[-1].read_text()
            try:
                # The metrics loop runs only after spool/cursor/input startup.
                # Test idle-input cancellation, independently of startup speed.
                return telemetry(idle_metrics).get("signal_agent_spool_events") == 0
            except (OSError, http.client.HTTPException):
                return False
        wait_for(idle_ready, "idle stdin agent did not finish startup")
        stop(idle)

        # Crash with the server offline after durable admission, then restart both.
        stop(server)
        offline_file = root / "offline.log"
        offline_expected = [f"offline {index}" for index in range(12)]
        offline_file.write_text("\n".join(offline_expected) + "\n")
        metrics_port = free_port()
        offline_args = ["--file", str(offline_file), "--source-name", "offline-gate",
                        "--max-spool-events", "8", "--max-spool-bytes", "65536",
                        "--max-event-bytes", "1024"]
        offline = start_agent("offline", offline_args, metrics_port)

        def spooled():
            assert offline.poll() is None, "offline agent exited"
            try:
                metrics = telemetry(metrics_port)
                return metrics.get("signal_agent_spool_events", 0) == 8
            except (OSError, http.client.HTTPException):
                return False
        wait_for(spooled, "offline events not durably spooled")
        metrics = telemetry(metrics_port)
        assert metrics["signal_agent_spool_capacity_events"] == 8
        assert metrics["signal_agent_spool_capacity_bytes"] == 65536
        assert metrics["signal_agent_spool_events"] <= metrics["signal_agent_spool_capacity_events"]
        assert metrics["signal_agent_spool_bytes"] <= metrics["signal_agent_spool_capacity_bytes"]
        wait_for(lambda: telemetry(metrics_port).get("signal_agent_retries_total", 0) > 0,
                 "offline agent did not retry")
        stop(offline, kill=True)
        start_server()
        recovered = start_agent("offline", offline_args)
        expect_messages("offline-gate", offline_expected)
        with offline_file.open("a") as file:
            file.write("after restart\n")
        expect_messages("offline-gate", offline_expected + ["after restart"])
        stop(recovered)
        stop(server)
        start_server()
        expect_messages("offline-gate", offline_expected + ["after restart"])
        expect_messages("stdin-gate", ["plain first", "json second"])
        stop(server)
        for log in logs:
            assert token not in log.read_text(), f"API token leaked in {log}"
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
    print("Phase 6 process gate passed: stdin/plain/JSON, nested attributes, file cursors, oversized canonical event rejection/cursor restart, partial lines, rotation/truncation, idle cancellation, authenticated delivery, saturated bounded offline spool, retry, SIGKILL recovery, server restart, invalid cross limits and token redaction")


if __name__ == "__main__":
    main()

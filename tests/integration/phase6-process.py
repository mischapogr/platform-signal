#!/usr/bin/env python3
"""Real agent -> authenticated server -> Parquet query acceptance gate.

Every wait has a deadline. Child processes, listeners and data belong to this run.
Run after cargo build -p signal-agent -p signal-server.
"""
import http.client
import http.server
from collections import Counter
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
import threading
import urllib.parse
import uuid
import zlib


def logical_events(events, known):
    """Allow at-least-once copies only with original IDs and canonical payloads."""
    unique = {}
    for event in events:
        identity = event.get("id")
        assert isinstance(identity, str) and uuid.UUID(identity).int != 0, "invalid event identity"
        if identity in known:
            assert known[identity] == event, "replay changed canonical event payload"
        if identity in unique:
            assert unique[identity] == event, "duplicate ID changed canonical event payload"
        unique[identity] = event
    assert all(identity in unique for identity in known), "previously delivered event disappeared"
    return unique


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
    relay = relay_thread = None
    reply_loss = {"accepted": None, "replayed": False, "requests": 0}
    known_events = {}

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

    def start_agent(name, args, metrics_port=None, endpoint=None):
        log = root / f"agent-{name}-{len(logs)}.log"
        logs.append(log)
        command = [agent_binary, "--server", endpoint or url, "--spool-dir", str(root / name),
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
        known = known_events.get(source, {})
        def complete():
            unique = logical_events(rows(source), known)
            if sorted(row.get("message") for row in unique.values()) != sorted(expected):
                return False
            known_events[source] = unique
            return True
        try:
            wait_for(complete, f"missing/unexpected logical rows: {source} {expected}")
        except TimeoutError as error:
            actual = rows(source)
            counts = Counter(row.get("message") for row in actual)
            diagnostic = {
                "source": source,
                "expected": expected,
                "actual_count": len(actual),
                "unique_ids": len({row.get("id") for row in actual}),
                "missing": [message for message in expected if counts[message] == 0],
                "repeated": {message: count for message, count in counts.items() if count > 1},
                "samples": [{"id": row.get("id"), "message": str(row.get("message"))[:128]}
                            for row in actual[:32]],
            }
            encoded = json.dumps(diagnostic, sort_keys=True)
            assert len(encoded.encode()) <= 16384, "recovery diagnostic exceeded bound"
            (root / "delivery-mismatch.json").write_text(encoded + "\n")
            raise TimeoutError(str(error) + "; diagnostic=" + encoded) from error

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
        # Selected structured authentication profile reuses the real file
        # worker, durable spool/cursor and authenticated server publication.
        auth_record = {"schema_version": 1, "timestamp": "2026-10-14T12:00:00Z",
                       "outcome": "success", "identity_authority": "fixture-authority",
                       "principal_id": "fixture-user", "target_id": "fixture-host",
                       "method": "public_key", "session_id": "fixture-session",
                       "client_ip": "198.51.100.10", "producer": {"boot_id": "fixture-boot",
                       "sequence": 1, "checkpoint": 1, "dropped_events": 0}}
        auth_failure = dict(auth_record, outcome="failure", producer={"boot_id": "fixture-boot",
                            "sequence": 2, "checkpoint": 2, "dropped_events": 1})
        auth_secret = "owned-auth-credential-redaction-sentinel"
        auth_path = root / "authentication.jsonl"
        auth_path.write_text('\n'.join(json.dumps(record) for record in [auth_record,
                             auth_failure, dict(auth_record, password=auth_secret),
                             dict(auth_record, runtime_sensor_coverage="verified")]) + '\n')
        auth_args = ["--file", str(auth_path), "--once", "--format", "auth-json",
                     "--source-name", "host-auth-gate", "--source-type", "host-authentication"]
        authentication = start_agent("authentication", auth_args)
        auth_log = logs[-1]
        assert authentication.wait(timeout=15) == 0
        expect_messages("host-auth-gate", ["Authentication succeeded", "Authentication failed"])
        auth_rows = rows("host-auth-gate")
        assert len(auth_rows) == 2 and {r['severity'] for r in auth_rows} == {'info', 'warn'}
        assert {r['attributes']['producer']['checkpoint'] for r in auth_rows} == {1, 2}
        assert all(r['attributes']['authentication']['principal_id'] == 'fixture-user' and
                   r['source']['type'] == 'host-authentication' and
                   r['attributes']['authentication']['target_id'] == 'fixture-host' and
                   r['attributes']['evidence']['runtime_sensor_coverage'] == 'not_assessed' and
                   r['timestamp'].startswith('2026-10-14T12:00:00') for r in auth_rows)
        assert any(r.get('accepted') == 2 and r.get('rejected') == 2
                   for r in map(json.loads, auth_log.read_text().splitlines()))
        auth_ids = {r['id'] for r in auth_rows}
        cursor_restart = start_agent("authentication", auth_args)
        assert cursor_restart.wait(timeout=15) == 0
        assert {r['id'] for r in rows('host-auth-gate')} == auth_ids
        assert auth_secret not in auth_log.read_text() and auth_secret not in json.dumps(auth_rows)
        (root / 'host-auth-report.json').write_text(json.dumps({
            'status': 'passed_simulated', 'profile': 'host-auth-json-v1', 'accepted': 2,
            'rejected': 2, 'original_ids': sorted(auth_ids), 'cursor_restart_no_reread': True,
            'runtime_sensor_coverage': 'not_assessed', 'credential_field_rejected': True,
            'scope': 'Real file/agent/spool/authenticated server/Parquet source-field retention; synthetic authentication producer, no native kernel/runtime coverage'
        }, sort_keys=True) + '\n')
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
        # Observe the actual synced records before the physical crash, rather
        # than inferring original identity from the restarted process.
        original_spool = []
        frames = sorted((root / "offline").glob("record-*"))
        assert len(frames) == 8
        for sequence, path in enumerate(frames, 1):
            assert not path.is_symlink() and 12 < path.stat().st_size <= 2060
            frame = path.read_bytes()
            length, payload_crc, header_crc = struct.unpack("<III", frame[:12])
            assert len(frame) == length + 12
            assert zlib.crc32(frame[:8]) == header_crc and zlib.crc32(frame[12:]) == payload_crc
            record = json.loads(frame[12:])
            assert record["version"] == 1 and record["sequence"] == sequence
            original_spool.append(record["event"])
        assert [event["message"] for event in original_spool] == offline_expected[:8]
        stop(offline, kill=True)
        start_server()
        class LostReply(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                reply_loss["requests"] += 1
                assert reply_loss["requests"] <= 16, "reply-loss fixture request bound"
                length = int(self.headers.get("Content-Length", "0"))
                assert self.path == "/v1/events/batch" and 0 < length <= 65536
                self.connection.settimeout(2)
                body = self.rfile.read(length)
                assert len(body) == length
                events = json.loads(body)["events"]
                if reply_loss["accepted"] is None:
                    assert events == original_spool, "restart changed original durable spool events"
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    connection.request("POST", self.path, body=body,
                                       headers={"Authorization": "Bearer " + token,
                                                "Content-Type": "application/json"})
                    response = connection.getresponse()
                    payload = response.read(65537)
                    assert response.status == 202 and len(payload) <= 65536
                    assert json.loads(payload)["accepted"] == len(events), "lost reply lacked full admission"
                finally:
                    connection.close()
                if reply_loss["accepted"] is None:
                    # Actual server admission completed; the agent receives no
                    # verified prefix and must retry the original spool bytes.
                    reply_loss["accepted"] = events
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                if not reply_loss["replayed"]:
                    assert events == reply_loss["accepted"], "uncertain retry changed original events"
                    reply_loss["replayed"] = True
                self.send_response(202)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        relay = http.server.HTTPServer(("127.0.0.1", 0), LostReply)
        relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
        relay_thread.start()
        recovered = start_agent("offline", offline_args,
                                endpoint=f"http://127.0.0.1:{relay.server_port}")
        expect_messages("offline-gate", offline_expected)
        assert reply_loss["replayed"] and len(reply_loss["accepted"]) == 8
        assert len(rows("offline-gate")) >= len(offline_expected) + 8, "actual uncertain replay was not persisted"
        with offline_file.open("a") as file:
            file.write("after restart\n")
        expect_messages("offline-gate", offline_expected + ["after restart"])
        stop(recovered)
        stop(server)
        start_server()
        expect_messages("offline-gate", offline_expected + ["after restart"])
        expect_messages("stdin-gate", ["plain first", "json second"])
        stop(server)
        (root / "recovery-report.json").write_text(json.dumps({
            "status": "passed", "original_spooled_ids": [event["id"] for event in original_spool],
            "logical_events": len(known_events["offline-gate"]),
            "lost_accepted_reply": True, "exact_replay_verified": reply_loss["replayed"],
            "relay_requests": reply_loss["requests"],
        }, sort_keys=True) + "\n")
        for log in logs:
            assert token not in log.read_text(), f"API token leaked in {log}"
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
        if relay is not None:
            relay.shutdown()
            relay.server_close()
            relay_thread.join(timeout=3)
            assert not relay_thread.is_alive(), "reply-loss fixture thread survived cleanup"
    print("Phase 6 process gate passed: stdin/plain/JSON, nested attributes, file cursors, oversized canonical event rejection/cursor restart, partial lines, rotation/truncation, idle cancellation, authenticated delivery, saturated bounded offline spool, retry, original durable identity, actual lost-admission reply/exact replay, SIGKILL recovery, server restart, invalid cross limits and token redaction")


if __name__ == "__main__":
    main()

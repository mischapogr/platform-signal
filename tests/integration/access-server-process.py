#!/usr/bin/env python3
"""Finite real TLS provider -> monolith -> scoped WAL/Parquet/query restart gate."""
import base64
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("signal_owned_processes", REPO / "scripts/check-object-query.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)


class Owned(BASE.Run):
    """Reuse the qualified finite process/log ownership seam only."""
    def __init__(self, out):
        self.out = out
        self.logs, self.processes = [], []
        self.owned, self.drains, self.log_errors = {}, {}, {}
        self.server = self.fixture = None


class FiniteTLSProvider(http.server.HTTPServer):
    def __init__(self, address, handler, context):
        self.context = context
        super().__init__(address, handler)

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(0.5)
        try:
            # Handshake inherits the raw socket timeout before Handler exists.
            return self.context.wrap_socket(raw, server_side=True), address
        except BaseException:
            raw.close()
            raise


def log_text(path):
    with path.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RuntimeError("identity fixture log byte capacity")
    return data.decode("utf-8", errors="replace")


def spawn_owned(owner, command, environment, label):
    pending = []
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    def defer(kind, _frame):
        if not pending:
            pending.append(kind)
    try:
        for kind in previous:
            signal.signal(kind, defer)
        child = owner.spawn(command, environment, label)
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
    if pending:
        raise KeyboardInterrupt("owned identity server creation interrupted")
    return child


def start_provider_thread(thread):
    pending = []
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    def defer(kind, _frame):
        if not pending:
            pending.append(kind)
    try:
        for kind in previous:
            signal.signal(kind, defer)
        # Caller already owns the Thread before interruption can be delivered.
        thread.start()
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
    if pending:
        raise KeyboardInterrupt("owned provider thread creation interrupted")


def stop_provider(provider, thread):
    if provider is not None:
        try:
            # BaseServer.shutdown waits forever if serve_forever never started.
            if thread is not None and thread.is_alive():
                provider.shutdown()
        finally:
            provider.server_close()
    if thread is not None and thread.ident is not None:
        thread.join(timeout=3)
        assert not thread.is_alive(), "provider fixture thread did not stop"


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    owner = Owned(root)
    secret = "synthetic-server-introspection-secret"
    issuer = "https://identity.example.test"
    process = None
    provider = None
    provider_thread = None
    process_logs = []
    counters = {"calls": 0, "invalid": 0, "revoked": False, "stall": False}
    generation, host, port = 0, "127.0.0.1", 0

    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

    def stop(kill=False):
        nonlocal process
        if process is None:
            return
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
            result = process.wait(timeout=10)
            if not kill:
                assert result == 0, "server shutdown failed"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            owner.reap_log(process)
            owner.reaped(process)
            process = None

    try:
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "1",
                "-subj", "/CN=synthetic-signal-ca", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-noenc", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=synthetic-provider")
        (root / "leaf.ext").write_text("subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key",
                "-set_serial", "2", "-days", "1", "-extfile", "leaf.ext", "-out", "leaf.pem")
        ca_der = ssl.PEM_cert_to_DER_cert((root / "root.pem").read_text())

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.connection.settimeout(2)
                counters["calls"] += 1
                size = int(self.headers.get("Content-Length", "0"))
                expected = "Basic " + base64.b64encode(("synthetic-client:" + secret).encode()).decode()
                if (counters["calls"] > 128 or self.path != "/token" or not 0 < size <= 16_384
                        or self.headers.get("Authorization") != expected):
                    counters["invalid"] += 1
                    self.send_error(400)
                    return
                fields = urllib.parse.parse_qs(self.rfile.read(size).decode())
                if fields.get("token_type_hint") != ["access_token"]:
                    counters["invalid"] += 1
                token = fields.get("token", [""])[0]
                if counters["stall"]:
                    time.sleep(0.7)
                payload = {"active": token in {"write-a", "write-b", "read-a", "read-b", "global", "expired", "wrong-audience"}
                           and not counters["revoked"], "iss": issuer, "sub": token,
                           "aud": "signal" if token != "wrong-audience" else "other",
                           "exp": int(time.time()) + (60 if token != "expired" else -1), "token_type": "Bearer",
                           "roles": ["global"], "scope": "admin"}
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass  # A cancelled caller may close its socket first.

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "leaf.pem", root / "leaf.key")
        provider = FiniteTLSProvider(("127.0.0.1", 0), Handler, context)
        provider_thread = threading.Thread(target=provider.serve_forever, kwargs={"poll_interval": 0.02})
        start_provider_thread(provider_thread)
        all_scope = {field: {"mode": "all"} for field in ("sources", "accounts", "resources")}

        def scoped(account):
            return {"sources": {"mode": "only", "values": ["synthetic"]},
                    "accounts": {"mode": "only", "values": [account]},
                    "resources": {"mode": "only", "values": ["resource-" + account]}}

        roles = []
        bindings = []
        for token, op, account in (("write-a", "ingest_events", "a"), ("write-b", "ingest_events", "b"),
                                   ("read-a", "query_events", "a"), ("read-b", "query_events", "b")):
            roles.append({"id": token, "permissions": [{"operation": op, "scope": scoped(account)}]})
            bindings.append({"issuer": issuer, "subject": token, "roles": [token]})
        roles.append({"id": "global", "permissions": [{"operation": op, "scope": all_scope}
                     for op in ("read_findings", "read_findings_feed", "read_evidence", "configure", "manage_rules", "read_audit")]})
        bindings.append({"issuer": issuer, "subject": "global", "roles": ["global"]})
        # A restricted finding capability authorizes only canonical, newly derived rows.
        roles.append({"id": "scoped-findings", "permissions": [{"operation": "read_findings", "scope": scoped("a")}]})
        bindings[2]["roles"].append("scoped-findings")
        config = {"schema_version": 1, "endpoint": f"https://127.0.0.1:{provider.server_port}/token",
                  "client_id": "synthetic-client", "issuer": issuer, "audience": "signal", "workers": 2,
                  "lease_seconds": 30, "request_timeout_ms": 1000,
                  "roots_der_base64": [base64.b64encode(ca_der).decode()],
                  "policy": {"schema_version": 1, "roles": roles, "bindings": bindings}}
        config_path = root / "identity.json"
        config_path.write_text(json.dumps(config))
        rules = root / "rules"
        rules.mkdir()
        (rules / "synthetic.yaml").write_text("apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: synthetic.scope\n  name: Synthetic scope\nspec:\n  severity: high\n  match:\n    all:\n      - field: source.type\n        eq: synthetic\n  finding:\n    title: Synthetic security event\n")
        server_config = root / "server.yaml"
        server_config.write_text("schema_version: 1\nrules:\n  directories:\n    - " + json.dumps(str(rules)) + "\n")
        env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
        env.update(SIGNAL_CONFIG=str(server_config), SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_ACCESS_CONFIG=str(config_path),
                   SIGNAL_IDENTITY_CLIENT_SECRET=secret, SIGNAL_WAL_DIR=str(root / "wal"),
                   SIGNAL_STORAGE_DIR=str(root / "events"), SIGNAL_FINDINGS_DIR=str(root / "findings"),
                   SIGNAL_STORAGE_FLUSH_MS="10", SIGNAL_QUERY_TIMEOUT_MS="500", SIGNAL_REQUEST_TIMEOUT_MS="500")

        def request(method, path, body=None, token=None, headers=None):
            connection = http.client.HTTPConnection(host, port, timeout=3)
            try:
                h = {"Content-Type": "application/json", **(headers or {})}
                if token is not None:
                    h["Authorization"] = "Bearer " + token
                connection.request(method, path, json.dumps(body) if body is not None else None, h)
                response = connection.getresponse()
                body_bytes = response.read(1024 * 1024 + 1)
                assert len(body_bytes) <= 1024 * 1024, "bounded identity HTTP response"
                body_value = json.loads(body_bytes) if response.getheader("Content-Type", "").startswith("application/json") else body_bytes.decode()
                return response.status, body_value, dict(response.getheaders())
            finally:
                connection.close()

        def start(overrides=None, fail=False):
            nonlocal process, port, generation
            generation += 1
            log = root / f"identity-server-{generation}.log"
            process_logs.append(log)
            process = spawn_owned(owner, [binary], dict(env, **(overrides or {})), log.stem)
            if fail:
                assert process.wait(timeout=7) != 0, "invalid access configuration started"
                owner.reap_log(process)
                owner.reaped(process)
                assert "durable ingest and Parquet storage ready" not in log_text(log)
                process = None
                return
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                owner.check_logs()
                assert process.poll() is None, "server exited before readiness"
                for line in log_text(log).splitlines():
                    try:
                        address = json.loads(line).get("fields", {}).get("listen")
                    except ValueError:
                        continue
                    if address:
                        port = int(address.rsplit(":", 1)[1])
                        assert request("GET", "/readyz")[0] == 200
                        return
                time.sleep(0.01)
            raise TimeoutError("identity server startup deadline exceeded")

        # All configuration failures precede persistence/readiness and expose no secrets.
        start({"SIGNAL_API_TOKEN": "legacy-synthetic-token"}, fail=True)
        start({"SIGNAL_IDENTITY_CLIENT_SECRET": ""}, fail=True)
        start({"SIGNAL_ACCESS_CONFIG": str(root)}, fail=True)
        assert not (root / "wal").exists()
        retained_event = None
        if (root / "retained-event.json").exists():
            retained_event = json.loads((root / "retained-event.json").read_text())
            (root / "retained-wal").rename(root / "wal")
        start()
        endpoint = "/v1/events"
        assert request("GET", endpoint + "?limit=bad", headers={"x-forwarded-user": "global"})[0] == 401
        assert request("GET", endpoint, token="bogus", headers={"x-forwarded-user": "global", "x-forwarded-roles": "global"})[0] == 403
        assert request("GET", endpoint, token="expired")[0] == 403
        assert request("GET", endpoint, token="wrong-audience")[0] == 403
        assert request("GET", endpoint, token="write-a")[0] == 403
        assert request("GET", endpoint + "?limit=bad", token="read-a")[0] == 400

        events = []
        for index, account in enumerate(("b", "a")):
            events.append({"schema_version": 1, "id": str(uuid.uuid4()),
                           "timestamp": f"2026-10-06T0{index}:00:00Z", "observed_at": "2026-10-06T12:00:00Z",
                           "source": {"type": "synthetic"}, "severity": "info", "message": "private-event-" + account,
                           "resource": {"kind": "host", "id": "resource-" + account, "account_id": account},
                           "attributes": {"account_id": "a", "roles": ["global"]}, "tags": []})
        status, denial, _ = request("POST", endpoint + "/batch", {"events": events}, "write-a")
        assert status == 403 and denial["accepted"] == 0
        assert request("POST", endpoint + "/batch", {"events": [events[1]]}, "read-a")[0] == 403
        for token, event in (("write-b", events[0]), ("write-a", events[1])):
            status, reply, _ = request("POST", endpoint + "/batch", {"events": [event]}, token)
            assert status == 202 and reply["event_ids"] == [event["id"]]

        def exact_rows():
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                code_a, rows_a, headers_a = request("GET", endpoint + "?from=2026-10-06T00%3A00%3A00Z&limit=1", token="read-a")
                code_b, rows_b, _ = request("GET", endpoint + "?limit=1", token="read-b")
                assert code_a == code_b == 200
                assert headers_a.get("cache-control") == "no-store"
                if rows_a["events"] and rows_b["events"]:
                    assert rows_a["events"] == [events[1]] and rows_b["events"] == [events[0]]
                    assert request("GET", endpoint + "?account=b", token="read-a")[1]["events"] == []
                    return
                time.sleep(0.01)
            raise TimeoutError("exact scoped Parquet query deadline")

        exact_rows()
        counters["revoked"] = True
        assert request("GET", endpoint, token="read-a")[0] == 403
        assert request("POST", endpoint + "/batch", {"events": [events[1]]}, "write-a")[0] == 403
        counters["revoked"] = False
        exact_rows()
        def exact_findings():
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status, scoped_rows, headers = request("GET", "/v1/findings?limit=1", token="read-a")
                assert status == 200 and headers.get("cache-control") == "no-store"
                if scoped_rows["findings"]:
                    rows = scoped_rows["findings"]
                    assert len(rows) == 1 and rows[0]["event_ids"] == [events[1]["id"]]
                    assert rows[0]["attributes"]["signal.scope.v1"]["account"] == "a"
                    assert request("GET", "/v1/findings?rule_id=absent", token="read-a")[1]["findings"] == []
                    status, global_rows, _ = request("GET", "/v1/findings", token="global")
                    assert status == 200 and len(global_rows["findings"]) == 2 + int(retained_event is not None)
                    expected_ids = {row["id"] for row in events}
                    if retained_event is not None:
                        expected_ids.add(retained_event["id"])
                        historical = [row for row in global_rows["findings"] if row["event_ids"] == [retained_event["id"]]]
                        assert len(historical) == 1 and "signal.scope.v1" not in historical[0]["attributes"]
                    assert {row["event_ids"][0] for row in global_rows["findings"]} == expected_ids
                    return rows
                time.sleep(0.01)
            raise TimeoutError("exact scoped finding deadline")
        original_findings = exact_findings()
        assert request("GET", "/v1/findings?limit=bad", token="write-a")[0] == 403
        assert request("GET", "/v1/findings?limit=bad", token="read-a")[0] == 400
        assert request("GET", "/v1/findings", token="read-b")[0] == 403
        assert request("GET", "/v1/findings/feed?after=begin", token="read-a")[0] == 403
        assert request("GET", "/v1/findings", token="global")[0] == 200
        status, original_feed, _ = request("GET", "/v1/findings/feed?after=begin", token="global")
        assert status == 200 and len(original_feed["findings"]) == 2 + int(retained_event is not None)
        assert request("GET", endpoint, token="global")[0] == 403
        for path in ("/v1/evidence", "/v1/admin", "/v1/rules", "/v1/audit"):
            conn = http.client.HTTPConnection(host, port, timeout=3)
            try:
                conn.request("GET", path, headers={"Authorization": "Bearer global"})
                r = conn.getresponse()
                assert r.status == 404
                r.read()
            finally:
                conn.close()
        counters["stall"] = True
        started = time.monotonic()
        assert request("GET", endpoint, token="read-a")[0] == 408
        assert request("GET", "/v1/findings", token="read-a")[0] == 408
        assert time.monotonic() - started < 1.5
        counters["stall"] = False
        time.sleep(0.25)
        exact_rows()
        stop(kill=True)
        start()
        exact_rows()
        assert exact_findings() == original_findings
        assert request("GET", "/v1/findings/feed?after=begin", token="global")[1] == original_feed
        stop()
        # Replacing policy changes subsequent requests only through validated restart.
        config["policy"]["bindings"] = [b for b in config["policy"]["bindings"] if b["subject"] != "read-a"]
        config_path.write_text(json.dumps(config))
        start()
        assert request("GET", endpoint, token="read-a")[0] == 403
        assert request("GET", endpoint, token="read-b")[1]["events"] == [events[0]]
        stop()
        assert counters["invalid"] == 0 and 0 < counters["calls"] <= 128
        owner.check_logs()
        for log in process_logs:
            text = log_text(log)
            assert secret not in text and "legacy-synthetic-token" not in text
            assert "private-event-" not in text
        print("Identity server gate passed: scoped synced admission, exact Parquet and scoped finding queries, unknown backlog, revocation, crash/restart and immutable-policy reload")
    finally:
        # Every owner gets cleanup even if another cleanup reports failure.
        signal.alarm(0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_errors = owner.cleanup()
        stop_provider(provider, provider_thread)
        assert not cleanup_errors, "owned identity fixture cleanup failed"


if __name__ == "__main__":
    def timed_out(_signal, _frame):
        raise TimeoutError("identity server campaign deadline exceeded")
    signal.signal(signal.SIGALRM, timed_out)
    signal.signal(signal.SIGTERM, timed_out)
    signal.signal(signal.SIGINT, timed_out)
    signal.alarm(90)
    main()

#!/usr/bin/env python3
"""Validate proposed requirements; optionally exercise existing predicate rules.

The runtime mode qualifies normalized synthetic inputs only. It does not evaluate
the catalog's proposed coverage, window, state or correlation semantics.
"""

import argparse
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "tests/fixtures/security-requirements/catalog.json"
DOMAINS = {"aws_control_plane", "iam_security_controls", "kubernetes_audit",
           "authentication", "host_runtime"}
NATIVE_IDS = {"SIG-D01", "SIG-D02", "SIG-D03", "SIG-D05", "SIG-D07"}
REQUIRED = {"id", "name", "domain", "required_sources", "coverage_preconditions",
            "normalization", "rule_type", "trigger", "state_requirements",
            "missing_data_behavior", "evidence_retention", "severity_confidence",
            "expected_secops_action", "capability_status", "fixtures"}
TOKEN = "synthetic-loopback-requirements"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_catalog(path):
    require(path.stat().st_size <= 4_194_304, "catalog exceeds 4 MiB limit")
    raw = path.read_bytes()
    catalog = json.loads(raw)
    require(catalog.get("schema_version") == 1, "unsupported catalog version")
    sources = catalog.get("source_profiles", [])
    require(len(sources) == 7, "expected seven source profiles")
    source_ids = {s["id"] for s in sources}
    require(len(source_ids) == 7, "duplicate source profile")
    records = catalog.get("detections", [])
    require(len(records) == 15, "expected fifteen requirements")
    require({d["domain"] for d in records} == DOMAINS, "evidence domain mismatch")
    require({d["id"] for d in records} == {f"SIG-D{i:02d}" for i in range(1, 16)},
            "requirement IDs missing or duplicated")
    native = set()
    event_ids = set()
    for d in records:
        require(REQUIRED <= d.keys(), f"{d['id']}: incomplete requirement")
        require(all(d[key] for key in REQUIRED), f"{d['id']}: empty requirement field")
        require(d["required_sources"] and set(d["required_sources"]) <= source_ids,
                f"{d['id']}: unknown source")
        require(d["rule_type"] in {"predicate", "window", "state", "correlation"},
                f"{d['id']}: unknown rule type")
        native_rule = d.get("native_rule")
        if native_rule:
            native.add(d["id"])
            require(d["rule_type"] == "predicate" and
                    d["capability_status"] == "normalized_predicate_runnable",
                    "native rules must describe existing predicates")
            require(native_rule["metadata"]["id"] == d["id"], "native rule ID mismatch")
            require(native_rule["spec"]["severity"] ==
                    d["severity_confidence"]["suggested_severity"], "severity mismatch")
        else:
            require(d["capability_status"] == "planned", "future capability mislabeled")
        cases = d["fixtures"]
        require(len(cases) == 3 and {f["case"] for f in cases} ==
                {"positive", "negative", "missing_data"}, "fixture cases missing/duplicated")
        for f in cases:
            expected = {"positive": "match", "negative": "no_match",
                        "missing_data": "indeterminate"}[f["case"]]
            require(f["id"] == d["id"] + "-" + f["case"], "fixture ID mismatch")
            require(f["expected_assessment"] == expected, "fixture assessment mismatch")
            require(f["expected_native_findings"] ==
                    int(bool(native_rule) and f["case"] == "positive"),
                    "fixture native finding expectation mismatch")
            require(f["coverage_status"] == ("unknown" if f["case"] == "missing_data"
                                              else "verified_for_fixture"),
                    "fixture coverage expectation mismatch")
            require(isinstance(f["state"], dict) and isinstance(f["parameters"], dict),
                    "fixture state/parameters must be objects")
            require(len(f["events"]) == 1, "starter fixtures require one event each")
            for e in f["events"]:
                require({"schema_version", "id", "timestamp", "observed_at", "source",
                         "severity", "message", "attributes", "tags"} <= e.keys(),
                        "incomplete canonical fixture event")
                require(e["schema_version"] == 1 and e["severity"] == "info",
                        "unexpected canonical event version/severity")
                for key in ("timestamp", "observed_at"):
                    require(e[key].endswith("Z") and
                            datetime.fromisoformat(e[key].replace("Z", "+00:00")).tzinfo is not None,
                            "fixture timestamps must be explicit UTC")
                require(e["source"]["type"] and isinstance(e["message"], str) and
                        isinstance(e["tags"], list), "invalid canonical fixture fields")
                require(e["source"]["name"] == "requirement-fixture", "non-fixture source")
                require(isinstance(e["attributes"]["security"], dict), "missing normalized fields")
                require(e["attributes"]["evidence_ref"] == f"fixture://{d['id']}/{f['case']}",
                        "non-synthetic evidence reference")
                require(str(uuid.UUID(e["id"])) == e["id"] and e["id"] not in event_ids,
                        "invalid or reused fixture event ID")
                event_ids.add(e["id"])
                require(len(json.dumps(e).encode()) <= 8192, "fixture event exceeds 8 KiB")
    require(native == NATIVE_IDS, "unexpected native predicate set")
    return catalog, hashlib.sha256(raw).hexdigest()


def request(address, method, path, body=None):
    conn = http.client.HTTPConnection(address, timeout=3)
    try:
        payload = None if body is None else json.dumps(body).encode()
        conn.request(method, path, payload, {"Authorization": f"Bearer {TOKEN}",
                                            "Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read(8_388_609)
        require(len(raw) <= 8_388_608, "HTTP response exceeds bound")
        return response.status, json.loads(raw) if raw else None
    finally:
        conn.close()


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start(server, output, iteration):
    log_path = output / f"server-{iteration}.log"
    env = {k: v for k, v in os.environ.items() if not k.startswith("SIGNAL_")}
    env.update(SIGNAL_LISTEN="127.0.0.1:0", SIGNAL_API_TOKEN=TOKEN,
               SIGNAL_WAL_DIR=str(output / "wal"), SIGNAL_STORAGE_DIR=str(output / "store"),
               SIGNAL_FINDINGS_DIR=str(output / "findings"),
               SIGNAL_RULE_DIRS=str(output / "rules"), SIGNAL_STORAGE_FLUSH_MS="10")
    with log_path.open("xb") as log:
        process = subprocess.Popen([str(server)], cwd=output, env=env,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            require(process.poll() is None, f"server exited; see {log_path}")
            require(log_path.stat().st_size <= 1_048_576, "server startup log exceeds bound")
            for line in log_path.read_text().splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                address = record.get("fields", {}).get("listen")
                if address:
                    require(address.startswith("127.0.0.1:"), "non-loopback server")
                    if request(address, "GET", "/readyz")[0] == 200:
                        return process, address
            time.sleep(0.02)
        raise ValueError(f"server startup deadline exceeded; see {log_path}")
    except BaseException:
        stop(process)
        raise


def snapshot(address):
    status, events = request(address, "GET", "/v1/events?limit=100")
    require(status == 200, f"event query returned {status}")
    status, findings = request(address, "GET", "/v1/findings?limit=100")
    require(status == 200, f"finding query returned {status}")
    require(events["schema_version"] == findings["schema_version"] == 1,
            "unexpected query schema")
    return events["events"], findings["findings"]


def runtime(catalog, catalog_hash, server, output):
    require(server.is_file() and os.access(server, os.X_OK), "server binary unavailable")
    output.mkdir(parents=True, exist_ok=False)
    (output / "rules").mkdir()
    native = [d for d in catalog["detections"] if d.get("native_rule")]
    events = [f["events"][0] for d in native for f in d["fixtures"]]
    for d in native:
        (output / "rules" / (d["id"] + ".yaml")).write_text(json.dumps(d["native_rule"]))
    expected_pairs = {(d["id"], d["fixtures"][0]["events"][0]["id"]) for d in native}
    process, address = start(server, output, 1)
    try:
        status, admission = request(address, "POST", "/v1/events/batch", {"events": events})
        require(status == 202 and admission["accepted"] == len(events), "WAL admission failed")
        require(admission["event_ids"] == [e["id"] for e in events], "admission IDs differ")
        deadline = time.monotonic() + 20
        rows, findings = [], []
        while time.monotonic() < deadline:
            require(process.poll() is None, "server exited during processing")
            rows, findings = snapshot(address)
            if len(rows) == len(events) and len(findings) == len(native):
                break
            time.sleep(0.03)
        require(len(rows) == len(events), "events did not persist within deadline")
        require(len(findings) == len(native), "unexpected finding count")
        require({(f["rule_id"], f["event_ids"][0]) for f in findings} == expected_pairs,
                "positive/negative/missing predicate results differ")
        expected_events = {e["id"]: e for e in events}
        require({e["id"] for e in rows} == set(expected_events), "persisted event IDs differ")
        for e in rows:
            for field, value in expected_events[e["id"]].items():
                require(e[field] == value, f"persisted event {field} differs")
        for f in findings:
            d = next(d for d in native if d["id"] == f["rule_id"])
            require(f["severity"] == d["severity_confidence"]["suggested_severity"] and
                    f["schema_version"] == 1, "finding contract differs")
        before = sorted(findings, key=lambda f: f["id"])
        process.kill()
        require(process.wait(timeout=5) == -signal.SIGKILL, "forced owned-server stop failed")
        process, address = start(server, output, 2)
        rows_after, findings_after = snapshot(address)
        require(sorted(rows_after, key=lambda e: e["id"]) == sorted(rows, key=lambda e: e["id"]),
                "events changed after crash/restart")
        require(sorted(findings_after, key=lambda f: f["id"]) == before,
                "findings changed after crash/restart")
        process.send_signal(signal.SIGTERM)
        require(process.wait(timeout=12) == 0, "graceful stop failed")
        with server.open("rb") as binary:
            server_hash = hashlib.file_digest(binary, "sha256").hexdigest()
        report = {"schema_version": 1, "status": "passed", "catalog_sha256": catalog_hash,
                  "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "server_sha256": server_hash,
                  "fixture_cases": 15, "persisted_events": len(rows), "persisted_findings": len(findings),
                  "native_rules": len(native), "crash_restart": True, "graceful_shutdown": True,
                  "scope": "Existing normalized predicates and event/finding persistence only",
                  "not_qualified": ["raw source collection", "coverage assessment", "window/state/correlation",
                                    "AWS/EKS/ARM64", "notification", "security-owned evidence"]}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--server", type=Path)
    parser.add_argument("--output", type=Path, help="New owned runtime output directory")
    args = parser.parse_args()
    require(bool(args.server) == bool(args.output), "--server and --output must be supplied together")
    catalog, digest = load_catalog(args.catalog)
    print("Catalog valid: 15 requirements, 7 source profiles, 45 fixture cases, 5 native predicates")
    if args.server:
        report = runtime(catalog, digest, args.server.resolve(), args.output.resolve())
        print(f"Runtime passed: {report['fixture_cases']} cases, {report['persisted_events']} events, "
              f"{report['persisted_findings']} findings, crash/restart; report: {args.output / 'report.json'}")
    else:
        print("Structural validation only; future assessments and real source coverage remain unqualified")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired,
            http.client.HTTPException) as error:
        print(f"Security requirement check failed: {error}", file=sys.stderr)
        sys.exit(1)

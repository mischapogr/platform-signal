#!/usr/bin/env python3
"""Bounded native Linux release-binary pipeline campaign; no builds or Docker changes."""
import argparse
import contextlib
import concurrent.futures
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
WORKERS = 4
MAX_EVENTS = 10000
WINDOW = 5.0
HTTP_TIMEOUT = 5
RESPONSE_BYTES = 1048576


@contextlib.contextmanager
def defer_spawn_signals():
    """Keep Python interrupts pending until the spawned process is registered.

    Signals are not blocked in the OS, so children retain their normal mask.
    """
    previous = {}
    pending = None

    def defer(signum, _frame):
        nonlocal pending
        pending = signum

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, defer)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if pending is not None:
        raise KeyboardInterrupt(f'interrupted by signal {pending} during spawn')


def request(base, path, payload=None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(RESPONSE_BYTES + 1)
        if len(body) > RESPONSE_BYTES:
            raise RuntimeError("response exceeded harness bound")
        return response.status, body


def metrics(base):
    status, body = request(base, "/metrics")
    if status != 200:
        raise RuntimeError("metrics status " + str(status))
    return {parts[0]: int(parts[1]) for line in body.decode().splitlines()
            if not line.startswith("#") and len(parts := line.split()) == 2}


def port():
    # The listener bind can race another process; startup failure is reported.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def event(size, index):
    row = {"schema_version": 1, "id": str(uuid.uuid4()),
           "timestamp": "2026-10-06T12:00:00Z", "observed_at": "2026-10-06T12:00:01Z",
           "source": {"type": "application", "name": "pipeline-benchmark"},
           "severity": "warn", "message": "login failed" if index % 20 == 0 else "request completed",
           "attributes": {"index": index, "padding": ""}}
    encoded = json.dumps(row, separators=(",", ":")).encode()
    row["attributes"]["padding"] = "x" * (size - len(encoded))
    return row


def config(directory, http_port, metrics_port, saturation):
    return f'''schema_version: 1
server:
  listen: "127.0.0.1:{http_port}"
  shutdown_timeout: "10s"
ingest:
  max_request_bytes: 1048576
  max_batch_events: 100
  request_timeout: "4s"
buffer:
  memory_events: {8 if saturation else 4096}
  memory_bytes: 16777216
  wal_directory: {directory}/wal
  max_record_bytes: 16384
  segment_bytes: 1048576
  max_segments: 64
  max_wal_bytes: 67108864
  admission_policy: reject_new
storage:
  type: parquet
  directory: {directory}/events
  flush_events: 1000
  flush_interval: "100ms"
  max_event_bytes: 16384
  max_disk_bytes: 67108864
  max_files: 2048
  compression: snappy
query:
  memory_bytes: 67108864
  max_concurrent: 2
  max_limit: 100
  max_response_bytes: 1048576
  max_files: 2048
  timeout: "4s"
rules:
  directories: [{ROOT}/rules/examples]
findings:
  directory: {directory}/findings
  max_disk_bytes: 16777216
  max_findings: 10000
telemetry:
  metrics_listen: "127.0.0.1:{metrics_port}"
'''


class Sampler:
    def __init__(self, pid, endpoint):
        self.pid, self.endpoint = pid, endpoint
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.peak_rss = 0
        self.cpu_ticks = 0
        self.peaks = {}
        self.samples = 0
        self.failures = 0

    def sample(self):
        try:
            fields = Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()
            rss = int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
            ticks = int(fields[11]) + int(fields[12])
            snapshot = metrics(self.endpoint)
            with self.lock:
                self.peak_rss = max(self.peak_rss, rss)
                self.cpu_ticks = max(self.cpu_ticks, ticks)
                for name, value in snapshot.items():
                    self.peaks[name] = max(value, self.peaks.get(name, 0))
                self.samples += 1
        except (OSError, ValueError, RuntimeError):
            self.failures += 1

    def run(self):
        while not self.stop.is_set():
            self.sample()
            self.stop.wait(0.1)


def profile(binary, size, rate, saturation):
    with tempfile.TemporaryDirectory(prefix="signal-pipeline-bench-") as folder:
        directory = Path(folder)
        http_port, metrics_port = port(), port()
        while metrics_port == http_port:
            metrics_port = port()
        api, telemetry = f"http://127.0.0.1:{http_port}", f"http://127.0.0.1:{metrics_port}"
        configuration = config(directory, http_port, metrics_port, saturation)
        if "  admission_policy: reject_new\n" not in configuration:
            raise RuntimeError("this harness requires reject_new for definite 429 suffix accounting")
        (directory / "server.yaml").write_text(configuration)
        # Preserve an explicit minimal environment; never inherit host SIGNAL_* settings/tokens.
        env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
        env["SIGNAL_CONFIG"] = str(directory / "server.yaml")
        process = sampler = sampling = None
        started = False
        try:
            with defer_spawn_signals():
                process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, start_new_session=True)
            sampler = Sampler(process.pid, telemetry)
            sampling = threading.Thread(target=sampler.run)
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError("server startup failed: exit " + str(process.returncode))
                try:
                    if request(api, "/readyz")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("readiness deadline")
                time.sleep(0.1)
            sampler.sample()
            initial_ticks = sampler.cpu_ticks
            sampling.start()
            started = True
            start = time.monotonic()
            batch_size = min(100, max(1, rate // (WORKERS * 10)))

            def send(worker):
                attempted = accepted = rejected = uncertain = matched = timeout_rejected = unavailable_rejected = capacity_rejected = 0
                responses = {}
                while attempted < MAX_EVENTS // WORKERS and time.monotonic() - start < WINDOW:
                    due = start + attempted / (rate / WORKERS)
                    delay = due - time.monotonic()
                    if delay > 0:
                        time.sleep(min(delay, max(0, WINDOW - (time.monotonic() - start))))
                    if time.monotonic() - start >= WINDOW:
                        break
                    count = min(batch_size, MAX_EVENTS // WORKERS - attempted)
                    rows = [event(size, worker * (MAX_EVENTS // WORKERS) + attempted + index)
                            for index in range(count)]
                    attempted += count
                    try:
                        status, body = request(api, "/v1/events/batch", {"events": rows})
                        result = json.loads(body)
                        a, r = result["accepted"], result["rejected"]
                        if a + r != count or not (0 <= a <= count and 0 <= r <= count):
                            raise RuntimeError("batch response accounting")
                        accepted += a
                        rejected += r
                        if status == 408:
                            timeout_rejected += r
                        elif status == 503:
                            unavailable_rejected += r
                        elif status == 429:
                            capacity_rejected += r
                        matched += sum(row["message"] == "login failed" for row in rows[:a])
                        responses[str(status)] = responses.get(str(status), 0) + 1
                    except (OSError, ValueError, KeyError):
                        uncertain += count
                return {"attempted": attempted, "accepted": accepted, "rejected": rejected,
                        "transport_uncertain": uncertain, "expected_matches": matched,
                        "timeout_response_rejected": timeout_rejected,
                        "unavailable_response_rejected": unavailable_rejected,
                        "confirmed_capacity_rejected": capacity_rejected, "statuses": responses}

            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
                results = list(pool.map(send, range(WORKERS)))
            load_seconds = time.monotonic() - start
            sampler.sample()
            totals = {name: sum(row[name] for row in results) for name in
                      ("attempted", "accepted", "rejected", "transport_uncertain", "expected_matches", "timeout_response_rejected", "unavailable_response_rejected", "confirmed_capacity_rejected")}
            if totals["attempted"] != totals["accepted"] + totals["rejected"] + totals["transport_uncertain"]:
                raise RuntimeError("campaign accounting")
            load_cpu = (sampler.cpu_ticks - initial_ticks) / os.sysconf("SC_CLK_TCK")
            drain_started = time.monotonic()
            while True:
                final = metrics(telemetry)
                if final["signal_queue_depth"] == 0 and final["signal_storage_persisted_total"] >= final["signal_events_accepted_total"]:
                    break
                if time.monotonic() - drain_started > 30:
                    raise RuntimeError("drain deadline")
                time.sleep(0.1)
            drain_seconds = time.monotonic() - drain_started
            if totals["transport_uncertain"] == 0:
                for key, value in [("signal_events_accepted_total", totals["accepted"]),
                                   ("signal_events_rejected_total", totals["rejected"])]:
                    if final[key] != value:
                        raise RuntimeError(f"{key} accounting mismatch: metric={final[key]} expected={value}; counts={totals}; metrics={final}")
            durable = final["signal_wal_accepted_total"]
            # A received 408/503 can hide only its one in-flight append beyond
            # the known prefix. A lost response can hide the whole batch;
            # transport_uncertain counts events, rather than failed requests.
            uncertain_requests = sum(row["statuses"].get("408", 0) + row["statuses"].get("503", 0) for row in results)
            uncertain_suffix = totals["timeout_response_rejected"] + totals["unavailable_response_rejected"]
            uncertainty_bound = min(uncertain_suffix, uncertain_requests) + totals["transport_uncertain"]
            if not totals["accepted"] <= durable <= totals["accepted"] + uncertainty_bound:
                raise RuntimeError("WAL admissions outside HTTP confirmed plus deadline/transport uncertainty bound")
            for key in ("signal_storage_persisted_total", "signal_rules_evaluated_total"):
                if final[key] != durable:
                    raise RuntimeError(key + " does not match durable WAL admissions")
            if not totals["expected_matches"] <= final["signal_findings_count"] <= totals["expected_matches"] + uncertainty_bound:
                raise RuntimeError("finding count outside confirmed match plus admission uncertainty bound")
            latencies = []
            for _ in range(20):
                began = time.monotonic()
                status, body = request(api, "/v1/events?source_name=pipeline-benchmark&limit=100")
                if status != 200:
                    raise RuntimeError("query status " + str(status))
                rows = json.loads(body)["events"]
                if len(rows) != min(durable, 100):
                    raise RuntimeError("bounded query sample count")
                latencies.append((time.monotonic() - began) * 1000)
            sampler.sample()
            status, body = request(api, "/v1/findings?limit=100")
            if status != 200:
                raise RuntimeError("finding query status " + str(status))
            final = metrics(telemetry)
            disk = {name: sum(path.stat().st_size for path in (directory / name).rglob("*") if path.is_file())
                    for name in ("wal", "events", "findings")}
            result = {"event_bytes": size, "target_eps": rate, "saturation": saturation,
                      "window_seconds": WINDOW, "max_events": MAX_EVENTS, "workers": WORKERS,
                      "batch_events": batch_size, "load_seconds": round(load_seconds, 4),
                      "drain_seconds": round(drain_seconds, 4), **totals,
                      "attempted_eps": round(totals["attempted"] / load_seconds, 2),
                      "accepted_eps": round(totals["accepted"] / load_seconds, 2),
                      "wal_durable_events": durable,
                      "admission_uncertainty_bound": uncertainty_bound,
                      "durable_beyond_http_confirmed": durable - totals["accepted"],
                      "durable_eps": round(durable / (load_seconds + drain_seconds), 2),
                      "admission_payload_mib_per_second": round(totals["accepted"] * size / load_seconds / 1048576, 4),
                      "parquet_growth_mib_per_second": round(final["signal_storage_bytes"] / (load_seconds + drain_seconds) / 1048576, 4),
                      "load_cpu_seconds": round(load_cpu, 3),
                      "load_cpu_percent_one_core": round(load_cpu / load_seconds * 100, 2),
                      "peak_rss_bytes": sampler.peak_rss, "sample_count": sampler.samples,
                      "sample_failures": sampler.failures, "metric_peaks": sampler.peaks,
                      "final_metrics": final, "disk_bytes": disk,
                      "query_samples": 20, "query_median_ms": round(statistics.median(latencies), 3),
                      "query_p95_ms": round(sorted(latencies)[math.ceil(0.95 * len(latencies)) - 1], 3),
                      "statuses": {key: sum(row["statuses"].get(key, 0) for row in results)
                                   for key in sorted({key for row in results for key in row["statuses"]})},
                      "configuration": configuration.replace(str(directory), "<temporary-data>")}
        finally:
            if sampler is not None:
                sampler.stop.set()
            if started:
                sampling.join(timeout=HTTP_TIMEOUT + 2)
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if started and sampling.is_alive():
                raise RuntimeError("sampler failed to stop")
        if process.returncode != 0:
            raise RuntimeError("server graceful shutdown failed: " + str(process.returncode))
        result["shutdown_exit_code"] = process.returncode
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-id", default="unspecified; binary hash is authoritative")
    parser.add_argument("--quick", action="store_true", help="one 1 KiB/100 EPS profile for harness diagnosis")
    parser.add_argument("--quick-rate", type=int, choices=(100, 1000, 10000), default=100)
    parser.add_argument("--overload-only", action="store_true", help="one 4 KiB/20,000 target EPS profile with an eight-event queue")
    args = parser.parse_args()
    binary = args.server.resolve(strict=True)
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        raise RuntimeError("native Linux AMD64/ARM64 required")
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    report = {"schema_version": 1, "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "platform": platform.platform(), "architecture": platform.machine(), "cpu_count": os.cpu_count(),
              "server_version": subprocess.run([str(binary), "--version"], capture_output=True,
                                               text=True, check=True, timeout=10).stdout.strip(),
              "binary_sha256": digest.hexdigest(), "image_id": args.image_id,
              "profiles": [], "limits": {"profile_seconds": WINDOW, "max_events": MAX_EVENTS,
                                         "workers": WORKERS, "http_timeout_seconds": HTTP_TIMEOUT,
                                         "wal_bytes": 67108864, "storage_bytes": 67108864,
                                         "findings_bytes": 16777216}}
    profiles = [(4096, 20000, True)] if args.overload_only else [(1024, args.quick_rate, False)] if args.quick else [
        (size, rate, False) for size in (1024, 4096) for rate in (100, 1000, 10000)] + [(4096, 20000, True)]
    for size, rate, saturation in profiles:
        result = profile(binary, size, rate, saturation)
        report["profiles"].append(result)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: result[key] for key in ("event_bytes", "target_eps", "saturation", "attempted",
                          "accepted", "rejected", "transport_uncertain", "accepted_eps", "peak_rss_bytes")}), flush=True)


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    main()

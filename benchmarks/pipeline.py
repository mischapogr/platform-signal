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
import stat
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



# Public diagnostics contain only these source-known labels, never exception text.
PIPELINE_PROFILES = frozenset({'prepare', 'report', '1k-100', '1k-1000', '1k-10000',
                               '4k-100', '4k-1000', '4k-10000', '4k-20000-saturation'})
PIPELINE_CHECKS = frozenset({'prepare', 'configuration', 'spawn', 'readiness', 'load',
    'batch-accounting', 'campaign-accounting', 'drain', 'http-accepted-accounting',
    'http-rejected-accounting', 'wal-accounting', 'storage-accounting', 'rules-accounting',
    'findings-accounting', 'event-query', 'event-query-status', 'event-query-count',
    'finding-query', 'finding-query-status', 'measurement', 'sampler-shutdown',
    'server-shutdown', 'report-write', 'report-identity', 'report-profiles',
    'report-measurements', 'report-accounting', 'report-validation'})
PIPELINE_KINDS = frozenset({'last-entered', 'assertion-failed'})
DIAGNOSTIC_BYTES = 2048


def profile_label(size, rate, saturation):
    return f'{size // 1024}k-{rate}' + ('-saturation' if saturation else '')


class PipelineAssertion(RuntimeError):
    def __init__(self, check, message):
        super().__init__(message)
        self.check = check


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate diagnostic field')
        value[key] = item
    return value


def validate_diagnostic(value):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'profile', 'check', 'kind'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['profile'], str) or value['profile'] not in PIPELINE_PROFILES
            or not isinstance(value['check'], str) or value['check'] not in PIPELINE_CHECKS
            or not isinstance(value['kind'], str) or value['kind'] not in PIPELINE_KINDS):
        raise ValueError('invalid pipeline diagnostic')
    return value


def read_diagnostic(path):
    # A fresh host-selected sidecar is optional evidence, never qualification.
    try:
        initial = os.lstat(path)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1
                or initial.st_size > DIAGNOSTIC_BYTES):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_size > DIAGNOSTIC_BYTES
                    or (metadata.st_dev, metadata.st_ino) != (initial.st_dev, initial.st_ino)):
                return None
            raw = stream.read(DIAGNOSTIC_BYTES + 1)
        if len(raw) > DIAGNOSTIC_BYTES:
            return None
        return validate_diagnostic(json.loads(raw, object_pairs_hook=unique_object))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return None


class Diagnostic:
    def __init__(self, path):
        self.path = path
        self.current = {'schema_version': 1, 'profile': 'prepare', 'check': 'prepare', 'kind': 'last-entered'}
        self.failed = False
        self.lock = threading.RLock()
        # Never adopt or overwrite a prior run's diagnostic.
        with path.open('x') as stream:
            stream.write(json.dumps(self.current) + '\n')

    def enter(self, check, profile=None):
        with self.lock:
            if self.failed:
                return
            self.current.update(check=check, kind='last-entered')
            if profile is not None:
                self.current['profile'] = profile
            self.write()

    def fail(self, error):
        with self.lock:
            if self.failed:
                return
            self.failed = True
            if isinstance(error, PipelineAssertion):
                self.current.update(check=error.check, kind='assertion-failed')
            self.write()

    def write(self):
        validate_diagnostic(self.current)
        raw = (json.dumps(self.current, separators=(',', ':')) + '\n').encode()
        if len(raw) > DIAGNOSTIC_BYTES:
            raise ValueError('pipeline diagnostic exceeded bound')
        temporary = self.path.with_name(self.path.name + '.next')
        try:
            with temporary.open('x') as stream:
                stream.write(raw.decode())
            temporary.replace(self.path)
        except OSError:
            # Optional diagnostic I/O cannot interrupt owned process retirement
            # or replace the underlying assertion. A prior point is last-known.
            pass


def enter(diagnostic, check):
    if diagnostic is not None:
        diagnostic.enter(check)


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


def profile(binary, size, rate, saturation, diagnostic=None):
    enter(diagnostic, "configuration")
    with tempfile.TemporaryDirectory(prefix="signal-pipeline-bench-") as folder:
        directory = Path(folder)
        http_port, metrics_port = port(), port()
        while metrics_port == http_port:
            metrics_port = port()
        api, telemetry = f"http://127.0.0.1:{http_port}", f"http://127.0.0.1:{metrics_port}"
        configuration = config(directory, http_port, metrics_port, saturation)
        if "  admission_policy: reject_new\n" not in configuration:
            raise PipelineAssertion("configuration", "this harness requires reject_new for definite 429 suffix accounting")
        (directory / "server.yaml").write_text(configuration)
        # Preserve an explicit minimal environment; never inherit host SIGNAL_* settings/tokens.
        env = {key: value for key, value in os.environ.items() if not key.startswith("SIGNAL_")}
        env["SIGNAL_CONFIG"] = str(directory / "server.yaml")
        process = sampler = sampling = None
        started = False
        primary = None
        try:
            enter(diagnostic, "spawn")
            with defer_spawn_signals():
                process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, start_new_session=True)
            sampler = Sampler(process.pid, telemetry)
            sampling = threading.Thread(target=sampler.run)
            enter(diagnostic, "readiness")
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise PipelineAssertion("readiness", "server startup failed: exit " + str(process.returncode))
                try:
                    if request(api, "/readyz")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise PipelineAssertion("readiness", "readiness deadline")
                time.sleep(0.1)
            sampler.sample()
            initial_ticks = sampler.cpu_ticks
            sampling.start()
            started = True
            enter(diagnostic, "load")
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
                            error = PipelineAssertion("batch-accounting", "batch response accounting")
                            if diagnostic is not None:
                                diagnostic.fail(error)
                            raise error
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
                raise PipelineAssertion("campaign-accounting", "campaign accounting")
            load_cpu = (sampler.cpu_ticks - initial_ticks) / os.sysconf("SC_CLK_TCK")
            enter(diagnostic, "drain")
            drain_started = time.monotonic()
            while True:
                final = metrics(telemetry)
                if final["signal_queue_depth"] == 0 and final["signal_storage_persisted_total"] >= final["signal_events_accepted_total"]:
                    break
                if time.monotonic() - drain_started > 30:
                    raise PipelineAssertion("drain", "drain deadline")
                time.sleep(0.1)
            drain_seconds = time.monotonic() - drain_started
            if totals["transport_uncertain"] == 0:
                for key, value in [("signal_events_accepted_total", totals["accepted"]),
                                   ("signal_events_rejected_total", totals["rejected"])]:
                    if final[key] != value:
                        raise PipelineAssertion("http-accepted-accounting" if key == "signal_events_accepted_total" else "http-rejected-accounting", f"{key} accounting mismatch: metric={final[key]} expected={value}; counts={totals}; metrics={final}")
            durable = final["signal_wal_accepted_total"]
            # A received 408/503 can hide only its one in-flight append beyond
            # the known prefix. A lost response can hide the whole batch;
            # transport_uncertain counts events, rather than failed requests.
            uncertain_requests = sum(row["statuses"].get("408", 0) + row["statuses"].get("503", 0) for row in results)
            uncertain_suffix = totals["timeout_response_rejected"] + totals["unavailable_response_rejected"]
            uncertainty_bound = min(uncertain_suffix, uncertain_requests) + totals["transport_uncertain"]
            if not totals["accepted"] <= durable <= totals["accepted"] + uncertainty_bound:
                raise PipelineAssertion("wal-accounting", "WAL admissions outside HTTP confirmed plus deadline/transport uncertainty bound")
            for key in ("signal_storage_persisted_total", "signal_rules_evaluated_total"):
                if final[key] != durable:
                    raise PipelineAssertion("storage-accounting" if key == "signal_storage_persisted_total" else "rules-accounting", key + " does not match durable WAL admissions")
            if not totals["expected_matches"] <= final["signal_findings_count"] <= totals["expected_matches"] + uncertainty_bound:
                raise PipelineAssertion("findings-accounting", "finding count outside confirmed match plus admission uncertainty bound")
            enter(diagnostic, "event-query")
            latencies = []
            for _ in range(20):
                began = time.monotonic()
                status, body = request(api, "/v1/events?source_name=pipeline-benchmark&limit=100")
                if status != 200:
                    raise PipelineAssertion("event-query-status", "query status " + str(status))
                rows = json.loads(body)["events"]
                if len(rows) != min(durable, 100):
                    raise PipelineAssertion("event-query-count", "bounded query sample count")
                latencies.append((time.monotonic() - began) * 1000)
            sampler.sample()
            enter(diagnostic, "finding-query")
            status, body = request(api, "/v1/findings?limit=100")
            if status != 200:
                raise PipelineAssertion("finding-query-status", "finding query status " + str(status))
            enter(diagnostic, "measurement")
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
        except BaseException as error:
            primary = error
            if diagnostic is not None:
                diagnostic.fail(error)
            raise
        finally:
            cleanup_errors = []
            try:
                enter(diagnostic, 'sampler-shutdown')
                if sampler is not None:
                    sampler.stop.set()
                if started:
                    sampling.join(timeout=HTTP_TIMEOUT + 2)
                    if sampling.is_alive():
                        raise PipelineAssertion('sampler-shutdown', 'sampler failed to stop')
            except BaseException as error:
                cleanup_errors.append(error)
                if diagnostic is not None:
                    diagnostic.fail(error)
            try:
                enter(diagnostic, 'server-shutdown')
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                if process is not None and process.returncode != 0:
                    raise PipelineAssertion('server-shutdown', 'server graceful shutdown failed: ' + str(process.returncode))
            except BaseException as error:
                cleanup_errors.append(error)
                if diagnostic is not None:
                    diagnostic.fail(error)
            if primary is not None:
                for error in cleanup_errors:
                    primary.add_note('secondary pipeline cleanup failure: ' +
                                     (error.check if isinstance(error, PipelineAssertion) else 'last-entered'))
            elif cleanup_errors:
                raise cleanup_errors[0]
        result["shutdown_exit_code"] = process.returncode
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-id", default="unspecified; binary hash is authoritative")
    parser.add_argument("--quick", action="store_true", help="one 1 KiB/100 EPS profile for harness diagnosis")
    parser.add_argument("--quick-rate", type=int, choices=(100, 1000, 10000), default=100)
    parser.add_argument("--overload-only", action="store_true", help="one 4 KiB/20,000 target EPS profile with an eight-event queue")
    parser.add_argument("--diagnostic-output", type=Path, help="fresh host-selected fixed-label sidecar")
    args = parser.parse_args(argv)
    diagnostic = Diagnostic(args.diagnostic_output) if args.diagnostic_output is not None else None
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
        if diagnostic is not None:
            diagnostic.enter('configuration', profile_label(size, rate, saturation))
        try:
            result = (profile(binary, size, rate, saturation) if diagnostic is None else
                      profile(binary, size, rate, saturation, diagnostic))
        except BaseException as error:
            if diagnostic is not None:
                diagnostic.fail(error)
            raise
        enter(diagnostic, 'report-write')
        report["profiles"].append(result)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: result[key] for key in ("event_bytes", "target_eps", "saturation", "attempted",
                          "accepted", "rejected", "transport_uncertain", "accepted_eps", "peak_rss_bytes")}), flush=True)


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    main()

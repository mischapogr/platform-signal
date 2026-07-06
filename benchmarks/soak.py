#!/usr/bin/env python3
"""Finite native server soak and process-accounted I/O; no device throughput claim."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import tempfile
import threading
import time

_spec = importlib.util.spec_from_file_location('soak_pipeline', Path(__file__).with_name('pipeline.py'))
pipeline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pipeline)
BUCKETS = 12
REPORT_CAP = 262144
QUERY_MEMORY_BYTES = 268435456
IO_KEYS = ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes', 'cancelled_write_bytes')
METRICS = ('signal_queue_depth', 'signal_queue_capacity', 'signal_wal_bytes',
           'signal_storage_bytes', 'signal_storage_files', 'signal_findings_count',
           'signal_queue_bytes', 'signal_wal_command_depth', 'signal_wal_waiters',
           'signal_storage_command_depth', 'signal_wal_segments')
COUNTS = ('attempted', 'accepted', 'rejected', 'transport_uncertain', 'expected_matches',
          'timeout_response_rejected', 'unavailable_response_rejected', 'confirmed_capacity_rejected')


def bounds(seconds, rate):
    if not 10 <= seconds <= 600 or not 10 <= rate <= 200:
        raise ValueError('duration must be 10..600 seconds and target EPS 10..200')
    return math.ceil(seconds * rate)


def binary_identity(binary):
    if binary.is_symlink() or not binary.is_file() or binary.stat().st_size > 134217728:
        raise ValueError('server must be a bounded regular executable ELF file')
    machine = {'x86_64': 62, 'aarch64': 183}.get(platform.machine())
    with binary.open('rb') as stream:
        header = stream.read(20)
    if platform.system() != 'Linux' or len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', header[18:20])[0] != machine or not os.access(binary, os.X_OK):
        raise ValueError('native Linux AMD64/ARM64 executable required')
    digest = hashlib.sha256()
    with binary.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def process_sample(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    counters = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/io').read_text().splitlines())
    return {'rss': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'),
            'ticks': int(fields[11]) + int(fields[12]),
            'io': {name: int(counters[name]) for name in IO_KEYS}}


def io_delta(first, last):
    result = {name: last[name] - first[name] for name in IO_KEYS}
    if any(value < 0 for value in result.values()):
        raise RuntimeError('process I/O counters decreased')
    return result


class Trend:
    """Fixed twelve time buckets; no growing sample history."""
    def __init__(self, pid, endpoint, start, seconds):
        self.pid, self.endpoint, self.start, self.seconds = pid, endpoint, start, seconds
        self.stop = threading.Event()
        self.buckets = [dict(samples=0, rss_sum=0, rss_min=None, rss_max=0, metric_peaks={}) for _ in range(BUCKETS)]
        self.failures = 0
        self.samples = 0
        self.first = self.last = None
        self.last_elapsed = None
        self.max_sample_gap_seconds = 0

    def add(self, elapsed, reading, snapshot):
        index = min(BUCKETS - 1, max(0, int(elapsed / self.seconds * BUCKETS)))
        bucket = self.buckets[index]
        bucket['samples'] += 1
        bucket['rss_sum'] += reading['rss']
        bucket['rss_min'] = reading['rss'] if bucket['rss_min'] is None else min(bucket['rss_min'], reading['rss'])
        bucket['rss_max'] = max(bucket['rss_max'], reading['rss'])
        for name in METRICS:
            if name in snapshot:
                bucket['metric_peaks'][name] = max(snapshot[name], bucket['metric_peaks'].get(name, 0))
        if self.first is None:
            self.first = reading
        self.last = reading
        if self.last_elapsed is not None:
            self.max_sample_gap_seconds = max(self.max_sample_gap_seconds, elapsed - self.last_elapsed)
        self.last_elapsed = elapsed
        bucket.setdefault('first_elapsed', elapsed)
        bucket['last_elapsed'] = elapsed
        bucket.setdefault('first_ticks', reading['ticks'])
        bucket['last_ticks'] = reading['ticks']
        bucket.setdefault('first_io', reading['io'])
        bucket['last_io'] = reading['io']
        self.samples += 1

    def sample(self):
        reading = process_sample(self.pid)
        snapshot = pipeline.metrics(self.endpoint)
        self.add(time.monotonic() - self.start, reading, snapshot)

    def run(self):
        # At most ceil(duration) + 1 samples, each bounded by HTTP_TIMEOUT.
        for _ in range(math.ceil(self.seconds) + 1):
            if self.stop.is_set() or time.monotonic() - self.start >= self.seconds:
                return
            try:
                self.sample()
            except (OSError, ValueError, RuntimeError, KeyError):
                self.failures += 1
            self.stop.wait(1)

    def report(self):
        if not self.samples or not self.buckets[0]['samples'] or not self.buckets[-1]['samples']:
            raise RuntimeError('missing warmup or final load resource samples')
        rows = []
        for index, bucket in enumerate(self.buckets):
            row = {'from_seconds': index * self.seconds / BUCKETS, 'to_seconds': (index + 1) * self.seconds / BUCKETS,
                   'samples': bucket['samples'], 'rss_min_bytes': bucket['rss_min'],
                   'rss_max_bytes': bucket['rss_max'], 'metric_peaks': bucket['metric_peaks']}
            if bucket['samples']:
                row.update(sampled_span_seconds=bucket['last_elapsed'] - bucket['first_elapsed'],
                           rss_mean_bytes=bucket['rss_sum'] / bucket['samples'],
                           cpu_seconds=(bucket['last_ticks'] - bucket['first_ticks']) / os.sysconf('SC_CLK_TCK'),
                           process_io_delta=io_delta(bucket['first_io'], bucket['last_io']))
            rows.append(row)
        drift = rows[-1]['rss_mean_bytes'] - rows[0]['rss_mean_bytes']
        return {'sample_count': self.samples, 'sample_failures': self.failures, 'max_sample_gap_seconds': self.max_sample_gap_seconds, 'buckets': rows,
                'warmup_to_final_rss_mean_drift_bytes': drift,
                'rss_observed_min_bytes': min(row['rss_min_bytes'] for row in rows if row['samples']),
                'rss_observed_max_bytes': max(row['rss_max_bytes'] for row in rows),
                'scope': 'finite shared-host observations; no universal memory plateau or ceiling pass'}


def account_response(totals, statuses, rows, status, body):
    result = json.loads(body)
    a, r = result['accepted'], result['rejected']
    if type(a) is not int or type(r) is not int or a < 0 or r < 0 or a + r != len(rows) or status not in (202, 408, 429, 503):
        raise RuntimeError('invalid batch response accounting')
    totals['accepted'] += a
    totals['rejected'] += r
    totals['expected_matches'] += sum(row['message'] == 'login failed' for row in rows[:a])
    name = {408: 'timeout_response_rejected', 429: 'confirmed_capacity_rejected', 503: 'unavailable_response_rejected'}.get(status)
    if name:
        totals[name] += r
    statuses[str(status)] = statuses.get(str(status), 0) + 1


def reconcile(totals, statuses, final):
    if totals['attempted'] != totals['accepted'] + totals['rejected'] + totals['transport_uncertain']:
        raise RuntimeError('campaign accounting mismatch')
    if totals['transport_uncertain'] == 0:
        for key, expected in [('signal_events_accepted_total', totals['accepted']), ('signal_events_rejected_total', totals['rejected'])]:
            if final[key] != expected:
                raise RuntimeError(key + ' HTTP accounting mismatch')
    uncertain = min(totals['timeout_response_rejected'] + totals['unavailable_response_rejected'],
                    statuses.get('408', 0) + statuses.get('503', 0)) + totals['transport_uncertain']
    durable = final['signal_wal_accepted_total']
    if not totals['accepted'] <= durable <= totals['accepted'] + uncertain:
        raise RuntimeError('WAL admissions outside bounded HTTP uncertainty')
    for key in ('signal_storage_persisted_total', 'signal_rules_evaluated_total'):
        if final[key] != durable:
            raise RuntimeError(key + ' does not match WAL admissions')
    for key in ('signal_events_dropped_total', 'signal_storage_failures_total', 'signal_storage_timeouts_total',
                'signal_storage_full_total', 'signal_storage_fail_closed', 'signal_rules_failures_total',
                'signal_findings_failures_total', 'signal_findings_rejections_total', 'signal_findings_timeouts_total', 'signal_findings_closed'):
        if final[key] != 0:
            raise RuntimeError(key + ' must remain zero')
    if not totals['expected_matches'] <= final['signal_findings_count'] <= totals['expected_matches'] + uncertain:
        raise RuntimeError('finding count outside bounded uncertainty')
    return durable, uncertain


def stop_process(process):
    # This server has no subprocess workers. A second interrupt still kills/reaps it.
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=12)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def soak_config(directory, http_port, metrics_port):
    # Long campaigns retain more Parquet files. The bounded query budget uses
    # QueryConfig's 256 MiB default; the short pipeline keeps its 64 MiB budget.
    return pipeline.config(directory, http_port, metrics_port, False).replace(
        'max_files: 2048', 'max_files: 8192').replace(
        'max_disk_bytes: 67108864', 'max_disk_bytes: 268435456').replace(
        'query:\n  memory_bytes: 67108864', f'query:\n  memory_bytes: {QUERY_MEMORY_BYTES}')


class QueryFailure(RuntimeError):
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__('bounded query failed: ' + json.dumps(diagnostic, sort_keys=True))


def checked_query(api, path, field, expected):
    began = time.monotonic()
    diagnostic = {'path': path, 'expected_rows': expected}
    try:
        status, body = pipeline.request(api, path)
    except OSError as error:
        diagnostic.update(kind='transport', error=str(error)[:512])
        raise QueryFailure(diagnostic) from error
    diagnostic['status'] = status
    if status != 200:
        diagnostic.update(kind='http_status', response_preview=body[:2048].decode('utf-8', errors='replace'))
        raise QueryFailure(diagnostic)
    try:
        rows = json.loads(body)[field]
        if not isinstance(rows, list):
            raise ValueError('response rows are not a list')
    except (ValueError, KeyError, TypeError) as error:
        diagnostic.update(kind='response_shape', error=str(error)[:512],
                          response_preview=body[:2048].decode('utf-8', errors='replace'))
        raise QueryFailure(diagnostic) from error
    if len(rows) != expected:
        diagnostic.update(kind='row_count', observed_rows=len(rows))
        raise QueryFailure(diagnostic)
    return (time.monotonic() - began) * 1000


def profile(binary, size, seconds=120, rate=100, observation=None, retain=lambda: None):
    maximum = bounds(seconds, rate)
    if size not in (1024, 4096):
        raise ValueError('event size must be 1024 or 4096')
    with tempfile.TemporaryDirectory(prefix='signal-soak-') as folder:
        directory = Path(folder)
        http_port, metrics_port = pipeline.port(), pipeline.port()
        while metrics_port == http_port:
            metrics_port = pipeline.port()
        api, telemetry = f'http://127.0.0.1:{http_port}', f'http://127.0.0.1:{metrics_port}'
        configuration = soak_config(directory, http_port, metrics_port)
        (directory / 'server.yaml').write_text(configuration)
        result = {} if observation is None else observation
        result.update(event_bytes=size, target_eps=rate, duration_seconds=seconds, max_events=maximum,
                      status='failed', stage='startup', shutdown_exit_code=None, query_samples=0, query_ms=[],
                      configuration=configuration.replace(str(directory), '<temporary-data>'),
                      configuration_sha256=hashlib.sha256(configuration.replace(str(directory), '<temporary-data>').encode()).hexdigest())
        retain()
        env = {key: value for key, value in os.environ.items() if not key.startswith('SIGNAL_')}
        env['SIGNAL_CONFIG'] = str(directory / 'server.yaml')
        process = trend = thread = None
        try:
            with pipeline.defer_spawn_signals():
                process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError('server startup failed')
                try:
                    if pipeline.request(api, '/readyz')[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError('readiness deadline')
                time.sleep(0.1)
            start = time.monotonic()
            initial = process_sample(process.pid)
            trend = Trend(process.pid, telemetry, start, seconds)
            thread = threading.Thread(target=trend.run)
            thread.start()
            totals, statuses = dict.fromkeys(COUNTS, 0), {}
            batch = min(20, max(1, rate // 10))
            requests = 0
            while totals['attempted'] < maximum:
                due = start + totals['attempted'] / rate
                delay = min(due - time.monotonic(), start + seconds - time.monotonic())
                if delay > 0:
                    time.sleep(delay)
                if time.monotonic() >= start + seconds:
                    break
                count = min(batch, maximum - totals['attempted'])
                rows = [pipeline.event(size, totals['attempted'] + index) for index in range(count)]
                totals['attempted'] += count
                requests += 1
                try:
                    status, body = pipeline.request(api, '/v1/events/batch', {'events': rows})
                except OSError:
                    totals['transport_uncertain'] += count
                    continue
                # Malformed responses fail qualification, rather than disguising a server bug.
                account_response(totals, statuses, rows, status, body)
            # Finish the requested window even when the final paced batch reaches the event cap.
            remaining = start + seconds - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            load_seconds = time.monotonic() - start
            trend.stop.set()
            thread.join(timeout=pipeline.HTTP_TIMEOUT + 2)
            if thread.is_alive():
                raise RuntimeError('resource sampler stop deadline')
            load_end = process_sample(process.pid)
            trend.sample()
            resources = trend.report()
            result.update(stage='load_complete', load_seconds=load_seconds, **totals, statuses=statuses,
                          ingest_requests=requests, batch_events=batch, resources=resources,
                          attempted_eps=totals['attempted'] / load_seconds, accepted_eps=totals['accepted'] / load_seconds,
                          load_cpu_seconds=(load_end['ticks'] - initial['ticks']) / os.sysconf('SC_CLK_TCK'),
                          load_process_io_delta=io_delta(initial['io'], load_end['io']))
            retain()
            drain_start = time.monotonic()
            while True:
                final = pipeline.metrics(telemetry)
                if final['signal_queue_depth'] == 0 and final['signal_storage_persisted_total'] >= final['signal_wal_accepted_total'] and final['signal_rules_evaluated_total'] >= final['signal_wal_accepted_total']:
                    break
                if time.monotonic() - drain_start >= 30:
                    raise RuntimeError('drain deadline')
                time.sleep(0.1)
            drain_seconds = time.monotonic() - drain_start
            durable, uncertain = reconcile(totals, statuses, final)
            result.update(stage='drained', drain_seconds=drain_seconds, final_metrics=final,
                          wal_durable_events=durable, admission_uncertainty_bound=uncertain,
                          durable_beyond_http_confirmed=durable - totals['accepted'],
                          io_scope='/proc/PID/io: rchar/wchar include nondisk I/O; read_bytes storage-layer reads; write_bytes page-dirtying accounting; cancelled_write_bytes separate cancellation counter; not physical-device throughput')
            retain()
            result['stage'] = 'queries'
            try:
                for _ in range(20):
                    result['query_ms'].append(checked_query(api, '/v1/events?source_name=pipeline-benchmark&limit=100', 'events', min(durable, 100)))
                    result['query_samples'] = len(result['query_ms'])
                result['findings_query_ms'] = checked_query(api, '/v1/findings?limit=100', 'findings', min(final['signal_findings_count'], 100))
            except QueryFailure as error:
                result['query_failure'] = error.diagnostic
                raise
            finally:
                try:
                    after = process_sample(process.pid)
                    result['load_drain_queries_process_io_delta'] = io_delta(initial['io'], after['io'])
                    result['post_query_metrics'] = pipeline.metrics(telemetry)
                except (OSError, ValueError, RuntimeError, KeyError) as error:
                    result['post_query_sampling_error'] = str(error)[:512]
                    if 'query_failure' not in result:
                        raise
                finally:
                    retain()
        except BaseException as error:
            result['error'] = str(error)[:4096]
            retain()
            raise
        finally:
            try:
                if trend is not None:
                    trend.stop.set()
                if thread is not None and thread.ident is not None:
                    thread.join(timeout=pipeline.HTTP_TIMEOUT + 2)
            finally:
                try:
                    stop_process(process)
                finally:
                    if process is not None:
                        result['shutdown_exit_code'] = process.returncode
                    retain()
        if process.returncode != 0:
            raise RuntimeError('server graceful shutdown failed')
        result.update(status='passed', stage='complete', shutdown_exit_code=process.returncode)
        retain()
        return result


def write_report(stream, report):
    encoded = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    if len(encoded) > REPORT_CAP:
        raise RuntimeError('report exceeds bound')
    stream.seek(0)
    stream.write(encoded)
    stream.truncate()
    stream.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--output', type=Path, required=True, help='new file; existing evidence is never overwritten')
    parser.add_argument('--duration', '--seconds', type=int, default=120, help='seconds per size profile (10..600)')
    parser.add_argument('--rate', type=int, default=100, help='target EPS (10..200)')
    parser.add_argument('--event-bytes', type=int, choices=(1024, 4096), help='one size; default runs both')
    args = parser.parse_args(argv)
    maximum = bounds(args.duration, args.rate)
    digest = binary_identity(args.server)
    binary = args.server.resolve(strict=True)
    report = {'schema_version': 1, 'status': 'failed', 'architecture': platform.machine(),
              'platform': platform.platform(), 'cpu_count': os.cpu_count(),
              'binary_sha256': digest, 'scope': 'bounded-soak' if args.duration >= 120 else 'diagnostic',
              'inputs_sha256': {str(path.relative_to(pipeline.ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in [Path(__file__).resolve(), Path(pipeline.__file__).resolve()]
                                + sorted((pipeline.ROOT / 'rules/examples').glob('*.yaml'))}, 'image_id': args.image_id, 'profiles': [],
              'limits': {'seconds_per_profile': args.duration, 'max_events_per_profile': maximum,
                         'retained_buckets': BUCKETS, 'sample_attempts_per_profile': args.duration + 1,
                         'http_timeout_seconds': pipeline.HTTP_TIMEOUT, 'response_bytes': pipeline.RESPONSE_BYTES,
                         'max_batch_events': 20, 'report_bytes': REPORT_CAP, 'wal_bytes': 67108864,
                         'query_memory_bytes': QUERY_MEMORY_BYTES, 'storage_bytes': 268435456, 'storage_files': 8192, 'findings_bytes': 16777216},
              'measured_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    # Exclusive creation rejects existing files, symlinks and binary/hardlink aliases.
    with args.output.open('xb') as stream:
        write_report(stream, report)
        try:
            for size in ((args.event_bytes,) if args.event_bytes else (1024, 4096)):
                row = {}
                report['profiles'].append(row)
                profile(binary, size, args.duration, args.rate, observation=row,
                        retain=lambda: write_report(stream, report))
                write_report(stream, report)
                print(json.dumps({name: row[name] for name in ('event_bytes', 'accepted', 'rejected', 'accepted_eps')}), flush=True)
            report['status'] = 'passed'
        except BaseException as error:
            report['error'] = str(error)
            raise
        finally:
            write_report(stream, report)
    return 0


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())

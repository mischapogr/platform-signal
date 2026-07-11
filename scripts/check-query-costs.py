#!/usr/bin/env python3
"""Finite actual-server query/cache measurements over owned persistent S3 fixtures.

Structural local evidence only: no AWS price, production throughput, physical
storage or full-release qualification. Reuses the existing bounded process owner.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import time
from urllib.parse import urlencode
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signal_query_cost_fixture', ROOT / 'scripts/check-object-query.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
HOURS, PER_HOUR, BATCH, MESSAGE_BYTES, REPEATS, LIMIT = 8, 256, 128, 4096, 5, 32


def http(url, method='GET', body=None):
    payload = None if body is None else json.dumps(body).encode()
    if payload is not None and len(payload) > BASE.MAX_HTTP:
        raise RuntimeError('bounded request bytes')
    request = Request(url, data=payload, method=method, headers={'Authorization': 'Bearer ' + BASE.TOKEN, 'Content-Type': 'application/json'})
    try:
        response = build_opener(ProxyHandler({})).open(request, timeout=6)
    except HTTPError as error:
        response = error
    with response:
        data = response.read(BASE.MAX_HTTP + 1)
        if len(data) > BASE.MAX_HTTP:
            raise RuntimeError('bounded response bytes')
        return response.status, data


def message(hour, index):
    return hashlib.shake_256(f'synthetic-query-cost/{hour}/{index}'.encode()).hexdigest(MESSAGE_BYTES // 2)


class Run(BASE.Run):
    def __init__(self, out, binary):
        super().__init__(out, binary)
        self.query_files = 32
        self.query_memory = 32 * 1024 * 1024
        self.oracle = []
        self.samples = []

    def env(self):
        env = super().env()
        env.update({'SIGNAL_STORAGE_BATCH_EVENTS': str(BATCH),
                    'SIGNAL_STORAGE_FLUSH_MS': '1000',
                    'SIGNAL_QUERY_FILES': str(self.query_files),
                    'SIGNAL_QUERY_MEMORY_BYTES': str(self.query_memory),
                    'SIGNAL_QUERY_TIMEOUT_MS': '5000'})
        return env

    def requests(self):
        path = self.fixture_root / 'requests.jsonl'
        if not path.exists():
            return []
        with path.open('rb') as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise RuntimeError('fixture request accounting capacity')
        return [json.loads(line) for line in data.splitlines()]

    def data_gets(self):
        return sum(row['method'] == 'GET' and row['key'].split('?', 1)[0].endswith('.parquet') for row in self.requests())

    def metric(self, name):
        code, body = http(self.url + '/metrics')
        if code != 200:
            raise RuntimeError('query metrics unavailable')
        matches = [line.split()[1] for line in body.decode().splitlines() if line.startswith(name + ' ')]
        if len(matches) != 1:
            raise RuntimeError('exact query metric required')
        return int(matches[0])

    def cache_identity(self):
        paths = sorted((self.server_root / 'derived' / 'objects').glob('*.parquet'))
        if len(paths) > 32:
            raise RuntimeError('bounded cache evidence inventory')
        return {path.name: [path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ino, BASE.file_hash(path)] for path in paths}

    def query(self, label, selected, partitions, expected, extra=None, error=None):
        params = {'order': 'asc', 'limit': str(LIMIT)}
        params.update(extra or {})
        before_gets = self.data_gets()
        before_scans = self.metric('signal_query_scanned_files_total')
        started = time.monotonic()
        code, body = http(self.url + '/v1/events?' + urlencode(params))
        elapsed = round((time.monotonic() - started) * 1000, 3)
        data = json.loads(body)
        if error is not None:
            if code != error or 'events' in data:
                raise RuntimeError('resource denial must not return partial/empty success')
            metadata = None
            identities = []
        else:
            if code != 200 or set(data) != {'schema_version', 'events', 'metadata'} or data['schema_version'] != 1:
                raise RuntimeError(f'query response contract at {label}: HTTP {code}; keys {sorted(data)}; error code {data.get("error", data.get("code"))}')
            rows = data['events']
            identities = [row['id'] for row in rows]
            if identities != [row['id'] for row in expected[:LIMIT]]:
                raise RuntimeError('exact query oracle mismatch')
            for row, reference in zip(rows, expected[:LIMIT]):
                if row['message'] != message(reference['hour'], reference['index']) or row['attributes'] != {'sample': {'group': 'security' if reference['index'] % 64 == 0 else 'normal', 'ordinal': reference['index'], 'nested': [1, True, None]}}:
                    raise RuntimeError('canonical payload/projection changed')
            metadata = data['metadata']
            if (metadata['scanned_files'], metadata['candidate_partitions']) != (selected, partitions):
                raise RuntimeError('partition selection metadata mismatch')
        after_scans = self.metric('signal_query_scanned_files_total')
        if error == 413 and (self.data_gets() != before_gets or after_scans != before_scans):
            raise RuntimeError('selected/decoded budget denial must precede data materialization')
        if error is None and after_scans - before_scans != selected:
            raise RuntimeError('selected files counter mismatch')
        sample = {'label': label, 'status': code, 'wall_ms': elapsed,
                  'metadata': metadata, 'response_bytes': len(body),
                  'data_gets': self.data_gets() - before_gets,
                  'scanned_counter_delta': after_scans - before_scans,
                  'event_ids': identities}
        self.samples.append(sample)
        return sample

    def range(self, hour):
        return {'from': f'2026-07-10T{hour:02d}:00:00Z', 'to': f'2026-07-10T{hour + 1:02d}:00:00Z'}

    def run(self):
        self.start_fixture()
        self.start_server()
        for hour in range(HOURS):
            for first in range(0, PER_HOUR, BATCH):
                events = [{'timestamp': f'2026-07-10T{hour:02d}:{index // 60:02d}:{index % 60:02d}Z',
                           'source': {'type': 'cost-canary' if index % 64 == 0 else 'cost-simulation'},
                           'severity': 'error' if index % 64 == 0 else 'info',
                           'message': message(hour, index),
                           'attributes': {'sample': {'group': 'security' if index % 64 == 0 else 'normal', 'ordinal': index, 'nested': [1, True, None]}}}
                          for index in range(first, first + BATCH)]
                code, body = http(self.url + '/v1/events/batch', 'POST', {'schema_version': 1, 'events': events})
                response = json.loads(body)
                if code != 202 or response.get('accepted') != BATCH or len(response.get('event_ids', [])) != BATCH:
                    raise RuntimeError(f'exact bounded WAL admission accounting: status {code}; accepted {response.get("accepted")}')
                self.oracle.extend({'id': identity, 'hour': hour, 'index': first + offset}
                                   for offset, identity in enumerate(response['event_ids']))
                def acknowledged():
                    try:
                        return self.checkpoint() == len(self.oracle)
                    except FileNotFoundError:
                        return False
                self.wait(acknowledged)
        catalog = BASE.read_json(self.fixture_root / 'catalog.json')
        data = {key: value for key, value in catalog.items() if '/data/' in key}
        if len(catalog) != 32 or len(data) != 16 or self.checkpoint() != HOURS * PER_HOUR:
            raise RuntimeError('exact 16-batch/8-partition publication')
        protected = BASE.file_hash(self.fixture_root / 'catalog.json')
        objects = {key: BASE.file_hash(self.fixture_root / 'objects' / value['file']) for key, value in catalog.items()}
        narrow = [row for row in self.oracle if row['hour'] == 3]
        cold = self.query('narrow-cold', 2, 1, narrow, self.range(3))
        if cold['data_gets'] != 2:
            raise RuntimeError('cold query must download only selected partition data')
        narrow_identity = self.cache_identity()
        for _ in range(REPEATS):
            if self.query('narrow-warm', 2, 1, narrow, self.range(3))['data_gets'] != 2:
                raise RuntimeError('warm selected copies must retain exact remote reauthentication')
        if self.cache_identity() != narrow_identity:
            raise RuntimeError('warm narrow query changed derived file identity/mtime/hash')
        broad = self.query('broad-first', 16, 8, self.oracle)
        if broad['data_gets'] != 16:
            raise RuntimeError('broad query must authenticate every selected source object')
        broad_identity = self.cache_identity()
        for _ in range(REPEATS):
            if self.query('broad-warm', 16, 8, self.oracle)['data_gets'] != 16:
                raise RuntimeError('warm broad copies must retain exact remote reauthentication')
        rare = [row for row in self.oracle if row['index'] % 64 == 0]
        for params, label in [({'source': 'cost-canary'}, 'source-predicate'),
                              ({'severity': 'error'}, 'severity-predicate'),
                              ({'attribute.sample.group': json.dumps('security')}, 'attribute-predicate')]:
            for _ in range(REPEATS):
                self.query(label, 16, 8, rare, params)
        if self.cache_identity() != broad_identity:
            raise RuntimeError('warm broad/predicate query changed derived file identity/mtime/hash')
        self.query('outside-retained-range', 0, 0, [], self.range(9))
        cache = self.server_root / 'derived'
        files = sorted((cache / 'objects').glob('*.parquet'))
        if len(files) != 16:
            raise RuntimeError('exact rebuildable cache file count')
        cache_bytes = sum(path.stat().st_size for path in files)
        cache_hashes = {path.name: BASE.file_hash(path) for path in files}
        if any(name != digest + '.parquet' for name, digest in cache_hashes.items()):
            raise RuntimeError('authenticated content-addressed cache')
        self.stop('server')
        # Preserve the stopped derived directory as a witness; restart with a
        # fresh cache, rather than claiming this fixture move tests the pruner.
        os.rename(cache, self.out / 'retained-cache-witness')
        self.start_server()
        rebuilt = self.query('narrow-after-empty-cache', 2, 1, narrow, self.range(3))
        if rebuilt['data_gets'] != 2:
            raise RuntimeError('cache rebuild must authenticate selected source objects')
        if any(cache_hashes.get(path.name) != BASE.file_hash(path) for path in (cache / 'objects').glob('*.parquet')):
            raise RuntimeError('rebuild changed canonical query copy')
        self.stop('server')
        self.query_files = 4
        self.start_server()
        self.query('file-budget-broad-denial', 0, 0, [], error=413)
        self.query('file-budget-narrow-success', 2, 1, narrow, self.range(3))
        self.stop('server')
        self.query_files, self.query_memory = 32, 64 * 1024
        self.start_server()
        self.query('decoded-budget-broad-denial', 0, 0, [], error=413)
        self.query('decoded-budget-empty-success', 0, 0, [], self.range(9))
        if BASE.file_hash(self.fixture_root / 'catalog.json') != protected or self.checkpoint() != len(self.oracle):
            raise RuntimeError('query changed committed source/control')
        for key, value in catalog.items():
            if BASE.file_hash(self.fixture_root / 'objects' / value['file']) != objects[key]:
                raise RuntimeError('query modified immutable source bytes')
        groups = {}
        for label in sorted({sample['label'] for sample in self.samples}):
            matched = [sample for sample in self.samples if sample['label'] == label]
            groups[label] = {'samples': len(matched), 'median_wall_ms': statistics.median(sample['wall_ms'] for sample in matched),
                             'max_wall_ms': max(sample['wall_ms'] for sample in matched),
                             'data_gets': sum(sample['data_gets'] for sample in matched)}
        return {'canonical_event_count': len(self.oracle), 'partitions': HOURS,
                'committed_data_objects': len(data), 'manifest_objects': len(catalog) - len(data),
                'compressed_data_bytes': sum(meta['bytes'] for meta in data.values()),
                'fixture_bytes': sum(meta['bytes'] for meta in catalog.values()),
                'cache_bytes': cache_bytes, 'samples': self.samples, 'groups': groups,
                'warm_file_identity_mtime_hash_preserved': True,
                'cache_boundary': 'Derived files are reused/rebuildable, but each query reauthenticates exact remote bytes. Warm cache is not a remote-GET cost reduction.',
                'query_files_normal': 32, 'query_memory_normal': 32 * 1024 * 1024,
                'query_files_denial': 4, 'query_memory_denial': 64 * 1024,
                'index_decision': 'Defer optional field indexes. Time partition selection reduces selected data files 16 to 2; typed/JSON predicates retain bounded canonical event responses. These local measurements do not establish a production bottleneck or index benefit.',
                'projection_boundary': 'Version1 returns whole canonical events. No partial-event/field projection API is invented; Parquet schema and predicate pushdown remain the current contract.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    output, binary = args.output.absolute(), args.binary.absolute()
    if output.exists() or binary.is_symlink() or not binary.is_file():
        raise RuntimeError('fresh owned output and immutable binary required')
    output.mkdir(parents=True)
    run = Run(output, binary)
    report = {'schema_version': 1, 'status': 'in_progress', 'full_release': False,
              'scope': 'Finite local S3/actual debug server structural query measurements; no AWS cost, capacity or production qualification',
              'architecture': platform.machine(), 'binary_sha256': BASE.file_hash(binary),
              'source_sha256': {name: BASE.file_hash(ROOT / name) for name in ['scripts/check-query-costs.py', 'scripts/check-object-query.py', 'scripts/fixtures/s3-query-server.py']}}
    started = time.monotonic()
    def interrupted(kind, _frame):
        raise KeyboardInterrupt('owned query measurements interrupted by signal ' + str(kind))
    for kind in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(kind, interrupted)
    try:
        report.update(run.run())
        report['status'] = 'passed_simulated'
    except BaseException as error:
        report.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        for kind in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(kind, signal.SIG_IGN)
        errors = run.cleanup()
        log_error = None
        try:
            run.check_logs()
        except Exception as failure:
            log_error = type(failure).__name__
            report.update(status='failed', log_validation_error=log_error)
        if errors:
            report.update(status='failed', cleanup_errors=errors)
        report.setdefault('samples', run.samples)
        report.setdefault('admitted_events', len(run.oracle))
        report['processes'] = run.processes
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['logs'] = {str(path.relative_to(output)): BASE.file_hash(path) for path in run.logs if path.exists()}
        report['missing_logs'] = [str(path.relative_to(output)) for path in run.logs if not path.exists()]
        report['external_exceptions'] = ['Actual S3/IAM/KMS/Object Lock/TLS', 'Native ARM64/remote CI/EKS/shared HA', 'Production capacity/hardware/AWS pricing']
        BASE.write_json(output / 'report.json', report)
        if errors:
            raise RuntimeError('owned query measurement cleanup failed')
        if log_error is not None:
            raise RuntimeError('owned query measurement log validation failed')
    print(json.dumps({'status': report['status'], 'events': report['canonical_event_count'], 'samples': len(report['samples']), 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Finite actual audit credential rotation/recovery with synthetic host delivery.

No cloud provider, encrypted-media or independently fresh restore claim. Private
credentials are captured into explicit child environments, never global env/logs.
"""
import argparse
import contextlib
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINARY_ROOT = ROOT / 'target/goal-execution-20261007/SECURITY-AUDIT/health-probe-stable-binary'
BINARY_SHA = 'd195462384ddab0498fd39afda5a2b9777c9cabd10ed7f21485dcb5317661dd8'
BINARY_COMMIT = '315ae8c148e55308eaf84802a9d8a02733375a4c'
METADATA_PATH = 'target/goal-execution-20261007/SECURITY-AUDIT/health-probe-stable-binary/binary.json'
PROVENANCE_KEYS = frozenset(('crates/signal-protocol/src/audit.rs', 'crates/signal-protocol/src/audit/tests.rs',
    'crates/signal-collector-sdk/src/audit.rs', 'crates/signal-collector-sdk/src/audit/health.rs',
    'crates/signal-collector-sdk/src/audit/health/tests.rs', 'apps/signal-server/src/audit_receiver.rs'))
HELPERS = ['tests/integration/transport-server-process.py', 'scripts/check-access-idp.py',
    'tests/integration/access-server-process.py', 'scripts/check-object-query.py',
    'scripts/check-native-qualification.py', 'benchmarks/pipeline.py',
    'scripts/check-audit-secret-rotation.py', 'scripts/test-audit-secret-rotation.py',
    'rules/examples/login-failure.yaml',
    METADATA_PATH]


def require(value, name):
    if not value:
        raise AssertionError(name)


def consume(path, cap, collect=False):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'regular bounded input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    identity = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
    sha, raw, total = hashlib.sha256(), bytearray(), 0
    with os.fdopen(descriptor, 'rb') as stream:
        require(identity(before) == identity(os.fstat(stream.fileno())), 'input opened identity')
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            require(total <= cap, 'input byte capacity')
            sha.update(chunk)
            if collect:
                raw.extend(chunk)
        require(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), 'input stable identity')
    return bytes(raw) if collect else sha.hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate private field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def validate_provenance(metadata, read_source):
    require(isinstance(metadata, dict) and metadata.get('binary_sha256') == BINARY_SHA,
            'accepted binary provenance')
    sources = metadata.get('source_sha256')
    require(isinstance(sources, dict) and set(sources) == PROVENANCE_KEYS,
            'exact accepted provenance source keys')
    for path, digest in sources.items():
        require(isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest) is not None,
                'strict accepted source SHA256')
        raw = read_source(path)
        require(len(raw) <= 2 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == digest,
                'accepted commit source provenance')


@contextlib.contextmanager
def budget(seconds):
    previous = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    began = time.monotonic()
    def expired(*_):
        raise TimeoutError('original fixture deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, timer[0]) if timer[0] else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if timer[0]:
            remaining = timer[0] - (time.monotonic() - began)
            if remaining <= 0:
                raise TimeoutError('original fixture deadline')
            signal.setitimer(signal.ITIMER_REAL, remaining, timer[1])


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class Delivery:
    """Synthetic external host contract, not a SIGNAL/runtime secret API."""
    def __init__(self, values, available=True):
        self.values, self.available = values, available

    def capture(self, required):
        if not self.available:
            raise ValueError('synthetic provider unavailable')
        require(isinstance(self.values, dict) and len(self.values) <= 8, 'provider finite entries')
        result = {}
        for key in required:
            value = self.values.get(key)
            require(isinstance(value, str) and 1 <= len(value) <= 512 and
                    all(33 <= ord(c) <= 126 for c in value), 'required host credential')
            result[key] = value
        return result

    def launch(self, spawn, command, base, required, label):
        captured = self.capture(required)
        return spawn(command, dict(base, **captured), label)


def journal(store):
    control = consume(store / 'control', 32, True)
    require(len(control) == 32 and control[:8] == b'SIGAUD01' and control[24:] == bytes(8), 'store identity')
    require(uuid.UUID(bytes=control[8:24]).int != 0, 'nonzero store identity')
    raw = consume(store / 'journal', 131072, True)
    rows, offset, identifiers = [], 0, set()
    while offset < len(raw):
        require(len(rows) < 64 and len(raw) - offset >= 72, 'frame capacity')
        head = raw[offset:offset + 72]
        require(head[:4] == b'AUD1' and head[40:] == hashlib.sha256(
            b'platform-signal/audit-receiver-header/v1\0' + control + head[:40]).digest(), 'header checksum')
        size = struct.unpack_from('<I', head, 4)[0]
        require(1 <= size <= 4096 and offset + 72 + size <= len(raw), 'body bound')
        body = raw[offset + 72:offset + 72 + size]
        require(head[8:40] == hashlib.sha256(b'platform-signal/audit-receiver-frame/v1\0' + control + body).digest(), 'body checksum')
        row = strict_json(body)
        require(type(row['schema_version']) is int and row['schema_version'] == 1 and
                type(row['sequence']) is int and row['sequence'] == len(rows) + 1, 'contiguous actual sequence')
        require(str(uuid.UUID(row['record_id'])) == row['record_id'] and row['record_id'] not in identifiers, 'unique actual ID')
        identifiers.add(row['record_id']); rows.append({'original': body, 'record': row}); offset += 72 + size
    return rows


def validate_pair(rows, before, producer):
    require(len(rows) == before + 2, 'exact pair count')
    first, second = [item['record'] for item in rows[-2:]]
    require(first['producer_id'] == second['producer_id'] == producer and
            first['actor'] == second['actor'] == {'kind': 'bootstrap'}, 'native captured actor/producer')
    a, b = first['action'], second['action']
    require(set(a) == {'kind', 'operation', 'operation_id', 'decision'} and
            set(b) == {'kind', 'operation', 'operation_id', 'completion'} and
            a['kind'] == 'access_decision' and b['kind'] == 'operation_completion' and
            a['operation'] == b['operation'] == 'query_events' and a['decision'] == 'granted' and
            b['completion'] == 'success' and a['operation_id'] == b['operation_id'] and
            uuid.UUID(a['operation_id']).int != 0 and
            a['operation_id'] not in [item['record']['action'].get('operation_id') for item in rows[:-2]],
            'native exact fresh decision/completion pair')


def snapshot(source, destination, expected):
    names = []
    with os.scandir(source) as entries:
        for item in entries:
            require(len(names) < 4, 'snapshot entry bound')
            names.append(item.name)
    require(set(names) == set(expected), 'snapshot known entries')
    destination.mkdir(mode=0o700)
    for name in names:
        data = consume(source / name, 131072, True)
        path = destination / name
        with path.open('xb') as stream:
            os.chmod(path, 0o600); stream.write(data); stream.flush(); os.fsync(stream.fileno())


def request(context, port, path, credential, method='GET', body=None):
    with budget(2):
        client = http.client.HTTPSConnection('127.0.0.1', port, timeout=2, context=context)
        try:
            headers = {'Authorization': 'Bearer ' + credential, 'Content-Type': 'application/json'}
            client.request(method, path, body, headers)
            reply = client.getresponse(); raw = reply.read(65537)
            require(len(raw) <= 65536, 'response bound')
            return reply.status, raw
        finally:
            client.close()


class Campaign:
    def __init__(self, output):
        require(not output.exists(), 'fresh output')
        output.mkdir(parents=True, mode=0o700)
        self.output, self.stage = output, 'guard'
        self.checks, self.cleanup_errors, self.delivery_failures = [], [], 0
        self.hashes = {p: consume(ROOT / p, 2 * 1024 * 1024) for p in HELPERS}
        self.binary = BINARY_ROOT / 'signal-server'
        self.binary_hash = consume(self.binary, 1024 * 1024 * 1024)
        require(self.binary_hash == BINARY_SHA, 'immutable accepted binary')
        metadata = strict_json(consume(BINARY_ROOT / 'binary.json', 65536, True))
        def read_source(path):
            result = subprocess.run(['git', 'show', BINARY_COMMIT + ':' + path], cwd=ROOT,
                                    capture_output=True, timeout=3, check=True)
            return result.stdout
        validate_provenance(metadata, read_source)
        self.tls = module('secret_rotation_tls', ROOT / HELPERS[0])
        tls = self.tls
        class Quiet(tls.Run):
            def openssl(self, *args):
                self.command_count += 1
                require(self.command_count <= 80, 'certificate command capacity')
                capture = io.BytesIO()
                try:
                    tls.HELP.NATIVE.run_bounded(['openssl', *map(str, args)], capture, timeout=5, grace=.05)
                except BaseException:
                    raise RuntimeError('synthetic certificate unavailable') from None
                require(capture.tell() <= 65536, 'certificate output bound')
        self.run = Quiet(self.binary, self.binary, output / 'run')
        self.base = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'RUST_LOG': 'warn'}
        self.monolith = self.receiver = None
        self.rows = []

    def check(self, name, value):
        self.stage = name; require(value, name); self.checks.append(name)

    def wait_health(self):
        def healthy():
            if self.receiver_owner.exited(self.receiver) is not None:
                raise RuntimeError('receiver early exit')
            try:
                return request(self.health_context, self.health_port, '/v1/audit/health', self.current_health)[0] == 200
            except (OSError, http.client.HTTPException):
                return False
        self.run.wait(healthy, 'receiver healthy', 5)

    def start_receiver(self, label, initialize=False):
        self.stage = label
        self.receiver_owner = self.run.owner(label)
        self.receiver = self.provider.launch(self.receiver_owner.spawn,
            [str(self.binary), '--initialize-audit-receiver' if initialize else '--audit-receiver', '--config', str(self.receiver_path)],
            self.base, ['SYNTHETIC_APPEND', 'SYNTHETIC_HEALTH'], 'receiver')
        if initialize:
            self.run.wait(lambda: self.receiver_owner.exited(self.receiver) is not None, 'initialize exit', 5)
            self.check('initialize-native-history', self.receiver_owner.stop(self.receiver) == 0); self.receiver = None
        else:
            self.wait_health()

    def stop_receiver(self):
        self.check('stop-receiver-owned', self.receiver_owner.stop(self.receiver) == 0); self.receiver = None

    def start_monolith(self, label, expected=None):
        self.stage = label
        self.monolith_owner = self.run.owner(label)
        self.monolith = self.provider.launch(self.monolith_owner.spawn, [str(self.binary)],
            self.monolith_env, ['SIGNAL_AUDIT_TOKEN', 'SIGNAL_API_TOKEN'], 'monolith')
        def ready():
            if self.monolith_owner.exited(self.monolith) is not None:
                raise RuntimeError('monolith early exit')
            try:
                if expected is not None:
                    code, raw = request(self.health_context, self.health_port, '/v1/audit/health', self.current_health)
                    value = strict_json(raw)
                    if code != 200 or value['records'] != expected or value['physical_depth'] != 0 or value['append_http_depth'] != 0:
                        return False
                    if len(journal(self.store)) != expected:
                        return False
                return request(self.api_context, self.api_port, '/readyz', self.api_token)[0] == 200
            except (OSError, http.client.HTTPException):
                return False
        self.run.wait(ready, 'monolith actual readiness', 5)
        if expected is not None:
            self.check(label + '-synced-originals-before-ready-request', len(journal(self.store)) == expected)

    def stop_monolith(self):
        self.check('stop-monolith-owned', self.monolith_owner.stop(self.monolith) == 0); self.monolith = None

    def denied(self, label, context, port, path, credential, method='GET', body=None):
        before = consume(self.store / 'journal', 131072)
        self.check(label, request(context, port, path, credential, method, body)[0] == 403)
        self.check(label + '-history-unchanged', consume(self.store / 'journal', 131072) == before)

    def execute(self):
        r, t = self.run, self.tls
        self.stage = 'prepare'
        append_ca, health_ca = r.ca('rotation-append'), r.ca('rotation-health')
        append_server = r.leaf(append_ca, 'append-server', 'serverAuth')
        append_client = r.leaf(append_ca, 'append-client', 'clientAuth')
        health_server = r.leaf(health_ca, 'health-server', 'serverAuth')
        health_client = r.leaf(health_ca, 'health-client', 'clientAuth')
        append_material = r.material('append-listener', append_server, [append_ca])
        health_material = r.material('health-listener', health_server, [health_ca])
        client_material = r.material('audit-client', append_client, [append_ca])
        api_material = r.material('api-listener', append_server, [append_ca])
        self.append_context, self.api_context = r.context(append_ca, append_client), r.context(append_ca, append_client)
        self.health_context = r.context(health_ca, health_client)
        self.append_port, self.health_port, self.api_port = [t.HELP.free_port() for _ in range(3)]
        self.old_append, self.old_health, self.api_token = ['synthetic-secret-rotation-' + name for name in ('old-append', 'old-health', 'api')]
        self.new_append, self.new_health = ['synthetic-secret-rotation-' + name for name in ('current-append', 'current-health')]
        self.current_health = self.old_health
        self.provider = Delivery({'SYNTHETIC_APPEND': self.old_append, 'SYNTHETIC_HEALTH': self.old_health,
            'SIGNAL_AUDIT_TOKEN': self.old_append, 'SIGNAL_API_TOKEN': self.api_token})
        self.secrets = [v.encode() for v in [self.old_append, self.old_health, self.new_append, self.new_health, self.api_token]]
        for name in ('outbox', 'receipts', 'rules'):
            (r.private / name).mkdir(mode=0o700)
        self.outbox, self.store = r.private / 'outbox', r.private / 'receipts'
        (r.private / 'rules/rule.yaml').write_bytes(consume(ROOT / 'rules/examples/login-failure.yaml', 65536, True))
        audit_path = r.private / 'audit.json'
        t.HELP.private_json(audit_path, {'schema_version': 1, 'operations': ['query_events'],
            'endpoint': f'https://127.0.0.1:{self.append_port}/v1/audit/records', 'tls_config': str(client_material),
            'outbox_directory': str(self.outbox), 'connect_timeout_ms': 300})
        self.monolith_env = dict(self.base, SIGNAL_LISTEN=f'127.0.0.1:{self.api_port}', SIGNAL_TLS_CONFIG=str(api_material),
            SIGNAL_AUDIT_CONFIG=str(audit_path), SIGNAL_WAL_DIR=str(r.private / 'wal'), SIGNAL_STORAGE_DIR=str(r.private / 'events'),
            SIGNAL_FINDINGS_DIR=str(r.private / 'findings'), SIGNAL_RULE_DIRS=str(r.private / 'rules'), SIGNAL_STORAGE_FLUSH_MS='20',
            SIGNAL_STORAGE_BATCH_EVENTS='1', SIGNAL_REQUEST_TIMEOUT_MS='1000', SIGNAL_QUERY_TIMEOUT_MS='1000',
            SIGNAL_CONNECTION_TIMEOUT_MS='3000', SIGNAL_SHUTDOWN_TIMEOUT_MS='1000')
        # Synthetic provider failure is a host-contract check, not a native API.
        for provider in (Delivery({}, False), Delivery({'SIGNAL_API_TOKEN': self.api_token})):
            self.delivery_failures += 1
            called = []
            try:
                provider.launch(lambda *args: called.append(args), [str(self.binary)], self.monolith_env,
                                ['SIGNAL_AUDIT_TOKEN', 'SIGNAL_API_TOKEN'], 'blocked')
            except (ValueError, AssertionError):
                pass
            else:
                raise AssertionError('invalid provider launched')
            self.check('provider-failure-prevents-launch-' + str(self.delivery_failures), not called and not (self.outbox / 'state').exists())
        self.start_monolith('onboarding'); self.stop_monolith()
        state = strict_json(consume(self.outbox / 'state', 65536, True)); self.producer = state['producer_id']
        self.check('generated-producer-trusted-enrollment', str(uuid.UUID(self.producer)) == self.producer and state['acknowledged'] is None and not (self.outbox / 'pending').exists())
        self.receiver_path = r.private / 'receiver.json'
        t.HELP.private_json(self.receiver_path, {'schema_version': 1, 'directory': str(self.store),
            'append': {'listen': f'127.0.0.1:{self.append_port}', 'tls_config': str(append_material), 'max_connections': 4},
            'health': {'listen': f'127.0.0.1:{self.health_port}', 'tls_config': str(health_material), 'max_connections': 2},
            'producers': [{'producer_id': self.producer, 'credential_env': 'SYNTHETIC_APPEND'}], 'health_credential_env': 'SYNTHETIC_HEALTH',
            'max_bytes': 131072, 'max_records': 64, 'request_timeout_ms': 700, 'header_timeout_ms': 700,
            'connection_timeout_ms': 1500, 'shutdown_timeout_ms': 1000})
        self.start_receiver('initialize', True); self.start_receiver('receiver-old'); self.start_monolith('monolith-old')
        code, _ = request(self.api_context, self.api_port, '/v1/events', self.api_token)
        validate_pair(journal(self.store), 0, self.producer)
        self.check('old-native-client-actual-success-pair', code == 200)
        self.stop_receiver()
        code, body = request(self.api_context, self.api_port, '/v1/events', self.api_token)
        self.check('destination-outage-fail-closed', code == 503 and b'events' not in body)
        pending = consume(self.outbox / 'pending', 4096, True); record = strict_json(pending)
        self.check('actual-pending-original-sequence3', record['sequence'] == 3 and record['producer_id'] == self.producer and record['action']['kind'] == 'access_decision')
        self.stop_monolith()
        self.start_receiver('receiver-old-recovered')
        self.start_monolith('monolith-old-captured', 3)
        self.check('old-authority-exact-outage-replay', journal(self.store)[2]['original'] == pending)
        self.stop_receiver()
        self.provider.values.update(SYNTHETIC_APPEND=self.new_append, SYNTHETIC_HEALTH=self.new_health,
                                    SIGNAL_AUDIT_TOKEN=self.new_append)
        self.current_health = self.new_health
        self.start_receiver('receiver-current')
        self.denied('revoked-append403', self.append_context, self.append_port, '/v1/audit/records', self.old_append, 'POST', pending)
        self.denied('revoked-health403', self.health_context, self.health_port, '/v1/audit/health', self.old_health)
        self.denied('health-token-cannot-append', self.append_context, self.append_port, '/v1/audit/records', self.new_health, 'POST', pending)
        self.denied('append-token-cannot-health', self.health_context, self.health_port, '/v1/audit/health', self.new_append)
        self.check('current-health200', request(self.health_context, self.health_port, '/v1/audit/health', self.new_health)[0] == 200)
        # Running client keeps its originally captured credential across provider replacement.
        code, body = request(self.api_context, self.api_port, '/v1/events', self.api_token)
        self.check('running-old-client-cannot-renew-from-provider-edit', code == 503 and b'events' not in body and
                   len(journal(self.store)) == 3)
        pending = consume(self.outbox / 'pending', 4096, True); record = strict_json(pending)
        self.check('revoked-client-retains-actual-pending-sequence4', record['sequence'] == 4 and
                   record['producer_id'] == self.producer and record['action']['kind'] == 'access_decision')
        self.stop_monolith()
        self.check('stopped-old-client-keeps-exact-pending', consume(self.outbox / 'pending', 4096, True) == pending)
        self.stop_receiver()
        backup = r.private / 'backup'; backup.mkdir(mode=0o700)
        snapshot(self.store, backup / 'receipts', ('control', 'journal', 'lock'))
        snapshot(self.outbox, backup / 'outbox', ('state', 'pending', 'lock'))
        self.start_receiver('receiver-current-before-client-restart')
        self.start_monolith('monolith-current', 4)
        self.check('current-authority-exact-pending-replay', journal(self.store)[3]['original'] == pending and not (self.outbox / 'pending').exists())
        code, _ = request(self.api_context, self.api_port, '/v1/events', self.api_token); first_rows = journal(self.store)
        validate_pair(first_rows, 4, self.producer)
        self.check('fresh-operation-after-rotation', code == 200 and len(first_rows) == 6 and first_rows[-2]['record']['action']['operation_id'] != record['action']['operation_id'])
        self.stop_monolith(); self.stop_receiver()
        for name in ('receipts', 'outbox'):
            shutil.rmtree(r.private / name)
            snapshot(backup / name, r.private / name, ('control', 'journal', 'lock') if name == 'receipts' else ('state', 'pending', 'lock'))
        self.check('restore-original-pending-and-earlier-consistent-data', consume(self.outbox / 'pending', 4096, True) == pending and len(journal(self.store)) == 3)
        self.start_receiver('receiver-restored-current-authority')
        self.denied('restored-data-does-not-renew-old-append', self.append_context, self.append_port, '/v1/audit/records', self.old_append, 'POST', pending)
        self.denied('restored-data-does-not-renew-old-health', self.health_context, self.health_port, '/v1/audit/health', self.old_health)
        self.start_monolith('monolith-restored-current-authority', 4)
        self.check('restored-exact-original-replay-current-authority', journal(self.store)[3]['original'] == pending)
        code, _ = request(self.api_context, self.api_port, '/v1/events', self.api_token); self.rows = journal(self.store)
        validate_pair(self.rows, 4, self.producer)
        self.check('restored-fresh-operation-new-identity', code == 200 and len(self.rows) == 6 and self.rows[-2]['record']['action']['operation_id'] not in
            [record['action']['operation_id'], first_rows[-2]['record']['action']['operation_id']])
        self.stop_monolith()
        code, raw = request(self.health_context, self.health_port, '/v1/audit/health', self.new_health)
        self.check('current-health-retains-history-after-observability-stop', code == 200 and strict_json(raw)['records'] == 6)
        self.stop_receiver()
        self.check('final-exact-receipt-count', len(self.rows) == 6)
        for name in ('control', 'journal'):
            path = self.output / ('actual-receiver-' + name)
            path.write_bytes(consume(self.store / name, 131072, True)); path.chmod(0o600)
        (self.output / 'original-pending.json').write_bytes(pending); (self.output / 'original-pending.json').chmod(0o600)

    def finish(self, failure, began):
        if hasattr(self, 'run'):
            for owner in self.run.owners:
                try:
                    self.cleanup_errors.extend(owner.cleanup()); owner.check()
                except BaseException as error:
                    self.cleanup_errors.append(type(error).__name__)
            try:
                logs = list((self.output / 'run').glob('**/*.log'))
                require(len(logs) <= 24, 'ordinary log count')
                markers = getattr(self, 'secrets', [])
                total = 0
                for path in logs:
                    raw = consume(path, 1024 * 1024, True); total += len(raw)
                    require(total <= 8 * 1024 * 1024 and not any(value in raw for value in markers), 'ordinary log secret privacy')
                self.check('ordinary-log-secret-privacy', True)
            except BaseException as error:
                self.cleanup_errors.append('privacy:' + type(error).__name__)
            try:
                shutil.rmtree(self.run.private)
            except BaseException as error:
                self.cleanup_errors.append('private-cleanup:' + type(error).__name__)
        try:
            final_hashes = {p: consume(ROOT / p, 2 * 1024 * 1024) for p in HELPERS}
            metadata_drift = final_hashes[METADATA_PATH] != self.hashes[METADATA_PATH]
            drift = final_hashes != self.hashes
            binary_drift = consume(self.binary, 1024 * 1024 * 1024) != self.binary_hash
        except BaseException as error:
            drift = binary_drift = metadata_drift = True
            self.cleanup_errors.append('final-guard:' + type(error).__name__)
        result = {'status': 'passed_simulated' if not failure and not self.cleanup_errors and not drift and not binary_drift else 'failed',
            'elapsed_seconds': time.monotonic() - began, 'checks': self.checks, 'passed_check_count': len(self.checks), 'failure': failure,
            'cleanup_errors': self.cleanup_errors, 'helper_source_sha256': self.hashes, 'helper_source_drift': drift,
            'binary_sha256': self.binary_hash, 'binary_commit': BINARY_COMMIT, 'binary_drift': binary_drift,
            'binary_metadata_sha256': self.hashes[METADATA_PATH], 'binary_metadata_drift': metadata_drift,
            'actual_receipt_count': len(self.rows), 'provider': 'finite synthetic explicit host environment delivery; no AWS API/client',
            'limitations': ['Accepted315 immutable LinuxAMD64 default binary only; moving workspace KMS code not exercised.',
                'Synthetic sameUID native processes; separateUID permissions and current release image/cloud/nativeARM separate.',
                'Actual stopped data restore uses current separately delivered authority; old valid history is not independently fresh.',
                'Health HTTP observations show availability only; no SDK health-owner qualification.',
                'No Secrets Manager/IAM/KMS/encrypted media/backup or physical powerloss proof.']}
        (self.output / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: result[k] for k in ('status', 'elapsed_seconds', 'passed_check_count', 'failure', 'cleanup_errors', 'helper_source_drift', 'binary_drift')}, indent=2))
        return result['status'] == 'passed_simulated'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077); began = time.monotonic(); campaign = None; failure = None
    output_existed = args.output.exists()
    try:
        campaign = Campaign(args.output)
        with budget(90):
            campaign.execute()
    except BaseException as error:
        failure = {'kind': type(error).__name__, 'stage': campaign.stage if campaign else 'preparation'}
        if isinstance(error, AssertionError) and str(error) in ('input stable identity', 'input opened identity', 'frame capacity', 'header checksum', 'body checksum', 'body bound'):
            failure['oracle'] = str(error)
    if campaign is None:
        result = {'status': 'failed', 'failure': failure, 'scope': 'preparation only; no native campaign started'}
        if not output_existed and args.output.is_dir():
            (args.output / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result)); return 1
    return 0 if campaign.finish(failure, began) else 1


if __name__ == '__main__':
    raise SystemExit(main())

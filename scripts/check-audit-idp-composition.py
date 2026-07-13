#!/usr/bin/env python3
"""Finite actual local established IdP/native audit/independent receiver fixture.

Synthetic credentials stay in private scratch. No production policy, service,
source enrollment, cloud qualification or encryption claim is created here.
"""
import argparse
import base64
import contextlib
import datetime
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import struct
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINARY_SHA = 'd195462384ddab0498fd39afda5a2b9777c9cabd10ed7f21485dcb5317661dd8'
BINARY_ROOT = ROOT / 'target/goal-execution-20261007/SECURITY-AUDIT/health-probe-stable-binary'
PHASES = ('login', 'ingested', 'granted', 'denied', 'unverified', 'provider-pause',
          'provider-denied', 'provider-recovered', 'receiver-stop', 'receiver-denied',
          'recovered', 'observability-stop', 'final')
HEALTH_FIELDS = {'schema_version', 'held', 'records', 'bytes', 'record_capacity',
    'byte_capacity', 'physical_depth', 'physical_capacity', 'physical_rejected',
    'rejected', 'uncertain', 'append_http_depth', 'append_http_capacity',
    'append_http_rejected', 'health_http_rejected'}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


IDP = module('signal_composition_idp', ROOT / 'scripts/check-access-idp.py')
TLS = module('signal_composition_tls', ROOT / 'tests/integration/transport-server-process.py')


def bounded_read(path, cap):
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError('fixture byte capacity')
    return raw


def digest(path, cap=2 * 1024 * 1024):
    total = 0
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(65536), b''):
            total += len(part)
            if total > cap:
                raise ValueError('digest byte capacity')
            sha.update(part)
    return sha.hexdigest()


def unique_object(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate fixture field')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def require(condition, name):
    if not condition:
        raise AssertionError(name)


def actor_key(issuer, subject):
    # Independent witness: same published framing, no token or unverified header.
    fields = [issuer.encode(), subject.encode()]
    return hashlib.sha256(b'signal.audit.subject.v1\0' + b''.join(
        len(value).to_bytes(8, 'big') + value for value in fields)).hexdigest()


@contextlib.contextmanager
def absolute_budget(seconds):
    previous = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    began = time.monotonic()
    def expired(*_):
        raise TimeoutError('fixture original deadline')
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
                raise TimeoutError('fixture original deadline')
            signal.setitimer(signal.ITIMER_REAL, remaining, timer[1])


def request(port, path, context=None, credential=None, cap=65536):
    with absolute_budget(2):
        connection = (http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=2)
                      if context else http.client.HTTPConnection('127.0.0.1', port, timeout=2))
        try:
            headers = {} if credential is None else {'Authorization': 'Bearer ' + credential}
            connection.request('GET', path, headers=headers)
            response = connection.getresponse()
            raw = response.read(cap + 1)
            require(len(raw) <= cap, 'actual response bound')
            return response.status, raw, response.getheaders()
        finally:
            connection.close()


def journal(store):
    control = bounded_read(store / 'control', 32)
    require(len(control) == 32 and control[:8] == b'SIGAUD01' and control[24:] == bytes(8), 'journal identity')
    require(uuid.UUID(bytes=control[8:24]).int != 0, 'journal identity UUID')
    raw = bounded_read(store / 'journal', 131072)
    rows, offset, ids = [], 0, set()
    while offset < len(raw):
        require(len(rows) < 64 and len(raw) - offset >= 72, 'journal frame capacity')
        header = raw[offset:offset + 72]
        require(header[:4] == b'AUD1' and header[40:] == hashlib.sha256(
            b'platform-signal/audit-receiver-header/v1\0' + control + header[:40]).digest(), 'journal identity-bound header checksum')
        length = struct.unpack_from('<I', header, 4)[0]
        require(1 <= length <= 4096 and offset + 72 + length <= len(raw), 'journal frame length')
        body = raw[offset + 72:offset + 72 + length]
        require(header[8:40] == hashlib.sha256(
            b'platform-signal/audit-receiver-frame/v1\0' + control + body).digest(), 'journal exact body digest')
        row = decode(body)
        require(set(row) == {'schema_version', 'record_id', 'producer_id', 'sequence', 'timestamp', 'actor', 'action'}, 'record shape')
        require(type(row['schema_version']) is int and row['schema_version'] == 1 and
                type(row['sequence']) is int and row['sequence'] == len(rows) + 1, 'record contiguous sequence')
        for key in ('record_id', 'producer_id'):
            require(str(uuid.UUID(row[key])) == row[key] and uuid.UUID(row[key]).int != 0, 'record UUID')
        require(row['record_id'] not in ids, 'unique record ID')
        ids.add(row['record_id'])
        require(datetime.datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')).utcoffset() == datetime.timedelta(0), 'ordinary UTC record')
        rows.append({'original': body, 'record': row})
        offset += 72 + length
    return rows


def check_pair(rows, before, producer, operation, actor, decision, completion):
    require(len(rows) == before + 2, 'exact decision/completion count')
    first, second = (r['record'] for r in rows[-2:])
    require(first['producer_id'] == second['producer_id'] == producer, 'fixed producer binding')
    require(first['actor'] == second['actor'] == actor, 'host verified actor witness')
    a, b = first['action'], second['action']
    require(set(a) == {'kind', 'operation', 'operation_id', 'decision'} and set(b) ==
            {'kind', 'operation', 'operation_id', 'completion'}, 'pair action shape')
    require(a['kind'] == 'access_decision' and b['kind'] == 'operation_completion' and
            a['operation'] == b['operation'] == operation and a['operation_id'] == b['operation_id'] and
            uuid.UUID(a['operation_id']).int != 0 and a['decision'] == decision and b['completion'] == completion, 'pair semantic binding')
    require(a['operation_id'] not in {r['record']['action'].get('operation_id') for r in rows[:-2]}, 'fresh operation UUID')


def validate_phase(raw, generation, index):
    value = decode(raw)
    require(set(value) == {'generation', 'index', 'phase', 'result'}, 'phase shape')
    require(value['generation'] == generation and type(value['index']) is int and value['index'] == index and
            index < len(PHASES) and value['phase'] == PHASES[index] and isinstance(value['result'], dict), 'phase current binding')
    if index == 0:
        require(set(value['result']) == {'secret_digests'} and len(value['result']['secret_digests']) == 6 and
                all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for v in value['result']['secret_digests']), 'private token digest shape')
    else:
        expected = {'ingested': 202, 'granted': 200, 'denied': 403, 'unverified': 403,
            'provider-denied': 408, 'provider-recovered': 200, 'receiver-denied': 503, 'recovered': 200, 'final': 200}
        require(value['result'] == ({'status': expected[value['phase']]} if value['phase'] in expected else {}), 'fixed phase result')
    return value


def validate_health(status, raw, headers):
    require(0 < len(raw) <= 1024 and raw.lstrip().startswith(b'{'), 'health object byte bound')
    value = decode(raw)
    require(status in (200, 503) and isinstance(value, dict) and set(value) == HEALTH_FIELDS, 'health exact shape/status')
    require(type(value['held']) is bool and value['held'] == (status == 503), 'health held status')
    require([v for k, v in headers if k.lower() == 'cache-control'] == ['no-store'] and
            [v for k, v in headers if k.lower() == 'content-type'] == ['application/json'], 'health exact headers')
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            all(type(value[k]) is int and 0 <= value[k] <= (1 << 64)-1
                for k in HEALTH_FIELDS - {'schema_version', 'held'}), 'health numeric shape')
    require(1 <= value['record_capacity'] <= 16384 and 4168 <= value['byte_capacity'] <= 64 * 1024 * 1024 and
            value['records'] <= value['record_capacity'] and value['bytes'] <= value['byte_capacity'] and
            value['physical_capacity'] == value['append_http_capacity'] == 1 and
            value['physical_depth'] <= 1 and value['append_http_depth'] <= 1, 'health individual capacity bounds')
    return value


def health_worker(config_path):
    wire = decode(bounded_read(config_path, 16384))
    context = ssl.create_default_context(cafile=wire['ca'])
    context.load_cert_chain(wire['certificate'], wire['key'])
    end = time.monotonic() + 100
    with Path(wire['output']).open('xb') as stream:
        for index in range(400):
            if time.monotonic() >= end:
                break
            sample = {'index': index, 'status': 'unavailable'}
            try:
                status, raw, headers = request(wire['port'], '/v1/audit/health', context, wire['token'], 1024)
                value = validate_health(status, raw, headers)
                capacity = ('full' if value['records'] == value['record_capacity'] or value['bytes'] == value['byte_capacity'] else
                            'busy' if value['physical_depth'] or value['append_http_depth'] else 'available')
                sample.update(status='held' if value['held'] else 'authenticated', records=value['records'], capacity=capacity)
            except (Exception,):
                pass  # Does not renew authenticated evidence; only unavailable is emitted.
            sample['received_monotonic'] = time.monotonic()
            encoded = (json.dumps(sample) + '\n').encode()
            require(len(encoded) <= 512, 'health observation byte bound')
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            time.sleep(0.1)


SOURCE_EXTRAS = ('Cargo.toml', 'Cargo.lock', 'scripts/check-audit-idp-composition.py',
    'scripts/test-audit-idp-composition.py', 'scripts/check-access-idp.py', 'scripts/check-access-idp-browser.cjs',
    'scripts/test-access-idp.py', 'scripts/check-native-qualification.py', 'tests/integration/access-server-process.py',
    'tests/integration/transport-server-process.py', 'tools/identity/package.json', 'tools/identity/package-lock.json',
    'tools/identity/Containerfile')


def source_inventory(root=ROOT, extras=SOURCE_EXTRAS):
    root = root.resolve(strict=True)
    files, traversed, directories = {}, 0, 0
    def checked(path):
        require(not path.is_symlink(), 'source inventory symlink denied')
        try:
            require(path.resolve(strict=True).is_relative_to(root), 'source inventory outside root')
        except (OSError, RuntimeError):
            raise ValueError('source inventory path denied') from None
    def add(path):
        checked(path)
        name = str(path.relative_to(root))
        if name not in files:
            require(len(files) < 512, 'source inventory capacity')
            files[name] = digest(path)
    def entries(path):
        nonlocal traversed, directories
        checked(path)
        directories += 1
        require(directories <= 256, 'source directory capacity')
        with os.scandir(path) as iterator:
            for count, entry in enumerate(iterator, 1):
                traversed += 1
                require(count <= 256 and traversed <= 4096, 'source traversal capacity')
                require(not entry.is_symlink(), 'source inventory symlink denied')
                yield entry
    def visit(path, depth=0):
        require(depth <= 32, 'source traversal depth')
        for entry in entries(path):
            candidate = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                visit(candidate, depth + 1)
            elif entry.is_file(follow_symlinks=False) and candidate.suffix == '.rs':
                add(candidate)
    for base in ('apps', 'crates'):
        for entry in entries(root / base):
            if entry.is_dir(follow_symlinks=False):
                package = Path(entry.path)
                require(not (package / 'Cargo.toml').is_symlink() and not (package / 'src').is_symlink(),
                        'package input symlink denied')
                if (package / 'Cargo.toml').exists():
                    add(package / 'Cargo.toml')
                if (package / 'src').exists():
                    visit(package / 'src')
    for name in extras:
        add(root / name)
    return dict(sorted(files.items()))


class Run:
    def __init__(self, output, binary):
        self.idp = IDP.Run(output)
        self.output, self.binary = output, binary
        self.tls = TLS.Run(binary, binary, output / 'transport')
        self.scratch = self.tls.private
        self.roles = IDP.OwnedGroups(output / 'roles')
        self.roles.output.mkdir()
        self.started = time.monotonic()
        self.stage, self.checks, self.cleanup_errors = 'prepare', [], []
        self.monolith = self.receiver = self.health = self.client = None
        self.index, self.count = 0, 0
        self.token_digests = []
        self.health_output = output / 'health-observations.jsonl'

    def check(self, name, condition=True):
        require(condition, name)
        self.checks.append(name)

    def wait(self, predicate, budget=15):
        until = time.monotonic() + budget
        while time.monotonic() < until:
            self.idp.owner.check(); self.roles.check()
            if predicate():
                return
            time.sleep(0.02)
        raise TimeoutError('bounded fixture readiness')

    def stop_monolith(self, kill=False):
        if kill:
            os.killpg(self.monolith.pid, signal.SIGKILL)
        code = self.idp.owner.stop(self.monolith)
        self.monolith = None
        self.check('owned monolith SIGKILL' if kill else 'owned monolith stop', code == (-signal.SIGKILL if kill else 0))

    def start_monolith(self, label):
        self.monolith = self.idp.owner.spawn([str(self.binary)], self.monoenv, label)
        def ready():
            if self.idp.owner.exited(self.monolith) is not None:
                raise RuntimeError('monolith early exit')
            try:
                return request(self.api_port, '/readyz')[0] == 200
            except (OSError, TimeoutError):
                return False
        self.wait(ready)

    def start_receiver(self, initialize=False):
        self.receiver = self.roles.spawn([str(self.binary), '--initialize-audit-receiver' if initialize else '--audit-receiver',
            '--config', str(self.receiver_config)], self.receiverenv, 'receiver-init' if initialize else 'receiver-' + str(self.index))
        if initialize:
            self.wait(lambda: self.roles.exited(self.receiver) is not None, 5)
            self.check('actual receiver initialized', self.roles.stop(self.receiver) == 0)
            self.receiver = None
        else:
            self.wait(lambda: self.healthy(), 10)

    def healthy(self):
        try:
            return request(self.health_port, '/v1/audit/health', self.health_context, self.health_credential, 1024)[0] == 200
        except (OSError, TimeoutError):
            return False

    def observe(self, status, count=None, after=None):
        after = time.monotonic() if after is None else after
        def latest():
            if not self.health_output.exists():
                return False
            raw = bounded_read(self.health_output, 262144)
            lines = raw.splitlines()
            if raw and not raw.endswith(b'\n'):
                lines = lines[:-1]
            if not lines:
                return False
            row = decode(lines[-1])
            return row['received_monotonic'] >= after and row['status'] == status and (count is None or row.get('records') == count)
        self.wait(latest, 4)
        self.check('fresh independent health ' + status)

    def pair(self, operation, actor, decision='granted', completion='success'):
        rows = journal(self.store)
        check_pair(rows, self.count, self.producer, operation, actor, decision, completion)
        self.count = len(rows)
        self.check('synced exact ' + operation + ' ' + decision + '/' + completion)

    def logs(self):
        paths = self.idp.owner.logs + self.roles.logs
        require(len(paths) <= 16, 'retained log capacity')
        parts, total = [], 0
        for path in paths:
            if path.exists():
                raw = bounded_read(path, 1048576); total += len(raw)
                require(total <= 8 * 1048576, 'aggregate ordinary log bound')
                parts.append(raw)
        return b''.join(parts)

    def cleanup(self):
        # Both owners attempted before any daemon cleanup. Failures retain scratch.
        try:
            self.cleanup_errors.extend(self.roles.cleanup())
        except Exception as exc:
            self.cleanup_errors.append('roles cleanup ' + type(exc).__name__)
        try:
            self.idp.cleanup()
        except Exception as exc:
            self.cleanup_errors.append('provider cleanup ' + type(exc).__name__)
        self.cleanup_errors.extend(self.idp.cleanup_errors)
        try:
            self.idp.owner.check(); self.roles.check()
        except Exception as exc:
            self.cleanup_errors.append('late drain ' + type(exc).__name__)

    def execute(self, browser_path):
        provider = self.idp.prepare_provider(self.scratch)
        issuer, secrets, certs = (provider[k] for k in ('issuer', 'secrets', 'certs'))
        self.secrets = list(secrets.values())
        self.api_port, self.append_port, self.health_port = (IDP.free_port() for _ in range(3))
        self.a_actor = {'kind': 'verified_subject', 'key': actor_key(issuer, IDP.SUBJECTS['a'])}
        admin_actor = {'kind': 'verified_subject', 'key': actor_key(issuer, IDP.SUBJECTS['admin'])}
        self.store = self.scratch / 'receipts'; self.store.mkdir(mode=0o700)
        outbox = self.scratch / 'outbox'; outbox.mkdir(mode=0o700)
        rules = self.scratch / 'rules'; rules.mkdir(mode=0o700)
        (rules / 'synthetic.yaml').write_text('apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: synthetic.idp.audit\n  name: Synthetic audit fixture\nspec:\n  severity: high\n  match:\n    all:\n      - field: source.type\n        eq: synthetic-idp\n  finding:\n    title: Synthetic audit fixture\n')
        append_ca, health_ca = self.tls.ca('append-ca'), self.tls.ca('health-ca')
        append_server = self.tls.leaf(append_ca, 'server', 'serverAuth')
        append_client = self.tls.leaf(append_ca, 'client', 'clientAuth')
        health_server = self.tls.leaf(health_ca, 'server', 'serverAuth')
        health_client = self.tls.leaf(health_ca, 'client', 'clientAuth')
        append_material = self.tls.material('append-listener', append_server, [append_ca])
        health_material = self.tls.material('health-listener', health_server, [health_ca])
        audit_material = self.tls.material('audit-client', append_client, [append_ca])
        self.health_context = self.tls.context(health_ca, health_client)
        credential, self.health_credential = ('synthetic-audit-' + uuid.uuid4().hex for _ in range(2))
        self.secrets += [credential, self.health_credential]
        identity = self.scratch / 'identity.json'
        IDP.private_json(identity, {'schema_version': 1, 'endpoint': issuer + '/protocol/openid-connect/token/introspect',
            'client_id': 'signal-fixture', 'issuer': issuer, 'audience': 'signal', 'lease_seconds': 5, 'workers': 2,
            'request_timeout_ms': 1000, 'roots_der_base64': [base64.b64encode(ssl.PEM_cert_to_DER_cert((certs / 'root.pem').read_text())).decode()],
            'policy': IDP.policy(issuer)})
        audit = self.scratch / 'audit.json'
        IDP.private_json(audit, {'schema_version': 1, 'operations': ['ingest_events', 'query_events'],
            'endpoint': f'https://127.0.0.1:{self.append_port}/v1/audit/records', 'tls_config': str(audit_material),
            'outbox_directory': str(outbox), 'connect_timeout_ms': 300})
        self.monoenv = dict(self.tls.environment, SIGNAL_LISTEN=f'127.0.0.1:{self.api_port}',
            SIGNAL_ACCESS_CONFIG=str(identity), SIGNAL_IDENTITY_CLIENT_SECRET=secrets['signal-fixture'],
            SIGNAL_AUDIT_CONFIG=str(audit), SIGNAL_AUDIT_TOKEN=credential, SIGNAL_RULE_DIRS=str(rules),
            SIGNAL_WAL_DIR=str(self.scratch / 'wal'), SIGNAL_STORAGE_DIR=str(self.scratch / 'events'),
            SIGNAL_FINDINGS_DIR=str(self.scratch / 'findings'), SIGNAL_STORAGE_FLUSH_MS='10', SIGNAL_STORAGE_BATCH_EVENTS='1',
            SIGNAL_REQUEST_TIMEOUT_MS='2500', SIGNAL_QUERY_TIMEOUT_MS='2500', SIGNAL_SHUTDOWN_TIMEOUT_MS='1500')
        self.start_monolith('onboarding')
        state = decode(bounded_read(outbox / 'state', 1024))
        self.check('quiescent real generated producer enrollment', state['acknowledged'] is None and not (outbox / 'pending').exists())
        self.producer = state['producer_id']; require(str(uuid.UUID(self.producer)) == self.producer, 'actual producer UUID')
        self.stop_monolith()
        self.receiver_config = self.scratch / 'receiver.json'
        IDP.private_json(self.receiver_config, {'schema_version': 1, 'directory': str(self.store),
            'append': {'listen': f'127.0.0.1:{self.append_port}', 'tls_config': str(append_material), 'max_connections': 4},
            'health': {'listen': f'127.0.0.1:{self.health_port}', 'tls_config': str(health_material), 'max_connections': 2},
            'producers': [{'producer_id': self.producer, 'credential_env': 'SYNTHETIC_AUDIT_APPEND'}],
            'health_credential_env': 'SYNTHETIC_AUDIT_HEALTH', 'max_bytes': 131072, 'max_records': 64,
            'request_timeout_ms': 700, 'header_timeout_ms': 700, 'connection_timeout_ms': 1500, 'shutdown_timeout_ms': 1000})
        self.receiverenv = dict(self.tls.environment, SYNTHETIC_AUDIT_APPEND=credential, SYNTHETIC_AUDIT_HEALTH=self.health_credential)
        self.start_receiver(True); self.start_receiver()
        config = self.scratch / 'health.json'
        IDP.private_json(config, {'ca': str(health_ca / 'ca.pem'), 'certificate': str(health_client.with_suffix('.pem')),
            'key': str(health_client.with_suffix('.key')), 'token': self.health_credential, 'port': self.health_port,
            'output': str(self.health_output)})
        self.health = self.roles.spawn(['python3', str(Path(__file__).resolve()), '--health-worker', str(config)], self.tls.environment, 'health-owner')
        self.observe('authenticated', 0)
        self.start_monolith('monolith')
        browser_path = browser_path or Path(self.idp.command(['node', '-e',
            "process.stdout.write(require('./tools/identity/node_modules/playwright-core').chromium.executablePath())"]))
        browser_hash = digest(browser_path, 512 * 1024 * 1024)
        public = self.scratch / 'spki.pem'; der = self.scratch / 'spki.der'
        public.write_text(self.idp.command(['openssl', 'x509', '-in', str(certs / 'leaf.pem'), '-pubkey', '-noout']))
        self.idp.command(['openssl', 'pkey', '-pubin', '-in', str(public), '-outform', 'DER', '-out', str(der)])
        spki = base64.b64encode(bytes.fromhex(digest(der))).decode()
        profile = self.scratch / 'browser'; profile.mkdir()
        browser = self.idp.owner.spawn([str(browser_path), '--headless', '--no-sandbox', '--disable-background-networking',
            '--disable-breakpad', '--disable-crash-reporter', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
            '--ignore-certificate-errors-spki-list=' + spki, '--user-data-dir=' + str(profile), 'about:blank'], self.tls.environment, 'browser')
        self.wait(lambda: (profile / 'DevToolsActivePort').exists(), 10)
        debug_port = int(bounded_read(profile / 'DevToolsActivePort', 1024).splitlines()[0])
        event = {'schema_version': 1, 'id': str(uuid.uuid4()), 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            'source': {'type': 'synthetic-idp'}, 'severity': 'info', 'message': 'synthetic-private-idp-audit-event',
            'resource': {'kind': 'host', 'id': 'resource-a', 'account_id': 'a'}, 'attributes': {'roles': ['forged-admin']}, 'tags': []}
        node_config = self.scratch / 'node.json'; node_report = self.scratch / 'node-report.json'
        log_scan = self.scratch / 'log-scan'
        IDP.private_json(node_config, {'mode': 'audit-composition', 'generation': self.idp.generation, 'issuer': issuer,
            'callback': provider['callback'], 'server_origin': f'http://127.0.0.1:{self.api_port}',
            'debug_url': f'http://127.0.0.1:{debug_port}', 'secrets': secrets, 'subjects': IDP.SUBJECTS,
            'certs': str(certs), 'scratch': str(self.scratch), 'report': str(node_report), 'event': event, 'log_scan': str(log_scan)})
        self.client = self.idp.owner.spawn(['node', str(ROOT / 'scripts/check-access-idp-browser.cjs'), '--config', str(node_config)],
            self.tls.environment, 'oidc-client')
        self.stage = 'composition'
        until = time.monotonic() + 85
        while self.index < len(PHASES):
            self.idp.owner.check(); self.roles.check()
            require(self.idp.owner.exited(self.client) is None, 'OIDC client did not complete early')
            if time.monotonic() >= until:
                raise TimeoutError('OIDC composition deadline')
            path = self.scratch / ('composition-' + str(self.index) + '.request')
            if not path.exists():
                time.sleep(0.02); continue
            require(not path.is_symlink(), 'phase regular input')
            phase = validate_phase(bounded_read(path, 4096), self.idp.generation, self.index)
            self.stage = phase['phase']
            if self.stage == 'login':
                self.token_digests = phase['result']['secret_digests']
                self.check('two actual SDK PKCE/state/nonce verified OIDC logins')
            elif self.stage == 'ingested':
                self.pair('ingest_events', self.a_actor)
                self.wait(lambda: any((self.scratch / 'events').glob('date=*/hour=*/*.parquet')), 5)
            elif self.stage == 'granted':
                self.pair('query_events', self.a_actor)
            elif self.stage == 'denied':
                self.pair('query_events', admin_actor, 'denied', 'denied')
            elif self.stage == 'unverified':
                self.pair('query_events', {'kind': 'unattributed'}, 'denied', 'denied')
            elif self.stage == 'provider-pause':
                self.idp.control('pause')
            elif self.stage == 'provider-denied':
                self.pair('query_events', {'kind': 'unattributed'}, 'unavailable', 'uncertain')
                self.observe('authenticated', self.count)
                self.idp.control('unpause')
            elif self.stage == 'provider-recovered':
                self.pair('query_events', self.a_actor)
            elif self.stage == 'receiver-stop':
                self.original_history = bounded_read(self.store / 'journal', 131072)
                self.check('receiver clean stop', self.roles.stop(self.receiver) == 0); self.receiver = None
                self.observe('unavailable')
            elif self.stage == 'receiver-denied':
                pending = bounded_read(outbox / 'pending', 4096); record = decode(pending)
                self.check('real pending verified actor decision during receiver outage', record['producer_id'] == self.producer and
                    record['sequence'] == self.count + 1 and record['actor'] == self.a_actor and record['action']['decision'] == 'granted')
                self.check('receiver outage no disclosure and held readiness', request(self.api_port, '/readyz')[0] == 503)
                self.check('receiver history unchanged through outage', bounded_read(self.store / 'journal', 131072) == self.original_history)
                self.stop_monolith(); self.start_receiver()
                self.start_monolith('monolith-recovered')
                rows = journal(self.store)
                self.check('exact original pending replay before fresh request', len(rows) == self.count + 1 and rows[-1]['original'] == pending)
                self.pending_operation = record['action']['operation_id']; self.count += 1
                self.observe('authenticated', self.count)
            elif self.stage == 'recovered':
                self.pair('query_events', self.a_actor)
                self.check('fresh request cannot reuse pending operation', journal(self.store)[-1]['record']['action']['operation_id'] != self.pending_operation)
            elif self.stage == 'observability-stop':
                raw = bounded_read(self.store / 'journal', 131072)
                self.stop_monolith(True)
                self.check('SIGKILL observability preserves independent accepted bytes', bounded_read(self.store / 'journal', 131072) == raw)
                self.observe('authenticated', self.count)
                self.start_monolith('monolith-after-kill')
            elif self.stage == 'final':
                self.pair('query_events', self.a_actor)
                self.observe('authenticated', self.count)
                log_scan.write_bytes(self.logs())
            ack = self.scratch / ('composition-' + str(self.index) + '.ack')
            temporary = ack.with_suffix('.ack.tmp')
            IDP.private_json(temporary, {key: phase[key] for key in ('generation', 'index', 'phase')})
            os.rename(temporary, ack)
            self.index += 1
        self.wait(lambda: self.idp.owner.exited(self.client) is not None, 10)
        self.check('actual OIDC child report success', self.idp.owner.stop(self.client) == 0)
        result = decode(bounded_read(node_report, 65536))
        self.check('strict selected composition completed', result['status'] == 'passed_simulated' and result['mode'] == 'audit-composition' and result['phases'] == len(PHASES))
        rows = journal(self.store)
        markers = [event['message'].encode(), event['id'].encode(), self.producer.encode()] + [r['record']['record_id'].encode() for r in rows]
        self.check('control-only receipt privacy', all(event['message'].encode() not in r['original'] and event['id'].encode() not in r['original'] for r in rows))
        self.check('ordinary log metadata privacy', all(v not in self.logs() for v in markers))
        witness = self.output / 'actual-receipt-history'; witness.mkdir(mode=0o700)
        (witness / 'control').write_bytes(bounded_read(self.store / 'control', 32))
        (witness / 'journal').write_bytes(bounded_read(self.store / 'journal', 131072))
        self.check('retained independently reverified framed receipt witness',
            journal(witness) == rows and digest(browser_path, 512 * 1024 * 1024) == browser_hash)
        (self.output / 'original-receipts.jsonl').write_bytes(b'\n'.join(r['original'] for r in rows) + b'\n')
        return {'provider_image_reference': IDP.IMAGE, 'provider_image': provider['provider_image'],
            'provider_prepared_image_id': provider['provider_prepared_image_id'], 'browser_sha256': browser_hash,
            'browser': result['browser'], 'protocol_client': result['protocol_client'], 'actual_receipt_count': len(rows),
            'original_receipt_sha256': digest(self.store / 'journal'), 'completed_phases': self.index}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--binary', type=Path, default=BINARY_ROOT / 'signal-server')
    parser.add_argument('--browser-path', type=Path)
    parser.add_argument('--health-worker', type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.health_worker:
        try:
            health_worker(args.health_worker)
        except KeyboardInterrupt:
            pass
        return 0
    require(args.output is not None, 'fresh output required')
    before = source_inventory()
    provenance = decode(bounded_read(BINARY_ROOT / 'binary.json', 65536))
    require(provenance['binary_sha256'] == BINARY_SHA and digest(args.binary, 1024 ** 3) == BINARY_SHA, 'qualified immutable binary')
    require(all(digest(ROOT / name) == sha for name, sha in provenance['source_sha256'].items()), 'qualified production source guard')
    run = Run(args.output.resolve(), args.binary.resolve())
    report = {'schema_version': 1, 'status': 'running', 'scope': 'Actual established local IdP -> native selected hooks -> actual sameUID independent receiver; not whole parent/cloud/permission/encryption qualification',
        'source_sha256': before, 'binary_sha256': BINARY_SHA, 'provenance_sha256': digest(BINARY_ROOT / 'binary.json')}
    error = None
    try:
        with absolute_budget(240):
            report.update(run.execute(args.browser_path))
    except BaseException as exc:
        error = {'kind': type(exc).__name__, 'stage': run.stage}
    finally:
        for kind in (signal.SIGTERM, signal.SIGINT):
            signal.signal(kind, signal.SIG_IGN)
        signal.setitimer(signal.ITIMER_REAL, 0)
        run.cleanup()
        try:
            logs = run.logs()
            require(not any(v.encode() in logs for v in getattr(run, 'secrets', [])), 'synthetic secret log privacy')
            require(not any(hashlib.sha256(v).hexdigest() in run.token_digests for v in
                    re.findall(rb'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', logs)), 'late token log privacy')
        except Exception as exc:
            run.cleanup_errors.append('final privacy/drain ' + type(exc).__name__)
        if run.cleanup_errors:
            report['private_recovery'] = {'scratch': str(run.scratch), 'container': run.idp.name, 'generation': run.idp.generation}
        else:
            try:
                shutil.rmtree(run.scratch)
            except Exception as exc:
                run.cleanup_errors.append('private removal ' + type(exc).__name__)
    try:
        after = source_inventory()
        binary_matches = digest(args.binary, 1024 ** 3) == BINARY_SHA
    except Exception as exc:
        after, binary_matches = {}, False
        if error is None:
            error = {'kind': type(exc).__name__, 'stage': 'final-guards'}
    report.update(status='passed_simulated' if error is None and not run.cleanup_errors and before == after and
        binary_matches else 'failed', failure=error, cleanup_errors=run.cleanup_errors,
        source_drift=before != after, binary_drift=not binary_matches, checks=run.checks, elapsed_seconds=time.monotonic()-run.started,
        limitations=['SameUID synthetic enrollment/keys, real local Keycloak and real native audit receiver; no production tenant, separateUID compromise, cloud/ARM/current image/release qualification.',
            'Health owner is an independent bounded Python mTLS client; authenticated200 is a timed aggregate observation with explicit capacity facts, not automatic health/readiness or source completeness; SDK health probe integration is not claimed.',
            'Only IngestEvents and QueryEvents are selected; previously accepted other-hook and browser campaigns are reused, not requalified here.',
            'Secrets/encryption/rotation/restore and permission-isolation gates remain separate.'])
    with (run.output / 'report.json').open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps({key: report[key] for key in ('status', 'failure', 'cleanup_errors', 'elapsed_seconds', 'source_drift')}))
    return 0 if report['status'] == 'passed_simulated' else 1


if __name__ == '__main__':
    def interrupted(*_):
        raise KeyboardInterrupt('owned composition interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())

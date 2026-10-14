"""Owned actual Small Main observer admission and atomic gap/outbox recovery."""
import base64
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid


def exercise(root, checkpoint, start, stop, request, hold_request):
    began = time.monotonic()
    checks = []
    repo = Path(__file__).resolve().parents[1]
    sources = [repo/'Cargo.toml', repo/'Cargo.lock', Path(__file__).resolve(),
               repo/'scripts/check-onboarding-native.py', repo/'scripts/onboarding-native-fixture.py',
               repo/'tests/integration/access-server-process.py']
    for component in ['apps/signal-server', 'crates/signal-rules', 'crates/signal-findings',
                      'crates/signal-buffer', 'crates/signal-protocol', 'crates/signal-ingest',
                      'crates/signal-event', 'crates/signal-coverage']:
        sources.extend([repo/component/'Cargo.toml', *(repo/component/'src').rglob('*.rs')])
    hashes = {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    directory = root / 'sensor-health'
    directory.mkdir(mode=0o700)
    database = directory / 'state.sqlite'
    key, public = directory / 'observer.key', directory / 'observer.der'
    held = None

    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def wait(predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except sqlite3.OperationalError as error:
                if error.sqlite_errorcode not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                    raise
            time.sleep(.01)
        raise RuntimeError('Small SENSOR-HEALTH bounded milestone deadline')

    def now():
        return time.time_ns() // 1_000_000

    openssl('genpkey', '-algorithm', 'ED25519', '-out', key)
    openssl('pkey', '-in', key, '-pubout', '-outform', 'DER', '-out', public)
    source, observer = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))
    # Insertion order matches the versioned Rust Policy serialization contract.
    policy = {'schema_version': 1, 'rule_id': 'fixture.sensor-health', 'revision': 'fixture-v1',
              'heartbeat_ms': 1000, 'grace_ms': 100, 'observer_freshness_ms': 5000,
              'max_sources': 1, 'max_state_bytes': 8192,
              'expected': [{'source_id': source, 'binding': [1]*32, 'observer_id': observer,
                            'expected_since_ms': now(), 'require_checkpoint': True}]}
    document = {'schema_version': 1, 'database': str(database),
                'owner_generation': str(uuid.UUID(int=3)), 'cadence_ms': 25,
                'detector': {'schema_version': 1, 'policy': policy,
                             'observer_keys': [{'schema_version': 1, 'observer_id': observer,
                                               'public_key': list(public.read_bytes()[-32:])}],
                             'source_scopes': [{'schema_version': 1, 'source_id': source,
                                               'event_scope': {'schema_version': 1, 'source': 'synthetic',
                                                               'account': 'a', 'resource': 'resource-a'}}],
                             'title': 'Fixture collection gap', 'severity': 'high', 'max_proofs': 3,
                             'max_event_bytes': 16384, 'max_state_bytes': 262144,
                             'max_record_bytes': 1048576, 'max_outputs': 4, 'max_output_bytes': 65536}}
    config = directory / 'config.json'
    config.write_text(json.dumps(document))
    overrides = {'SIGNAL_SENSOR_HEALTH_CONFIG': str(config)}
    digest = list(hashlib.sha256(json.dumps(policy, separators=(',', ':')).encode()).digest())

    def event(sequence, heartbeat=None, forged=False):
        observed = now()
        payload = json.dumps({'schema_version': 1, 'policy_sha256': digest, 'observation': {
            'schema_version': 1, 'source_id': source, 'observer_id': observer, 'binding': [1]*32,
            'sequence': sequence, 'observed_at_ms': observed, 'health': 'healthy',
            'heartbeat_at_ms': observed if heartbeat is None else heartbeat, 'checkpoint': sequence,
        }}, separators=(',', ':')).encode()
        data, signature = directory / 'signed.bin', directory / 'signature.bin'
        data.write_bytes(b'platform-signal/sensor-health-observer/v1\0' + payload)
        openssl('pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', data, '-out', signature)
        envelope = {'schema_version': 1, 'observer_id': observer,
                    'payload_base64': base64.b64encode(payload).decode(),
                    'signature_base64': base64.b64encode(bytes(64) if forged else signature.read_bytes()).decode()}
        stamp = dt.datetime.fromtimestamp(observed/1000, dt.timezone.utc).isoformat().replace('+00:00', 'Z')
        return {'id': str(uuid.uuid4()), 'timestamp': stamp, 'observed_at': stamp,
                'source': {'type': 'synthetic'}, 'resource': {'kind': 'host', 'id': 'resource-a', 'account_id': 'a'},
                'attributes': {'signal.sensor_health.observation': json.dumps(envelope)}}

    def send(value, expected=202):
        code, _, _ = request('POST', '/v1/events/batch', {'events': [value]}, 'write-a')
        assert code == expected, (code, expected)

    def metric(name):
        code, body, _ = request('GET', '/metrics', token='global')
        assert code == 200
        return int(next(line.split()[1] for line in body.splitlines()
                        if line.startswith('signal_sensor_health_' + name + ' ')))

    def snapshot():
        with sqlite3.connect(f'file:{database}?mode=ro', uri=True, timeout=.05) as db:
            row = db.execute('SELECT substr(payload,1,1048577) FROM state_snapshot WHERE singleton=1').fetchone()
        if row is None:
            return None
        assert len(row[0]) <= 1048576
        return json.loads(row[0])

    def findings():
        code, body, _ = request('GET', '/v1/findings?limit=100', token='global')
        assert code == 200
        return body['findings']

    try:
        baseline = checkpoint()
        start(overrides)
        wait(lambda: snapshot() is not None)
        assert metric('coverage_gap') == metric('indeterminate') == 1
        checks.append('idle_without_independent_report_remains_indeterminate')
        send(event(1, forged=True), 422)
        wrong = event(1)
        wrong['resource']['id'] = 'different-resource'
        send(wrong, 403)
        assert checkpoint() == baseline and metric('rejections_total') == 1
        checks.append('forged_signature_and_wrong_resource_refused_before_WAL')
        first = event(1)
        first_envelope = json.loads(first['attributes']['signal.sensor_health.observation'])
        heartbeat = json.loads(base64.b64decode(first_envelope['payload_base64']))['observation']['heartbeat_at_ms']
        send(first)
        wait(lambda: checkpoint() == baseline + 1)
        assert metric('coverage_gap') == 0 and metric('indeterminate') == 0
        checks.append('fresh_authenticated_independent_report_proves_current_NoMatch')
        # No new observation can prove absence after its observation time.
        wait(lambda: metric('coverage_gap') == 1)
        assert not [f for f in findings() if f['rule_id'] == policy['rule_id']]
        rows = findings()
        stop()
        checks.append('idle_deadline_expiry_never_invents_a_collection_gap_finding')
        start({**overrides, 'SIGNAL_FINDINGS_MAX_FINDINGS': str(len(rows)+1),
               'SIGNAL_REQUEST_TIMEOUT_MS': '5000'})
        assert metric('coverage_gap') == 1
        held = hold_request()
        gap = event(2, heartbeat=heartbeat)
        send(gap)
        wait(lambda: (snapshot() or {}).get('checkpoint') == baseline+2)
        pending = snapshot()
        assert pending['outbox'] and checkpoint() == baseline+1
        original = bytes(pending['outbox'][0]['bytes'])
        (directory/'pending-outbox.json').write_text(json.dumps(pending))
        stop(kill=True)
        held.close()
        held = None
        assert bytes(snapshot()['outbox'][0]['bytes']) == original and checkpoint() == baseline+1
        checks.append('actual_SIGKILL_preserves_atomic_original_pending_output_and_unacked_WAL')
        start(overrides)
        wait(lambda: checkpoint() == baseline+2)
        matches = [f for f in findings() if f['rule_id'] == policy['rule_id']]
        assert len(matches) == 1 and set(matches[0]['event_ids']) == {first['id'], gap['id']}
        published = copy.deepcopy(matches[0])
        scope = published['attributes'].pop('signal.scope.v1')
        assert published == json.loads(original)['finding']
        assert scope['source'] == 'synthetic' and scope['account'] == 'a' and scope['resource'] == 'resource-a'
        assert not snapshot()['outbox'] and metric('coverage_gap') == 1
        stop()
        checks.append('restart_publishes_and_retires_original_gap_without_renewing_observer_authority')
        saved = database.read_bytes()
        changed = copy.deepcopy(document)
        changed['owner_generation'] = str(uuid.UUID(int=4))
        config.write_text(json.dumps(changed))
        start(overrides, fail=True)
        assert database.read_bytes() == saved and checkpoint() == baseline+2
        checks.append('changed_owner_generation_refuses_recovery_without_checkpoint_or_database_mutation')
        binary = Path(sys.argv[1]).resolve()
        with binary.open('rb') as stream:
            binary_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        report = {'status': 'passed_simulated', 'passed': len(checks), 'checks': checks,
                  'elapsed_seconds': time.monotonic()-began, 'binary_sha256': binary_hash,
                  'source_sha256': hashes,
                  'scope': 'actual Small Main, SQLite/WAL/findings, synthetic independently signed observer',
                  'timestamp': dt.datetime.now(dt.timezone.utc).isoformat()}
        (root/'sensor-health-native-report.json').write_text(json.dumps(report, indent=2)+'\n')
    finally:
        if held is not None:
            held.close()
        stop()
        key.unlink(missing_ok=True)

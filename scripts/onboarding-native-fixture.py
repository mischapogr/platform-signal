"""Owned local signed-host/real Small Main gate, composed with native TLS identity."""
import base64
import copy
import datetime as dt
import json
from pathlib import Path
import struct
import subprocess
import time
import uuid
import zlib

DOMAIN = b'PLATFORM::SIGNAL/onboarding/v1\0'


def exercise(root, repo, binding, profile, start, stop, request, coverage_request, counters):
    began = time.monotonic()
    key, public = root / 'onboarding-fixture.key', root / 'onboarding-fixture.der'
    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl('genpkey', '-algorithm', 'ED25519', '-out', key)
    openssl('pkey', '-in', key, '-pubout', '-outform', 'DER', '-out', public)
    public_key = public.read_bytes()[-32:]
    fixtures = json.loads((repo / 'tests/fixtures/source-coverage/contract.json').read_text())
    record_template = next(c['record'] for c in fixtures['record_cases'] if c['id'] == 'quiet_verified')
    context_template = next(c['context'] for c in fixtures['assessment_cases'] if c['id'] == 'quiet_current')
    context = copy.deepcopy(context_template)
    context['binding'] = {k: v for k, v in binding.items() if k != 'observer_id'}
    context['observer_id'] = binding['observer_id']
    report_path, policy_path = root / 'onboarding-report.json', root / 'onboarding-policy.json'
    policy = {'schema_version': 1, 'scope_id': 'coverage-a',
              'public_key_base64': base64.b64encode(public_key).decode(),
              'report_path': str(report_path), 'coverage_profile_json': json.dumps(profile),
              'coverage_context_json': json.dumps(context),
              'event_scope': {'source': 'synthetic', 'account': 'a', 'resource': 'resource-a'},
              'detections': [{'id': 'synthetic.scope', 'supported': True,
                              'permissions': ['read-audit'], 'categories': ['audit'], 'state': ['baseline']}]}
    policy_path.write_text(json.dumps(policy))
    def stamp(value):
        return value.isoformat().replace('+00:00', 'Z')
    def evidence():
        now = dt.datetime.now(dt.timezone.utc)
        base = dt.datetime.fromisoformat('2026-10-07T00:05:30+00:00')
        def shift(value):
            if isinstance(value, dict): return {k: shift(v) for k, v in value.items()}
            if isinstance(value, list): return [shift(v) for v in value]
            if isinstance(value, str) and value.endswith('Z'):
                try: return stamp(dt.datetime.fromisoformat(value.replace('Z', '+00:00')) + (now - base))
                except ValueError: pass
            return value
        record = shift(copy.deepcopy(record_template))
        record.update({k: v for k, v in binding.items() if k != 'observer_id'})
        record['provenance']['observer_id'] = binding['observer_id']
        return {'schema_version': 1, 'scope_id': 'coverage-a', 'observed_at': stamp(now),
                'expires_at': stamp(now + dt.timedelta(seconds=20)), 'connected': True,
                'observer_status': 'healthy', 'coverage_record': record,
                'interval': shift(context_template['interval']), 'permissions': {'read-audit': 'met'},
                'categories': {'audit': 'met'}, 'state': {'baseline': 'met'}}
    def publish(payload, forged=False):
        raw = json.dumps(payload, separators=(',', ':')).encode()
        data, sig = root / 'onboarding-signed.bin', root / 'onboarding-signature.bin'
        data.write_bytes(DOMAIN + raw)
        openssl('pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', data, '-out', sig)
        signature = bytes(64) if forged else sig.read_bytes()
        assert len(signature) == 64
        temporary = report_path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'schema_version': 1, 'payload_base64': base64.b64encode(raw).decode(),
                                        'signature_base64': base64.b64encode(signature).decode()}))
        temporary.replace(report_path)
    def assess(token='coverage-read-a', scope='coverage-a'):
        return coverage_request('GET', '/v1/coverage/onboarding', token=token, scope=scope)
    def checkpoint():
        data = (root / 'wal/checkpoint').read_bytes()
        assert len(data) == 28 and data[:8] == b'SIGACK01'
        assert zlib.crc32(data[:24]) == struct.unpack('<I', data[24:])[0]
        return struct.unpack('<Q', data[8:16])[0]
    def admit(expect_finding):
        before = checkpoint()
        event_id = str(uuid.uuid4())
        event = {'id': event_id, 'timestamp': stamp(dt.datetime.now(dt.timezone.utc)),
                 'source': {'type': 'synthetic'}, 'message': 'onboarding fixture',
                 'resource': {'kind': 'host', 'id': 'resource-a', 'account_id': 'a'}}
        assert request('POST', '/v1/events/batch', {'events': [event]}, 'write-a')[0] == 202
        end = time.monotonic() + 5
        while checkpoint() <= before:
            assert time.monotonic() < end, 'onboarding WAL checkpoint deadline'
            time.sleep(.02)
        code, rows, _ = request('GET', '/v1/findings?limit=100', token='global')
        assert code == 200
        found = [row for row in rows['findings'] if row['event_ids'] == [event_id]]
        assert len(found) == int(expect_finding), 'actual Main did not enforce readiness'
        return event_id
    checks = []
    try:
        start({'SIGNAL_ONBOARDING_CONFIG': str(policy_path)})
        code, report = assess()
        assert code == 200 and report['stage'] == 'disconnected' and not report['detections'][0]['active']
        admit(False); checks.append('missing host evidence suppresses actual matching rule after WAL checkpoint')
        publish(evidence())
        code, report = assess()
        assert code == 200 and report['stage'] == 'detections_active' and report['valid_until']
        admit(True); checks.append('fresh signed current coverage enables actual matching rule')
        for category, name in [('permissions', 'read-audit'), ('categories', 'audit'), ('state', 'baseline')]:
            payload = evidence(); payload[category][name] = 'missing'; publish(payload)
            code, report = assess(); assert code == 200 and not report['detections'][0]['active']
            assert any(b.get('requirement') == name for b in report['detections'][0]['blockers'])
        admit(False); checks.append('missing permission/category/state are explicit and suppress native execution')
        publish(evidence(), forged=True); assert assess()[1]['stage'] == 'disconnected'; admit(False)
        checks.append('forged host signature has no activation authority')
        payload = evidence(); payload['expires_at'] = stamp(dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1));publish(payload)
        assert assess()[1]['stage'] == 'disconnected'; checks.append('expired attestation refuses readiness')
        assert assess(token='coverage-read-b', scope='coverage-b')[0] == 403
        assert assess(token='coverage-write')[0] == 403
        counters['revoked'] = True
        assert assess()[0] == 403
        counters['revoked'] = False
        checks.append('read/write scope isolation and live identity revocation')
        stop()
        report_path.unlink()
        start({'SIGNAL_ONBOARDING_CONFIG': str(policy_path)})
        assert assess()[1]['stage'] == 'disconnected';admit(False);stop()
        checks.append('restart without current evidence does not inherit activation')
        result = {'status': 'passed_simulated', 'scope': 'actual local Small Main, native TLS identity, signed synthetic host checks, WAL checkpoint and findings',
                  'passed': len(checks), 'checks': checks, 'elapsed_seconds': time.monotonic() - began,
                  'actual_timestamp': stamp(dt.datetime.now(dt.timezone.utc))}
        (root / 'onboarding-native-report.json').write_text(json.dumps(result, indent=2) + '\n')
    finally:
        counters['revoked'] = False
        stop()
        key.unlink(missing_ok=True)

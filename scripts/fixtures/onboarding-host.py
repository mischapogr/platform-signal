"""Synthetic independently signed host evidence for owned native qualification."""
import base64
import copy
import datetime as dt
import json
from pathlib import Path
import subprocess

DOMAIN = b'PLATFORM::SIGNAL/onboarding/v1\0'


class Host:
    def __init__(self, root, repo, scope, binding, profile, rule, event_scope):
        self.root = root
        self.key = root / 'onboarding-fixture.key'
        self.public = root / 'onboarding-fixture.der'
        self.report = root / 'onboarding-report.json'
        self.policy = root / 'onboarding-policy.json'
        self.binding, self.scope = binding, scope
        self.openssl('genpkey', '-algorithm', 'ED25519', '-out', self.key)
        self.key.chmod(0o600)
        self.openssl('pkey', '-in', self.key, '-pubout', '-outform', 'DER', '-out', self.public)
        fixtures = json.loads((repo / 'tests/fixtures/source-coverage/contract.json').read_text())
        self.record_template = next(c['record'] for c in fixtures['record_cases'] if c['id'] == 'quiet_verified')
        self.context_template = next(c['context'] for c in fixtures['assessment_cases'] if c['id'] == 'quiet_current')
        context = copy.deepcopy(self.context_template)
        context['binding'] = {k: v for k, v in binding.items() if k != 'observer_id'}
        context['observer_id'] = binding['observer_id']
        self.policy.write_text(json.dumps({'schema_version': 1, 'scope_id': scope,
            'public_key_base64': base64.b64encode(self.public.read_bytes()[-32:]).decode(),
            'report_path': str(self.report), 'coverage_profile_json': json.dumps(profile),
            'coverage_context_json': json.dumps(context), 'event_scope': event_scope,
            'detections': [{'id': rule, 'supported': True, 'permissions': ['read-audit'],
                            'categories': ['audit'], 'state': ['baseline']}]}))
        self.policy.chmod(0o600)

    def openssl(self, *args):
        subprocess.run(['openssl', *map(str, args)], check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def evidence(self):
        now = dt.datetime.now(dt.timezone.utc)
        base = dt.datetime.fromisoformat('2026-10-07T00:05:30+00:00')
        def shift(value):
            if isinstance(value, dict): return {k: shift(v) for k, v in value.items()}
            if isinstance(value, list): return [shift(v) for v in value]
            if isinstance(value, str) and value.endswith('Z'):
                try: return (dt.datetime.fromisoformat(value.replace('Z', '+00:00')) + (now - base)).isoformat().replace('+00:00', 'Z')
                except ValueError: pass
            return value
        record = shift(copy.deepcopy(self.record_template))
        record.update({k: v for k, v in self.binding.items() if k != 'observer_id'})
        record['provenance']['observer_id'] = self.binding['observer_id']
        return {'schema_version': 1, 'scope_id': self.scope, 'observed_at': now.isoformat().replace('+00:00', 'Z'),
                'expires_at': (now + dt.timedelta(seconds=20)).isoformat().replace('+00:00', 'Z'),
                'connected': True, 'observer_status': 'healthy', 'coverage_record': record,
                'interval': shift(self.context_template['interval']), 'permissions': {'read-audit': 'met'},
                'categories': {'audit': 'met'}, 'state': {'baseline': 'met'}}

    def publish(self, payload=None, forged=False):
        payload = self.evidence() if payload is None else payload
        body = json.dumps(payload, separators=(',', ':')).encode()
        raw, signature = self.root / 'onboarding-signed.bin', self.root / 'onboarding-signature.bin'
        raw.write_bytes(DOMAIN + body)
        self.openssl('pkeyutl', '-sign', '-rawin', '-inkey', self.key, '-in', raw, '-out', signature)
        sig = bytes(64) if forged else signature.read_bytes()
        assert len(sig) == 64
        temporary = self.report.with_suffix('.tmp')
        temporary.write_text(json.dumps({'schema_version': 1, 'payload_base64': base64.b64encode(body).decode(),
                                        'signature_base64': base64.b64encode(sig).decode()}))
        temporary.replace(self.report)

    def close(self):
        self.key.unlink(missing_ok=True)

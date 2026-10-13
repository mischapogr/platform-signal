#!/usr/bin/env python3
"""Real local Ed25519 qualification on current OSS inputs; no publication."""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_trust', ROOT / 'scripts/release-trust.py')
trust = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trust)

def run(argv):
    subprocess.run(argv, check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / 'target') or out == ROOT / 'target' or out.exists():
        parser.error('absent owned output under target/ required')
    out.mkdir(mode=0o700)
    bundle = out / 'bundle'
    bundle.mkdir()
    private = out / 'test-private.pem'
    wrong_private = out / 'wrong-private.pem'
    public = out / 'test-public.pem'
    wrong_public = out / 'wrong-public.pem'
    ec_private = out / 'ec-private.pem'
    ec_public = out / 'ec-public.pem'
    checks = []
    try:
        for key, pub in [(private, public), (wrong_private, wrong_public)]:
            run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)])
            key.chmod(0o600)
            run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(pub)])
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=5).strip()
        names = ['Cargo.lock', 'rules/examples/login-failure.yaml']
        for name in names:
            dst = bundle / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dst)
        provenance = {'schema_version': 1, 'source_revision': revision, 'purpose': 'local-test',
                      'builder_attested': False, 'released': False}
        (bundle / 'provenance.json').write_text(json.dumps(provenance, sort_keys=True) + '\n')
        names.append('provenance.json')
        manifest = {'schema_version': 1, 'revision': revision, 'purpose': 'local-test',
                    'artifacts': [trust.artifact(bundle, name) for name in names]}
        def sign(raw, domain=trust.DOMAIN):
            (bundle / 'inventory.json').write_bytes(raw)
            payload = out / 'sign-input'
            payload.write_bytes(domain + raw)
            run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(private), '-in', str(payload), '-out', str(bundle / 'inventory.sig')])
        def encode(value):
            return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        def reject(name, key=public):
            try:
                trust.verify(bundle, key)
            except (ValueError, OSError):
                checks.append(name)
                return
            raise ValueError('expected rejection: ' + name)
        raw = encode(manifest)
        sign(raw)
        accepted = trust.verify(bundle, public)
        assert accepted['status'] == 'verified_local_test' and accepted['artifacts'] == 3
        checks.append('current_lock_rule_and_explicit_local_provenance_pinned_signature_verified')
        reject('wrong_external_trust_key_rejected', wrong_public)
        run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(ec_private)])
        ec_private.chmod(0o600)
        run(['openssl', 'pkey', '-in', str(ec_private), '-pubout', '-out', str(ec_public)])
        reject('non_Ed25519_trust_key_rejected', ec_public)
        original = (bundle / names[1]).read_bytes()
        (bundle / names[1]).write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        reject('same_length_rule_tampering_rejected')
        (bundle / names[1]).write_bytes(original)
        (bundle / 'inventory.json').write_bytes(raw + b' ')
        reject('exact_inventory_byte_tampering_rejected')
        sign(raw, b'foreign-domain\0')
        reject('foreign_signature_domain_rejected')
        sign(raw)
        (bundle / 'inventory.sig').unlink()
        reject('unsigned_bundle_rejected')
        sign(raw)
        (bundle / 'inventory.sig').write_bytes(b'\0' * 64)
        reject('forged_signature_rejected')
        for label, mutation in [
            ('unknown_manifest_fields_rejected', lambda m: m.update(key='untrusted')),
            ('production_purpose_not_silently_qualified', lambda m: m.update(purpose='production')),
            ('newer_schema_rejected', lambda m: m.update(schema_version=2)),
            ('boolean_version_rejected', lambda m: m.update(schema_version=True)),
            ('duplicate_artifact_rejected', lambda m: m['artifacts'].append(m['artifacts'][0])),
            ('traversal_artifact_rejected', lambda m: m['artifacts'][0].update(path='../outside')),
            ('boolean_artifact_size_rejected', lambda m: m['artifacts'][0].update(bytes=True)),
            ('file_count_capacity_rejected', lambda m: m.update(artifacts=m['artifacts'] * 43)),
        ]:
            mutated = copy.deepcopy(manifest)
            mutation(mutated)
            sign(encode(mutated))
            reject(label)
        sign(raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
        reject('signed_duplicate_manifest_fields_rejected')
        sign(b' ' * (trust.MAX_DOCUMENT + 1))
        reject('inventory_byte_capacity_rejected')
        sign(raw)
        target = bundle / 'Cargo.lock'
        target.unlink()
        target.symlink_to(ROOT / 'Cargo.lock')
        reject('artifact_symlink_rejected')
        target.unlink()
        os.mkfifo(target)
        reject('nonregular_artifact_rejected_without_blocking')
        target.unlink()
        shutil.copyfile(ROOT / 'Cargo.lock', target)
        sign(raw)
        final = trust.verify(bundle, public)
        checks.append('restored_original_inventory_and_artifacts_verify')
        report = {'status': 'passed_local_test', 'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'checks': checks, 'passed': len(checks), 'inventory': final,
                  'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ['scripts/release-trust.py', 'scripts/check-release-trust.py', 'Cargo.lock', 'rules/examples/login-failure.yaml']},
                  'scope': 'Local test-key Ed25519 pinned inventory, current OSS lock/rule bytes and explicitly unattested local provenance; no actual release, SBOM generation, CI builder attestation or startup enforcement'}
    finally:
        private.unlink(missing_ok=True)
        wrong_private.unlink(missing_ok=True)
        ec_private.unlink(missing_ok=True)
        (out / 'sign-input').unlink(missing_ok=True)
    report['private_test_keys_removed'] = True
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'passed': len(checks), 'report': str(out / 'report.json')}))

if __name__ == '__main__':
    main()

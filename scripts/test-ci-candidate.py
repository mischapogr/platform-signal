#!/usr/bin/env python3
"""Reject incomplete, stale or changed candidate evidence before packaging."""
import copy
import importlib.util
import json
from pathlib import Path
import platform
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('prepare-ci-candidate.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SHA = 'a' * 40
IMAGE = 'sha256:' + 'b' * 64


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class CandidateEvidence(unittest.TestCase):
    def test_finalization_failure_cannot_persist_success(self):
        for failure in ('hash', 'checksum-write'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                output = Path(folder)
                manifest = {'status': 'failed', 'full_release': False}
                write(output / 'candidate.json', manifest)
                for name in ('signal-server', 'signal-agent', 'signal-healthcheck', 'source.tar.gz',
                             'evidence.tar.gz', 'image.tar', 'packaging.log', 'cleanup.log', 'signal-0.1.0.tgz'):
                    (output / name).write_bytes(b'finite test artifact')
                original = Path.write_text
                def write_or_fail(path, *args, **kwargs):
                    if path.name == 'SHA256SUMS': raise OSError('checksum disk failure')
                    return original(path, *args, **kwargs)
                patch = mock.patch.object(c.gate, 'sha256', side_effect=OSError('hash failure')) if failure == 'hash' else mock.patch.object(Path, 'write_text', write_or_fail)
                with patch, self.assertRaises(OSError):
                    c.finalize_candidate(output, manifest)
                self.assertEqual(c.read_json(output / 'candidate.json')['status'], 'failed')
                c.finalize_candidate(output, manifest)
                self.assertEqual(c.read_json(output / 'candidate.json')['status'], 'passed_ci_development_candidate')
                sums = (output / 'SHA256SUMS').read_text()
                self.assertIn(c.gate.sha256(output / 'candidate.json') + '  candidate.json', sums)

    def test_check_source_log_and_success_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in c.REQUIRED:
                path = root / 'target/ci' / (name + '.json')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.with_suffix('.log').write_text('actual retained check output')
                write(path, {'status': 'passed', 'source_sha': SHA, 'architecture': platform.machine(),
                             'log_sha256': c.gate.sha256(path.with_suffix('.log'))})
            self.assertEqual(set(c.require_checks(root, SHA)), set(c.REQUIRED))
            path = root / 'target/ci/native.json'
            original = c.read_json(path)
            for field, value in [('status', 'failed'), ('source_sha', 'c' * 40),
                                 ('architecture', 'other'), ('log_sha256', 'd' * 64)]:
                changed = dict(original)
                changed[field] = value
                write(path, changed)
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    c.require_checks(root, SHA)
            write(path, original)
            path.with_suffix('.log').write_text('changed after check')
            with self.assertRaises(RuntimeError):
                c.require_checks(root, SHA)

    def test_native_and_supply_evidence_matches_exact_image(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            native = root / 'target/native-qualification/attempt/qualification.json'
            supply = root / 'target/supply-chain/reports/attempt/provenance.json'
            report = {'status': 'passed', 'full_qualification': True, 'expected_architecture': 'amd64',
                      'image': {'id': IMAGE}, 'binary_sha256': 'server', 'reports_sha256': {}}
            for name in ('hardening/campaign.json', 'hardening/campaign.log', 'pipeline.json', 'soak.json'):
                path = native.parent / name
                write(path, {})
                report['reports_sha256'][name] = c.gate.sha256(path)
            write(native, report)
            provenance = {'image_id': IMAGE, 'image_architecture': 'amd64', 'checks': {
                name: {'exit_code': 0} for name in ('cargo-audit', 'cargo-sbom', 'image-sbom',
                                                   'image-vulnerabilities', 'container-policy')},
                'report_sha256': {}}
            for name in ('image.json', 'cargo.spdx.json', 'image.spdx.json', 'image-vulnerabilities.json'):
                path = supply.parent / name
                write(path, [{'Id': IMAGE}] if name == 'image.json' else {})
                provenance['report_sha256'][name] = c.gate.sha256(path)
            write(supply, provenance)
            c.require_image_evidence(root, IMAGE, 'amd64', 'server')
            for change in ('partial', 'wrong-binary', 'stale-hash', 'failed-scan', 'different-image'):
                n, s = copy.deepcopy(report), copy.deepcopy(provenance)
                if change == 'partial': n['reports_sha256'].pop('soak.json')
                if change == 'wrong-binary': n['binary_sha256'] = 'other'
                if change == 'stale-hash': n['reports_sha256']['pipeline.json'] = '0' * 64
                if change == 'failed-scan': s['checks']['container-policy']['exit_code'] = 1
                if change == 'different-image': s['image_id'] = 'other'
                write(native, n)
                write(supply, s)
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    c.require_image_evidence(root, IMAGE, 'amd64', 'server')

    def test_archive_rejects_symlink_and_budget_overflow(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'target/ci/result.log'
            path.parent.mkdir(parents=True)
            path.write_text('12345678')
            with mock.patch.object(c, 'EVIDENCE_CAP', 4), self.assertRaises(RuntimeError):
                c.archive_evidence(root, root / 'over-budget.tar.gz')
            self.assertFalse((root / 'over-budget.tar.gz').exists())
            (path.parent / 'link').symlink_to(path)
            with self.assertRaises(RuntimeError):
                c.archive_evidence(root, root / 'symlink.tar.gz')
            self.assertFalse((root / 'symlink.tar.gz').exists())

    def test_no_source_identity_refuses_before_docker(self):
        with mock.patch.dict('os.environ', {}, clear=True), self.assertRaises(RuntimeError):
            c.main(['--image', 'example:dev', '--architecture', 'amd64', '--helm', 'helm'])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Guard local audit capture selection, original bytes, ownership and WAL proof."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

SPEC = importlib.util.spec_from_file_location('kubernetes_audit_gate', Path(__file__).with_name('check-kubernetes-audit.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def records():
    rows = []
    for name, (namespace, _, _) in GATE.CASES.items():
        record = {'apiVersion': 'audit.k8s.io/v1', 'kind': 'Event', 'auditID': name,
                  'verb': 'create', 'stage': 'ResponseComplete',
                  'objectRef': {'namespace': namespace, 'name': name},
                  'responseStatus': {'code': 403 if name == 'denied' else 201},
                  'level': 'Metadata' if name == 'metadata' else 'RequestResponse'}
        rows.append(record)
    rows.append(dict(rows[0], stage='RequestReceived'))
    return rows


def encoded(rows):
    return ('\n'.join(json.dumps(row, separators=(',', ':')) for row in rows) + '\n').encode()


class AuditGateTests(unittest.TestCase):
    def test_exact_original_lines_and_stage_selection(self):
        raw = encoded(records())
        cases = GATE.select_records(raw)
        self.assertEqual(len(cases), 6)
        self.assertEqual(cases[0]['expected_findings'], 1)
        self.assertTrue(all(case['raw_utf8'].encode() in raw.splitlines() for case in cases))
        self.assertEqual(cases[-1]['name'], 'request-received')
        self.assertIsNone(cases[-1]['expected_privileged'])

    def test_duplicate_missing_or_wrong_outcome_refuses(self):
        rows = records()
        for broken in [rows + [rows[0]], rows[1:], [dict(r, responseStatus={'code': 200}) for r in rows]]:
            with self.assertRaises(ValueError):
                GATE.select_records(encoded(broken))

    def test_metadata_body_or_capture_overflow_refuses(self):
        rows = records()
        rows[2]['responseObject'] = {'spec': {}}
        with self.assertRaises(ValueError):
            GATE.select_records(encoded(rows))
        with self.assertRaises(ValueError):
            GATE.select_records(b' ' * (GATE.MAX_CAPTURE + 1))

    def test_kubeconfig_is_isolated_and_no_unowned_delete(self):
        with patch.dict(os.environ, {'KUBECONFIG': '/synthetic/do-not-touch'}):
            capture = GATE.Capture('/tmp/signal-audit-owned')
            self.assertEqual(os.environ['KUBECONFIG'], '/synthetic/do-not-touch')
            self.assertEqual(capture.env['KUBECONFIG'], '/tmp/signal-audit-owned/kubeconfig')
        calls = []
        capture.run = lambda argv, **kwargs: calls.append(argv) or ''
        capture.cleanup()
        self.assertEqual(calls, [])
        capture.attempted = True
        capture.cleanup()
        self.assertEqual(calls[0], ['kind', 'delete', 'cluster', '--name', capture.name])
        self.assertIn('label=io.x-k8s.kind.cluster=' + capture.name, calls[-1])

    def test_cleanup_refuses_remaining_owned_nodes(self):
        capture = GATE.Capture('/tmp/signal-audit-owned')
        capture.attempted = True
        capture.run = lambda argv, **kwargs: 'owned-node' if argv[0] == 'docker' else ''
        with self.assertRaises(ValueError):
            capture.cleanup()

    def test_policy_is_namespaced_and_pods_never_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = GATE.Capture(directory)
            calls = []
            capture.run = lambda argv, **kwargs: calls.append((argv, kwargs)) or ''
            policy = json.loads(capture.prepare().read_text())
            self.assertEqual(policy['rules'][-1], {'level': 'None'})
            self.assertEqual(policy['rules'][0]['resources'], [{'group': '', 'resources': ['pods']}])
            config = json.loads((Path(directory) / 'kind.json').read_text())
            self.assertIn('audit-log-mode: blocking', config['nodes'][0]['kubeadmConfigPatches'][0])
            manifests = []
            def kube(*args, data=None, **kwargs):
                manifests.append(json.loads(data))
                return ''
            capture.kube = kube
            capture.run = lambda argv, **kwargs: encoded(records()).decode()
            capture.capture()
            self.assertEqual(len(manifests), 5)
            self.assertTrue(all(pod['spec']['nodeName'] == 'signal-audit-fixture-never-executes' for pod in manifests))

    def test_checkpoint_requires_crc_and_zero_drops(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checkpoint'
            header = b'SIGACK01' + (12).to_bytes(8, 'little') + (0).to_bytes(8, 'little')
            path.write_bytes(header + zlib.crc32(header).to_bytes(4, 'little'))
            self.assertEqual(GATE.checkpoint(path), 12)
            path.write_bytes(header + b'\0' * 4)
            with self.assertRaises(ValueError):
                GATE.checkpoint(path)
            header = b'SIGACK01' + (12).to_bytes(8, 'little') + (1).to_bytes(8, 'little')
            path.write_bytes(header + zlib.crc32(header).to_bytes(4, 'little'))
            with self.assertRaises(ValueError):
                GATE.checkpoint(path)


if __name__ == '__main__':
    unittest.main()

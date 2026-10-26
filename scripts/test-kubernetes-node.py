#!/usr/bin/env python3
"""Native node-gate byte, ownership and cleanup failure regressions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

SPEC = importlib.util.spec_from_file_location('node_kind_gate', Path(__file__).with_name('check-kubernetes-node.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class Tests(unittest.TestCase):
    def test_native_cri_keeps_binary_and_cr_and_refuses_truncated_or_bad_headers(self):
        raw = b'2026-10-25T12:00:00Z stderr P \xf0\x9f\r\n'
        parsed = GATE.parse_native(raw)
        self.assertEqual(parsed[0]['payload'], b'\xf0\x9f\r')
        self.assertEqual(parsed[0]['sha256'], hashlib.sha256(raw).hexdigest())
        for bad in [raw[:-1], b'bad\n', raw.replace(b'stderr', b'foreign'), raw.replace(b' P ', b' X ')]:
            with self.assertRaises(ValueError):
                GATE.parse_native(bad)

    def test_frames_require_exact_length_both_crcs_and_bound(self):
        body = b'{"schema_version":1}'
        prefix = len(body).to_bytes(4, 'little')+zlib.crc32(body).to_bytes(4, 'little')
        raw = prefix+zlib.crc32(prefix).to_bytes(4, 'little')+body
        self.assertEqual(GATE.decode_frame(raw), {'schema_version': 1})
        for broken in [raw[:-1], raw+b'x', b'x'+raw[1:], raw[:-1]+b'x', b'x'*(1024*1024+1)]:
            with self.assertRaises(ValueError):
                GATE.decode_frame(broken)

    def test_isolated_kubeconfig_and_unattempted_cleanup_never_delete_cluster(self):
        with patch.dict(os.environ, {'KUBECONFIG': '/unowned/preserve'}):
            c = GATE.Capture('/tmp/node-owned', Path('/tmp/output-owned'), Path('/tmp/agent'))
            self.assertEqual(os.environ['KUBECONFIG'], '/unowned/preserve')
            self.assertEqual(c.env['KUBECONFIG'], '/tmp/node-owned/kubeconfig')
        calls = []
        c.run = lambda args, **kwargs: calls.append(args) or ''
        c.cleanup()
        self.assertEqual(calls, [])

    def test_cluster_and_image_cleanup_attempted_even_when_mode_restore_fails(self):
        c = GATE.Capture('/tmp/node-owned', Path('/tmp/output-owned'), Path('/tmp/agent'))
        c.restore_mode = '644'
        c.log = '/var/log/pods/owned/fixture/0.log'
        c.attempted = c.image_created = True
        calls = []
        c.docker = lambda *args, **kwargs: (_ for _ in ()).throw(OSError('owned failure'))
        def run(args, **kwargs):
            calls.append(args)
            if args[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([{'Config': {'Labels': {'org.platform-signal.fixture-owner': c.suffix}}}])
            return ''
        c.run = run
        with self.assertRaises(OSError):
            c.cleanup()
        self.assertEqual(calls[0], ['kind', 'delete', 'cluster', '--name', c.name])
        self.assertIn(['docker', 'image', 'rm', c.image], calls)

    def test_foreign_image_owner_is_never_removed(self):
        c = GATE.Capture('/tmp/node-owned', Path('/tmp/output-owned'), Path('/tmp/agent'))
        c.image_created = True
        calls = []
        c.run = lambda args, **kwargs: calls.append(args) or json.dumps([{'Config': {'Labels': {'org.platform-signal.fixture-owner': 'foreign'}}}])
        with self.assertRaises(ValueError):
            c.cleanup()
        self.assertFalse(any(args[:3] == ['docker', 'image', 'rm'] for args in calls))

    def test_native_query_requires_every_accepted_id_and_exact_payload(self):
        a, b = {'id': 'a', 'message': 'one'}, {'id': 'b', 'message': 'two'}
        original = {'a': a, 'b': b}
        self.assertTrue(GATE.queried_complete([a, a, b], original))
        for rows in [[a], [], [a, b, {'id': 'c'}], [a, dict(b, message='changed')]]:
            self.assertFalse(GATE.queried_complete(rows, original))

    def test_process_cleanup_attempts_all_stages_and_reports_failures(self):
        calls = []
        class Proxy:
            def shutdown(self):
                calls.append('shutdown')
                raise OSError('owned failure')
            def server_close(self):
                calls.append('close')
        class Thread:
            def join(self, timeout):
                calls.append('join')
            def is_alive(self):
                return True
        with patch.object(GATE.LOCAL.PIPE, 'stop', side_effect=lambda p: calls.append(p)):
            errors = GATE.LOCAL.cleanup_owned(['agent'], Proxy(), Thread(), 'server')
        self.assertEqual(calls, ['agent', 'shutdown', 'close', 'join', 'server'])
        self.assertEqual(errors, ['OSError', 'ProxyThreadStillAlive'])

    def test_spool_capture_rejects_foreign_basename_before_read(self):
        c = GATE.Capture('/tmp/node-owned', Path('/tmp/output-owned'), Path('/tmp/agent'))
        calls = []
        c.docker = lambda *args, **kwargs: calls.append(args) or '../unowned\n'
        with self.assertRaises(ValueError):
            c.spool_records()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], 'find')


if __name__ == '__main__':
    unittest.main()

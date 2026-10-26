#!/usr/bin/env python3
"""Failure and ownership checks for the disposable context API harness."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('context_gate', Path(__file__).with_name('check-kubernetes-context.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class GateTests(unittest.TestCase):
    def test_never_uses_caller_kubeconfig_or_deletes_unattempted_cluster(self):
        with patch.dict(os.environ, {'KUBECONFIG': '/unowned/preserve'}):
            c = GATE.Capture('/tmp/context-owned')
            self.assertEqual(os.environ['KUBECONFIG'], '/unowned/preserve')
            self.assertEqual(c.env['KUBECONFIG'], '/tmp/context-owned/kubeconfig')
        calls = []
        c.run = lambda args, **kwargs: calls.append(args) or ''
        c.cleanup()
        self.assertEqual(calls, [])
        c.attempted = True
        c.cleanup()
        self.assertEqual(calls[0], ['kind', 'delete', 'cluster', '--name', c.name])
        self.assertIn('label=io.x-k8s.kind.cluster=' + c.name, calls[-1])

    def test_residual_nodes_fail_cleanup(self):
        c = GATE.Capture('/tmp/context-owned')
        c.attempted = True
        c.run = lambda args, **kwargs: 'owned-node' if args[0] == 'docker' else ''
        with self.assertRaisesRegex(ValueError, 'owned node cleanup'):
            c.cleanup()

    def test_fixture_does_not_run_on_actual_cluster_nodes(self):
        p = GATE.pod('fixture', 'sample', 'context-fixture-node')
        self.assertEqual(p['spec']['nodeName'], 'context-fixture-node')
        self.assertFalse(p['spec']['automountServiceAccountToken'])
        self.assertNotIn('hostPath', json.dumps(p))

    def test_marker_wait_refuses_early_bridge_exit(self):
        class Exited:
            def poll(self):
                return 1
        with tempfile.TemporaryDirectory() as d:
            c = GATE.Capture(d)
            c.process = Exited()
            with self.assertRaisesRegex(ValueError, 'exited before marker'):
                c.wait(Path(d), 'missing.json')

    def test_bridge_terminated_before_cluster_deleted(self):
        calls = []
        class Live:
            def poll(self):
                return None
            def terminate(self):
                calls.append('terminate')
            def wait(self, timeout):
                calls.append('reap')
        c = GATE.Capture('/tmp/context-owned')
        c.process = Live()
        c.attempted = True
        c.run = lambda args, **kwargs: calls.append(args[0]) or ''
        c.cleanup()
        self.assertEqual(calls[:3], ['terminate', 'reap', 'kind'])

    def test_cluster_cleanup_runs_when_bridge_termination_fails(self):
        calls = []
        class Broken:
            def poll(self):
                return None
            def terminate(self):
                raise OSError('owned fixture failure')
        c = GATE.Capture('/tmp/context-owned')
        c.process = Broken()
        c.attempted = True
        c.run = lambda args, **kwargs: calls.append(args) or ''
        with self.assertRaises(OSError):
            c.cleanup()
        self.assertEqual(calls[0], ['kind', 'delete', 'cluster', '--name', c.name])
        self.assertEqual(calls[-1][0], 'docker')

    def test_authorization_is_not_forwarded_on_foreign_redirect(self):
        import io
        import urllib.error
        import urllib.request
        requests = []
        class RedirectResponse(io.BytesIO):
            code = status = 302
            msg = reason = 'Moved'
            headers = {'Location': 'https://foreign.invalid/steal'}
            def info(self):
                return self.headers
            def geturl(self):
                return 'https://owned.invalid/start'
        class Transport(urllib.request.HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                return RedirectResponse(b'')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), GATE.NoRedirect(), Transport())
        request = urllib.request.Request('https://owned.invalid/start', headers={'Authorization': 'Bearer fixture'})
        with self.assertRaises(urllib.error.HTTPError) as error:
            opener.open(request)
        error.exception.close()
        self.assertEqual(error.exception.code, 302)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].full_url, 'https://owned.invalid/start')


if __name__ == '__main__':
    unittest.main()

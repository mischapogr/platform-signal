#!/usr/bin/env python3
"""Focused false-positive/cleanup regressions for the native TLS qualification."""
import http.client
import importlib.util
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signal_transport_fixture', ROOT / 'tests/integration/transport-server-process.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class QualificationRegressions(unittest.TestCase):
    def run_object(self):
        run = FIXTURE.Run.__new__(FIXTURE.Run)
        run.port, run.metrics_port, run.token, run.trusted_context = 1, 2, 'synthetic', object()
        return run

    def test_timeout_refusal_malformed_http_never_qualify_tls_denial(self):
        for error in [TimeoutError(), ConnectionRefusedError(), http.client.BadStatusLine('synthetic')]:
            with self.subTest(kind=type(error).__name__), patch.object(FIXTURE, 'absolute_request', side_effect=error) as request:
                with self.assertRaises(type(error)):
                    self.run_object().deny(object())
                self.assertEqual(request.call_count, 1)

    def test_peer_denial_requires_authenticated_same_listener_liveness(self):
        run = self.run_object()
        with patch.object(FIXTURE, 'absolute_request', side_effect=[ConnectionResetError(), (200, b'')]) as request:
            run.deny(object(), port=run.metrics_port)
            self.assertIs(request.call_args.args[0], run.trusted_context)
            self.assertEqual(request.call_args.args[1:3], (run.metrics_port, '/metrics'))
        with patch.object(FIXTURE, 'absolute_request', side_effect=[ConnectionResetError(), TimeoutError()]):
            with self.assertRaises(TimeoutError):
                run.deny(object())

    def test_local_server_chain_failure_is_only_expected_for_explicit_rotation(self):
        error = ssl.SSLError('synthetic')
        error.reason = 'CERTIFICATE_VERIFY_FAILED'
        with patch.object(FIXTURE, 'absolute_request', side_effect=error):
            with self.assertRaises(AssertionError):
                self.run_object().deny(object())
        with patch.object(FIXTURE, 'absolute_request', side_effect=[error, (200, b'')]):
            self.run_object().deny(object(), server_trust_changed=True)

    def test_one_cleanup_failure_cannot_skip_actual_owned_child_retirement(self):
        with tempfile.TemporaryDirectory(prefix='signal-transport-helper-') as temp:
            root = Path(temp)
            run = self.run_object()
            run.private = root / 'private'
            run.private.mkdir()
            run.cleanup_errors = []
            owner = FIXTURE.HELP.OwnedGroups(root)
            child = owner.spawn([sys.executable, '-c', 'import time; time.sleep(10)'], {}, 'owned')
            class InterruptedOwner:
                def cleanup(self):
                    raise KeyboardInterrupt('synthetic cleanup interruption')
            run.owners = [owner, InterruptedOwner()]
            try:
                run.cleanup()
                self.assertFalse(owner.children)
                self.assertIsNotNone(child.returncode)
                self.assertTrue(run.cleanup_errors)
                self.assertTrue(run.private.exists())
            finally:
                self.assertFalse(owner.cleanup())


if __name__ == '__main__':
    unittest.main()

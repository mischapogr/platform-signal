#!/usr/bin/env python3
"""Failure-path regressions for the optional established IdP qualification gate."""
import http.server
import contextlib
import io
import json
import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import shutil
import threading
import time
import unittest
from unittest import mock
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signal_idp_gate', ROOT / 'scripts/check-access-idp.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class IdpFailures(unittest.TestCase):
    def test_persistent_join_failure_does_not_skip_daemon_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            run = GATE.Run(Path(root) / 'out')
            child = run.owner.spawn([sys.executable, '-c', 'import time; time.sleep(10)'], dict(os.environ), 'child')
            actual = run.owner.drains[child.pid]
            class BrokenJoin:
                ident = actual.ident
                def join(self, timeout):
                    raise RuntimeError('persistent synthetic join error')
                def is_alive(self):
                    return actual.is_alive()
            run.owner.drains[child.pid] = BrokenJoin()
            run.container_attempted = run.image_attempted = True
            try:
                with self.assertRaises(RuntimeError):
                    run.owner.stop(child)
                with mock.patch.object(run, 'command', return_value=None) as commands, mock.patch.object(
                        GATE.os, 'killpg', side_effect=AssertionError('reaped PID signalling')):
                    run.cleanup()
                self.assertTrue(run.cleanup_errors)
                self.assertEqual(commands.call_count, 3)  # absence confirmation plus image
                self.assertFalse(run.owner.children)
            finally:
                actual.join(timeout=1)
                run.owner.drains.clear()

    def test_unexpected_cleanup_error_retains_private_recovery_outside_artifacts(self):
        saved = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM)}
        recovery = None
        try:
            with tempfile.TemporaryDirectory() as root:
                output = Path(root) / 'qualification'
                with (mock.patch.object(GATE.Run, 'execute', return_value={'checks': []}), mock.patch.object(
                        GATE.Run, 'cleanup', side_effect=RuntimeError('synthetic cleanup exception')),
                        contextlib.redirect_stdout(io.StringIO())):
                    self.assertEqual(GATE.main(['--output', str(output), '--provider-only']), 1)
                result = json.loads((output / 'qualification.json').read_text())
                self.assertEqual(result['status'], 'failed')
                recovery = Path(result['private_recovery']['scratch'])
                self.assertTrue(recovery.is_dir())
                self.assertFalse(recovery.is_relative_to(output.parent))
                self.assertEqual(recovery.stat().st_mode & 0o777, 0o700)
        finally:
            for kind, handler in saved.items():
                signal.signal(kind, handler)
            if recovery:
                shutil.rmtree(recovery)

    def test_reaped_leader_is_never_signalled_when_drain_join_fails(self):
        with tempfile.TemporaryDirectory() as root:
            owner = GATE.OwnedGroups(Path(root))
            child = owner.spawn([sys.executable, '-c', 'import time; time.sleep(10)'], dict(os.environ), 'child')
            actual = owner.drains[child.pid]
            class FailOnce:
                ident = actual.ident
                calls = 0
                def join(self, timeout):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError('synthetic join failure')
                    actual.join(timeout)
                def is_alive(self):
                    return actual.is_alive()
            owner.drains[child.pid] = FailOnce()
            try:
                with self.assertRaises(RuntimeError):
                    owner.stop(child)
                self.assertNotIn(child.pid, owner.children)
                self.assertIsNotNone(child.returncode)
                with mock.patch.object(GATE.os, 'killpg', side_effect=AssertionError('reaped PID signalling')):
                    self.assertEqual(owner.cleanup(), [])
                    with self.assertRaises(RuntimeError):
                        owner.stop(child)
                self.assertFalse(owner.drains)
            finally:
                owner.cleanup()

    def test_thread_start_failure_still_retires_registered_child(self):
        with tempfile.TemporaryDirectory() as root:
            owner = GATE.OwnedGroups(Path(root))
            with mock.patch.object(GATE.threading.Thread, 'start', side_effect=OSError('synthetic thread start')):
                with self.assertRaises(OSError):
                    owner.spawn([sys.executable, '-c', 'import time; time.sleep(10)'], dict(os.environ), 'child')
            self.assertEqual(len(owner.children), 1)
            self.assertEqual(owner.cleanup(), [])
            self.assertFalse(owner.children)
            self.assertFalse(owner.drains)

    def test_late_output_overflow_is_retained_after_physical_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            owner = GATE.OwnedGroups(Path(root))
            child = owner.spawn([sys.executable, '-c',
                "import os,time; os.write(1,b'x'*(2*1024*1024)); time.sleep(10)"], dict(os.environ), 'flood')
            end = time.monotonic() + 5
            while owner.exited(child) is None and time.monotonic() < end:
                time.sleep(0.02)
            self.assertIsNotNone(owner.exited(child))
            self.assertIn('process output capacity', owner.cleanup())
            self.assertFalse(owner.children)
            self.assertLessEqual((Path(root) / 'flood.log').stat().st_size, 1024 * 1024)

    def test_only_exact_inspection_not_found_can_confirm_absence(self):
        with tempfile.TemporaryDirectory() as root:
            run = GATE.Run(Path(root) / 'out')
            for reason, text, absent in [
                ('command failed with exit 1', 'error: no such object: ' + run.name, True),
                ('command failed with exit 1', 'Error: No such object: ' + run.name, True),
                ('deadline exceeded', 'error: no such object: ' + run.name, False),
                ('command failed with exit 1', 'Cannot connect to the Docker daemon', False),
                ('command failed with exit 1', 'error: no such object: unrelated', False)]:
                def failed(_args, log, **_kwargs):
                    log.write(text.encode())
                    raise RuntimeError(reason)
                with self.subTest(reason=reason, absent=absent), mock.patch.object(GATE.NATIVE, 'run_bounded', failed):
                    if absent:
                        self.assertFalse(run.container_owned())
                    else:
                        with self.assertRaises(RuntimeError):
                            run.container_owned()

    def test_foreign_label_is_never_removed(self):
        with tempfile.TemporaryDirectory() as root:
            run = GATE.Run(Path(root) / 'out')
            run.container_attempted = run.image_attempted = True
            calls = []
            def command(args, **_kwargs):
                calls.append(args)
                return 'foreign-owner'
            with mock.patch.object(run, 'command', command):
                run.cleanup()
            self.assertEqual(len(run.cleanup_errors), 2)
            self.assertTrue(all('inspect' in args for args in calls))

    def test_discovery_absolute_budget_stops_trickling_headers_and_body(self):
        for trickle_headers in (False, True):
            class Trickle(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass
                def do_GET(self):
                    try:
                        if trickle_headers:
                            for byte in b'HTTP/1.0 200 OK\r\nContent-Length: 64\r\n\r\n':
                                self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(0.04)
                        else:
                            self.send_response(200); self.send_header('Content-Length', '64'); self.end_headers()
                            for byte in b'{"issuer":"synthetic"}' + b' ' * 42:
                                self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(0.04)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
            server = http.server.HTTPServer(('127.0.0.1', 0), Trickle)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
            thread.start()
            try:
                start = time.monotonic()
                previous = signal.getsignal(signal.SIGALRM)
                with self.assertRaises(TimeoutError):
                    GATE.discovery(urllib.request.build_opener(urllib.request.ProxyHandler({})),
                        'http://127.0.0.1:' + str(server.server_port), 0.15)
                self.assertLess(time.monotonic() - start, 0.6)
                self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
                self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)
                self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()

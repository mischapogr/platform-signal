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



class BrowserReadiness(unittest.TestCase):
    valid = b'12345\n/devtools/browser/00000000-0000-4000-8000-000000000001'

    def wait_created(self, owner, child, path):
        deadline = time.monotonic() + 2
        while not path.exists():
            owner.check()
            self.assertIsNone(owner.exited(child))
            if time.monotonic() >= deadline:
                self.fail('owned fixture child did not create port file')
            time.sleep(0.005)

    def test_actual_empty_then_complete_owned_child_is_not_false_start_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); profile = root / 'browser'; profile.mkdir()
            owner = GATE.OwnedGroups(root)
            code = r"""import pathlib,sys,time
p=pathlib.Path(sys.argv[1]); f=p.open('x'); pathlib.Path(sys.argv[2]).write_bytes(b'')
end=time.monotonic()+3
while not pathlib.Path(sys.argv[3]).exists():
    if time.monotonic()>=end: raise SystemExit(2)
    time.sleep(.005)
f.write('12345\n/devtools/browser/00000000-0000');f.flush();time.sleep(.1)
f.write('-4000-8000-000000000001');f.flush();time.sleep(30)
"""
            port_file = profile / 'DevToolsActivePort'; created = root / 'created'; release = root / 'release'
            child = owner.spawn([sys.executable, '-c', code, str(port_file), str(created), str(release)],
                                dict(os.environ), 'browser')
            try:
                self.wait_created(owner, child, created)
                self.assertEqual(port_file.read_bytes(), b'')
                self.assertIsNone(GATE.read_browser_port(port_file))
                release.write_bytes(b'')
                self.assertEqual(GATE.wait_browser_port(owner, child, profile, time.monotonic() + 2), 12345)
                self.assertEqual(port_file.read_bytes(), self.valid)
                self.assertIsNone(owner.exited(child))
            finally:
                self.assertEqual(owner.cleanup(), [])
            self.assertFalse(owner.children)
            self.assertFalse(owner.drains)

    def test_exited_owned_child_with_stale_valid_port_never_becomes_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); profile = root / 'browser'; profile.mkdir()
            (profile / 'DevToolsActivePort').write_bytes(self.valid)
            owner = GATE.OwnedGroups(root)
            child = owner.spawn([sys.executable, '-c', 'pass'], dict(os.environ), 'browser')
            try:
                deadline = time.monotonic() + 2
                while owner.exited(child) is None:
                    if time.monotonic() >= deadline:self.fail('fixture child failed to exit')
                    time.sleep(.005)
                with self.assertRaisesRegex(RuntimeError, 'owned browser startup failed'):
                    GATE.wait_browser_port(owner, child, profile, time.monotonic() + 10)
            finally:
                self.assertEqual(owner.cleanup(), [])
            self.assertFalse(owner.children)

    def test_complete_shape_and_transient_prefixes_are_distinct(self):
        for raw in (b'', b'123', b'12345\n', b'12345\n/devt', self.valid[:-4]):
            self.assertIsNone(GATE.browser_port_bytes(raw))
        self.assertEqual(GATE.browser_port_bytes(self.valid), 12345)
        self.assertEqual(GATE.browser_port_bytes(self.valid + b'\n'), 12345)
        for raw in (b'0\n', b'65536\n', b'-1\n', b'0123\n', b' 123\n',
                    b'12345\r\n', b'12345\n/foreign/browser/id',
                    b'12345\n/devtools/browser/short\n', self.valid + b'\nextra',
                    self.valid + b'\n\n', self.valid[:-1] + b'g', self.valid[:-1] + b'/',
                    b'12345\nhttps://foreign.example/devtools/browser/id', b'12345\n\xff'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                GATE.browser_port_bytes(raw)

    def test_ordinary_bounded_file_rejects_oversize_fifo_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / 'DevToolsActivePort'
            self.assertIsNone(GATE.read_browser_port(path))
            path.write_bytes(b'x' * 1025)
            with self.assertRaises(ValueError):GATE.read_browser_port(path)
            path.unlink(); os.mkfifo(path)
            with mock.patch.object(GATE.os, 'open', side_effect=AssertionError('special file opened')):
                with self.assertRaises(ValueError):GATE.read_browser_port(path)
            path.unlink(); external = root / 'external'; external.write_bytes(self.valid)
            path.symlink_to(external)
            with self.assertRaises(ValueError):GATE.read_browser_port(path)
            path.unlink(); path.hardlink_to(external)
            with self.assertRaises(ValueError):GATE.read_browser_port(path)
            path.unlink(); path.mkdir()
            with self.assertRaises(ValueError):GATE.read_browser_port(path)

    def test_replaced_fifo_and_concurrent_write_cannot_be_disclosed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'DevToolsActivePort'; path.write_bytes(self.valid)
            original_open = GATE.os.open
            def replace_with_fifo(*args):
                path.unlink();os.mkfifo(path)
                self.assertTrue(args[1] & os.O_NOFOLLOW)
                self.assertTrue(args[1] & os.O_NONBLOCK)
                return original_open(*args)
            with mock.patch.object(GATE.os, 'open', side_effect=replace_with_fifo):
                with self.assertRaises(ValueError):GATE.read_browser_port(path)
            path.unlink();path.write_bytes(self.valid)
            original_stat = GATE.os.fstat; calls = 0
            def modified(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.write_bytes(self.valid.replace(b'12345', b'12346'))
                    os.utime(path, ns=(1, 1))
                return original_stat(fd)
            with mock.patch.object(GATE.os, 'fstat', side_effect=modified):
                self.assertIsNone(GATE.read_browser_port(path))
            self.assertEqual(GATE.read_browser_port(path), 12346)

    def test_original_deadline_rechecked_before_ready_port_handoff(self):
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder); (profile / 'DevToolsActivePort').write_bytes(self.valid)
            owner = mock.Mock(); owner.exited.return_value = None
            with self.assertRaisesRegex(RuntimeError, 'owned browser startup failed'):
                GATE.wait_browser_port(owner, object(), profile, time.monotonic() - 1)
            deadline = time.monotonic() + .02
            def late_ready(_path):
                time.sleep(.04)
                return 12345
            with mock.patch.object(GATE, 'read_browser_port', side_effect=late_ready):
                with self.assertRaisesRegex(RuntimeError, 'owned browser startup failed'):
                    GATE.wait_browser_port(owner, object(), profile, deadline)

if __name__ == '__main__':
    unittest.main()

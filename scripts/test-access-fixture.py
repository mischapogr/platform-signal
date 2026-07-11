#!/usr/bin/env python3
"""Failure regressions for identity fixture ownership, byte bounds and TLS stalls."""
import http.server
import importlib.util
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("signal_access_fixture", ROOT / "tests/integration/access-server-process.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class FixtureFailures(unittest.TestCase):
    def test_unstarted_provider_cleanup_and_thread_start_failure_do_not_wait_for_loop(self):
        for failing_start in (False, True):
            with self.subTest(start_failure=failing_start):
                provider = GATE.FiniteTLSProvider(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler,
                    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
                task = threading.Thread(target=provider.serve_forever)
                started = time.monotonic()
                if failing_start:
                    with mock.patch.object(task, "start", side_effect=OSError("synthetic thread start failure")):
                        with self.assertRaises(OSError):
                            GATE.start_provider_thread(task)
                GATE.stop_provider(provider, task)
                self.assertEqual(provider.socket.fileno(), -1)
                self.assertLess(time.monotonic() - started, 1)

    def test_output_capacity_kills_and_reaps_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = GATE.Owned(Path(directory))
            try:
                child = GATE.spawn_owned(owner, [sys.executable, "-c", "import os,time; os.write(1,b'x'*(2*1024*1024)); time.sleep(8)"], dict(os.environ), "flood")
                child.wait(timeout=5)
                owner.reap_log(child)
                self.assertLessEqual((Path(directory) / "flood.log").stat().st_size, 1024 * 1024)
                with self.assertRaises(RuntimeError):
                    owner.check_logs()
            finally:
                self.assertEqual(owner.cleanup(), [])
            self.assertFalse(owner.owned)

    def test_interrupt_during_child_creation_preserves_registered_owner(self):
        real_popen = subprocess.Popen
        sentinel = real_popen([sys.executable, "-c", "import time; time.sleep(15)"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for kind in (signal.SIGTERM, signal.SIGALRM):
                with self.subTest(signal=kind), tempfile.TemporaryDirectory() as directory:
                    owner = GATE.Owned(Path(directory))
                    def interrupt(*args, **kwargs):
                        child = real_popen(*args, **kwargs)
                        signal.getsignal(kind)(kind, None)
                        return child
                    try:
                        with mock.patch.object(GATE.BASE.subprocess, "Popen", interrupt):
                            with self.assertRaises(KeyboardInterrupt):
                                GATE.spawn_owned(owner, [sys.executable, "-c", "import time; time.sleep(8)"], dict(os.environ), "interrupted")
                        self.assertEqual(len(owner.owned), 1)
                        pid = next(iter(owner.owned))
                    finally:
                        self.assertEqual(owner.cleanup(), [])
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                    self.assertIsNone(sentinel.poll())
        finally:
            sentinel.kill()
            sentinel.wait(timeout=3)

    def test_silent_tls_client_cannot_block_provider_shutdown(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        provider = GATE.FiniteTLSProvider(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler, context)
        task = threading.Thread(target=provider.serve_forever, kwargs={"poll_interval": 0.01})
        task.start()
        raw = socket.create_connection(provider.server_address, timeout=1)
        try:
            time.sleep(0.1)
            started = time.monotonic()
            provider.shutdown()
            task.join(timeout=2)
            self.assertFalse(task.is_alive())
            self.assertLess(time.monotonic() - started, 2)
        finally:
            raw.close()
            provider.server_close()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Real curl retries retain pinned tool integrity and permanent failure behavior."""
import hashlib
import http.server
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('supply_chain', Path(__file__).with_name('check-supply-chain.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REAL_RUN = subprocess.run


class DownloadTests(unittest.TestCase):
    def attempt(self, responses, corrupt=False):
        payload = b'#!/bin/sh\nexit 0\n'
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as package:
            item = tarfile.TarInfo('syft')
            item.size = len(payload)
            package.addfile(item, io.BytesIO(payload))
        body = archive.getvalue()
        expected = hashlib.sha256(body).hexdigest()
        calls, commands = [], []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.connection.settimeout(2)
                calls.append(self.path)
                code = responses[min(len(calls) - 1, len(responses) - 1)]
                content = b'corrupt' if corrupt else body
                self.send_response(code)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05})
        thread.start()

        def run(command, **kwargs):
            commands.append((command[:], kwargs.copy()))
            # Only substitute the remote URL; execute the real curl retry code.
            command = [*command[:-1], f'http://127.0.0.1:{server.server_port}/asset']
            return REAL_RUN(command, **kwargs)

        tools = {'syft': ('test', 'synthetic/tool', 'test', {'x86_64': ('tool.tar.gz', expected)})}
        try:
            with tempfile.TemporaryDirectory() as directory, patch.object(MODULE, 'TOOLS', tools), \
                    patch.object(MODULE.platform, 'machine', return_value='x86_64'), \
                    patch.object(MODULE.subprocess, 'run', side_effect=run):
                root = Path(directory)
                if corrupt:
                    with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                        MODULE.install('syft', root)
                    self.assertFalse((root / 'syft').exists())
                    self.assertFalse((root / 'tool.tar.gz').exists())
                elif responses[-1] != 200:
                    with self.assertRaises(subprocess.CalledProcessError):
                        MODULE.install('syft', root)
                    self.assertFalse((root / 'syft').exists())
                else:
                    executable, metadata = MODULE.install('syft', root)
                    self.assertEqual(executable.read_bytes(), payload)
                    self.assertEqual(metadata['archive_sha256'], expected)
                    self.assertEqual(executable.stat().st_mode & 0o777, 0o755)
                self.assertEqual(commands[0][1], {'check': True, 'timeout': 190})
                self.assertIn('--max-filesize', commands[0][0])
                self.assertNotIn('--retry-all-errors', commands[0][0])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        return len(calls)

    def test_two_transient_504s_then_verified_archive(self):
        self.assertEqual(self.attempt([504, 504, 200]), 3)

    def test_permanent_404_is_not_retried_or_activated(self):
        self.assertEqual(self.attempt([404]), 1)

    def test_retry_budget_exhausted_stays_failed(self):
        self.assertEqual(self.attempt([504]), 3)

    def test_successful_corrupt_response_cannot_activate(self):
        self.assertEqual(self.attempt([200], corrupt=True), 1)


if __name__ == '__main__':
    unittest.main()

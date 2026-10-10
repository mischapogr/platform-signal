#!/usr/bin/env python3
"""Check passthrough privacy, argument/exit preservation and cancellation."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def command(self, argv, mcp=False):
        source = (
            'import sys; from pathlib import Path; '
            f'sys.path.insert(0, {str(ROOT / "scripts/ai")!r}); import telemetry; '
            f'telemetry.ROOT=Path({str(self.root)!r}); '
            'telemetry.capture=lambda path: None; '
            f'sys.exit(telemetry.run("serena" if {mcp!r} else "codex", {argv!r}, {mcp!r}))'
        )
        return [sys.executable, '-c', source]

    def summary(self):
        files = list((self.root / 'target/ai-telemetry').glob('*/summary.json'))
        self.assertEqual(len(files), 1)
        return files[0], json.loads(files[0].read_text())

    def test_mcp_preserves_payloads_without_recording_them(self):
        source = ('import sys,json; '
                  'request=json.loads(sys.stdin.readline()); '
                  'print(json.dumps({"jsonrpc":"2.0","id":request["id"],'
                  '"result":{"content":[{"type":"text","text":"private-result"}],"isError":True}}),flush=True); '
                  'sys.exit(7)')
        request = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                   'params': {'name': 'find_symbol', 'arguments': {'query': 'private-argument'}}}
        result = subprocess.run(self.command([sys.executable, '-c', source], True),
                                input=json.dumps(request) + '\n', text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(json.loads(result.stdout)['result']['content'][0]['text'], 'private-result')
        path, summary = self.summary()
        self.assertEqual(summary['exit_code'], 7)
        retained = '\n'.join(p.read_text() for p in path.parent.glob('*'))
        self.assertNotIn('private-result', retained)
        self.assertNotIn('private-argument', retained)
        metric = json.loads((path.parent / 'mcp.jsonl').read_text())
        self.assertEqual(metric['tool'], 'find_symbol')
        self.assertTrue(metric['error'])
        self.assertGreater(metric['output_bytes'], 0)

    def test_session_preserves_literal_arguments_cwd_and_exit(self):
        args = ['space argument', '$(literal)', 'line\nbreak', '--flag']
        source = 'import os,sys,json; print(json.dumps([os.getcwd(),sys.argv[1:]]));sys.exit(19)'
        result = subprocess.run(self.command([sys.executable, '-c', source, *args]),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 19)
        cwd, received = json.loads(result.stdout)
        self.assertEqual(cwd, str(self.root))
        self.assertEqual(received, args)
        path, summary = self.summary()
        self.assertEqual(summary['exit_code'], 19)
        self.assertNotIn('space argument', path.read_text())

    def test_mcp_sigterm_reaches_child_and_records_completion(self):
        source = 'import time; print("ready",flush=True); time.sleep(30)'
        process = subprocess.Popen(self.command([sys.executable, '-c', source], True),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.assertEqual(process.stdout.readline(), 'ready\n')
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM)
        self.assertLess(time.monotonic() - started, 5)
        _, summary = self.summary()
        self.assertEqual(summary['exit_code'], -signal.SIGTERM)


if __name__ == '__main__':
    unittest.main()

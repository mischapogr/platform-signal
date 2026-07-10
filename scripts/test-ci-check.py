#!/usr/bin/env python3
"""Actual finite subprocess failures must retain evidence and clean their group."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('ci_check', Path(__file__).with_name('run-ci-check.py'))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class RetainedDiagnostics(unittest.TestCase):
    def run_check(self, folder, name, code, timeout=5):
        result = ci.main(['--name', name, '--output', folder, '--timeout', str(timeout),
                          '--', sys.executable, '-c', code])
        return result, json.loads((Path(folder) / (name + '.json')).read_text())

    def test_success_failure_and_retry_collision(self):
        with tempfile.TemporaryDirectory() as folder:
            result, report = self.run_check(folder, 'pass', 'print("actual child")')
            self.assertEqual(result, 0)
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(report['log_sha256'], ci.gate.sha256(Path(folder) / 'pass.log'))
            result, report = self.run_check(folder, 'failure', 'print("diagnostic", flush=True); raise SystemExit(7)')
            self.assertEqual(result, 1)
            self.assertEqual(report['status'], 'failed')
            self.assertIn('exit 7', report['error'])
            self.assertIn('diagnostic', (Path(folder) / 'failure.log').read_text())
            retained = (Path(folder) / 'failure.json').read_bytes()
            with self.assertRaises(FileExistsError):
                self.run_check(folder, 'failure', 'pass')
            self.assertEqual((Path(folder) / 'failure.json').read_bytes(), retained)

    def test_output_cap_retains_failed_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = ci.gate.LOG_CAP
            try:
                ci.gate.LOG_CAP = 1024
                result, report = self.run_check(folder, 'verbose', 'print("x" * 65536)')
            finally:
                ci.gate.LOG_CAP = previous
            self.assertEqual(result, 1)
            self.assertEqual(report['status'], 'failed')
            self.assertLessEqual(report['log_bytes'], 1024)
            self.assertIn('capture bound', report['error'])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Failure evidence and process ownership regressions for finite query measurements."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('signal_query_costs', ROOT / 'scripts/check-query-costs.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class FailureEvidence(unittest.TestCase):
    def invoke(self, output):
        handlers = {kind: signal.getsignal(kind) for kind in [signal.SIGTERM, signal.SIGINT]}
        try:
            with mock.patch.object(sys, 'argv', ['check-query-costs', '--output', str(output), '--binary', str(Path(sys.executable).resolve())]):
                GATE.main()
        finally:
            for kind, handler in handlers.items():
                signal.signal(kind, handler)

    def test_failed_spawn_preserves_failed_report_and_missing_log(self):
        def run(owner):
            owner.spawn([sys.executable, '-c', 'pass'], dict(os.environ), 'early')
        with tempfile.TemporaryDirectory(prefix='signal-query-cost-failure-') as root:
            output = Path(root) / 'evidence'
            with mock.patch.object(GATE.Run, 'run', run), mock.patch.object(GATE.BASE.subprocess, 'Popen', side_effect=OSError('synthetic spawn failure')):
                with self.assertRaises(OSError):
                    self.invoke(output)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['missing_logs'], ['early.log'])
            self.assertEqual(report['logs'], {})
            self.assertEqual(report['processes'], [])

    def test_signal_after_child_registration_reaps_child_and_records_failure(self):
        real_popen = subprocess.Popen
        def run(owner):
            owner.spawn([sys.executable, '-c', 'import time; time.sleep(8)'], dict(os.environ), 'creation-signal')
        def interrupted(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return child
        with tempfile.TemporaryDirectory(prefix='signal-query-cost-signal-') as root:
            output = Path(root) / 'evidence'
            with mock.patch.object(GATE.Run, 'run', run), mock.patch.object(GATE.BASE.subprocess, 'Popen', interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    self.invoke(output)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['missing_logs'], ['creation-signal.log'])
            self.assertEqual(len(report['processes']), 1)
            self.assertIsNotNone(report['processes'][0]['return_code'])
            with self.assertRaises(ProcessLookupError):
                os.kill(report['processes'][0]['pid'], 0)

    def test_late_drainer_failure_cannot_keep_passed_status(self):
        def cleanup(owner):
            owner.log_errors['late'] = 'synthetic delayed drain failure'
            return []
        with tempfile.TemporaryDirectory(prefix='signal-query-cost-late-') as root:
            output = Path(root) / 'evidence'
            with mock.patch.object(GATE.Run, 'run', return_value={'canonical_event_count': 0}), mock.patch.object(GATE.Run, 'cleanup', cleanup):
                with self.assertRaises(RuntimeError):
                    self.invoke(output)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['log_validation_error'], 'RuntimeError')

    def test_late_materialization_cannot_be_counted_as_preflight_denial(self):
        with tempfile.TemporaryDirectory(prefix='signal-query-cost-denial-') as root:
            owner = GATE.Run(Path(root), Path(sys.executable).resolve())
            with mock.patch.object(owner, 'data_gets', side_effect=[0, 1]), mock.patch.object(owner, 'metric', return_value=0), mock.patch.object(GATE, 'http', return_value=(413, b'{"schema_version":1,"error":{"code":"resource"}}')):
                with self.assertRaisesRegex(RuntimeError, 'denial must precede'):
                    owner.query('preflight', 0, 0, [], error=413)
            self.assertEqual(owner.samples, [])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Regression tests for acceptance guards and failure evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ai_task', ROOT / 'scripts/ai/task.py')
task = importlib.util.module_from_spec(spec)
spec.loader.exec_module(task)


class Workflow(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.original = task.ROOT
        task.ROOT = self.root
        (self.root / 'scripts/ai').mkdir(parents=True)
        (self.root / 'docs').mkdir()
        (self.root / 'source.py').write_text('source\n')
        (self.root / 'docs/contract.md').write_text('contract\n')
        shutil.copy(ROOT / 'scripts/ai/task.py', self.root / 'scripts/ai/task.py')
        # Real finite runner and its existing bounded subprocess implementation.
        for name in ['run-ci-check.py', 'check-native-qualification.py', 'check-hardening.py']:
            shutil.copy(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        (self.root / 'benchmarks').mkdir()
        shutil.copy(ROOT / 'benchmarks/pipeline.py', self.root / 'benchmarks/pipeline.py')
        self.value = dict(task='guard fixture', kind='tooling', route='implementation',
                          outcome='retained guards', actual_model='test', actual_effort='test',
                          owned_paths=['source.py'], contracts=['docs/contract.md'],
                          failure_cases=['stale review'], stop_condition='accepted fixture',
                          focused_commands=[['python3', 'scripts/pass.py']],
                          acceptance_commands=[['python3', 'scripts/pass.py']])
        (self.root / 'scripts/pass.py').write_text('print("passed")\n')
        self.output = self.root / 'target/task'
        self.specfile = self.root / 'spec.json'
        self.specfile.write_text(json.dumps(self.value))
        task.init(self.specfile, self.output)

    def tearDown(self):
        task.ROOT = self.original
        self.directory.cleanup()

    def accept_review(self):
        task.review(self.output)
        path = self.output / 'review.json'
        value = task.read_json(path)
        value.update(status='passed', reviewer='writer fixture', actual_model='test', actual_effort='test')
        path.write_text(json.dumps(value))

    def test_unknown_ledger_item(self):
        (self.root / 'docs/31-execution-ledger.json').write_text('{"items": [{"id": "known"}]}')
        with self.assertRaises(ValueError):
            task.packet(dict(self.value, ledger_item='unknown'))

    def test_paths_and_symlinks(self):
        (self.root / 'escape').symlink_to('/tmp')
        for path in ['../other', '/tmp/other', '.git/index', '.aws/config', 'escape/file']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                task.relative(path)

    def test_bounded_packet_and_no_overwrite(self):
        with self.assertRaises(ValueError):
            task.packet(dict(self.value, outcome='x' * 2049))
        with self.assertRaises(FileExistsError):
            task.init(self.specfile, self.output)

    def test_literal_argv_and_no_shell(self):
        self.assertEqual(task.command(['python3', 'scripts/pass.py', '$(touch secret)'])[-1], '$(touch secret)')
        for argv in [['bash', '-c', 'true'], ['python3', '../external.py']]:
            with self.assertRaises(ValueError):
                task.command(argv)

    def test_mandatory_rust_gates_cannot_be_omitted(self):
        commands = task.selected_commands(dict(self.value, kind='rust'), 'final')
        self.assertEqual(commands[:4], task.RUST_GATES)
        self.assertEqual(task.selected_commands(self.value, 'final'), self.value['acceptance_commands'])

    def test_packet_edit_rejects_review(self):
        self.accept_review()
        path = self.output / 'task.json'; value = task.read_json(path)
        value['outcome'] = 'different outcome'; path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            task.reviewed(self.output, value)

    def test_gate_source_edit_rejects_review(self):
        self.accept_review()
        (self.root / 'scripts/pass.py').write_text('print("changed gate")')
        with self.assertRaises(ValueError):
            task.reviewed(self.output, self.value)

    def test_pending_review_prevents_any_run(self):
        task.review(self.output)
        with self.assertRaises(ValueError):
            task.validate(self.output, 'final', 5)
        self.assertFalse(list(self.output.glob('final-*')))

    def test_source_and_packet_changes_reject_review(self):
        self.accept_review()
        (self.root / 'source.py').write_text('changed')
        with self.assertRaises(ValueError):
            task.reviewed(self.output, self.value)

    def test_blocking_findings(self):
        self.accept_review()
        path = self.output / 'review.json'; value = task.read_json(path)
        value['blocking_findings'] = ['unresolved']; path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            task.reviewed(self.output, self.value)

    def test_process_lock_contention(self):
        code = 'import fcntl,sys; f=open(sys.argv[1],"a"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)'
        with task.campaign_lock():
            result = subprocess.run([sys.executable, '-c', code, str(self.root / 'target/ai-validation.lock')],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_actual_serial_success(self):
        self.accept_review()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(task.validate(self.output, 'final', 5), 0)
        report = json.loads(next(self.output.glob('final-*/campaign.json')).read_text())
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['source_before'], report['source_after'])

    def test_actual_failure_stops_remaining_and_retains_log(self):
        (self.root / 'scripts/fail.py').write_text('raise SystemExit(3)\n')
        value = task.read_json(self.output / 'task.json')
        value['acceptance_commands'].insert(0, ['python3', 'scripts/fail.py'])
        (self.output / 'task.json').write_text(json.dumps(value))
        self.accept_review()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(task.validate(self.output, 'final', 5), 1)
        path = next(self.output.glob('final-*/campaign.json'))
        report = json.loads(path.read_text())
        self.assertEqual(len(report['commands']), 1)
        self.assertTrue((path.parent / 'gate-1.log').exists())

    def test_actual_source_drift(self):
        (self.root / 'scripts/pass.py').write_text('from pathlib import Path\nPath("source.py").write_text("drift")\n')
        self.accept_review()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(task.validate(self.output, 'final', 5), 1)
        report = json.loads(next(self.output.glob('final-*/campaign.json')).read_text())
        self.assertIn('changed', report['error'])


if __name__ == '__main__':
    unittest.main()

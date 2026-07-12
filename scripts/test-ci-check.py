#!/usr/bin/env python3
"""Actual finite subprocess failures must retain evidence and clean their group."""
import importlib.util
import contextlib
import io
import json
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ci_check', Path(__file__).with_name('run-ci-check.py'))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class RetainedDiagnostics(unittest.TestCase):
    def test_actual_child_workflow_commands_stay_inside_disabled_region(self):
        lines = ['::error title=synthetic-secret::synthetic-secret-token',
                 '::set-output name=unsafe::synthetic-secret-token',
                 '::stop-commands::known-token', '::known-token::',
                 'error: test failed, to rerun pass `-p signal-server --bin signal-server`']
        tokens = []
        for index in range(2):
            code = f'print({chr(10).join(lines)!r}, flush=True); raise SystemExit(9)'
            with tempfile.TemporaryDirectory() as folder, patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'true'}), contextlib.redirect_stdout(io.StringIO()) as output:
                result, report = self.run_check(folder, f'injected-{index}', code)
                retained = (Path(folder) / f'injected-{index}.log').read_text()
            self.assertEqual(result, 1)
            captured = output.getvalue().splitlines()
            stop = re.fullmatch(r'::stop-commands::([0-9a-f]{64})', captured[0])
            self.assertIsNotNone(stop)
            token = stop[1]
            tokens.append(token)
            resume = captured.index(f'::{token}::')
            for line in lines:
                self.assertIn(line, captured[1:resume])
            self.assertEqual(captured[resume + 1:],
                             ['::error title=Rust regression::signal-server --bin signal-server'])
            self.assertEqual(report['failed_rust_targets'],
                             [{'package': 'signal-server', 'kind': 'bin', 'name': 'signal-server'}])
            self.assertIn(lines[0], retained)
        self.assertNotEqual(*tokens)

    def test_inventory_refuses_external_or_oversized_manifest_content(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / 'repo'
            package = root / 'crates/fixture'
            package.mkdir(parents=True)
            manifest = package / 'Cargo.toml'
            external = base / 'private.toml'
            external.write_text('[package]\nname="private-marker"\n[lib]\n')
            manifest.symlink_to(external)
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())
            manifest.unlink()
            manifest.write_text('[package]\nname="fixture"\n[lib]\n#' + 'x' * 262145)
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())
            manifest.write_text('[package]\nname="fixture"\n[lib]\n')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), {('fixture', 'lib', '')})

    def test_actual_failure_emits_only_bounded_source_validated_targets(self):
        footer = 'error: test failed, to rerun pass `-p signal-server --bin signal-server`'
        lines = [footer, footer,
                 'Error: synthetic-secret-token',
                 'test synthetic_secret ... FAILED',
                 'error: test failed, to rerun pass `-p synthetic-secret-token --lib`',
                 'error: test failed, to rerun pass `-p signal-server --bin unknown-secret`',
                 'error: test failed, to rerun pass `-p signal-server --bin unsafe%0A::error`']
        allowed = sorted(ci.rust_targets())
        self.assertGreater(len(allowed), 16)
        lines += [f'error: test failed, to rerun pass `-p {p} --{k}' + (f' {n}' if n else '') + '`' for p, k, n in allowed]
        code = f'print({chr(10).join(lines)!r}, flush=True); raise SystemExit(9)'
        with tempfile.TemporaryDirectory() as folder, patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'true'}), contextlib.redirect_stdout(io.StringIO()) as output:
            result, report = self.run_check(folder, 'named-failures', code)
        self.assertEqual(result, 1)
        self.assertEqual(len(report['failed_rust_targets']), 16)
        self.assertEqual(report['failed_rust_targets'][0], {'package': 'signal-server', 'kind': 'bin', 'name': 'signal-server'})
        annotations = [line for line in output.getvalue().splitlines() if line.startswith('::error')]
        self.assertEqual(len(annotations), 16)
        self.assertTrue(all(line.startswith('::error title=Rust regression::') for line in annotations))
        self.assertFalse(any('secret' in line or '%' in line or 'unsafe' in line for line in annotations))
        self.assertNotIn('synthetic-secret-token', str(report['failed_rust_targets']))

    def test_local_and_success_runs_never_emit_failure_annotations(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'false'}), contextlib.redirect_stdout(io.StringIO()) as output:
            result, report = self.run_check(folder, 'local-failure', 'print("error: test failed, to rerun pass `-p signal-server --bin signal-server`"); raise SystemExit(1)')
        self.assertEqual(result, 1)
        self.assertEqual(report['failed_rust_targets'], [{'package': 'signal-server', 'kind': 'bin', 'name': 'signal-server'}])
        self.assertNotIn('::error title=', output.getvalue())
        with tempfile.TemporaryDirectory() as folder, patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'true'}), contextlib.redirect_stdout(io.StringIO()) as output:
            result, report = self.run_check(folder, 'successful-noise', 'print("test fixture::not_a_failure ... FAILED")')
        self.assertEqual(result, 0)
        self.assertNotIn('failed_rust_targets', report)
        self.assertNotIn('::error title=', output.getvalue())

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

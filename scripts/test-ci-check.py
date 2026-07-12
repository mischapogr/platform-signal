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
    def test_automatic_integration_targets_follow_public_source_and_autotests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'repo'
            package = root / 'crates/fixture'
            tests = package / 'tests'
            (tests / 'directory_case').mkdir(parents=True)
            (tests / 'file-case.rs').write_text('// public fixture')
            (tests / 'directory_case/main.rs').write_text('// public fixture')
            (tests / 'ignored.txt').write_text('synthetic-private-canary')
            manifest = package / 'Cargo.toml'
            manifest.write_text('[package]\nname="fixture"\n')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), {
                    ('fixture', 'test', 'file-case'), ('fixture', 'test', 'directory_case')})
                self.assertEqual(ci.failed_rust_targets(
                    'error: test failed, to rerun pass `-p fixture --test file-case`'),
                    [{'package': 'fixture', 'kind': 'test', 'name': 'file-case'}])
            manifest.write_text('[package]\nname="fixture"\nautotests=false\n'
                                '[[test]]\nname="explicit"\npath="tests/file-case.rs"\n')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), {('fixture', 'test', 'explicit')})

    def test_automatic_inventory_refuses_external_symlinks_and_directory_capacity(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / 'repo'
            package = root / 'crates/fixture'
            tests = package / 'tests'
            tests.mkdir(parents=True)
            (package / 'Cargo.toml').write_text('[package]\nname="fixture"\n')
            external = base / 'private.rs'
            external.write_text('synthetic-private-canary')
            link = tests / 'private-marker.rs'
            link.symlink_to(external)
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())
            link.unlink()
            directory = tests / 'nested'
            directory.mkdir()
            (directory / 'main.rs').symlink_to(external)
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())
            (directory / 'main.rs').unlink()
            directory.rmdir()
            for n in range(129):
                (tests / f'case{n}.rs').write_text('// fixture')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())

    def test_actual_automatic_target_failure_annotation_has_no_child_payload(self):
        # This repository target has no explicit [[test]] entry.
        footer = 'error: test failed, to rerun pass `-p signal-query --test object_query`'
        self.assertIn(('signal-query', 'test', 'object_query'), ci.rust_targets())
        code = f'print("Error: synthetic-private-canary"); print({footer!r}); raise SystemExit(9)'
        with tempfile.TemporaryDirectory() as folder, \
                patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'true'}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result, report = self.run_check(folder, 'automatic-target', code)
        self.assertEqual(result, 1)
        captured = output.getvalue().splitlines()
        token = re.fullmatch(r'::stop-commands::([0-9a-f]{64})', captured[0])[1]
        resume = captured.index(f'::{token}::')
        self.assertEqual(captured[resume + 1:],
                         ['::error title=Rust regression::signal-query --test object_query'])
        self.assertNotIn('synthetic-private-canary', str(report['failed_rust_targets']))

    def test_automatic_scan_does_not_materialize_directory_or_overconsume_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'repo'
            package = root / 'crates/fixture'
            tests = package / 'tests'
            tests.mkdir(parents=True)
            (package / 'Cargo.toml').write_text('[package]\nname="fixture"\n')
            (tests / 'known.rs').write_text('// public fixture')
            original_listdir = ci.os.listdir
            def guarded_listdir(path):
                self.assertNotEqual(Path(path), tests, 'automatic target scan materialized directory')
                return original_listdir(path)
            with patch.object(ci, 'ROOT', root), patch.object(ci.os, 'listdir', guarded_listdir):
                self.assertEqual(ci.rust_targets(), {('fixture', 'test', 'known')})
            for n in range(128):
                (tests / f'case{n}.rs').write_text('// fixture')
            original_scandir = ci.os.scandir
            consumed = []
            class Counted:
                def __init__(self, path):
                    self.path = Path(path)
                    self.entries = original_scandir(path)
                def __enter__(self):
                    return self
                def __exit__(self, *_):
                    self.entries.close()
                def __iter__(self):
                    return self
                def __next__(self):
                    entry = next(self.entries)
                    if self.path == tests:
                        consumed.append(1)
                        if len(consumed) > 129:
                            raise AssertionError('automatic target scan exceeded capacity witness')
                    return entry
            with patch.object(ci, 'ROOT', root), patch.object(ci.os, 'scandir', Counted):
                self.assertEqual(ci.rust_targets(), set())
            self.assertEqual(len(consumed), 129)

    def test_automatic_symlink_cycles_fail_closed_for_directory_source_and_main(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'repo'
            package = root / 'crates/fixture'
            package.mkdir(parents=True)
            (package / 'Cargo.toml').write_text('[package]\nname="fixture"\n[lib]\n')
            tests = package / 'tests'
            tests.symlink_to('tests')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())
            tests.unlink()
            tests.mkdir()
            source = tests / 'cycle.rs'
            source.symlink_to('cycle.rs')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())
            source.unlink()
            nested = tests / 'nested'
            nested.mkdir()
            (nested / 'main.rs').symlink_to('main.rs')
            with patch.object(ci, 'ROOT', root):
                self.assertEqual(ci.rust_targets(), set())

    def test_native_stage_rejects_payloads_and_matches_source_enum(self):
        source = (ci.ROOT / 'scripts/check-native-qualification.py').read_text()
        stages = set(re.findall(r"report\['stage'\] = '([a-z-]+)'", source))
        stages.update(re.findall(r"setdefault\('failed_stage', '([a-z-]+)'\)", source))
        stages.add('prepare')
        self.assertEqual(ci.gate.NATIVE_STAGES, stages)
        for stage in ci.gate.NATIVE_STAGES - {'qualified'}:
            self.assertEqual(ci.failed_native_stage(json.dumps(
                {'status': 'failed', 'stage': stage, 'report': 'private-path'})), stage)
        for value in [None, [], {'status': 'passed', 'stage': 'pipeline', 'report': 'private-path'},
                      {'status': 'failed', 'stage': 'qualified', 'report': 'private-path'},
                      {'status': 'failed', 'stage': 'secret%0A::error', 'report': 'private-path'},
                      {'status': 'failed', 'stage': [], 'report': 'private-path'},
                      {'status': 'failed', 'stage': 'pipeline', 'report': 'é' * 1024},
                      {'status': 'failed', 'stage': 'pipeline', 'report': 'private-path', 'error': 'secret'}]:
            self.assertIsNone(ci.failed_native_stage(json.dumps(value, ensure_ascii=False)))
        self.assertIsNone(ci.failed_native_stage('{malformed'))
        self.assertIsNone(ci.failed_native_stage(json.dumps(
            {'status': 'failed', 'stage': 'pipeline', 'report': 'private-path'}) + '\ntrailing payload'))

    def test_actual_native_failure_annotation_excludes_raw_payload_after_resume(self):
        line = json.dumps({'status': 'failed', 'stage': 'pipeline', 'report': 'synthetic-secret-path'})
        code = f'print("::error title=synthetic-secret::synthetic-secret"); print({line!r}); raise SystemExit(7)'
        with tempfile.TemporaryDirectory() as folder, \
                patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'true'}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result, report = self.run_check(folder, 'native', code)
        self.assertEqual(result, 1)
        self.assertEqual(report['failed_native_stage'], 'pipeline')
        captured = output.getvalue().splitlines()
        token = re.fullmatch(r'::stop-commands::([0-9a-f]{64})', captured[0])[1]
        resume = captured.index(f'::{token}::')
        self.assertIn(line, captured[1:resume])
        self.assertEqual(captured[resume + 1:],
                         ['::error title=Reported native failure stage::pipeline'])
        self.assertNotIn('synthetic-secret', '\n'.join(captured[resume + 1:]))

    def test_reported_idp_stage_matches_source_and_rejects_unbounded_payloads(self):
        source = (ci.ROOT / 'scripts/check-access-idp.py').read_text()
        self.assertEqual(ci.IDP_STAGES, set(re.findall(r"self.stage = '([a-z-]+)'", source)))
        for stage in ci.IDP_STAGES:
            self.assertEqual(ci.failed_idp_stage(json.dumps(
                {'status': 'failed', 'stage': stage, 'report': 'private-path'})), stage)
        for value in [[], None, {'status': 'passed', 'stage': 'prepare', 'report': 'private-path'},
                      {'status': 'failed', 'stage': 'synthetic-secret', 'report': 'private-path'},
                      {'status': 'failed', 'stage': [], 'report': 'private-path'},
                      {'status': 'failed', 'stage': 'prepare', 'report': 'x' * 2048},
                      {'status': 'failed', 'stage': 'prepare', 'report': 'private-path',
                       'error': 'synthetic-secret'}]:
            self.assertIsNone(ci.failed_idp_stage(json.dumps(value)))
        self.assertIsNone(ci.failed_idp_stage('{malformed'))
        self.assertIsNone(ci.failed_idp_stage(''))
        unicode_line = json.dumps({'status': 'failed', 'stage': 'prepare',
                                   'report': 'é' * 1000}, ensure_ascii=False)
        self.assertLess(len(unicode_line), 2048)
        self.assertGreater(len(unicode_line.encode('utf-8')), 2048)
        self.assertIsNone(ci.failed_idp_stage(unicode_line))

    def test_actual_failed_idp_child_emits_only_allowlisted_stage_after_resume(self):
        line = json.dumps({'status': 'failed', 'stage': 'oidc-browser-flow',
                           'report': 'synthetic-secret-path'})
        with tempfile.TemporaryDirectory() as folder, \
                patch.dict(ci.os.environ, {'GITHUB_ACTIONS': 'true'}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result, report = self.run_check(folder, 'idp-browser', f'print({line!r}); raise SystemExit(7)')
            self.assertIn('synthetic-secret-path', (Path(folder) / 'idp-browser.log').read_text())
        self.assertEqual(result, 1)
        captured = output.getvalue().splitlines()
        token = re.fullmatch(r'::stop-commands::([0-9a-f]{64})', captured[0])[1]
        resume = captured.index(f'::{token}::')
        self.assertIn(line, captured[1:resume])
        self.assertEqual(captured[resume + 1:],
                         ['::error title=Reported IdP failure stage::oidc-browser-flow'])
        self.assertEqual(report['failed_idp_stage'], 'oidc-browser-flow')
        self.assertNotIn('synthetic-secret-path', '\n'.join(captured[resume + 1:]))

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

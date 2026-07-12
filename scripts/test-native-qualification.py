#!/usr/bin/env python3
"""Focused native-gate failures: identity, partial evidence and owned cleanup."""
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('check-native-qualification.py'))
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)
IMAGE = 'sha256:' + 'a' * 64


def pipeline(quick=False):
    profiles = [(1024, 100, False)] if quick else [(size, rate, False) for size in (1024, 4096) for rate in (100, 1000, 10000)] + [(4096, 20000, True)]
    return {'schema_version': 1, 'architecture': 'x86_64', 'image_id': IMAGE,
            'binary_sha256': 'hash', 'profiles': [
                {'event_bytes': size, 'target_eps': rate, 'saturation': saturation,
                 'shutdown_exit_code': 0, 'sample_count': 1, 'query_samples': 20,
                 'attempted': 1, 'accepted': 1, 'rejected': 0, 'transport_uncertain': 0}
                for size, rate, saturation in profiles]}


def soak_report():
    counters = {key: 0 for key in ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes', 'cancelled_write_bytes')}
    return {'schema_version': 1, 'status': 'passed', 'architecture': 'x86_64',
            'image_id': IMAGE, 'binary_sha256': 'hash', 'profiles': [
                {'event_bytes': size, 'duration_seconds': 120, 'load_seconds': 120.1,
                 'shutdown_exit_code': 0, 'query_samples': 20,
                 'attempted': 1, 'accepted': 1, 'rejected': 0, 'transport_uncertain': 0,
                 'wal_durable_events': 1, 'admission_uncertainty_bound': 0,
                 'final_metrics': {name: 1 for name in ('signal_wal_accepted_total', 'signal_storage_persisted_total', 'signal_rules_evaluated_total')},
                 'resources': {'sample_count': 12, 'buckets': [{'samples': 1} for _ in range(12)]},
                 'load_process_io_delta': counters.copy(), 'load_drain_queries_process_io_delta': counters.copy()}
                for size in (1024, 4096)]}


class IdentityAndReports(unittest.TestCase):
    def test_partial_or_inconsistent_soak_evidence_fails(self):
        qualification.validate_soak(soak_report(), 'amd64', IMAGE, 'hash', 120)
        for failure in ('missing-size', 'wrong-binary', 'failed', 'short-load', 'nan-load',
                        'uncertain-admission', 'storage-count', 'missing-io', 'missing-trend', 'boolean-count'):
            report = soak_report()
            row = report['profiles'][0]
            if failure == 'missing-size':
                report['profiles'].pop()
            elif failure == 'wrong-binary':
                report['binary_sha256'] = 'other'
            elif failure == 'failed':
                report['status'] = 'failed'
            elif failure == 'short-load':
                row['load_seconds'] = 119.9
            elif failure == 'nan-load':
                row['load_seconds'] = float('nan')
            elif failure == 'uncertain-admission':
                row['wal_durable_events'] = 2
            elif failure == 'storage-count':
                row['final_metrics']['signal_storage_persisted_total'] = 0
            elif failure == 'missing-io':
                del row['load_process_io_delta']['write_bytes']
            elif failure == 'missing-trend':
                row['resources']['buckets'][-1]['samples'] = 0
            elif failure == 'boolean-count':
                row['attempted'] = True
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                qualification.validate_soak(report, 'amd64', IMAGE, 'hash', 120)

    def test_invalid_soak_modes_fail_before_any_docker_operation(self):
        for flags in (['--soak-only'], ['--soak-seconds', '601'], ['--soak-seconds', '-1'],
                      ['--soak-only', '--soak-seconds', '120', '--quick'], ['--quick', '--soak-seconds', '120']):
            with tempfile.TemporaryDirectory() as folder, mock.patch.object(qualification.Gate, 'run') as run, mock.patch('sys.stderr', new=io.StringIO()):
                with self.subTest(flags=flags), self.assertRaises(SystemExit):
                    qualification.main(['--image', IMAGE, '--expect-architecture', 'amd64', '--output-root', folder, *flags])
                run.assert_not_called()
                self.assertEqual(list(Path(folder).iterdir()), [])
    def test_wrong_host_daemon_and_image_architecture_fail(self):
        daemon = {'os': 'linux', 'architecture': 'x86_64'}
        image = {'os': 'linux', 'architecture': 'amd64', 'id': IMAGE}
        qualification.verify_native('amd64', 'Linux', 'x86_64', daemon, image)
        for host_os, host_arch, actual_daemon, actual_image in [
            ('Darwin', 'x86_64', daemon, image), ('Linux', 'aarch64', daemon, image),
            ('Linux', 'x86_64', {'os': 'linux', 'architecture': 'aarch64'}, image),
            ('Linux', 'x86_64', daemon, dict(image, architecture='arm64')),
            ('Linux', 'x86_64', daemon, dict(image, id='mutable:tag'))]:
            with self.subTest(host_os=host_os, host_arch=host_arch, daemon=actual_daemon, image=actual_image):
                with self.assertRaises(RuntimeError):
                    qualification.verify_native('amd64', host_os, host_arch, actual_daemon, actual_image)

    def test_wrong_elf_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'server'
            binary.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + struct.pack('<H', 183))
            binary.chmod(0o755)
            with self.assertRaises(RuntimeError):
                qualification.verify_binary(binary, 'amd64')
            link = Path(folder) / 'link'
            link.symlink_to(binary)
            with self.assertRaises(RuntimeError):
                qualification.verify_binary(link, 'arm64')

    def test_partial_pipeline_never_passes_full(self):
        qualification.validate_pipeline(pipeline(), 'amd64', IMAGE, 'hash', False)
        for report in [pipeline(True), dict(pipeline(), binary_sha256='other'), dict(pipeline(), profiles=[])]:
            with self.assertRaises(RuntimeError):
                qualification.validate_pipeline(report, 'amd64', IMAGE, 'hash', False)
        report = pipeline()
        report['profiles'][-1]['shutdown_exit_code'] = None
        with self.assertRaises(RuntimeError):
            qualification.validate_pipeline(report, 'amd64', IMAGE, 'hash', False)

    def test_missing_and_oversized_report_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report'
            with self.assertRaises(RuntimeError):
                qualification.bounded_json(path)
            path.write_bytes(b' ' * (qualification.REPORT_CAP + 1))
            with self.assertRaises(RuntimeError):
                qualification.bounded_json(path)

    def test_missing_hardening_mutation_observation_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'campaign.log'
            log.write_text('\n'.join(f'test result: ok. {count} passed; 0 failed;' for count in (3, 2, 2, 2)))
            report = {'schema_version': 1, 'exit_code': 0, 'log_sha256': qualification.sha256(log),
                      'configured_cases': {'event_roundtrip': 512, 'url_transport': 512, 'rule_truth_model': 512, 'wal_ack_prefix': 9},
                      'source_sha256': {package: qualification.sha256(qualification.ROOT / 'crates' / package / 'tests/phase10-properties.rs') for package in ('signal-event', 'signal-protocol', 'signal-rules', 'signal-buffer')},
                      'observed_wal_cases': {'wal_record_mutations': 104}}
            with self.assertRaisesRegex(RuntimeError, 'WAL mutation'):
                qualification.validate_hardening(report, log)

    def test_hardening_directory_collision_preserves_existing(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / 'campaign'
            directory.mkdir()
            sentinel = directory / 'campaign.json'
            sentinel.write_text('existing evidence')
            result = subprocess.run([sys.executable, str(qualification.ROOT / 'scripts/check-hardening.py'), '--output-dir', str(directory)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(sentinel.read_text(), 'existing evidence')


class ResourceOwnership(unittest.TestCase):
    def test_actual_harness_reports_first_failed_stage_after_owned_cleanup(self):
        for stage in ('native-identity', 'binary-extraction', 'hardening', 'pipeline',
                      'soak', 'report-finalization', 'container-cleanup', 'late-interruption'):
            commands = []
            def fake_run(_gate, command, **_kwargs):
                commands.append(command)
                if command[0] == 'docker':
                    if command[1] == 'info':
                        if stage == 'native-identity':
                            raise RuntimeError('synthetic-private-diagnostic')
                        return json.dumps({'os': 'linux', 'architecture': 'x86_64'})
                    if command[1] == 'image':
                        return json.dumps({'id': IMAGE, 'os': 'linux', 'architecture': 'amd64'})
                    if command[1] == 'cp':
                        if stage == 'binary-extraction':
                            raise RuntimeError('synthetic-private-diagnostic')
                        binary = Path(command[-1])
                        binary.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + struct.pack('<H', 62))
                        binary.chmod(0o755)
                    if command[1] == 'rm' and stage in ('pipeline', 'container-cleanup'):
                        raise RuntimeError('synthetic-private-cleanup')
                    return ''
                phase = ('hardening' if command[1].endswith('check-hardening.py')
                         else 'pipeline' if command[1].endswith('pipeline.py') else 'soak')
                if stage == phase:
                    raise RuntimeError('synthetic-private-diagnostic')
                if phase == 'hardening':
                    directory = Path(command[command.index('--output-dir') + 1])
                    directory.mkdir()
                    (directory / 'campaign.json').write_text('{}')
                    (directory / 'campaign.log').write_text('fixture')
                else:
                    Path(command[command.index('--output') + 1]).write_text('{}')
                return ''
            original_hash = qualification.sha256
            def file_hash(path):
                if stage == 'report-finalization' and path.name == 'pipeline.json':
                    raise RuntimeError('synthetic-private-diagnostic')
                return original_hash(path)
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as folder, \
                    mock.patch.object(qualification.Gate, 'run', fake_run), \
                    mock.patch.object(qualification, 'sha256', file_hash), \
                    mock.patch.object(qualification, 'validate_hardening'), \
                    mock.patch.object(qualification, 'validate_pipeline'), \
                    mock.patch.object(qualification, 'validate_soak'), \
                    mock.patch.object(qualification.platform, 'system', return_value='Linux'), \
                    mock.patch.object(qualification.platform, 'machine', return_value='x86_64'), \
                    mock.patch('sys.stdout', new=io.StringIO()) as output:
                # Reproduce cancellation between preparing success metadata and
                # finalizing it, after all mocked operation stages completed.
                final_line = next(index for index, line in enumerate(
                    Path(qualification.__file__).read_text().splitlines(), 1)
                    if line.strip() == "report['stage'] = 'qualified'")
                previous_trace = sys.gettrace()
                def interrupt_at_success(frame, event, _arg):
                    if (event == 'line' and frame.f_code.co_filename == qualification.__file__
                            and frame.f_lineno == final_line):
                        raise KeyboardInterrupt('synthetic late interruption')
                    return interrupt_at_success
                try:
                    if stage == 'late-interruption':
                        sys.settrace(interrupt_at_success)
                    result = qualification.main(['--image', IMAGE, '--expect-architecture', 'amd64',
                                                 '--output-root', folder, '--soak-seconds', '120'])
                finally:
                    sys.settrace(previous_trace)
                report_path = next(Path(folder).glob('*/qualification.json'))
                report = json.loads(report_path.read_text())
                summary = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(result, 1)
                self.assertFalse(report['full_qualification'])
                expected_stage = 'report-finalization' if stage == 'late-interruption' else stage
                self.assertEqual(report['failed_stage'], expected_stage)
                self.assertEqual(summary, {'status': 'failed', 'stage': expected_stage,
                                           'report': str(report_path)})
                self.assertNotIn('synthetic-private', json.dumps(summary))
                if stage != 'native-identity':
                    self.assertTrue(any(c[:3] == ['docker', 'rm', '-f'] for c in commands))
                    self.assertIn({'resource': 'owned-temporary-directory', 'status': 'removed'},
                                  report['cleanup'])
                if stage == 'pipeline':
                    self.assertEqual(report['cleanup'][0]['status'], 'failed')
                    self.assertEqual(summary['stage'], 'pipeline')

    def test_soak_only_preserves_scope_identity_and_skips_completed_campaigns(self):
        for failed in (False, True):
            commands = []
            def fake_run(_gate, command, **_kwargs):
                commands.append(command)
                if command[1] == 'info':
                    return json.dumps({'os': 'linux', 'architecture': 'x86_64'})
                if command[1:3] == ['image', 'inspect']:
                    return json.dumps({'os': 'linux', 'architecture': 'amd64', 'id': IMAGE})
                if command[1] == 'cp':
                    binary = Path(command[-1])
                    binary.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + struct.pack('<H', 62))
                    binary.chmod(0o755)
                if '--output' in command:
                    report = soak_report()
                    report['binary_sha256'] = qualification.sha256(Path(command[command.index('--server') + 1]))
                    if failed:
                        report['profiles'].pop()
                    Path(command[command.index('--output') + 1]).write_text(json.dumps(report))
                return 'fixture'
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as folder, mock.patch.object(qualification.Gate, 'run', fake_run), mock.patch.object(qualification.platform, 'system', return_value='Linux'), mock.patch.object(qualification.platform, 'machine', return_value='x86_64'), mock.patch('sys.stdout', new=io.StringIO()) as output:
                result = qualification.main(['--image', IMAGE, '--expect-architecture', 'amd64', '--output-root', folder, '--soak-only', '--soak-seconds', '120'])
                report = json.loads(next(Path(folder).glob('*/qualification.json')).read_text())
                self.assertEqual(result, 1 if failed else 0)
                self.assertEqual(report['scope'], 'native-soak')
                self.assertFalse(report['full_qualification'])
                self.assertTrue(all(row['status'] == 'removed' for row in report['cleanup']))
                self.assertFalse(any('--output-dir' in command or any(str(value).endswith('/pipeline.py') for value in command) for command in commands))
                summary = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(summary['stage'], 'soak' if failed else 'qualified')
                self.assertEqual(summary['status'], 'failed' if failed else 'passed')
                if not failed:
                    self.assertIn('soak.json', report['reports_sha256'])
    def test_extraction_failure_removes_only_owned_container_and_temp(self):
        commands, paths = [], []
        def fake_run(_gate, command, **_kwargs):
            commands.append(command)
            if command[1] == 'info':
                return json.dumps({'os': 'linux', 'architecture': 'x86_64'})
            if command[1:3] == ['image', 'inspect']:
                return json.dumps({'os': 'linux', 'architecture': 'amd64', 'id': IMAGE})
            if command[1] == 'cp':
                paths.append(Path(command[-1]).parent)
                raise RuntimeError('simulated copy failure')
            return 'owned'
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(qualification.Gate, 'run', fake_run), mock.patch.object(qualification.platform, 'system', return_value='Linux'), mock.patch.object(qualification.platform, 'machine', return_value='x86_64'), mock.patch('sys.stdout', new=io.StringIO()):
            sentinel = Path(folder) / 'unrelated'
            sentinel.write_text('keep')
            code = qualification.main(['--image', 'existing:image', '--expect-architecture', 'amd64', '--output-root', folder])
            self.assertEqual(code, 1)
            create = next(command for command in commands if command[1] == 'create')
            removal = next(command for command in commands if command[1] == 'rm')
            self.assertEqual(create[-1], IMAGE)
            self.assertIn('--pull=never', create)
            self.assertEqual(removal, ['docker', 'rm', '-f', create[create.index('--name') + 1]])
            self.assertFalse(paths[0].exists())
            self.assertEqual(sentinel.read_text(), 'keep')
            report = json.loads(next(Path(folder).glob('*/qualification.json')).read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertFalse(report['full_qualification'])
            self.assertTrue(all(row['status'] == 'removed' for row in report['cleanup']))

    def test_missing_pipeline_report_fails_and_smoke_is_explicit(self):
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as folder:
                def fake_run(_gate, command, **_kwargs):
                    if command[1] == 'info':
                        return json.dumps({'os': 'linux', 'architecture': 'x86_64'})
                    if command[1:3] == ['image', 'inspect']:
                        return json.dumps({'os': 'linux', 'architecture': 'amd64', 'id': IMAGE})
                    if command[1] == 'cp':
                        binary = Path(command[-1])
                        binary.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + struct.pack('<H', 62))
                        binary.chmod(0o755)
                    if '--output-dir' in command:
                        campaign = Path(command[command.index('--output-dir') + 1])
                        campaign.mkdir()
                        (campaign / 'campaign.json').write_text('{}')
                        (campaign / 'campaign.log').write_text('fixture')
                    if '--output' in command and not missing:
                        report = pipeline(True)
                        report['binary_sha256'] = qualification.sha256(Path(command[command.index('--server') + 1]))
                        Path(command[command.index('--output') + 1]).write_text(json.dumps(report))
                    return 'fixture'
                with mock.patch.object(qualification.Gate, 'run', fake_run), mock.patch.object(qualification, 'validate_hardening'), mock.patch.object(qualification.platform, 'system', return_value='Linux'), mock.patch.object(qualification.platform, 'machine', return_value='x86_64'), mock.patch('sys.stdout', new=io.StringIO()):
                    code = qualification.main(['--image', IMAGE, '--expect-architecture', 'amd64', '--output-root', folder, '--quick'])
                report = json.loads(next(Path(folder).glob('*/qualification.json')).read_text())
                self.assertEqual(code, 1 if missing else 0)
                self.assertEqual(report['status'], 'failed' if missing else 'passed')
                self.assertEqual(report['scope'], 'smoke')
                self.assertFalse(report['full_qualification'])
                self.assertTrue(all(row['status'] == 'removed' for row in report['cleanup']))

    @unittest.skipUnless(sys.platform == 'linux', 'native gate targets Linux')
    def test_timeout_stops_owned_descendant_preserves_unrelated(self):
        libc = ctypes.CDLL(None, use_errno=True)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        child = None
        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'pids'
                parent_code = '''import json,os,pathlib,signal,subprocess,sys,time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])
pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid]))
time.sleep(30)
'''
                began = time.monotonic()
                with (Path(folder) / 'log').open('wb') as stream:
                    with self.assertRaisesRegex(RuntimeError, 'deadline'):
                        qualification.run_bounded([sys.executable, '-c', parent_code, str(path)], stream, timeout=0.5, grace=0.05)
                parent, child = json.loads(path.read_text())
                self.assertLess(time.monotonic() - began, 2)
                self.assertFalse(Path(f'/proc/{parent}').exists())
                waited, status = os.waitpid(child, 0)
                self.assertEqual(waited, child)
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                self.assertIsNone(sentinel.poll())
        finally:
            if child is not None:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            sentinel.kill()
            sentinel.wait(timeout=2)

    @unittest.skipUnless(sys.platform == 'linux', 'native gate targets Linux')
    def test_real_harness_sigterm_cleans_nested_session(self):
        # Both actual entrypoints create separate sessions. SIGTERM must reach
        # their finally blocks before the outer group deadline escalates.
        libc = ctypes.CDLL(None, use_errno=True)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        for harness in ('pipeline', 'hardening'):
            with self.subTest(harness=harness), tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                pids = directory / 'pids'
                executable = directory / ('server' if harness == 'pipeline' else 'cargo')
                executable.write_text('#!' + sys.executable + '\n' +
                                      'import os,pathlib,sys,time\n' +
                                      'if "--version" in sys.argv: print("test-server"); sys.exit(0)\n' +
                                      'pathlib.Path(' + repr(str(pids)) + ').write_text(str(os.getpid()))\n' +
                                      'time.sleep(30)\n')
                executable.chmod(0o755)
                if harness == 'pipeline':
                    wrapper = '''import itertools,runpy,socket,sys,urllib.request
ports = itertools.count(20000)
socket.socket.bind = lambda self, address: None
socket.socket.getsockname = lambda self: ('127.0.0.1', next(ports))
def unavailable(*args, **kwargs):
    raise OSError('offline readiness fixture')
urllib.request.urlopen = unavailable
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
'''
                    command = [sys.executable, '-c', wrapper, str(qualification.ROOT / 'benchmarks/pipeline.py'),
                               '--server', str(executable), '--output', str(directory / 'pipeline.json'), '--quick']
                else:
                    # Alter only this process's PATH to provide a finite fake
                    # Cargo executable; actual property campaigns are unchanged.
                    wrapper = 'import os,sys; os.environ["PATH"]=sys.argv[1]+os.pathsep+os.environ["PATH"]; os.execv(sys.executable,[sys.executable]+sys.argv[2:])'
                    command = [sys.executable, '-c', wrapper, str(directory),
                               str(qualification.ROOT / 'scripts/check-hardening.py'), '--output-dir', str(directory / 'campaign')]
                with (directory / 'log').open('wb') as stream:
                    with self.assertRaises(RuntimeError) as interrupted:
                        qualification.run_bounded(command, stream, timeout=0.5, grace=3)
                self.assertRegex(str(interrupted.exception), 'deadline',
                                 msg=(directory / 'log').read_text())
                self.assertTrue(pids.exists(), 'nested process must start before cancellation')
                child = int(pids.read_text())
                self.assertFalse(Path(f'/proc/{child}').exists(), 'nested harness session survived outer timeout')

    def test_selector_initialization_failure_cleans_owned_process(self):
        original_popen = subprocess.Popen
        owned = []
        def record(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            owned.append(process)
            return process
        sentinel = original_popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            with tempfile.TemporaryDirectory() as folder, (Path(folder) / 'log').open('wb') as stream:
                with mock.patch.object(qualification.subprocess, 'Popen', record), mock.patch.object(qualification.selectors, 'DefaultSelector', side_effect=RuntimeError('selector setup failed')):
                    with self.assertRaisesRegex(RuntimeError, 'selector setup failed'):
                        qualification.run_bounded([sys.executable, '-c', 'import time; time.sleep(30)'], stream, grace=0.01)
            self.assertFalse(Path(f'/proc/{owned[0].pid}').exists())
            self.assertIsNone(sentinel.poll())
        finally:
            sentinel.kill()
            sentinel.wait(timeout=2)

    def test_spawn_assignment_defers_signal_until_cleanup_registered(self):
        hardening_spec = importlib.util.spec_from_file_location('hardening_gap', qualification.ROOT / 'scripts/check-hardening.py')
        hardening = importlib.util.module_from_spec(hardening_spec)
        hardening_spec.loader.exec_module(hardening)
        original_popen = subprocess.Popen
        sentinel = original_popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            for harness in (qualification, hardening):
                with self.subTest(harness=harness.__name__), tempfile.TemporaryDirectory() as folder:
                    owned = []
                    prior = signal.getsignal(signal.SIGTERM)
                    def interrupt_before_assignment(*args, **kwargs):
                        process = original_popen(*args, **kwargs)
                        owned.append(process)
                        os.kill(os.getpid(), signal.SIGTERM)
                        return process
                    with (Path(folder) / 'log').open('wb') as stream, mock.patch.object(harness.subprocess, 'Popen', interrupt_before_assignment):
                        with self.assertRaisesRegex(KeyboardInterrupt, 'during spawn'):
                            harness.run_bounded([sys.executable, '-c', 'import time; time.sleep(30)'], stream, grace=0.01)
                    self.assertEqual(signal.getsignal(signal.SIGTERM), prior)
                    self.assertFalse(Path(f'/proc/{owned[0].pid}').exists())
                    self.assertIsNone(sentinel.poll())
        finally:
            sentinel.kill()
            sentinel.wait(timeout=2)

    def test_sampler_constructor_interrupt_cleans_pipeline_session(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            pids = directory / 'pid'
            executable = directory / 'server'
            executable.write_text('#!' + sys.executable + '\nimport os,pathlib,time\npathlib.Path(' + repr(str(pids)) + ').write_text(str(os.getpid()))\ntime.sleep(30)\n')
            executable.chmod(0o755)
            wrapper = """import importlib.util,itertools,os,pathlib,signal,sys,time
spec = importlib.util.spec_from_file_location('pipeline_gap', sys.argv[1])
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
ports = itertools.count(20000)
pipeline.port = lambda: next(ports)
def interrupted(signum, frame):
    raise KeyboardInterrupt('sampler initialization interrupt')
signal.signal(signal.SIGTERM, interrupted)
def interrupted_sampler(*args):
    deadline = time.monotonic() + 2
    while not pathlib.Path(sys.argv[3]).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('fixture server did not start')
        time.sleep(0.01)
    os.kill(os.getpid(), signal.SIGTERM)
pipeline.Sampler = interrupted_sampler
pipeline.profile(pathlib.Path(sys.argv[2]), 1024, 100, False)
"""
            result = subprocess.run([sys.executable, '-c', wrapper, str(qualification.ROOT / 'benchmarks/pipeline.py'), str(executable), str(pids)], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'sampler initialization interrupt', result.stderr)
            self.assertTrue(pids.exists())
            self.assertFalse(Path(f'/proc/{int(pids.read_text())}').exists())

    def test_interrupt_during_cleanup_grace_still_kills_and_reaps(self):
        original_popen = subprocess.Popen
        original_sleep = time.sleep
        interrupted = False
        def interrupt_once(seconds):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt("second interrupt")
            return original_sleep(seconds)
        owned = []
        def record(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            owned.append(process)
            return process
        sentinel = original_popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            with tempfile.TemporaryDirectory() as folder, (Path(folder) / 'log').open('wb') as stream:
                # Setup fails while command is live; the simulated second
                # interrupt arrives while finally waits between TERM and KILL.
                with mock.patch.object(qualification.subprocess, 'Popen', record), mock.patch.object(qualification.selectors, 'DefaultSelector', side_effect=RuntimeError('setup failure')), mock.patch.object(qualification.time, 'sleep', side_effect=interrupt_once):
                    with self.assertRaisesRegex(KeyboardInterrupt, 'second interrupt'):
                        qualification.run_bounded([sys.executable, '-c', 'import time; time.sleep(30)'], stream)
            self.assertFalse(Path(f'/proc/{owned[0].pid}').exists())
            self.assertIsNone(sentinel.poll())
        finally:
            sentinel.kill()
            sentinel.wait(timeout=2)

    def test_output_flood_fails_with_bounded_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'log'
            with path.open('wb') as stream:
                with self.assertRaisesRegex(RuntimeError, 'capture bound'):
                    qualification.run_bounded([sys.executable, '-c', 'import os; [os.write(1,b"x"*65536) for _ in range(100)]'], stream, timeout=3, grace=0.01)
            self.assertLessEqual(path.stat().st_size, qualification.LOG_CAP)


if __name__ == '__main__':
    unittest.main()

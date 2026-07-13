#!/usr/bin/env python3
"""Fixed diagnostics exercise real benchmark branches without a load campaign."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('pipeline', Path(__file__).resolve().parents[1] / 'benchmarks/pipeline.py')
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class FixedDiagnostics(unittest.TestCase):
    def test_first_and_later_failed_profiles_preserve_partial_measurements(self):
        for failed_index in (0, 1):
            with self.subTest(index=failed_index), tempfile.TemporaryDirectory() as folder:
                binary = Path(folder) / 'binary'
                binary.write_bytes(b'not executed')
                output = Path(folder) / 'measurements.json'
                sidecar = Path(folder) / 'diagnostic.json'
                called = []
                def run_profile(_binary, size, rate, saturation, diagnostic):
                    called.append((size, rate, saturation))
                    if len(called) == failed_index + 1:
                        raise pipeline.PipelineAssertion('event-query-count', 'synthetic-private-canary')
                    return dict(event_bytes=size, target_eps=rate, saturation=saturation, attempted=1,
                                accepted=1, rejected=0, transport_uncertain=0, accepted_eps=1, peak_rss_bytes=1)
                with mock.patch.object(pipeline, 'profile', side_effect=run_profile), \
                        mock.patch.object(pipeline.subprocess, 'run', return_value=SimpleNamespace(stdout='fixture')), \
                        mock.patch.object(pipeline.platform, 'system', return_value='Linux'), \
                        mock.patch.object(pipeline.platform, 'machine', return_value='x86_64'), \
                        contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(pipeline.PipelineAssertion, 'synthetic-private-canary'):
                        pipeline.main(['--server', str(binary), '--output', str(output),
                                       '--diagnostic-output', str(sidecar)])
                point = pipeline.read_diagnostic(sidecar)
                self.assertEqual(point, {'schema_version': 1, 'profile': '1k-100' if failed_index == 0 else '1k-1000',
                    'check': 'event-query-count', 'kind': 'assertion-failed'})
                self.assertNotIn('canary', sidecar.read_text())
                self.assertEqual(len(json.loads(output.read_text())['profiles']) if output.exists() else 0, failed_index)

    def test_last_entered_is_not_an_asserted_failure_and_fresh_path_is_required(self):
        with tempfile.TemporaryDirectory() as folder:
            sidecar = Path(folder) / 'point.json'
            diagnostic = pipeline.Diagnostic(sidecar)
            diagnostic.enter('load', '4k-10000')
            diagnostic.fail(KeyboardInterrupt('private interrupt'))
            diagnostic.enter('server-shutdown')
            diagnostic.fail(pipeline.PipelineAssertion('server-shutdown', 'secondary'))
            self.assertEqual(pipeline.read_diagnostic(sidecar), {
                'schema_version': 1, 'profile': '4k-10000', 'check': 'load', 'kind': 'last-entered'})
            original = sidecar.read_bytes()
            with self.assertRaises(FileExistsError):
                pipeline.Diagnostic(sidecar)
            self.assertEqual(sidecar.read_bytes(), original)

    def test_primary_accounting_survives_sampler_and_server_cleanup_failures(self):
        class Process:
            pid = 12345
            returncode = None
            terminated = False
            def poll(self):
                return self.returncode
            def terminate(self):
                self.terminated = True
            def wait(self, timeout):
                self.returncode = 1
        class Sampler:
            def __init__(self, *_args):
                self.stop, self.cpu_ticks = threading.Event(), 0
            def sample(self):
                pass
            def run(self):
                raise AssertionError('fixture must not run a thread')
        class Pool:
            def __init__(self, **_args):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def map(self, *_args):
                return [dict(attempted=1, accepted=1, rejected=0, transport_uncertain=0,
                    expected_matches=0, timeout_response_rejected=0, unavailable_response_rejected=0,
                    confirmed_capacity_rejected=0, statuses={'202': 1}) for _ in range(4)]
        process = Process()
        sampling = SimpleNamespace(start=lambda: None, join=lambda **_kw: None, is_alive=lambda: True)
        metric = {'signal_queue_depth': 0, 'signal_storage_persisted_total': 5,
                  'signal_events_accepted_total': 5, 'signal_events_rejected_total': 0}
        with tempfile.TemporaryDirectory() as folder:
            sidecar = Path(folder) / 'point.json'
            diagnostic = pipeline.Diagnostic(sidecar)
            diagnostic.enter('configuration', '1k-100')
            with mock.patch.object(pipeline, 'port', side_effect=[10001, 10002]), \
                    mock.patch.object(pipeline, 'Sampler', Sampler), \
                    mock.patch.object(pipeline.threading, 'Thread', return_value=sampling), \
                    mock.patch.object(pipeline.subprocess, 'Popen', return_value=process), \
                    mock.patch.object(pipeline, 'request', return_value=(200, b'')), \
                    mock.patch.object(pipeline, 'metrics', return_value=metric), \
                    mock.patch.object(pipeline.concurrent.futures, 'ThreadPoolExecutor', Pool):
                with self.assertRaises(pipeline.PipelineAssertion) as failure:
                    pipeline.profile(Path('not-executed'), 1024, 100, False, diagnostic)
            self.assertEqual(failure.exception.check, 'http-accepted-accounting')
            self.assertEqual(failure.exception.__notes__, [
                'secondary pipeline cleanup failure: sampler-shutdown',
                'secondary pipeline cleanup failure: server-shutdown'])
            self.assertTrue(process.terminated)
            self.assertEqual(pipeline.read_diagnostic(sidecar)['check'], 'http-accepted-accounting')

    def test_strict_bounded_sidecar_rejects_duplicates_types_unknown_and_aliases(self):
        valid = {'schema_version': 1, 'profile': '1k-100', 'check': 'readiness', 'kind': 'last-entered'}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'point.json'
            cases = [json.dumps({**valid, 'schema_version': True}), json.dumps({**valid, 'profile': 'private'}),
                json.dumps({**valid, 'check': 'unsafe%0A::error'}), json.dumps({**valid, 'kind': 'cause'}),
                json.dumps([1, '1k-100', 'readiness', 'last-entered']), json.dumps({**valid, 'secret': 'private'}),
                '{"schema_version":1,"schema_version":1,"profile":"1k-100","check":"readiness","kind":"last-entered"}',
                json.dumps(valid) + ' ' * 2048, json.dumps(valid) + 'é' * 1024, '[' * 1024 + ']' * 1024]
            for value in cases:
                path.write_text(value)
                self.assertIsNone(pipeline.read_diagnostic(path), value[:80])
            path.write_text(json.dumps(valid))
            self.assertEqual(pipeline.read_diagnostic(path), valid)
            link = Path(folder) / 'alias'
            link.symlink_to(path)
            self.assertIsNone(pipeline.read_diagnostic(link))
            link.unlink()
            link.hardlink_to(path)
            self.assertIsNone(pipeline.read_diagnostic(path))
            fifo = Path(folder) / 'fifo'
            os.mkfifo(fifo)
            self.assertIsNone(pipeline.read_diagnostic(fifo))

    def test_optional_write_failure_cannot_prevent_cleanup_or_replace_primary(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'point.json'
            diagnostic = pipeline.Diagnostic(path)
            diagnostic.enter('load', '1k-100')
            with mock.patch.object(Path, 'open', side_effect=OSError('synthetic disk denial')):
                diagnostic.fail(pipeline.PipelineAssertion('batch-accounting', 'original'))
                diagnostic.enter('server-shutdown')
            self.assertEqual(pipeline.read_diagnostic(path)['check'], 'load')
            self.assertEqual(pipeline.read_diagnostic(path)['kind'], 'last-entered')


if __name__ == '__main__':
    unittest.main()

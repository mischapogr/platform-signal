#!/usr/bin/env python3
"""Finite soak regressions for evidence bounds, admission ambiguity and process custody."""
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

spec = importlib.util.spec_from_file_location('soak', Path(__file__).resolve().parents[1] / 'benchmarks/soak.py')
soak = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soak)


def final_metrics(durable=2, matches=1):
    row = {'signal_events_accepted_total': 2, 'signal_events_rejected_total': 8,
           'signal_wal_accepted_total': durable, 'signal_storage_persisted_total': durable,
           'signal_rules_evaluated_total': durable, 'signal_findings_count': matches}
    row.update(dict.fromkeys(('signal_events_dropped_total', 'signal_storage_failures_total', 'signal_storage_timeouts_total',
                             'signal_storage_full_total', 'signal_storage_fail_closed', 'signal_rules_failures_total',
                             'signal_findings_failures_total', 'signal_findings_rejections_total', 'signal_findings_timeouts_total', 'signal_findings_closed'), 0))
    return row


class BoundsAndEvidence(unittest.TestCase):
    def test_invalid_duration_rate_and_finite_maximum(self):
        for seconds, rate in ((9, 100), (601, 100), (120, 9), (120, 201)):
            with self.subTest(seconds=seconds, rate=rate), self.assertRaises(ValueError):
                soak.bounds(seconds, rate)
        self.assertEqual(soak.bounds(120, 100), 12000)
        self.assertEqual(soak.bounds(600, 200), 120000)

    def test_soak_query_budget_changes_only_explicit_query_memory(self):
        directory = Path('/owned-synthetic-data')
        original_pipeline = soak.pipeline.config(directory, 20000, 20001, False)
        previous_soak = original_pipeline.replace('max_files: 2048', 'max_files: 8192').replace(
            'max_disk_bytes: 67108864', 'max_disk_bytes: 268435456')
        current_soak = soak.soak_config(directory, 20000, 20001)
        self.assertEqual(current_soak.replace('query:\n  memory_bytes: 268435456',
                                               'query:\n  memory_bytes: 67108864'), previous_soak)
        self.assertIn('query:\n  memory_bytes: 67108864', original_pipeline)
        self.assertEqual(soak.QUERY_MEMORY_BYTES, 256 * 1024 * 1024)

    def test_existing_evidence_and_symlink_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'binary'
            binary.write_text('owned binary sentinel')
            output = Path(folder) / 'report'
            output.write_text('prior evidence')
            alias = Path(folder) / 'alias'
            alias.symlink_to(binary)
            hardlink = Path(folder) / 'hardlink'
            os.link(binary, hardlink)
            for destination in (binary, output, alias, hardlink):
                with self.subTest(destination=destination), mock.patch.object(soak, 'binary_identity', return_value='hash'), mock.patch.object(soak, 'profile') as profile:
                    with self.assertRaises(FileExistsError):
                        soak.main(['--server', str(binary), '--image-id', 'id', '--output', str(destination)])
                    profile.assert_not_called()
            self.assertEqual(binary.read_text(), 'owned binary sentinel')
            self.assertEqual(output.read_text(), 'prior evidence')

    def test_wrong_elf_and_symlink_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'server'
            binary.write_bytes(b'not native ELF')
            binary.chmod(0o755)
            with self.assertRaises(ValueError):
                soak.binary_identity(binary)
            link = Path(folder) / 'link'
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                soak.binary_identity(link)

    def test_fixed_buckets_expose_rss_drift_and_io_without_subtraction(self):
        trend = soak.Trend(0, '', 0, 120)
        for index in range(12000):
            reading = {'rss': 100 + index, 'ticks': index, 'io': dict.fromkeys(soak.IO_KEYS, index)}
            trend.add(index / 100, reading, {'signal_queue_depth': index % 4})
        report = trend.report()
        self.assertEqual(len(report['buckets']), 12)
        self.assertGreater(report['warmup_to_final_rss_mean_drift_bytes'], 0)
        self.assertEqual(report['rss_observed_min_bytes'], 100)
        self.assertEqual(report['rss_observed_max_bytes'], 12099)
        self.assertEqual(report['buckets'][0]['process_io_delta']['cancelled_write_bytes'], 999)
        self.assertNotIn('device_throughput', report)

    def test_missing_final_samples_and_decreasing_io_fail(self):
        trend = soak.Trend(0, '', 0, 120)
        reading = {'rss': 100, 'ticks': 0, 'io': dict.fromkeys(soak.IO_KEYS, 0)}
        trend.add(1, reading, {})
        with self.assertRaises(RuntimeError):
            trend.report()
        with self.assertRaises(RuntimeError):
            soak.io_delta(dict.fromkeys(soak.IO_KEYS, 1), dict.fromkeys(soak.IO_KEYS, 0))

    def test_report_overflow_does_not_write(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report'
            with path.open('w+b') as stream:
                stream.write(b'keep')
                with self.assertRaises(RuntimeError):
                    soak.write_report(stream, {'payload': 'x' * soak.REPORT_CAP})
                stream.seek(0)
                self.assertEqual(stream.read(), b'keep')

    def test_failed_profile_retains_partial_failure_report(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'server'
            binary.write_text('fixture')
            output = Path(folder) / 'report'
            def failed_profile(_binary, size, seconds, rate, observation, retain):
                observation.update(event_bytes=size, duration_seconds=seconds, accepted=300,
                                   load_seconds=seconds, resources={'sample_count': 10},
                                   stage='queries', status='failed', shutdown_exit_code=0,
                                   query_failure={'status': 408, 'kind': 'http_status'})
                retain()
                raise RuntimeError('readiness failed')
            with mock.patch.object(soak, 'binary_identity', return_value='hash'), mock.patch.object(soak, 'profile', side_effect=failed_profile):
                with self.assertRaisesRegex(RuntimeError, 'readiness failed'):
                    soak.main(['--server', str(binary), '--image-id', 'id', '--output', str(output), '--seconds', '10'])
            report = json.loads(output.read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['scope'], 'diagnostic')
            self.assertEqual(report['limits']['query_memory_bytes'], 256 * 1024 * 1024)
            self.assertEqual(report['profiles'][0]['accepted'], 300)
            self.assertEqual(report['profiles'][0]['resources']['sample_count'], 10)
            self.assertEqual(report['profiles'][0]['query_failure']['status'], 408)
            self.assertIn('readiness failed', report['error'])


class AdmissionAccounting(unittest.TestCase):
    def totals(self):
        totals = dict.fromkeys(soak.COUNTS, 0)
        totals.update(attempted=10, accepted=2, rejected=8, expected_matches=1)
        return totals

    def test_deadline_one_inflight_bound_and_capacity_definite(self):
        totals = self.totals()
        totals['timeout_response_rejected'] = 8
        self.assertEqual(soak.reconcile(totals, {'408': 1}, final_metrics(3, 2)), (3, 1))
        with self.assertRaises(RuntimeError):
            soak.reconcile(totals, {'408': 1}, final_metrics(4, 2))
        totals['timeout_response_rejected'] = 0
        totals['confirmed_capacity_rejected'] = 8
        with self.assertRaises(RuntimeError):
            soak.reconcile(totals, {'429': 1}, final_metrics(3, 1))

    def test_transport_uncertain_still_requires_exact_wal_storage_rules(self):
        totals = self.totals()
        totals.update(attempted=14, transport_uncertain=4)
        self.assertEqual(soak.reconcile(totals, {}, final_metrics(6, 1)), (6, 4))
        for changed in ('signal_storage_persisted_total', 'signal_rules_evaluated_total', 'signal_rules_failures_total', 'signal_events_dropped_total'):
            row = final_metrics(6, 1)
            row[changed] += 1
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                soak.reconcile(totals, {}, row)

    def test_invalid_status_and_counts_fail_before_accounting(self):
        rows = [soak.pipeline.event(1024, index) for index in range(10)]
        for status, accepted, rejected in ((500, 2, 8), (202, True, 9), (202, -1, 11), (202, 2, 7)):
            totals = dict.fromkeys(soak.COUNTS, 0)
            with self.subTest(status=status, accepted=accepted), self.assertRaises(RuntimeError):
                soak.account_response(totals, {}, rows, status, json.dumps({'accepted': accepted, 'rejected': rejected}))
            self.assertEqual(totals['accepted'], 0)
        for size in (1024, 4096):
            self.assertEqual(len(json.dumps(soak.pipeline.event(size, 1), separators=(',', ':')).encode()), size)


class QueryDiagnostics(unittest.TestCase):
    def test_http_status_retained_with_bounded_error_body(self):
        with mock.patch.object(soak.pipeline, 'request', return_value=(413, b'x' * 10000)):
            with self.assertRaises(soak.QueryFailure) as raised:
                soak.checked_query('', '/v1/events', 'events', 100)
        diagnostic = raised.exception.diagnostic
        self.assertEqual(diagnostic['kind'], 'http_status')
        self.assertEqual(diagnostic['status'], 413)
        self.assertEqual(len(diagnostic['response_preview']), 2048)

    def test_success_count_mismatch_and_malformed_shape_distinct(self):
        for body, kind in ((b'{"events": []}', 'row_count'), (b'{"events": {}}', 'response_shape'), (b'not-json', 'response_shape')):
            with self.subTest(kind=kind), mock.patch.object(soak.pipeline, 'request', return_value=(200, body)):
                with self.assertRaises(soak.QueryFailure) as raised:
                    soak.checked_query('', '/v1/events', 'events', 100)
                self.assertEqual(raised.exception.diagnostic['kind'], kind)
        with mock.patch.object(soak.pipeline, 'request', return_value=(200, b'{"events": []}')):
            self.assertGreaterEqual(soak.checked_query('', '/v1/events', 'events', 0), 0)

    def test_transport_error_is_bounded_and_distinct(self):
        with mock.patch.object(soak.pipeline, 'request', side_effect=OSError('x' * 10000)):
            with self.assertRaises(soak.QueryFailure) as raised:
                soak.checked_query('', '/v1/events', 'events', 100)
        self.assertEqual(raised.exception.diagnostic['kind'], 'transport')
        self.assertEqual(len(raised.exception.diagnostic['error']), 512)


class Ownership(unittest.TestCase):
    def test_profile_interrupt_cleans_owned_process_and_temp_preserves_unrelated(self):
        original = subprocess.Popen
        unrelated = original([sys.executable, '-c', 'import time; time.sleep(30)'])
        owned, folders = [], []
        def spawn(*args, **kwargs):
            process = original([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
            owned.append(process)
            folders.append(Path(kwargs['env']['SIGNAL_CONFIG']).parent)
            return process
        try:
            with mock.patch.object(soak.subprocess, 'Popen', spawn), mock.patch.object(soak.pipeline, 'port', side_effect=(20000, 20001)), mock.patch.object(soak.pipeline, 'request', side_effect=KeyboardInterrupt('cancel readiness')):
                with self.assertRaisesRegex(KeyboardInterrupt, 'cancel readiness'):
                    soak.profile(Path('/unused'), 1024, 10, 100)
            self.assertFalse(Path(f'/proc/{owned[0].pid}').exists())
            self.assertFalse(folders[0].exists())
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.kill()
            unrelated.wait(timeout=2)

    def test_signal_during_spawn_waits_for_registered_cleanup(self):
        original = subprocess.Popen
        owned = []
        def spawn(*args, **kwargs):
            process = original([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
            owned.append(process)
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        prior = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(soak.subprocess, 'Popen', spawn), mock.patch.object(soak.pipeline, 'port', side_effect=(20000, 20001)):
            with self.assertRaisesRegex(KeyboardInterrupt, 'during spawn'):
                soak.profile(Path('/unused'), 1024, 10, 100)
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior)
        self.assertFalse(Path(f'/proc/{owned[0].pid}').exists())

    def test_second_interrupt_in_shutdown_still_kills_and_reaps(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        original_wait = process.wait
        waits = 0
        def wait(*args, **kwargs):
            nonlocal waits
            waits += 1
            if waits == 1:
                raise KeyboardInterrupt('repeat interruption')
            return original_wait(*args, **kwargs)
        with mock.patch.object(process, 'wait', side_effect=wait):
            with self.assertRaisesRegex(KeyboardInterrupt, 'repeat interruption'):
                soak.stop_process(process)
        self.assertFalse(Path(f'/proc/{process.pid}').exists())


if __name__ == '__main__':
    unittest.main()

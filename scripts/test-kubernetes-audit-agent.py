#!/usr/bin/env python3
"""Failure regressions for audit-agent acceptance; optional actual drift rejection."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('audit_agent_gate', Path(__file__).with_name('check-kubernetes-audit-agent.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
OPTIONS = None


class AuditAgentGateTests(unittest.TestCase):
    def test_wal_checkpoint_refuses_corrupt_crc_and_nonzero_drops(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checkpoint'
            def write(sequence, dropped):
                raw = b'SIGACK01' + sequence.to_bytes(8, 'little') + dropped.to_bytes(8, 'little')
                path.write_bytes(raw + zlib.crc32(raw).to_bytes(4, 'little'))
            write(8, 0)
            self.assertEqual(GATE.wal_checkpoint(path), 8)
            write(8, 1)
            with self.assertRaises(ValueError):
                GATE.wal_checkpoint(path)
            path.write_bytes(b'SIGACK01' + b'\0' * 20)
            with self.assertRaises(ValueError):
                GATE.wal_checkpoint(path)

    def test_proxy_construction_failure_stops_owned_server_and_reports_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'target', prefix='audit-agent-cleanup-') as directory:
            base = Path(directory)
            capture = base / 'capture'
            capture.mkdir()
            (capture / 'audit.log').write_text('{}\n')
            policy = 'a' * 64
            (capture / 'report.json').write_text(json.dumps({'status': 'passed_local', 'owned_cleanup': True,
                'capture_sha256': hashlib.sha256(b'{}\n').hexdigest(), 'policy_sha256': policy}))
            (capture / 'capture.json').write_text(json.dumps({'cluster': 'fixture', 'policy_revision': policy,
                'cases': [{'raw_utf8': '{}'}] * 6}))
            class Process:
                returncode = None
                def poll(self): return self.returncode
            owned = Process()
            def stop(process): process.returncode = 0
            args = argparse.Namespace(output=base / 'result', capture=capture, agent=base/'agent', server=base/'server')
            with patch.object(GATE, 'source_hashes', return_value={}), \
                 patch.object(GATE.PIPE, 'start', return_value=(owned, '127.0.0.1:1')), \
                 patch.object(GATE.PIPE, 'stop', side_effect=stop) as stopper, \
                 patch.object(GATE, 'HTTPServer', side_effect=OSError('injected bind failure')):
                with self.assertRaises(OSError):
                    GATE.run(args)
                stopper.assert_called_once_with(owned)
            report = json.loads((args.output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertTrue(report['owned_cleanup'])

    def test_actual_source_drift_never_publishes_passing_acceptance(self):
        if OPTIONS.agent is None or OPTIONS.server is None:
            self.skipTest('requires explicit current agent/server binaries for actual source-drift campaign')
        identity = GATE.source_hashes()
        output = OPTIONS.output / ('source-drift-' + str(time.time_ns()))
        args = argparse.Namespace(output=output, capture=OPTIONS.capture, agent=OPTIONS.agent, server=OPTIONS.server)
        with patch.object(GATE, 'source_hashes', side_effect=[identity, {**identity, 'injected-drift': 'changed'}]):
            with self.assertRaisesRegex(ValueError, 'source drift'):
                GATE.run(args)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertTrue(report['owned_cleanup'])
        self.assertEqual(report['wal_checkpoint'], 8)
        self.assertTrue(report['original_finding_bytes_preserved'])
        print(json.dumps({'source_drift_rejected': True, 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--capture', type=Path, default=ROOT / 'target/kubernetes-audit-capture-20261024/capture-01')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/kubernetes-audit-agent-failures')
    OPTIONS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining])

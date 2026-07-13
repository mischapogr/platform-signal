#!/usr/bin/env python3
"""Meaningful bounded oracle and failure-path tests; no Docker/IdP needed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import time
import signal
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('audit_idp_composition', ROOT / 'scripts/check-audit-idp-composition.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def record(sequence=1, actor=None, completion=False, operation_id=None):
    return {'schema_version': 1, 'record_id': str(uuid.uuid4()), 'producer_id': str(uuid.UUID(int=42)),
        'sequence': sequence, 'timestamp': '2026-10-09T12:00:00Z',
        'actor': actor or {'kind': 'verified_subject', 'key': 'a' * 64},
        'action': dict(kind='operation_completion' if completion else 'access_decision',
            operation='query_events', operation_id=operation_id or str(uuid.UUID(int=100)),
            **({'completion': 'success'} if completion else {'decision': 'granted'}))}


def frame(control, row):
    body = json.dumps(row).encode()
    first = b'AUD1' + struct.pack('<I', len(body)) + hashlib.sha256(
        b'platform-signal/audit-receiver-frame/v1\0' + control + body).digest()
    return first + hashlib.sha256(b'platform-signal/audit-receiver-header/v1\0' + control + first).digest() + body


class CompositionFailures(unittest.TestCase):
    def test_actor_oracle_frames_distinct_issuer_subject_pairs(self):
        self.assertNotEqual(GATE.actor_key('ab', 'c'), GATE.actor_key('a', 'bc'))
        self.assertEqual(GATE.actor_key('issuer', 'subject'), hashlib.sha256(
            b'signal.audit.subject.v1\0' + (6).to_bytes(8, 'big') + b'issuer' +
            (7).to_bytes(8, 'big') + b'subject').hexdigest())

    def test_authenticated_journal_rejects_header_length_body_and_identity_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = b'SIGAUD01' + uuid.uuid4().bytes + bytes(8)
            (root / 'control').write_bytes(control)
            raw = frame(control, record())
            (root / 'journal').write_bytes(raw)
            self.assertEqual(len(GATE.journal(root)), 1)
            for index in (4, 8, 40, 80):
                changed = bytearray(raw); changed[index] ^= 1
                (root / 'journal').write_bytes(changed)
                with self.assertRaises(AssertionError):
                    GATE.journal(root)
            (root / 'journal').write_bytes(raw[:-1])
            with self.assertRaises(AssertionError):
                GATE.journal(root)
            (root / 'journal').write_bytes(raw)
            (root / 'control').write_bytes(b'SIGAUD01' + uuid.uuid4().bytes + bytes(8))
            with self.assertRaises(AssertionError):
                GATE.journal(root)

    def test_count_and_status_cannot_substitute_actor_pair_or_operation(self):
        rows = [{'record': record()}, {'record': record(2, completion=True)}]
        producer = rows[0]['record']['producer_id']
        GATE.check_pair(rows, 0, producer, 'query_events', rows[0]['record']['actor'], 'granted', 'success')
        rows[1]['record']['actor'] = {'kind': 'bootstrap'}
        with self.assertRaises(AssertionError):
            GATE.check_pair(rows, 0, producer, 'query_events', rows[0]['record']['actor'], 'granted', 'success')
        rows[1]['record']['actor'] = rows[0]['record']['actor']
        rows[1]['record']['action']['operation_id'] = str(uuid.uuid4())
        with self.assertRaises(AssertionError):
            GATE.check_pair(rows, 0, producer, 'query_events', rows[0]['record']['actor'], 'granted', 'success')

    def test_phase_denies_stale_generation_index_unknown_and_freeform_payload(self):
        value = {'generation': 'current', 'index': 1, 'phase': 'ingested', 'result': {'status': 202}}
        self.assertEqual(GATE.validate_phase(json.dumps(value).encode(), 'current', 1), value)
        for changed in [dict(value, generation='stale'), dict(value, index=2), dict(value, phase='arbitrary'),
                        dict(value, result={'status': 202, 'token': 'synthetic-private'})]:
            with self.assertRaises(AssertionError):
                GATE.validate_phase(json.dumps(changed).encode(), 'current', 1)
        with self.assertRaises(ValueError):
            GATE.validate_phase(b'{"generation":"current","generation":"current"}', 'current', 0)

    def test_cleanup_attempts_both_owners_and_records_late_drain_error(self):
        run = GATE.Run.__new__(GATE.Run)
        run.cleanup_errors = []
        run.roles = mock.Mock()
        run.roles.cleanup.side_effect = RuntimeError('first owner failure')
        run.idp = mock.Mock()
        run.idp.cleanup_errors = []
        run.idp.owner.check.side_effect = RuntimeError('late drain')
        run.cleanup()
        run.idp.cleanup.assert_called_once()
        self.assertEqual(len(run.cleanup_errors), 2)

    def test_late_drain_and_source_drift_cannot_report_pass(self):
        saved = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM)}
        try:
            for late_error, drift in ((True, False), (False, True)):
                with tempfile.TemporaryDirectory() as tmp:
                    output = Path(tmp) / 'out'; output.mkdir()
                    scratch = Path(tmp) / 'private'; scratch.mkdir()
                    run = mock.Mock()
                    run.output, run.scratch = output, scratch
                    run.cleanup_errors, run.token_digests, run.checks, run.secrets = [], [], [], []
                    run.stage, run.started = 'final', time.monotonic()
                    run.idp.name, run.idp.generation = 'synthetic-owned', 'synthetic-generation'
                    run.logs.return_value = b''
                    run.execute.return_value = {}
                    if late_error:
                        run.cleanup.side_effect = lambda: run.cleanup_errors.append('late drain')
                    before = {'public': 'a'}
                    after = {'public': 'b'} if drift else before
                    provenance = json.dumps({'binary_sha256': GATE.BINARY_SHA, 'source_sha256': {}}).encode()
                    with (mock.patch.object(GATE, 'Run', return_value=run),
                          mock.patch.object(GATE, 'source_inventory', side_effect=[before, after]),
                          mock.patch.object(GATE, 'bounded_read', return_value=provenance),
                          mock.patch.object(GATE, 'digest', return_value=GATE.BINARY_SHA)):
                        self.assertEqual(GATE.main(['--output', str(output)]), 1)
                    report = json.loads((output / 'report.json').read_text())
                    self.assertEqual(report['status'], 'failed')
                    self.assertEqual(report['source_drift'], drift)
                    if late_error:
                        self.assertTrue(scratch.exists())
                    else:
                        self.assertFalse(scratch.exists())
        finally:
            for kind, handler in saved.items():
                signal.signal(kind, handler)

    def test_health_strict_types_capacity_and_observation_distinction(self):
        value = {key: 0 for key in GATE.HEALTH_FIELDS}
        value.update(schema_version=1, held=False, record_capacity=64, byte_capacity=131072,
                     physical_capacity=1, append_http_capacity=1)
        headers = [('Cache-Control', 'no-store'), ('Content-Type', 'application/json')]
        self.assertEqual(GATE.validate_health(200, json.dumps(value).encode(), headers), value)
        for key, invalid in [('schema_version', True), ('schema_version', 1.0), ('records', True),
                             ('records', 65), ('bytes', 131073), ('record_capacity', 0),
                             ('record_capacity', 16385), ('byte_capacity', 4167),
                             ('byte_capacity', 67108865), ('physical_capacity', 2),
                             ('physical_depth', 2), ('append_http_depth', 2),
                             ('append_http_capacity', 0), ('rejected', -1), ('uncertain', 2**64)]:
            with self.subTest(key=key, invalid=invalid), self.assertRaises(AssertionError):
                GATE.validate_health(200, json.dumps(dict(value, **{key: invalid})).encode(), headers)
        full = dict(value, records=64, physical_depth=1)
        self.assertEqual(GATE.validate_health(200, json.dumps(full).encode(), headers), full)
        with self.assertRaises(AssertionError):
            GATE.validate_health(503, json.dumps(value).encode(), headers)
        with self.assertRaises(AssertionError):
            GATE.validate_health(200, json.dumps(list(value.values())).encode(), headers)

    def test_journal_rejects_numeric_bool_and_float_schema_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control = b'SIGAUD01' + uuid.uuid4().bytes + bytes(8)
            (root / 'control').write_bytes(control)
            for key, invalid in [('schema_version', True), ('schema_version', 1.0),
                                 ('sequence', True), ('sequence', 1.0)]:
                row = record(); row[key] = invalid
                (root / 'journal').write_bytes(frame(control, row))
                with self.assertRaises(AssertionError):
                    GATE.journal(root)

    def test_inventory_traversal_is_incremental_and_denies_cycles_external_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'apps').mkdir(); source = root / 'crates/pkg/src'; source.mkdir(parents=True)
            (source.parent / 'Cargo.toml').write_text('[package]\nname="synthetic"\n')
            for index in range(300):
                (source / (str(index) + '.rs')).write_text('// synthetic')
            count = 0
            original = GATE.os.scandir
            class Counted:
                def __init__(self, path):
                    self.iterator = original(path)
                def __enter__(self):
                    self.iterator.__enter__(); return self
                def __exit__(self, *args):
                    return self.iterator.__exit__(*args)
                def __iter__(self):
                    return self
                def __next__(self):
                    nonlocal count
                    value = next(self.iterator); count += 1; return value
            with mock.patch.object(GATE.os, 'scandir', Counted), mock.patch.object(
                    Path, 'glob', side_effect=AssertionError('whole glob must not enumerate')):
                with self.assertRaises(AssertionError):
                    GATE.source_inventory(root, extras=())
            self.assertLessEqual(count, 259)
            for path in source.iterdir():
                path.unlink()
            source.rmdir(); source.symlink_to('src')
            with self.assertRaises(AssertionError):
                GATE.source_inventory(root, extras=())
            source.unlink(); source.symlink_to(Path(tmp).parent)
            with self.assertRaises(AssertionError):
                GATE.source_inventory(root, extras=())

    def test_inventory_checks_selected_file_cap_before_hashing_or_insertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'apps').mkdir(); source = root / 'crates/pkg/src'; source.mkdir(parents=True)
            (source.parent / 'Cargo.toml').write_text('[package]')
            for directory in range(3):
                folder = source / str(directory); folder.mkdir()
                for index in range(180):
                    (folder / (str(index) + '.rs')).write_text('// synthetic')
            with mock.patch.object(GATE, 'digest', return_value='bounded') as hashed:
                with self.assertRaises(AssertionError):
                    GATE.source_inventory(root, extras=())
            self.assertEqual(hashed.call_count, 512)

    def test_file_and_log_bounds_before_whole_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'large'; path.write_bytes(b'x' * 100)
            with self.assertRaises(ValueError):
                GATE.bounded_read(path, 64)
            with self.assertRaises(ValueError):
                GATE.digest(path, 64)
            run = GATE.Run.__new__(GATE.Run)
            run.idp = mock.Mock(); run.idp.owner.logs = [path] * 9
            run.roles = mock.Mock(); run.roles.logs = []
            with mock.patch.object(GATE, 'bounded_read', return_value=b'x' * 1048576):
                with self.assertRaises(AssertionError):
                    run.logs()


if __name__ == '__main__':
    unittest.main()

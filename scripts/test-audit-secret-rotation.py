#!/usr/bin/env python3
"""Bounded negative/original-byte checks for the native rotation fixture."""
import contextlib
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('secret_rotation', ROOT / 'scripts/check-audit-secret-rotation.py')
GATE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(GATE)


def fixture(control):
    row = {'schema_version': 1, 'record_id': str(uuid.uuid4()), 'producer_id': str(uuid.UUID(int=42)), 'sequence': 1}
    body = json.dumps(row).encode()
    head = b'AUD1' + struct.pack('<I', len(body)) + hashlib.sha256(
        b'platform-signal/audit-receiver-frame/v1\0' + control + body).digest()
    return head + hashlib.sha256(b'platform-signal/audit-receiver-header/v1\0' + control + head).digest() + body


class RotationFailures(unittest.TestCase):
    def test_provider_failure_missing_invalid_cannot_spawn_or_mutate_environment(self):
        before = dict(os.environ)
        for provider in [GATE.Delivery({}, False), GATE.Delivery({}),
                         GATE.Delivery({'TOKEN': ''}), GATE.Delivery({'TOKEN': 'x' * 513}),
                         GATE.Delivery({'TOKEN': 'has space'}), GATE.Delivery({'TOKEN': 42})]:
            spawn = mock.Mock()
            with self.assertRaises((AssertionError, ValueError)):
                provider.launch(spawn, ['binary'], {'TOKEN': 'valid-fallback'}, ['TOKEN'], 'blocked')
            spawn.assert_not_called()
        self.assertEqual(before, dict(os.environ))

    def test_child_delivery_is_captured_not_hot_referenced(self):
        provider = GATE.Delivery({'TOKEN': 'old'})
        spawn = mock.Mock()
        provider.launch(spawn, ['binary'], {}, ['TOKEN'], 'owner')
        captured = spawn.call_args.args[1]
        provider.values['TOKEN'] = 'new'
        self.assertEqual(captured['TOKEN'], 'old')
        self.assertEqual(provider.capture(['TOKEN'])['TOKEN'], 'new')

    def test_private_input_rejects_capacity_symlink_fifo_and_changed_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / 'file'; path.write_bytes(b'original')
            self.assertEqual(GATE.consume(path, 8, True), b'original')
            with self.assertRaises(AssertionError):
                GATE.consume(path, 7, True)
            (root / 'symlink').symlink_to(path)
            with self.assertRaises(AssertionError):
                GATE.consume(root / 'symlink', 20)
            os.mkfifo(root / 'fifo')
            with self.assertRaises(AssertionError):
                GATE.consume(root / 'fifo', 20)
            real = os.fstat
            calls = 0
            def change(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.write_bytes(b'mutated!!')
                return real(descriptor)
            with mock.patch.object(GATE.os, 'fstat', side_effect=change):
                with self.assertRaises(AssertionError):
                    GATE.consume(path, 20, True)

    def test_journal_checks_original_header_body_and_store_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); control = b'SIGAUD01' + uuid.uuid4().bytes + bytes(8)
            (root / 'control').write_bytes(control); raw = fixture(control)
            (root / 'journal').write_bytes(raw)
            self.assertEqual(len(GATE.journal(root)), 1)
            for position in (4, 8, 40, 75):
                changed = bytearray(raw); changed[position] ^= 1
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

    def test_snapshot_denies_unknown_entries_and_preserves_private_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'source'; source.mkdir(); (source / 'state').write_bytes(b'original')
            GATE.snapshot(source, root / 'copy', ('state',))
            self.assertEqual((root / 'copy/state').read_bytes(), b'original')
            self.assertEqual((root / 'copy/state').stat().st_mode & 0o777, 0o600)
            (source / 'secret').write_bytes(b'old-private-credential')
            with self.assertRaises(AssertionError):
                GATE.snapshot(source, root / 'bad-copy', ('state',))
            self.assertFalse((root / 'bad-copy').exists())

    def test_pair_counts_do_not_substitute_actor_action_or_fresh_identity(self):
        operation = str(uuid.uuid4()); producer = str(uuid.UUID(int=42))
        first = {'producer_id': producer, 'actor': {'kind': 'bootstrap'}, 'action': {
            'kind': 'access_decision', 'operation': 'query_events', 'operation_id': operation, 'decision': 'granted'}}
        second = {'producer_id': producer, 'actor': {'kind': 'bootstrap'}, 'action': {
            'kind': 'operation_completion', 'operation': 'query_events', 'operation_id': operation, 'completion': 'success'}}
        rows = [{'record': first}, {'record': second}]
        GATE.validate_pair(rows, 0, producer)
        for field, value in [('kind', 'access_decision'), ('completion', 'uncertain'),
                             ('operation_id', str(uuid.uuid4())), ('operation', 'ingest_events')]:
            original = second['action'][field]; second['action'][field] = value
            with self.assertRaises(AssertionError):
                GATE.validate_pair(rows, 0, producer)
            second['action'][field] = original
        second['actor'] = {'kind': 'anonymous'}
        with self.assertRaises(AssertionError):
            GATE.validate_pair(rows, 0, producer)

    def test_late_owner_drain_failure_cannot_report_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); output = root / 'output'; output.mkdir(); (output / 'run').mkdir()
            private = root / 'private'; private.mkdir()
            campaign = GATE.Campaign.__new__(GATE.Campaign)
            campaign.output, campaign.stage = output, 'final'
            campaign.checks, campaign.cleanup_errors, campaign.rows = [], [], []
            campaign.hashes = {p: 'same' for p in GATE.HELPERS}
            campaign.binary, campaign.binary_hash = Path('binary'), 'same'
            owner = mock.Mock(); owner.cleanup.return_value = []; owner.check.side_effect = RuntimeError('late drain')
            campaign.run = mock.Mock(); campaign.run.owners = [owner]; campaign.run.private = private
            with mock.patch.object(GATE, 'consume', return_value='same'), contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(campaign.finish(None, GATE.time.monotonic()))
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['cleanup_errors'], ['RuntimeError'])
            self.assertFalse(private.exists())

    def test_provenance_requires_exact_six_known_keys_and_strict_digests(self):
        digest = hashlib.sha256(b'accepted').hexdigest()
        valid = {'binary_sha256': GATE.BINARY_SHA, 'source_sha256': {p: digest for p in GATE.PROVENANCE_KEYS}}
        GATE.validate_provenance(valid, lambda _: b'accepted')
        for sources in [{}, dict(list(valid['source_sha256'].items())[1:]),
                        dict(valid['source_sha256'], unknown=digest), None, [],
                        {p: 42 for p in GATE.PROVENANCE_KEYS}, {p: None for p in GATE.PROVENANCE_KEYS},
                        {p: 'A' * 64 for p in GATE.PROVENANCE_KEYS}, {p: 'x' * 63 for p in GATE.PROVENANCE_KEYS}]:
            read = mock.Mock(return_value=b'accepted')
            with self.assertRaises(AssertionError):
                GATE.validate_provenance(dict(valid, source_sha256=sources), read)
            read.assert_not_called()
        with self.assertRaises(AssertionError):
            GATE.validate_provenance(valid, lambda _: b'changed')

    def test_late_provenance_metadata_drift_cannot_report_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            campaign = GATE.Campaign.__new__(GATE.Campaign)
            campaign.output, campaign.stage = output, 'final'
            campaign.checks, campaign.cleanup_errors, campaign.rows = [], [], []
            campaign.hashes = {p: 'same' for p in GATE.HELPERS}
            campaign.binary, campaign.binary_hash = Path('binary'), 'same'
            def consumed(path, *_):
                return 'changed' if path == GATE.ROOT / GATE.METADATA_PATH else 'same'
            with mock.patch.object(GATE, 'consume', side_effect=consumed), contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(campaign.finish(None, GATE.time.monotonic()))
            report = json.loads((output / 'report.json').read_text())
            self.assertTrue(report['binary_metadata_drift'])
            self.assertTrue(report['helper_source_drift'])
            self.assertFalse(report['binary_drift'])
            self.assertEqual(report['status'], 'failed')

    def test_duplicate_private_fields_are_not_silently_collapsed(self):
        with self.assertRaises(ValueError):
            GATE.strict_json(b'{"sequence":1,"sequence":2}')


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Guard original WAL preservation across synthetic Kubernetes fixture restarts."""
import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest
import uuid

SPEC = importlib.util.spec_from_file_location('standard_fixture', Path(__file__).parent / 'fixtures/standard-kubernetes.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OriginalStateTests(unittest.TestCase):
    def document(self):
        return {'identity': {'backend': str(uuid.uuid4()), 'stream': str(uuid.uuid4())},
                'files': {'wal/checkpoint': base64.b64encode(b'original-floor-zero').decode()}}

    def test_replacement_preserves_advanced_wal_and_refuses_foreign_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self.document()
            MODULE.initialize(root, document)
            self.assertEqual((root / 'wal').stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / 'wal/checkpoint').stat().st_mode & 0o777, 0o600)
            (root / 'wal/checkpoint').write_bytes(b'advanced-floor-two')
            MODULE.initialize(root, document)
            self.assertEqual((root / 'wal/checkpoint').read_bytes(), b'advanced-floor-two')
            with self.assertRaisesRegex(ValueError, 'ownership mismatch'):
                MODULE.initialize(root, self.document())
            self.assertEqual((root / 'wal/checkpoint').read_bytes(), b'advanced-floor-two')

    def test_invalid_paths_and_capacity_fail_before_state_changes(self):
        for name in ('../escape', '/tmp/escape', 'wal/../../escape', 'events/body'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                document = self.document()
                document['files'][name] = base64.b64encode(b'invalid').decode()
                with self.assertRaisesRegex(ValueError, 'outside owned state'):
                    MODULE.initialize(Path(directory), document)
                self.assertEqual(list(Path(directory).iterdir()), [])
        with tempfile.TemporaryDirectory() as directory:
            document = self.document()
            document['files'] = {f'wal/{i}': '' for i in range(65)}
            with self.assertRaisesRegex(ValueError, 'capacity'):
                MODULE.initialize(Path(directory), document)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Checkpoint publication-race and corruption guards for the bounded fixture."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zlib

SPEC = importlib.util.spec_from_file_location('baseline_gate', Path(__file__).with_name('check-baseline-pack.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class Tests(unittest.TestCase):
    def test_absent_checkpoint_is_not_yet_published_and_corruption_never_qualifies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checkpoint'
            self.assertFalse(GATE.checkpoint(path))
            payload = b'SIGACK01'+(15).to_bytes(8, 'little')+(0).to_bytes(8, 'little')
            valid = payload+zlib.crc32(payload).to_bytes(4, 'little')
            path.write_bytes(valid)
            self.assertTrue(GATE.checkpoint(path))
            for invalid in [valid[:-1], valid+b'x', b'x'+valid[1:]]:
                path.write_bytes(invalid)
                self.assertFalse(GATE.checkpoint(path))
            dropped = payload[:16]+(1).to_bytes(8, 'little')
            path.write_bytes(dropped+zlib.crc32(dropped).to_bytes(4, 'little'))
            self.assertFalse(GATE.checkpoint(path))

    def test_duplicate_manifest_keys_refuse(self):
        with self.assertRaises(ValueError):
            GATE.pairs_unique([('schema_version', 1), ('schema_version', 1)])


if __name__ == '__main__':
    unittest.main()

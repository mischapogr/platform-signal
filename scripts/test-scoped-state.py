#!/usr/bin/env python3
"""Refuse ambiguous, foreign-architecture and unowned process-gate inputs."""
import importlib.util
import json
import platform
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('scoped_gate', Path(__file__).with_name('check-scoped-state.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class Tests(unittest.TestCase):
    def artifact(self, directory, machine=None):
        binary = directory / 'test-elf'
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = (machine or {'x86_64': 62, 'aarch64': 183}[platform.machine()]).to_bytes(2, 'little')
        binary.write_bytes(header)
        binary.chmod(0o700)
        row = {'reason': 'compiler-artifact', 'target': {'name': 'scoped-state', 'kind': ['test'],
               'src_path': str(GATE.ROOT / 'crates/signal-rules/tests/scoped-state.rs')},
               'profile': {'test': True}, 'executable': str(binary), 'features': []}
        artifacts = directory / 'artifacts.jsonl'
        artifacts.write_text(json.dumps(row)+'\n')
        return binary, artifacts, row

    def test_exact_artifact_selection_and_duplicate_refusal(self):
        with tempfile.TemporaryDirectory(dir=GATE.TARGET) as directory:
            binary, artifacts, row = self.artifact(Path(directory))
            self.assertEqual(GATE.executable(artifacts), (binary, []))
            artifacts.write_text((json.dumps(row)+'\n')*2)
            with self.assertRaises(ValueError):
                GATE.executable(artifacts)
            row['target']['src_path'] = str(GATE.ROOT / 'apps/signal-server/tests/scoped-state.rs')
            artifacts.write_text(json.dumps(row)+'\n')
            with self.assertRaises(ValueError):
                GATE.executable(artifacts)

    def test_foreign_machine_and_truncated_header_refuse(self):
        with tempfile.TemporaryDirectory(dir=GATE.TARGET) as directory:
            binary, artifacts, _ = self.artifact(Path(directory), machine=40)
            with self.assertRaises(ValueError):
                GATE.executable(artifacts)
            binary.write_bytes(b'\x7fELF\x02')
            with self.assertRaises(ValueError):
                GATE.executable(artifacts)

    def test_source_inventory_and_ownership(self):
        with tempfile.TemporaryDirectory(dir=GATE.TARGET) as directory:
            spec = Path(directory) / 'spec.json'
            spec.write_text(json.dumps({'owned_paths': ['Cargo.toml'], 'contracts': []}))
            self.assertIn('Cargo.lock', GATE.sources(spec))
            spec.write_text(json.dumps({'owned_paths': ['../outside'], 'contracts': []}))
            with self.assertRaises(ValueError):
                GATE.sources(spec)
            with self.assertRaises(ValueError):
                GATE.owned(GATE.ROOT / 'Cargo.toml')


if __name__ == '__main__':
    unittest.main()

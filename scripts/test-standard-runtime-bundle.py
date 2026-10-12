#!/usr/bin/env python3
"""Reject wrong-source, wrong-architecture and damaged transferred executables."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('runtime_bundle', Path(__file__).with_name('standard-runtime-bundle.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BundleTests(unittest.TestCase):
    def fixture(self, root):
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = (62).to_bytes(2, 'little')
        executables = {}
        for name in ('server', 'offline-fixture'):
            path = root / name
            path.write_bytes(header + name.encode())
            path.chmod(0o644)
            executables[name] = {'sha256': MODULE.digest(path), 'bytes': path.stat().st_size}
        manifest = {'schema_version': 1, 'source_revision': 'a' * 40, 'architecture': 'amd64',
                    'source_inputs': {'source.rs': 'b' * 64}, 'executables': executables}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return manifest

    def test_artifact_permissions_restored_only_after_all_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.fixture(root)
            (root / 'offline-fixture').write_bytes(b'not the original ELF')
            with self.assertRaises(ValueError):
                MODULE.verify(root, 'a' * 40, 'amd64', manifest['source_inputs'])
            self.assertEqual((root / 'server').stat().st_mode & 0o777, 0o644)
            self.fixture(root)
            MODULE.verify(root, 'a' * 40, 'amd64', manifest['source_inputs'])
            for name in ('server', 'offline-fixture'):
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o700)

    def test_revision_architecture_and_source_drift_refused(self):
        for revision, arch, inputs in [('c' * 40, 'amd64', {'source.rs': 'b' * 64}),
                                       ('a' * 40, 'arm64', {'source.rs': 'b' * 64}),
                                       ('a' * 40, 'amd64', {'source.rs': 'd' * 64})]:
            with self.subTest(arch=arch, inputs=inputs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                with self.assertRaisesRegex(ValueError, 'source mismatch'):
                    MODULE.verify(root, revision, arch, inputs)

    def test_changed_hash_size_and_missing_bindings_refused(self):
        for mutation in ('hash', 'size', 'missing'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = self.fixture(root)
                if mutation == 'hash':
                    manifest['executables']['server']['sha256'] = 'd' * 64
                elif mutation == 'size':
                    manifest['executables']['server']['bytes'] += 1
                else:
                    del manifest['executables']['offline-fixture']
                (root / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    MODULE.verify(root, 'a' * 40, 'amd64', manifest['source_inputs'])

    def test_elf_architecture_symlinks_and_extra_files_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'ELF architecture'):
                MODULE.executable(root / 'server', 'arm64')
            (root / 'server').unlink()
            (root / 'server').symlink_to(root / 'offline-fixture')
            with self.assertRaisesRegex(ValueError, 'regular file'):
                MODULE.verify(root, 'a' * 40, 'amd64', manifest['source_inputs'])
            (root / 'server').unlink()
            self.fixture(root)
            (root / 'unexpected').write_text('extra')
            with self.assertRaisesRegex(ValueError, 'unexpected'):
                MODULE.verify(root, 'a' * 40, 'amd64', manifest['source_inputs'])


if __name__ == '__main__':
    unittest.main()

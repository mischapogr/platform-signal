#!/usr/bin/env python3
"""Adversarial offline candidate identity, archive bounds and process ownership tests."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('prepare-local-candidate.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def write(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    return path


def image_tar(path, label='original'):
    # Legitimate runtime layer symlinks are opaque payload, never extracted.
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
        info = tarfile.TarInfo('usr/bin/runtime-link')
        info.type, info.linkname = tarfile.SYMTYPE, '../lib/runtime'
        bundle.addfile(info)
        info = tarfile.TarInfo('usr/lib/runtime')
        raw = label.encode()
        info.size = len(raw)
        bundle.addfile(info, io.BytesIO(raw))
    raw_layer = layer.getvalue()
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers',
                         'diff_ids': ['sha256:' + hashlib.sha256(raw_layer).hexdigest()]}}).encode()
    image = 'sha256:' + hashlib.sha256(config).hexdigest()
    config_name = image[7:] + '.json'
    manifest = json.dumps([{'Config': config_name, 'RepoTags': ['example:local'], 'Layers': ['layer/layer.tar']}]).encode()
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as bundle:
        for name, raw in [(config_name, config), ('manifest.json', manifest), ('layer/layer.tar', raw_layer)]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            bundle.addfile(info, io.BytesIO(raw))
    return image


def fixture(root):
    workspace = '[workspace]\nmembers = ' + json.dumps(list(c.MEMBERS)) + '\n[workspace.package]\nversion = "' + c.VERSION + '"\n'
    write(root, 'Cargo.toml', workspace)
    for name in c.MEMBERS:
        write(root, name + '/Cargo.toml', '[package]\nname="' + name.split('/')[-1] + '"\nversion.workspace=true\npublish=false\n')
        write(root, name + '/src/lib.rs', '// reviewed fixture\n')
    for name in ('Cargo.lock', 'rust-toolchain.toml', 'LICENSE', 'benchmarks/harness.rs', 'benchmarks/pipeline.py',
                 'benchmarks/soak.py', 'rules/examples/login-failure.yaml', 'deploy/docker/healthcheck.rs',
                 'tests/integration/foundation.rs', 'README.md'):
        write(root, name, 'reviewed fixture\n')
    for name in c.CHART_FILES:
        write(root, 'deploy/helm/signal/' + name, 'fixture chart\n')
    for name in c.FIXTURE_FILES:
        write(root, name, '{}\n')
    image = image_tar(root / 'fixture-image.tar')
    snapshot_name = c.EVIDENCE_ROOTS[0] + '/source-snapshot.json'
    image_name = c.EVIDENCE_ROOTS[0] + '/image.json'
    origin_name = c.EVIDENCE_ROOTS[0] + '/extraction/origin.json'
    source = c.collect(root, tuple(c.TOP_FILES) + ('apps', 'crates', 'benchmarks', 'rules', 'deploy', 'tests/integration', 'tests/fixtures', 'schemas'), c.source_allowed)
    snapshot = {'files': {name: c.file_info(root / name, c.SOURCE_CAP) for name in source}}
    write(root, snapshot_name, json.dumps(snapshot))
    write(root, image_name, json.dumps({'image': {'id': image, 'os': 'linux', 'architecture': 'amd64'}}))
    write(root, origin_name, json.dumps({'image': {'id': image, 'os': 'linux', 'architecture': 'amd64'}, 'binary_sha256': 'b' * 64}))
    review_name = c.EVIDENCE_ROOTS[1] + '/accepted.json'
    review = {'schema_version': 1, 'status': 'accepted', 'unresolved_findings': [],
              'source_sha256': {'crates/signal-storage/src/lib.rs': c.file_info(root / 'crates/signal-storage/src/lib.rs', c.SOURCE_CAP)['sha256']},
              'artifact_sha256': {name: c.file_info(root / name, c.EVIDENCE_CAP)['sha256'] for name in (snapshot_name, image_name, origin_name)},
              'remaining_external_gates': ['native ARM64', 'EKS', 'remote CI', 'published dependencies']}
    return image, write(root, review_name, json.dumps(review))


def fake_docker(root):
    def run(command, record, **kwargs):
        record.append({'command': [str(value) for value in command], 'status': 'passed'})
        if command[1] == 'info':
            return json.dumps({'os': 'linux', 'architecture': 'x86_64'})
        if command[1:3] == ['image', 'inspect']:
            return json.dumps({'id': command[-1], 'os': 'linux', 'architecture': 'amd64', 'size': 109270326})
        if command[1:3] == ['image', 'save']:
            shutil.copyfile(root / 'fixture-image.tar', Path(command[command.index('--output') + 1]))
            return ''
        raise AssertionError(command)
    return run


def prepared(root):
    image, review = fixture(root)
    output = root / 'target/candidate'
    with mock.patch.object(c, 'run', side_effect=fake_docker(root)), mock.patch.object(c.platform, 'system', return_value='Linux'), mock.patch.object(c.platform, 'machine', return_value='x86_64'):
        c.prepare(image, review, output, root)
    return output


def rebuild_archive(output, name, transform):
    files = []
    with tarfile.open(output / name, 'r:gz') as bundle:
        for member in bundle:
            files.append((member, bundle.extractfile(member).read()))
    transform(files)
    (output / name).unlink()
    with (output / name).open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.USTAR_FORMAT) as bundle:
            for member, data in files:
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
    manifest = c.read_json(output / 'candidate.json')
    kind = manifest['artifacts'][name]['kind']
    cap = c.EVIDENCE_CAP if kind == 'evidence' else c.SOURCE_CAP
    summary = c.file_info(output / name, cap)
    summary.update(kind=kind, **c.archive_contents(output / name, kind, cap))
    manifest['artifacts'][name] = summary
    c.write_json(output / 'candidate.json', manifest)
    c.checksums(output)


class CandidateIntegrity(unittest.TestCase):
    def test_bound_docker_inspection_array_prepares_and_verifies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image, review_path = fixture(root)
            image_name = c.EVIDENCE_ROOTS[0] + '/image.json'
            write(root, image_name, json.dumps([{'Id': image, 'Os': 'linux', 'Architecture': 'amd64'}]))
            review = c.read_json(review_path)
            review['artifact_sha256'][image_name] = c.file_info(root / image_name, c.EVIDENCE_CAP)['sha256']
            c.write_json(review_path, review)
            output = root / 'target/inspection-array'
            with mock.patch.object(c, 'run', side_effect=fake_docker(root)), mock.patch.object(c.platform, 'system', return_value='Linux'), mock.patch.object(c.platform, 'machine', return_value='x86_64'):
                c.prepare(image, review_path, output, root)
            self.assertEqual(c.verify(output)['status'], 'verified')

    def test_ambiguous_or_invalid_image_report_fails_closed(self):
        for value in ([], [{}, {}], None, 'image', {}, {'image': []}):
            with self.assertRaises(RuntimeError):
                c.normalize_image_report(value)

    def test_current_fixture_allowlist_excludes_unreviewed_data(self):
        self.assertIn('crates/signal-coverage', c.MEMBERS)
        for name in c.FIXTURE_FILES | c.SAMPLE_FILES:
            self.assertTrue(c.source_allowed(name), name)
        for name in ('tests/fixtures/private.json', 'tests/fixtures/source-coverage/private.json',
                     'schemas/private.json', 'private/policy.json', 'examples/logs/company.json',
                     'examples/logs/credentials.log', 'examples/private/policy.json'):
            self.assertFalse(c.source_allowed(name), name)

    def test_ui_allowlist_is_exact_and_excludes_adjacent_assets(self):
        expected = {'apps/signal-server/ui/index.html', 'apps/signal-server/ui/app.js',
                    'apps/signal-server/ui/style.css'}
        self.assertEqual(c.UI_FILES, expected)
        for name in expected | c.UI_TEST_HELPERS:
            self.assertTrue(c.source_allowed(name), name)
        for name in ('apps/signal-server/ui/extra.js', 'apps/signal-server/ui/private.html',
                     'apps/signal-server/ui/nested/app.js', 'apps/signal-agent/ui/app.js',
                     'scripts/test-secops-ui-extra.cjs', 'scripts/secret.cjs',
                     'apps/signal-server/ui/.credentials', 'apps/signal-server/ui/app.js.bak'):
            self.assertFalse(c.source_allowed(name), name)

    def test_embedded_ui_and_exact_test_helpers_are_exported(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            for name in c.UI_FILES | c.UI_TEST_HELPERS:
                write(root, name, 'reviewed UI input\n')
            unwanted = {'apps/signal-server/ui/extra.js', 'scripts/private.cjs'}
            for name in unwanted:
                write(root, name, 'unreviewed adjacent input\n')
            names = c.collect(root, ('apps', 'scripts'), c.source_allowed)
            self.assertTrue((c.UI_FILES | c.UI_TEST_HELPERS) <= set(names))
            self.assertFalse(unwanted & set(names))
            output = root / 'ui-source.tar.gz'
            summary = c.archive(output, root, names, 'platform-signal/', 'source', c.SOURCE_CAP)
            verified = c.archive_contents(output, 'source', c.SOURCE_CAP)
            self.assertEqual(summary['files'], verified['files'])
            for name in c.UI_FILES | c.UI_TEST_HELPERS:
                self.assertIn('platform-signal/' + name, verified['files'])
            with tarfile.open(output, 'r:gz') as bundle:
                for name in c.UI_FILES:
                    self.assertEqual(bundle.extractfile('platform-signal/' + name).read(),
                                     b'reviewed UI input\n')

    def test_each_missing_embedded_ui_asset_fails_compile_time_closure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            includes = []
            for name in sorted(c.UI_FILES):
                write(root, name, 'reviewed UI input\n')
                includes.append('const INPUT' + str(len(includes)) + ': &str = include_str!("../ui/'
                                + Path(name).name + '");\n')
            write(root, 'apps/signal-server/src/ui.rs', ''.join(includes))
            names = c.collect(root, tuple(c.TOP_FILES) +
                              ('apps', 'crates', 'benchmarks', 'rules', 'deploy', 'tests', 'schemas'),
                              c.source_allowed)
            c.validate_workspace(names, lambda name: (root / name).read_text())
            for name in c.UI_FILES:
                with self.subTest(missing=name):
                    missing = [entry for entry in names if entry != name]
                    with self.assertRaisesRegex(RuntimeError, 'missing compile-time source input: ' + name):
                        c.validate_workspace(missing, lambda entry: (root / entry).read_text())

    def test_compile_time_fixture_missing_from_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            write(root, 'crates/signal-coverage/src/lib.rs',
                  'const INPUT: &[u8] = include_bytes!("../../../tests/fixtures/source-coverage/backend-vectors.json");\n')
            names = c.collect(root, tuple(c.TOP_FILES) + ('apps', 'crates', 'benchmarks', 'rules', 'deploy', 'tests', 'schemas'), c.source_allowed)
            c.validate_workspace(names, lambda name: (root / name).read_text())
            names.remove('tests/fixtures/source-coverage/backend-vectors.json')
            with self.assertRaisesRegex(RuntimeError, 'missing compile-time source input'):
                c.validate_workspace(names, lambda name: (root / name).read_text())

    def test_historical_membership_supported_without_undeclared_current_crate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers = ' + json.dumps(list(c.LEGACY_MEMBERS)) + '\n[workspace.package]\nversion = "' + c.VERSION + '"\n')
            names = c.collect(root, tuple(c.TOP_FILES) + ('apps', 'crates', 'benchmarks', 'rules', 'deploy', 'tests', 'schemas'), c.source_allowed)
            with self.assertRaisesRegex(RuntimeError, 'undeclared workspace member'):
                c.validate_workspace(names, lambda name: (root / name).read_text())
            names = [name for name in names if not name.startswith('crates/signal-coverage/')]
            c.validate_workspace(names, lambda name: (root / name).read_text())

    def test_complete_offline_verification_and_reproducible_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = prepared(root)
            with mock.patch.object(c, 'run', side_effect=AssertionError('offline verifier called subprocess')):
                self.assertEqual(c.verify(output)['status'], 'verified')
            image, review = fixture(root)
            other = root / 'target/other'
            with mock.patch.object(c, 'run', side_effect=fake_docker(root)):
                c.prepare(image, review, other, root)
            for name in ('source.tar.gz', 'signal-0.1.0.tgz', 'evidence.tar.gz'):
                self.assertEqual(c.file_info(output / name, c.EVIDENCE_CAP), c.file_info(other / name, c.EVIDENCE_CAP))
            verification = c.read_json(output / 'candidate.json')['artifacts']['image.tar']['verification']
            self.assertEqual(verification['repo_tags'], ['example:local'])

    def test_checksum_tampering_extra_missing_and_checksum_duplicate(self):
        for mode in ('tamper', 'extra', 'missing', 'duplicate'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                output = prepared(Path(folder))
                if mode == 'tamper':
                    with (output / 'source.tar.gz').open('ab') as stream:
                        stream.write(b'altered')
                elif mode == 'extra':
                    (output / 'extra.txt').write_text('extra')
                elif mode == 'missing':
                    (output / 'signal-0.1.0.tgz').unlink()
                else:
                    with (output / 'SHA256SUMS').open('a') as stream:
                        stream.write((output / 'SHA256SUMS').read_text().splitlines()[0] + '\n')
                with self.assertRaises(RuntimeError):
                    c.verify(output)

    def test_substituted_valid_image_rejected_after_refreshing_all_self_checksums(self):
        with tempfile.TemporaryDirectory() as folder:
            output = prepared(Path(folder))
            image = image_tar(output / 'image.tar', 'different valid image')
            manifest = c.read_json(output / 'candidate.json')
            manifest['image']['id'] = image
            manifest['artifacts']['image.tar'] = {**c.file_info(output / 'image.tar', c.IMAGE_CAP),
                                                  'kind': 'docker-image', 'verification': c.docker_archive(output / 'image.tar', image)}
            c.write_json(output / 'candidate.json', manifest)
            c.checksums(output)
            with self.assertRaisesRegex(RuntimeError, 'archived accepted origin'):
                c.verify(output)

    def test_changed_unselected_production_file_rejected_with_fresh_archive_checksums(self):
        with tempfile.TemporaryDirectory() as folder:
            output = prepared(Path(folder))
            def mutate(files):
                for index, (member, data) in enumerate(files):
                    if member.name == 'platform-signal/apps/signalctl/src/lib.rs':
                        files[index] = member, b'// unreviewed production change\n'
            rebuild_archive(output, 'source.tar.gz', mutate)
            with self.assertRaisesRegex(RuntimeError, 'unreviewed non-document source'):
                c.verify(output)

    def test_removed_workspace_input_rejected_with_fresh_archive_checksums(self):
        with tempfile.TemporaryDirectory() as folder:
            output = prepared(Path(folder))
            rebuild_archive(output, 'source.tar.gz', lambda files: files.__setitem__(slice(None), [item for item in files if item[0].name != 'platform-signal/Cargo.lock']))
            with self.assertRaisesRegex(RuntimeError, 'required workspace inputs'):
                c.verify(output)

    def test_changed_preparation_delta_declaration_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            output = prepared(Path(folder))
            rebuild_archive(output, 'source.tar.gz', lambda files: files.__setitem__(slice(None), [(member, b'new preparation docs\n' if member.name == 'platform-signal/README.md' else data) for member, data in files]))
            with self.assertRaisesRegex(RuntimeError, 'preparation changes'):
                c.verify(output)

    def test_removed_deferred_gates_rejected_with_refreshed_checksums(self):
        with tempfile.TemporaryDirectory() as folder:
            output = prepared(Path(folder))
            manifest = c.read_json(output / 'candidate.json')
            manifest['deferred_gates'] = []
            c.write_json(output / 'candidate.json', manifest)
            c.checksums(output)
            with self.assertRaisesRegex(RuntimeError, 'deferred gates'):
                c.verify(output)


class SafeArchives(unittest.TestCase):
    def test_secret_and_private_paths_not_selected_and_source_symlink_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            for name in ('.aws/config', '.codex/config.toml', '.mcp.json', '.env', 'docs/private/secrets.md', 'apps/signal-server/data/test.rs'):
                write(root, name, 'SECRET sentinel')
            names = c.collect(root, tuple(c.TOP_FILES) + ('apps', 'crates', 'docs'), c.source_allowed)
            self.assertFalse(any('secrets' in name or name.startswith(('.aws', '.codex', '.mcp', '.env')) or '/data/' in name for name in names))
            link = root / 'apps/signal-server/src/linked.rs'
            link.symlink_to(root / '.aws/config')
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                c.collect(root, ('apps',), c.source_allowed)

    def test_target_output_collision_escape_and_ancestor_symlink_preserve_existing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image, review = fixture(root)
            existing = root / 'target/existing'
            existing.mkdir(parents=True)
            (existing / 'sentinel').write_text('keep')
            alias = root / 'target/alias'
            alias.symlink_to(existing, target_is_directory=True)
            for output in (existing, root / 'outside', alias / 'new'):
                with self.subTest(output=output), mock.patch.object(c, 'run') as run:
                    with self.assertRaises((RuntimeError, FileExistsError)):
                        c.prepare(image, review, output, root)
                    run.assert_not_called()
            self.assertEqual((existing / 'sentinel').read_text(), 'keep')

    def test_traversal_duplicates_and_symlink_members_refused(self):
        for mode in ('traversal', 'duplicate', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'archive.gz'
                with tarfile.open(path, 'w:gz', format=tarfile.USTAR_FORMAT) as bundle:
                    names = ['platform-signal/README.md', 'platform-signal/README.md'] if mode == 'duplicate' else ['platform-signal/../secret'] if mode == 'traversal' else ['platform-signal/README.md']
                    for name in names:
                        info = tarfile.TarInfo(name)
                        info.mode = 0o644
                        if mode == 'symlink':
                            info.type, info.linkname = tarfile.SYMTYPE, '/secret'
                            bundle.addfile(info)
                        else:
                            info.size = 1
                            bundle.addfile(info, io.BytesIO(b'x'))
                with self.assertRaises(RuntimeError):
                    c.archive_contents(path, 'source', c.SOURCE_CAP)

    def test_hidden_pax_expansion_and_oversized_member_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'pax.gz'
            with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as bundle:
                info = tarfile.TarInfo('platform-signal/README.md')
                info.size = 1
                info.mode = 0o644
                info.pax_headers = {'comment': 'x' * (c.JSON_CAP + 1)}
                bundle.addfile(info, io.BytesIO(b'x'))
            with self.assertRaisesRegex(RuntimeError, 'metadata'):
                c.archive_contents(path, 'source', c.SOURCE_CAP)
            root = Path(folder)
            write(root, 'README.md', 'x' * 1048577)
            with self.assertRaises(RuntimeError):
                c.archive(root / 'oversized.gz', root, ['README.md'], 'platform-signal/', 'source', c.SOURCE_CAP)

    def test_final_member_record_alignment_accepts_bounded_zero_padding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for size in (8704, 9216, 9728):
                with self.subTest(size=size):
                    write(root, 'README.md', 'x' * size)
                    path = root / ('aligned-' + str(size) + '.gz')
                    expected = c.archive(path, root, ['README.md'], 'platform-signal/', 'source', c.SOURCE_CAP)
                    self.assertEqual(c.archive_contents(path, 'source', c.SOURCE_CAP, expected)['content_bytes'], size)
                    if size == 9216:
                        raw = gzip.decompress(path.read_bytes())
                        self.assertEqual(len(raw) - 512 - size, 10752)
                        path.write_bytes(gzip.compress(raw + b'\0' * 512, mtime=0))
                        with self.assertRaisesRegex(RuntimeError, 'trailing padding bound'):
                            c.archive_contents(path, 'source', c.SOURCE_CAP)

    def test_layer_corruption_rejected_but_inner_symlinks_allowed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'image.tar'
            image = image_tar(path)
            self.assertEqual(c.docker_archive(path, image)['architecture'], 'amd64')
            raw = bytearray(path.read_bytes())
            marker = raw.find(b'original')
            self.assertGreater(marker, 0)
            raw[marker] ^= 1
            path.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, 'diff_id'):
                c.docker_archive(path, image)


class OwnedFailure(unittest.TestCase):
    def test_failed_save_retains_failed_manifest_and_removes_only_owned_partials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image, review = fixture(root)
            normal = fake_docker(root)
            output = root / 'target/candidate'
            sentinel = write(root, 'target/unrelated', 'keep')
            def fail(command, record, **kwargs):
                if command[1:3] == ['image', 'save']:
                    Path(command[command.index('--output') + 1]).write_text('partial')
                    raise KeyboardInterrupt('cancel export')
                return normal(command, record, **kwargs)
            with mock.patch.object(c, 'run', side_effect=fail):
                with self.assertRaises(KeyboardInterrupt):
                    c.prepare(image, review, output, root)
            self.assertEqual({p.name for p in output.iterdir()}, {'candidate.json'})
            self.assertEqual(c.read_json(output / 'candidate.json')['status'], 'failed')
            self.assertEqual(sentinel.read_text(), 'keep')

    def test_command_timeout_and_output_flood_reap_owned_process(self):
        original = subprocess.Popen
        owned = []
        def record(*args, **kwargs):
            process = original(*args, **kwargs)
            owned.append(process)
            return process
        for code, message in [('import time;time.sleep(30)', 'deadline'), ('import os;os.write(1,b"x"*131072)', 'output cap')]:
            with self.subTest(message=message), mock.patch.object(c.subprocess, 'Popen', record):
                with self.assertRaisesRegex(RuntimeError, message):
                    c.run([sys.executable, '-c', code], [], timeout=0.2)
                self.assertIsNotNone(owned[-1].returncode)

    def test_interrupt_during_spawn_assignment_still_reaps(self):
        original = subprocess.Popen
        owned = []
        def interrupt(*args, **kwargs):
            process = original(*args, **kwargs)
            owned.append(process)
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        prior = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(c.subprocess, 'Popen', interrupt):
            with self.assertRaisesRegex(KeyboardInterrupt, 'registration'):
                c.run([sys.executable, '-c', 'import time;time.sleep(30)'], [])
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior)
        self.assertIsNotNone(owned[0].returncode)


if __name__ == '__main__':
    unittest.main()

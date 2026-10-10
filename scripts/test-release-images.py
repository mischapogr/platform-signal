#!/usr/bin/env python3
"""Offline failure regressions for release authorization and exact image evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('release_images', Path(__file__).with_name('release-images.py'))
release_images = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_images)

REVISION = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64


class ReleasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.event = {'action': 'published', 'repository': {'private': False, 'full_name': 'Owner/Signal'},
                      'release': {'draft': False, 'tag_name': 'v0.1.0', 'prerelease': False}}

    def policy(self, event=None, **overrides):
        arguments = dict(event=self.event if event is None else event, event_name='release',
                         ready_tag='v0.1.0', version='0.1.0', revision=REVISION)
        arguments.update(overrides)
        return release_images.release_policy(**arguments)

    def test_public_stable_owner_identity(self):
        policy = self.policy()
        self.assertTrue(policy['stable'])
        self.assertEqual(policy['prefix'], 'ghcr.io/owner')

    def test_alpha_is_allowed_without_stable_promotion(self):
        self.event['release'].update(tag_name='v0.1.0-alpha.1', prerelease=True)
        self.assertFalse(self.policy(ready_tag='v0.1.0-alpha.1', version='0.1.0-alpha.1')['stable'])

    def test_missing_readiness_version_source_or_event_fail(self):
        for overrides in [{'ready_tag': ''}, {'ready_tag': 'v0.2.0'}, {'version': '0.1.0-dev.0'},
                          {'revision': 'main'}, {'event_name': 'push'}, {'event_name': 'pull_request'}]:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.policy(**overrides)

    def test_private_draft_and_unpublished_fail(self):
        for section, key, value in [('repository', 'private', True), ('release', 'draft', True),
                                     ('release', 'prerelease', True), ('repository', 'full_name', 'Owner/Signal;bad')]:
            event = copy.deepcopy(self.event)
            event[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.policy(event=event)
        self.event['action'] = 'created'
        with self.assertRaises(ValueError):
            self.policy()

    def test_development_and_invalid_semver_fail_even_when_ready(self):
        for version in ['0.1.0-dev.0', '0.1.0-dirty', '0.1.0-alpha.01', '00.1.0', '0.1.0+build', '0.1.0-$(id)']:
            self.event['release'].update(tag_name='v'+version, prerelease='-' in version)
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.policy(version=version, ready_tag='v'+version)

    def test_digest_cannot_cross_release_role_architecture_or_repository(self):
        policy = self.policy()
        record = {'role': 'server', 'arch': 'amd64', 'image': 'ghcr.io/owner/signal-server',
                  'digest': DIGEST, 'revision': REVISION, 'tag': 'v0.1.0'}
        self.assertEqual(release_images.record_digest(record, 'server', 'amd64', policy), record['image']+'@'+DIGEST)
        for field, value in [('role', 'agent'), ('arch', 'arm64'), ('image', 'ghcr.io/private/overlay'),
                             ('digest', 'latest'), ('revision', 'c'*40), ('tag', 'v0.2.0')]:
            mutated = {**record, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                release_images.record_digest(mutated, 'server', 'amd64', policy)

    def test_index_record_binding(self):
        policy = self.policy()
        record = {'image': 'ghcr.io/owner/signal-agent', 'digest': DIGEST, 'tag': 'v0.1.0', 'revision': REVISION}
        self.assertTrue(release_images.index_digest(record, 'agent', policy).endswith('@'+DIGEST))
        for mutation in [{'tag': 'v0.2.0'}, {'revision': 'c'*40}, {'image': 'ghcr.io/owner/signal-server'}, {'extra': True}]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                release_images.index_digest({**record, **mutation}, 'agent', policy)

    def test_prerelease_promote_has_no_registry_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'Cargo.toml').write_text('[workspace.package]\nversion="0.1.0-alpha.1"\n')
            self.event['release'].update(tag_name='v0.1.0-alpha.1', prerelease=True)
            event = root/'event.json'
            event.write_text(json.dumps(self.event))
            environment = {'GITHUB_EVENT_PATH': str(event), 'GITHUB_EVENT_NAME': 'release',
                           'GITHUB_SHA': REVISION, 'SIGNAL_RELEASE_READY_TAG': 'v0.1.0-alpha.1'}
            with mock.patch.object(release_images, 'ROOT', root), mock.patch.dict(release_images.os.environ, environment), \
                    mock.patch('sys.argv', ['release-images.py', 'promote']), mock.patch.object(release_images, 'run') as registry:
                with self.assertRaises(ValueError):
                    release_images.main()
                registry.assert_not_called()

    def test_mismatched_second_index_prevents_any_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'Cargo.toml').write_text('[workspace.package]\nversion="0.1.0"\n')
            event = root/'event.json'
            event.write_text(json.dumps(self.event))
            records = root/'target/release-images'
            records.mkdir(parents=True)
            for role in release_images.ROLES:
                record = {'image': 'ghcr.io/owner/signal-'+role, 'digest': DIGEST,
                          'tag': 'v0.1.0', 'revision': REVISION if role == 'server' else 'c'*40}
                (records/f'{role}-index.json').write_text(json.dumps(record))
            environment = {'GITHUB_EVENT_PATH': str(event), 'GITHUB_EVENT_NAME': 'release',
                           'GITHUB_SHA': REVISION, 'SIGNAL_RELEASE_READY_TAG': 'v0.1.0'}
            with mock.patch.object(release_images, 'ROOT', root), mock.patch.dict(release_images.os.environ, environment), \
                    mock.patch('sys.argv', ['release-images.py', 'promote']), mock.patch.object(release_images, 'run') as registry:
                with self.assertRaises(ValueError):
                    release_images.main()
                registry.assert_not_called()

    def test_duplicate_unknown_or_unqualified_platform_rejected(self):
        records = {'amd64': {'digest': DIGEST}, 'arm64': {'digest': 'sha256:'+'c'*64}}
        entries = [{'digest': records[arch]['digest'], 'platform': {'os': 'linux', 'architecture': arch}} for arch in release_images.ARCHES]
        release_images.validate_manifest({'manifests': entries}, records)
        bad = [entries[:1], entries+[entries[0]], [entries[0], entries[0]],
               [entries[0], {**entries[1], 'digest': DIGEST}],
               [entries[0], {**entries[1], 'platform': {'os': 'windows', 'architecture': 'arm64'}}]]
        for entries in bad:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                release_images.validate_manifest({'manifests': entries}, records)


class SecurityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = self.root/'reports/20261010T120000Z'
        self.report.mkdir(parents=True)
        self.lock = self.root/'Cargo.lock'
        self.lock.write_text('locked OSS dependency fixture\n')
        self.info = {'Os': 'linux', 'Architecture': 'amd64', 'Id': DIGEST}
        self.summary = {'image_id': DIGEST, 'image_architecture': 'amd64',
                        'cargo_lock_sha256': hashlib.sha256(self.lock.read_bytes()).hexdigest(),
                        'checks': {name: {'exit_code': 0} for name in ['cargo-audit', 'cargo-sbom', 'image-inspect', 'image-sbom', 'image-vulnerabilities', 'container-policy']},
                        'report_sha256': {}}
        for name in ['cargo.spdx.json', 'image.spdx.json', 'image-vulnerabilities.json', 'image.json', 'cargo-audit.json']:
            (self.report/name).write_text('{}\n')
            self.summary['report_sha256'][name] = hashlib.sha256((self.report/name).read_bytes()).hexdigest()
        self.save()

    def save(self):
        (self.report/'provenance.json').write_text(json.dumps(self.summary))

    def qualify(self):
        return release_images.qualified_image(self.info, 'amd64', self.root/'reports', self.lock)

    def test_all_scanned_image_evidence_binds(self):
        self.assertEqual(self.qualify(), self.report)

    def test_missing_or_failed_gate_blocks(self):
        original = copy.deepcopy(self.summary)
        for name in original['checks']:
            for remove in [True, False]:
                self.summary = copy.deepcopy(original)
                if remove:
                    del self.summary['checks'][name]
                else:
                    self.summary['checks'][name]['exit_code'] = 1
                self.save()
                with self.subTest(name=name, remove=remove), self.assertRaises(ValueError):
                    self.qualify()

    def test_report_tampering_blocks(self):
        (self.report/'image.spdx.json').write_text('{"changed":true}')
        with self.assertRaises(ValueError):
            self.qualify()

    def test_changed_dependencies_or_image_blocks(self):
        self.lock.write_text('different dependencies')
        with self.assertRaises(ValueError):
            self.qualify()
        self.summary['cargo_lock_sha256'] = hashlib.sha256(self.lock.read_bytes()).hexdigest()
        self.summary['image_id'] = 'sha256:'+'d'*64
        self.save()
        with self.assertRaises(ValueError):
            self.qualify()

    def test_duplicate_reports_and_failure_error_block(self):
        self.summary['error'] = 'scanner interrupted'
        self.save()
        with self.assertRaises(ValueError):
            self.qualify()
        self.summary.pop('error')
        self.save()
        other = self.root/'reports/other'
        other.mkdir()
        (other/'provenance.json').write_text('{}')
        with self.assertRaises(ValueError):
            self.qualify()

    def test_security_path_escape_blocks(self):
        self.summary['report_sha256']['../outside'] = '0'*64
        self.save()
        with self.assertRaises(ValueError):
            self.qualify()

    def test_missing_agent_security_prevents_server_push(self):
        # A qualified server alone must not permit any publication mutation.
        shutil.copytree(self.root/'reports', self.root/'target/release-security/server')
        (self.root/'Cargo.toml').write_text('[workspace.package]\nversion="0.1.0"\n')
        event = self.root/'event.json'
        event.write_text(json.dumps({'action': 'published',
                                    'repository': {'private': False, 'full_name': 'Owner/Signal'},
                                    'release': {'draft': False, 'tag_name': 'v0.1.0', 'prerelease': False}}))
        environment = {'GITHUB_EVENT_PATH': str(event), 'GITHUB_EVENT_NAME': 'release',
                       'GITHUB_SHA': REVISION, 'SIGNAL_RELEASE_READY_TAG': 'v0.1.0'}
        with mock.patch.object(release_images, 'ROOT', self.root), mock.patch.dict(release_images.os.environ, environment), \
                mock.patch('sys.argv', ['release-images.py', 'push', '--arch', 'amd64']), \
                mock.patch.object(release_images, 'run', return_value=json.dumps([self.info])) as registry:
            with self.assertRaises(ValueError):
                release_images.main()
            self.assertEqual(len(registry.call_args_list), 2)
            for call in registry.call_args_list:
                self.assertEqual(call.args[0][:3], ['docker', 'image', 'inspect'])


if __name__ == '__main__':
    unittest.main()

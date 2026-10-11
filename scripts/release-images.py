#!/usr/bin/env python3
"""Fail-closed GHCR release policy; no registry access in preflight."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ROLES = ('server', 'agent')
ARCHES = ('amd64', 'arm64')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def release_policy(event, event_name, ready_tag, version, revision):
    if event_name != 'release' or event.get('action') != 'published':
        raise ValueError('only an owner-published release can publish images')
    repository = event.get('repository', {})
    release = event.get('release', {})
    if repository.get('private') is not False or release.get('draft') is not False:
        raise ValueError('public OSS repository and published non-draft release required')
    name = repository.get('full_name', '')
    if re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', name) is None:
        raise ValueError('repository identity')
    tag = release.get('tag_name', '')
    match = re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', tag)
    if match is None or len(tag) > 96 or tag != ready_tag or tag[1:] != version:
        raise ValueError('ready tag, release SemVer and workspace version must match')
    prerelease = match.group(4)
    if prerelease:
        for part in prerelease.split('.'):
            if part.lower() in ('dev', 'dirty') or (part.isdigit() and len(part) > 1 and part.startswith('0')):
                raise ValueError('development or invalid prerelease cannot publish')
    if release.get('prerelease') is not bool(prerelease):
        raise ValueError('release prerelease flag must agree with version')
    if re.fullmatch('[0-9a-f]{40}', revision) is None:
        raise ValueError('release source revision')
    return {'tag': tag, 'stable': not bool(prerelease), 'prefix': 'ghcr.io/' + name.split('/')[0].lower(), 'repository': name, 'revision': revision}


def record_digest(record, role, arch, policy):
    if role not in ROLES or arch not in ARCHES:
        raise ValueError('supported image role/architecture')
    if set(record) != {'role', 'arch', 'image', 'digest', 'revision', 'tag'}:
        raise ValueError('image digest record fields')
    expected = policy['prefix'] + '/signal-' + role
    if record['role'] != role or record['arch'] != arch or record['image'] != expected or record['revision'] != policy['revision'] or record['tag'] != policy['tag'] or DIGEST.fullmatch(record['digest']) is None:
        raise ValueError('image digest is not bound to this release/role/architecture')
    return expected + '@' + record['digest']


def run(argv):
    return subprocess.check_output(argv, text=True, timeout=180).strip()


def read(path):
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('release input byte capacity')
    return json.loads(path.read_text())


def qualified_image(info, arch, report_directory, lock_path):
    reports = list(report_directory.glob('*/provenance.json'))
    if len(reports) != 1:
        raise ValueError('one fresh security report required')
    summary = read(reports[0])
    required = {'cargo-audit', 'cargo-sbom', 'image-inspect', 'image-sbom', 'image-vulnerabilities', 'container-policy'}
    checks = summary.get('checks', {})
    if (info.get('Os') != 'linux' or info.get('Architecture') != arch
            or summary.get('image_id') != info.get('Id')
            or summary.get('image_architecture') != arch
            or 'error' in summary or not required.issubset(checks)
            or any(check.get('exit_code') != 0 for check in checks.values())
            or summary.get('cargo_lock_sha256') != hashlib.sha256(lock_path.read_bytes()).hexdigest()):
        raise ValueError('exact native image and locked dependencies must pass all security gates')
    hashes = summary.get('report_sha256', {})
    if not {'cargo.spdx.json', 'image.spdx.json', 'image-vulnerabilities.json', 'image.json', 'cargo-audit.json'}.issubset(hashes):
        raise ValueError('required security evidence missing')
    for name, expected in hashes.items():
        if Path(name).name != name or name in ('.', '..'):
            raise ValueError('security report filename')
        path = reports[0].parent / name
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('security evidence changed after qualification')
    return reports[0].parent


def index_digest(record, role, policy):
    if set(record) != {'image', 'digest', 'tag', 'revision'} or role not in ROLES:
        raise ValueError('index record fields')
    if (record['image'] != policy['prefix'] + '/signal-' + role
            or record['tag'] != policy['tag'] or record['revision'] != policy['revision']
            or DIGEST.fullmatch(record['digest']) is None):
        raise ValueError('index is not bound to this release')
    return record['image'] + '@' + record['digest']


def validate_manifest(manifest, records):
    entries = manifest.get('manifests', [])
    if len(entries) != len(ARCHES):
        raise ValueError('exactly two platform manifests required')
    seen = set()
    for entry in entries:
        platform = entry.get('platform', {})
        arch = platform.get('architecture')
        if platform.get('os') != 'linux' or arch not in ARCHES or arch in seen or entry.get('digest') != records[arch]['digest']:
            raise ValueError('index platform and digest do not match qualified images')
        seen.add(arch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['preflight', 'push', 'merge', 'promote'])
    parser.add_argument('--role', choices=ROLES)
    parser.add_argument('--arch', choices=ARCHES)
    parser.add_argument('--directory', type=Path, default=ROOT/'target/release-images')
    args = parser.parse_args()
    event = read(Path(os.environ['GITHUB_EVENT_PATH']))
    version = tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['package']['version']
    policy = release_policy(event, os.environ['GITHUB_EVENT_NAME'], os.environ.get('SIGNAL_RELEASE_READY_TAG', ''), version, os.environ['GITHUB_SHA'])
    args.directory.mkdir(parents=True, exist_ok=True)
    if args.action == 'preflight':
        (args.directory/'policy.json').write_text(json.dumps(policy, indent=2)+'\n')
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            for key in ['tag', 'prefix', 'revision']:
                output.write(f'{key}={policy[key]}\n')
        return
    if args.action == 'push':
        if args.arch is None:
            raise ValueError('native architecture required')
        # Login happens only after exact local IDs pass the supply-chain scan.
        qualified = {}
        for role in ROLES:
            local = 'signal-release-' + role + ':qualified'
            info = json.loads(run(['docker', 'image', 'inspect', local]))[0]
            report = qualified_image(info, args.arch, ROOT/f'target/release-security/{role}', ROOT/'Cargo.lock')
            qualified[role] = (info, report)
        for role, (info, report) in qualified.items():
            image = policy['prefix']+'/signal-'+role
            remote = image+':'+policy['tag']+'-'+args.arch
            run(['docker', 'tag', info['Id'], remote])
            run(['docker', 'push', remote])
            descriptor = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', remote, '--format', '{{json .Manifest}}']))
            manifest = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', remote, '--raw']))
            if manifest.get('config', {}).get('digest') != info['Id']:
                raise ValueError('published platform differs from scanned image')
            record = {'role':role, 'arch':args.arch, 'image':image, 'digest':descriptor.get('digest', ''), 'revision':policy['revision'], 'tag':policy['tag']}
            record_digest(record, role, args.arch, policy)
            (args.directory/f'{role}-{args.arch}.json').write_text(json.dumps(record, indent=2)+'\n')
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
                output.write(f'{role}_image={image}\n{role}_digest={record["digest"]}\n{role}_sbom={report / "image.spdx.json"}\n')
    elif args.action == 'merge':
        if args.role is None:
            raise ValueError('image role required')
        records = {arch: read(args.directory/f'{args.role}-{arch}.json') for arch in ARCHES}
        references = [record_digest(records[arch], args.role, arch, policy) for arch in ARCHES]
        image = policy['prefix']+'/signal-'+args.role
        run(['docker', 'buildx', 'imagetools', 'create', '--tag', image+':'+policy['tag'], *references])
        manifest = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', '--raw', image+':'+policy['tag']]))
        validate_manifest(manifest, records)
        descriptor = run(['docker', 'buildx', 'imagetools', 'inspect', image+':'+policy['tag'], '--format', '{{json .Manifest}}'])
        digest = json.loads(descriptor).get('digest', '')
        if DIGEST.fullmatch(digest) is None:
            raise ValueError('image index digest')
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write(f'image={image}\ndigest={digest}\n')
        (args.directory/f'{args.role}-index.json').write_text(json.dumps({'image':image,'digest':digest,'tag':policy['tag'],'revision':policy['revision']},indent=2)+'\n')
        # latest is promoted only after public verification and provenance by the workflow.
    else:
        if not policy['stable']:
            raise ValueError('prerelease must never promote latest')
        references = [index_digest(read(args.directory/f'{role}-index.json'), role, policy) for role in ROLES]
        for role, reference in zip(ROLES, references):
            tag = policy['prefix']+'/signal-'+role+':latest'
            run(['docker', 'buildx', 'imagetools', 'create', '--tag', tag, reference])
            descriptor = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', tag, '--format', '{{json .Manifest}}']))
            if descriptor.get('digest') != reference.split('@')[1]:
                raise ValueError('latest does not match the signed public release index')


if __name__ == '__main__':
    main()

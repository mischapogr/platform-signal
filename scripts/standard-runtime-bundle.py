#!/usr/bin/env python3
"""Transfer source-bound native Standard executables between CI jobs; no compilation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ARCHES = {'x86_64': ('amd64', 62), 'aarch64': ('arm64', 183)}
MAX_BINARY = 2 * 1024**3


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    with path.open('rb') as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('manifest/report byte capacity')
    return json.loads(data)


def source_inputs():
    names = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.github/workflows/ci.yml',
             'scripts/standard-runtime-bundle.py', 'scripts/check-shared-runtime.py',
             'scripts/check-standard-kubernetes.py', 'scripts/check-kubernetes.py',
             'scripts/check-object-query.py', 'scripts/check-native-qualification.py',
             'scripts/fixtures/standard-kubernetes.py', 'scripts/fixtures/s3-query-server.py',
             'tests/integration/standard-main-process.py', 'tests/integration/transport-server-process.py',
             'tests/integration/access-server-process.py', 'tests/integration/standard-sensor.py',
             'tests/integration/shared-feed-provider.py', 'scripts/fixtures/onboarding-host.py',
             'scripts/check-audit-role-composition.py', 'scripts/check-audit-receiver-permissions.py'}
    for directory in ('apps', 'crates', 'schemas/shared-control', 'deploy/helm/signal', 'tests/fixtures/source-coverage'):
        names.update(str(p.relative_to(ROOT)) for p in (ROOT / directory).rglob('*')
                     if p.is_file() and p.suffix in {'.rs', '.toml', '.json', '.sql', '.yaml', '.tpl', '.sha256'})
    if len(names) > 2048:
        raise ValueError('source inventory capacity')
    return {name: digest(ROOT / name) for name in sorted(names)}


def executable(path, arch):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BINARY:
        raise ValueError('bounded executable regular file required')
    with path.open('rb') as stream:
        header = stream.read(20)
    machine = {'amd64': 62, 'arm64': 183}.get(arch)
    if (len(header) != 20 or header[:6] != b'\x7fELF\x02\x01'
            or machine is None or int.from_bytes(header[18:20], 'little') != machine):
        raise ValueError('native ELF architecture mismatch')
    return digest(path)


def verify(directory, revision, arch, inputs):
    if (directory / 'manifest.json').is_symlink():
        raise ValueError('regular bundle manifest required')
    manifest = read_json(directory / 'manifest.json')
    if (manifest.get('schema_version') != 1 or manifest.get('source_revision') != revision
            or manifest.get('architecture') != arch or manifest.get('source_inputs') != inputs):
        raise ValueError('bundle revision/architecture/source mismatch')
    if set(p.name for p in directory.iterdir()) != {'manifest.json', 'server', 'offline-fixture'}:
        raise ValueError('unexpected bundle files')
    if set(manifest.get('executables', {})) != {'server', 'offline-fixture'}:
        raise ValueError('missing executable bindings')
    for name, metadata in manifest['executables'].items():
        path = directory / name
        if executable(path, arch) != metadata['sha256'] or path.stat().st_size != metadata['bytes']:
            raise ValueError('bundle executable hash/size mismatch')
    # Artifact downloads reset modes. Only restore permissions after all checks.
    for name in manifest['executables']:
        (directory / name).chmod(0o700)
    return manifest


def prepare(directory, qualification, revision, arch, inputs):
    report = read_json(qualification / 'report.json')
    child = read_json(qualification / 'standard-process/report.json')
    if (report.get('status') != 'passed_simulated' or child.get('status') != 'passed_simulated'
            or report.get('architecture') != arch or not report.get('container_removed')
            or report.get('cleanup_errors') != []):
        raise ValueError('passing native Standard qualification required')
    for name, sha in report['source_hashes'].items():
        if inputs.get(name) != sha:
            raise ValueError('qualified compilation or runtime source drift')
    server = qualification / 'standard-server'
    if report.get('standard_offline_binary_sha256'):
        offline = qualification / 'standard-offline-fixture'
    else:
        log = (qualification / 'standard-process/offline-prepare.log').read_text()
        if len(log.encode()) > 65536:
            raise ValueError('offline build log capacity')
        matches = re.findall(r'Running tests/standard_main\.rs \((target/debug/deps/standard_main-[0-9a-f]+)\)', log)
        if len(matches) != 1:
            raise ValueError('unique qualified offline executable required')
        offline = ROOT / matches[0]
    originals = {'server': executable(server, arch), 'offline-fixture': executable(offline, arch)}
    if (originals['server'] != report.get('standard_binary_sha256')
            or originals['server'] != child.get('binary_sha256')
            or originals['offline-fixture'] != child.get('offline_binary_sha256')):
        raise ValueError('qualified executable hashes mismatch')
    directory.mkdir(parents=True, exist_ok=False)
    entries = {}
    for name, source in [('server', server), ('offline-fixture', offline)]:
        target = directory / name
        shutil.copyfile(source, target)
        if digest(target) != originals[name]:
            raise ValueError('executable changed during snapshot')
        subprocess.run(['strip', '--strip-debug', str(target)], check=True, timeout=60)
        entries[name] = {'sha256': executable(target, arch), 'bytes': target.stat().st_size,
                         'qualified_original_sha256': originals[name]}
    manifest = {'schema_version': 1, 'source_revision': revision, 'architecture': arch,
                'source_inputs': inputs, 'executables': entries,
                'qualification_report_sha256': digest(qualification / 'report.json'),
                'derivation': 'copies of qualified native executables, debug sections removed with strip --strip-debug'}
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return verify(directory, revision, arch, inputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--qualification', type=Path)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    args = parser.parse_args()
    if ARCHES.get(platform.machine(), (None,))[0] != args.architecture:
        raise ValueError('native runner architecture mismatch')
    output = args.output.absolute()
    if output.is_symlink() or not output.resolve().is_relative_to(ROOT / 'target'):
        raise ValueError('owned target bundle directory required')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if os.environ.get('GITHUB_SHA', revision) != revision:
        raise ValueError('workflow source revision mismatch')
    inputs = source_inputs()
    if args.action == 'prepare':
        if args.qualification is None:
            parser.error('--qualification required for prepare')
        manifest = prepare(output, args.qualification, revision, args.architecture, inputs)
    else:
        manifest = verify(output, revision, args.architecture, inputs)
    print(json.dumps({'status': 'passed', 'architecture': manifest['architecture'],
                      'source_revision': revision, 'executables': manifest['executables']}))


if __name__ == '__main__':
    main()

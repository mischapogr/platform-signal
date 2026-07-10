#!/usr/bin/env python3
"""Package an unsigned CI development candidate from an already qualified image.

This is deliberately separate from the retained historical local dev0 preview.
No registry, GitHub Release, tag or signing service is written.
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_gate', ROOT / 'scripts/check-native-qualification.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
JSON_CAP = 2 * 1024 * 1024
IMAGE_CAP = 512 * 1024 * 1024
EVIDENCE_CAP = 64 * 1024 * 1024
REQUIRED = ('image-build', 'container', 'native', 'kind', 'supply-chain',
            'helm-default', 'helm-optional', 'helm-render', 'helm-render-optional')


def read_json(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > JSON_CAP:
        raise RuntimeError('missing or oversized JSON: ' + str(path))
    return json.loads(path.read_text())


def require_checks(root, source_sha):
    records = {}
    for name in REQUIRED:
        path = root / 'target/ci' / (name + '.json')
        report = read_json(path)
        log = path.with_suffix('.log')
        if (report.get('status') != 'passed' or report.get('source_sha') != source_sha
                or report.get('architecture') != platform.machine()
                or not log.is_file() or log.is_symlink()
                or log.stat().st_size > 8 * 1024 * 1024
                or gate.sha256(log) != report.get('log_sha256')):
            raise RuntimeError('qualification check identity mismatch: ' + name)
        records[name] = gate.sha256(path)
    return records


def require_image_evidence(root, image_id, architecture, binary_hash):
    native = sorted((root / 'target/native-qualification').glob('*/qualification.json'))
    supply = sorted((root / 'target/supply-chain/reports').glob('*/provenance.json'))
    if len(native) != 1 or len(supply) != 1:
        raise RuntimeError('exactly one native and supply-chain report required')
    report = read_json(native[0])
    if (report.get('status') != 'passed' or report.get('full_qualification') is not True
            or report.get('expected_architecture') != architecture
            or report.get('image', {}).get('id') != image_id
            or report.get('binary_sha256') != binary_hash):
        raise RuntimeError('native evidence does not identify this image and binary')
    if set(report.get('reports_sha256', {})) != {
            'hardening/campaign.json', 'hardening/campaign.log', 'pipeline.json', 'soak.json'}:
        raise RuntimeError('complete native reports required')
    for name, digest in report.get('reports_sha256', {}).items():
        path = native[0].parent / name
        if not path.is_relative_to(native[0].parent) or '..' in Path(name).parts:
            raise RuntimeError('unsafe evidence path')
        if not path.is_file() or path.is_symlink() or path.stat().st_size > JSON_CAP or gate.sha256(path) != digest:
            raise RuntimeError('native report digest mismatch')
    provenance = read_json(supply[0])
    checks = provenance.get('checks', {})
    required = ('cargo-audit', 'cargo-sbom', 'image-sbom', 'image-vulnerabilities', 'container-policy')
    if ('error' in provenance or provenance.get('image_id') != image_id
            or provenance.get('image_architecture') != architecture
            or any(checks.get(name, {}).get('exit_code') != 0 for name in required)):
        raise RuntimeError('supply-chain checks incomplete')
    image = read_json(supply[0].parent / 'image.json')
    # Docker inspect produces an array. Validate the scanned immutable image.
    if not isinstance(image, list) or len(image) != 1 or image[0].get('Id') != image_id:
        raise RuntimeError('supply-chain image identity mismatch')
    if not {'image.json', 'cargo.spdx.json', 'image.spdx.json', 'image-vulnerabilities.json'} <= set(provenance.get('report_sha256', {})):
        raise RuntimeError('complete supply-chain reports required')
    for name, digest in provenance.get('report_sha256', {}).items():
        if Path(name).name != name:
            raise RuntimeError('unsafe supply-chain evidence path')
        path = supply[0].parent / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > EVIDENCE_CAP or gate.sha256(path) != digest:
            raise RuntimeError('supply-chain digest mismatch')


def archive_evidence(root, destination):
    files = []
    total = 0
    for relative in ('target/ci', 'target/native-qualification', 'target/supply-chain/reports'):
        directory = root / relative
        for path in sorted(directory.rglob('*')):
            if path.is_symlink():
                raise RuntimeError('symlink in evidence')
            if path.is_file():
                size = path.stat().st_size
                total += size
                if len(files) >= 1024 or total > EVIDENCE_CAP:
                    raise RuntimeError('evidence archive budget exceeded')
                files.append(path)
    with tarfile.open(destination, 'x:gz') as archive:
        for path in files:
            archive.add(path, arcname=str(path.relative_to(root)), recursive=False)


def finalize_candidate(output, manifest):
    """Commit success only after the complete inventory and checksum file exist."""
    required = {'signal-server', 'signal-agent', 'signal-healthcheck', 'source.tar.gz',
                'evidence.tar.gz', 'image.tar', 'packaging.log', 'cleanup.log'}
    if not required <= {p.name for p in output.iterdir()} or len(list(output.glob('*.tgz'))) != 1:
        raise RuntimeError('candidate artifact inventory incomplete')
    complete = copy.deepcopy(manifest)
    complete['artifacts'] = {}
    for path in sorted(output.iterdir()):
        if path.name == 'candidate.json':
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('unsafe candidate artifact')
        complete['artifacts'][path.name] = {'bytes': path.stat().st_size,
                                           'sha256': gate.sha256(path)}
    complete['status'] = 'passed_ci_development_candidate'
    document = (json.dumps(complete, indent=2) + '\n').encode()
    sums = ''.join(value['sha256'] + '  ' + name + '\n'
                   for name, value in complete['artifacts'].items())
    sums += hashlib.sha256(document).hexdigest() + '  candidate.json\n'
    (output / 'SHA256SUMS').write_text(sums)
    # Keep the existing failed record until every checksum has been written.
    temporary = output / 'candidate.tmp'
    temporary.write_bytes(document)
    temporary.replace(output / 'candidate.json')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--helm', required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/ci-candidate')
    args = parser.parse_args(argv)
    source_sha = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise RuntimeError('actual GitHub source SHA required')
    if platform.system() != 'Linux' or platform.machine() != gate.ARCHITECTURES[args.architecture][0]:
        raise RuntimeError('native architecture required')
    checks = require_checks(ROOT, source_sha)
    actual_sha = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True,
                                text=True, check=True, timeout=10).stdout.strip()
    if actual_sha != source_sha:
        raise RuntimeError('checkout source mismatch')
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], cwd=ROOT, check=True, timeout=10)
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {'schema_version': 1, 'status': 'failed', 'full_release': False,
                'signed': False, 'published': False, 'source_sha': source_sha,
                'version': version, 'architecture': args.architecture,
                'prepared_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'checks_sha256': checks,
                'external_gates': ['actual AWS/EKS', 'live vendor tenants', 'released dependency',
                                   'remaining product ledger', 'owner-selected version/publication']}
    container = 'signal-ci-package-' + os.urandom(8).hex()
    owns_container = False
    try:
        with (args.output / 'packaging.log').open('xb') as log:
            image = json.loads(gate.run_bounded(['docker', 'image', 'inspect', '--format',
                '{"id":{{json .Id}},"architecture":{{json .Architecture}},"os":{{json .Os}}}', args.image], log))
            if image['architecture'] != args.architecture or image['os'] != 'linux':
                raise RuntimeError('image architecture mismatch')
            manifest['image_id'] = image['id']
            owns_container = True
            gate.run_bounded(['docker', 'create', '--pull=never', '--name', container, image['id']], log)
            binary = args.output / 'signal-server'
            gate.run_bounded(['docker', 'cp', container + ':/usr/local/bin/signal-server', str(binary)], log,
                             files=lambda: [(binary, gate.BINARY_CAP)])
            binary_hash = gate.verify_binary(binary, args.architecture)
            require_image_evidence(ROOT, image['id'], args.architecture, binary_hash)
            for name in ('signal-agent', 'signal-healthcheck'):
                target = args.output / name
                gate.run_bounded(['docker', 'cp', container + ':/usr/local/bin/' + name, str(target)], log,
                                 files=lambda: [(target, gate.BINARY_CAP)])
                gate.verify_binary(target, args.architecture)
            gate.run_bounded([args.helm, 'package', str(ROOT / 'deploy/helm/signal'),
                              '--destination', str(args.output)], log,
                             files=lambda: [(p, 8 * 1024 * 1024) for p in args.output.glob('*.tgz')])
            source = args.output / 'source.tar.gz'
            gate.run_bounded(['git', 'archive', '--format=tar.gz', '--output=' + str(source), source_sha], log,
                             files=lambda: [(source, 16 * 1024 * 1024)])
            archive_evidence(ROOT, args.output / 'evidence.tar.gz')
            image_tar = args.output / 'image.tar'
            gate.run_bounded(['docker', 'save', '--output', str(image_tar), image['id']], log,
                             timeout=180, files=lambda: [(image_tar, IMAGE_CAP)])
    finally:
        if owns_container:
            with (args.output / 'cleanup.log').open('xb') as log:
                try:
                    gate.run_bounded(['docker', 'rm', '-f', container], log, timeout=30)
                except BaseException:
                    manifest['status'] = 'failed'
                    raise
                finally:
                    (args.output / 'candidate.json').write_text(json.dumps(manifest, indent=2) + '\n')
        else:
            (args.output / 'candidate.json').write_text(json.dumps(manifest, indent=2) + '\n')
    finalize_candidate(args.output, manifest)
    return 0


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())

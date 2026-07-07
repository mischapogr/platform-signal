#!/usr/bin/env python3
"""Pinned, local-only SBOM and security checks; no publication or global installs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
# Official release checksum files (Syft/Trivy) and GitHub asset digest (cargo-audit).
TOOLS = {
    'syft': ('1.54.1', 'anchore/syft', 'v1.54.1', {
        'x86_64': ('syft_1.54.1_linux_amd64.tar.gz', 'c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47'),
        'aarch64': ('syft_1.54.1_linux_arm64.tar.gz', 'dfdf0537610113edbefe1f1fc6548bc957b2d77439636ec824fcf0e10d46d054')}),
    'trivy': ('0.75.0', 'aquasecurity/trivy', 'v0.75.0', {
        'x86_64': ('trivy_0.75.0_Linux-64bit.tar.gz', 'c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f'),
        'aarch64': ('trivy_0.75.0_Linux-ARM64.tar.gz', 'a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3')}),
    'cargo-audit': ('0.22.2', 'rustsec/rustsec', 'cargo-audit/v0.22.2', {
        'x86_64': ('cargo-audit-x86_64-unknown-linux-gnu-v0.22.2.tgz', 'ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39'),
        'aarch64': ('cargo-audit-aarch64-unknown-linux-gnu-v0.22.2.tgz', 'c6603814ddaa45e51263dafd31c0ac98808f688d26f7395804f9670b0fd599dd')})}
LIMIT = 64 * 1024 * 1024


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bounds():
    # Trivy's current SQLite DB is ~1.4 GiB; reports have a separate 64 MiB cap.
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**3, 2 * 1024**3))


def install(name, directory):
    version, repo, tag, assets = TOOLS[name]
    asset, expected = assets[platform.machine()]
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / asset
    if not archive.exists() or digest(archive) != expected:
        temporary = archive.with_suffix('.download')
        url = f'https://github.com/{repo}/releases/download/{tag}/{asset}'
        # A finite deadline and 128 MiB bound cover tool release downloads.
        subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                        '--connect-timeout', '20', '--max-time', '180',
                        '--max-filesize', str(128 * 1024 * 1024),
                        '--output', str(temporary), url], check=True, timeout=190)
        if digest(temporary) != expected:
            temporary.unlink()
            raise ValueError(f'{name}: release SHA256 mismatch')
        temporary.replace(archive)
    # Extract only the verified regular executable, never archive paths or links.
    with tarfile.open(archive) as package:
        candidates = [member for member in package.getmembers()
                      if member.isfile() and Path(member.name).name == name]
        if len(candidates) != 1 or candidates[0].size > 256 * 1024 * 1024:
            raise ValueError(f'{name}: unexpected release archive')
        with package.extractfile(candidates[0]) as source, (directory / name).open('wb') as dest:
            shutil.copyfileobj(source, dest)
    executable = directory / name
    executable.chmod(0o755)
    return executable, {'version': version, 'archive': asset, 'archive_sha256': expected,
                        'binary_sha256': digest(executable), 'repository': repo, 'tag': tag}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Existing local Docker image; never pulled')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/supply-chain/reports')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        parser.error('requires native Linux AMD64 or ARM64')
    output = args.output.resolve() / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output.mkdir(parents=True, exist_ok=False)
    work = ROOT / 'target/supply-chain'
    work.mkdir(parents=True, exist_ok=True)
    config = work / 'scanner-empty.yaml'
    config.write_text('{}\n')
    # cargo-audit resolves ./ .cargo/audit.toml before the user's Cargo home.
    audit_config = work / '.cargo/audit.toml'
    audit_config.parent.mkdir(parents=True, exist_ok=True)
    audit_config.write_text('[advisories]\nignore = []\n')
    # Trivy and audit config from a home directory/repo must not silently ignore findings.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('SYFT_', 'TRIVY_'))}
    env.update({'SYFT_CHECK_FOR_APP_UPDATE': 'false', 'TRIVY_DISABLE_TELEMETRY': 'true'})
    summary = {'schema_version': 1, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'platform': platform.machine(), 'cargo_lock_sha256': digest(ROOT / 'Cargo.lock'),
               'image_reference': args.image, 'tools': {}, 'checks': {}}

    def run(name, command, stdout=None):
        log = output / f'{name}.log'
        with log.open('wb') as errors, (stdout or log.with_suffix('.stdout')).open('wb') as result:
            try:
                process = subprocess.run([str(x) for x in command], cwd=work, env=env,
                                         stdout=result, stderr=errors, timeout=600, preexec_fn=bounds)
                code = process.returncode
            except subprocess.TimeoutExpired:
                code = 124
        for report in output.iterdir():
            if report.is_file() and report.stat().st_size > LIMIT:
                report.unlink()
                code = 125
                with log.open('ab') as errors:
                    errors.write(b'report exceeded 64 MiB limit and was removed\n')
        summary['checks'][name] = {'exit_code': code}
        print(f'{name}: exit {code}', flush=True)
        return code

    try:
        bins = {}
        for name in TOOLS:
            bins[name], summary['tools'][name] = install(name, work / 'tools' / name)
        # Only OSS dependency inputs are included; no source tree/secrets/private overlay.
        inputs = work / 'inputs'
        inputs.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'Cargo.lock', inputs / 'Cargo.lock')
        shutil.copyfile(ROOT / 'Cargo.toml', inputs / 'Cargo.toml')
        run('cargo-sbom', [bins['syft'], '--config', config, 'scan', f'dir:{inputs}', '-o',
                          f'spdx-json={output / "cargo.spdx.json"}'])
        audit = output / 'cargo-audit.json'
        run('cargo-audit', [bins['cargo-audit'], 'audit', '--json', '--no-yanked', '--file', ROOT / 'Cargo.lock',
                            '--db', work / 'rustsec-db'], audit)
        if summary['checks']['cargo-audit']['exit_code'] == 0:
            audited = json.loads(audit.read_text())
            settings = audited.get('settings', {})
            if (settings.get('ignore') or settings.get('target_arch')
                    or settings.get('target_os') or settings.get('severity') is not None):
                raise RuntimeError('cargo-audit settings unexpectedly filtered advisories')
        # Scan the immutable local ID, so the tag cannot move between inspection and scan.
        inspect = output / 'image.json'
        if run('image-inspect', ['docker', 'image', 'inspect', args.image], inspect):
            raise RuntimeError('local image inspection failed')
        info = json.loads(inspect.read_text())[0]
        summary['image_id'] = info['Id']
        summary['image_architecture'] = info['Architecture']
        summary['image_created'] = info['Created']
        run('image-sbom', [bins['syft'], '--config', config, 'scan', f'docker:{info["Id"]}', '-o',
                          f'spdx-json={output / "image.spdx.json"}'])
        # Full report includes all severities; any HIGH/CRITICAL fails the CI gate.
        run('image-vulnerabilities', [bins['trivy'], '--config', config, 'image',
             '--ignorefile', '/dev/null', '--image-src', 'docker', '--scanners', 'vuln', '--format', 'json',
             '--output', output / 'image-vulnerabilities.json', '--timeout', '9m',
             '--cache-dir', work / 'trivy-cache', '--exit-code', '0', info['Id']])
        report = output / 'image-vulnerabilities.json'
        if summary['checks']['image-vulnerabilities']['exit_code'] == 0:
            findings = [v for result in json.loads(report.read_text()).get('Results', [])
                        for v in result.get('Vulnerabilities', [])]
            summary['container_vulnerabilities'] = {
                severity: sum(v.get('Severity') == severity for v in findings)
                for severity in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')}
            summary['checks']['container-policy'] = {'exit_code': int(any(
                v.get('Severity') in ('HIGH', 'CRITICAL') for v in findings))}
        for name, check in (('cargo.spdx.json', 'cargo-sbom'), ('image.spdx.json', 'image-sbom')):
            path = output / name
            if summary['checks'][check]['exit_code'] == 0:
                document = json.loads(path.read_text())
                if not document.get('packages'):
                    raise RuntimeError(f'{name}: empty SBOM')
                summary.setdefault('sbom_packages', {})[name] = len(document['packages'])
        metadata = work / 'trivy-cache/db/metadata.json'
        if metadata.exists():
            summary['trivy_database'] = json.loads(metadata.read_text())
        if audit.exists() and audit.stat().st_size:
            summary['rustsec_database'] = json.loads(audit.read_text()).get('database')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        summary['error'] = str(error)
    summary['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary['report_sha256'] = {path.name: digest(path) for path in output.iterdir()
                              if path.is_file() and path.name != 'provenance.json'}
    print(f'reports: {output}', flush=True)
    (output / 'provenance.json').write_text(json.dumps(summary, indent=2) + '\n')
    failed = 'error' in summary or any(c['exit_code'] for c in summary['checks'].values())
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())

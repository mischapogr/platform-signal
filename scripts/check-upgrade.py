#!/usr/bin/env python3
"""Rehearse explicit development schema paths and isolated stopped restore locally."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def document(path):
    if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('missing or oversized fixture report')
    return json.loads(path.read_text())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', required=True, help='immutable local PostgreSQL image digest')
    parser.add_argument('--agent', type=Path, default=ROOT / 'target/debug/signal-agent')
    parser.add_argument('--server', type=Path, default=ROOT / 'target/debug/signal-server')
    parser.add_argument('--reuse-fixtures', type=Path, help='reuse exact completed fixture gates after a report-check-only correction')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / 'target') or out == ROOT / 'target' or out.exists():
        parser.error('output must be an absent owned directory under target/')
    if '@sha256:' not in args.image or len(args.image.rsplit('@sha256:', 1)[1]) != 64:
        parser.error('immutable PostgreSQL image digest required')
    binaries = {name: path.resolve() for name, path in [('agent', args.agent), ('server', args.server)]}
    for path in binaries.values():
        if not path.is_relative_to(ROOT / 'target') or not path.is_file():
            parser.error('prebuilt binaries must be owned files under target/')
    paths = set(ROOT.glob('schemas/shared-control/*'))
    for base in ['apps', 'crates']:
        paths.update((ROOT / base).rglob('*.rs'))
        paths.update((ROOT / base).rglob('Cargo.toml'))
    paths.update(ROOT / p for p in ['Cargo.toml', 'Cargo.lock', 'scripts/check-upgrade.py',
        'scripts/check-shared-runtime.py', 'scripts/run-ci-check.py',
        'tests/integration/phase10-restore-process.py', 'docs/56-upgrade-compatibility.md'])
    before = {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths) if p.is_file()}
    binary_hashes = {name: digest(path) for name, path in binaries.items()}
    fixture_root = out
    if args.reuse_fixtures:
        fixture_root = args.reuse_fixtures.resolve()
        if not fixture_root.is_relative_to(ROOT / 'target'):
            parser.error('reused fixtures must be under owned target/')
        previous = document(fixture_root / 'report.json')
        if previous.get('binary_sha256') != binary_hashes or previous.get('gates') != [
                {'name': 'shared-schema', 'exit_code': 0}, {'name': 'stopped-restore', 'exit_code': 0}]:
            parser.error('reused fixture gates and binary identities must match')
        # Only this report-check wrapper may differ. Every runtime, schema,
        # harness and contract input remains bound to the completed campaign.
        old = previous.get('source_before', {})
        wrapper = 'scripts/check-upgrade.py'
        if {p: h for p, h in old.items() if p != wrapper} != {p: h for p, h in before.items() if p != wrapper}:
            parser.error('reused fixture inputs changed')
        for name in ['shared-schema', 'stopped-restore']:
            if document(fixture_root / 'gates' / (name + '.json')).get('status') != 'passed':
                parser.error('reused fixture gate report must pass')
    out.mkdir(mode=0o700)
    report = {'schema_version': 1, 'status': 'failed', 'scope': 'Local development schema migration and same-binary stopped restore; no released-to-released, ARM64, AWS/EKS or production proof',
              'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_before': before, 'binary_sha256': binary_hashes, 'gates': []}
    try:
        # The full populated matrix exceeds the helper's 96 MiB ephemeral
        # profile. Its existing matrix mode owns and removes a dedicated volume.
        commands = [('shared-schema', ['python3', 'scripts/check-shared-runtime.py', '--matrix', '--output', str(out / 'shared'), '--image', args.image]),
                    ('stopped-restore', ['python3', 'tests/integration/phase10-restore-process.py', str(binaries['agent']), str(binaries['server']), str(out / 'stopped')])]
        for name, command in ([] if args.reuse_fixtures else commands):
            result = subprocess.run(['python3', 'scripts/run-ci-check.py', '--name', name,
                '--timeout', '600', '--output', str(out / 'gates'), '--', *command], cwd=ROOT, timeout=610, check=False)
            report['gates'].append({'name': name, 'exit_code': result.returncode})
            if result.returncode:
                raise ValueError(name + ' failed; remaining gates not run')
        report['fixture_root'] = str(fixture_root.relative_to(ROOT))
        report['reused_fixtures'] = bool(args.reuse_fixtures)
        if args.reuse_fixtures:
            report['gates'] = previous['gates']
        shared = document(fixture_root / 'shared/report.json')
        stopped = document(fixture_root / 'stopped/report.json')
        required = {'actual_explicit_initialization_populated_checksummed_migration_and_rollback',
                    'actual_stopped_restore_fresh_generation_history_current_authority_and_custody',
                    'actual_dynamic_catalog_populated_stopped_migration_replay_empty_quotas',
                    'actual_coordinated_catalog_restore_preserved_pins_resumed_parquet_query'}
        if shared.get('status') != 'passed_simulated' or not required <= set(shared.get('checks', [])) or shared.get('container_removed') is not True or shared.get('volume_removed') is not True:
            raise ValueError('complete schema migration/restore and cleanup evidence required')
        if stopped.get('original_and_backup_unchanged') is not True or stopped.get('final_checkpoint') != 9 or stopped.get('final_events') != 9 or stopped.get('final_findings') != 2:
            raise ValueError('exact stopped WAL/spool/event/finding restore evidence required')
        if any(stopped['binaries'][name]['sha256'] != h for name, h in binary_hashes.items()):
            raise ValueError('restored binary identity changed')
        report['supported_paths'] = ['exact notification revision1 -> administration2', 'exact administration2 -> catalog4', 'stopped revision2 -> fresh restored3', 'stopped catalog4 -> fresh restored5', 'same binary stopped Small WAL/spool/Parquet/findings restore']
        report['checks'] = sorted(required)
        report['source_after'] = {p: digest(ROOT / p) for p in before}
        if report['source_after'] != before or any(digest(binaries[name]) != h for name, h in binary_hashes.items()):
            raise ValueError('source or binary drift invalidates rehearsal')
        report['status'] = 'passed_simulated'
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report['error'] = str(error)[:2048]
    finally:
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(out / 'report.json')}))
    return 0 if report['status'] == 'passed_simulated' else 1

if __name__ == '__main__':
    sys.exit(main())

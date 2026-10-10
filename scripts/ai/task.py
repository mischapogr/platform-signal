#!/usr/bin/env python3
"""Bounded task packets and serial, reviewed-source local acceptance campaigns."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 16 * 1024
RUST_GATES = [
    ['cargo', 'fmt', '--check'],
    ['cargo', 'clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'],
    ['cargo', 'test', '--workspace'],
    ['python3', 'scripts/check-workspace.py'],
]
ROUTES = {'implementation': ['gpt-6.1-sol', 'medium'],
          'critical': ['gpt-6.1-sol', 'high'], 'mechanical': ['gpt-6-luna', 'low']}


def read_json(path):
    with path.open('rb') as source:
        data = source.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('task/review JSON exceeds 16 KiB')
    return json.loads(data)


def write_json(path, value):
    with path.open('x') as destination:
        json.dump(value, destination, indent=2)
        destination.write('\n')


def relative(value, artifact=False):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError('bounded relative path required')
    path = Path(value)
    if path.is_absolute() or not path.parts or '..' in path.parts:
        raise ValueError('repository relative paths only')
    if path.parts[0] in {'.git', '.aws'} or (not artifact and path.parts[0] == 'target'):
        raise ValueError('protected or evidence path cannot be a task source')
    resolved = (ROOT / path).resolve()
    if not resolved.is_relative_to(ROOT.resolve()):
        raise ValueError('path escapes repository')
    if artifact and (path.parts[0] != 'target' or len(path.parts) < 2):
        raise ValueError('artifact directory must be below target/')
    return resolved


def command(argv):
    if (not isinstance(argv, list) or not 2 <= len(argv) <= 64
            or any(not isinstance(a, str) or len(a) > 1024 for a in argv)):
        raise ValueError('bounded argv array required')
    if argv[0] == 'cargo' and argv[1] in {'fmt', 'clippy', 'test'}:
        return argv
    if argv[0] == 'python3' and argv[1].startswith('scripts/'):
        relative(argv[1])
        return argv
    raise ValueError('only local Cargo checks and Python scripts are supported')


def packet(value):
    if not isinstance(value, dict) or value.get('kind') not in {'rust', 'tooling', 'docs'}:
        raise ValueError('kind must be rust, tooling or docs')
    for field in ('task', 'outcome', 'actual_model', 'actual_effort', 'stop_condition'):
        if not isinstance(value.get(field), str) or not 1 <= len(value[field]) <= 2048:
            raise ValueError(f'bounded nonempty {field} required')
    if value.get('route') not in ROUTES:
        raise ValueError('unknown route')
    for field, maximum in [('owned_paths', 64), ('contracts', 16), ('failure_cases', 16)]:
        items = value.get(field)
        if not isinstance(items, list) or not 1 <= len(items) <= maximum:
            raise ValueError(f'bounded nonempty {field} required')
        for item in items:
            if not isinstance(item, str) or len(item) > 2048:
                raise ValueError(f'invalid {field} entry')
            if field != 'failure_cases':
                relative(item)
    for field in ('focused_commands', 'acceptance_commands'):
        commands = value.get(field)
        if not isinstance(commands, list) or not 1 <= len(commands) <= 16:
            raise ValueError(f'1..16 {field} required')
        for argv in commands:
            command(argv)
    if value.get('ledger_item') is not None:
        ledger = ROOT / 'docs/31-execution-ledger.json'
        if ledger.stat().st_size > 1024 * 1024:
            raise ValueError('ledger exceeds bound')
        ids = {item['id'] for item in json.loads(ledger.read_text())['items']}
        if value['ledger_item'] not in ids:
            raise ValueError('unknown ledger item')
    if len(json.dumps(value, indent=2).encode()) + 1 > LIMIT:
        raise ValueError('packet exceeds 16 KiB')
    return value


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            result.update(block)
    return result.hexdigest()


def identity(value):
    paths = set(value['owned_paths'] + value['contracts'])
    paths.update(['scripts/ai/task.py', 'scripts/run-ci-check.py',
                  'scripts/check-native-qualification.py', 'benchmarks/pipeline.py'])
    for field in ('focused_commands', 'acceptance_commands'):
        paths.update(argv[1] for argv in value[field] if argv[0] == 'python3')
    if value['kind'] == 'rust':
        paths.update(['Cargo.toml', 'Cargo.lock'])
    hashes = {}
    for name in sorted(paths):
        path = relative(name)
        if path.is_dir():
            raise ValueError('list individual source files, not directories')
        hashes[name] = digest(path) if path.is_file() else None
    return hashes


def init(spec, output):
    value = packet(read_json(spec))
    value['schema_version'] = 1
    value['recommended_route'] = ROUTES[value['route']]
    value['authority'] = 'local task only; no model/config/Git/external authority changes'
    if len(json.dumps(value, indent=2).encode()) + 1 > LIMIT:
        raise ValueError('packet exceeds 16 KiB')
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / 'task.json', value)


def review(output):
    value = packet(read_json(output / 'task.json'))
    write_json(output / 'review.json', {
        'schema_version': 1, 'status': 'pending', 'reviewer': '',
        'actual_model': '', 'actual_effort': '', 'findings': [],
        'blocking_findings': [], 'packet_sha256': digest(output / 'task.json'),
        'source_sha256': identity(value),
        'note': 'Template only. Record the actual focused review before setting passed.'})


def reviewed(output, value):
    result = read_json(output / 'review.json')
    if (result.get('status') != 'passed' or result.get('blocking_findings') != []
            or any(not result.get(k) for k in ('reviewer', 'actual_model', 'actual_effort'))
            or result.get('packet_sha256') != digest(output / 'task.json')
            or result.get('source_sha256') != identity(value)):
        raise ValueError('missing, pending, blocked or stale source-bound review')


@contextmanager
def campaign_lock():
    path = ROOT / 'target/ai-validation.lock'
    path.parent.mkdir(exist_ok=True)
    relative('target/ai-validation.lock', artifact=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('another task campaign is running; do not start parallel Cargo') from None
        yield
    finally:
        os.close(descriptor)


def selected_commands(value, stage):
    commands = value['focused_commands' if stage == 'focused' else 'acceptance_commands'][:]
    if stage == 'final' and value['kind'] == 'rust':
        commands = RUST_GATES + [c for c in commands if c not in RUST_GATES]
    return commands


def validate(output, stage, timeout):
    packet_sha = digest(output / 'task.json')
    value = packet(read_json(output / 'task.json'))
    if stage == 'final':
        reviewed(output, value)
    commands = selected_commands(value, stage)
    before = identity(value)
    with campaign_lock():
        # Recheck under the lock; evidence directories never overwrite a prior attempt.
        if digest(output / 'task.json') != packet_sha:
            raise ValueError('task packet changed before campaign start')
        if stage == 'final':
            reviewed(output, value)
        directory = output / f'{stage}-{time.time_ns()}'
        directory.mkdir()
        result = {'schema_version': 1, 'stage': stage, 'status': 'failed',
                  'packet_sha256': packet_sha,
                  'source_before': before, 'commands': [], 'scope': 'local only'}
        began = time.monotonic()
        try:
            for index, argv in enumerate(commands):
                name = f'gate-{index + 1}'
                completed = subprocess.run(
                    [sys.executable, str(ROOT / 'scripts/run-ci-check.py'), '--name', name,
                     '--timeout', str(timeout), '--output', str(directory), '--', *argv],
                    cwd=ROOT, check=False)
                result['commands'].append({'argv': argv, 'exit_code': completed.returncode,
                                           'report': f'{name}.json'})
                if completed.returncode:
                    raise ValueError(f'{name} failed; remaining commands were not run')
            if digest(output / 'task.json') != result['packet_sha256'] or identity(value) != before:
                raise ValueError('task packet or source changed during acceptance')
            result['status'] = 'passed'
        except (Exception, KeyboardInterrupt) as error:
            result['error'] = str(error)[:2048]
        finally:
            result['elapsed_seconds'] = round(time.monotonic() - began, 3)
            try:
                result['source_after'] = identity(value)
            except (OSError, ValueError) as error:
                result['status'] = 'failed'
                result['source_after_error'] = str(error)[:2048]
            write_json(directory / 'campaign.json', result)
        print(json.dumps({'status': result['status'], 'report': str(directory / 'campaign.json')}))
        return 0 if result['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'review', 'validate'])
    parser.add_argument('--output', required=True, help='repository-relative target/<task>')
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--stage', choices=['focused', 'final'], default='focused')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    try:
        output = relative(args.output, artifact=True)
        if not 1 <= args.timeout <= 600:
            raise ValueError('per-command timeout must be 1..600 seconds')
        if args.action == 'init':
            if args.spec is None:
                raise ValueError('--spec required for init')
            init(args.spec, output)
        elif args.action == 'review':
            review(output)
        else:
            return validate(output, args.stage, args.timeout)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'task workflow: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

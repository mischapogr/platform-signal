#!/usr/bin/env python3
"""Run one finite CI command, retaining failure output and source identity."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import sys
import time
import tomllib
import itertools

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_gate', ROOT / 'scripts/check-native-qualification.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
# Cargo/build diagnostics have a larger, still finite budget than a load report.
gate.LOG_CAP = 8 * 1024 * 1024
IDP_STAGES = frozenset({'prepare', 'image-prepare', 'provider-start', 'provider-ready',
                        'server-start', 'browser-start', 'oidc-browser-flow', 'qualified'})


def failed_idp_stage(tail):
    """Classify only the harness's final bounded public stage, never its payload."""
    lines = tail.splitlines()
    if not lines or len(lines[-1].encode('utf-8')) > 2048:
        return None
    try:
        # This is diagnostic child output, not an authenticated outcome proof.
        value = json.loads(lines[-1])
        if (isinstance(value, dict) and set(value) == {'status', 'stage', 'report'}
                and value['status'] == 'failed' and isinstance(value['report'], str)
                and isinstance(value['stage'], str) and value['stage'] in IDP_STAGES):
            return value['stage']
    except (ValueError, TypeError):
        pass
    return None


def rust_targets():
    """Finite public manifest inventory; failure payloads cannot invent names."""
    targets = set()
    manifests = itertools.chain((ROOT / 'crates').glob('*/Cargo.toml'),
                                (ROOT / 'apps').glob('*/Cargo.toml'))
    total = 0
    try:
        for index, path in enumerate(manifests):
            if index >= 64:
                return set()
            if not path.resolve().is_relative_to(ROOT.resolve()):
                return set()
            with path.open('rb') as stream:
                data = stream.read(262145)
            total += len(data)
            if len(data) > 262144 or total > 4 * 1024 * 1024:
                return set()
            manifest = tomllib.loads(data.decode('utf-8'))
            package = manifest.get('package', {}).get('name', '')
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,127}', package):
                continue
            if (path.parent / 'src/lib.rs').is_file() or 'lib' in manifest:
                targets.add((package, 'lib', ''))
            if (path.parent / 'src/main.rs').is_file():
                targets.add((package, 'bin', package))
            for kind in ('bin', 'test'):
                entries = manifest.get(kind, [])
                if not isinstance(entries, list) or len(entries) > 64:
                    return set()
                for entry in entries:
                    name = entry.get('name', '')
                    if isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,127}', name):
                        targets.add((package, kind, name))
    except (OSError, ValueError, TypeError, AttributeError):
        return set()
    return targets


def failed_rust_targets(tail):
    """Only source-validated package/target identifiers enter public metadata."""
    allowed = rust_targets()
    results = []
    for line in tail.splitlines():
        match = re.fullmatch(r'error: test failed, to rerun pass `-p ([A-Za-z_][A-Za-z0-9_-]{0,127}) --(lib|bin|test)(?: ([A-Za-z_][A-Za-z0-9_-]{0,127}))?`', line)
        if not match:
            continue
        target = (match[1], match[2], match[3] or '')
        if target in allowed and target not in results:
            results.append(target)
            if len(results) == 16:
                break
    return [{'package': p, 'kind': k, 'name': n} for p, k, n in results]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/ci')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', args.name) or not 1 <= args.timeout <= 7200:
        parser.error('bounded name and timeout (1..7200 seconds) required')
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('command required')
    args.output.mkdir(parents=True, exist_ok=True)
    log_path = args.output / (args.name + '.log')
    report_path = args.output / (args.name + '.json')
    # Refuse collisions: a retry may not overwrite a failed attempt's evidence.
    report = {'schema_version': 1, 'status': 'running', 'check': args.name,
              'command': command, 'timeout_seconds': args.timeout,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'architecture': platform.machine(), 'platform': platform.system(),
              'source_sha': os.environ.get('GITHUB_SHA', 'local'),
              'run_id': os.environ.get('GITHUB_RUN_ID', 'local'),
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT', 'local')}
    with report_path.open('x') as dest:
        json.dump(report, dest, indent=2)
    began = time.monotonic()
    error = None
    try:
        with log_path.open('xb') as log:
            gate.run_bounded(command, log, timeout=args.timeout)
        report['status'] = 'passed'
    except (Exception, KeyboardInterrupt) as failure:
        error = failure
        report['status'] = 'failed'
        report['error'] = str(failure)[:2048]
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - began, 3)
        if log_path.exists():
            report['log_bytes'] = log_path.stat().st_size
            report['log_sha256'] = gate.sha256(log_path)
            with log_path.open('rb') as log:
                log.seek(max(0, report['log_bytes'] - 65536))
                tail = log.read(65536).decode('utf-8', errors='replace')
                if os.environ.get('GITHUB_ACTIONS') == 'true':
                    # Child output is data, never workflow commands. Generate the
                    # unpredictable resume token after the child has retired.
                    nonce = secrets.token_hex(32)
                    print(f'::stop-commands::{nonce}', flush=True)
                    try:
                        print(tail, flush=True)
                    finally:
                        print(f'::{nonce}::', flush=True)
                else:
                    print(tail, flush=True)
            if report['status'] == 'failed':
                report['failed_rust_targets'] = failed_rust_targets(tail)
                if args.name == 'idp-browser':
                    stage = failed_idp_stage(tail)
                    if stage is not None:
                        report['failed_idp_stage'] = stage
                        if os.environ.get('GITHUB_ACTIONS') == 'true':
                            print(f'::error title=Reported IdP failure stage::{stage}', flush=True)
                if os.environ.get('GITHUB_ACTIONS') == 'true':
                    for target in report['failed_rust_targets']:
                        label = f'{target["package"]} --{target["kind"]}'
                        if target['name']:
                            label += ' ' + target['name']
                        print(f'::error title=Rust regression::{label}', flush=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    if error is not None:
        print(f'CI check failed: {args.name}: {report["error"]}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())

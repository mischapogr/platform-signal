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
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_gate', ROOT / 'scripts/check-native-qualification.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
# Cargo/build diagnostics have a larger, still finite budget than a load report.
gate.LOG_CAP = 8 * 1024 * 1024


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
                print(log.read(65536).decode('utf-8', errors='replace'), flush=True)
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

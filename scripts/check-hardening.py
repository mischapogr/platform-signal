#!/usr/bin/env python3
"""Run the finite Phase 10 parser/WAL property campaign and persist its evidence."""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('signal-event', 'signal-protocol', 'signal-rules', 'signal-buffer')


@contextlib.contextmanager
def defer_spawn_signals():
    """Keep Python interrupts pending until the spawned process is registered.

    Signals are not blocked in the OS, so children retain their normal mask.
    """
    previous = {}
    pending = None

    def defer(signum, _frame):
        nonlocal pending
        pending = signum

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, defer)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if pending is not None:
        raise KeyboardInterrupt(f'interrupted by signal {pending} during spawn')


def run_bounded(command, log, timeout=300, grace=2):
    """Own the process group so Cargo's test children stop with the deadline."""
    process = None

    def stop_group():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        # Keep the leader unreaped until the group is killed: its PID remains
        # reserved even if SIGTERM exited it, preventing group-ID reuse races.
        try:
            time.sleep(grace)
        finally:
            # The leader can exit before a test; always kill surviving members.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=grace)

    try:
        with defer_spawn_signals():
            process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_group()
        return 124
    except BaseException:
        if process is not None:
            stop_group()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='exclusively created campaign directory')
    args = parser.parse_args()
    output = args.output_dir if args.output_dir is not None else ROOT / 'target/phase10-hardening' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output.mkdir(parents=True, exist_ok=False)
    command = ['cargo', 'test', '--locked']
    for package in PACKAGES:
        command.extend(['-p', package])
    command.extend(['--test', 'phase10-properties', '--', '--nocapture'])
    started = time.monotonic()
    with (output / 'campaign.log').open('wb') as log:
        code = run_bounded(command, log)
    content = (output / 'campaign.log').read_bytes()
    report = {'schema_version': 1, 'exit_code': code, 'elapsed_seconds': round(time.monotonic() - started, 3),
              'timeout_seconds': 300, 'max_input_bytes': 65536, 'command': command,
              'seeds': dict(zip(PACKAGES, ('0x51a10e01', '0x51a10e02', '0x51a10e03', '0x51a10e04'), strict=True)),
              'configured_cases': {'event_roundtrip': 512, 'url_transport': 512, 'rule_truth_model': 512,
                                   'wal_ack_prefix': 9},
              'observed_wal_cases': dict((name, int(count)) for name, count in
                                        re.findall(r'CAMPAIGN (\w+)=(\d+)', content.decode(errors='replace'))),
              'log_sha256': hashlib.sha256(content).hexdigest(),
              'source_sha256': {package: hashlib.sha256((ROOT / 'crates' / package / 'tests/phase10-properties.rs').read_bytes()).hexdigest()
                                for package in PACKAGES}}
    (output / 'campaign.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    print(f'Reports: {output}')
    return code


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())

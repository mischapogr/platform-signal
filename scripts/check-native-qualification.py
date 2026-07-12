#!/usr/bin/env python3
"""Qualify one existing native Linux image; never build, pull, run emulation or publish."""
import argparse
import contextlib
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
LOG_CAP = 1024 * 1024
TOTAL_CAP = 64 * 1024 * 1024
REPORT_CAP = 2 * 1024 * 1024
BINARY_CAP = 128 * 1024 * 1024
ARCHITECTURES = {'amd64': ('x86_64', 62), 'arm64': ('aarch64', 183)}
NATIVE_STAGES = frozenset({'prepare', 'native-identity', 'binary-extraction',
                           'hardening', 'pipeline', 'soak', 'report-finalization',
                           'container-cleanup', 'temporary-cleanup', 'qualified'})


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


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def check_files(paths):
    for path, limit in paths():
        if path.exists() and (not path.is_file() or path.stat().st_size > limit):
            raise RuntimeError(f'artifact exceeds file bound: {path}')


def run_bounded(command, log, timeout=60, files=lambda: (), grace=30):
    """Drain finite output and kill the owned group before reaping its leader.

    waitid(WNOWAIT) detects exit without releasing the process-group ID. Even
    successful leaders can leave descendants, so every return kills that group.
    """
    process = selector = None
    captured = bytearray()
    reason = None
    completed = False
    deadline = time.monotonic() + timeout
    try:
        with defer_spawn_signals():
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() >= deadline:
                reason = 'deadline exceeded'
                break
            check_files(files)
            for key, _ in selector.select(timeout=min(0.05, max(0, deadline - time.monotonic()))):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    if len(captured) + len(block) > LOG_CAP:
                        reason = 'output exceeds capture bound'
                        break
                    captured.extend(block)
                    log.write(block)
                    log.flush()
            if reason:
                break
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not selector.get_map():
                completed = True
                break
    finally:
        # Do not call poll/wait/communicate until the last group kill: the
        # reserved leader PID makes cleanup safe against process-group reuse.
        try:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                # Nested campaign/server sessions need time for their SIGTERM
                # handlers to finish bounded cleanup (pipeline: at most 24 seconds).
                try:
                    time.sleep(0.01 if completed else grace)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        code = process.wait(timeout=5)
                    finally:
                        if process.stdout is not None:
                            process.stdout.close()
        finally:
            if selector is not None:
                selector.close()
    check_files(files)
    if reason:
        raise RuntimeError(reason)
    if code:
        raise RuntimeError(f'command failed with exit {code}')
    return captured.decode('utf-8', errors='replace')


def bounded_json(path):
    if not path.is_file() or path.stat().st_size > REPORT_CAP:
        raise RuntimeError(f'missing or oversized report: {path}')
    return json.loads(path.read_text())


def verify_native(expected, host_os, host_arch, daemon, image):
    host = ARCHITECTURES[expected][0]
    aliases = {expected, host}
    if host_os != 'Linux' or host_arch != host:
        raise RuntimeError('Python host is not the expected native Linux architecture')
    if daemon.get('os') != 'linux' or daemon.get('architecture') not in aliases:
        raise RuntimeError('Docker daemon is not the expected native Linux architecture')
    if image.get('os') != 'linux' or image.get('architecture') != expected:
        raise RuntimeError('image is not the expected native Linux architecture')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image.get('id', '')):
        raise RuntimeError('image has no immutable config ID')


def verify_binary(binary, architecture):
    if binary.is_symlink() or not binary.is_file() or binary.stat().st_size > BINARY_CAP:
        raise RuntimeError('extracted server is not a bounded regular file')
    with binary.open('rb') as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', header[18:20])[0] != ARCHITECTURES[architecture][1]:
        raise RuntimeError('extracted server is not a native ELF64 binary')
    if not os.access(binary, os.X_OK):
        raise RuntimeError('extracted server is not executable')
    return sha256(binary)


def validate_pipeline(report, architecture, image_id, binary_hash, quick):
    expected = [(1024, 100, False)] if quick else [(size, rate, False) for size in (1024, 4096) for rate in (100, 1000, 10000)] + [(4096, 20000, True)]
    if report.get('schema_version') != 1 or report.get('architecture') != ARCHITECTURES[architecture][0] or report.get('image_id') != image_id or report.get('binary_sha256') != binary_hash:
        raise RuntimeError('pipeline report identity mismatch')
    profiles = report.get('profiles', [])
    if [(row.get('event_bytes'), row.get('target_eps'), row.get('saturation')) for row in profiles] != expected:
        raise RuntimeError('pipeline report missing required completed profiles')
    for row in profiles:
        if row.get('shutdown_exit_code') != 0 or row.get('sample_count', 0) <= 0 or row.get('query_samples') != 20:
            raise RuntimeError('pipeline report has incomplete measurements or shutdown')
        if row.get('attempted', 0) <= 0 or row.get('attempted') != sum(row.get(key, -1) for key in ('accepted', 'rejected', 'transport_uncertain')):
            raise RuntimeError('pipeline report event accounting mismatch')


def validate_hardening(report, log):
    if report.get('schema_version') != 1 or report.get('exit_code') != 0 or report.get('log_sha256') != sha256(log):
        raise RuntimeError('hardening report failed or log identity mismatch')
    expected = {'event_roundtrip': 512, 'url_transport': 512, 'rule_truth_model': 512, 'wal_ack_prefix': 9}
    if report.get('configured_cases') != expected:
        raise RuntimeError('hardening campaign case contract mismatch')
    expected_sources = {package: sha256(ROOT / 'crates' / package / 'tests/phase10-properties.rs') for package in ('signal-event', 'signal-protocol', 'signal-rules', 'signal-buffer')}
    if report.get('source_sha256') != expected_sources:
        raise RuntimeError('hardening campaign source identity mismatch')
    # Four independently completed integration-test executables, nine total cases.
    totals = re.findall(r'test result: ok\. (\d+) passed; 0 failed;', log.read_text(errors='replace'))
    if len(totals) != 4 or sum(map(int, totals)) != 9:
        raise RuntimeError('hardening log missing completed campaign tests')
    expected_wal = {'wal_record_mutations': 104, 'wal_checkpoint_mutations': 28, 'wal_tail_cuts': 303}
    if report.get('observed_wal_cases') != expected_wal:
        raise RuntimeError('hardening log missing required WAL mutation observations')


def validate_soak(report, architecture, image_id, binary_hash, seconds):
    if (report.get('schema_version') != 1 or report.get('status') != 'passed'
            or report.get('architecture') != ARCHITECTURES[architecture][0]
            or report.get('image_id') != image_id or report.get('binary_sha256') != binary_hash):
        raise RuntimeError('soak report identity or completion mismatch')
    profiles = report.get('profiles', [])
    if [row.get('event_bytes') for row in profiles] != [1024, 4096]:
        raise RuntimeError('soak report missing required size profiles')
    for row in profiles:
        duration = row.get('load_seconds')
        if (row.get('duration_seconds') != seconds or type(duration) not in (int, float)
                or not math.isfinite(duration) or duration < seconds
                or row.get('shutdown_exit_code') != 0 or row.get('query_samples') != 20):
            raise RuntimeError('soak report has incomplete duration, queries or shutdown')
        counts = [row.get(name) for name in ('attempted', 'accepted', 'rejected', 'transport_uncertain')]
        if any(type(value) is not int or value < 0 for value in counts) or counts[0] <= 0 or counts[0] != sum(counts[1:]):
            raise RuntimeError('soak report admission accounting mismatch')
        durable, uncertainty = row.get('wal_durable_events'), row.get('admission_uncertainty_bound')
        if (type(durable) is not int or type(uncertainty) is not int or uncertainty < 0
                or not counts[1] <= durable <= counts[1] + uncertainty):
            raise RuntimeError('soak report durable accounting mismatch')
        final = row.get('final_metrics', {})
        if any(final.get(name) != durable for name in ('signal_wal_accepted_total', 'signal_storage_persisted_total', 'signal_rules_evaluated_total')):
            raise RuntimeError('soak report storage/rule accounting mismatch')
        resources = row.get('resources', {})
        buckets = resources.get('buckets', [])
        if (resources.get('sample_count', 0) <= 0 or len(buckets) != 12
                or buckets[0].get('samples', 0) <= 0 or buckets[-1].get('samples', 0) <= 0
                or sum(bucket.get('samples', 0) for bucket in buckets) != resources['sample_count']):
            raise RuntimeError('soak report missing resource trend coverage')
        for name in ('load_process_io_delta', 'load_drain_queries_process_io_delta'):
            counters = row.get(name, {})
            expected = ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes', 'cancelled_write_bytes')
            if any(type(counters.get(key)) is not int or counters[key] < 0 for key in expected):
                raise RuntimeError('soak report missing process I/O accounting')


class Gate:
    def __init__(self, output):
        self.output = output
        self.commands = []

    def run(self, command, timeout=60, files=lambda: ()):
        entry = {'command': [str(value) for value in command], 'timeout_seconds': timeout, 'status': 'running'}
        self.commands.append(entry)
        started = time.monotonic()
        def bounded_files():
            paths = [(path, LOG_CAP if path.suffix == '.log' else REPORT_CAP) for path in self.output.rglob('*') if path.is_file()]
            if sum(path.stat().st_size for path, _ in paths) > TOTAL_CAP:
                raise RuntimeError('total report files exceed bound')
            return paths + list(files())
        log = self.output / f'command-{len(self.commands):02d}.log'
        try:
            with log.open('xb') as stream:
                result = run_bounded(entry['command'], stream, timeout, bounded_files)
            entry['status'] = 'passed'
            return result.strip()
        except BaseException as error:
            entry['status'] = 'failed'
            entry['error'] = str(error)
            raise
        finally:
            entry['elapsed_seconds'] = round(time.monotonic() - started, 3)
            entry['log'] = log.name
            entry['log_sha256'] = sha256(log)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='existing local image reference or immutable config ID')
    parser.add_argument('--expect-architecture', choices=tuple(ARCHITECTURES), required=True)
    parser.add_argument('--output-root', type=Path, default=ROOT / 'target/native-qualification')
    parser.add_argument('--quick', action='store_true', help='smoke only: one measured profile, never full qualification')
    parser.add_argument('--soak-seconds', type=int, default=0, help='optional seconds per 1/4 KiB soak (10..600; zero disables)')
    parser.add_argument('--soak-only', action='store_true', help='measure soak without repeating completed parser/pipeline campaigns')
    args = parser.parse_args(argv)
    if args.soak_seconds != 0 and not 10 <= args.soak_seconds <= 600:
        parser.error('--soak-seconds must be zero or 10..600')
    if args.soak_only and (args.quick or args.soak_seconds == 0):
        parser.error('--soak-only requires --soak-seconds and cannot combine with --quick')
    if args.quick and args.soak_seconds:
        parser.error('--quick cannot combine with --soak-seconds')
    output = args.output_root.resolve() / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '-' + uuid.uuid4().hex[:8])
    output.mkdir(parents=True, exist_ok=False)
    gate = Gate(output)
    report = {'schema_version': 1, 'status': 'failed', 'scope': ('native-soak' if args.soak_seconds >= 120 else 'diagnostic-soak') if args.soak_only else 'smoke' if args.quick else 'native-qualification',
              'full_qualification': False, 'stage': 'prepare', 'expected_architecture': args.expect_architecture,
              'image_reference': args.image, 'host': {'os': platform.system(), 'architecture': platform.machine()},
              'commands': gate.commands, 'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'limits': {'capture_bytes_per_command': LOG_CAP, 'total_report_bytes': TOTAL_CAP, 'report_bytes': REPORT_CAP, 'binary_bytes': BINARY_CAP},
              'inputs_sha256': {}, 'reports_sha256': {}}
    container = 'signal-native-qualification-' + uuid.uuid4().hex
    # The random name is exclusively ours, including ambiguous create responses.
    owns_container = False
    temp = None
    try:
        sources = ['scripts/check-native-qualification.py', 'scripts/check-hardening.py', 'benchmarks/pipeline.py', 'benchmarks/soak.py', 'Cargo.lock'] + [str(path.relative_to(ROOT)) for path in sorted((ROOT / 'rules/examples').rglob('*')) if path.is_file()]
        for source in sources:
            path = ROOT / source
            if path.is_file():
                report['inputs_sha256'][source] = sha256(path)
        report['stage'] = 'native-identity'
        if platform.system() != 'Linux' or platform.machine() != ARCHITECTURES[args.expect_architecture][0]:
            raise RuntimeError('Python host is not the expected native Linux architecture')
        daemon = json.loads(gate.run(['docker', 'info', '--format', '{"os":{{json .OSType}},"architecture":{{json .Architecture}}}']))
        image = json.loads(gate.run(['docker', 'image', 'inspect', '--format', '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"repo_digests":{{json .RepoDigests}}}', args.image]))
        verify_native(args.expect_architecture, platform.system(), platform.machine(), daemon, image)
        report.update({'daemon': daemon, 'image': image})
        report['stage'] = 'binary-extraction'
        temp = tempfile.TemporaryDirectory(prefix='signal-native-qualification-')
        binary = Path(temp.name) / 'signal-server'
        owns_container = True
        gate.run(['docker', 'create', '--pull=never', '--name', container, image['id']])
        gate.run(['docker', 'cp', container + ':/usr/local/bin/signal-server', str(binary)],
                 files=lambda: [(binary, BINARY_CAP)])
        binary_hash = verify_binary(binary, args.expect_architecture)
        report['binary_sha256'] = binary_hash
        retained = []
        if not args.soak_only:
            report['stage'] = 'hardening'
            campaign = output / 'hardening'

            def campaign_files():
                return [(campaign / 'campaign.json', REPORT_CAP), (campaign / 'campaign.log', LOG_CAP)]

            gate.run([sys.executable, str(ROOT / 'scripts/check-hardening.py'), '--output-dir', str(campaign)],
                     timeout=330, files=campaign_files)
            validate_hardening(bounded_json(campaign / 'campaign.json'), campaign / 'campaign.log')
            report['hardening_directory'] = 'hardening'
            report['stage'] = 'pipeline'
            pipeline = output / 'pipeline.json'
            command = [sys.executable, str(ROOT / 'benchmarks/pipeline.py'), '--server', str(binary), '--output', str(pipeline), '--image-id', image['id']]
            if args.quick:
                command.append('--quick')
            gate.run(command, timeout=120 if args.quick else 600, files=lambda: [(pipeline, REPORT_CAP)])
            validate_pipeline(bounded_json(pipeline), args.expect_architecture, image['id'], binary_hash, args.quick)
            retained.extend(('hardening/campaign.json', 'hardening/campaign.log', 'pipeline.json'))
        if args.soak_seconds:
            report['stage'] = 'soak'
            soak = output / 'soak.json'
            command = [sys.executable, str(ROOT / 'benchmarks/soak.py'), '--server', str(binary),
                       '--output', str(soak), '--image-id', image['id'], '--seconds', str(args.soak_seconds)]
            gate.run(command, timeout=2 * args.soak_seconds + 180, files=lambda: [(soak, REPORT_CAP)])
            validate_soak(bounded_json(soak), args.expect_architecture, image['id'], binary_hash, args.soak_seconds)
            retained.append('soak.json')
        report['stage'] = 'report-finalization'
        for name in retained:
            report['reports_sha256'][name] = sha256(output / name)
        report['status'] = 'passed'
        report['full_qualification'] = not args.quick and not args.soak_only
        report['stage'] = 'qualified'
    except BaseException as error:
        # Cancellation can arrive after preparing successful report metadata.
        # A caught failure must never leave the qualification successful.
        report.update(status='failed', full_qualification=False)
        report['error'] = str(error)
        report['failed_stage'] = report['stage']
    finally:
        cleanup = []
        if owns_container:
            try:
                gate.run(['docker', 'rm', '-f', container], timeout=30)
                cleanup.append({'resource': 'owned-container', 'status': 'removed'})
            except BaseException as error:
                cleanup.append({'resource': 'owned-container', 'status': 'failed', 'error': str(error)})
                report.setdefault('failed_stage', 'container-cleanup')
                report.update(status='failed', full_qualification=False, error='owned container cleanup failed')
        if temp is not None:
            try:
                temp.cleanup()
                cleanup.append({'resource': 'owned-temporary-directory', 'status': 'removed'})
            except BaseException as error:
                cleanup.append({'resource': 'owned-temporary-directory', 'status': 'failed', 'error': str(error)})
                report.setdefault('failed_stage', 'temporary-cleanup')
                report.update(status='failed', full_qualification=False, error='owned temporary directory cleanup failed')
        report['cleanup'] = cleanup
        (output / 'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(f'Reports: {output}', flush=True)
        # A fixed public diagnostic, never an authenticated outcome or a cause.
        # Preserve the first failed stage even when owned cleanup also fails.
        print(json.dumps({'status': report['status'],
                          'stage': report.get('failed_stage', report['stage']),
                          'report': str(output / 'qualification.json')}), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())

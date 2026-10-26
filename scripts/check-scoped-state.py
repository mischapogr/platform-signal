#!/usr/bin/env python3
"""Bounded actual Rust state-journal SIGKILL matrix using a Cargo-bound test ELF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TARGET = (ROOT / 'target').resolve()
MAX_LOG = 2*1024*1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def owned(path):
    path = path.resolve()
    require(path.is_relative_to(TARGET), 'owned target artifact required')
    return path


def executable(artifacts):
    artifacts = owned(artifacts)
    require(artifacts.is_file() and artifacts.stat().st_size <= 8*1024*1024, 'bounded Cargo artifact stream')
    matches = []
    for line in artifacts.read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') != 'compiler-artifact':
            continue
        target = row.get('target', {})
        if (target.get('name') == 'scoped-state' and target.get('kind') == ['test']
                and row.get('profile', {}).get('test') is True
                and target.get('src_path') == str(ROOT / 'crates/signal-rules/tests/scoped-state.rs')
                and row.get('executable')):
            matches.append((owned(Path(row['executable'])), row.get('features', [])))
    require(len(matches) == 1, 'exactly one source-bound rules integration test ELF')
    binary, features = matches[0]
    require(binary.is_file() and os.access(binary, os.X_OK) and binary.stat().st_size <= 512*1024*1024, 'bounded executable')
    with binary.open('rb') as source:
        header = source.read(64)
        require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01', '64-bit little-endian test ELF')
        machine = {'x86_64': 62, 'aarch64': 183}.get(platform.machine())
        require(machine is not None and int.from_bytes(header[18:20], 'little') == machine, 'native host test ELF architecture')
    return binary, features


def sources(spec):
    spec = owned(spec)
    require(spec.stat().st_size <= 16384, 'bounded source spec')
    data = json.loads(spec.read_text())
    paths = sorted(set(data['owned_paths'] + data['contracts'] + ['Cargo.toml', 'Cargo.lock']))
    require(len(paths) <= 80, 'bounded source inventory')
    result = {}
    for name in paths:
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and path.parts[0] not in ['.git', '.aws'], 'explicit source path')
        absolute = (ROOT / path).resolve()
        require(absolute.is_relative_to(ROOT) and absolute.is_file() and absolute.stat().st_size <= 2*1024*1024, 'bounded repository source')
        result[name] = digest(absolute)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--source-spec', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = owned(args.output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = sources(args.source_spec)
    binary, features = executable(args.artifacts)
    binary_hash = digest(binary)
    report = {'schema_version': 1, 'status': 'failed', 'source_sha256': before,
              'test_elf_sha256': binary_hash, 'cargo_artifacts_sha256': digest(args.artifacts),
              'cargo_features': features, 'architecture': platform.machine(),
              'scope': 'production state library/journal through actual owned test processes; synthetic source and private authority',
              'limits': ['not a production server image', 'no live AWS/EKS/kernel/source/state custody or ARM64/CI/release qualification']}
    process = None
    began = time.monotonic()
    def interrupted(signum, frame):
        raise InterruptedError('owned scoped state campaign interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        env = {'SCOPED_STATE_OUTPUT': str(output)}
        with (output / 'matrix.log').open('xb') as log:
            process = subprocess.Popen([str(binary), '--ignored', '--exact', 'process_crash_matrix', '--nocapture'],
                                       cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=log, start_new_session=True)
            while process.poll() is None:
                require(time.monotonic()-began < 120, 'owned process matrix deadline')
                require((output / 'matrix.log').stat().st_size <= MAX_LOG, 'bounded matrix log')
                time.sleep(0.05)
            require(process.returncode == 0, 'actual owned process matrix failed')
        data = json.loads((output / 'process-report.json').read_text())
        require(data['status'] == 'passed_local' and data['actual_sigkill'] == 5 and data['owned_process_cleanup'], 'all owned effects/cleanup required')
        require({c['rule'] for c in data['cases']} == {'SIG-D04','SIG-D06','SIG-D08','SIG-D09','SIG-D13'}, 'all supported detectors')
        require(all(c['actual_sigkill_signal'] == 9 and c['checkpoint'] == 7 and c['original_commit_recovered']
                    and c['published_before_retirement'] and c['original_published_bytes_survive'] and c['changed_enrollment_refused']
                    and c['intervening_event_preserves_original'] and c['duplicate_checkpoint'] == 9
                    and c['generation_carry_reopen_preserves_original'] for c in data['cases']), 'exact original replay and enrollment evidence')
        require(before == sources(args.source_spec) and binary_hash == digest(binary), 'source/ELF drift')
        report.update(status='passed_local', actual_sigkill=5, exact_original_replay_after_new_policy=True,
                      published_before_retirement=True, changed_enrollment_refused=True, cases=data['cases'])
    finally:
        cleanup = True
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                cleanup = False
        if process is not None:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                os.killpg(process.pid, signal.SIGKILL)
                cleanup = False
        report['owned_cleanup'] = cleanup
        if not cleanup:
            report['status'] = 'failed'
        report['elapsed_seconds'] = round(time.monotonic()-began, 3)
        (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
        require(cleanup, 'owned process group cleanup incomplete')
    print(json.dumps({'status': report['status'], 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()
